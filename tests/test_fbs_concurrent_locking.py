from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import BytesIO
import os
import threading
import time

import pytest
from openpyxl import Workbook
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import sessionmaker

from wbcz.models import Decision, Event, Operation
from wbcz.write_pipeline import ExactDocumentBuilder, InvalidWriteOperation
from wbcz_web.config import WebConfig
from wbcz_web.models import (
    AgentJobRecord,
    Base,
    CheckRecord,
    ControlRun,
    WriteOperationRecord,
)
from wbcz_web.repositories import ImportRepository
from wbcz_web.services.agent_orchestration import AgentOrchestrationBroker, WRITE
from wbcz_web.services.authorization import BootstrapService
from wbcz_web.services.imports import FileImportService, record_to_event
from wbcz_web.services.tenant import bind_tenant_scope


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL")
OWN = "1234567890"
TOKEN = "concurrent-lock-test-machine-token-0123456789"
KIZ = "010290089707781021CONCURRENT-TOCTOU"


def _config(database_url: str) -> WebConfig:
    base = WebConfig(
        database_url=database_url,
        own_inn=OWN,
        environment="test",
        agent_enabled=True,
        agent_machine_token=TOKEN,
        true_api_write_enabled=False,
        true_api_real_read_enabled=True,
        fbs_dry_run_only=False,
    ).validate_for_startup()
    return replace(base, true_api_write_enabled=True)


def _event(operation: Operation, *, occurred_at: datetime, suffix: str) -> Event:
    return Event(
        kiz=KIZ,
        task_number=f"task-{suffix}",
        sticker=f"sticker-{suffix}",
        operation=operation,
        occurred_at=occurred_at,
        receipt_number=f"receipt-{suffix}" if operation is Operation.SALE else None,
        fiscal_drive_number="7380440903834317" if operation is Operation.SALE else None,
        amount=Decimal("1901.75"),
        currency="RUB",
        legal_entity_sale=False,
    )


def _workbook_bytes(item: Event) -> bytes:
    wb = Workbook()
    sheet = wb.active
    sheet.title = "КИЗ"
    sheet.append([
        "№ задания",
        "Стикер",
        "КИЗ",
        "Номер чека",
        "Стоимость",
        "Валюта",
        "Номер фискального накопителя",
        "Дата",
        "Тип операции",
        "Признак продажи юрлицу",
    ])
    sheet.append([
        item.task_number,
        item.sticker,
        item.kiz,
        item.receipt_number,
        float(item.amount),
        item.currency,
        item.fiscal_drive_number,
        item.occurred_at.astimezone(timezone.utc).strftime("%H:%M:%S %d.%m.%Y")
        if item.occurred_at
        else None,
        item.operation.value,
        "нет",
    ])
    stream = BytesIO()
    wb.save(stream)
    wb.close()
    return stream.getvalue()


@pytest.fixture
def pg_factory():
    if not DB_URL:
        pytest.skip("WBCZ_TEST_DATABASE_URL requires PostgreSQL")
    engine = create_engine(DB_URL, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def _bind(db, *, org_id: str, participant_id: str, user_id: int) -> None:
    bind_tenant_scope(
        db,
        organisation_id=org_id,
        participant_id=participant_id,
        user_id=user_id,
        role="OWNER",
    )


def _seed_live_ready_sale(pg_factory):
    sale = _event(
        Operation.SALE,
        occurred_at=datetime(2026, 9, 14, 12, 54, tzinfo=timezone.utc),
        suffix="sale",
    )
    newer_return = _event(
        Operation.RETURN,
        occurred_at=sale.occurred_at + timedelta(hours=1),
        suffix="return",
    )
    with pg_factory() as db:
        user, org, participant, _ = BootstrapService(db).bootstrap(
            username="toctou-operator",
            password="very-secure-toctou-test-password",
            organisation_name="TOCTOU Regression",
            participant_inn=OWN,
        )
        imported = FileImportService(db).import_xlsx(
            "sale.xlsx",
            _workbook_bytes(sale),
            user.id,
        )
        sale_row = ImportRepository(db).ordered_event_records(imported.id)[0]
        sale_event = record_to_event(sale_row)
        run = ControlRun(
            organisation_id=org.id,
            participant_id=participant.id,
            import_id=imported.id,
            user_id=user.id,
            mode="AUTO",
            provider="windows-agent-true-api",
        )
        db.add(run)
        db.flush()
        db.add(
            CheckRecord(
                run_id=run.id,
                event_id=sale_row.event_id,
                source="windows-agent-true-api",
                snapshot={
                    "status": "IN_CIRCULATION",
                    "statusEx": None,
                    "withdrawReason": None,
                    "ownerInn": OWN,
                    "productGroup": "lp",
                },
                decision=Decision.READY_TO_WITHDRAW.value,
                reason="SALE_IN_CIRCULATION",
                error=None,
            )
        )
        db.commit()
        return {
            "user_id": user.id,
            "org_id": org.id,
            "participant_id": participant.id,
            "import_id": imported.id,
            "sale_event_id": sale_row.event_id,
            "sale": sale_event,
            "return_bytes": _workbook_bytes(newer_return),
        }


def _wait_for_backend_lock(db, pid: int, timeout: float = 5.0) -> tuple[str | None, str | None]:
    deadline = time.monotonic() + timeout
    last = (None, None)
    while time.monotonic() < deadline:
        row = db.execute(
            text(
                "SELECT wait_event_type, wait_event "
                "FROM pg_stat_activity WHERE pid=:pid"
            ),
            {"pid": pid},
        ).one_or_none()
        if row is not None:
            last = (row[0], row[1])
            if row[0] == "Lock":
                return last
        time.sleep(0.02)
    return last


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_write_critical_section_blocks_newer_import_between_sequence_and_write_state(
    pg_factory,
):
    seeded = _seed_live_ready_sale(pg_factory)
    cfg = _config(DB_URL)
    writer_after_sequence = threading.Event()
    importer_ready = threading.Event()
    importer_attempted = threading.Event()
    importer_committed = threading.Event()
    importer_errors: list[BaseException] = []
    importer_pid: list[int] = []

    def import_newer_return() -> None:
        try:
            with pg_factory() as db:
                _bind(
                    db,
                    org_id=seeded["org_id"],
                    participant_id=seeded["participant_id"],
                    user_id=seeded["user_id"],
                )
                importer_pid.append(int(db.scalar(text("SELECT pg_backend_pid()"))))
                importer_ready.set()
                assert writer_after_sequence.wait(5)
                importer_attempted.set()
                FileImportService(db).import_xlsx(
                    "newer-return.xlsx",
                    seeded["return_bytes"],
                    seeded["user_id"],
                )
                db.commit()
                importer_committed.set()
        except BaseException as exc:  # surfaced in the main test thread below
            importer_errors.append(exc)
            importer_ready.set()
            importer_attempted.set()

    thread = threading.Thread(target=import_newer_return, daemon=True)
    thread.start()
    assert importer_ready.wait(5)
    assert importer_pid

    with pg_factory() as writer_db:
        _bind(
            writer_db,
            org_id=seeded["org_id"],
            participant_id=seeded["participant_id"],
            user_id=seeded["user_id"],
        )
        broker = AgentOrchestrationBroker(writer_db, cfg)

        def abort_at_write_state_boundary(**_kwargs):
            writer_after_sequence.set()
            assert importer_attempted.wait(5)
            wait_type, _ = _wait_for_backend_lock(writer_db, importer_pid[0])
            assert wait_type == "Lock"
            raise RuntimeError("TEST_ABORT_AFTER_FINAL_SEQUENCE")

        broker.write_store.prepare = abort_at_write_state_boundary  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="TEST_ABORT_AFTER_FINAL_SEQUENCE"):
            broker.prepare_approved_write(
                seeded["sale_event_id"],
                ExactDocumentBuilder.from_json_value({"toctou": "writer-first"}),
                decision=Decision.READY_TO_WITHDRAW,
            )

        # The importer cannot make the newer history authoritative inside the
        # final sequence-check -> write-state-creation critical section.
        assert importer_committed.is_set() is False
        writer_db.rollback()

    thread.join(timeout=5)
    assert thread.is_alive() is False
    assert importer_errors == []
    assert importer_committed.is_set()

    with pg_factory() as db:
        _bind(
            db,
            org_id=seeded["org_id"],
            participant_id=seeded["participant_id"],
            user_id=seeded["user_id"],
        )
        with pytest.raises(
            InvalidWriteOperation,
            match="SUPERSEDED_BY_LATER_WB_EVENT",
        ):
            AgentOrchestrationBroker(db, cfg).prepare_approved_write(
                seeded["sale_event_id"],
                ExactDocumentBuilder.from_json_value({"toctou": "retry-after-import"}),
                decision=Decision.READY_TO_WITHDRAW,
            )
        assert db.scalar(
            select(func.count())
            .select_from(WriteOperationRecord)
            .where(WriteOperationRecord.event_id == seeded["sale_event_id"])
        ) == 0
        assert db.scalar(
            select(func.count())
            .select_from(AgentJobRecord)
            .where(
                AgentJobRecord.event_id == seeded["sale_event_id"],
                AgentJobRecord.purpose == WRITE,
            )
        ) == 0


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_newer_import_lock_commits_first_then_old_prepare_observes_superseded(
    pg_factory,
):
    seeded = _seed_live_ready_sale(pg_factory)
    cfg = _config(DB_URL)
    writer_ready = threading.Event()
    writer_done = threading.Event()
    writer_pid: list[int] = []
    writer_errors: list[BaseException] = []

    with pg_factory() as importer_db:
        _bind(
            importer_db,
            org_id=seeded["org_id"],
            participant_id=seeded["participant_id"],
            user_id=seeded["user_id"],
        )
        FileImportService(importer_db).import_xlsx(
            "newer-return-first.xlsx",
            seeded["return_bytes"],
            seeded["user_id"],
        )

        def prepare_old_sale() -> None:
            try:
                with pg_factory() as writer_db:
                    _bind(
                        writer_db,
                        org_id=seeded["org_id"],
                        participant_id=seeded["participant_id"],
                        user_id=seeded["user_id"],
                    )
                    writer_pid.append(int(writer_db.scalar(text("SELECT pg_backend_pid()"))))
                    writer_ready.set()
                    try:
                        AgentOrchestrationBroker(writer_db, cfg).prepare_approved_write(
                            seeded["sale_event_id"],
                            ExactDocumentBuilder.from_json_value({"toctou": "import-first"}),
                            decision=Decision.READY_TO_WITHDRAW,
                        )
                    except BaseException as exc:
                        writer_errors.append(exc)
                    finally:
                        writer_db.rollback()
                        writer_done.set()
            except BaseException as exc:
                writer_errors.append(exc)
                writer_ready.set()
                writer_done.set()

        thread = threading.Thread(target=prepare_old_sale, daemon=True)
        thread.start()
        assert writer_ready.wait(5)
        assert writer_pid
        wait_type, _ = _wait_for_backend_lock(importer_db, writer_pid[0])
        assert wait_type == "Lock"
        assert writer_done.is_set() is False

        # Commit makes the newer RETURN authoritative, then the blocked writer
        # acquires the same tenant+KIZ lock and must re-run sequence validation.
        importer_db.commit()

    thread.join(timeout=5)
    assert thread.is_alive() is False
    assert writer_done.is_set()
    assert len(writer_errors) == 1
    assert isinstance(writer_errors[0], InvalidWriteOperation)
    assert "SUPERSEDED_BY_LATER_WB_EVENT" in str(writer_errors[0])

    with pg_factory() as db:
        _bind(
            db,
            org_id=seeded["org_id"],
            participant_id=seeded["participant_id"],
            user_id=seeded["user_id"],
        )
        assert db.scalar(
            select(func.count())
            .select_from(WriteOperationRecord)
            .where(WriteOperationRecord.event_id == seeded["sale_event_id"])
        ) == 0
        assert db.scalar(
            select(func.count())
            .select_from(AgentJobRecord)
            .where(
                AgentJobRecord.event_id == seeded["sale_event_id"],
                AgentJobRecord.purpose == WRITE,
            )
        ) == 0
