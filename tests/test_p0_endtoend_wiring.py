from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
import inspect as pyinspect
import os
from pathlib import Path
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from wbcz.agent_cli import WindowsAgentPreflight, WindowsAgentRuntime
from wbcz.models import Decision, Event, Operation
from wbcz.windows_agent import (
    AgentHttpResponse,
    AgentJob,
    AgentJobType,
    AgentReplayConflict,
    AgentResult,
    WindowsOutboundAgent,
)
from wbcz.windows_agent_runtime import (
    AgentCreateOutcomeUnresolved,
    DurableWindowsAgentExecutor,
    WindowsAgentReplayStore,
)
from wbcz.write_pipeline import CreateCategory, ExactDocumentBuilder, InvalidWriteOperation, WriteState
from wbcz_web.config import WebConfig
from wbcz_web.main import create_app
from wbcz_web.models import AgentJobRecord, Base, CheckRecord, ControlRun, EventRecord, ImportRecord, ImportRow, User
from wbcz_web.repositories import SqlAlchemyAgentJobStore, SqlAlchemyWriteOperationStore
from wbcz_web.services.agent_orchestration import (
    AgentControlService,
    AgentOrchestrationBroker,
    CONTROL_CIS,
    POLL,
    RECONCILIATION_CIS,
    WRITE,
)
from wbcz_web.services.imports import event_to_record


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL")
OWN = "1234567890"
TOKEN = "test-machine-token-for-agent-0123456789"
TEST_CIS_PREFIX = "010290089707781021"


def valid_test_cis(label: str) -> str:
    value = TEST_CIS_PREFIX + label
    assert 18 <= len(value) <= 74
    return value


def agent_config(database_url: str) -> WebConfig:
    return WebConfig(
        database_url=database_url,
        own_inn=OWN,
        environment="test",
        agent_enabled=True,
        agent_machine_token=TOKEN,
        agent_job_lease_seconds=30,
        agent_poll_initial_seconds=1,
        agent_poll_max_seconds=4,
        agent_poll_max_attempts=3,
        true_api_write_enabled=False,
    ).validate_for_startup()


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


def sale_event(kiz: str = "TEST-CIS-SALE") -> Event:
    return Event(
        kiz=valid_test_cis(kiz),
        task_number="100",
        sticker="200",
        operation=Operation.SALE,
        occurred_at=datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc),
        receipt_number="300",
        fiscal_drive_number="9999078900000001",
        amount=Decimal("1500.00"),
        currency="RUB",
        legal_entity_sale=False,
    )


def seed_import(db, event: Event):
    user = User(username=f"u-{event.kiz}", password_hash="not-used", is_active=True, is_admin=True)
    db.add(user)
    db.flush()
    record = ImportRecord(
        fingerprint=(event.event_id[:64]),
        filename="archive.xlsx",
        imported_by=user.id,
        new_events=1,
        duplicate_events=0,
        rejected_rows=0,
        row_count=1,
        unique_kiz=1,
        sales=1 if event.operation is Operation.SALE else 0,
        returns=1 if event.operation is Operation.RETURN else 0,
        dated=1,
        undated=0,
    )
    db.add(record)
    db.add(event_to_record(event))
    db.flush()
    db.add(ImportRow(import_id=record.id, row_number=2, event_id=event.event_id))
    db.flush()
    return user, record


def add_check(db, event: Event, import_id: str, user_id: int, decision: Decision, reason: str):
    run = ControlRun(import_id=import_id, user_id=user_id, mode="AUTO", provider="test")
    db.add(run)
    db.flush()
    db.add(CheckRecord(
        run_id=run.id,
        event_id=event.event_id,
        source="test",
        snapshot=None,
        decision=decision.value,
        reason=reason,
        error=None,
    ))
    db.flush()


def test_config_agent_and_write_are_fail_closed(monkeypatch):
    monkeypatch.setenv("WBCZ_ENV", "production")
    monkeypatch.setenv("WBCZ_DATABASE_URL", "postgresql+psycopg://wbcz:strong-db-password-value@db:5432/wbcz")
    monkeypatch.setenv("WBCZ_OWN_INN", OWN)
    monkeypatch.setenv("WBCZ_COOKIE_SECURE", "true")
    monkeypatch.setenv("WBCZ_TRUSTED_HOSTS", "mark.sellari.ru")
    monkeypatch.setenv("WBCZ_BUILD_SHA", "a" * 40)
    monkeypatch.setenv("WBCZ_AGENT_ENABLED", "true")
    monkeypatch.delenv("WBCZ_AGENT_MACHINE_TOKEN", raising=False)
    with pytest.raises(ValueError, match="WBCZ_AGENT_MACHINE_TOKEN"):
        WebConfig.from_env()
    monkeypatch.setenv("WBCZ_AGENT_MACHINE_TOKEN", "x" * 40)
    monkeypatch.setenv("WBCZ_TRUE_API_WRITE_ENABLED", "true")
    with pytest.raises(ValueError, match="write remains disabled"):
        WebConfig.from_env()


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_fastapi_agent_endpoints_dispatch_machine_auth_and_duplicate_result_once(pg_factory, caplog):
    config = agent_config(DB_URL)
    event = sale_event("CIS-HTTP-DISPATCH")
    with pg_factory() as db:
        user, imported = seed_import(db, event)
        AgentControlService(db, config).run(imported.id, user.id, "AUTO")
        queued = db.scalar(select(AgentJobRecord).where(AgentJobRecord.purpose == CONTROL_CIS))
        assert queued is not None
        job_id = queued.job_id
        operation_id = queued.operation_id
        db.commit()

    app = create_app(config, session_factory=pg_factory)
    result = AgentResult(
        job_id,
        operation_id,
        "CIS_CHECKED",
        cises=({
            "cis": event.kiz,
            "status": "IN_CIRCULATION",
            "statusEx": None,
            "withdrawReason": None,
            "ownerInn": OWN,
            "productGroup": "lp",
        },),
    )
    payload = result.safe_dict()
    payload["cises"] = list(result.cises)

    with TestClient(app) as client:
        missing = client.get("/api/agent/v1/jobs/next")
        assert missing.status_code == 401
        cookie_only = client.get(
            "/api/agent/v1/jobs/next",
            cookies={config.session_cookie_name: TOKEN},
        )
        assert cookie_only.status_code == 401
        wrong = client.get(
            "/api/agent/v1/jobs/next",
            headers={"Authorization": "Bearer " + "z" * 40},
        )
        assert wrong.status_code == 401
        preflight = client.head(
            "/api/agent/v1/jobs/next",
            headers={"Authorization": "Bearer " + TOKEN},
        )
        assert preflight.status_code == 204

        fetched = client.get(
            "/api/agent/v1/jobs/next",
            headers={"Authorization": "Bearer " + TOKEN},
        )
        assert fetched.status_code == 200
        assert fetched.json()["job_id"] == job_id
        assert fetched.json()["operation_id"] == operation_id

        first = client.post(
            f"/api/agent/v1/jobs/{job_id}/result",
            headers={"Authorization": "Bearer " + TOKEN},
            json=payload,
        )
        assert first.status_code == 202
        duplicate = client.post(
            f"/api/agent/v1/jobs/{job_id}/result",
            headers={"Authorization": "Bearer " + TOKEN},
            json=payload,
        )
        assert duplicate.status_code == 202

        incompatible_payload = dict(payload)
        incompatible_payload["outcome"] = "MANUAL_REVIEW"
        incompatible = client.post(
            f"/api/agent/v1/jobs/{job_id}/result",
            headers={"Authorization": "Bearer " + TOKEN},
            json=incompatible_payload,
        )
        assert incompatible.status_code == 400

        empty = client.get(
            "/api/agent/v1/jobs/next",
            headers={"Authorization": "Bearer " + TOKEN},
        )
        assert empty.status_code == 204
        arbitrary = client.get(
            "/api/agent/v1/arbitrary",
            headers={"Authorization": "Bearer " + TOKEN},
        )
        assert arbitrary.status_code == 404
        response_text = (
            missing.text + wrong.text + preflight.text + fetched.text + first.text
            + duplicate.text + incompatible.text + empty.text + arbitrary.text
        )
        assert TOKEN not in response_text
        assert TOKEN not in caplog.text

    with pg_factory() as db:
        completed = db.get(AgentJobRecord, job_id)
        assert completed is not None and completed.state == "COMPLETED"
        checks = list(db.scalars(select(CheckRecord).where(CheckRecord.event_id == event.event_id)))
        assert len(checks) == 1
        assert checks[0].decision == Decision.MANUAL_REVIEW.value
        assert checks[0].reason == "ORGANISATION_CONFIG_MISSING"


def test_direct_vps_true_api_production_path_is_absent():
    root = Path(__file__).parents[1] / "src" / "wbcz_web"
    forbidden = (
        "markirovka.crpt.ru",
        '"/auth/key"',
        '"/auth/simpleSignIn"',
        '"/cises/info"',
        '"/lk/documents/create',
        '"/doc/{docId}/info"',
        "ProductionAgentTrueApiTransport",
    )
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in root.rglob("*.py")
    )
    for marker in forbidden:
        assert marker not in combined


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_postgres_agent_job_persists_and_replay_is_idempotent(pg_factory):
    job = AgentJob(
        "job-persist",
        AgentJobType.CIS_CHECK,
        "cis:request-1",
        "lp",
        OWN,
        cises=(valid_test_cis("PERSIST-A"),),
    )
    with pg_factory() as db:
        store = SqlAlchemyAgentJobStore(db, lease_seconds=30)
        assert store.enqueue(job, purpose=CONTROL_CIS, event_id="e1") == job
        db.commit()
    with pg_factory() as db:
        store = SqlAlchemyAgentJobStore(db, lease_seconds=30)
        assert store.enqueue(job, purpose=CONTROL_CIS, event_id="e1") == job
        assert db.get(AgentJobRecord, job.job_id) is not None
        incompatible = AgentJob(
            job.job_id,
            AgentJobType.CIS_CHECK,
            job.operation_id,
            "lp",
            OWN,
            cises=(valid_test_cis("PERSIST-B"),),
        )
        with pytest.raises(AgentReplayConflict):
            store.enqueue(incompatible, purpose=CONTROL_CIS, event_id="e1")


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_postgres_write_state_persists_and_business_fingerprint_is_idempotent(pg_factory):
    document = ExactDocumentBuilder.from_json_value({"TEST_ONLY": True})
    with pg_factory() as db:
        store = SqlAlchemyWriteOperationStore(db)
        op = store.prepare(
            event_id="event-1",
            decision=Decision.READY_TO_WITHDRAW,
            document_type="LK_RECEIPT",
            operation_reason="DISTANCE",
            pg="lp",
            expected_inn=OWN,
            document=document,
        )
        db.commit()
    with pg_factory() as db:
        store = SqlAlchemyWriteOperationStore(db)
        persisted = store.get(op.operation_id)
        assert persisted.state is WriteState.AWAITING_SIGNATURE
        replay = store.prepare(
            event_id="event-1",
            decision=Decision.READY_TO_WITHDRAW,
            document_type="LK_RECEIPT",
            operation_reason="DISTANCE",
            pg="lp",
            expected_inn=OWN,
            document=document,
        )
        assert replay.operation_id == op.operation_id


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_wb_control_queues_cis_and_windows_result_is_decided_on_vps(pg_factory):
    config = agent_config(DB_URL)
    event = sale_event()
    with pg_factory() as db:
        user, imported = seed_import(db, event)
        response = AgentControlService(db, config).run(imported.id, user.id, "AUTO")
        assert response["pending"] == 1
        job = db.scalar(select(AgentJobRecord).where(AgentJobRecord.purpose == CONTROL_CIS))
        assert job is not None and job.job_type == AgentJobType.CIS_CHECK.value
        job_id = job.job_id
        operation_id = job.operation_id
        db.commit()
    with pg_factory() as db:
        broker = AgentOrchestrationBroker(db, config)
        broker.submit_result(
            TOKEN,
            AgentResult(
                job_id,
                operation_id,
                "CIS_CHECKED",
                cises=({
                    "cis": event.kiz,
                    "status": "IN_CIRCULATION",
                    "statusEx": None,
                    "withdrawReason": None,
                    "ownerInn": OWN,
                    "productGroup": "lp",
                },),
            ),
        )
        check = broker.imports.latest_check(event.event_id)
        assert check is not None
        assert check.decision == Decision.READY_TO_WITHDRAW.value
        # Exact production document contract is still deliberately unavailable,
        # so READY alone does not silently fabricate a write job.
        assert db.scalar(select(AgentJobRecord).where(AgentJobRecord.purpose == WRITE)) is None


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
@pytest.mark.parametrize(
    "decision,operation,job_type",
    [
        (Decision.READY_TO_WITHDRAW, Operation.SALE, AgentJobType.LK_RECEIPT),
        (Decision.READY_TO_RETURN, Operation.RETURN, AgentJobType.LP_RETURN),
    ],
)
def test_only_ready_decisions_map_to_exact_write_types(pg_factory, decision, operation, job_type):
    config = agent_config(DB_URL)
    event = replace(sale_event(f"CIS-{decision.value}"), operation=operation)
    with pg_factory() as db:
        user, imported = seed_import(db, event)
        add_check(db, event, imported.id, user.id, decision, "TEST_READY")
        broker = AgentOrchestrationBroker(db, config)
        job = broker.prepare_approved_write(
            event.event_id,
            ExactDocumentBuilder.from_json_value({"TEST_ONLY": True}),
        )
        assert job.job_type is job_type
        assert job.document_type == job_type.value


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
@pytest.mark.parametrize("decision", [Decision.MANUAL_REVIEW, Decision.ERROR, Decision.ALREADY_DONE, Decision.NO_ACTION])
def test_non_ready_decisions_cannot_queue_write(pg_factory, decision):
    config = agent_config(DB_URL)
    event = sale_event(f"CIS-{decision.value}")
    with pg_factory() as db:
        user, imported = seed_import(db, event)
        add_check(db, event, imported.id, user.id, decision, "TEST_BLOCKED")
        broker = AgentOrchestrationBroker(db, config)
        with pytest.raises(InvalidWriteOperation, match="only READY"):
            broker.prepare_approved_write(
                event.event_id,
                ExactDocumentBuilder.from_json_value({"TEST_ONLY": True}),
            )
        assert db.scalar(select(AgentJobRecord).where(AgentJobRecord.purpose == WRITE)) is None


def _prepare_submitted_write(db, config: WebConfig, event: Event, imported, user):
    add_check(db, event, imported.id, user.id, Decision.READY_TO_WITHDRAW, "TEST_READY")
    broker = AgentOrchestrationBroker(db, config)
    write_job = broker.prepare_approved_write(
        event.event_id,
        ExactDocumentBuilder.from_json_value({"TEST_ONLY": True}),
    )
    broker.submit_result(
        TOKEN,
        AgentResult(
            write_job.job_id,
            write_job.operation_id,
            "SUBMITTED",
            document_sha256=write_job.document_sha256,
            signature_base64=base64.b64encode(b"detached-signature").decode(),
            certificate_thumbprint="AA11",
            certificate_inn=OWN,
            http_status=201,
            create_category=CreateCategory.SUCCESS_WITH_ID.value,
            document_id="doc-confirmed-runtime-test",
            body_sha256="1" * 64,
        ),
    )
    return broker, write_job


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_checked_ok_requires_reconciliation_and_mismatch_becomes_manual_review(pg_factory):
    config = agent_config(DB_URL)
    event = sale_event("CIS-RECON")
    with pg_factory() as db:
        user, imported = seed_import(db, event)
        broker, write_job = _prepare_submitted_write(db, config, event, imported, user)
        assert broker.write_store.get(write_job.operation_id).state is WriteState.SUBMITTED
        poll = db.scalar(select(AgentJobRecord).where(AgentJobRecord.purpose == POLL))
        assert poll is not None and poll.poll_attempt == 1
        broker.submit_result(
            TOKEN,
            AgentResult(
                poll.job_id,
                write_job.operation_id,
                "RECONCILIATION_REQUIRED",
                http_status=200,
                remote_status="CHECKED_OK",
                body_sha256="2" * 64,
            ),
        )
        assert broker.write_store.get(write_job.operation_id).state is WriteState.RECONCILIATION_REQUIRED
        reconcile = db.scalar(select(AgentJobRecord).where(AgentJobRecord.purpose == RECONCILIATION_CIS))
        assert reconcile is not None
        broker.submit_result(
            TOKEN,
            AgentResult(
                reconcile.job_id,
                write_job.operation_id,
                "CIS_CHECKED",
                cises=({
                    "cis": event.kiz,
                    "status": "IN_CIRCULATION",
                    "statusEx": None,
                    "withdrawReason": None,
                    "ownerInn": OWN,
                    "productGroup": "lp",
                },),
            ),
        )
        assert broker.write_store.get(write_job.operation_id).state is WriteState.MANUAL_REVIEW


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_intermediate_poll_is_backoff_scheduled_and_unknown_status_fails_closed(pg_factory):
    config = agent_config(DB_URL)
    event = sale_event("CIS-POLL")
    with pg_factory() as db:
        user, imported = seed_import(db, event)
        broker, write_job = _prepare_submitted_write(db, config, event, imported, user)
        first = db.scalar(select(AgentJobRecord).where(AgentJobRecord.purpose == POLL))
        assert first is not None
        broker.submit_result(
            TOKEN,
            AgentResult(
                first.job_id,
                write_job.operation_id,
                "INTERMEDIATE",
                http_status=200,
                remote_status="IN_PROGRESS",
                body_sha256="3" * 64,
            ),
        )
        op = broker.write_store.get(write_job.operation_id)
        assert op.state is WriteState.PROCESSING
        second = db.scalar(
            select(AgentJobRecord).where(
                AgentJobRecord.purpose == POLL,
                AgentJobRecord.poll_attempt == 2,
            )
        )
        assert second is not None
        assert second.available_at > datetime.now(timezone.utc)
        broker.submit_result(
            TOKEN,
            AgentResult(
                second.job_id,
                write_job.operation_id,
                "MANUAL_REVIEW",
                http_status=200,
                remote_status="UNKNOWN_FUTURE_STATUS",
                body_sha256="4" * 64,
            ),
        )
        assert broker.write_store.get(write_job.operation_id).state is WriteState.MANUAL_REVIEW


class FakeInspector:
    def inspect(self):
        return {
            "certificate_found": True,
            "thumbprint_match": True,
            "has_private_key": True,
            "not_expired": True,
            "gost_compatible": True,
            "cryptopro_provider": True,
        }


class FakePreflightTransport:
    def __init__(self):
        self.cis_calls = 0
        self.create_calls = 0
    def tls_diagnostics(self):
        return {"executable": "stunnel_msspi.exe", "gost_session_verified": True}
    def cises_info(self, cises, *, bearer_token):
        self.cis_calls += 1
        return []
    def create_document(self, **kwargs):
        self.create_calls += 1
        raise AssertionError("preflight must never create")


class FakeAuthenticator:
    def preflight(self):
        return {"true_api_available": True}


class FakeSession:
    expire_date = datetime(2099, 1, 1, tzinfo=timezone.utc)
    def bearer_token(self):
        return "memory-only-token"


class FakeBackend:
    def __init__(self): self.calls = 0
    def check_auth(self, token): self.calls += 1


def test_preflight_is_mutation_free_even_with_optional_cis():
    transport = FakePreflightTransport()
    backend = FakeBackend()
    preflight = WindowsAgentPreflight(
        certificate_inspector=FakeInspector(),
        transport=transport,
        authenticator=FakeAuthenticator(),
        session_manager=FakeSession(),
        backend=backend,
        machine_token=TOKEN,
    )
    result = preflight.check(test_cis=valid_test_cis("PREFLIGHT"))
    assert result["ok"] is True
    assert result["production_write"] is False
    assert transport.cis_calls == 1
    assert transport.create_calls == 0
    assert backend.calls == 1
    assert "memory-only-token" not in repr(result)


def test_windows_runtime_and_outbound_agent_have_no_listener():
    source = pyinspect.getsource(WindowsAgentRuntime) + pyinspect.getsource(WindowsOutboundAgent)
    for marker in ("serve_forever", "HTTPServer", "socketserver", ".listen(", ".bind("):
        assert marker not in source


class FailingSigner:
    def sign_document_bytes(self, **kwargs):
        raise RuntimeError("local signing failed")


class NoCreateTransport:
    def __init__(self): self.calls = 0
    def create_document(self, **kwargs):
        self.calls += 1
        raise RuntimeError("ambiguous transport")


class SessionToken:
    def bearer_token(self): return "memory-token"


def _write_job():
    document = ExactDocumentBuilder.from_json_value({"TEST_ONLY": True})
    return AgentJob(
        "job-replay",
        AgentJobType.LK_RECEIPT,
        "op-replay",
        "lp",
        OWN,
        document_type="LK_RECEIPT",
        document_sha256=document.sha256,
        product_document_base64=document.product_document_base64,
    )


def test_local_signing_failure_does_not_poison_replay_reservation(tmp_path):
    transport = NoCreateTransport()
    with WindowsAgentReplayStore(tmp_path / "replay.sqlite") as replay:
        executor = DurableWindowsAgentExecutor(
            participant_inn=OWN,
            transport=transport,
            session_manager=SessionToken(),
            document_signer=FailingSigner(),
            replay_store=replay,
            production_write=True,
        )
        job = _write_job()
        with pytest.raises(RuntimeError, match="local signing"):
            executor.execute(job)
        assert replay.state(job.operation_id) is None
        assert transport.calls == 0


def test_ambiguous_create_reservation_survives_restart_and_blocks_second_create(tmp_path):
    class Signer:
        def sign_document_bytes(self, **kwargs):
            return base64.b64encode(b"signature").decode(), {
                "certificate_thumbprint": "AA11",
                "certificate_subject": None,
                "certificate_inn": OWN,
                "certificate_valid_from": None,
                "certificate_valid_to": None,
            }
    path = tmp_path / "replay.sqlite"
    transport = NoCreateTransport()
    job = _write_job()
    with WindowsAgentReplayStore(path) as replay:
        executor = DurableWindowsAgentExecutor(
            participant_inn=OWN,
            transport=transport,
            session_manager=SessionToken(),
            document_signer=Signer(),
            replay_store=replay,
            production_write=True,
        )
        with pytest.raises(RuntimeError, match="ambiguous transport"):
            executor.execute(job)
        assert replay.state(job.operation_id) == "RESERVED"
        assert transport.calls == 1
    with WindowsAgentReplayStore(path) as replay:
        executor = DurableWindowsAgentExecutor(
            participant_inn=OWN,
            transport=transport,
            session_manager=SessionToken(),
            document_signer=Signer(),
            replay_store=replay,
            production_write=True,
        )
        with pytest.raises(AgentCreateOutcomeUnresolved):
            executor.execute(job)
        assert transport.calls == 1
