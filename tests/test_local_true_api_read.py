from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import BytesIO
import os
from pathlib import Path

from openpyxl import Workbook
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from wbcz.models import Decision, Event, KiState, Operation
from wbcz_ui.live_true_api import ProductionMutationDisabled, ReadOnlyTrueApiTransport, TrueApiHttpError
from wbcz_local.bridge import LocalTrueApiReadBridge, LocalTrueApiReadRuntime, LocalTrueApiUnavailable
from wbcz_local.control import LocalTrueApiControlService
from wbcz_web.models import AgentJobRecord, Base, CheckRecord, ControlRun, WriteOperationRecord
from wbcz_web.repositories import ImportRepository
from wbcz_web.services.authorization import BootstrapService
from wbcz_web.services.control import OperationMode
from wbcz_web.services.imports import FileImportService
from wbcz_web.services.tenant import bind_tenant_scope


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL")
CIS = "010460123456789021"
INN = "1234567890"
THUMBPRINT = "A" * 40
TOKEN = "SECRET-UUID-TOKEN-MUST-STAY-IN-MEMORY"


class FakeInspector:
    def __init__(self) -> None:
        self.calls = 0

    def inspect(self) -> dict:
        self.calls += 1
        return {
            "certificate_found": True,
            "has_private_key": True,
            "gost_compatible": True,
            "cryptopro_provider": True,
        }


class FakeSigner:
    def __init__(self) -> None:
        self.challenges: list[str] = []

    def sign_auth_challenge(self, challenge: str) -> str:
        self.challenges.append(challenge)
        return "SIGNED-EXACT-CHALLENGE"


class FakeTunnel:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.tunnel = FakeTunnel()
        self.fail_next_info_status: int | None = None

    def tls_diagnostics(self) -> dict:
        return {
            "mechanism": "fake-gost-test",
            "gost_session_verified": True,
        }

    def request_json(
        self,
        method: str,
        path: str,
        *,
        params=None,
        body=None,
        bearer_token=None,
        cis_count=0,
    ):
        self.calls.append({
            "method": method,
            "path": path,
            "params": params,
            "body": body,
            "bearer_token": bearer_token,
            "cis_count": cis_count,
        })
        if (method, path) == ("GET", "/auth/key"):
            return {"uuid": "challenge-uuid", "data": "EXACT-CRPT-CHALLENGE"}
        if (method, path) == ("POST", "/auth/simpleSignIn"):
            assert body == {
                "uuid": "challenge-uuid",
                "data": "SIGNED-EXACT-CHALLENGE",
                "inn": INN,
                "unitedToken": True,
            }
            return {
                "uuidToken": TOKEN,
                "expireDate": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            }
        if (method, path) == ("POST", "/cises/info"):
            if self.fail_next_info_status is not None:
                status = self.fail_next_info_status
                self.fail_next_info_status = None
                raise TrueApiHttpError(status, "synthetic")
            assert params == {"pg": "lp"}
            assert body == [CIS]
            assert bearer_token == TOKEN
            assert cis_count == 1
            return [{
                "cisInfo": {
                    "requestedCis": CIS,
                    "status": "INTRODUCED",
                    "statusEx": "EMPTY",
                    "ownerInn": INN,
                    "productGroup": "lp",
                }
            }]
        raise AssertionError(f"unexpected request: {method} {path}")


class FakeDiscovery:
    def discover(self) -> dict:
        return {
            "cryptopro_available": True,
            "candidates": [{
                "thumbprint": THUMBPRINT,
                "subject": f"CN=Test, INN={INN}",
                "certificate_inn": INN,
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_to": "2027-01-01T00:00:00+00:00",
                "has_private_key": True,
                "compatibility": "GOST_CRYPTOPRO",
                "crypto_provider": "Crypto-Pro GOST R 34.10-2012",
            }],
        }


def _runtime() -> tuple[LocalTrueApiReadRuntime, FakeTransport, FakeSigner, FakeInspector]:
    transport = FakeTransport()
    signer = FakeSigner()
    inspector = FakeInspector()
    runtime = LocalTrueApiReadRuntime(
        participant_inn=INN,
        transport=transport,  # type: ignore[arg-type]
        inspector=inspector,
        signer=signer,
    )
    return runtime, transport, signer, inspector


def test_local_auth_signs_exact_crpt_challenge_once_and_keeps_uuid_token_in_memory() -> None:
    runtime, transport, signer, inspector = _runtime()

    result = runtime.authenticate()

    assert [(item["method"], item["path"]) for item in transport.calls] == [
        ("GET", "/auth/key"),
        ("POST", "/auth/simpleSignIn"),
    ]
    assert signer.challenges == ["EXACT-CRPT-CHALLENGE"]
    assert inspector.calls == 1
    assert runtime.authenticated is True
    assert runtime._session is not None
    assert runtime._session.uuid_token == TOKEN
    assert TOKEN not in repr(result)
    assert set(result) == {
        "authenticated",
        "expire_date",
        "read_only",
        "business_write_enabled",
        "tls",
    }
    assert result["business_write_enabled"] is False


def test_local_cises_info_uses_in_memory_bearer_and_normalizes_fresh_state() -> None:
    runtime, transport, _, _ = _runtime()
    runtime.authenticate()

    result = runtime.read_states([CIS])

    state = result[CIS]
    assert isinstance(state, KiState)
    assert state.status == "IN_CIRCULATION"
    assert state.ownerInn == INN
    assert state.productGroup == "lp"
    call = transport.calls[-1]
    assert call["path"] == "/cises/info"
    assert call["body"] == [CIS]
    assert call["bearer_token"] == TOKEN


def test_local_auth_is_cleared_after_true_api_unauthorized_response() -> None:
    runtime, transport, _, _ = _runtime()
    runtime.authenticate()
    transport.fail_next_info_status = 401

    with pytest.raises(TrueApiHttpError):
        runtime.read_states([CIS])

    assert runtime.authenticated is False


def test_local_bridge_persists_only_certificate_selection_not_uuid_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeCertificateInspector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def inspect(self) -> dict:
            return {"ok": True}

    monkeypatch.setattr(
        "wbcz_local.bridge.WindowsCryptoProCertificateInspector",
        FakeCertificateInspector,
    )

    runtime, _, _, _ = _runtime()
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "true_api_read.json",
        audit_log_path=tmp_path / "true_api_audit.jsonl",
        discovery=FakeDiscovery(),
    )
    bridge.select_certificate(INN, THUMBPRINT)
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn, thumbprint: runtime)

    auth = bridge.authenticate(INN)

    stored = (tmp_path / "true_api_read.json").read_text(encoding="utf-8")
    assert THUMBPRINT in stored
    assert INN in stored
    assert TOKEN not in stored
    assert TOKEN not in repr(auth)
    assert not (tmp_path / "true_api_audit.jsonl").exists()


def test_local_bridge_has_no_document_sign_or_business_mutation_method(tmp_path: Path) -> None:
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
    )
    public = {name for name in dir(bridge) if not name.startswith("_")}
    assert {"authenticate", "read_states", "select_certificate", "status"} <= public
    assert "sign" not in public
    assert "sign_document" not in public
    assert "submit" not in public
    assert "create_document" not in public


def test_underlying_true_api_transport_allowlist_still_denies_business_endpoints() -> None:
    with pytest.raises(ProductionMutationDisabled):
        ReadOnlyTrueApiTransport.assert_allowed(
            "POST",
            "/lk/documents/create",
            None,
        )


def test_local_control_source_contains_no_agent_job_or_write_pipeline() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "wbcz_local" / "control.py"
    ).read_text(encoding="utf-8")
    assert "AgentJob" not in source
    assert "WriteOperation" not in source
    assert "create_document" not in source
    assert 'provider="local-cryptopro-true-api"' in source
    assert '"production_submission_available": False' in source


class StaticStateBridge:
    def __init__(self, state: KiState | None = None, error: Exception | None = None) -> None:
        self.state = state
        self.error = error
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def read_states(self, participant_inn: str, cises) -> dict[str, KiState | Exception]:
        values = tuple(cises)
        self.calls.append((participant_inn, values))
        if self.error is not None:
            raise self.error
        assert self.state is not None
        return {cis: self.state for cis in values}


def _workbook_bytes(event: Event) -> bytes:
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
        event.task_number,
        event.sticker,
        event.kiz,
        event.receipt_number,
        float(event.amount),
        event.currency,
        event.fiscal_drive_number,
        event.occurred_at.astimezone(timezone.utc).strftime("%H:%M:%S %d.%m.%Y")
        if event.occurred_at else None,
        event.operation.value,
        "нет",
    ])
    stream = BytesIO()
    wb.save(stream)
    wb.close()
    return stream.getvalue()


@pytest.fixture
def local_pg_factory():
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


def _seed_local_sale(factory):
    with factory() as db:
        user, org, participant, _ = BootstrapService(db).bootstrap(
            username="local-read-owner",
            password="local-read-regression-password",
            organisation_name="Sellari Local Read",
            participant_inn=INN,
        )
        event = Event(
            kiz=CIS,
            task_number="local-task-1",
            sticker="local-sticker-1",
            operation=Operation.SALE,
            occurred_at=datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc),
            receipt_number="local-receipt-1",
            fiscal_drive_number="7380440903834317",
            amount=Decimal("1900.00"),
            currency="RUB",
            legal_entity_sale=False,
        )
        imported = FileImportService(db).import_xlsx(
            "local-sale.xlsx",
            _workbook_bytes(event),
            user.id,
        )
        db.commit()
        return user.id, org.id, participant.id, imported.id


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_local_fbs_control_uses_fresh_true_api_state_without_agent_or_write_state(
    local_pg_factory,
) -> None:
    user_id, org_id, participant_id, import_id = _seed_local_sale(local_pg_factory)
    state = KiState(
        status="IN_CIRCULATION",
        statusEx=None,
        withdrawReason=None,
        ownerInn=INN,
        productGroup="lp",
    )
    bridge = StaticStateBridge(state=state)

    with local_pg_factory() as db:
        bind_tenant_scope(
            db,
            organisation_id=org_id,
            participant_id=participant_id,
            user_id=user_id,
            role="OWNER",
        )
        result = LocalTrueApiControlService(db, bridge).run(  # type: ignore[arg-type]
            import_id,
            user_id,
            OperationMode.AUTO,
        )
        db.commit()

        assert result["provider"] == "local-cryptopro-true-api"
        assert result["production_submission_available"] is False
        assert bridge.calls == [(INN, (CIS,))]
        event_id = ImportRepository(db).ordered_event_records(import_id)[0].event_id
        check = ImportRepository(db).latest_check(event_id)
        assert check is not None
        assert check.source == "local-cryptopro-true-api"
        assert check.decision == Decision.READY_TO_WITHDRAW.value
        assert check.snapshot["status"] == "IN_CIRCULATION"
        assert db.scalar(select(func.count()).select_from(AgentJobRecord)) == 0
        assert db.scalar(select(func.count()).select_from(WriteOperationRecord)) == 0


@pytest.mark.skipif(not DB_URL, reason="PostgreSQL required")
def test_local_fbs_control_auth_failure_persists_no_control_result(
    local_pg_factory,
) -> None:
    user_id, org_id, participant_id, import_id = _seed_local_sale(local_pg_factory)
    bridge = StaticStateBridge(
        error=LocalTrueApiUnavailable(
            "TRUE_API_AUTH_REQUIRED",
            "Authenticate locally first",
        )
    )

    with local_pg_factory() as db:
        bind_tenant_scope(
            db,
            organisation_id=org_id,
            participant_id=participant_id,
            user_id=user_id,
            role="OWNER",
        )
        with pytest.raises(LocalTrueApiUnavailable, match="Authenticate locally first"):
            LocalTrueApiControlService(db, bridge).run(  # type: ignore[arg-type]
                import_id,
                user_id,
                OperationMode.AUTO,
            )
        db.rollback()
        assert db.scalar(select(func.count()).select_from(ControlRun)) == 0
        assert db.scalar(select(func.count()).select_from(CheckRecord)) == 0
        assert db.scalar(select(func.count()).select_from(AgentJobRecord)) == 0
        assert db.scalar(select(func.count()).select_from(WriteOperationRecord)) == 0
