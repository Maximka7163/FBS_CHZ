from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import BytesIO
import os
from pathlib import Path
from uuid import uuid4

from openpyxl import Workbook
import pytest
from sqlalchemy import create_engine, func, select, text
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
            return {
                "uuid": "challenge-uuid",
                "data": " EXACT-CRPT-CHALLENGE\nЮникод ",
            }
        if (method, path) == ("POST", "/auth/simpleSignIn"):
            assert body == {
                "uuid": "challenge-uuid",
                "data": "BROWSER-CADES-ATTACHED-SIGNATURE",
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
            assert bearer_token == TOKEN
            if body == [CIS]:
                assert cis_count == 1
            return [{
                "cisInfo": {
                    "requestedCis": cis,
                    "status": "INTRODUCED",
                    "statusEx": "EMPTY",
                    "ownerInn": INN,
                    "productGroup": "lp",
                }
            } for cis in body]
        raise AssertionError(f"unexpected request: {method} {path}")


class FakeDiscovery:
    def discover(self) -> dict:
        return {
            "cryptopro_available": False,  # cryptcp is deliberately absent.
            "candidates": [{
                "thumbprint": THUMBPRINT,
                "subject": f"CN=Test, INN={INN}",
                "certificate_inn": INN,
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_to": "2027-01-01T00:00:00+00:00",
                "has_private_key": True,
                "compatibility": "UNSUPPORTED",
                "crypto_provider": "Crypto-Pro GOST R 34.10-2012",
                "public_key_oid": "1.2.643.7.1.1.1.1",
            }],
        }


def _runtime() -> tuple[LocalTrueApiReadRuntime, FakeTransport]:
    transport = FakeTransport()
    runtime = LocalTrueApiReadRuntime(
        participant_inn=INN,
        transport=transport,  # type: ignore[arg-type]
    )
    return runtime, transport


def _browser_auth(runtime: LocalTrueApiReadRuntime) -> dict:
    uuid, challenge = runtime.prepare_auth_challenge()
    assert uuid == "challenge-uuid"
    assert challenge == " EXACT-CRPT-CHALLENGE\nЮникод "
    return runtime.complete_auth(
        uuid=uuid,
        signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
    )


def test_local_runtime_preserves_exact_challenge_and_keeps_uuid_token_in_memory() -> None:
    runtime, transport = _runtime()

    uuid, challenge = runtime.prepare_auth_challenge()
    assert uuid == "challenge-uuid"
    assert challenge.encode("utf-8") == " EXACT-CRPT-CHALLENGE\nЮникод ".encode("utf-8")
    result = runtime.complete_auth(
        uuid=uuid,
        signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
    )

    assert [(item["method"], item["path"]) for item in transport.calls] == [
        ("GET", "/auth/key"),
        ("POST", "/auth/simpleSignIn"),
    ]
    assert runtime.authenticated is True
    assert runtime._session is not None
    assert runtime._session.uuid_token == TOKEN
    assert TOKEN not in repr(result)
    assert result["business_write_enabled"] is False


def test_local_cises_info_uses_in_memory_bearer_and_normalizes_fresh_state() -> None:
    runtime, transport = _runtime()
    _browser_auth(runtime)

    result = runtime.read_states([CIS])

    state = result[CIS]
    assert isinstance(state, KiState)
    assert state.status == "IN_CIRCULATION"
    assert state.ownerInn == INN
    call = transport.calls[-1]
    assert call["path"] == "/cises/info"
    assert call["bearer_token"] == TOKEN


class BatchTransport(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.batch_sizes: list[int] = []

    def request_json(self, method: str, path: str, **kwargs):
        if (method, path) != ("POST", "/cises/info"):
            return super().request_json(method, path, **kwargs)
        body = kwargs["body"]
        assert kwargs["params"] == {"pg": "lp"}
        assert kwargs["bearer_token"] == TOKEN
        self.batch_sizes.append(len(body))
        return [{
            "cisInfo": {
                "requestedCis": cis,
                "status": "INTRODUCED",
                "statusEx": "EMPTY",
                "ownerInn": INN,
                "productGroup": "lp",
            }
        } for cis in body]


def test_local_cises_info_batches_more_than_1000_codes() -> None:
    transport = BatchTransport()
    runtime = LocalTrueApiReadRuntime(
        participant_inn=INN,
        transport=transport,  # type: ignore[arg-type]
    )
    _browser_auth(runtime)
    cises = [f"010460123456{index:06d}" for index in range(1001)]

    result = runtime.read_states(cises)

    assert len(result) == 1001
    assert transport.batch_sizes == [1000, 1]


@pytest.mark.parametrize("http_status", [401, 403])
def test_local_auth_is_cleared_after_true_api_unauthorized_response(
    http_status: int,
) -> None:
    runtime, transport = _runtime()
    _browser_auth(runtime)
    transport.fail_next_info_status = http_status

    with pytest.raises(TrueApiHttpError):
        runtime.read_states([CIS])

    assert runtime.authenticated is False
    assert runtime._session is None


def test_cryptcp_absence_does_not_make_valid_ukep_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )

    status = bridge.discover(INN)

    assert status["cryptcp_available"] is False
    assert status["candidates"][0]["compatibility"] == "UNSUPPORTED"
    assert status["candidates"][0]["eligible"] is True


def test_expired_certificate_is_not_eligible_even_without_cryptcp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExpiredDiscovery:
        def discover(self) -> dict:
            data = FakeDiscovery().discover()
            data["candidates"][0]["valid_to"] = "2025-01-01T00:00:00+00:00"
            return data

    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=ExpiredDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )

    assert bridge.discover(INN)["candidates"][0]["eligible"] is False


def test_typed_prepare_complete_attempt_keeps_token_server_side_and_is_one_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = _runtime()
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "true_api_read.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )

    prepared = bridge.prepare_auth(INN, "browser-session-1")

    exact = " EXACT-CRPT-CHALLENGE\nЮникод ".encode("utf-8")
    import base64
    assert base64.b64decode(prepared["challenge_base64"]) == exact
    assert "uuid" not in prepared
    assert TOKEN not in repr(prepared)
    assert set(prepared) == {
        "attempt_id",
        "challenge_base64",
        "participant_inn",
        "expires_at",
        "read_only",
    }

    completed = bridge.complete_auth(
        INN,
        "browser-session-1",
        attempt_id=prepared["attempt_id"],
        signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
        selected_certificate_thumbprint=THUMBPRINT,
    )
    assert completed["authenticated"] is True
    assert TOKEN not in repr(completed)

    stored = (tmp_path / "true_api_read.json").read_text(encoding="utf-8")
    assert THUMBPRINT in stored and INN in stored
    assert TOKEN not in stored

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.complete_auth(
            INN,
            "browser-session-1",
            attempt_id=prepared["attempt_id"],
            signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
            selected_certificate_thumbprint=THUMBPRINT,
        )
    assert exc_info.value.code == "AUTH_ATTEMPT_INVALID"


def test_auth_attempt_rejects_wrong_session_and_wrong_thumbprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _ = _runtime()
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )
    prepared = bridge.prepare_auth(INN, "browser-session-1")

    with pytest.raises(LocalTrueApiUnavailable) as wrong_session:
        bridge.complete_auth(
            INN,
            "browser-session-2",
            attempt_id=prepared["attempt_id"],
            signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
            selected_certificate_thumbprint=THUMBPRINT,
        )
    assert wrong_session.value.code == "AUTH_ATTEMPT_MISMATCH"

    with pytest.raises(LocalTrueApiUnavailable) as wrong_cert:
        bridge.complete_auth(
            INN,
            "browser-session-1",
            attempt_id=prepared["attempt_id"],
            signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
            selected_certificate_thumbprint="B" * 40,
        )
    assert wrong_cert.value.code == "CERTIFICATE_NOT_ELIGIBLE"


def test_browser_cades_cms_signer_must_match_selected_thumbprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, transport = _runtime()
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: "B" * 40,
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )
    prepared = bridge.prepare_auth(INN, "browser-session-1")

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.complete_auth(
            INN,
            "browser-session-1",
            attempt_id=prepared["attempt_id"],
            signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
            selected_certificate_thumbprint=THUMBPRINT,
        )

    assert exc_info.value.code == "CERTIFICATE_NOT_ELIGIBLE"
    assert not any(call["path"] == "/auth/simpleSignIn" for call in transport.calls)


def test_expired_auth_attempt_is_rejected_before_simple_sign_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, transport = _runtime()
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )
    prepared = bridge.prepare_auth(INN, "browser-session-1")
    bridge._attempts[prepared["attempt_id"]].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.complete_auth(
            INN,
            "browser-session-1",
            attempt_id=prepared["attempt_id"],
            signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
            selected_certificate_thumbprint=THUMBPRINT,
        )

    assert exc_info.value.code == "AUTH_ATTEMPT_INVALID"
    assert not any(call["path"] == "/auth/simpleSignIn" for call in transport.calls)


def test_participant_inn_is_server_side_attempt_state_not_frontend_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = (Path(__file__).parents[1] / "src" / "wbcz_local" / "routes.py").read_text(
        encoding="utf-8"
    )
    assert "class BrowserAuthCompleteRequest" in source
    request_block = source.split("class BrowserAuthCompleteRequest", 1)[1].split("def _bridge", 1)[0]
    assert "participant_inn" not in request_block

    runtime, transport = _runtime()
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )
    prepared = bridge.prepare_auth(INN, "browser-session-1")
    bridge.complete_auth(
        INN,
        "browser-session-1",
        attempt_id=prepared["attempt_id"],
        signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
        selected_certificate_thumbprint=THUMBPRINT,
    )
    auth_call = next(call for call in transport.calls if call["path"] == "/auth/simpleSignIn")
    assert auth_call["body"]["inn"] == INN


def test_persisted_wrong_participant_certificate_blocks_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other_thumbprint = "B" * 40
    settings = tmp_path / "settings.json"
    settings.write_text(
        '{"thumbprint":"' + other_thumbprint + '","participant_inn":"' + INN + '"}',
        encoding="utf-8",
    )

    class OtherParticipantDiscovery:
        def discover(self) -> dict:
            return {
                "cryptopro_available": False,
                "candidates": [{
                    "thumbprint": other_thumbprint,
                    "subject": "CN=Other Participant, INN=9999999999",
                    "certificate_inn": "9999999999",
                    "valid_from": "2026-01-01T00:00:00+00:00",
                    "valid_to": "2027-01-01T00:00:00+00:00",
                    "has_private_key": True,
                    "compatibility": "UNSUPPORTED",
                    "crypto_provider": "Crypto-Pro GOST R 34.10-2012",
                    "public_key_oid": "1.2.643.7.1.1.1.1",
                }],
            }

    bridge = LocalTrueApiReadBridge(
        settings_path=settings,
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=OtherParticipantDiscovery(),
    )
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )
    build_calls = 0

    def forbidden_build(participant_inn: str):
        nonlocal build_calls
        build_calls += 1
        raise AssertionError("transport runtime must not be constructed")

    monkeypatch.setattr(bridge, "_build_runtime", forbidden_build)

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.read_states(INN, [CIS])

    assert exc_info.value.code == "CERTIFICATE_NOT_ELIGIBLE"
    assert build_calls == 0


def test_missing_stunnel_is_reported_as_transport_not_ready_not_cryptopro_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TransportBlockedRuntime:
        authenticated = False
        expire_date = None

        def prepare_auth_challenge(self):
            raise RuntimeError("stunnel missing")

        def close(self):
            pass

    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: TransportBlockedRuntime())
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": False,
            "cryptcp_available": False,
        })(),
    )

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.prepare_auth(INN, "browser-session-1")

    assert exc_info.value.code == "GOST_TRANSPORT_NOT_READY"
    assert "CryptoPro" not in str(exc_info.value)


def test_local_bridge_has_no_arbitrary_sign_or_business_mutation_method(tmp_path: Path) -> None:
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signer_thumbprint=lambda signature: THUMBPRINT,
    )
    public = {name for name in dir(bridge) if not name.startswith("_")}
    assert {"prepare_auth", "complete_auth", "read_states", "status"} <= public
    assert "authenticate" not in public
    assert "sign" not in public
    assert "sign_bytes" not in public
    assert "sign_file" not in public
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

    # Never mutate the shared/public test schema. Each local True API test gets
    # its own PostgreSQL schema and drops only that schema at teardown.
    schema = f"local_true_api_{uuid4().hex}"
    admin_engine = create_engine(DB_URL, future=True)
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_engine(
        DB_URL,
        future=True,
        connect_args={"options": f"-csearch_path={schema}"},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin_engine.dispose()


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
def test_local_fbs_control_rechecks_history_after_read_and_later_return_wins(
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

    class LaterReturnDuringReadBridge(StaticStateBridge):
        def read_states(self, participant_inn: str, cises):
            values = tuple(cises)
            self.calls.append((participant_inn, values))
            later_return = Event(
                kiz=CIS,
                task_number="local-task-2",
                sticker="local-sticker-2",
                operation=Operation.RETURN,
                occurred_at=datetime(2026, 9, 25, 13, 0, tzinfo=timezone.utc),
                receipt_number=None,
                fiscal_drive_number=None,
                amount=Decimal("1900.00"),
                currency="RUB",
                legal_entity_sale=False,
            )
            # Separate DB session simulates a rolling WB import committing while
            # the original control request is waiting on True API network I/O.
            with local_pg_factory() as other:
                bind_tenant_scope(
                    other,
                    organisation_id=org_id,
                    participant_id=participant_id,
                    user_id=user_id,
                    role="OWNER",
                )
                FileImportService(other).import_xlsx(
                    "later-return.xlsx",
                    _workbook_bytes(later_return),
                    user_id,
                )
                other.commit()
            return {cis: state for cis in values}

    bridge = LaterReturnDuringReadBridge(state=state)

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

        old_event_id = ImportRepository(db).ordered_event_records(import_id)[0].event_id
        check = ImportRepository(db).latest_check(old_event_id)
        assert check is not None
        assert check.source == "wb-sequence-policy"
        assert check.decision == Decision.NO_ACTION.value
        assert check.reason == "SUPERSEDED_BY_LATER_WB_EVENT"
        assert check.snapshot is None
        assert check.decision != Decision.READY_TO_WITHDRAW.value
        assert result["counts"].get(Decision.READY_TO_WITHDRAW.value, 0) == 0


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
