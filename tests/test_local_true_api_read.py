from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from wbcz.models import KiState
from wbcz_ui.live_true_api import ProductionMutationDisabled, ReadOnlyTrueApiTransport, TrueApiHttpError
from wbcz_local.bridge import LocalTrueApiReadBridge, LocalTrueApiReadRuntime


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
