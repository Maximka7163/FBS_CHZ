from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import BytesIO
import base64
import inspect
import json
import os
import subprocess
from pathlib import Path
from uuid import uuid4

from openpyxl import Workbook
import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import sessionmaker

from wbcz.models import Decision, Event, KiState, Operation
from wbcz_ui.live_true_api import (
    GostTlsUnavailable,
    ProductionMutationDisabled,
    ReadOnlyTrueApiTransport,
    TrueApiError,
    TrueApiHttpError,
    WindowsCryptoProCertificateDiscovery,
    WindowsCryptoProCertificateInspector,
)
from wbcz_local.bridge import (
    LocalTrueApiReadBridge,
    LocalTrueApiReadRuntime,
    LocalTrueApiUnavailable,
    _browser_cades_signature_info,
)
import wbcz_local.stunnel_msspi as stunnel_module
from wbcz_local.stunnel_msspi import (
    GOST_ONLY_CIPHERS,
    PRIVATE_PORT_MAX,
    PRIVATE_PORT_MIN,
    PRODUCTION_HOST,
    PRODUCTION_PORT,
    STUNNEL_MSSPI_OFFICIAL_SHA256,
    StunnelMsspiTransport,
    TcpOwnerRow,
    _select_private_port,
    _windows_tcp_owner_rows,
    probe_stunnel_msspi,
    render_stunnel_msspi_config,
)
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
EXACT_CHALLENGE = " EXACT-CRPT-CHALLENGE\nЮникод "
EXACT_CHALLENGE_BYTES = EXACT_CHALLENGE.encode("utf-8")


def _powershell_json_payload(payload: dict) -> bytes:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(raw)


def _foundation_status(gost_ready: bool = True):
    return type("Status", (), {
        "csp_available": True,
        "csp_version": "5.0.13000",
        "csp_version_supported": True,
        "csp_technical_supported": True,
        "csp_compliance_status": "UNKNOWN",
        "csp_license_valid": True,
        "license_status": "VALID",
        "sspi_diagnostic_status": "AVAILABLE",
        "gost_transport_available": gost_ready,
        "winhttp_available": gost_ready,
        "cryptopro_tls_sspi_available": gost_ready,
        "winhttp_gost_transport_initializable": gost_ready,
        "cryptcp_available": False,
        "cryptcp_path": None,
        "readiness_reasons": () if gost_ready else ("WINHTTP_GOST_TRANSPORT_NOT_INITIALIZABLE",),
    })()


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
                "data": EXACT_CHALLENGE,
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


class _FakeStunnelProcess:
    def __init__(self, *, pid: int = 4242, exited: bool = False) -> None:
        self.pid = pid
        self.returncode = 1 if exited else None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class _FakeSocket:
    def __init__(
        self,
        *,
        client_port: int,
        server_port: int,
    ) -> None:
        self.client_port = client_port
        self.server_port = server_port

    def getsockname(self):
        return ("127.0.0.1", self.client_port)

    def getpeername(self):
        return ("127.0.0.1", self.server_port)


class _FakeHttpResponse:
    status = 200

    def __init__(self, payload: bytes = b'{"uuid":"u","data":"challenge"}') -> None:
        self.payload = payload

    def read(self, _limit: int) -> bytes:
        return self.payload


class _FakeHttpConnection:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        sink: list[dict],
        client_port: int = 61001,
        on_connect=None,
        response_payload: bytes = b'{"uuid":"u","data":"challenge"}',
    ) -> None:
        sink.append({"connect_host": host, "connect_port": port, "timeout": timeout})
        self.sink = sink
        self.sock = None
        self.client_port = client_port
        self.server_port = port
        self.on_connect = on_connect
        self.response_payload = response_payload

    def connect(self) -> None:
        if self.on_connect is not None:
            self.on_connect()
        self.sock = _FakeSocket(
            client_port=self.client_port,
            server_port=self.server_port,
        )
        self.sink.append({"tcp_connected": True})

    def request(self, method: str, target: str, *, body=None, headers=None) -> None:
        assert self.sock is not None
        self.sink.append({
            "method": method,
            "target": target,
            "body": body,
            "headers": dict(headers or {}),
        })

    def getresponse(self):
        return _FakeHttpResponse(self.response_payload)

    def close(self) -> None:
        self.sock = None


def _fake_stunnel_executable(tmp_path: Path) -> Path:
    executable = tmp_path / "stunnel_msspi.exe"
    executable.write_bytes(b"MZsynthetic-offline-test")
    return executable


def _trust_fake_stunnel_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        stunnel_module,
        "_sha256_file",
        lambda _path: STUNNEL_MSSPI_OFFICIAL_SHA256,
    )


def _owner_rows(
    *,
    child_pid: int,
    port: int,
    client_port: int = 61001,
    listener_pid: int | None = None,
    established_pid: int | None = None,
) -> tuple[TcpOwnerRow, ...]:
    return (
        TcpOwnerRow(
            state=2,
            local_address="127.0.0.1",
            local_port=port,
            remote_address="0.0.0.0",
            remote_port=0,
            owning_pid=child_pid if listener_pid is None else listener_pid,
        ),
        TcpOwnerRow(
            state=5,
            local_address="127.0.0.1",
            local_port=port,
            remote_address="127.0.0.1",
            remote_port=client_port,
            owning_pid=child_pid if established_pid is None else established_pid,
        ),
    )



def test_stunnel_msspi_config_is_fixed_loopback_gost_only_and_has_no_client_material() -> None:
    config = render_stunnel_msspi_config(55001)

    assert "accept = 127.0.0.1:55001" in config
    assert f"connect = {PRODUCTION_HOST}:{PRODUCTION_PORT}" in config
    assert f"sni = {PRODUCTION_HOST}" in config
    assert "verify = 2" in config
    assert f"checkHost = {PRODUCTION_HOST}" in config
    assert "sslVersion = TLSv1.2" in config
    assert f"ciphers = {GOST_ONLY_CIPHERS}" in config
    lower = config.casefold()
    assert "\ncert =" not in lower
    assert "\nkey =" not in lower
    assert "\npin =" not in lower
    assert "msspi = 0" not in lower
    assert "-install" not in lower


def test_stunnel_private_port_selector_returns_high_private_loopback_port() -> None:
    port = _select_private_port()
    assert PRIVATE_PORT_MIN <= port <= PRIVATE_PORT_MAX


def test_stunnel_probe_missing_executable_fails_closed(tmp_path: Path) -> None:
    probe = probe_stunnel_msspi(
        tmp_path / "missing-stunnel_msspi.exe",
        windows_supported=True,
    )

    assert probe.stunnel_msspi_present is False
    assert probe.stunnel_msspi_structural_ready is False
    assert "CRYPTOPRO_STUNNEL_MSSPI_MISSING" in probe.reasons
    assert probe.safe_dict()["true_api_live_verified"] is False


def test_fake_mz_stunnel_is_rejected_by_pinned_sha256(tmp_path: Path) -> None:
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)

    assert STUNNEL_MSSPI_OFFICIAL_SHA256 == (
        "C15491EA8EAB0ADB7F8F761337DF85DA335A57E3AA18D1CBC19B31D1EEA09F8B"
    )
    assert probe.stunnel_msspi_present is True
    assert probe.stunnel_msspi_authenticity_valid is False
    assert probe.stunnel_msspi_executable_valid is False
    assert probe.stunnel_msspi_structural_ready is False
    assert "CRYPTOPRO_STUNNEL_MSSPI_AUTHENTICITY_FAILED" in probe.reasons


@pytest.mark.parametrize("source", ["explicit", "env", "path"])
def test_all_discovery_sources_reject_substituted_stunnel_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    executable = _fake_stunnel_executable(tmp_path)
    monkeypatch.delenv("WBCZ_CRYPTOPRO_STUNNEL_MSSPI", raising=False)
    monkeypatch.setattr(stunnel_module.shutil, "which", lambda _name: None)

    explicit = None
    if source == "explicit":
        explicit = executable
    elif source == "env":
        monkeypatch.setenv(
            "WBCZ_CRYPTOPRO_STUNNEL_MSSPI",
            str(executable),
        )
    else:
        monkeypatch.setattr(
            stunnel_module.shutil,
            "which",
            lambda name: (
                str(executable)
                if name == stunnel_module.STUNNEL_MSSPI_FILENAME
                else None
            ),
        )

    probe = probe_stunnel_msspi(explicit, windows_supported=True)

    assert probe.stunnel_msspi_present is True
    assert probe.stunnel_msspi_authenticity_valid is False
    assert probe.stunnel_msspi_executable_valid is False
    assert probe.stunnel_msspi_structural_ready is False
    assert "CRYPTOPRO_STUNNEL_MSSPI_AUTHENTICITY_FAILED" in probe.reasons


def test_expected_digest_fixture_is_accepted_without_changing_production_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _fake_stunnel_executable(tmp_path)
    _trust_fake_stunnel_digest(monkeypatch)

    probe = probe_stunnel_msspi(executable, windows_supported=True)

    assert probe.stunnel_msspi_present is True
    assert probe.stunnel_msspi_authenticity_valid is True
    assert probe.stunnel_msspi_executable_valid is True
    assert probe.stunnel_msspi_config_supported is True
    assert probe.stunnel_msspi_structural_ready is True


def test_stunnel_transport_child_is_non_service_non_shell_fixed_loopback_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    process = _FakeStunnelProcess(pid=4242)
    popen_calls: list[dict] = []
    http_calls: list[dict] = []

    def popen_factory(args, **kwargs):
        popen_calls.append({"args": list(args), "kwargs": dict(kwargs)})
        return process

    def connection_factory(host, port, *, timeout):
        return _FakeHttpConnection(
            host,
            port,
            timeout=timeout,
            sink=http_calls,
            client_port=61001,
        )

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=popen_factory,
        connection_factory=connection_factory,
        port_selector=lambda: 55001,
        ownership_rows=lambda: _owner_rows(
            child_pid=4242,
            port=55001,
            client_port=61001,
        ),
        temp_root=tmp_path,
    )
    runtime = LocalTrueApiReadRuntime(
        participant_inn=INN,
        transport=transport,
    )

    uuid, challenge = runtime.prepare_auth_challenge()

    assert (uuid, challenge) == ("u", "challenge")
    assert len(popen_calls) == 1
    call = popen_calls[0]
    assert call["args"][0] == str(executable.resolve())
    assert len(call["args"]) == 2
    assert "-install" not in " ".join(call["args"]).casefold()
    assert call["kwargs"]["shell"] is False
    assert http_calls[0]["connect_host"] == "127.0.0.1"
    assert http_calls[0]["connect_port"] == 55001
    request = next(item for item in http_calls if item.get("method") == "GET")
    assert request["target"] == "/api/v3/true-api/auth/key"
    assert request["headers"]["Host"] == PRODUCTION_HOST
    assert transport.tls_diagnostics()["startup_pid_ownership_verified"] is True
    assert transport.tls_diagnostics()["true_api_live_verified"] is True
    config_path = transport._config_path
    assert config_path is not None and config_path.is_file()
    config_text = config_path.read_text(encoding="ascii")
    assert "accept = 127.0.0.1:55001" in config_text
    assert f"connect = {PRODUCTION_HOST}:{PRODUCTION_PORT}" in config_text

    runtime.close()

    assert process.terminated is True
    assert config_path.exists() is False


def test_attacker_listener_occupying_selected_port_fails_before_http_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    process = _FakeStunnelProcess(pid=4242)
    http_calls: list[dict] = []

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=lambda *_args, **_kwargs: process,
        connection_factory=lambda host, port, timeout: _FakeHttpConnection(
            host, port, timeout=timeout, sink=http_calls
        ),
        port_selector=lambda: 55005,
        ownership_rows=lambda: _owner_rows(
            child_pid=4242,
            port=55005,
            listener_pid=9999,
            established_pid=9999,
        ),
        temp_root=tmp_path,
    )

    with pytest.raises(
        GostTlsUnavailable,
        match="STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_MISMATCH",
    ):
        transport.request_json("GET", "/auth/key")

    assert http_calls == []
    assert transport.tls_diagnostics()["true_api_live_verified"] is False


def test_fake_auth_key_listener_pid_mismatch_receives_no_http_and_cannot_mark_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    process = _FakeStunnelProcess(pid=4242)
    http_calls: list[dict] = []

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=lambda *_args, **_kwargs: process,
        connection_factory=lambda host, port, timeout: _FakeHttpConnection(
            host,
            port,
            timeout=timeout,
            sink=http_calls,
            client_port=61002,
            response_payload=b'{"uuid":"fake","data":"fake"}',
        ),
        port_selector=lambda: 55006,
        ownership_rows=lambda: _owner_rows(
            child_pid=4242,
            port=55006,
            client_port=61002,
            established_pid=9999,
        ),
        temp_root=tmp_path,
    )

    with pytest.raises(
        GostTlsUnavailable,
        match="STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_MISMATCH",
    ):
        transport.request_json("GET", "/auth/key")

    assert not any(item.get("method") for item in http_calls)
    assert transport.tls_diagnostics()["true_api_live_verified"] is False


def test_bearer_request_ownership_mismatch_sends_no_authorization_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    process = _FakeStunnelProcess(pid=4242)
    http_calls: list[dict] = []

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=lambda *_args, **_kwargs: process,
        connection_factory=lambda host, port, timeout: _FakeHttpConnection(
            host,
            port,
            timeout=timeout,
            sink=http_calls,
            client_port=61003,
        ),
        port_selector=lambda: 55007,
        ownership_rows=lambda: _owner_rows(
            child_pid=4242,
            port=55007,
            client_port=61003,
            established_pid=9999,
        ),
        temp_root=tmp_path,
    )

    with pytest.raises(
        GostTlsUnavailable,
        match="STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_MISMATCH",
    ):
        transport.request_json(
            "POST",
            "/cises/info",
            params={"pg": "lp"},
            body=[CIS],
            bearer_token="ATTACKER-MUST-NOT-SEE-THIS",
            cis_count=1,
        )

    requests = [item for item in http_calls if item.get("method")]
    assert requests == []
    assert "ATTACKER-MUST-NOT-SEE-THIS" not in repr(http_calls)


def test_child_exit_after_startup_fails_before_http_request_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    process = _FakeStunnelProcess(pid=4242)
    http_calls: list[dict] = []

    def connection_factory(host, port, *, timeout):
        return _FakeHttpConnection(
            host,
            port,
            timeout=timeout,
            sink=http_calls,
            client_port=61004,
            on_connect=lambda: setattr(process, "returncode", 1),
        )

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=lambda *_args, **_kwargs: process,
        connection_factory=connection_factory,
        port_selector=lambda: 55008,
        ownership_rows=lambda: _owner_rows(
            child_pid=4242,
            port=55008,
            client_port=61004,
        ),
        temp_root=tmp_path,
    )

    with pytest.raises(
        GostTlsUnavailable,
        match="STUNNEL_MSSPI_CHILD_EXITED_EARLY",
    ):
        transport.request_json("GET", "/auth/key")

    assert not any(item.get("method") for item in http_calls)
    assert transport.tls_diagnostics()["true_api_live_verified"] is False


def test_invalid_auth_key_payload_never_sets_live_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    process = _FakeStunnelProcess(pid=4242)
    http_calls: list[dict] = []

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=lambda *_args, **_kwargs: process,
        connection_factory=lambda host, port, timeout: _FakeHttpConnection(
            host,
            port,
            timeout=timeout,
            sink=http_calls,
            client_port=61005,
            response_payload=b'{"uuid":"","data":"fake"}',
        ),
        port_selector=lambda: 55009,
        ownership_rows=lambda: _owner_rows(
            child_pid=4242,
            port=55009,
            client_port=61005,
        ),
        temp_root=tmp_path,
    )
    runtime = LocalTrueApiReadRuntime(participant_inn=INN, transport=transport)

    with pytest.raises(TrueApiError, match="uuid/data"):
        runtime.prepare_auth_challenge()

    assert transport.tls_diagnostics()["true_api_live_verified"] is False
    runtime.close()


def test_stunnel_child_startup_failure_fails_closed_and_cleans_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)

    def popen_factory(_args, **_kwargs):
        raise OSError("synthetic startup failure")

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=popen_factory,
        port_selector=lambda: 55002,
        ownership_rows=lambda: (),
        temp_root=tmp_path,
    )

    with pytest.raises(GostTlsUnavailable, match="STUNNEL_MSSPI_CHILD_START_FAILED"):
        transport.request_json("GET", "/auth/key")

    assert transport._config_path is None
    assert transport._temp_dir is None


def test_stunnel_child_early_exit_fails_closed_and_cleans_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    process = _FakeStunnelProcess(pid=4242, exited=True)
    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=lambda *_args, **_kwargs: process,
        port_selector=lambda: 55003,
        ownership_rows=lambda: (),
        temp_root=tmp_path,
    )

    with pytest.raises(GostTlsUnavailable, match="STUNNEL_MSSPI_CHILD_EXITED_EARLY"):
        transport.request_json("GET", "/auth/key")

    assert transport._config_path is None
    assert transport._temp_dir is None


def test_stunnel_allowlist_blocks_writes_before_child_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_stunnel_digest(monkeypatch)
    executable = _fake_stunnel_executable(tmp_path)
    probe = probe_stunnel_msspi(executable, windows_supported=True)
    starts = 0

    def popen_factory(*_args, **_kwargs):
        nonlocal starts
        starts += 1
        return _FakeStunnelProcess()

    transport = StunnelMsspiTransport(
        executable_path=executable,
        validated_probe=probe,
        popen_factory=popen_factory,
        port_selector=lambda: 55004,
        ownership_rows=lambda: (),
        temp_root=tmp_path,
    )

    with pytest.raises(ProductionMutationDisabled):
        transport.request_json("POST", "/lk/documents/create", body={})
    with pytest.raises(ProductionMutationDisabled):
        transport.request_json("POST", "/cises/info", params={"pg": "shoes"}, body=[])
    with pytest.raises(ProductionMutationDisabled):
        transport.request_json("GET", "/auth/key", params={"unexpected": "1"})

    assert starts == 0
    transport.close()


def test_local_true_api_runtime_has_no_direct_winhttp_fallback() -> None:
    source = inspect.getsource(LocalTrueApiReadBridge._build_runtime)
    assert "StunnelMsspiTransport" in source
    assert "WindowsWinHttpGostTransport" not in source


def test_missing_stunnel_msspi_is_exact_readiness_error_and_local_ready_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "csp_version": "5.0.13455",
            "csp_version_supported": True,
            "csp_technical_supported": True,
            "csp_compliance_status": "UNCERTIFIED",
            "csp_license_valid": True,
            "license_status": "VALID",
            "sspi_diagnostic_status": "AVAILABLE",
            "gost_transport_available": False,
            "stunnel_msspi_present": False,
            "stunnel_msspi_executable_valid": False,
            "stunnel_msspi_config_supported": True,
            "stunnel_msspi_structural_ready": False,
            "winhttp_available": True,
            "cryptopro_tls_sspi_available": True,
            "winhttp_gost_transport_initializable": True,
            "cryptcp_available": False,
            "cryptcp_path": None,
            "readiness_reasons": ("CRYPTOPRO_STUNNEL_MSSPI_MISSING",),
        })(),
    )

    status = bridge.status(INN)

    assert status["error_code"] == "CRYPTOPRO_STUNNEL_MSSPI_MISSING"
    assert status["stunnel_msspi_present"] is False
    assert status["stunnel_msspi_structural_ready"] is False
    assert status["true_api_local_ready"] is False
    assert status["true_api_live_verified"] is False


def _browser_auth(runtime: LocalTrueApiReadRuntime) -> dict:
    uuid, challenge = runtime.prepare_auth_challenge()
    assert uuid == "challenge-uuid"
    assert challenge == EXACT_CHALLENGE
    return runtime.complete_auth(
        uuid=uuid,
        signature_base64="BROWSER-CADES-ATTACHED-SIGNATURE",
    )


def test_local_runtime_preserves_exact_challenge_and_keeps_uuid_token_in_memory() -> None:
    runtime, transport = _runtime()

    uuid, challenge = runtime.prepare_auth_challenge()
    assert uuid == "challenge-uuid"
    assert challenge.encode("utf-8") == EXACT_CHALLENGE_BYTES
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


def test_browser_cades_cms_cryptographic_verification_precedes_signer_and_content_trust() -> None:
    captured: dict[str, str] = {}

    def runner(args, **kwargs):
        script = args[-1]
        captured["script"] = script
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps({
                "thumbprint": THUMBPRINT,
                "contentBase64": base64.b64encode(EXACT_CHALLENGE_BYTES).decode("ascii"),
            }),
            stderr="",
        )

    thumbprint, content = _browser_cades_signature_info(
        "SYNTHETIC-ATTACHED-CMS",
        runner=runner,
    )

    script = captured["script"]
    verify_index = script.index("$cms.CheckSignature($true)")
    certificate_index = script.index("$cert=$cms.SignerInfos[0].Certificate")
    output_index = script.index("[pscustomobject]@{")
    assert verify_index < certificate_index < output_index
    assert thumbprint == THUMBPRINT
    assert content == EXACT_CHALLENGE_BYTES


def test_browser_cades_invalid_or_tampered_cms_is_rejected_by_local_crypto_check() -> None:
    def runner(args, **kwargs):
        script = args[-1]
        assert "$cms.CheckSignature($true)" in script
        return subprocess.CompletedProcess(
            args,
            1,
            stdout="",
            stderr="Exception calling CheckSignature: invalid signature",
        )

    with pytest.raises(TrueApiError, match="invalid signature"):
        _browser_cades_signature_info(
            "CORRUPTED-CMS",
            runner=runner,
        )


def test_invalid_cms_never_reaches_true_api_simple_sign_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, transport = _runtime()

    def invalid_cms(_signature: str):
        raise TrueApiError("synthetic cryptographic CMS verification failure")

    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signature_info=invalid_cms,
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
    )
    prepared = bridge.prepare_auth(INN, "browser-session-1")

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.complete_auth(
            INN,
            "browser-session-1",
            attempt_id=prepared["attempt_id"],
            signature_base64="CORRUPTED-CMS",
            selected_certificate_thumbprint=THUMBPRINT,
        )

    assert exc_info.value.code == "CADES_SIGNER_VALIDATION_FAILED"
    assert not any(call["path"] == "/auth/simpleSignIn" for call in transport.calls)


def test_cryptcp_absence_does_not_make_valid_ukep_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
    )

    status = bridge.discover(INN)

    assert status["cryptcp_available"] is False
    assert status["candidates"][0]["compatibility"] == "GOST_CRYPTOPRO"
    assert status["candidates"][0]["eligible"] is True


if os.name == "nt":
    def test_real_windows_certificate_discovery_reads_current_user_my_without_cryptcp() -> None:
        discovery = WindowsCryptoProCertificateDiscovery(
            cryptcp_path="C:/missing/cryptcp.exe",
        )
        inventory = discovery.discover()
        assert isinstance(inventory["candidates"], list)
        assert inventory["cryptcp_available"] is False
        assert inventory["discovery_state"] == "OK"


    def test_real_windows_tcp_ownership_table_structural() -> None:
        rows = _windows_tcp_owner_rows()

        assert isinstance(rows, tuple)
        for row in rows:
            assert isinstance(row.owning_pid, int)
            assert isinstance(row.local_port, int)
            assert isinstance(row.remote_port, int)


    def test_real_windows_stunnel_msspi_probe_is_offline_structural_only() -> None:
        probe = probe_stunnel_msspi()
        safe = probe.safe_dict()

        assert safe["true_api_live_verified"] is False
        assert safe["canonical_transport"] == "CRYPTOPRO_STUNNEL_MSSPI_CHILD_PROCESS"
        if not probe.stunnel_msspi_present:
            assert "CRYPTOPRO_STUNNEL_MSSPI_MISSING" in probe.reasons


def test_windows_certificate_discovery_enumerates_current_user_my_without_cryptcp() -> None:
    captured: dict[str, object] = {}
    payload = {
        "certificates": [{
            "thumbprint": THUMBPRINT,
            "subject": f"CN=Тестовая организация, OID.1.2.643.100.4={INN}",
            "issuer": "CN=Идентификация УЦ",
            "serial": "1234",
            "hasPrivateKey": True,
            "notBefore": "2026-01-01T00:00:00.0000000Z",
            "notAfter": "2027-01-01T00:00:00.0000000Z",
            "publicKeyOid": "1.2.643.7.1.1.1.1",
            "signatureOid": "1.2.643.7.1.1.3.2",
            "providerName": "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
        }],
        "skippedCount": 0,
    }
    raw_json = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    transported = _powershell_json_payload(payload)
    assert b"\x98" in raw_json
    assert all(byte < 128 for byte in transported)

    def runner(args, **kwargs):
        captured["script"] = args[-1]
        captured["text"] = kwargs.get("text")
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=transported,
            stderr=b"",
        )

    discovery = WindowsCryptoProCertificateDiscovery(
        cryptcp_path="C:/definitely/not/required/cryptcp.exe",
        runner=runner,
    )
    inventory = discovery.discover()

    candidate = inventory["candidates"][0]
    assert candidate["compatibility"] == "GOST_CRYPTOPRO"
    assert candidate["certificate_inn"] == INN
    assert candidate["subject"] == f"CN=Тестовая организация, OID.1.2.643.100.4={INN}"
    assert candidate["issuer"] == "CN=Идентификация УЦ"
    assert candidate["has_private_key"] is True
    assert candidate["public_key_oid"] == "1.2.643.7.1.1.1.1"
    assert inventory["cryptcp_available"] is False
    assert inventory["discovery_state"] == "OK"
    assert captured["text"] is False
    assert "X509Store('My','CurrentUser')" in str(captured["script"])
    assert "$cert.GetKeyAlgorithm()" in str(captured["script"])
    assert "OpenStandardOutput" in str(captured["script"])
    assert "cryptcp.exe" not in str(captured["script"])


def _certificate_candidate_for_inns(*inns: str) -> dict:
    return {
        "thumbprint": THUMBPRINT,
        "certificate_inn": inns[0] if inns else None,
        "certificate_inns": list(inns),
        "valid_from": "2026-01-01T00:00:00+00:00",
        "valid_to": "2027-01-01T00:00:00+00:00",
        "has_private_key": True,
        "crypto_provider": "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
        "public_key_oid": "1.2.643.7.1.1.1.1",
    }


@pytest.mark.parametrize(
    ("subject", "expected"),
    [
        (
            "CN=Организация, INN=1234567890, "
            "OID.1.2.643.3.131.1.1=027504733612",
            ["1234567890", "027504733612"],
        ),
        (
            "CN=Организация, OID.1.2.643.3.131.1.1=027504733612, "
            "INN=1234567890",
            ["027504733612", "1234567890"],
        ),
    ],
)
def test_certificate_discovery_parses_all_inns_and_eligibility_is_order_independent(
    subject: str,
    expected: list[str],
) -> None:
    payload = {
        "certificates": [{
            "thumbprint": THUMBPRINT,
            "subject": subject,
            "issuer": "CN=УЦ",
            "serial": "1234",
            "hasPrivateKey": True,
            "notBefore": "2026-01-01T00:00:00.0000000Z",
            "notAfter": "2027-01-01T00:00:00.0000000Z",
            "publicKeyOid": "1.2.643.7.1.1.1.1",
            "signatureOid": "1.2.643.7.1.1.3.2",
            "providerName": "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
        }],
        "skippedCount": 0,
    }

    def runner(args, **kwargs):
        assert kwargs["text"] is False
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=_powershell_json_payload(payload),
            stderr=b"",
        )

    inventory = WindowsCryptoProCertificateDiscovery(runner=runner).discover()
    candidate = inventory["candidates"][0]

    assert candidate["certificate_inns"] == expected
    assert candidate["certificate_inn"] == expected[0]
    assert LocalTrueApiReadBridge._eligible(candidate, "027504733612") is True


@pytest.mark.parametrize("participant_inn", ["1234567890", "027504733612"])
def test_single_certificate_inn_keeps_10_and_12_digit_eligibility(
    participant_inn: str,
) -> None:
    candidate = _certificate_candidate_for_inns(participant_inn)
    assert LocalTrueApiReadBridge._eligible(candidate, participant_inn) is True


def test_certificate_discovery_ignores_unbound_digit_strings_and_deduplicates_aliases() -> None:
    payload = {
        "certificates": [{
            "thumbprint": THUMBPRINT,
            "subject": (
                "CN=1234567890, SERIALNUMBER=027504733612, "
                "XINN=9999999999, INN=027504733612, "
                "OID.1.2.643.100.4=027504733612, "
                "OID.1.2.643.3.131.1.1=027504733612"
            ),
            "issuer": "CN=УЦ 9999999999",
            "serial": "1234",
            "hasPrivateKey": True,
            "notBefore": "2026-01-01T00:00:00.0000000Z",
            "notAfter": "2027-01-01T00:00:00.0000000Z",
            "publicKeyOid": "1.2.643.7.1.1.1.1",
            "signatureOid": "1.2.643.7.1.1.3.2",
            "providerName": "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
        }],
        "skippedCount": 0,
    }

    def runner(args, **kwargs):
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=_powershell_json_payload(payload),
            stderr=b"",
        )

    candidate = WindowsCryptoProCertificateDiscovery(runner=runner).discover()["candidates"][0]

    assert candidate["certificate_inns"] == ["027504733612"]
    assert candidate["certificate_inn"] == "027504733612"


def test_multi_inn_certificate_rejects_other_participant() -> None:
    candidate = _certificate_candidate_for_inns("1234567890", "027504733612")
    assert LocalTrueApiReadBridge._eligible(candidate, "111111111111") is False


@pytest.mark.parametrize(
    ("subject", "expected"),
    [
        ("CN=INN=027504733612", []),
        ("CN=X-INN=027504733612", []),
        ("X-INN=027504733612", []),
        ("FOO-INN=027504733612", []),
        ("CN=foo-INN=027504733612", []),
        ("SERIALNUMBER=027504733612", []),
        ("CN=027504733612", []),
        ('CN="Org, INN=027504733612"', []),
        (r"CN=Org\, INN=027504733612", []),
        ("INN=027504733612", ["027504733612"]),
        ("ИНН=027504733612", ["027504733612"]),
        ("OID.1.2.643.3.131.1.1=027504733612", ["027504733612"]),
        ("OID.1.2.643.100.4=1234567890", ["1234567890"]),
        ("CN=Org, INN=027504733612", ["027504733612"]),
        ("CN=Org,INN=027504733612", ["027504733612"]),
        (
            "CN=Org, OID.1.2.643.3.131.1.1=027504733612",
            ["027504733612"],
        ),
        ("CN=Org, INN : 027504733612", ["027504733612"]),
    ],
)
def test_certificate_inn_parser_requires_real_dn_attribute_boundary(
    subject: str,
    expected: list[str],
) -> None:
    payload = {
        "certificates": [{
            "thumbprint": THUMBPRINT,
            "subject": subject,
            "issuer": "CN=УЦ",
            "serial": "1234",
            "hasPrivateKey": True,
            "notBefore": "2026-01-01T00:00:00.0000000Z",
            "notAfter": "2027-01-01T00:00:00.0000000Z",
            "publicKeyOid": "1.2.643.7.1.1.1.1",
            "signatureOid": "1.2.643.7.1.1.3.2",
            "providerName": "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
        }],
        "skippedCount": 0,
    }

    def runner(args, **kwargs):
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=_powershell_json_payload(payload),
            stderr=b"",
        )

    candidate = WindowsCryptoProCertificateDiscovery(runner=runner).discover()["candidates"][0]

    assert candidate["certificate_inns"] == expected
    assert candidate["certificate_inn"] == (expected[0] if expected else None)


def test_windows_certificate_inspector_uses_same_binary_unicode_transport(
    tmp_path: Path,
) -> None:
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"")
    provider = (
        "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider "
        "— Тестовый провайдер"
    )
    payload = {
        "thumbprint": THUMBPRINT,
        "hasPrivateKey": True,
        "notBefore": "2026-01-01T00:00:00.0000000Z",
        "notAfter": "2027-01-01T00:00:00.0000000Z",
        "publicKeyOid": "1.2.643.7.1.1.1.1",
        "signatureOid": "1.2.643.7.1.1.3.2",
        "providerName": provider,
    }
    captured: dict[str, object] = {}

    def runner(args, **kwargs):
        captured["text"] = kwargs.get("text")
        captured["script"] = args[-1]
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=_powershell_json_payload(payload),
            stderr=b"",
        )

    inspector = WindowsCryptoProCertificateInspector(
        THUMBPRINT,
        cryptcp_path=cryptcp,
        runner=runner,
    )
    result = inspector.inspect()

    assert result["provider"] == provider
    assert result["gost_compatible"] is True
    assert result["cryptopro_provider"] is True
    assert captured["text"] is False
    assert "OpenStandardOutput" in str(captured["script"])


def test_certificate_powershell_failure_handles_non_utf8_stderr_without_decode_crash(
    tmp_path: Path,
) -> None:
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"")

    def runner(args, **kwargs):
        assert kwargs["text"] is False
        return subprocess.CompletedProcess(
            args,
            7,
            stdout=b"",
            stderr=b"failure:\xff\xfe\x98",
        )

    discovery = WindowsCryptoProCertificateDiscovery(runner=runner)
    with pytest.raises(TrueApiError) as discovery_error:
        discovery.discover()
    assert "failure:" in str(discovery_error.value)

    inspector = WindowsCryptoProCertificateInspector(
        THUMBPRINT,
        cryptcp_path=cryptcp,
        runner=runner,
    )
    with pytest.raises(TrueApiError) as inspector_error:
        inspector.inspect()
    assert "failure:" in str(inspector_error.value)


@pytest.mark.parametrize("stdout", [None, b"", b"not-base64%%%"])
def test_certificate_powershell_empty_or_malformed_success_is_typed(
    tmp_path: Path,
    stdout,
) -> None:
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"")

    def runner(args, **kwargs):
        assert kwargs["text"] is False
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=stdout,
            stderr=b"",
        )

    discovery = WindowsCryptoProCertificateDiscovery(runner=runner)
    with pytest.raises(TrueApiError, match="Certificate discovery returned invalid data"):
        discovery.discover()

    inspector = WindowsCryptoProCertificateInspector(
        THUMBPRINT,
        cryptcp_path=cryptcp,
        runner=runner,
    )
    with pytest.raises(TrueApiError, match="Certificate diagnostics returned invalid data"):
        inspector.inspect()


def test_certificate_discovery_failure_is_distinct_from_no_eligible_certificate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenDiscovery:
        def discover(self):
            raise TrueApiError("synthetic store failure")

    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
    )
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=BrokenDiscovery(),
    )

    status = bridge.discover(INN)
    assert status["ukep_state"] == "DISCOVERY_FAILED"
    assert status["ukep_available"] is False
    assert status["candidates"] == []
    assert status["error_code"] == "CRYPTOPRO_CERTIFICATE_DISCOVERY_FAILED"

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.prepare_auth(INN, "browser-session-1")
    assert exc_info.value.code == "CERTIFICATE_DISCOVERY_FAILED"


def test_successful_discovery_with_no_eligible_certificate_reports_not_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyDiscovery:
        def discover(self):
            return {"cryptopro_available": True, "candidates": []}

    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
    )
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=EmptyDiscovery(),
    )

    status = bridge.discover(INN)
    assert status["ukep_state"] == "NOT_VISIBLE"
    assert status["error_code"] == "NO_ELIGIBLE_CERTIFICATE"

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.prepare_auth(INN, "browser-session-1")
    assert exc_info.value.code == "NO_ELIGIBLE_CERTIFICATE"


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
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
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
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
    )

    prepared = bridge.prepare_auth(INN, "browser-session-1")

    exact = EXACT_CHALLENGE_BYTES
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
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
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
        cms_signature_info=lambda signature: ("B" * 40, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
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


def test_browser_cades_attached_content_must_match_exact_auth_challenge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, transport = _runtime()
    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signature_info=lambda signature: (
            THUMBPRINT,
            b"DIFFERENT-CONTENT",
        ),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
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

    assert exc_info.value.code == "AUTH_CHALLENGE_MISMATCH"
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
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
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
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(True),
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
        lambda: _foundation_status(True),
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


def test_missing_gost_transport_on_authenticated_read_preserves_transport_error_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"thumbprint": THUMBPRINT, "participant_inn": INN}),
        encoding="utf-8",
    )

    class ReadTransportBlockedRuntime:
        authenticated = True
        expire_date = datetime.now(timezone.utc) + timedelta(hours=1)

        def __init__(self) -> None:
            self.read_calls = 0

        def read_states(self, cises):
            self.read_calls += 1
            raise GostTlsUnavailable("native WinHTTP unavailable")

        def close(self):
            pass

    runtime = ReadTransportBlockedRuntime()
    bridge = LocalTrueApiReadBridge(
        settings_path=settings,
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: runtime)
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(False),
    )

    with pytest.raises(LocalTrueApiUnavailable) as exc_info:
        bridge.read_states(INN, [CIS])

    assert exc_info.value.code == "GOST_TRANSPORT_NOT_READY"
    assert runtime.read_calls == 1


def test_missing_native_winhttp_is_reported_as_transport_not_ready_not_cryptopro_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TransportBlockedRuntime:
        authenticated = False
        expire_date = None

        def prepare_auth_challenge(self):
            raise RuntimeError("native WinHTTP missing")

        def close(self):
            pass

    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(bridge, "_build_runtime", lambda participant_inn: TransportBlockedRuntime())
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: _foundation_status(False),
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
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
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



def test_live_verified_tracks_gost_transport_before_true_api_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Runtime:
        authenticated = False
        expire_date = None

        class Transport:
            @staticmethod
            def tls_diagnostics():
                return {
                    "mechanism": "Windows WinHTTP / SSPI / CryptoPro GOST TLS",
                    "gost_session_verified": True,
                }

        transport = Transport()

        def close(self):
            pass

    bridge = LocalTrueApiReadBridge(
        settings_path=tmp_path / "settings.json",
        audit_log_path=tmp_path / "audit.jsonl",
        discovery=FakeDiscovery(),
        cms_signature_info=lambda signature: (THUMBPRINT, EXACT_CHALLENGE_BYTES),
    )
    monkeypatch.setattr(
        "wbcz_local.bridge.inspect_local_cryptopro_foundation",
        lambda: type("Status", (), {
            "csp_available": True,
            "gost_transport_available": True,
            "cryptcp_available": False,
        })(),
    )
    bridge._runtime = Runtime()
    bridge._runtime_key = INN

    status = bridge.status(INN)

    assert status["authenticated"] is False
    assert status["gost_session_verified"] is True
    assert status["true_api_live_verified"] is True
