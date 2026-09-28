from __future__ import annotations

import ctypes
from dataclasses import replace
from pathlib import Path
import subprocess

import pytest

import wbcz_local.winhttp_gost as native_module
from wbcz_local.winhttp_gost import (
    APPROVED_GOST_CIPHER_SUITES,
    NativeHttpResponse,
    PRODUCTION_HOST,
    PRODUCTION_PORT,
    WindowsWinHttpGostTransport,
    _WinHttpNative,
    evaluate_true_api_local_readiness,
    probe_native_gost_transport,
)
from wbcz_ui.live_true_api import GostTlsUnavailable, ProductionMutationDisabled


class MemoryAudit:
    def __init__(self) -> None:
        self.rows = []

    def record(self, **kwargs) -> None:
        self.rows.append(kwargs)


class FakeNative:
    def __init__(self, cipher_suite: int = 0xC100) -> None:
        self.cipher_suite = cipher_suite
        self.calls = []

    def request(self, **kwargs):
        self.calls.append(kwargs)
        return NativeHttpResponse(
            status=200,
            body=b'{"uuid":"u","data":"challenge"}',
            cipher_suite=self.cipher_suite,
            cipher_suite_name="TLS_GOST_SYNTHETIC",
        )


def test_winhttp_transport_is_fixed_secure_production_boundary() -> None:
    native = FakeNative()
    transport = WindowsWinHttpGostTransport(native=native, audit=MemoryAudit())

    assert transport.request_json("GET", "/auth/key") == {
        "uuid": "u",
        "data": "challenge",
    }
    assert native.calls[0]["host"] == PRODUCTION_HOST
    assert native.calls[0]["port"] == PRODUCTION_PORT
    assert native.calls[0]["target"] == "/api/v3/true-api/auth/key"
    assert transport.tls_diagnostics()["gost_session_verified"] is True

    with pytest.raises(ValueError):
        WindowsWinHttpGostTransport(
            base_url="https://example.invalid/api/v3/true-api", native=native
        )
    with pytest.raises(ValueError):
        WindowsWinHttpGostTransport(target_host="example.invalid", native=native)
    with pytest.raises(ValueError):
        WindowsWinHttpGostTransport(target_port=8443, native=native)


def test_allowlist_and_pg_contract_fail_before_native_io() -> None:
    native = FakeNative()
    transport = WindowsWinHttpGostTransport(native=native)

    with pytest.raises(ProductionMutationDisabled):
        transport.request_json("POST", "/lk/documents/create", body={})
    with pytest.raises(ProductionMutationDisabled):
        transport.request_json("POST", "/cises/info", params={"pg": "shoes"}, body=[])
    with pytest.raises(ProductionMutationDisabled):
        transport.request_json("GET", "/auth/key", params={"unexpected": "1"})

    assert native.calls == []


def test_non_gost_cipher_fails_closed_without_fallback() -> None:
    native = FakeNative(cipher_suite=0x1301)
    transport = WindowsWinHttpGostTransport(native=native)

    with pytest.raises(GostTlsUnavailable, match="GOST_TLS_NOT_NEGOTIATED"):
        transport.request_json("GET", "/auth/key")

    assert len(native.calls) == 1
    assert transport.tls_diagnostics()["gost_session_verified"] is False


def test_approved_gost_cipher_ids_are_explicit_and_narrow() -> None:
    assert APPROVED_GOST_CIPHER_SUITES == {0xC100, 0xC101, 0xC102}


class FakeWinHttp:
    def __init__(self) -> None:
        self.open_request_flags = None
        self.connect_target = None
        self.options = []

    def WinHttpOpen(self, *_args):
        return 1

    def WinHttpConnect(self, _session, host, port, _reserved):
        self.connect_target = (host, port)
        return 2

    def WinHttpOpenRequest(
        self, _connect, _method, _target, _version, _referrer, _accept, flags
    ):
        self.open_request_flags = flags
        return 3

    def WinHttpSetTimeouts(self, *_args):
        return 1

    def WinHttpSetOption(self, handle, option, buffer, size):
        self.options.append((handle, option, buffer is None, size))
        return 1

    def WinHttpAddRequestHeaders(self, *_args):
        return 1

    def WinHttpSendRequest(self, *_args):
        return 1

    def WinHttpReceiveResponse(self, *_args):
        return 1

    def WinHttpQueryOption(self, _request, option, buffer, _size):
        assert option == 151
        security = buffer._obj
        security.CipherInfo.dwCipherSuite = 0xC100
        security.CipherInfo.szCipherSuite = "TLS_GOST_SYNTHETIC"
        return 1

    def WinHttpQueryHeaders(self, _request, info, _name, buffer, size, _index):
        assert info == (19 | 0x20000000)
        buffer._obj.value = 200
        size._obj.value = 4
        return 1

    def WinHttpQueryDataAvailable(self, _request, available):
        available._obj.value = 0
        return 1

    def WinHttpReadData(self, *_args):
        raise AssertionError("empty body must not read")

    def WinHttpCloseHandle(self, _handle):
        return 1


def test_native_wrapper_enforces_secure_request_no_client_cert_and_no_redirects() -> None:
    winhttp = FakeWinHttp()

    def loader(name: str):
        return winhttp if name == "winhttp.dll" else object()

    native = _WinHttpNative(dll_loader=loader)
    response = native.request(
        host=PRODUCTION_HOST,
        port=PRODUCTION_PORT,
        method="GET",
        target="/api/v3/true-api/auth/key",
        headers={"Accept": "application/json"},
        body=None,
        timeout_ms=1000,
    )

    assert response.status == 200
    assert response.cipher_suite == 0xC100
    assert winhttp.connect_target == (PRODUCTION_HOST, PRODUCTION_PORT)
    assert winhttp.open_request_flags == 0x00800000
    assert any(option == 88 for _, option, _, _ in winhttp.options)
    assert any(
        option == 47 and null_buffer and size == 0
        for _, option, null_buffer, size in winhttp.options
    )


def test_native_wrapper_has_no_cert_ignore_or_tls_fallback() -> None:
    source = Path(native_module.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "SECURITY_FLAG_IGNORE_UNKNOWN_CA",
        "SECURITY_FLAG_IGNORE_CERT_CN_INVALID",
        "SECURITY_FLAG_IGNORE_CERT_DATE_INVALID",
        "SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE",
        "http.client",
        "HTTPSConnection",
        "requests.",
        "httpx.",
        "ssl.",
        "CryptoProGostTlsTunnel",
        "stunnel_msspi.exe",
    ):
        assert forbidden not in source
    for required in (
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "_WINHTTP_OPTION_SECURITY_INFO = 151",
        "_WINHTTP_FLAG_SECURE = 0x00800000",
    ):
        assert required in source


class ProbeWinHttp:
    def WinHttpOpen(self, *_args):
        return 1

    def WinHttpCloseHandle(self, _handle):
        return 1


def _successful_probe(tmp_path: Path):
    csptest = tmp_path / "csptest.exe"
    cpconfig = tmp_path / "cpconfig.exe"
    csptest.write_bytes(b"synthetic")
    cpconfig.write_bytes(b"synthetic")

    def runner(command, **_kwargs):
        if Path(command[0]) == csptest:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "CSP (Type:80) v5.0.10013 KC1 Release Ver:5.0.13000 "
                    "OS:Windows CPU:AMD64 FastCode:READY:AVX,AVX2.\n"
                    "AcquireContext: OK.\n[ErrorCode: 0x00000000]\n"
                ),
                stderr="",
            )
        assert Path(command[0]) == cpconfig
        return subprocess.CompletedProcess(
            command, 0, stdout="License: permanent; status: valid\n", stderr=""
        )

    winhttp = ProbeWinHttp()

    def loader(name: str):
        if name == "winhttp.dll":
            return winhttp
        if name in {"secur32.dll", "crypt32.dll"}:
            return object()
        raise OSError(name)

    return probe_native_gost_transport(
        system="Windows",
        windows_build=26100,
        dll_loader=loader,
        csptest_path=csptest,
        cpconfig_path=cpconfig,
        runner=runner,
        sspi_probe=lambda _secur32: True,
    )


def test_structural_probe_accepts_supported_windows_csp_and_native_dlls(
    tmp_path: Path,
) -> None:
    probe = _successful_probe(tmp_path)
    assert probe.backend_ready is True
    assert probe.csp_version == "5.0.13000"
    assert probe.csp_version_supported is True
    assert probe.csp_license_valid is True
    assert probe.cryptopro_tls_sspi_available is True
    assert probe.winhttp_gost_transport_initializable is True
    assert probe.reasons == ()


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("windows_supported", "UNSUPPORTED_WINDOWS"),
        ("winhttp_available", "WINHTTP_UNAVAILABLE"),
        ("secur32_available", "SSPI_UNAVAILABLE"),
        ("crypt32_available", "CRYPT32_UNAVAILABLE"),
        ("csp_installed", "CRYPTOPRO_CSP_NOT_INSTALLED"),
        ("csp_version_supported", "UNSUPPORTED_CRYPTOPRO_VERSION"),
        ("csp_license_valid", "CRYPTOPRO_CSP_LICENSE_NOT_VALID"),
        ("cryptopro_tls_sspi_available", "CRYPTOPRO_TLS_SSPI_UNAVAILABLE"),
        (
            "winhttp_gost_transport_initializable",
            "WINHTTP_GOST_TRANSPORT_NOT_INITIALIZABLE",
        ),
    ],
)
def test_readiness_fails_closed_for_each_backend_prerequisite(
    tmp_path: Path,
    field: str,
    reason: str,
) -> None:
    probe = _successful_probe(tmp_path)
    broken = replace(
        probe,
        **{
            field: False,
            "reasons": tuple(dict.fromkeys((*probe.reasons, reason))),
        },
    )
    result = evaluate_true_api_local_readiness(
        broken,
        browser_cades_available=True,
        eligible_ukep_visible=True,
    )
    assert result.true_api_local_ready is False
    assert reason in result.reasons


def test_readiness_requires_browser_cades_and_visible_eligible_ukep(
    tmp_path: Path,
) -> None:
    probe = _successful_probe(tmp_path)
    ready = evaluate_true_api_local_readiness(
        probe,
        browser_cades_available=True,
        eligible_ukep_visible=True,
    )
    assert ready.true_api_local_ready is True
    assert ready.true_api_live_verified is False

    no_plugin = evaluate_true_api_local_readiness(
        probe,
        browser_cades_available=False,
        eligible_ukep_visible=True,
    )
    assert no_plugin.true_api_local_ready is False
    assert "BROWSER_CADES_NOT_READY" in no_plugin.reasons

    no_ukep = evaluate_true_api_local_readiness(
        probe,
        browser_cades_available=True,
        eligible_ukep_visible=False,
    )
    assert no_ukep.true_api_local_ready is False
    assert "ELIGIBLE_UKEP_NOT_VISIBLE" in no_ukep.reasons


def test_legacy_optional_tools_are_not_readiness_inputs(tmp_path: Path) -> None:
    probe = _successful_probe(tmp_path)
    assert evaluate_true_api_local_readiness(
        probe,
        browser_cades_available=True,
        eligible_ukep_visible=True,
    ).true_api_local_ready is True
    source = Path(native_module.__file__).read_text(encoding="utf-8")
    assert "cryptcp.exe" not in source
    assert "stunnel_msspi.exe" not in source



def test_structural_probe_rejects_missing_cryptopro_sspi_package(
    tmp_path: Path,
) -> None:
    csptest = tmp_path / "csptest.exe"
    cpconfig = tmp_path / "cpconfig.exe"
    csptest.write_bytes(b"synthetic")
    cpconfig.write_bytes(b"synthetic")

    def runner(command, **_kwargs):
        if Path(command[0]) == csptest:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "CSP (Type:80) v5.0.10013 KC1 Release Ver:5.0.13000 "
                    "OS:Windows CPU:AMD64 FastCode:READY:AVX,AVX2.\n"
                    "AcquireContext: OK.\n[ErrorCode: 0x00000000]\n"
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="License: permanent; status: valid\n",
            stderr="",
        )

    winhttp = ProbeWinHttp()

    def loader(name: str):
        if name == "winhttp.dll":
            return winhttp
        if name in {"secur32.dll", "crypt32.dll"}:
            return object()
        raise OSError(name)

    probe = probe_native_gost_transport(
        system="Windows",
        windows_build=26100,
        dll_loader=loader,
        csptest_path=csptest,
        cpconfig_path=cpconfig,
        runner=runner,
        sspi_probe=lambda _secur32: False,
    )

    assert probe.cryptopro_tls_sspi_available is False
    assert probe.backend_ready is False
    assert "CRYPTOPRO_TLS_SSPI_UNAVAILABLE" in probe.reasons
