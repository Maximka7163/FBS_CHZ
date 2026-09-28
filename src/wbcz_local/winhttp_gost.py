from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Any, Callable

from wbcz.cis_inventory import safe_transport_error
from wbcz_ui.live_true_api import (
    GostTlsUnavailable,
    JsonlLiveAudit,
    ProductionMutationDisabled,
    TrueApiError,
    TrueApiHttpError,
    TrueApiProtocolError,
)

PRODUCTION_HOST = "markirovka.crpt.ru"
PRODUCTION_PORT = 443
PRODUCTION_BASE_PATH = "/api/v3/true-api"
PRODUCTION_BASE_URL = f"https://{PRODUCTION_HOST}{PRODUCTION_BASE_PATH}"
APPROVED_GOST_CIPHER_SUITES = frozenset({0xC100, 0xC101, 0xC102})
MIN_WINDOWS_BUILD_FOR_SECURITY_INFO = 20348
MIN_CRYPTOPRO_RELEASE = (5, 0, 13000)
_ALLOWED = frozenset({
    ("GET", "/auth/key"),
    ("POST", "/auth/simpleSignIn"),
    ("POST", "/cises/info"),
})
_MAX_RESPONSE = 16 * 1024 * 1024

_WINHTTP_ACCESS_TYPE_NO_PROXY = 1
_WINHTTP_FLAG_SECURE = 0x00800000
_WINHTTP_OPTION_CLIENT_CERT_CONTEXT = 47
_WINHTTP_OPTION_REDIRECT_POLICY = 88
_WINHTTP_OPTION_REDIRECT_POLICY_NEVER = 0
_WINHTTP_OPTION_SECURITY_INFO = 151
_WINHTTP_QUERY_STATUS_CODE = 19
_WINHTTP_QUERY_FLAG_NUMBER = 0x20000000
_ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED = 12044
_SZ_ALG_MAX_SIZE = 64


class _ConnectionInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "dwProtocol", "aiCipher", "dwCipherStrength", "aiHash",
        "dwHashStrength", "aiExch", "dwExchStrength",
    )]


class _CipherInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", ctypes.c_uint32),
        ("dwProtocol", ctypes.c_uint32),
        ("dwCipherSuite", ctypes.c_uint32),
        ("dwBaseCipherSuite", ctypes.c_uint32),
        ("szCipherSuite", ctypes.c_wchar * _SZ_ALG_MAX_SIZE),
        ("szCipher", ctypes.c_wchar * _SZ_ALG_MAX_SIZE),
        ("dwCipherLen", ctypes.c_uint32),
        ("dwCipherBlockLen", ctypes.c_uint32),
        ("szHash", ctypes.c_wchar * _SZ_ALG_MAX_SIZE),
        ("dwHashLen", ctypes.c_uint32),
        ("szExchange", ctypes.c_wchar * _SZ_ALG_MAX_SIZE),
        ("dwMinExchangeLen", ctypes.c_uint32),
        ("dwMaxExchangeLen", ctypes.c_uint32),
        ("szCertificate", ctypes.c_wchar * _SZ_ALG_MAX_SIZE),
        ("dwKeyType", ctypes.c_uint32),
    ]


class _SecurityInfo(ctypes.Structure):
    _fields_ = [("ConnectionInfo", _ConnectionInfo), ("CipherInfo", _CipherInfo)]


@dataclass(frozen=True, slots=True)
class NativeTransportProbe:
    windows_supported: bool
    windows_build: int | None
    winhttp_available: bool
    secur32_available: bool
    crypt32_available: bool
    csp_installed: bool
    csp_version: str | None
    csp_version_supported: bool
    csp_license_valid: bool
    cryptopro_tls_sspi_available: bool
    winhttp_gost_transport_initializable: bool
    reasons: tuple[str, ...]

    @property
    def backend_ready(self) -> bool:
        return all((
            self.windows_supported,
            self.winhttp_available,
            self.secur32_available,
            self.crypt32_available,
            self.csp_installed,
            self.csp_version_supported,
            self.csp_license_valid,
            self.cryptopro_tls_sspi_available,
            self.winhttp_gost_transport_initializable,
        ))

    def safe_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "backend_ready": self.backend_ready,
            "transport": "WINHTTP_CRYPTOPRO_SSPI_GOST",
            "target_host": PRODUCTION_HOST,
            "target_port": PRODUCTION_PORT,
        }


@dataclass(frozen=True, slots=True)
class TrueApiLocalReadiness:
    true_api_local_ready: bool
    true_api_live_verified: bool
    reasons: tuple[str, ...]


def evaluate_true_api_local_readiness(
    probe: NativeTransportProbe,
    *,
    browser_cades_available: bool,
    eligible_ukep_visible: bool,
    true_api_live_verified: bool = False,
) -> TrueApiLocalReadiness:
    reasons = list(probe.reasons)
    if not browser_cades_available:
        reasons.append("BROWSER_CADES_NOT_READY")
    if not eligible_ukep_visible:
        reasons.append("ELIGIBLE_UKEP_NOT_VISIBLE")
    ready = probe.backend_ready and browser_cades_available and eligible_ukep_visible
    return TrueApiLocalReadiness(
        true_api_local_ready=ready,
        true_api_live_verified=bool(ready and true_api_live_verified),
        reasons=tuple(dict.fromkeys(reasons)),
    )


@dataclass(frozen=True, slots=True)
class NativeHttpResponse:
    status: int
    body: bytes
    cipher_suite: int
    cipher_suite_name: str | None


class _WinHttpNative:
    """In-process WinHTTP boundary with one fixed HTTPS destination."""

    def __init__(self, *, dll_loader: Callable[[str], Any] | None = None) -> None:
        if os.name != "nt" and dll_loader is None:
            raise GostTlsUnavailable("WINHTTP_WINDOWS_ONLY")
        loader = dll_loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))
        try:
            self.winhttp = loader("winhttp.dll")
            self.secur32 = loader("secur32.dll")
            self.crypt32 = loader("crypt32.dll")
        except Exception as exc:
            raise GostTlsUnavailable("WINHTTP_NATIVE_DLL_UNAVAILABLE") from exc
        self._configure()

    def _configure(self) -> None:
        try:
            w = self.winhttp
            w.WinHttpOpen.restype = ctypes.c_void_p
            w.WinHttpConnect.restype = ctypes.c_void_p
            w.WinHttpOpenRequest.restype = ctypes.c_void_p
            w.WinHttpOpen.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPCWSTR,
                wintypes.LPCWSTR, wintypes.DWORD,
            ]
            w.WinHttpConnect.argtypes = [
                ctypes.c_void_p, wintypes.LPCWSTR, wintypes.WORD, wintypes.DWORD,
            ]
            w.WinHttpOpenRequest.argtypes = [
                ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR,
                wintypes.LPCWSTR, wintypes.LPCWSTR,
                ctypes.POINTER(wintypes.LPCWSTR), wintypes.DWORD,
            ]
            w.WinHttpSetTimeouts.argtypes = [
                ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ]
            w.WinHttpSetOption.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            ]
            w.WinHttpAddRequestHeaders.argtypes = [
                ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ]
            w.WinHttpSendRequest.argtypes = [
                ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
                wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t,
            ]
            w.WinHttpReceiveResponse.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            w.WinHttpQueryOption.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                ctypes.POINTER(wintypes.DWORD),
            ]
            w.WinHttpQueryHeaders.argtypes = [
                ctypes.c_void_p, wintypes.DWORD, wintypes.LPCWSTR, ctypes.c_void_p,
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            ]
            w.WinHttpQueryDataAvailable.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
            ]
            w.WinHttpReadData.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            w.WinHttpCloseHandle.argtypes = [ctypes.c_void_p]
        except AttributeError:
            pass

    @staticmethod
    def _error() -> int:
        getter = getattr(ctypes, "get_last_error", None)
        return int(getter()) if getter else 0

    def _check(self, ok: Any, operation: str) -> None:
        if ok:
            return
        error = self._error()
        if error == _ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
            raise GostTlsUnavailable("TLS_CLIENT_CERT_REQUESTED")
        raise GostTlsUnavailable(f"{operation}_FAILED:{error}")

    def _configure_request_safety(self, request: Any) -> None:
        # Windows SDK contract for WINHTTP_OPTION_CLIENT_CERT_CONTEXT:
        # NULL + length 0 explicitly disables automatic client-certificate
        # selection. The user's UKEP remains available only to Browser CAdES.
        self._check(
            self.winhttp.WinHttpSetOption(
                request,
                _WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                None,
                0,
            ),
            "WINHTTP_NO_CLIENT_CERT",
        )
        never_redirect = wintypes.DWORD(_WINHTTP_OPTION_REDIRECT_POLICY_NEVER)
        self._check(
            self.winhttp.WinHttpSetOption(
                request,
                _WINHTTP_OPTION_REDIRECT_POLICY,
                ctypes.byref(never_redirect),
                ctypes.sizeof(never_redirect),
            ),
            "WINHTTP_REDIRECT_POLICY",
        )

    def structural_initializable(self) -> bool:
        handles: list[Any] = []
        try:
            session = self.winhttp.WinHttpOpen(
                "SellariMarking/WinHTTP-GOST structural probe",
                _WINHTTP_ACCESS_TYPE_NO_PROXY,
                None,
                None,
                0,
            )
            if not session:
                return False
            handles.append(session)

            connection = self.winhttp.WinHttpConnect(
                session,
                PRODUCTION_HOST,
                PRODUCTION_PORT,
                0,
            )
            if not connection:
                return False
            handles.append(connection)

            request = self.winhttp.WinHttpOpenRequest(
                connection,
                "GET",
                PRODUCTION_BASE_PATH + "/auth/key",
                None,
                None,
                None,
                _WINHTTP_FLAG_SECURE,
            )
            if not request:
                return False
            handles.append(request)

            # Structural probe is deliberately no-network: only prove that the
            # mandatory request options can be configured on this WinHTTP stack.
            self._configure_request_safety(request)
            return True
        except Exception:
            return False
        finally:
            for handle in reversed(handles):
                try:
                    self.winhttp.WinHttpCloseHandle(handle)
                except Exception:
                    pass

    def request(
        self,
        *,
        host: str,
        port: int,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_ms: int,
    ) -> NativeHttpResponse:
        if (host, port) != (PRODUCTION_HOST, PRODUCTION_PORT):
            raise ValueError("WinHTTP destination is fixed to markirovka.crpt.ru:443")
        if not target.startswith(PRODUCTION_BASE_PATH + "/"):
            raise ValueError("request path is outside True API v3")

        handles: list[Any] = []
        try:
            session = self.winhttp.WinHttpOpen(
                "SellariMarking/WinHTTP-GOST",
                _WINHTTP_ACCESS_TYPE_NO_PROXY,
                None,
                None,
                0,
            )
            if not session:
                self._check(False, "WINHTTP_OPEN")
            handles.append(session)
            self._check(
                self.winhttp.WinHttpSetTimeouts(
                    session, timeout_ms, timeout_ms, timeout_ms, timeout_ms
                ),
                "WINHTTP_TIMEOUTS",
            )

            connection = self.winhttp.WinHttpConnect(
                session, PRODUCTION_HOST, PRODUCTION_PORT, 0
            )
            if not connection:
                self._check(False, "WINHTTP_CONNECT")
            handles.append(connection)

            request = self.winhttp.WinHttpOpenRequest(
                connection, method, target, None, None, None, _WINHTTP_FLAG_SECURE
            )
            if not request:
                self._check(False, "WINHTTP_OPEN_REQUEST")
            handles.append(request)

            self._configure_request_safety(request)

            if headers:
                header_text = "".join(
                    f"{name}: {value}\r\n" for name, value in headers.items()
                )
                self._check(
                    self.winhttp.WinHttpAddRequestHeaders(
                        request, header_text, 0xFFFFFFFF, 0x20000000
                    ),
                    "WINHTTP_HEADERS",
                )

            payload = body or b""
            buffer = ctypes.create_string_buffer(payload) if payload else None
            pointer = ctypes.cast(buffer, ctypes.c_void_p) if buffer else None
            self._check(
                self.winhttp.WinHttpSendRequest(
                    request, None, 0, pointer, len(payload), len(payload), 0
                ),
                "WINHTTP_SEND",
            )
            self._check(
                self.winhttp.WinHttpReceiveResponse(request, None),
                "WINHTTP_RECEIVE",
            )

            security = _SecurityInfo()
            security_size = wintypes.DWORD(ctypes.sizeof(security))
            self._check(
                self.winhttp.WinHttpQueryOption(
                    request,
                    _WINHTTP_OPTION_SECURITY_INFO,
                    ctypes.byref(security),
                    ctypes.byref(security_size),
                ),
                "WINHTTP_SECURITY_INFO",
            )
            suite = int(security.CipherInfo.dwCipherSuite)
            name = str(security.CipherInfo.szCipherSuite).rstrip("\x00") or None
            if suite not in APPROVED_GOST_CIPHER_SUITES:
                raise GostTlsUnavailable(f"GOST_TLS_NOT_NEGOTIATED:0x{suite:04X}")

            status = wintypes.DWORD()
            status_size = wintypes.DWORD(ctypes.sizeof(status))
            self._check(
                self.winhttp.WinHttpQueryHeaders(
                    request,
                    _WINHTTP_QUERY_STATUS_CODE | _WINHTTP_QUERY_FLAG_NUMBER,
                    None,
                    ctypes.byref(status),
                    ctypes.byref(status_size),
                    None,
                ),
                "WINHTTP_STATUS",
            )
            return NativeHttpResponse(
                status=int(status.value),
                body=self._read_body(request),
                cipher_suite=suite,
                cipher_suite_name=name,
            )
        finally:
            for handle in reversed(handles):
                try:
                    self.winhttp.WinHttpCloseHandle(handle)
                except Exception:
                    pass

    def _read_body(self, request: Any) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            available = wintypes.DWORD()
            self._check(
                self.winhttp.WinHttpQueryDataAvailable(request, ctypes.byref(available)),
                "WINHTTP_QUERY_DATA",
            )
            if available.value == 0:
                break
            if total + int(available.value) > _MAX_RESPONSE:
                raise TrueApiProtocolError("True API response exceeds local safety limit")
            buffer = ctypes.create_string_buffer(int(available.value))
            read = wintypes.DWORD()
            self._check(
                self.winhttp.WinHttpReadData(
                    request, buffer, available.value, ctypes.byref(read)
                ),
                "WINHTTP_READ",
            )
            if read.value == 0:
                break
            data = bytes(buffer.raw[: read.value])
            chunks.append(data)
            total += len(data)
        return b"".join(chunks)


def _find_tool(filename: str) -> Path | None:
    found = shutil.which(filename)
    if found:
        return Path(found).resolve()
    for env_name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(env_name)
        if root:
            candidate = Path(root) / "Crypto Pro" / "CSP" / filename
            if candidate.is_file():
                return candidate.resolve()
    return None


_RELEASE_RE = re.compile(
    r"\bRelease\s+Ver\s*:\s*(\d+)\.(\d+)\.(\d+)\b", re.IGNORECASE
)
_BAD_LICENSE_RE = re.compile(
    r"(expired|not\s+found|invalid|unlicensed|license\s+is\s+not\s+valid|"
    r"ист[её]к|просроч|лицензи[яи]\s+не\s+найден|лицензи[яи].*недейств)",
    re.IGNORECASE,
)


def _probe_csp(
    *,
    csptest_path: Path | None = None,
    cpconfig_path: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[bool, str | None, bool, bool]:
    csptest = csptest_path or _find_tool("csptest.exe")
    cpconfig = cpconfig_path or _find_tool("cpconfig.exe")
    if csptest is None:
        return False, None, False, False
    try:
        version = runner(
            [str(csptest), "-keyset", "-verifycontext"],
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except Exception:
        return True, None, False, False
    version_text = f"{version.stdout}\n{version.stderr}"
    match = _RELEASE_RE.search(version_text)
    release = ".".join(match.groups()) if match else None
    release_tuple = tuple(map(int, match.groups())) if match else ()
    version_ok = bool(
        version.returncode == 0
        and "AcquireContext: OK" in version_text
        and release_tuple >= MIN_CRYPTOPRO_RELEASE
    )
    if cpconfig is None:
        return True, release, version_ok, False
    try:
        license_result = runner(
            [str(cpconfig), "-license", "-view"],
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except Exception:
        return True, release, version_ok, False
    license_text = f"{license_result.stdout}\n{license_result.stderr}".strip()
    license_ok = bool(
        license_result.returncode == 0
        and license_text
        and not _BAD_LICENSE_RE.search(license_text)
    )
    return True, release, version_ok, license_ok


class _SecPkgInfoW(ctypes.Structure):
    _fields_ = [
        ("fCapabilities", ctypes.c_uint32),
        ("wVersion", ctypes.c_uint16),
        ("wRPCID", ctypes.c_uint16),
        ("cbMaxToken", ctypes.c_uint32),
        ("Name", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
    ]


def _cryptopro_sspi_package_available(secur32: Any) -> bool:
    """Prove that a CryptoPro SSP/SChannel package is actually registered."""

    try:
        enumerate_packages = secur32.EnumerateSecurityPackagesW
        free_context = secur32.FreeContextBuffer
    except AttributeError:
        return False

    count = ctypes.c_uint32()
    packages = ctypes.POINTER(_SecPkgInfoW)()
    try:
        enumerate_packages.argtypes = [
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.POINTER(_SecPkgInfoW)),
        ]
        enumerate_packages.restype = ctypes.c_long
        free_context.argtypes = [ctypes.c_void_p]
        free_context.restype = ctypes.c_long
    except AttributeError:
        # Synthetic callables used by tests may not expose ctypes metadata.
        pass

    status = enumerate_packages(ctypes.byref(count), ctypes.byref(packages))
    if int(status) != 0 or not packages:
        return False
    try:
        for index in range(int(count.value)):
            item = packages[index]
            marker = f"{item.Name or ''} {item.Comment or ''}".casefold()
            if "cryptopro" in marker or "crypto-pro" in marker:
                return True
        return False
    finally:
        free_context(packages)


def probe_native_gost_transport(
    *,
    system: str | None = None,
    windows_build: int | None = None,
    dll_loader: Callable[[str], Any] | None = None,
    csptest_path: Path | None = None,
    cpconfig_path: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sspi_probe: Callable[[Any], bool] | None = None,
) -> NativeTransportProbe:
    windows = (system or platform.system()).casefold() == "windows"
    build = windows_build
    if windows and build is None:
        try:
            build = int(sys.getwindowsversion().build)  # type: ignore[attr-defined]
        except Exception:
            build = None
    supported_windows = bool(
        windows and build is not None and build >= MIN_WINDOWS_BUILD_FOR_SECURITY_INFO
    )

    csp_installed = False
    csp_version = None
    csp_version_supported = False
    csp_license_valid = False
    if windows:
        csp_installed, csp_version, csp_version_supported, csp_license_valid = (
            _probe_csp(
                csptest_path=csptest_path,
                cpconfig_path=cpconfig_path,
                runner=runner,
            )
        )

    available = {"winhttp.dll": False, "secur32.dll": False, "crypt32.dll": False}
    loaded: dict[str, Any] = {}
    initializable = False
    if windows:
        loader = dll_loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))
        for name in available:
            try:
                loaded[name] = loader(name)
                available[name] = True
            except Exception:
                pass
        if all(available.values()):
            try:
                initializable = _WinHttpNative(
                    dll_loader=loader
                ).structural_initializable()
            except Exception:
                initializable = False

    sspi_detector = sspi_probe or _cryptopro_sspi_package_available
    sspi = False
    if (
        available["secur32.dll"]
        and csp_installed
        and csp_version_supported
        and csp_license_valid
    ):
        try:
            sspi = bool(sspi_detector(loaded["secur32.dll"]))
        except Exception:
            sspi = False
    checks = (
        (supported_windows, "UNSUPPORTED_WINDOWS"),
        (csp_installed, "CRYPTOPRO_CSP_NOT_INSTALLED"),
        (not csp_installed or csp_version_supported, "UNSUPPORTED_CRYPTOPRO_VERSION"),
        (not csp_installed or csp_license_valid, "CRYPTOPRO_CSP_LICENSE_NOT_VALID"),
        (available["winhttp.dll"], "WINHTTP_UNAVAILABLE"),
        (available["secur32.dll"], "SSPI_UNAVAILABLE"),
        (available["crypt32.dll"], "CRYPT32_UNAVAILABLE"),
        (sspi, "CRYPTOPRO_TLS_SSPI_UNAVAILABLE"),
        (initializable, "WINHTTP_GOST_TRANSPORT_NOT_INITIALIZABLE"),
    )
    reasons = tuple(dict.fromkeys(reason for ok, reason in checks if not ok))
    return NativeTransportProbe(
        windows_supported=supported_windows,
        windows_build=build,
        winhttp_available=available["winhttp.dll"],
        secur32_available=available["secur32.dll"],
        crypt32_available=available["crypt32.dll"],
        csp_installed=csp_installed,
        csp_version=csp_version,
        csp_version_supported=csp_version_supported,
        csp_license_valid=csp_license_valid,
        cryptopro_tls_sspi_available=sspi,
        winhttp_gost_transport_initializable=initializable,
        reasons=reasons,
    )


class WindowsWinHttpGostTransport:
    """Read-only production True API transport over native Windows WinHTTP."""

    def __init__(
        self,
        base_url: str = PRODUCTION_BASE_URL,
        audit: JsonlLiveAudit | None = None,
        *,
        timeout: float = 30.0,
        target_host: str = PRODUCTION_HOST,
        target_port: int = PRODUCTION_PORT,
        native: Any | None = None,
    ) -> None:
        if base_url.rstrip("/") != PRODUCTION_BASE_URL:
            raise ValueError("Only the official production True API v3 base is allowed")
        if (target_host, target_port) != (PRODUCTION_HOST, PRODUCTION_PORT):
            raise ValueError("True API destination is fixed to markirovka.crpt.ru:443")
        if not 0 < timeout <= 120:
            raise ValueError("WinHTTP timeout is out of range")
        self.audit = audit or JsonlLiveAudit("live_true_api.jsonl")
        self.timeout = timeout
        self.target_host = PRODUCTION_HOST
        self.target_port = PRODUCTION_PORT
        self._native = native or _WinHttpNative()
        self._last_suite: int | None = None
        self._last_name: str | None = None

    @staticmethod
    def assert_allowed(
        method: str, path: str, params: dict[str, str] | None = None
    ) -> None:
        method = method.upper()
        if (method, path) not in _ALLOWED:
            raise ProductionMutationDisabled(
                f"Production endpoint is disabled in local read-only mode: {method} {path}"
            )
        if path == "/cises/info":
            if params != {"pg": "lp"}:
                raise ProductionMutationDisabled("cises/info is allowed only with pg=lp")
        elif params:
            raise ProductionMutationDisabled("Unexpected query parameters are disabled")

    def tls_diagnostics(self) -> dict[str, Any]:
        return {
            "mechanism": "Windows WinHTTP / SSPI / CryptoPro GOST TLS",
            "target_host": self.target_host,
            "target_port": self.target_port,
            "server_certificate_validation": True,
            "hostname_validation": True,
            "tls_client_certificate_attached": False,
            "redirects_enabled": False,
            "cipher_policy": "GOST_ONLY",
            "gost_session_verified": self._last_suite in APPROVED_GOST_CIPHER_SUITES,
            "negotiated_gost_cipher_id": (
                f"0x{self._last_suite:04X}" if self._last_suite is not None else None
            ),
            "negotiated_cipher_name": self._last_name,
            "openssl_tls_to_production": False,
        }

    def request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        body: Any = None,
        bearer_token: str | None = None,
        cis_count: int = 0,
    ) -> Any:
        method = method.upper()
        self.assert_allowed(method, path, params)
        target = PRODUCTION_BASE_PATH + path + ("?pg=lp" if params else "")
        headers = {"Accept": "application/json", "Host": PRODUCTION_HOST}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json; charset=UTF-8"
            data = json.dumps(
                body, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        if bearer_token:
            headers["Authorization"] = "Bearer " + bearer_token

        try:
            response = self._native.request(
                host=self.target_host,
                port=self.target_port,
                method=method,
                target=target,
                headers=headers,
                body=data,
                timeout_ms=int(self.timeout * 1000),
            )
            self._last_suite = int(response.cipher_suite)
            self._last_name = response.cipher_suite_name
            if self._last_suite not in APPROVED_GOST_CIPHER_SUITES:
                raise GostTlsUnavailable("GOST_TLS_NOT_NEGOTIATED")
            self.audit.record(
                method=method,
                endpoint=path,
                cis_count=cis_count,
                http_status=response.status,
            )
            if not 200 <= response.status < 300:
                safe = safe_transport_error(response.status, {}, response.body)
                raise TrueApiHttpError(
                    response.status,
                    safe.safe_error_message or f"True API HTTP {response.status}",
                    content_type=safe.content_type,
                    body_sha256=safe.body_sha256,
                    safe_error_code=safe.safe_error_code,
                )
            try:
                return (
                    json.loads(response.body.decode("utf-8"))
                    if response.body
                    else None
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TrueApiProtocolError("True API returned non-JSON content") from exc
        except ProductionMutationDisabled:
            raise
        except TrueApiError:
            raise
        except Exception as exc:
            self.audit.record(
                method=method,
                endpoint=path,
                cis_count=cis_count,
                http_status=None,
                error=type(exc).__name__,
            )
            raise TrueApiHttpError(
                None, "WinHTTP/CryptoPro GOST TLS transport error"
            ) from exc
