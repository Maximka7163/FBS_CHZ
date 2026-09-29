from __future__ import annotations

import atexit
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
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
STUNNEL_MSSPI_FILENAME = "stunnel_msspi.exe"
STUNNEL_MSSPI_OFFICIAL_SHA256 = (
    "C15491EA8EAB0ADB7F8F761337DF85DA335A57E3AA18D1CBC19B31D1EEA09F8B"
)
GOST_ONLY_CIPHERS = (
    "GOST2012-GOST8912-GOST8912:GOST2001-GOST89-GOST89"
)
PRIVATE_PORT_MIN = 49152
PRIVATE_PORT_MAX = 65535
_MAX_RESPONSE = 16 * 1024 * 1024
_ALLOWED = frozenset({
    ("GET", "/auth/key"),
    ("POST", "/auth/simpleSignIn"),
    ("POST", "/cises/info"),
})
_TCP_STATE_LISTEN = 2
_TCP_STATE_ESTABLISHED = 5
_AF_INET = 2
_TCP_TABLE_OWNER_PID_ALL = 5
_ERROR_INSUFFICIENT_BUFFER = 122


class _MibTcpRowOwnerPid(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class TcpOwnerRow:
    state: int
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    owning_pid: int


@dataclass(frozen=True, slots=True)
class StunnelMsspiProbe:
    windows_supported: bool
    executable_path: str | None
    stunnel_msspi_present: bool
    stunnel_msspi_executable_valid: bool
    stunnel_msspi_authenticity_valid: bool
    stunnel_msspi_config_supported: bool
    stunnel_msspi_structural_ready: bool
    reasons: tuple[str, ...]

    def safe_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "canonical_transport": "CRYPTOPRO_STUNNEL_MSSPI_CHILD_PROCESS",
            "true_api_live_verified": False,
        }


def render_stunnel_msspi_config(port: int) -> str:
    if not PRIVATE_PORT_MIN <= int(port) <= PRIVATE_PORT_MAX:
        raise ValueError("stunnel MSSPI port must be a high private port")
    return (
        "foreground = yes\n"
        "\n"
        "[true-api]\n"
        "client = yes\n"
        f"accept = 127.0.0.1:{int(port)}\n"
        f"connect = {PRODUCTION_HOST}:{PRODUCTION_PORT}\n"
        f"sni = {PRODUCTION_HOST}\n"
        "verify = 2\n"
        f"checkHost = {PRODUCTION_HOST}\n"
        "sslVersion = TLSv1.2\n"
        f"ciphers = {GOST_ONLY_CIPHERS}\n"
    )


def _config_contract_supported(config: str) -> bool:
    normalized = [line.strip() for line in config.splitlines() if line.strip()]
    required = {
        "[true-api]",
        "client = yes",
        f"connect = {PRODUCTION_HOST}:{PRODUCTION_PORT}",
        f"sni = {PRODUCTION_HOST}",
        "verify = 2",
        f"checkHost = {PRODUCTION_HOST}",
        "sslVersion = TLSv1.2",
        f"ciphers = {GOST_ONLY_CIPHERS}",
    }
    if not required.issubset(set(normalized)):
        return False
    accept = [line for line in normalized if line.startswith("accept = ")]
    if len(accept) != 1 or not accept[0].startswith("accept = 127.0.0.1:"):
        return False
    lower = "\n".join(normalized).casefold()
    forbidden = ("cert =", "key =", "pin =", "msspi = 0", "-install")
    return not any(token in lower for token in forbidden)


def _candidate_stunnel_paths(explicit: str | Path | None = None) -> list[Path]:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env_path = os.getenv("WBCZ_CRYPTOPRO_STUNNEL_MSSPI", "").strip()
    if env_path:
        candidates.append(Path(env_path).expanduser())
    resolved = shutil.which(STUNNEL_MSSPI_FILENAME)
    if resolved:
        candidates.append(Path(resolved))
    for env_name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        root = os.getenv(env_name, "").strip()
        if not root:
            continue
        base = Path(root) / "Crypto Pro"
        candidates.extend((
            base / STUNNEL_MSSPI_FILENAME,
            base / "CSP" / STUNNEL_MSSPI_FILENAME,
            base / "stunnel_msspi" / STUNNEL_MSSPI_FILENAME,
            base / "Stunnel MSSPI" / STUNNEL_MSSPI_FILENAME,
        ))
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(str(candidate))
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def _find_stunnel_msspi(explicit: str | Path | None = None) -> Path | None:
    for candidate in _candidate_stunnel_paths(explicit):
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _inspect_stunnel_msspi_executable(path: Path | None) -> tuple[bool, bool]:
    if path is None or path.name.casefold() != STUNNEL_MSSPI_FILENAME:
        return False, False
    try:
        if not path.is_file() or path.suffix.casefold() != ".exe":
            return False, False
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                return False, False
        authentic = _sha256_file(path) == STUNNEL_MSSPI_OFFICIAL_SHA256
        return True, authentic
    except OSError:
        return False, False


def _valid_stunnel_msspi_executable(path: Path | None) -> bool:
    structural, authentic = _inspect_stunnel_msspi_executable(path)
    return structural and authentic


def probe_stunnel_msspi(
    executable_path: str | Path | None = None,
    *,
    windows_supported: bool | None = None,
) -> StunnelMsspiProbe:
    windows = (
        platform.system().lower() == "windows"
        if windows_supported is None
        else bool(windows_supported)
    )
    path = _find_stunnel_msspi(executable_path)
    present = path is not None
    executable_structural, authenticity_valid = _inspect_stunnel_msspi_executable(path)
    executable_valid = executable_structural and authenticity_valid
    config_supported = _config_contract_supported(
        render_stunnel_msspi_config(PRIVATE_PORT_MIN)
    )
    structural_ready = bool(
        windows and present and executable_valid and config_supported
    )

    reasons: list[str] = []
    if not windows:
        reasons.append("UNSUPPORTED_WINDOWS")
    if not present:
        reasons.append("CRYPTOPRO_STUNNEL_MSSPI_MISSING")
    elif not executable_structural:
        reasons.append("CRYPTOPRO_STUNNEL_MSSPI_EXECUTABLE_INVALID")
    elif not authenticity_valid:
        reasons.append("CRYPTOPRO_STUNNEL_MSSPI_AUTHENTICITY_FAILED")
    if not config_supported:
        reasons.append("CRYPTOPRO_STUNNEL_MSSPI_CONFIG_UNSUPPORTED")
    return StunnelMsspiProbe(
        windows_supported=windows,
        executable_path=str(path) if path is not None else None,
        stunnel_msspi_present=present,
        stunnel_msspi_executable_valid=executable_valid,
        stunnel_msspi_authenticity_valid=authenticity_valid,
        stunnel_msspi_config_supported=config_supported,
        stunnel_msspi_structural_ready=structural_ready,
        reasons=tuple(dict.fromkeys(reasons)),
    )


def _select_private_port() -> int:
    for _ in range(64):
        port = PRIVATE_PORT_MIN + secrets.randbelow(
            PRIVATE_PORT_MAX - PRIVATE_PORT_MIN + 1
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_EXCLUSIVEADDRUSE,
                        1,
                    )
                except OSError:
                    pass
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            sock.close()
    raise GostTlsUnavailable("STUNNEL_MSSPI_PRIVATE_PORT_UNAVAILABLE")


def _decode_ipv4(value: int) -> str:
    return socket.inet_ntoa(int(value).to_bytes(4, byteorder="little", signed=False))


def _decode_tcp_port(value: int) -> int:
    return socket.ntohs(int(value) & 0xFFFF)


def _windows_tcp_owner_rows() -> tuple[TcpOwnerRow, ...]:
    if os.name != "nt":
        raise GostTlsUnavailable("STUNNEL_MSSPI_TCP_OWNERSHIP_WINDOWS_ONLY")
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        get_table = iphlpapi.GetExtendedTcpTable
        get_table.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.BOOL,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
        ]
        get_table.restype = wintypes.DWORD
    except Exception as exc:
        raise GostTlsUnavailable(
            "STUNNEL_MSSPI_TCP_OWNERSHIP_API_UNAVAILABLE"
        ) from exc

    size = wintypes.ULONG(0)
    status = int(
        get_table(
            None,
            ctypes.byref(size),
            False,
            _AF_INET,
            _TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    )
    if status not in {0, _ERROR_INSUFFICIENT_BUFFER}:
        raise GostTlsUnavailable(
            f"STUNNEL_MSSPI_TCP_OWNERSHIP_API_FAILED:{status}"
        )
    if size.value == 0:
        return ()

    buffer = ctypes.create_string_buffer(int(size.value))
    status = int(
        get_table(
            buffer,
            ctypes.byref(size),
            False,
            _AF_INET,
            _TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    )
    if status != 0:
        raise GostTlsUnavailable(
            f"STUNNEL_MSSPI_TCP_OWNERSHIP_API_FAILED:{status}"
        )

    count = int(ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0])
    row_size = ctypes.sizeof(_MibTcpRowOwnerPid)
    offset = ctypes.sizeof(wintypes.DWORD)
    rows: list[TcpOwnerRow] = []
    for index in range(count):
        address = ctypes.addressof(buffer) + offset + (index * row_size)
        row = _MibTcpRowOwnerPid.from_address(address)
        rows.append(
            TcpOwnerRow(
                state=int(row.dwState),
                local_address=_decode_ipv4(int(row.dwLocalAddr)),
                local_port=_decode_tcp_port(int(row.dwLocalPort)),
                remote_address=_decode_ipv4(int(row.dwRemoteAddr)),
                remote_port=_decode_tcp_port(int(row.dwRemotePort)),
                owning_pid=int(row.dwOwningPid),
            )
        )
    return tuple(rows)


def _wait_for_child_listener(
    process: Any,
    port: int,
    timeout: float,
    ownership_rows: Callable[[], tuple[TcpOwnerRow, ...]],
) -> None:
    child_pid = int(getattr(process, "pid", 0) or 0)
    if child_pid <= 0:
        raise GostTlsUnavailable("STUNNEL_MSSPI_CHILD_PID_UNAVAILABLE")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise GostTlsUnavailable("STUNNEL_MSSPI_CHILD_EXITED_EARLY")
        listeners = [
            row
            for row in ownership_rows()
            if row.state == _TCP_STATE_LISTEN
            and row.local_address == "127.0.0.1"
            and row.local_port == port
        ]
        if any(row.owning_pid == child_pid for row in listeners):
            return
        if listeners:
            raise GostTlsUnavailable(
                "STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_MISMATCH"
            )
        time.sleep(0.05)
    raise GostTlsUnavailable("STUNNEL_MSSPI_NOT_READY")


class StunnelMsspiTransport:
    """Read-only True API transport through a child CryptoPro stunnel MSSPI."""

    def __init__(
        self,
        *,
        executable_path: str | Path,
        audit: JsonlLiveAudit | None = None,
        timeout: float = 30.0,
        startup_timeout: float = 8.0,
        validated_probe: StunnelMsspiProbe | None = None,
        popen_factory: Callable[..., Any] = subprocess.Popen,
        connection_factory: Callable[..., Any] = http.client.HTTPConnection,
        port_selector: Callable[[], int] = _select_private_port,
        ownership_rows: Callable[[], tuple[TcpOwnerRow, ...]] = _windows_tcp_owner_rows,
        temp_root: str | Path | None = None,
    ) -> None:
        if not 0 < timeout <= 120:
            raise ValueError("stunnel MSSPI HTTP timeout is out of range")
        if not 0 < startup_timeout <= 30:
            raise ValueError("stunnel MSSPI startup timeout is out of range")

        explicit = Path(executable_path).expanduser().resolve()
        probe = validated_probe or probe_stunnel_msspi(explicit)
        if not probe.stunnel_msspi_present:
            raise GostTlsUnavailable("CRYPTOPRO_STUNNEL_MSSPI_MISSING")
        if not probe.stunnel_msspi_executable_valid:
            if not probe.stunnel_msspi_authenticity_valid:
                raise GostTlsUnavailable(
                    "CRYPTOPRO_STUNNEL_MSSPI_AUTHENTICITY_FAILED"
                )
            raise GostTlsUnavailable("CRYPTOPRO_STUNNEL_MSSPI_EXECUTABLE_INVALID")
        if not probe.stunnel_msspi_config_supported:
            raise GostTlsUnavailable("CRYPTOPRO_STUNNEL_MSSPI_CONFIG_UNSUPPORTED")
        if not probe.stunnel_msspi_structural_ready:
            reason = probe.reasons[0] if probe.reasons else "STUNNEL_MSSPI_NOT_READY"
            raise GostTlsUnavailable(reason)
        if (
            probe.executable_path is None
            or Path(probe.executable_path).resolve() != explicit
        ):
            raise GostTlsUnavailable("CRYPTOPRO_STUNNEL_MSSPI_PATH_MISMATCH")
        if not _valid_stunnel_msspi_executable(explicit):
            raise GostTlsUnavailable(
                "CRYPTOPRO_STUNNEL_MSSPI_AUTHENTICITY_FAILED"
            )

        self.executable_path = explicit
        self.audit = audit or JsonlLiveAudit("live_true_api.jsonl")
        self.timeout = timeout
        self.startup_timeout = startup_timeout
        self._popen_factory = popen_factory
        self._connection_factory = connection_factory
        self._port_selector = port_selector
        self._ownership_rows = ownership_rows
        self._temp_root = Path(temp_root) if temp_root is not None else None
        self._process: Any | None = None
        self._port: int | None = None
        self._temp_dir: Path | None = None
        self._config_path: Path | None = None
        self._closed = False
        self._live_verified = False
        self._startup_ownership_verified = False
        self._pending_auth_key_ownership_verified = False
        atexit.register(self.close)

    @staticmethod
    def assert_allowed(
        method: str,
        path: str,
        params: dict[str, str] | None = None,
    ) -> None:
        method = method.upper()
        if (method, path) not in _ALLOWED:
            raise ProductionMutationDisabled(
                f"Production endpoint is disabled in local read-only mode: {method} {path}"
            )
        if path == "/cises/info":
            if params != {"pg": "lp"}:
                raise ProductionMutationDisabled(
                    "cises/info is allowed only with pg=lp"
                )
        elif params:
            raise ProductionMutationDisabled(
                "Unexpected query parameters are disabled"
            )

    def _write_config(self, port: int) -> Path:
        root = str(self._temp_root) if self._temp_root is not None else None
        temp_dir = Path(tempfile.mkdtemp(prefix="sellari-stunnel-msspi-", dir=root))
        try:
            os.chmod(temp_dir, 0o700)
        except OSError:
            pass
        config_path = temp_dir / "true-api.conf"
        config = render_stunnel_msspi_config(port)
        if not _config_contract_supported(config):
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise GostTlsUnavailable("CRYPTOPRO_STUNNEL_MSSPI_CONFIG_UNSUPPORTED")
        config_path.write_text(config, encoding="ascii", newline="\n")
        try:
            os.chmod(config_path, 0o600)
        except OSError:
            pass
        self._temp_dir = temp_dir
        self._config_path = config_path
        return config_path

    def _cleanup_config(self) -> None:
        temp_dir = self._temp_dir
        self._config_path = None
        self._temp_dir = None
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _stop_process(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except Exception:
                    process.kill()
                    try:
                        process.wait(timeout=2)
                    except Exception:
                        pass
        except Exception:
            pass

    def _start(self) -> None:
        if self._closed:
            raise GostTlsUnavailable("STUNNEL_MSSPI_TRANSPORT_CLOSED")
        if self._process is not None:
            if self._process.poll() is None:
                return
            self._stop_process()
            self._cleanup_config()
            raise GostTlsUnavailable("STUNNEL_MSSPI_CHILD_EXITED_EARLY")

        if not _valid_stunnel_msspi_executable(self.executable_path):
            raise GostTlsUnavailable(
                "CRYPTOPRO_STUNNEL_MSSPI_AUTHENTICITY_FAILED"
            )
        port = int(self._port_selector())
        if not PRIVATE_PORT_MIN <= port <= PRIVATE_PORT_MAX:
            raise GostTlsUnavailable("STUNNEL_MSSPI_PRIVATE_PORT_INVALID")
        config_path = self._write_config(port)
        try:
            process = self._popen_factory(
                [str(self.executable_path), str(config_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                cwd=str(self.executable_path.parent),
            )
            self._process = process
            self._port = port
            if process.poll() is not None:
                raise GostTlsUnavailable("STUNNEL_MSSPI_CHILD_EXITED_EARLY")
            _wait_for_child_listener(
                process,
                port,
                self.startup_timeout,
                self._ownership_rows,
            )
            self._startup_ownership_verified = True
        except GostTlsUnavailable:
            self._stop_process()
            self._cleanup_config()
            self._port = None
            self._startup_ownership_verified = False
            raise
        except Exception as exc:
            self._stop_process()
            self._cleanup_config()
            self._port = None
            self._startup_ownership_verified = False
            raise GostTlsUnavailable(
                "STUNNEL_MSSPI_CHILD_START_FAILED"
            ) from exc

    def _open_owned_connection(self) -> Any:
        process = self._process
        port = self._port
        if (
            process is None
            or port is None
            or process.poll() is not None
            or not self._startup_ownership_verified
        ):
            raise GostTlsUnavailable("STUNNEL_MSSPI_CHILD_EXITED_EARLY")
        child_pid = int(getattr(process, "pid", 0) or 0)
        if child_pid <= 0:
            raise GostTlsUnavailable("STUNNEL_MSSPI_CHILD_PID_UNAVAILABLE")

        connection = self._connection_factory(
            "127.0.0.1",
            port,
            timeout=self.timeout,
        )
        try:
            connection.connect()
            sock = getattr(connection, "sock", None)
            if sock is None:
                raise GostTlsUnavailable(
                    "STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_UNKNOWN"
                )
            client_host, client_port = sock.getsockname()[:2]
            server_host, server_port = sock.getpeername()[:2]
            if (
                client_host != "127.0.0.1"
                or server_host != "127.0.0.1"
                or int(server_port) != port
            ):
                raise GostTlsUnavailable(
                    "STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_MISMATCH"
                )

            deadline = time.monotonic() + min(self.startup_timeout, 1.0)
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise GostTlsUnavailable(
                        "STUNNEL_MSSPI_CHILD_EXITED_EARLY"
                    )
                established = [
                    row
                    for row in self._ownership_rows()
                    if row.state == _TCP_STATE_ESTABLISHED
                    and row.local_address == "127.0.0.1"
                    and row.local_port == port
                    and row.remote_address == "127.0.0.1"
                    and row.remote_port == int(client_port)
                ]
                if any(row.owning_pid == child_pid for row in established):
                    return connection
                if established:
                    raise GostTlsUnavailable(
                        "STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_MISMATCH"
                    )
                time.sleep(0.01)
            raise GostTlsUnavailable(
                "STUNNEL_MSSPI_LOOPBACK_OWNERSHIP_UNKNOWN"
            )
        except Exception:
            try:
                connection.close()
            except Exception:
                pass
            raise

    def mark_auth_key_verified(self) -> None:
        process = self._process
        if (
            not self._startup_ownership_verified
            or not self._pending_auth_key_ownership_verified
            or process is None
            or process.poll() is not None
        ):
            self._live_verified = False
            raise GostTlsUnavailable(
                "STUNNEL_MSSPI_LIVE_VERIFICATION_PROCESS_MISMATCH"
            )
        self._live_verified = True
        self._pending_auth_key_ownership_verified = False

    def tls_diagnostics(self) -> dict[str, Any]:
        return {
            "mechanism": "CryptoPro stunnel MSSPI child / GOST TLS",
            "canonical_transport": "CRYPTOPRO_STUNNEL_MSSPI_CHILD_PROCESS",
            "target_host": PRODUCTION_HOST,
            "target_port": PRODUCTION_PORT,
            "loopback_host": "127.0.0.1",
            "loopback_port": self._port,
            "server_certificate_validation": True,
            "hostname_validation": True,
            "tls_client_certificate_attached": False,
            "redirects_enabled": False,
            "cipher_policy": "GOST_ONLY",
            "gost_cipher_list": GOST_ONLY_CIPHERS,
            "gost_session_verified": self._live_verified,
            "true_api_live_verified": self._live_verified,
            "startup_pid_ownership_verified": self._startup_ownership_verified,
            "openssl_tls_to_production": False,
            "direct_winhttp_fallback": False,
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
        if (method, path) == ("GET", "/auth/key"):
            self._pending_auth_key_ownership_verified = False
            self._live_verified = False
        self._start()
        if self._process is None or self._process.poll() is not None:
            self.close()
            raise GostTlsUnavailable("STUNNEL_MSSPI_CHILD_EXITED_EARLY")
        if self._port is None:
            raise GostTlsUnavailable("STUNNEL_MSSPI_NOT_READY")

        target = PRODUCTION_BASE_PATH + path + ("?pg=lp" if params else "")
        headers = {
            "Accept": "application/json",
            "Host": PRODUCTION_HOST,
            "Connection": "close",
        }
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json; charset=UTF-8"
            data = json.dumps(
                body,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        if bearer_token:
            headers["Authorization"] = "Bearer " + bearer_token

        connection = None
        try:
            connection = self._open_owned_connection()
            if (method, path) == ("GET", "/auth/key"):
                self._pending_auth_key_ownership_verified = True
            connection.request(
                method,
                target,
                body=data,
                headers=headers,
            )
            response = connection.getresponse()
            response_body = response.read(_MAX_RESPONSE + 1)
            if len(response_body) > _MAX_RESPONSE:
                raise TrueApiProtocolError(
                    "True API response exceeds local safety limit"
                )
            status = int(response.status)
            self.audit.record(
                method=method,
                endpoint=path,
                cis_count=cis_count,
                http_status=status,
            )
            if not 200 <= status < 300:
                safe = safe_transport_error(status, {}, response_body)
                raise TrueApiHttpError(
                    status,
                    safe.safe_error_message or f"True API HTTP {status}",
                    content_type=safe.content_type,
                    body_sha256=safe.body_sha256,
                    safe_error_code=safe.safe_error_code,
                )
            try:
                return (
                    json.loads(response_body.decode("utf-8"))
                    if response_body
                    else None
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TrueApiProtocolError(
                    "True API returned non-JSON content"
                ) from exc
        except ProductionMutationDisabled:
            raise
        except TrueApiError:
            raise
        except GostTlsUnavailable:
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
                None,
                "CryptoPro stunnel MSSPI GOST TLS transport error",
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    def close(self) -> None:
        if self._closed and self._process is None and self._temp_dir is None:
            return
        self._closed = True
        self._live_verified = False
        self._startup_ownership_verified = False
        self._pending_auth_key_ownership_verified = False
        self._stop_process()
        self._cleanup_config()
        self._port = None
