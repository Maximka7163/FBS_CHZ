from __future__ import annotations

import atexit
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Protocol

from wbcz.models import KiState
from wbcz.true_api import TrueApiError


PRODUCTION_HOST = "markirovka.crpt.ru"
PRODUCTION_BASE_PATH = "/api/v3/true-api"
PRODUCTION_BASE_URL = f"https://{PRODUCTION_HOST}{PRODUCTION_BASE_PATH}"
CISES_INFO_BATCH_LIMIT = 1000
CISES_INFO_MAX_RPS = 50

# Exact v0.4 production allowlist. Anything else fails before network I/O.
_ALLOWED_ENDPOINTS = frozenset({
    ("GET", "/auth/key"),
    ("POST", "/auth/simpleSignIn"),
    ("POST", "/cises/info"),
})
_GOST_PUBLIC_KEY_OIDS = frozenset({
    "1.2.643.2.2.19",          # GOST R 34.10-2001
    "1.2.643.7.1.1.1.1",      # GOST R 34.10-2012 256
    "1.2.643.7.1.1.1.2",      # GOST R 34.10-2012 512
})
# Proof must describe the cipher suite negotiated for the actual MSSPI session.
# Configuration/offered cipher names never satisfy this expression.
_NEGOTIATED_GOST_CIPHER_RE = re.compile(
    r"SECPKG_ATTR_CIPHER_INFO\s*:\s*CipherSuite\s*:\s*(?:0x)?(c100|c101|c102)\b",
    re.IGNORECASE,
)


class ProductionMutationDisabled(RuntimeError):
    pass


class TrueApiProtocolError(TrueApiError):
    pass


class TrueApiHttpError(TrueApiError):
    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status


class GostTlsUnavailable(TrueApiError):
    pass


class LiveAuthorizationRequired(TrueApiError):
    pass


class AuthSigner(Protocol):
    """Authentication-challenge signing only. No document-signing contract."""

    def sign_auth_challenge(self, challenge: str) -> str:
        ...


class CertificateInspector(Protocol):
    """Local certificate diagnostics only; never signs and never reads PIN."""

    def inspect(self) -> dict[str, Any]:
        ...


@dataclass(frozen=True, slots=True)
class ActivityLocation:
    """Future production-withdraw setting; unused by v0.4 read-only checks."""

    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in {"FIAS_ID", "KPP"}:
            raise ValueError("Activity location kind must be FIAS_ID or KPP")
        if not self.value.strip():
            raise ValueError("Activity location value is empty")


@dataclass(frozen=True, slots=True)
class LiveReadOnlyConfig:
    enabled: bool
    participant_inn: str
    certificate_thumbprint: str | None = None
    base_url: str = PRODUCTION_BASE_URL
    audit_log_path: Path = Path("live_true_api.jsonl")
    activity_location: ActivityLocation | None = None
    stunnel_path: Path | None = None
    cryptcp_path: Path | None = None

    @classmethod
    def from_env(cls) -> LiveReadOnlyConfig:
        mode = os.environ.get("WBCZ_TRUE_API_MODE", "offline").strip().casefold()
        enabled = mode in {"live", "live-read-only", "production-read-only"}
        inn = os.environ.get("WBCZ_PARTICIPANT_INN", "1234567890").strip()
        thumbprint = os.environ.get("WBCZ_UKEP_THUMBPRINT", "").strip() or None
        base_url = os.environ.get(
            "WBCZ_TRUE_API_BASE_URL", PRODUCTION_BASE_URL
        ).rstrip("/")
        audit = Path(
            os.environ.get("WBCZ_LIVE_AUDIT_LOG", "live_true_api.jsonl")
        )
        loc_kind = os.environ.get(
            "WBCZ_ACTIVITY_LOCATION_TYPE", ""
        ).strip().upper()
        loc_value = os.environ.get(
            "WBCZ_ACTIVITY_LOCATION_VALUE", ""
        ).strip()
        location = (
            ActivityLocation(loc_kind, loc_value)
            if loc_kind and loc_value
            else None
        )
        stunnel = os.environ.get("WBCZ_CRYPTOPRO_STUNNEL", "").strip()
        cryptcp = os.environ.get("WBCZ_CRYPTOPRO_CRYPTCP", "").strip()
        if enabled:
            if os.name != "nt":
                raise ValueError("LIVE READ-ONLY requires Windows + CryptoPro CSP")
            if not thumbprint:
                raise ValueError(
                    "WBCZ_UKEP_THUMBPRINT is required in live read-only mode"
                )
            if not inn.isascii() or not inn.isdigit() or len(inn) not in (10, 12):
                raise ValueError(
                    "WBCZ_PARTICIPANT_INN must contain 10 or 12 digits"
                )
            if base_url != PRODUCTION_BASE_URL:
                raise ValueError(
                    "v0.4 live mode allows only the official production True API v3 base URL"
                )
        return cls(
            enabled=enabled,
            participant_inn=inn,
            certificate_thumbprint=thumbprint,
            base_url=base_url,
            audit_log_path=audit,
            activity_location=location,
            stunnel_path=Path(stunnel) if stunnel else None,
            cryptcp_path=Path(cryptcp) if cryptcp else None,
        )


@dataclass(frozen=True, slots=True)
class AuthSession:
    bearer_token: str
    expire_date: datetime


class JsonlLiveAudit:
    """Metadata-only LIVE audit. Secrets are not accepted by this interface."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        method: str,
        endpoint: str,
        cis_count: int,
        http_status: int | None,
        request_id: str | None = None,
        error: str | None = None,
    ) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "mode": "LIVE_READ_ONLY",
            "method": method,
            "endpoint": endpoint,
            "cis_count": cis_count,
            "http_status": http_status,
            "request_id": request_id,
            "error": error,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )


def _find_cryptopro_binary(explicit: Path | None, filename: str) -> Path:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if path.name.casefold() != filename.casefold():
            raise GostTlsUnavailable(f"Expected {filename}, got {path.name}")
        if not path.is_file():
            raise GostTlsUnavailable(f"CryptoPro tool not found: {path}")
        return path

    found = shutil.which(filename)
    if found:
        return Path(found).resolve()

    candidates: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if base:
            candidates.append(Path(base) / "Crypto Pro" / "CSP" / filename)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise GostTlsUnavailable(
        f"{filename} not found. Install CryptoPro CSP components or set the explicit path."
    )


class CryptoProGostTlsTunnel:
    """Loopback HTTP -> CryptoPro stunnel-msspi -> production GOST TLS."""

    def __init__(
        self,
        executable: str | Path | None = None,
        *,
        target_host: str = PRODUCTION_HOST,
        target_port: int = 443,
        startup_timeout: float = 12.0,
        process_factory: Callable[..., subprocess.Popen[Any]] = subprocess.Popen,
    ) -> None:
        self._explicit = Path(executable) if executable else None
        self.target_host = target_host
        self.target_port = target_port
        self.startup_timeout = startup_timeout
        self._process_factory = process_factory
        self._process: subprocess.Popen[Any] | None = None
        self._temp: tempfile.TemporaryDirectory[str] | None = None
        self._port: int | None = None
        self._log_path: Path | None = None
        self._lock = threading.Lock()
        atexit.register(self.close)

    @property
    def executable(self) -> Path:
        return _find_cryptopro_binary(self._explicit, "stunnel_msspi.exe")

    @property
    def local_port(self) -> int:
        self.start()
        assert self._port is not None
        return self._port

    def diagnostics(self) -> dict[str, Any]:
        executable = self.executable
        return {
            "mechanism": "CryptoPro CSP stunnel-msspi / MSSPI GOST TLS",
            "executable": str(executable),
            "target_host": self.target_host,
            "server_certificate_validation": True,
            "verify_chain": True,
            "tls_version": "TLSv1.2",
            "cipher_policy": "GOST_ONLY",
            "hostname_check": self.target_host,
            "sni": self.target_host,
            "gost_session_verified": self._gost_session_seen(),
            "negotiated_gost_cipher_id": self._negotiated_gost_cipher_id(),
            "openssl_tls_to_production": False,
        }

    def session_marker(self) -> int:
        path = self._log_path
        if path is None or not path.exists():
            return 0
        return path.stat().st_size

    def _negotiated_gost_cipher_id(self, start: int = 0) -> str | None:
        path = self._log_path
        if path is None or not path.exists():
            return None
        with path.open("rb") as stream:
            stream.seek(start)
            text = stream.read().decode("utf-8", errors="replace")
        match = _NEGOTIATED_GOST_CIPHER_RE.search(text)
        return match.group(1).upper() if match else None

    def _gost_session_seen(self, start: int = 0) -> bool:
        # Configuration text and offered cipher names are not session proof.
        # Only an explicit negotiated MSSPI CipherSuite marker is accepted.
        return self._negotiated_gost_cipher_id(start) is not None

    def assert_gost_session(self, start: int = 0) -> None:
        if not self._gost_session_seen(start):
            raise GostTlsUnavailable(
                "CryptoPro TLS connection was established, but a negotiated GOST cipher suite could not be proven from stunnel-msspi diagnostics"
            )

    @staticmethod
    def _free_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _config(self, port: int, log_path: Path) -> str:
        return "\n".join([
            "foreground = yes",
            "debug = 7",
            f'output = "{log_path}"',
            "",
            "[true-api]",
            "client = yes",
            "msspi = yes",
            f"accept = 127.0.0.1:{port}",
            f"connect = {self.target_host}:{self.target_port}",
            f"sni = {self.target_host}",
            "sslVersion = TLSv1.2",
            "ciphers = GOST2012-GOST8912-GOST8912:GOST2001-GOST89-GOST89",
            "verify = 2",
            f"checkHost = {self.target_host}",
            "",
        ])

    def start(self) -> None:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return
            if os.name != "nt" and self._process_factory is subprocess.Popen:
                raise GostTlsUnavailable(
                    "CryptoPro production TLS transport is Windows-only"
                )
            executable = self.executable
            self._temp = tempfile.TemporaryDirectory(prefix="wbcz-gost-tls-")
            temp = Path(self._temp.name)
            port = self._free_loopback_port()
            config_path = temp / "stunnel.conf"
            log_path = temp / "stunnel.log"
            self._log_path = log_path
            config_path.write_text(self._config(port, log_path), encoding="utf-8")
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            self._process = self._process_factory(
                [str(executable), str(config_path)],
                cwd=temp,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            self._port = port
            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    message = "CryptoPro stunnel-msspi exited during startup"
                    if log_path.exists():
                        log = log_path.read_text(
                            encoding="utf-8", errors="replace"
                        )[-2000:]
                        message += ": " + log.replace("\n", " ")[:1800]
                    self.close()
                    raise GostTlsUnavailable(message)
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=0.15
                    ):
                        return
                except OSError:
                    time.sleep(0.08)
            self.close()
            raise GostTlsUnavailable(
                "CryptoPro stunnel-msspi did not open its loopback listener"
            )

    def close(self) -> None:
        process = self._process
        self._process = None
        self._port = None
        self._log_path = None
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None


class ReadOnlyTrueApiTransport:
    """Production HTTP over the dedicated CryptoPro/MSSPI GOST TLS tunnel."""

    def __init__(
        self,
        base_url: str = PRODUCTION_BASE_URL,
        audit: JsonlLiveAudit | None = None,
        *,
        timeout: float = 30.0,
        tunnel: CryptoProGostTlsTunnel | None = None,
        connection_factory: Callable[..., http.client.HTTPConnection] = http.client.HTTPConnection,
        opener: Any = None,
    ) -> None:
        del opener  # backward-compatible test keyword; never a TLS fallback
        if base_url.rstrip("/") != PRODUCTION_BASE_URL:
            raise ValueError(
                "Only the official production True API v3 base is allowed"
            )
        self.base_url = PRODUCTION_BASE_URL
        self.audit = audit or JsonlLiveAudit("live_true_api.jsonl")
        self.timeout = timeout
        self.tunnel = tunnel or CryptoProGostTlsTunnel()
        self._connection_factory = connection_factory

    @staticmethod
    def assert_allowed(
        method: str,
        path: str,
        params: dict[str, str] | None = None,
    ) -> None:
        method = method.upper()
        if (method, path) not in _ALLOWED_ENDPOINTS:
            raise ProductionMutationDisabled(
                f"Production endpoint is disabled in v0.4: {method} {path}"
            )
        if path == "/cises/info":
            if params != {"pg": "lp"}:
                raise ProductionMutationDisabled(
                    "cises/info is allowed only with pg=lp"
                )
        elif params:
            raise ProductionMutationDisabled(
                "Unexpected query parameters are disabled in v0.4"
            )

    @staticmethod
    def _query(params: dict[str, str] | None) -> str:
        if not params:
            return ""
        return "?pg=lp"

    def tls_diagnostics(self) -> dict[str, Any]:
        return self.tunnel.diagnostics()

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
        # Safety barrier runs before tunnel startup or any network operation.
        self.assert_allowed(method, path, params)
        target = PRODUCTION_BASE_PATH + path + self._query(params)
        headers = {
            "Accept": "application/json",
            "Host": PRODUCTION_HOST,
            "Connection": "close",
        }
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json; charset=UTF-8"
            data = json.dumps(
                body, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            headers["Content-Length"] = str(len(data))
        if bearer_token:
            headers["Authorization"] = "Bearer " + bearer_token

        connection: http.client.HTTPConnection | None = None
        try:
            local_port = self.tunnel.local_port
            session_marker = self.tunnel.session_marker()
            connection = self._connection_factory(
                "127.0.0.1", local_port, timeout=self.timeout
            )
            connection.putrequest(method, target, skip_host=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders(data)
            response = connection.getresponse()
            status = int(response.status)
            response_headers = response.headers
            raw = response.read()
            request_id = self._request_id(response_headers)
            try:
                self.tunnel.assert_gost_session(session_marker)
            except GostTlsUnavailable:
                self.audit.record(
                    method=method,
                    endpoint=path,
                    cis_count=cis_count,
                    http_status=status,
                    request_id=request_id,
                    error="GOST_TLS_NOT_VERIFIED",
                )
                raise
            self.audit.record(
                method=method,
                endpoint=path,
                cis_count=cis_count,
                http_status=status,
                request_id=request_id,
            )
            if not 200 <= status < 300:
                text = raw[:4096].decode("utf-8", errors="replace")
                raise TrueApiHttpError(
                    status, f"True API HTTP {status}: {text[:500]}"
                )
        except ProductionMutationDisabled:
            raise
        except TrueApiError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            self.audit.record(
                method=method,
                endpoint=path,
                cis_count=cis_count,
                http_status=None,
                error=type(exc).__name__,
            )
            raise TrueApiHttpError(
                None, f"CryptoPro GOST TLS transport error: {exc}"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
        try:
            return json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrueApiProtocolError(
                "True API returned non-JSON content"
            ) from exc

    @staticmethod
    def _request_id(headers: Any) -> str | None:
        if headers is None:
            return None
        for name in ("X-Request-ID", "X-Correlation-ID", "Traceparent"):
            value = headers.get(name)
            if value:
                return str(value)[:200]
        return None


class WindowsCryptoProCertificateInspector:
    """Safe local diagnostics for the selected CurrentUser\\My UKEP cert."""

    def __init__(
        self,
        certificate_thumbprint: str,
        cryptcp_path: str | Path | None = None,
        powershell: str = "powershell.exe",
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        normalized = certificate_thumbprint.replace(" ", "").upper()
        if not normalized:
            raise ValueError("Certificate thumbprint is required")
        self.thumbprint = normalized
        self._explicit_cryptcp = Path(cryptcp_path) if cryptcp_path else None
        self.powershell = powershell
        self._runner = runner

    @property
    def cryptcp(self) -> Path:
        return _find_cryptopro_binary(self._explicit_cryptcp, "cryptcp.exe")

    def inspect(self) -> dict[str, Any]:
        if os.name != "nt" and self._runner is subprocess.run:
            raise TrueApiError("Certificate diagnostics require Windows")
        script = r'''
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class WbczCertNative {
  [StructLayout(LayoutKind.Sequential)]
  public struct CRYPT_KEY_PROV_INFO {
    public IntPtr pwszContainerName;
    public IntPtr pwszProvName;
    public UInt32 dwProvType;
    public UInt32 dwFlags;
    public UInt32 cProvParam;
    public IntPtr rgProvParam;
    public UInt32 dwKeySpec;
  }
  [DllImport("crypt32.dll", SetLastError=true)]
  public static extern bool CertGetCertificateContextProperty(
    IntPtr pCertContext, UInt32 dwPropId, IntPtr pvData, ref UInt32 pcbData);
}
"@
$thumb=$env:WBCZ_CERT_THUMBPRINT.Replace(' ','').ToUpperInvariant()
$store=New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
try {
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
  $cert=$store.Certificates | Where-Object {$_.Thumbprint.Replace(' ','').ToUpperInvariant() -eq $thumb} | Select-Object -First 1
  if ($null -eq $cert) { throw 'UKEP certificate not found in CurrentUser\\My' }
  $size=[uint32]0
  if (-not [WbczCertNative]::CertGetCertificateContextProperty($cert.Handle,2,[IntPtr]::Zero,[ref]$size)) { throw 'Certificate has no CryptoAPI provider information' }
  $ptr=[Runtime.InteropServices.Marshal]::AllocHGlobal([int]$size)
  try {
    if (-not [WbczCertNative]::CertGetCertificateContextProperty($cert.Handle,2,$ptr,[ref]$size)) { throw 'Cannot read certificate provider information' }
    $info=[Runtime.InteropServices.Marshal]::PtrToStructure($ptr,[type][WbczCertNative+CRYPT_KEY_PROV_INFO])
    $provider=[Runtime.InteropServices.Marshal]::PtrToStringUni($info.pwszProvName)
  } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr) }
  [pscustomobject]@{
    thumbprint=$cert.Thumbprint.Replace(' ','').ToUpperInvariant()
    hasPrivateKey=$cert.HasPrivateKey
    notBefore=$cert.NotBefore.ToUniversalTime().ToString('o')
    notAfter=$cert.NotAfter.ToUniversalTime().ToString('o')
    publicKeyOid=$cert.PublicKey.Oid.Value
    signatureOid=$cert.SignatureAlgorithm.Value
    providerName=$provider
  } | ConvertTo-Json -Compress
} finally { $store.Close() }
'''
        env = os.environ.copy()
        env["WBCZ_CERT_THUMBPRINT"] = self.thumbprint
        completed = self._runner(
            [
                self.powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            text=True,
            capture_output=True,
            timeout=30,
            env=env,
            check=False,
        )
        if completed.returncode != 0:
            raise TrueApiError(
                (completed.stderr.strip() or "Certificate diagnostics failed")[:1000]
            )
        try:
            data = json.loads(completed.stdout.strip())
        except json.JSONDecodeError as exc:
            raise TrueApiError("Certificate diagnostics returned invalid data") from exc
        if data.get("thumbprint") != self.thumbprint:
            raise TrueApiError("Certificate thumbprint mismatch")
        if data.get("hasPrivateKey") is not True:
            raise TrueApiError("Selected certificate has no private key")
        try:
            not_before = datetime.fromisoformat(
                str(data["notBefore"]).replace("Z", "+00:00")
            )
            not_after = datetime.fromisoformat(
                str(data["notAfter"]).replace("Z", "+00:00")
            )
        except (KeyError, ValueError) as exc:
            raise TrueApiError("Invalid certificate validity data") from exc
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if not (not_before <= now <= not_after):
            raise TrueApiError("Selected certificate is not currently valid")
        public_key_oid = str(data.get("publicKeyOid") or "")
        if public_key_oid not in _GOST_PUBLIC_KEY_OIDS:
            raise TrueApiError(
                f"Selected certificate is not a supported GOST certificate: {public_key_oid or 'missing OID'}"
            )
        provider = str(data.get("providerName") or "")
        normalized_provider = provider.casefold().replace("-", " ")
        if (
            "crypto pro" not in normalized_provider
            and "cryptopro" not in normalized_provider
        ):
            raise TrueApiError(
                "Selected private key is not linked to a CryptoPro provider"
            )
        cryptcp = self.cryptcp
        return {
            "certificate_found": True,
            "thumbprint_match": True,
            "has_private_key": True,
            "not_expired": True,
            "public_key_oid": public_key_oid,
            "signature_oid": str(data.get("signatureOid") or ""),
            "provider": provider,
            "gost_compatible": True,
            "cryptopro_provider": True,
            "signing_mechanism": "CryptoPro cryptcp attached CMS",
            "cryptcp": str(cryptcp),
        }


class WindowsCryptoProAuthSigner:
    """CryptoPro cryptcp attached CMS signer for authentication challenge only."""

    def __init__(
        self,
        certificate_thumbprint: str,
        cryptcp_path: str | Path | None = None,
        *,
        inspector: CertificateInspector | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        normalized = certificate_thumbprint.replace(" ", "").upper()
        if not normalized:
            raise ValueError("Certificate thumbprint is required")
        self.thumbprint = normalized
        self._explicit_cryptcp = Path(cryptcp_path) if cryptcp_path else None
        self._runner = runner
        self.inspector = inspector or WindowsCryptoProCertificateInspector(
            normalized,
            cryptcp_path=cryptcp_path,
            runner=runner,
        )

    @property
    def cryptcp(self) -> Path:
        return _find_cryptopro_binary(self._explicit_cryptcp, "cryptcp.exe")

    def sign_auth_challenge(self, challenge: str) -> str:
        if not challenge:
            raise ValueError("Empty authentication challenge")
        self.inspector.inspect()
        with tempfile.TemporaryDirectory(prefix="wbcz-auth-") as directory:
            temp = Path(directory)
            source = temp / "challenge.bin"
            source.write_bytes(challenge.encode("utf-8"))
            command = [
                str(self.cryptcp),
                "-signf",
                "-attached",
                "-der",
                "-strict",
                "-cert",
                "-uMy",
                "-thumbprint",
                self.thumbprint,
                "-dir",
                str(temp),
                str(source),
                "-fext",
                ".sgn",
            ]
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            completed = self._runner(
                command,
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
                creationflags=creationflags,
            )
            if completed.returncode != 0:
                raise TrueApiError(
                    (
                        completed.stderr.strip()
                        or completed.stdout.strip()
                        or "CryptoPro cryptcp authentication signing failed"
                    )[:1000]
                )
            expected = source.with_name(source.name + ".sgn")
            if not expected.is_file():
                candidates = list(temp.glob("*.sgn"))
                if len(candidates) != 1:
                    raise TrueApiError(
                        "CryptoPro cryptcp did not produce the attached CMS signature"
                    )
                expected = candidates[0]
            signature = expected.read_bytes()
            if not signature:
                raise TrueApiError(
                    "Authentication signer returned an empty signature"
                )
            return base64.b64encode(signature).decode("ascii")


class TrueApiAuthenticator:
    def __init__(
        self,
        transport: ReadOnlyTrueApiTransport,
        signer: AuthSigner,
        participant_inn: str,
    ) -> None:
        self.transport = transport
        self.signer = signer
        self.participant_inn = participant_inn

    @staticmethod
    def _challenge(payload: Any) -> tuple[str, str]:
        if not isinstance(payload, dict):
            raise TrueApiProtocolError(
                "/auth/key returned an unexpected payload"
            )
        uuid = payload.get("uuid")
        data = payload.get("data")
        if (
            not isinstance(uuid, str)
            or not uuid
            or not isinstance(data, str)
            or not data
        ):
            raise TrueApiProtocolError(
                "/auth/key response misses uuid/data"
            )
        return uuid, data

    def preflight(self) -> dict[str, Any]:
        challenge = self.transport.request_json("GET", "/auth/key")
        uuid, data = self._challenge(challenge)
        return {
            "crypto_pro_tls": True,
            "true_api_available": True,
            "challenge_received": True,
            "challenge_uuid_present": bool(uuid),
            "challenge_size": len(data),
            "tls": self.transport.tls_diagnostics(),
        }

    def authenticate(self) -> AuthSession:
        challenge = self.transport.request_json("GET", "/auth/key")
        uuid, data = self._challenge(challenge)
        signed = self.signer.sign_auth_challenge(data)
        response = self.transport.request_json(
            "POST",
            "/auth/simpleSignIn",
            body={
                "uuid": uuid,
                "data": signed,
                "inn": self.participant_inn,
                "unitedToken": True,
            },
        )
        if not isinstance(response, dict):
            raise TrueApiProtocolError(
                "/auth/simpleSignIn returned an unexpected payload"
            )
        token = response.get("uuidToken")
        expire = response.get("expireDate")
        if not isinstance(token, str) or not token:
            raise TrueApiProtocolError(
                "UUID authentication response misses uuidToken"
            )
        if not isinstance(expire, str) or not expire:
            raise TrueApiProtocolError(
                "UUID authentication response misses expireDate"
            )
        try:
            expire_date = datetime.fromisoformat(expire.replace("Z", "+00:00"))
            if expire_date.tzinfo is None:
                expire_date = expire_date.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise TrueApiProtocolError(
                "Invalid expireDate in authentication response"
            ) from exc
        return AuthSession(token, expire_date.astimezone(timezone.utc))


class TrueApiCisesInfoAdapter:
    """True API response -> conservative internal KiState."""

    _STATUS = {
        "INTRODUCED": "IN_CIRCULATION",
        "RETIRED": "WITHDRAWN",
    }

    def normalize(self, requested_cis: str, item: Any) -> KiState:
        if not isinstance(item, dict):
            raise TrueApiProtocolError("cises/info item is not an object")
        if item.get("errorCode") or item.get("errorMessage"):
            raise TrueApiError(
                "cises/info returned an error for the requested KI"
            )
        info = item.get("cisInfo", item)
        if not isinstance(info, dict):
            raise TrueApiProtocolError("cises/info item misses cisInfo")
        echoed = info.get("requestedCis") or info.get("cis")
        if isinstance(echoed, str) and echoed != requested_cis:
            raise TrueApiProtocolError("cises/info returned a mismatched KI")

        raw_status = info.get("status")
        status = self._STATUS.get(
            str(raw_status).upper(), f"UNKNOWN:{raw_status}"
        )
        raw_status_ex = info.get("statusEx")
        if raw_status_ex is None or str(raw_status_ex).upper() in {"", "EMPTY"}:
            status_ex = None
        else:
            status_ex = f"UNKNOWN:{raw_status_ex}"

        raw_pg = info.get("productGroup")
        product_group = raw_pg if isinstance(raw_pg, str) and raw_pg else "lp"
        return KiState(
            status=status,
            statusEx=status_ex,
            withdrawReason=(
                info.get("withdrawReason")
                if isinstance(info.get("withdrawReason"), str)
                else None
            ),
            ownerInn=(
                info.get("ownerInn")
                if isinstance(info.get("ownerInn"), str)
                else None
            ),
            productGroup=product_group,
        )


class LiveTrueApiClient:
    """Explicitly-authenticated production read-only True API client."""

    def __init__(
        self,
        transport: ReadOnlyTrueApiTransport,
        authenticator: TrueApiAuthenticator,
        *,
        batch_limit: int = CISES_INFO_BATCH_LIMIT,
        max_requests_per_second: float = 10.0,
        adapter: TrueApiCisesInfoAdapter | None = None,
        certificate_inspector: CertificateInspector | None = None,
    ) -> None:
        if not 1 <= batch_limit <= CISES_INFO_BATCH_LIMIT:
            raise ValueError(
                f"batch_limit must be between 1 and {CISES_INFO_BATCH_LIMIT}"
            )
        if not 0 < max_requests_per_second <= CISES_INFO_MAX_RPS:
            raise ValueError(
                f"max_requests_per_second must be <= {CISES_INFO_MAX_RPS}"
            )
        self.transport = transport
        self.authenticator = authenticator
        self.batch_limit = batch_limit
        self.min_interval = 1.0 / max_requests_per_second
        self.adapter = adapter or TrueApiCisesInfoAdapter()
        self._session: AuthSession | None = None
        self._cache: dict[str, KiState | Exception] = {}
        self._last_request_at = 0.0
        self.calls: list[str] = []
        self.preflight_ok = False
        self.certificate_inspector = certificate_inspector

    @classmethod
    def from_config(cls, config: LiveReadOnlyConfig) -> LiveTrueApiClient:
        if not config.enabled or not config.certificate_thumbprint:
            raise ValueError("Live read-only configuration is not enabled")
        audit = JsonlLiveAudit(config.audit_log_path)
        tunnel = CryptoProGostTlsTunnel(config.stunnel_path)
        transport = ReadOnlyTrueApiTransport(
            config.base_url, audit, tunnel=tunnel
        )
        inspector = WindowsCryptoProCertificateInspector(
            config.certificate_thumbprint,
            cryptcp_path=config.cryptcp_path,
        )
        signer = WindowsCryptoProAuthSigner(
            config.certificate_thumbprint,
            cryptcp_path=config.cryptcp_path,
            inspector=inspector,
        )
        authenticator = TrueApiAuthenticator(
            transport, signer, config.participant_inn
        )
        return cls(
            transport,
            authenticator,
            certificate_inspector=inspector,
        )

    @property
    def authenticated(self) -> bool:
        if self._session is None:
            return False
        return self._session.expire_date > datetime.now(timezone.utc)

    @property
    def expire_date(self) -> datetime | None:
        return self._session.expire_date if self._session is not None else None

    def preflight(self) -> dict[str, Any]:
        result = self.authenticator.preflight()
        certificate = (
            self.certificate_inspector.inspect()
            if self.certificate_inspector is not None
            else None
        )
        self.preflight_ok = True
        return {**result, "certificate": certificate}

    def authenticate(self) -> dict[str, Any]:
        if not self.preflight_ok:
            raise LiveAuthorizationRequired(
                "Run the CryptoPro TLS preflight before authentication"
            )
        self._session = self.authenticator.authenticate()
        self._cache.clear()
        return {
            "authenticated": True,
            "expire_date": self._session.expire_date.isoformat(),
            "submission": False,
            "document_signing": False,
        }

    def _bearer(self) -> str:
        if not self.authenticated or self._session is None:
            self._session = None
            raise LiveAuthorizationRequired(
                "LIVE READ-ONLY authorization is required or has expired"
            )
        return self._session.bearer_token

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        remaining = self.min_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last_request_at = time.monotonic()

    def prime(self, kizes: Iterable[str]) -> None:
        bearer = self._bearer()
        unique = list(dict.fromkeys(kizes))
        missing = [kiz for kiz in unique if kiz not in self._cache]
        for start in range(0, len(missing), self.batch_limit):
            batch = missing[start : start + self.batch_limit]
            if not batch:
                continue
            try:
                self._throttle()
                payload = self.transport.request_json(
                    "POST",
                    "/cises/info",
                    params={"pg": "lp"},
                    body={"cis": batch},
                    bearer_token=bearer,
                    cis_count=len(batch),
                )
                if (
                    isinstance(payload, dict)
                    and isinstance(payload.get("results"), list)
                ):
                    items = payload["results"]
                elif isinstance(payload, list):
                    items = payload
                else:
                    raise TrueApiProtocolError(
                        "cises/info returned an unexpected top-level payload"
                    )
            except Exception as exc:
                for kiz in batch:
                    self._cache[kiz] = exc
                continue

            by_requested: dict[str, Any] = {}
            for item in items:
                if not isinstance(item, dict):
                    continue
                info = item.get("cisInfo", item)
                if isinstance(info, dict):
                    key = info.get("requestedCis") or info.get("cis")
                    if isinstance(key, str):
                        by_requested[key] = item
            for kiz in batch:
                item = by_requested.get(kiz)
                if item is None:
                    self._cache[kiz] = TrueApiProtocolError(
                        "cises/info omitted requested KI"
                    )
                    continue
                try:
                    self._cache[kiz] = self.adapter.normalize(kiz, item)
                except Exception as exc:
                    self._cache[kiz] = exc

    def get_ki_state(self, kiz: str) -> KiState:
        self.calls.append(kiz)
        if kiz not in self._cache:
            self.prime([kiz])
        value = self._cache[kiz]
        if isinstance(value, Exception):
            raise value
        return value
