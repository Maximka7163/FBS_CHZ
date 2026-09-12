from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from typing import Any, Callable, Iterable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from wbcz.models import KiState
from wbcz.true_api import TrueApiError


PRODUCTION_BASE_URL = "https://markirovka.crpt.ru/api/v3/true-api"
CISES_INFO_BATCH_LIMIT = 1000
CISES_INFO_MAX_RPS = 50

# v0.4 is deliberately incapable of calling any production mutation endpoint.
_ALLOWED_ENDPOINTS = frozenset({
    ("GET", "/auth/key"),
    ("POST", "/auth/simpleSignIn"),
    ("POST", "/cises/info"),
})


class ProductionMutationDisabled(RuntimeError):
    pass


class TrueApiProtocolError(TrueApiError):
    pass


class TrueApiHttpError(TrueApiError):
    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status


class AuthSigner(Protocol):
    """Authentication-challenge signing only; not document signing."""

    def sign_auth_challenge(self, challenge: str) -> str:
        ...


@dataclass(frozen=True, slots=True)
class ActivityLocation:
    """Future production-withdraw setting. It is unused in v0.4 read-only."""

    kind: str  # FIAS_ID for IP, KPP for legal entity
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

    @classmethod
    def from_env(cls) -> LiveReadOnlyConfig:
        mode = os.environ.get("WBCZ_TRUE_API_MODE", "offline").strip().casefold()
        enabled = mode in {"live", "live-read-only", "production-read-only"}
        inn = os.environ.get("WBCZ_PARTICIPANT_INN", "1234567890").strip()
        thumbprint = os.environ.get("WBCZ_UKEP_THUMBPRINT", "").strip() or None
        base_url = os.environ.get("WBCZ_TRUE_API_BASE_URL", PRODUCTION_BASE_URL).rstrip("/")
        audit = Path(os.environ.get("WBCZ_LIVE_AUDIT_LOG", "live_true_api.jsonl"))
        loc_kind = os.environ.get("WBCZ_ACTIVITY_LOCATION_TYPE", "").strip().upper()
        loc_value = os.environ.get("WBCZ_ACTIVITY_LOCATION_VALUE", "").strip()
        location = ActivityLocation(loc_kind, loc_value) if loc_kind and loc_value else None
        if enabled:
            if not thumbprint:
                raise ValueError("WBCZ_UKEP_THUMBPRINT is required in live read-only mode")
            if not inn.isascii() or not inn.isdigit() or len(inn) not in (10, 12):
                raise ValueError("WBCZ_PARTICIPANT_INN must contain 10 or 12 digits")
            # v0.4 production is hard-bound to the official production True API base.
            if base_url != PRODUCTION_BASE_URL:
                raise ValueError("v0.4 live mode allows only the official production True API v3 base URL")
        return cls(enabled, inn, thumbprint, base_url, audit, location)


@dataclass(frozen=True, slots=True)
class AuthSession:
    bearer_token: str
    expire_date: datetime


class JsonlLiveAudit:
    """Safe metadata-only audit. Never accepts token/signature/private-key data."""

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
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "method": method,
            "endpoint": endpoint,
            "cis_count": cis_count,
            "http_status": http_status,
            "request_id": request_id,
            "error": error,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")


class ReadOnlyTrueApiTransport:
    """Production transport with an exact allowlist; all other calls are blocked."""

    def __init__(
        self,
        base_url: str = PRODUCTION_BASE_URL,
        audit: JsonlLiveAudit | None = None,
        *,
        timeout: float = 30.0,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        if base_url.rstrip("/") != PRODUCTION_BASE_URL:
            raise ValueError("Only the official production True API v3 base is allowed")
        self.base_url = PRODUCTION_BASE_URL
        self.audit = audit or JsonlLiveAudit("live_true_api.jsonl")
        self.timeout = timeout
        self._opener = opener

    @staticmethod
    def assert_allowed(method: str, path: str, params: dict[str, str] | None = None) -> None:
        method = method.upper()
        if (method, path) not in _ALLOWED_ENDPOINTS:
            raise ProductionMutationDisabled(f"Production endpoint is disabled in v0.4: {method} {path}")
        if path == "/cises/info":
            if params != {"pg": "lp"}:
                raise ProductionMutationDisabled("cises/info is allowed only with pg=lp")
        elif params:
            raise ProductionMutationDisabled("Unexpected query parameters are disabled in v0.4")

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
        url = self.base_url + path
        if params:
            url += "?" + urlencode(params)
        headers = {"Accept": "application/json"}
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json; charset=UTF-8"
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if bearer_token:
            headers["Authorization"] = "Bearer " + bearer_token
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener(request, timeout=self.timeout) as response:
                status = int(getattr(response, "status", response.getcode()))
                request_id = self._request_id(response.headers)
                raw = response.read()
                self.audit.record(
                    method=method, endpoint=path, cis_count=cis_count,
                    http_status=status, request_id=request_id,
                )
        except HTTPError as exc:
            request_id = self._request_id(exc.headers)
            body_text = exc.read(4096).decode("utf-8", errors="replace")
            self.audit.record(
                method=method, endpoint=path, cis_count=cis_count,
                http_status=exc.code, request_id=request_id,
                error=f"HTTP {exc.code}",
            )
            raise TrueApiHttpError(exc.code, f"True API HTTP {exc.code}: {body_text[:500]}") from exc
        except URLError as exc:
            self.audit.record(
                method=method, endpoint=path, cis_count=cis_count,
                http_status=None, error=type(exc.reason).__name__,
            )
            raise TrueApiHttpError(None, f"True API transport error: {exc.reason}") from exc
        try:
            return json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrueApiProtocolError("True API returned non-JSON content") from exc

    @staticmethod
    def _request_id(headers: Any) -> str | None:
        if headers is None:
            return None
        for name in ("X-Request-ID", "X-Correlation-ID", "Traceparent"):
            value = headers.get(name)
            if value:
                return str(value)[:200]
        return None


class WindowsCryptoProAuthSigner:
    """Signs ONLY the True API auth challenge via a certificate in Windows store.

    CryptoPro CSP remains the private-key provider. The private key never leaves
    the Windows certificate store. The produced CMS is attached and base64-encoded,
    as required by True API auth. There is intentionally no document-sign method.
    """

    def __init__(self, certificate_thumbprint: str, powershell: str = "powershell.exe") -> None:
        normalized = certificate_thumbprint.replace(" ", "").upper()
        if not normalized:
            raise ValueError("Certificate thumbprint is required")
        self.thumbprint = normalized
        self.powershell = powershell

    def sign_auth_challenge(self, challenge: str) -> str:
        if not challenge:
            raise ValueError("Empty authentication challenge")
        script = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$thumb = $env:WBCZ_CERT_THUMBPRINT.Replace(' ','').ToUpperInvariant()
$challenge = [Console]::In.ReadToEnd()
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
try {
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
  $cert = $store.Certificates | Where-Object {
    $_.Thumbprint.Replace(' ','').ToUpperInvariant() -eq $thumb
  } | Select-Object -First 1
  if ($null -eq $cert) { throw 'УКЭП certificate not found in CurrentUser\\My' }
  if (-not $cert.HasPrivateKey) { throw 'Selected certificate has no private key' }
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($challenge)
  $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,$bytes)
  $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms ($content, $false)
  $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner ($cert)
  $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
  $cms.ComputeSignature($signer)
  [Console]::Out.Write([Convert]::ToBase64String($cms.Encode()))
} finally {
  $store.Close()
}
'''
        env = os.environ.copy()
        env["WBCZ_CERT_THUMBPRINT"] = self.thumbprint
        completed = subprocess.run(
            [self.powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            input=challenge,
            text=True,
            capture_output=True,
            timeout=120,
            env=env,
            check=False,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or "CryptoPro/Windows certificate signing failed"
            raise TrueApiError(message[:1000])
        signature = completed.stdout.strip()
        if not signature:
            raise TrueApiError("Authentication signer returned an empty signature")
        return signature


class TrueApiAuthenticator:
    def __init__(self, transport: ReadOnlyTrueApiTransport, signer: AuthSigner) -> None:
        self.transport = transport
        self.signer = signer

    def authenticate(self) -> AuthSession:
        challenge = self.transport.request_json("GET", "/auth/key")
        if not isinstance(challenge, dict):
            raise TrueApiProtocolError("/auth/key returned an unexpected payload")
        uuid = challenge.get("uuid")
        data = challenge.get("data")
        if not isinstance(uuid, str) or not uuid or not isinstance(data, str) or not data:
            raise TrueApiProtocolError("/auth/key response misses uuid/data")
        signed = self.signer.sign_auth_challenge(data)
        response = self.transport.request_json(
            "POST", "/auth/simpleSignIn",
            body={"uuid": uuid, "data": signed, "unitedToken": True},
        )
        if not isinstance(response, dict):
            raise TrueApiProtocolError("/auth/simpleSignIn returned an unexpected payload")
        token = response.get("uuidToken")
        expire = response.get("expireDate")
        if not isinstance(token, str) or not token:
            raise TrueApiProtocolError("UUID authentication response misses uuidToken")
        if not isinstance(expire, str) or not expire:
            raise TrueApiProtocolError("UUID authentication response misses expireDate")
        try:
            expire_date = datetime.fromisoformat(expire.replace("Z", "+00:00"))
            if expire_date.tzinfo is None:
                expire_date = expire_date.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise TrueApiProtocolError("Invalid expireDate in authentication response") from exc
        return AuthSession(token, expire_date.astimezone(timezone.utc))


class TrueApiCisesInfoAdapter:
    """Maps raw cises/info records to the small conservative domain KiState."""

    _STATUS = {
        "INTRODUCED": "IN_CIRCULATION",
        "RETIRED": "WITHDRAWN",
    }

    def normalize(self, requested_cis: str, item: Any) -> KiState:
        if not isinstance(item, dict):
            raise TrueApiProtocolError("cises/info item is not an object")
        if item.get("errorCode") or item.get("errorMessage"):
            raise TrueApiError(
                f"cises/info error for selected KI: {item.get('errorCode') or ''} {item.get('errorMessage') or ''}".strip()
            )
        info = item.get("cisInfo", item)
        if not isinstance(info, dict):
            raise TrueApiProtocolError("cises/info item misses cisInfo")
        echoed = info.get("requestedCis") or info.get("cis")
        if isinstance(echoed, str) and echoed != requested_cis:
            raise TrueApiProtocolError("cises/info returned a mismatched KI")
        raw_status = info.get("status")
        status = self._STATUS.get(str(raw_status).upper(), f"UNKNOWN:{raw_status}")
        raw_status_ex = info.get("statusEx")
        if raw_status_ex is None or str(raw_status_ex).upper() in {"", "EMPTY"}:
            status_ex = None
        else:
            status_ex = f"UNKNOWN:{raw_status_ex}"
        product_group = info.get("productGroup")
        return KiState(
            status=status,
            statusEx=status_ex,
            withdrawReason=info.get("withdrawReason") if isinstance(info.get("withdrawReason"), str) else None,
            ownerInn=info.get("ownerInn") if isinstance(info.get("ownerInn"), str) else None,
            productGroup=product_group if isinstance(product_group, str) else None,
        )


class LiveTrueApiClient:
    """Read-only production True API client with sequential safe batching."""

    def __init__(
        self,
        transport: ReadOnlyTrueApiTransport,
        authenticator: TrueApiAuthenticator,
        *,
        batch_limit: int = CISES_INFO_BATCH_LIMIT,
        max_requests_per_second: float = 10.0,
        adapter: TrueApiCisesInfoAdapter | None = None,
    ) -> None:
        if not 1 <= batch_limit <= CISES_INFO_BATCH_LIMIT:
            raise ValueError(f"batch_limit must be between 1 and {CISES_INFO_BATCH_LIMIT}")
        if not 0 < max_requests_per_second <= CISES_INFO_MAX_RPS:
            raise ValueError(f"max_requests_per_second must be <= {CISES_INFO_MAX_RPS}")
        self.transport = transport
        self.authenticator = authenticator
        self.batch_limit = batch_limit
        self.min_interval = 1.0 / max_requests_per_second
        self.adapter = adapter or TrueApiCisesInfoAdapter()
        self._session: AuthSession | None = None
        self._cache: dict[str, KiState | Exception] = {}
        self._last_request_at = 0.0
        self.calls: list[str] = []

    @classmethod
    def from_config(cls, config: LiveReadOnlyConfig) -> LiveTrueApiClient:
        if not config.enabled or not config.certificate_thumbprint:
            raise ValueError("Live read-only configuration is not enabled")
        audit = JsonlLiveAudit(config.audit_log_path)
        transport = ReadOnlyTrueApiTransport(config.base_url, audit)
        signer = WindowsCryptoProAuthSigner(config.certificate_thumbprint)
        return cls(transport, TrueApiAuthenticator(transport, signer))

    def _bearer(self) -> str:
        now = datetime.now(timezone.utc)
        if self._session is None or self._session.expire_date <= now + timedelta(minutes=1):
            self._session = self.authenticator.authenticate()
        return self._session.bearer_token

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        remaining = self.min_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last_request_at = time.monotonic()

    def prime(self, kizes: Iterable[str]) -> None:
        unique = list(dict.fromkeys(kizes))
        missing = [kiz for kiz in unique if kiz not in self._cache]
        for start in range(0, len(missing), self.batch_limit):
            batch = missing[start:start + self.batch_limit]
            if not batch:
                continue
            self._throttle()
            payload = self.transport.request_json(
                "POST", "/cises/info", params={"pg": "lp"}, body=batch,
                bearer_token=self._bearer(), cis_count=len(batch),
            )
            if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                items = payload["results"]
            elif isinstance(payload, list):
                items = payload
            else:
                raise TrueApiProtocolError("cises/info returned an unexpected top-level payload")
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
                    self._cache[kiz] = TrueApiProtocolError("cises/info omitted requested KI")
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
