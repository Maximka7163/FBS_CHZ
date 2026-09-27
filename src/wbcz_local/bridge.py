from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import threading
from typing import Any, Iterable

from wbcz.cis_inventory import MAX_BATCH, SharedRateLimiter
from wbcz.models import KiState
from wbcz.true_api import normalize_cis
from wbcz_ui.live_true_api import (
    AuthSession,
    CryptoProGostTlsTunnel,
    JsonlLiveAudit,
    LiveAuthorizationRequired,
    ReadOnlyTrueApiTransport,
    TrueApiCisesInfoAdapter,
    TrueApiError,
    TrueApiHttpError,
    TrueApiProtocolError,
    WindowsCryptoProCertificateDiscovery,
    _find_cryptopro_binary,
)


class LocalTrueApiUnavailable(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class CryptoProFoundationStatus:
    windows: bool
    csp_available: bool
    browser_cades_available: bool | None
    ukep_available: bool | None
    gost_transport_available: bool
    cryptcp_available: bool
    cryptcp_path: str | None
    stunnel_path: str | None
    real_read_enabled: bool
    business_write_enabled: bool = False

    @property
    def cryptopro_csp_detected(self) -> bool:
        # Compatibility field for existing local diagnostics only.
        return self.csp_available

    def safe_dict(self) -> dict:
        value = asdict(self)
        value["cryptopro_csp_detected"] = self.csp_available
        return value


def _candidate_paths(explicit: str | None, names: Iterable[str]) -> list[Path]:
    result: list[Path] = []
    if explicit:
        result.append(Path(explicit).expanduser())
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            result.append(Path(resolved))
    roots = [
        os.getenv("ProgramFiles", ""),
        os.getenv("ProgramFiles(x86)", ""),
    ]
    for root in filter(None, roots):
        base = Path(root) / "Crypto Pro" / "CSP"
        for name in names:
            result.append(base / name)
    return result


def _first_existing(candidates: Iterable[Path]) -> Path | None:
    for path in candidates:
        try:
            if path.is_file():
                return path.resolve()
        except OSError:
            continue
    return None


def _find_optional_cryptopro(filename: str, explicit: str | None = None) -> Path | None:
    try:
        return _find_cryptopro_binary(Path(explicit) if explicit else None, filename)
    except Exception:
        return None


def _windows_csp_registry_detected() -> bool:
    if platform.system().lower() != "windows":
        return False
    try:
        import winreg
    except ImportError:
        return False
    for root, path in (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Crypto Pro\Settings"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Crypto Pro\Settings"),
    ):
        try:
            with winreg.OpenKey(root, path):
                return True
        except OSError:
            continue
    return False


def inspect_local_cryptopro_foundation() -> CryptoProFoundationStatus:
    windows = platform.system().lower() == "windows"
    cryptcp = _find_optional_cryptopro("cryptcp.exe", os.getenv("WBCZ_CRYPTOPRO_CRYPTCP"))
    stunnel = _find_optional_cryptopro(
        "stunnel_msspi.exe", os.getenv("WBCZ_CRYPTOPRO_STUNNEL")
    )
    csp = _first_existing(_candidate_paths(None, ("csptest.exe", "csptest")))
    csp_available = bool(windows and (csp or _windows_csp_registry_detected()))
    return CryptoProFoundationStatus(
        windows=windows,
        csp_available=csp_available,
        # Browser plug-in state is authoritative only inside Chromium/Yandex.
        browser_cades_available=None,
        ukep_available=None,
        gost_transport_available=bool(stunnel),
        cryptcp_available=bool(cryptcp),
        cryptcp_path=str(cryptcp) if cryptcp else None,
        stunnel_path=str(stunnel) if stunnel else None,
        real_read_enabled=bool(
            os.getenv("WBCZ_TRUE_API_REAL_READ_ENABLED", "false").strip().lower()
            in {"1", "true", "yes", "on"}
        ),
        business_write_enabled=False,
    )


def _browser_cades_signature_info(
    signature_base64: str,
    *,
    powershell: str = "powershell.exe",
    runner: Any = subprocess.run,
) -> tuple[str, bytes]:
    """Extract signer thumbprint and attached content from Browser CAdES CMS.

    Parsing is read-only: no private-key access, signing, PIN handling or
    persistence. Returning the attached content lets the Bridge prove that the
    browser signed exactly the one-time CRPT auth challenge.
    """
    if not signature_base64:
        raise TrueApiError("Empty Browser CAdES signature")
    if os.name != "nt" and runner is subprocess.run:
        raise TrueApiError("Browser CAdES signer inspection requires Windows")
    script = r'''
$ErrorActionPreference='Stop'
try {
  Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop
} catch {
  Add-Type -AssemblyName System.Security -ErrorAction Stop
}
$raw=[Console]::In.ReadToEnd()
$bytes=[Convert]::FromBase64String($raw)
$cms=New-Object System.Security.Cryptography.Pkcs.SignedCms
$cms.Decode($bytes)
if ($cms.Detached) { throw 'Detached CMS is not allowed for True API auth' }
if ($cms.SignerInfos.Count -ne 1) { throw 'Expected exactly one CMS signer' }
$cert=$cms.SignerInfos[0].Certificate
if ($null -eq $cert) { throw 'CMS signer certificate is missing' }
[pscustomobject]@{
  thumbprint=$cert.Thumbprint.Replace(' ','').ToUpperInvariant()
  contentBase64=[Convert]::ToBase64String($cms.ContentInfo.Content)
} | ConvertTo-Json -Compress
'''
    completed = runner(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        input=signature_base64,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise TrueApiError(
            (completed.stderr.strip() or "Cannot inspect Browser CAdES signature")[:1000]
        )
    try:
        payload = json.loads(completed.stdout.strip())
        thumbprint = str(payload["thumbprint"]).replace(" ", "").upper()
        content = base64.b64decode(str(payload["contentBase64"]), validate=True)
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise TrueApiError("Browser CAdES signature inspection returned invalid data") from exc
    if not thumbprint:
        raise TrueApiError("Browser CAdES signer thumbprint is empty")
    return thumbprint, content


class LocalTrueApiReadRuntime:
    """Read-only True API transport/session owner for typed Browser CAdES auth."""

    def __init__(
        self,
        *,
        participant_inn: str,
        transport: ReadOnlyTrueApiTransport,
    ) -> None:
        self.participant_inn = participant_inn
        self.transport = transport
        self.adapter = TrueApiCisesInfoAdapter()
        self.rate_limiter = SharedRateLimiter(max_rps=50)
        self._session: AuthSession | None = None

    @property
    def authenticated(self) -> bool:
        return (
            self._session is not None
            and self._session.expire_date > datetime.now(timezone.utc)
        )

    @property
    def expire_date(self) -> datetime | None:
        return self._session.expire_date if self.authenticated and self._session else None

    def prepare_auth_challenge(self) -> tuple[str, str]:
        payload = self.transport.request_json("GET", "/auth/key")
        if not isinstance(payload, dict):
            raise TrueApiProtocolError("/auth/key returned an unexpected payload")
        uuid = payload.get("uuid")
        data = payload.get("data")
        if not isinstance(uuid, str) or not uuid or not isinstance(data, str) or not data:
            raise TrueApiProtocolError("/auth/key response misses uuid/data")
        return uuid, data

    def complete_auth(self, *, uuid: str, signature_base64: str) -> dict[str, Any]:
        if not uuid or not signature_base64:
            raise ValueError("Typed authentication completion is incomplete")
        response = self.transport.request_json(
            "POST",
            "/auth/simpleSignIn",
            body={
                "uuid": uuid,
                "data": signature_base64,
                "inn": self.participant_inn,
                "unitedToken": True,
            },
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
        except ValueError as exc:
            raise TrueApiProtocolError("Invalid expireDate in authentication response") from exc
        if expire_date.tzinfo is None or expire_date.utcoffset() is None:
            raise TrueApiProtocolError("expireDate must include an explicit timezone")
        self._session = AuthSession(
            uuid_token=token,
            expire_date=expire_date.astimezone(timezone.utc),
        )
        return {
            "authenticated": True,
            "expire_date": self._session.expire_date.isoformat(),
            "read_only": True,
            "business_write_enabled": False,
            "tls": self.transport.tls_diagnostics(),
        }

    def _bearer(self) -> str:
        if not self.authenticated or self._session is None:
            self._session = None
            raise LiveAuthorizationRequired("LOCAL_TRUE_API_AUTH_REQUIRED")
        return self._session.bearer_token

    def clear_session(self) -> None:
        self._session = None

    def close(self) -> None:
        self.clear_session()
        tunnel = getattr(self.transport, "tunnel", None)
        close = getattr(tunnel, "close", None)
        if callable(close):
            close()

    def read_states(self, cises: Iterable[str]) -> dict[str, KiState | Exception]:
        requested = tuple(dict.fromkeys(normalize_cis(cis) for cis in cises))
        if not requested:
            raise ValueError("cises/info batch must contain at least one CIS")
        bearer = self._bearer()
        result: dict[str, KiState | Exception] = {}
        for offset in range(0, len(requested), MAX_BATCH):
            batch = requested[offset : offset + MAX_BATCH]
            self.rate_limiter.acquire()
            try:
                payload = self.transport.request_json(
                    "POST",
                    "/cises/info",
                    params={"pg": "lp"},
                    body=list(batch),
                    bearer_token=bearer,
                    cis_count=len(batch),
                )
            except TrueApiHttpError as exc:
                if exc.status in {401, 403}:
                    self.clear_session()
                raise
            if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                items = payload["results"]
            elif isinstance(payload, list):
                items = payload
            else:
                raise TrueApiProtocolError(
                    "cises/info returned an unexpected top-level payload"
                )
            by_requested: dict[str, Any] = {}
            for item in items:
                if not isinstance(item, dict):
                    continue
                info = item.get("cisInfo", item)
                if isinstance(info, dict):
                    key = info.get("requestedCis") or info.get("cis")
                    if isinstance(key, str):
                        by_requested[key] = item
            for cis in batch:
                item = by_requested.get(cis)
                if item is None:
                    result[cis] = TrueApiProtocolError("cises/info omitted requested KI")
                    continue
                try:
                    result[cis] = self.adapter.normalize(cis, item)
                except Exception as exc:
                    result[cis] = exc
        return result


@dataclass(slots=True)
class BrowserAuthAttempt:
    attempt_id: str
    uuid: str
    challenge_data: str
    participant_inn: str
    session_id: str
    eligible_thumbprints: frozenset[str]
    expires_at: datetime
    used: bool = False


class LocalTrueApiReadBridge:
    """Local CryptoPro + True API read boundary with no mutation methods."""

    def __init__(
        self,
        *,
        settings_path: str | Path | None = None,
        audit_log_path: str | Path | None = None,
        cryptcp_path: str | Path | None = None,
        stunnel_path: str | Path | None = None,
        discovery: Any | None = None,
        cms_signature_info: Any | None = None,
    ) -> None:
        config_dir = Path(
            os.getenv(
                "SELLARI_LOCAL_CONFIG_DIR",
                str(Path.home() / "AppData" / "Local" / "SellariMarking" / "config"),
            )
        ).expanduser()
        log_dir = Path(
            os.getenv(
                "SELLARI_LOCAL_LOG_DIR",
                str(Path.home() / "AppData" / "Local" / "SellariMarking" / "logs"),
            )
        ).expanduser()
        self.settings_path = Path(settings_path) if settings_path else config_dir / "true_api_read.json"
        self.audit_log_path = Path(audit_log_path) if audit_log_path else log_dir / "true_api_read_audit.jsonl"
        self.cryptcp_path = Path(cryptcp_path) if cryptcp_path else None
        self.stunnel_path = Path(stunnel_path) if stunnel_path else None
        self.discovery = discovery or WindowsCryptoProCertificateDiscovery(
            cryptcp_path=self.cryptcp_path
        )
        self._cms_signature_info = cms_signature_info or _browser_cades_signature_info
        self._runtime: LocalTrueApiReadRuntime | None = None
        self._runtime_key: str | None = None
        self._attempts: dict[str, BrowserAuthAttempt] = {}
        self._attempt_ttl = timedelta(minutes=5)
        self._lock = threading.RLock()

    @classmethod
    def from_env(cls) -> "LocalTrueApiReadBridge":
        config_dir = Path(
            os.getenv(
                "SELLARI_LOCAL_CONFIG_DIR",
                str(Path.home() / "AppData" / "Local" / "SellariMarking" / "config"),
            )
        ).expanduser()
        log_dir = Path(
            os.getenv(
                "SELLARI_LOCAL_LOG_DIR",
                str(Path.home() / "AppData" / "Local" / "SellariMarking" / "logs"),
            )
        ).expanduser()
        cryptcp = os.getenv("WBCZ_CRYPTOPRO_CRYPTCP", "").strip() or None
        stunnel = os.getenv("WBCZ_CRYPTOPRO_STUNNEL", "").strip() or None
        return cls(
            settings_path=config_dir / "true_api_read.json",
            audit_log_path=log_dir / "true_api_read_audit.jsonl",
            cryptcp_path=cryptcp,
            stunnel_path=stunnel,
        )

    def _settings(self) -> dict[str, str]:
        if not self.settings_path.is_file():
            return {}
        try:
            raw = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict):
            return {}
        thumbprint = str(raw.get("thumbprint") or "").replace(" ", "").upper()
        participant_inn = str(raw.get("participant_inn") or "").strip()
        if not thumbprint or not participant_inn:
            return {}
        return {"thumbprint": thumbprint, "participant_inn": participant_inn}

    def _write_settings(self, *, thumbprint: str, participant_inn: str) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"thumbprint": thumbprint, "participant_inn": participant_inn},
            ensure_ascii=True,
            separators=(",", ":"),
        )
        temp = self.settings_path.with_suffix(".tmp")
        temp.write_text(payload, encoding="utf-8")
        os.replace(temp, self.settings_path)

    @staticmethod
    def _eligible(candidate: dict[str, Any], participant_inn: str) -> bool:
        provider = str(candidate.get("crypto_provider") or "").casefold().replace("-", " ")
        public_key_oid = str(candidate.get("public_key_oid") or "")
        certificate_inn = candidate.get("certificate_inn")
        try:
            valid_from = datetime.fromisoformat(
                str(candidate.get("valid_from") or "").replace("Z", "+00:00")
            )
            valid_to = datetime.fromisoformat(
                str(candidate.get("valid_to") or "").replace("Z", "+00:00")
            )
            if valid_from.tzinfo is None:
                valid_from = valid_from.replace(tzinfo=timezone.utc)
            if valid_to.tzinfo is None:
                valid_to = valid_to.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            valid_now = valid_from <= now <= valid_to
        except ValueError:
            valid_now = False
        return bool(
            candidate.get("has_private_key") is True
            and valid_now
            and public_key_oid in {
                "1.2.643.2.2.19",
                "1.2.643.7.1.1.1.1",
                "1.2.643.7.1.1.1.2",
            }
            and ("crypto pro" in provider or "cryptopro" in provider)
            and certificate_inn == participant_inn
        )

    def discover(self, participant_inn: str) -> dict[str, Any]:
        try:
            inventory = self.discovery.discover()
        except Exception:
            components = inspect_local_cryptopro_foundation()
            return {
                "cryptopro_available": components.csp_available,
                "csp_available": components.csp_available,
                "browser_cades_available": None,
                "ukep_available": False,
                "gost_transport_available": components.gost_transport_available,
                "cryptcp_available": components.cryptcp_available,
                "candidates": [],
                "error_code": "CRYPTOPRO_CERTIFICATE_DISCOVERY_FAILED",
            }
        candidates: list[dict[str, Any]] = []
        for item in inventory.get("candidates") or []:
            if not isinstance(item, dict):
                continue
            safe = {
                "thumbprint": str(item.get("thumbprint") or ""),
                "subject": item.get("subject"),
                "certificate_inn": item.get("certificate_inn"),
                "valid_from": item.get("valid_from"),
                "valid_to": item.get("valid_to"),
                "has_private_key": bool(item.get("has_private_key")),
                "compatibility": item.get("compatibility"),
                "crypto_provider": item.get("crypto_provider"),
                "public_key_oid": item.get("public_key_oid"),
            }
            safe["eligible"] = self._eligible(item, participant_inn)
            candidates.append(safe)
        components = inspect_local_cryptopro_foundation()
        return {
            "cryptopro_available": components.csp_available,
            "csp_available": components.csp_available,
            "browser_cades_available": None,
            "ukep_available": any(item.get("eligible") for item in candidates),
            "gost_transport_available": components.gost_transport_available,
            "cryptcp_available": components.cryptcp_available,
            "candidates": candidates,
            "error_code": None,
        }

    def selected_thumbprint(self, participant_inn: str) -> str | None:
        settings = self._settings()
        if settings.get("participant_inn") != participant_inn:
            return None
        return settings.get("thumbprint")

    def _clear_runtime(self) -> None:
        if self._runtime is not None:
            self._runtime.close()
        self._runtime = None
        self._runtime_key = None

    def _eligible_candidate(
        self, participant_inn: str, thumbprint: str
    ) -> dict[str, Any]:
        normalized = thumbprint.replace(" ", "").upper()
        inventory = self.discover(participant_inn)
        candidate = next(
            (
                item
                for item in inventory.get("candidates", [])
                if item.get("thumbprint") == normalized
            ),
            None,
        )
        if candidate is None or not candidate.get("eligible"):
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_NOT_ELIGIBLE",
                "Selected browser certificate is not eligible for the active participant",
            )
        return candidate

    def _selected_certificate_for_read(self, participant_inn: str) -> str:
        settings = self._settings()
        thumbprint = settings.get("thumbprint")
        if not thumbprint or settings.get("participant_inn") != participant_inn:
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_SELECTION_REQUIRED",
                "Complete Browser CAdES authentication first",
            )
        self._eligible_candidate(participant_inn, thumbprint)
        return thumbprint

    def _build_runtime(self, participant_inn: str) -> LocalTrueApiReadRuntime:
        audit = JsonlLiveAudit(self.audit_log_path)
        tunnel = CryptoProGostTlsTunnel(self.stunnel_path)
        transport = ReadOnlyTrueApiTransport(audit=audit, tunnel=tunnel)
        return LocalTrueApiReadRuntime(
            participant_inn=participant_inn,
            transport=transport,
        )

    def _runtime_for(self, participant_inn: str) -> LocalTrueApiReadRuntime:
        with self._lock:
            if self._runtime is None or self._runtime_key != participant_inn:
                self._clear_runtime()
                self._runtime = self._build_runtime(participant_inn)
                self._runtime_key = participant_inn
            return self._runtime

    def _prune_attempts(self) -> None:
        now = datetime.now(timezone.utc)
        for attempt_id, attempt in list(self._attempts.items()):
            if attempt.used or attempt.expires_at <= now:
                self._attempts.pop(attempt_id, None)

    def prepare_auth(self, participant_inn: str, session_id: str) -> dict[str, Any]:
        with self._lock:
            self._prune_attempts()
            inventory = self.discover(participant_inn)
            eligible = frozenset(
                str(item["thumbprint"])
                for item in inventory.get("candidates", [])
                if item.get("eligible") and item.get("thumbprint")
            )
            if not eligible:
                raise LocalTrueApiUnavailable(
                    "CERTIFICATE_NOT_ELIGIBLE",
                    "No participant-bound CryptoPro GOST UKEP is available",
                )
            runtime = self._runtime_for(participant_inn)
            try:
                uuid, challenge = runtime.prepare_auth_challenge()
            except Exception as exc:
                raise LocalTrueApiUnavailable(
                    "GOST_TRANSPORT_NOT_READY",
                    "True API GOST transport is not ready",
                ) from exc
            attempt_id = secrets.token_urlsafe(32)
            expires_at = datetime.now(timezone.utc) + self._attempt_ttl
            self._attempts[attempt_id] = BrowserAuthAttempt(
                attempt_id=attempt_id,
                uuid=uuid,
                challenge_data=challenge,
                participant_inn=participant_inn,
                session_id=session_id,
                eligible_thumbprints=eligible,
                expires_at=expires_at,
            )
            return {
                "attempt_id": attempt_id,
                "challenge_base64": base64.b64encode(
                    challenge.encode("utf-8")
                ).decode("ascii"),
                "participant_inn": participant_inn,
                "expires_at": expires_at.isoformat(),
                "read_only": True,
            }

    def complete_auth(
        self,
        participant_inn: str,
        session_id: str,
        *,
        attempt_id: str,
        signature_base64: str,
        selected_certificate_thumbprint: str,
    ) -> dict[str, Any]:
        normalized = selected_certificate_thumbprint.replace(" ", "").upper()
        with self._lock:
            self._prune_attempts()
            attempt = self._attempts.get(attempt_id)
            if attempt is None:
                raise LocalTrueApiUnavailable(
                    "AUTH_ATTEMPT_INVALID",
                    "Authentication attempt is missing, expired, or already used",
                )
            if (
                attempt.session_id != session_id
                or attempt.participant_inn != participant_inn
            ):
                raise LocalTrueApiUnavailable(
                    "AUTH_ATTEMPT_MISMATCH",
                    "Authentication attempt does not match the active browser session",
                )
            if normalized not in attempt.eligible_thumbprints:
                raise LocalTrueApiUnavailable(
                    "CERTIFICATE_NOT_ELIGIBLE",
                    "Selected browser certificate is not bound to this auth attempt",
                )
            self._eligible_candidate(participant_inn, normalized)
            try:
                signer_thumbprint, signed_content = self._cms_signature_info(
                    signature_base64
                )
            except Exception as exc:
                raise LocalTrueApiUnavailable(
                    "CADES_SIGNER_VALIDATION_FAILED",
                    "Cannot validate Browser CAdES signer certificate/content",
                ) from exc
            if signer_thumbprint.replace(" ", "").upper() != normalized:
                raise LocalTrueApiUnavailable(
                    "CERTIFICATE_NOT_ELIGIBLE",
                    "Browser CAdES signer does not match the selected participant certificate",
                )
            exact_challenge = attempt.challenge_data.encode("utf-8")
            if signed_content != exact_challenge:
                raise LocalTrueApiUnavailable(
                    "AUTH_CHALLENGE_MISMATCH",
                    "Browser CAdES content does not match the typed CRPT auth attempt",
                )

            # Consume before network completion. A failed/retried completion
            # cannot replay a CRPT challenge/signature pair.
            attempt.used = True
            runtime = self._runtime_for(participant_inn)
            try:
                result = runtime.complete_auth(
                    uuid=attempt.uuid,
                    signature_base64=signature_base64,
                )
            except Exception as exc:
                runtime.clear_session()
                raise LocalTrueApiUnavailable(
                    "TRUE_API_AUTH_FAILED",
                    "Browser CAdES / True API authentication failed",
                ) from exc
            self._write_settings(
                thumbprint=normalized,
                participant_inn=participant_inn,
            )
            self._attempts.pop(attempt_id, None)
            return result

    def read_states(
        self, participant_inn: str, cises: Iterable[str]
    ) -> dict[str, KiState | Exception]:
        with self._lock:
            self._selected_certificate_for_read(participant_inn)
            runtime = self._runtime_for(participant_inn)
            try:
                return runtime.read_states(cises)
            except LiveAuthorizationRequired as exc:
                raise LocalTrueApiUnavailable(
                    "TRUE_API_AUTH_REQUIRED",
                    "Authenticate with Browser CAdES first",
                ) from exc
            except (TrueApiError, ValueError) as exc:
                raise LocalTrueApiUnavailable(
                    "TRUE_API_READ_FAILED", "True API read-only request failed"
                ) from exc

    def diagnostics(self) -> dict[str, Any]:
        return inspect_local_cryptopro_foundation().safe_dict()

    def status(self, participant_inn: str) -> dict[str, Any]:
        inventory = self.discover(participant_inn)
        selected = self.selected_thumbprint(participant_inn)
        selected_candidate = next(
            (
                item
                for item in inventory.get("candidates", [])
                if item.get("thumbprint") == selected
            ),
            None,
        )
        runtime = self._runtime if self._runtime_key == participant_inn else None
        error_code = inventory.get("error_code")
        if not error_code and selected:
            if selected_candidate is None:
                error_code = "CERTIFICATE_NOT_FOUND"
            elif not selected_candidate.get("eligible"):
                error_code = "CERTIFICATE_NOT_ELIGIBLE"
        tls: dict[str, Any] = {}
        if runtime is not None:
            try:
                tls = runtime.transport.tls_diagnostics()
            except Exception:
                tls = {}
        return {
            **inventory,
            "error_code": error_code,
            "selected_thumbprint": selected,
            "authenticated": bool(runtime and runtime.authenticated),
            "expire_date": (
                runtime.expire_date.isoformat()
                if runtime and runtime.expire_date is not None
                else None
            ),
            "gost_session_verified": bool(tls.get("gost_session_verified")),
            "real_read_enabled": True,
            "read_only": True,
            "business_write_enabled": False,
            "uuid_token_persisted": False,
            "pin_persisted": False,
        }


# Compatibility name used by phase-058 tests/docs. It now points at the real
# read-only bridge and still exposes no signing/document mutation method.
LocalTrueApiBridgeFoundation = LocalTrueApiReadBridge
