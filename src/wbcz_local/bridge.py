from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
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
    TrueApiAuthenticator,
    TrueApiCisesInfoAdapter,
    TrueApiError,
    TrueApiHttpError,
    TrueApiProtocolError,
    WindowsCryptoProAuthSigner,
    WindowsCryptoProCertificateDiscovery,
    WindowsCryptoProCertificateInspector,
    _find_cryptopro_binary,
)


class LocalTrueApiUnavailable(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class CryptoProFoundationStatus:
    windows: bool
    cryptopro_csp_detected: bool
    cryptcp_path: str | None
    stunnel_path: str | None
    real_read_enabled: bool
    business_write_enabled: bool = False

    def safe_dict(self) -> dict:
        return asdict(self)


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


def inspect_local_cryptopro_foundation() -> CryptoProFoundationStatus:
    windows = platform.system().lower() == "windows"
    cryptcp = _find_optional_cryptopro("cryptcp.exe", os.getenv("WBCZ_CRYPTOPRO_CRYPTCP"))
    stunnel = _find_optional_cryptopro(
        "stunnel_msspi.exe", os.getenv("WBCZ_CRYPTOPRO_STUNNEL")
    )
    csp = _first_existing(_candidate_paths(None, ("csptest.exe", "csptest")))
    return CryptoProFoundationStatus(
        windows=windows,
        cryptopro_csp_detected=bool(windows and (csp or cryptcp)),
        cryptcp_path=str(cryptcp) if cryptcp else None,
        stunnel_path=str(stunnel) if stunnel else None,
        real_read_enabled=bool(
            os.getenv("WBCZ_TRUE_API_REAL_READ_ENABLED", "false").strip().lower()
            in {"1", "true", "yes", "on"}
        ),
        business_write_enabled=False,
    )


class LocalTrueApiReadRuntime:
    """In-process read-only True API session.

    Authentication is exactly one /auth/key challenge, local CryptoPro signing of
    the returned data, then /auth/simpleSignIn. The resulting uuidToken exists
    only in this object and is never serialized.
    """

    def __init__(
        self,
        *,
        participant_inn: str,
        transport: ReadOnlyTrueApiTransport,
        inspector: Any,
        signer: Any,
    ) -> None:
        self.participant_inn = participant_inn
        self.transport = transport
        self.inspector = inspector
        self.signer = signer
        self.authenticator = TrueApiAuthenticator(transport, signer, participant_inn)
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

    def authenticate(self) -> dict[str, Any]:
        # Local certificate validation performs no network I/O and exports no key.
        self.inspector.inspect()
        self._session = self.authenticator.authenticate()
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
                    result[cis] = TrueApiProtocolError(
                        "cises/info omitted requested KI"
                    )
                    continue
                try:
                    result[cis] = self.adapter.normalize(cis, item)
                except Exception as exc:
                    result[cis] = exc
        return result


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
        self._runtime: LocalTrueApiReadRuntime | None = None
        self._runtime_key: tuple[str, str] | None = None
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
        certificate_inn = candidate.get("certificate_inn")
        return bool(
            candidate.get("compatibility") == "GOST_CRYPTOPRO"
            and candidate.get("has_private_key") is True
            and certificate_inn == participant_inn
        )

    def discover(self, participant_inn: str) -> dict[str, Any]:
        try:
            inventory = self.discovery.discover()
        except Exception:
            return {
                "cryptopro_available": False,
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
            }
            safe["eligible"] = self._eligible(item, participant_inn)
            candidates.append(safe)
        return {
            "cryptopro_available": bool(inventory.get("cryptopro_available")),
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

    def _validated_persisted_selection(self, participant_inn: str) -> str:
        """Re-bind persisted certificate metadata to the active participant.

        true_api_read.json is local operator metadata, not an identity proof.
        Every runtime/auth construction therefore re-resolves the thumbprint
        through the Windows certificate store and requires the discovered
        certificate INN to match the active participant exactly before any
        signer or network transport is constructed.
        """
        settings = self._settings()
        thumbprint = settings.get("thumbprint")
        if not thumbprint:
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_SELECTION_REQUIRED",
                "Select an eligible local UKEP certificate first",
            )

        inventory = self.discover(participant_inn)
        candidate = next(
            (
                item
                for item in inventory.get("candidates", [])
                if item.get("thumbprint") == thumbprint
            ),
            None,
        )
        if candidate is None or not candidate.get("eligible"):
            self._clear_runtime()
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_NOT_ELIGIBLE",
                "Persisted certificate is not eligible for the active participant",
            )

        try:
            WindowsCryptoProCertificateInspector(
                thumbprint, cryptcp_path=self.cryptcp_path
            ).inspect()
        except Exception as exc:
            self._clear_runtime()
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_NOT_ELIGIBLE",
                "Persisted certificate failed current local CryptoPro validation",
            ) from exc
        return thumbprint

    def select_certificate(self, participant_inn: str, thumbprint: str) -> dict[str, Any]:
        normalized = thumbprint.replace(" ", "").upper()
        inventory = self.discover(participant_inn)
        candidate = next(
            (
                item
                for item in inventory["candidates"]
                if item.get("thumbprint") == normalized
            ),
            None,
        )
        if candidate is None:
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_NOT_FOUND", "Selected UKEP certificate was not found"
            )
        if not candidate.get("eligible"):
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_NOT_ELIGIBLE",
                "Selected certificate is not an eligible CryptoPro GOST UKEP",
            )
        try:
            WindowsCryptoProCertificateInspector(
                normalized, cryptcp_path=self.cryptcp_path
            ).inspect()
        except Exception as exc:
            raise LocalTrueApiUnavailable(
                "CERTIFICATE_VALIDATION_FAILED",
                "Selected UKEP certificate failed local validation",
            ) from exc
        with self._lock:
            self._clear_runtime()
            self._write_settings(
                thumbprint=normalized, participant_inn=participant_inn
            )
        return self.status(participant_inn)

    def _build_runtime(
        self, participant_inn: str, thumbprint: str
    ) -> LocalTrueApiReadRuntime:
        audit = JsonlLiveAudit(self.audit_log_path)
        tunnel = CryptoProGostTlsTunnel(self.stunnel_path)
        transport = ReadOnlyTrueApiTransport(audit=audit, tunnel=tunnel)
        inspector = WindowsCryptoProCertificateInspector(
            thumbprint, cryptcp_path=self.cryptcp_path
        )
        signer = WindowsCryptoProAuthSigner(
            thumbprint,
            cryptcp_path=self.cryptcp_path,
            inspector=inspector,
        )
        return LocalTrueApiReadRuntime(
            participant_inn=participant_inn,
            transport=transport,
            inspector=inspector,
            signer=signer,
        )

    def _runtime_for(self, participant_inn: str) -> LocalTrueApiReadRuntime:
        # Do not trust participant_inn/thumbprint persisted in true_api_read.json
        # as identity proof. Re-resolve and validate the selected certificate
        # before a signer or GOST transport can be constructed.
        thumbprint = self._validated_persisted_selection(participant_inn)
        key = (participant_inn, thumbprint)
        with self._lock:
            if self._runtime is None or self._runtime_key != key:
                self._clear_runtime()
                self._runtime = self._build_runtime(participant_inn, thumbprint)
                self._runtime_key = key
            return self._runtime

    def authenticate(self, participant_inn: str) -> dict[str, Any]:
        with self._lock:
            runtime = self._runtime_for(participant_inn)
            try:
                return runtime.authenticate()
            except Exception as exc:
                runtime.clear_session()
                raise LocalTrueApiUnavailable(
                    "TRUE_API_AUTH_FAILED",
                    "Local CryptoPro / True API authentication failed",
                ) from exc

    def read_states(
        self, participant_inn: str, cises: Iterable[str]
    ) -> dict[str, KiState | Exception]:
        with self._lock:
            runtime = self._runtime_for(participant_inn)
            try:
                return runtime.read_states(cises)
            except LiveAuthorizationRequired as exc:
                raise LocalTrueApiUnavailable(
                    "TRUE_API_AUTH_REQUIRED",
                    "Authenticate with the selected local UKEP first",
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
        runtime = (
            self._runtime
            if self._runtime_key == (participant_inn, selected)
            else None
        )
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
