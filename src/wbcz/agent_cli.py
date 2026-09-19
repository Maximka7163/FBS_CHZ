from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
import os
from pathlib import Path
import signal
import random
from uuid import uuid4
import sys
import time
from typing import Any

from wbcz.agent_http import OutboundAgentEnrollmentClient, OutboundAgentHttpClient, StdlibHttpsAgentSender
from wbcz.agent_identity import DpapiAgentCredentialStore, parse_enrollment_response
from wbcz.agent_true_api_transport import ProductionAgentTrueApiTransport
from wbcz.control_engine import validate_owner_inn
from wbcz.windows_agent import (
    AgentJobType,
    AgentSessionManager,
    WindowsCryptoProDocumentSigner,
    WindowsOutboundAgent,
)
from wbcz.windows_agent_runtime import DurableDispenserRateLimiter, DurableWindowsAgentExecutor, WindowsAgentReplayStore
from wbcz_ui.live_true_api import (
    CryptoProGostTlsTunnel,
    JsonlLiveAudit,
    TrueApiAuthenticator,
    WindowsCryptoProAuthSigner,
    WindowsCryptoProCertificateInspector,
)


@dataclass(frozen=True, slots=True)
class WindowsAgentConfig:
    backend_url: str
    machine_token: str
    participant_inn: str
    certificate_thumbprint: str
    replay_db_path: Path
    audit_log_path: Path
    stunnel_path: Path | None = None
    cryptcp_path: Path | None = None
    idle_poll_seconds: float = 3.0
    error_backoff_max_seconds: float = 60.0
    production_write: bool = False
    production_true_api_reports: bool = False
    report_remote_download_byte_ceiling: int = 2 * 1024 * 1024 * 1024
    protocol_version: str = "m15-v1"
    agent_version: str = "0.5.1"
    credential_path: Path | None = None

    @classmethod
    def from_env(cls) -> "WindowsAgentConfig":
        if os.name != "nt":
            raise ValueError("wbcz-agent production runtime requires Windows + CryptoPro CSP")
        backend = os.getenv("WBCZ_AGENT_BACKEND_URL", "").strip()
        inn = os.getenv("WBCZ_PARTICIPANT_INN", "").strip()
        thumbprint = os.getenv("WBCZ_UKEP_THUMBPRINT", "").replace(" ", "").upper()
        if not backend:
            raise ValueError("WBCZ_AGENT_BACKEND_URL is required")
        # StdlibHttpsAgentSender performs the canonical HTTPS-origin validation.
        StdlibHttpsAgentSender(backend)
        data_dir = Path(os.getenv("WBCZ_AGENT_DATA_DIR", str(Path.home() / ".wbcz-agent"))).expanduser()
        credential_path = Path(os.getenv("WBCZ_AGENT_CREDENTIAL_PATH", str(data_dir / "agent-credential.dpapi"))).expanduser()
        token = os.getenv("WBCZ_AGENT_MACHINE_TOKEN", "")
        if not token:
            try:
                token = DpapiAgentCredentialStore(credential_path).load() or ""
            except (OSError, ValueError, RuntimeError):
                token = ""
        if len(token) < 32:
            raise ValueError("participant-bound agent credential is missing; enrollment is required")
        validate_owner_inn(inn)
        if not thumbprint:
            raise ValueError("WBCZ_UKEP_THUMBPRINT is required")
        if os.getenv("WBCZ_AGENT_PRODUCTION_WRITE_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}:
            raise ValueError("Production document write remains disabled pending runtime contract tests")
        replay = Path(os.getenv("WBCZ_AGENT_REPLAY_DB", str(data_dir / "replay.sqlite"))).expanduser()
        audit = Path(os.getenv("WBCZ_AGENT_AUDIT_LOG", str(data_dir / "true_api_audit.jsonl"))).expanduser()
        stunnel_raw = os.getenv("WBCZ_CRYPTOPRO_STUNNEL", "").strip()
        cryptcp_raw = os.getenv("WBCZ_CRYPTOPRO_CRYPTCP", "").strip()
        idle = float(os.getenv("WBCZ_AGENT_IDLE_POLL_SECONDS", "3"))
        backoff = float(os.getenv("WBCZ_AGENT_ERROR_BACKOFF_MAX_SECONDS", "60"))
        reports_enabled = os.getenv("WBCZ_AGENT_TRUE_API_REPORTS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
        report_download_ceiling = int(os.getenv("WBCZ_REPORT_REMOTE_DOWNLOAD_BYTE_CEILING", str(2 * 1024 * 1024 * 1024)))
        if idle < 0.5 or idle > 300:
            raise ValueError("WBCZ_AGENT_IDLE_POLL_SECONDS is out of range")
        if backoff < idle or backoff > 3600:
            raise ValueError("WBCZ_AGENT_ERROR_BACKOFF_MAX_SECONDS is out of range")
        if report_download_ceiling <= 0:
            raise ValueError("WBCZ_REPORT_REMOTE_DOWNLOAD_BYTE_CEILING must be positive")
        return cls(
            backend_url=backend,
            machine_token=token,
            participant_inn=inn,
            certificate_thumbprint=thumbprint,
            replay_db_path=replay,
            audit_log_path=audit,
            stunnel_path=Path(stunnel_raw) if stunnel_raw else None,
            cryptcp_path=Path(cryptcp_raw) if cryptcp_raw else None,
            idle_poll_seconds=idle,
            error_backoff_max_seconds=backoff,
            production_write=False,
            production_true_api_reports=reports_enabled,
            report_remote_download_byte_ceiling=report_download_ceiling,
            protocol_version=os.getenv("WBCZ_AGENT_PROTOCOL_VERSION", "m15-v1").strip() or "m15-v1",
            agent_version=os.getenv("WBCZ_AGENT_VERSION", "0.5.1").strip() or "0.5.1",
            credential_path=credential_path,
        )


class WindowsAgentPreflight:
    """Mutation-free runtime checks. This object has no document-create method."""

    def __init__(
        self,
        *,
        certificate_inspector: Any,
        transport: Any,
        authenticator: Any,
        session_manager: AgentSessionManager,
        backend: OutboundAgentHttpClient,
        machine_token: str,
    ) -> None:
        self.certificate_inspector = certificate_inspector
        self.transport = transport
        self.authenticator = authenticator
        self.session_manager = session_manager
        self.backend = backend
        self._machine_token = machine_token

    def check(self, *, test_cis: str | None = None) -> dict[str, Any]:
        certificate = self.certificate_inspector.inspect()
        tls_before = self.transport.tls_diagnostics()
        auth_probe = self.authenticator.preflight()
        # Authenticate for real, but keep UUID bearer only inside session memory.
        self.session_manager.bearer_token()
        self.backend.check_auth(self._machine_token)
        cises_checked = 0
        if test_cis:
            self.transport.cises_info(
                (test_cis,), bearer_token=self.session_manager.bearer_token()
            )
            cises_checked = 1
        tls_after = self.transport.tls_diagnostics()
        return {
            "ok": True,
            "certificate": {
                "certificate_found": bool(certificate.get("certificate_found")),
                "thumbprint_match": bool(certificate.get("thumbprint_match")),
                "has_private_key": bool(certificate.get("has_private_key")),
                "not_expired": bool(certificate.get("not_expired")),
                "gost_compatible": bool(certificate.get("gost_compatible")),
                "cryptopro_provider": bool(certificate.get("cryptopro_provider")),
            },
            "cryptopro_stunnel_available": bool(tls_before.get("executable")),
            "true_api_available": bool(auth_probe.get("true_api_available")),
            "true_api_authenticated": True,
            "gost_session_verified": bool(tls_after.get("gost_session_verified")),
            "backend_machine_auth": True,
            "optional_cises_checked": cises_checked,
            "true_api_token_expires_at": (
                self.session_manager.expire_date.isoformat()
                if self.session_manager.expire_date is not None
                else None
            ),
            "production_write": False,
            "production_true_api_reports": bool(getattr(self.transport, "production_true_api_reports", False)),
        }


class WindowsAgentRuntime:
    def __init__(self, config: WindowsAgentConfig) -> None:
        self.config = config
        config.replay_db_path.parent.mkdir(parents=True, exist_ok=True)
        config.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.replay_store = WindowsAgentReplayStore(config.replay_db_path)
        self.tunnel = CryptoProGostTlsTunnel(config.stunnel_path)
        self.audit = JsonlLiveAudit(config.audit_log_path)
        self.transport = ProductionAgentTrueApiTransport(
            tunnel=self.tunnel,
            audit=self.audit,
            report_rate_limiter=DurableDispenserRateLimiter(self.replay_store),
            production_true_api_reports=config.production_true_api_reports,
            remote_download_byte_ceiling=config.report_remote_download_byte_ceiling,
        )
        self.inspector = WindowsCryptoProCertificateInspector(
            config.certificate_thumbprint,
            cryptcp_path=config.cryptcp_path,
        )
        self.auth_signer = WindowsCryptoProAuthSigner(
            config.certificate_thumbprint,
            cryptcp_path=config.cryptcp_path,
            inspector=self.inspector,
        )
        self.authenticator = TrueApiAuthenticator(
            self.transport,
            self.auth_signer,
            config.participant_inn,
        )
        self.session_manager = AgentSessionManager(self.authenticator)
        self.document_signer = WindowsCryptoProDocumentSigner(
            certificate_thumbprint=config.certificate_thumbprint,
            participant_inn=config.participant_inn,
            cryptcp_path=config.cryptcp_path,
            inspector=self.inspector,
        )
        self.backend = OutboundAgentHttpClient(StdlibHttpsAgentSender(config.backend_url))
        self.executor = DurableWindowsAgentExecutor(
            participant_inn=config.participant_inn,
            transport=self.transport,
            session_manager=self.session_manager,
            document_signer=self.document_signer,
            replay_store=self.replay_store,
            production_write=False,
        )
        self.agent = WindowsOutboundAgent(
            backend=self.backend,
            machine_token=config.machine_token,
            executor=self.executor,
        )
        self.preflight = WindowsAgentPreflight(
            certificate_inspector=self.inspector,
            transport=self.transport,
            authenticator=self.authenticator,
            session_manager=self.session_manager,
            backend=self.backend,
            machine_token=config.machine_token,
        )

    def close(self) -> None:
        self.tunnel.close()
        self.replay_store.close()

    def run(self) -> None:
        stopped = False

        def stop(*_: object) -> None:
            nonlocal stopped
            stopped = True

        for name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, name, None)
            if sig is not None:
                signal.signal(sig, stop)
        failures = 0
        while not stopped:
            try:
                worked = self.agent.run_once()
                failures = 0
                if not worked:
                    time.sleep(self.config.idle_poll_seconds)
            except KeyboardInterrupt:
                stopped = True
            except Exception as exc:
                # Exception type only: never print bearer/machine token/provider details.
                failures += 1
                print(f"agent iteration failed: {type(exc).__name__}", file=sys.stderr)
                ceiling = min(
                    self.config.error_backoff_max_seconds,
                    self.config.idle_poll_seconds * (2 ** min(failures, 8)),
                )
                time.sleep(random.uniform(0.0, ceiling))


def _enroll_from_env() -> dict[str, Any]:
    if os.name != "nt":
        raise ValueError("agent enrollment runtime requires Windows")
    backend = os.getenv("WBCZ_AGENT_BACKEND_URL", "").strip()
    enrollment_token = os.getenv("WBCZ_AGENT_ENROLLMENT_TOKEN", "")
    if not backend or len(enrollment_token) < 43:
        raise ValueError("WBCZ_AGENT_BACKEND_URL and WBCZ_AGENT_ENROLLMENT_TOKEN are required")
    data_dir = Path(os.getenv("WBCZ_AGENT_DATA_DIR", str(Path.home() / ".wbcz-agent"))).expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)
    replay_path = Path(os.getenv("WBCZ_AGENT_REPLAY_DB", str(data_dir / "replay.sqlite"))).expanduser()
    credential_path = Path(os.getenv("WBCZ_AGENT_CREDENTIAL_PATH", str(data_dir / "agent-credential.dpapi"))).expanduser()
    protocol = os.getenv("WBCZ_AGENT_PROTOCOL_VERSION", "m15-v1").strip() or "m15-v1"
    version = os.getenv("WBCZ_AGENT_VERSION", "0.5.1").strip() or "0.5.1"
    with WindowsAgentReplayStore(replay_path) as replay:
        identity = replay.get_runtime_metadata("agent_identity") or {}
        installation_id = identity.get("installation_id")
        if not isinstance(installation_id, str) or not installation_id:
            installation_id = str(uuid4())
            replay.set_runtime_metadata("agent_identity", {
                "installation_id": installation_id,
                "protocol_version": protocol,
                "agent_version": version,
            })
    sender = StdlibHttpsAgentSender(backend)
    value = OutboundAgentEnrollmentClient(sender).exchange(
        enrollment_token=enrollment_token,
        installation_id=installation_id,
        protocol_version=protocol,
        agent_version=version,
        supported_job_types=[item.value for item in AgentJobType],
        supported_capabilities=["OUTBOUND_HTTPS", "TYPED_JOBS", "M11_DURABLE_RATE_LIMIT", "DPAPI_CREDENTIAL"],
    )
    response = parse_enrollment_response(json.dumps(value, separators=(",", ":")).encode("utf-8"))
    if response.compatibility != "COMPATIBLE" or not response.permanent_credential:
        return {
            "ok": False,
            "compatibility": response.compatibility,
            "binding_id": response.binding_id,
            "credential_stored": False,
        }
    DpapiAgentCredentialStore(credential_path).save(response.permanent_credential)
    os.environ.pop("WBCZ_AGENT_ENROLLMENT_TOKEN", None)
    return {
        "ok": True,
        "compatibility": response.compatibility,
        "binding_id": response.binding_id,
        "credential_version": response.credential_version,
        "credential_stored": True,
    }


def _safe_print_result(result: dict[str, Any]) -> None:
    import json
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wbcz-agent")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("check", "preflight"):
        command = sub.add_parser(name, help="safe Windows/CryptoPro/backend preflight")
        command.add_argument("--cis", default=None, help="optional test CIS for read-only cises/info")
    sub.add_parser("run", help="run outbound polling loop")
    sub.add_parser("enroll", help="exchange one-use enrollment token and store permanent credential with DPAPI")
    args = parser.parse_args(argv)
    if args.mode == "enroll":
        _safe_print_result(_enroll_from_env())
        return 0
    config = WindowsAgentConfig.from_env()
    runtime = WindowsAgentRuntime(config)
    try:
        if args.mode in {"check", "preflight"}:
            _safe_print_result(runtime.preflight.check(test_cis=args.cis))
            return 0
        runtime.run()
        return 0
    finally:
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
