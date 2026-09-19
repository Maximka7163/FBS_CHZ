from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import secrets
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz_web.models import AgentBindingRecord, AgentEnrollmentTokenRecord, ParticipantRecord
from wbcz_web.services.agent_bindings import AgentBindingService
from wbcz_web.services.tenant import active_tenant, bind_tenant_scope


_PROTOCOL_RE = re.compile(r"^m(\d+)-v(\d+)$")
_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _protocol_tuple(value: str) -> tuple[int, int] | None:
    match = _PROTOCOL_RE.fullmatch(value or "")
    return (int(match.group(1)), int(match.group(2))) if match else None


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.match(value or "")
    if not match:
        return None
    return tuple(int(match.group(i) or 0) for i in (1, 2, 3))


class ProtocolCompatibility:
    COMPATIBLE = "COMPATIBLE"
    UPGRADE_REQUIRED = "UPGRADE_REQUIRED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class AgentHandshake:
    protocol_version: str
    agent_version: str
    supported_job_types: tuple[str, ...]
    supported_capabilities: tuple[str, ...]


def evaluate_protocol(handshake: AgentHandshake, *, config) -> str:
    current = _protocol_tuple(config.agent_protocol_current)
    minimum = _protocol_tuple(config.agent_protocol_minimum)
    offered = _protocol_tuple(handshake.protocol_version)
    if current is None or minimum is None:
        raise ValueError("server protocol configuration invalid")
    if offered is None:
        return ProtocolCompatibility.UNSUPPORTED
    if offered < minimum:
        return ProtocolCompatibility.UPGRADE_REQUIRED
    if offered > current:
        return ProtocolCompatibility.UNSUPPORTED
    minimum_agent = _version_tuple(config.agent_minimum_version)
    offered_agent = _version_tuple(handshake.agent_version)
    if minimum_agent is not None and (offered_agent is None or offered_agent < minimum_agent):
        return ProtocolCompatibility.UPGRADE_REQUIRED
    return ProtocolCompatibility.COMPATIBLE


def enrollment_token_hash(raw: str) -> str:
    if not isinstance(raw, str) or len(raw) < 43:
        return hashlib.sha256(b"invalid-m15-enrollment-token").hexdigest()
    return hashlib.sha256(("m15-agent-enrollment:v1:" + raw).encode("utf-8")).hexdigest()


class AgentEnrollmentService:
    def __init__(self, db: Session, *, config) -> None:
        self.db = db
        self.config = config

    def create_intent(
        self,
        *,
        display_name: str,
        user_id: int,
        requested_protocol_version: str | None = None,
    ) -> tuple[AgentEnrollmentTokenRecord, str]:
        scope = active_tenant(self.db)
        raw = secrets.token_urlsafe(48)
        now = _now()
        trace = self.db.info.get("audit_trace") if isinstance(self.db.info.get("audit_trace"), dict) else {}
        row = AgentEnrollmentTokenRecord(
            organisation_id=scope.organisation_id,
            participant_id=scope.participant_id,
            token_hash=enrollment_token_hash(raw),
            display_name=display_name.strip()[:200] or "Windows Agent",
            requested_protocol_version=(requested_protocol_version or self.config.agent_protocol_current)[:32],
            state="PENDING",
            expires_at=now + timedelta(seconds=self.config.agent_enrollment_ttl_seconds),
            created_by_user_id=user_id,
            correlation_id=trace.get("correlation_id"),
        )
        self.db.add(row)
        self.db.flush()
        return row, raw

    def exchange(
        self,
        raw_token: str,
        *,
        installation_id: str,
        participant_inn: str,
        protocol_version: str,
        agent_version: str,
        supported_job_types: Iterable[str],
        supported_capabilities: Iterable[str],
    ) -> tuple[AgentBindingRecord | None, str | None, str]:
        digest = enrollment_token_hash(raw_token)
        row = self.db.scalar(
            select(AgentEnrollmentTokenRecord)
            .where(AgentEnrollmentTokenRecord.token_hash == digest)
            .with_for_update()
        )
        if row is None or not hmac.compare_digest(row.token_hash, digest):
            raise PermissionError("invalid enrollment token")
        participant = self.db.get(ParticipantRecord, row.participant_id)
        if participant is None or participant.organisation_id != row.organisation_id or participant.inn != participant_inn:
            raise PermissionError("enrollment participant mismatch")
        now = _now()
        if row.state != "PENDING":
            raise PermissionError("enrollment token already used or revoked")
        if row.expires_at <= now:
            row.state = "EXPIRED"
            self.db.flush()
            raise PermissionError("enrollment token expired")

        jobs = tuple(sorted({str(x)[:48] for x in supported_job_types if str(x)}))
        capabilities = tuple(sorted({str(x)[:80] for x in supported_capabilities if str(x)}))
        handshake = AgentHandshake(
            protocol_version=protocol_version[:32],
            agent_version=agent_version[:64],
            supported_job_types=jobs,
            supported_capabilities=capabilities,
        )
        compatibility = evaluate_protocol(handshake, config=self.config)
        row.used_at = now
        row.state = "USED"
        if compatibility != ProtocolCompatibility.COMPATIBLE:
            self.db.flush()
            return None, None, compatibility

        bind_tenant_scope(
            self.db,
            organisation_id=row.organisation_id,
            participant_id=row.participant_id,
            user_id=None,
            role=None,
        )
        binding, permanent = AgentBindingService(self.db).create(
            installation_id=installation_id,
            display_name=row.display_name,
            protocol_version=handshake.protocol_version,
            agent_version=handshake.agent_version,
            activate=True,
            primary=True,
            user_id=row.created_by_user_id,
        )
        binding.protocol_compatibility_state = compatibility
        binding.supported_job_types_json = list(jobs)
        binding.supported_capabilities_json = list(capabilities)
        binding.enrolled_at = now
        row.binding_id = binding.id
        self.db.flush()
        return binding, permanent, compatibility

    def handshake(
        self,
        binding: AgentBindingRecord,
        *,
        protocol_version: str,
        agent_version: str,
        supported_job_types: Iterable[str],
        supported_capabilities: Iterable[str],
    ) -> str:
        value = AgentHandshake(
            protocol_version=protocol_version[:32],
            agent_version=agent_version[:64],
            supported_job_types=tuple(sorted({str(x)[:48] for x in supported_job_types if str(x)})),
            supported_capabilities=tuple(sorted({str(x)[:80] for x in supported_capabilities if str(x)})),
        )
        compatibility = evaluate_protocol(value, config=self.config)
        binding.protocol_version = value.protocol_version
        binding.agent_version = value.agent_version
        binding.supported_job_types_json = list(value.supported_job_types)
        binding.supported_capabilities_json = list(value.supported_capabilities)
        binding.protocol_compatibility_state = compatibility
        binding.last_error_code = None if compatibility == ProtocolCompatibility.COMPATIBLE else "AGENT_PROTOCOL_INCOMPATIBLE"
        self.db.flush()
        return compatibility


def binding_supports_job(binding: AgentBindingRecord, job_type: str) -> bool:
    if binding.protocol_compatibility_state != ProtocolCompatibility.COMPATIBLE:
        return False
    advertised = tuple(binding.supported_job_types_json or ())
    # Empty is transitional M14 compatibility only. M15 enrolled agents always
    # advertise an explicit list; strict production disables legacy bootstrap.
    return not advertised or job_type in advertised
