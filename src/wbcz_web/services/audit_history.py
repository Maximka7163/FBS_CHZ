from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import hmac
import json
import math
import os
import re
from typing import Any, Iterable, Mapping
from uuid import UUID, uuid4

from sqlalchemy import MetaData, Table, inspect, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from wbcz_web.models.audit_history import (
    ACTOR_KINDS,
    AUDIT_CATEGORIES,
    AUDIT_FORMAT_VERSION,
    AUDIT_OUTCOMES,
    AUTHORIZATION_DECISIONS,
    CHECKPOINT_FORMAT_VERSION,
    SUBJECT_TYPES,
    ZERO_HASH,
    AuditChainHeadRecord,
    AuditCheckpointRecord,
    AuditEventRecord,
)
from wbcz_web.models.security import MembershipRecord, OrganisationRecord, ParticipantRecord
from wbcz_web.services.authorization import ROLE_PERMISSIONS, Role


SAFE_JSON_INTEGER_MAX = 9_007_199_254_740_991
MAX_SANITIZER_DEPTH = 8
MAX_METADATA_KEYS = 100
MAX_ARRAY_ELEMENTS = 100
MAX_STRING_CHARS = 4096
MAX_METADATA_BYTES = 32 * 1024

_SECRET_MARKERS = (
    "password", "passwd", "token", "authorization", "cookie", "session_token",
    "csrf", "invite_token", "secret", "api_key", "api-key", "private_key", "pin", "bearer",
)
_MARKING_MARKERS = (
    "kiz", "cis", "cises", "sgtin", "km", "marking_code", "marking_identifier", "marking",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AuditError(RuntimeError):
    pass


class AuditRegistryError(AuditError):
    pass


class AuditSanitizationError(AuditError):
    pass


class AuditEventKeyConflict(AuditError):
    pass


class AuditIntegrityError(AuditError):
    pass


class AuditCategory(StrEnum):
    SECURITY = "SECURITY"
    AUTHORIZATION = "AUTHORIZATION"
    TENANT_ADMIN = "TENANT_ADMIN"
    INTEGRATION = "INTEGRATION"
    IMPORT = "IMPORT"
    CONTROL = "CONTROL"
    CIS_READ = "CIS_READ"
    REFERENCE_READ = "REFERENCE_READ"
    DOCUMENT = "DOCUMENT"
    TURNOVER = "TURNOVER"
    AGGREGATION = "AGGREGATION"
    EDO = "EDO"
    SUZ = "SUZ"
    WB = "WB"
    OZON = "OZON"
    REPORT = "REPORT"
    AGENT = "AGENT"
    PRINTING = "PRINTING"
    SYSTEM = "SYSTEM"


class ActorKind(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    WORKER = "WORKER"
    WINDOWS_AGENT = "WINDOWS_AGENT"
    CLI_ADMIN = "CLI_ADMIN"
    BOOTSTRAP = "BOOTSTRAP"
    REMOTE_SYSTEM = "REMOTE_SYSTEM"


class SubjectType(StrEnum):
    USER = "USER"
    SESSION = "SESSION"
    MEMBERSHIP = "MEMBERSHIP"
    INVITATION = "INVITATION"
    ORGANISATION = "ORGANISATION"
    PARTICIPANT = "PARTICIPANT"
    IMPORT = "IMPORT"
    EVENT = "EVENT"
    CONTROL_RUN = "CONTROL_RUN"
    AGENT_JOB = "AGENT_JOB"
    WRITE_OPERATION = "WRITE_OPERATION"
    DOCUMENT_OPERATION = "DOCUMENT_OPERATION"
    TURNOVER_OPERATION = "TURNOVER_OPERATION"
    AGGREGATION_OPERATION = "AGGREGATION_OPERATION"
    EDO_OBJECT = "EDO_OBJECT"
    SUZ_CONNECTION = "SUZ_CONNECTION"
    SUZ_ORDER = "SUZ_ORDER"
    WB_CONNECTION = "WB_CONNECTION"
    WB_OBJECT = "WB_OBJECT"
    OZON_CONNECTION = "OZON_CONNECTION"
    OZON_OBJECT = "OZON_OBJECT"
    REPORT_JOB = "REPORT_JOB"
    REPORT_ARTIFACT = "REPORT_ARTIFACT"
    INTEGRATION_CONNECTION = "INTEGRATION_CONNECTION"
    MARKING_IDENTIFIER = "MARKING_IDENTIFIER"
    PRINT_TEMPLATE = "PRINT_TEMPLATE"
    PRINT_JOB = "PRINT_JOB"
    PRINT_EVENT = "PRINT_EVENT"
    AUDIT_CHAIN = "AUDIT_CHAIN"
    AUDIT_CHECKPOINT = "AUDIT_CHECKPOINT"


class AuditOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILED = "FAILED"
    PENDING = "PENDING"
    CONFLICT = "CONFLICT"
    CANCELLED = "CANCELLED"
    AMBIGUOUS = "AMBIGUOUS"


class AuthorizationDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class TenantRequirement(StrEnum):
    SYSTEM = "SYSTEM"
    ORGANISATION = "ORGANISATION"
    PARTICIPANT = "PARTICIPANT"
    SYSTEM_OR_ORGANISATION = "SYSTEM_OR_ORGANISATION"


@dataclass(frozen=True, slots=True)
class RegisteredAuditEvent:
    event_type: str
    category: AuditCategory
    action: str
    criticality: str
    allowed_actor_kinds: frozenset[ActorKind]
    allowed_subject_types: frozenset[SubjectType]
    tenant_requirement: TenantRequirement
    permission_snapshot_required: bool
    audit_required: bool
    allowed_metadata_keys: frozenset[str]
    required_metadata_keys: frozenset[str] = frozenset()


_COMMON_METADATA = frozenset({
    "reason", "count", "role", "old_role", "new_role", "identity_bound",
    "organisation_id", "participant_id", "legacy_sessions_revoked", "sensitivity_class",
    "report_job_id", "artifact_id", "report_type", "format", "schema_version", "row_count",
    "byte_size", "artifact_sha256", "request_fingerprint_sha256", "state", "from_state",
    "to_state", "operation_kind", "document_type", "document_sha256", "request_sha256",
    "idempotency_fingerprint", "precondition_evidence_sha256", "postcondition_evidence_sha256",
    "remote_document_id", "http_status", "remote_status", "remote_code", "body_sha256",
    "ambiguity", "manual_review_reason", "reconciliation_state", "job_type", "purpose",
    "delivery_count", "payload_sha256", "result_sha256", "machine_principal_hmac",
    "checkpoint_id", "checkpoint_hash", "through_sequence", "checked_from", "checked_to",
    "template_id", "template_version_id", "layout_sha256", "stored_km_item_id",
    "printer_profile_fingerprint", "original_print_event_id", "print_mode", "error_code",
    "checked_count", "verification_status", "first_invalid_sequence", "failure_reason",
    "semantics", "manifest", "cutoff", "source", "error_code", "error_class",
    "redacted_message", "retry_classification", "evidence_sha256", "changed_fields",
    "credential_present", "credential_changed", "safe_config_fingerprint", "client_ip_hmac",
    "user_agent_hmac", "filter_summary", "limit", "returned_count", "query_kind",
    "remote_result_part_id", "publication_key_present", "artifact_role", "origin",
    "attempt_count", "blind_retry", "lease_recovered", "result_outcome", "action",
    "child_set_hash", "relation_delta", "request_id", "document_id_present",
    "member_user_id", "controlled_recovery", "participant_verification_state",
    "integration_type", "connection_type", "connection_id", "configuration_status",
    "runtime_status", "contract_status", "feature_gate_status", "check_kind",
    "overall_status", "component_statuses", "capability_names", "reused",
    "binding_id", "installation_id", "protocol_version", "agent_version",
    "credential_version", "is_primary", "certificate_thumbprint", "certificate_state",
    "selection_state", "expiry_state", "match_state", "provider_capabilities",
    "rotation_state", "old_version", "new_version", "enabled", "blocker_code",
})


def _ev(
    event_type: str,
    category: AuditCategory,
    action: str,
    actors: Iterable[ActorKind],
    subjects: Iterable[SubjectType],
    tenant: TenantRequirement,
    *,
    snapshot: bool = False,
    criticality: str = "HIGH",
    required: bool = True,
    metadata: Iterable[str] = (),
    required_metadata: Iterable[str] = (),
) -> RegisteredAuditEvent:
    keys = _COMMON_METADATA | frozenset(metadata)
    required_keys = frozenset(required_metadata)
    if not required_keys.issubset(keys):
        raise AssertionError("required metadata must be allowed")
    return RegisteredAuditEvent(
        event_type=event_type,
        category=category,
        action=action,
        criticality=criticality,
        allowed_actor_kinds=frozenset(actors),
        allowed_subject_types=frozenset(subjects),
        tenant_requirement=tenant,
        permission_snapshot_required=snapshot,
        audit_required=required,
        allowed_metadata_keys=keys,
        required_metadata_keys=required_keys,
    )


U = ActorKind.USER
S = ActorKind.SYSTEM
W = ActorKind.WORKER
A = ActorKind.WINDOWS_AGENT
C = ActorKind.CLI_ADMIN
B = ActorKind.BOOTSTRAP
R = ActorKind.REMOTE_SYSTEM


_EVENT_DEFINITIONS = [
    _ev("AUDIT_CHAIN_GENESIS", AuditCategory.SYSTEM, "CHAIN_GENESIS", [S], [SubjectType.AUDIT_CHAIN], TenantRequirement.SYSTEM_OR_ORGANISATION),
    _ev("LEGACY_HISTORY_IMPORTED", AuditCategory.SYSTEM, "LEGACY_HISTORY_IMPORTED", [S], [SubjectType.AUDIT_CHAIN], TenantRequirement.SYSTEM_OR_ORGANISATION, metadata=["manifest","semantics","cutoff"]),
    _ev("CHECKPOINT_CREATED", AuditCategory.SYSTEM, "CHECKPOINT_CREATED", [S], [SubjectType.AUDIT_CHECKPOINT], TenantRequirement.SYSTEM_OR_ORGANISATION, metadata=["checkpoint_id","checkpoint_hash","through_sequence"]),
    _ev("CHAIN_VERIFICATION_FAILED", AuditCategory.SYSTEM, "CHAIN_VERIFICATION_FAILED", [S,C], [SubjectType.AUDIT_CHAIN], TenantRequirement.SYSTEM, metadata=["first_invalid_sequence","failure_reason","verification_status"]),
    _ev("AUDIT_QUERY_EXECUTED", AuditCategory.AUTHORIZATION, "AUDIT_QUERY", [U], [SubjectType.AUDIT_CHAIN], TenantRequirement.ORGANISATION, snapshot=True, metadata=["filter_summary","limit","returned_count","query_kind"]),
    _ev("AUTHORIZATION_DENIED", AuditCategory.AUTHORIZATION, "ACCESS_DENIED", [U], [SubjectType.AUDIT_CHAIN], TenantRequirement.SYSTEM_OR_ORGANISATION, snapshot=True, metadata=["reason","query_kind"]),
    _ev("LOGIN_SUCCESS", AuditCategory.SECURITY, "LOGIN", [U], [SubjectType.SESSION], TenantRequirement.SYSTEM),
    _ev("LOGIN_FAILED", AuditCategory.SECURITY, "LOGIN", [S,U], [SubjectType.USER,SubjectType.SESSION], TenantRequirement.SYSTEM, criticality="MEDIUM"),
    _ev("LOGIN_THROTTLED", AuditCategory.SECURITY, "LOGIN_THROTTLE", [S,U], [SubjectType.USER,SubjectType.SESSION], TenantRequirement.SYSTEM),
    _ev("LOGOUT", AuditCategory.SECURITY, "LOGOUT", [U], [SubjectType.SESSION], TenantRequirement.SYSTEM),
    _ev("LOGOUT_ALL", AuditCategory.SECURITY, "LOGOUT_ALL", [U,C], [SubjectType.USER], TenantRequirement.SYSTEM),
    _ev("SESSION_REVOKED", AuditCategory.SECURITY, "SESSION_REVOKED", [U,C,S], [SubjectType.SESSION,SubjectType.USER], TenantRequirement.SYSTEM),
    _ev("PASSWORD_CHANGED", AuditCategory.SECURITY, "PASSWORD_CHANGED", [U,C], [SubjectType.USER], TenantRequirement.SYSTEM),
    _ev("PASSWORD_AUTHENTICATOR_UNLOCKED", AuditCategory.SECURITY, "PASSWORD_AUTHENTICATOR_UNLOCKED", [C,U], [SubjectType.USER], TenantRequirement.SYSTEM),
    _ev("USER_DISABLED", AuditCategory.SECURITY, "USER_DISABLED", [C], [SubjectType.USER], TenantRequirement.SYSTEM),
    _ev("SCOPE_CHANGED", AuditCategory.TENANT_ADMIN, "SCOPE_CHANGED", [U], [SubjectType.ORGANISATION], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("MEMBERSHIP_ADDED", AuditCategory.TENANT_ADMIN, "MEMBERSHIP_ADDED", [U,B,C], [SubjectType.MEMBERSHIP], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("MEMBERSHIP_REMOVED", AuditCategory.TENANT_ADMIN, "MEMBERSHIP_REMOVED", [U,C], [SubjectType.MEMBERSHIP], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("ROLE_CHANGED", AuditCategory.TENANT_ADMIN, "ROLE_CHANGED", [U,C], [SubjectType.MEMBERSHIP], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("INVITATION_CREATED", AuditCategory.TENANT_ADMIN, "INVITATION_CREATED", [U], [SubjectType.INVITATION], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("INVITATION_ACCEPTED", AuditCategory.TENANT_ADMIN, "INVITATION_ACCEPTED", [U], [SubjectType.INVITATION,SubjectType.MEMBERSHIP], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("INVITATION_REVOKED", AuditCategory.TENANT_ADMIN, "INVITATION_REVOKED", [U], [SubjectType.INVITATION], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("BOOTSTRAP_COMPLETED", AuditCategory.TENANT_ADMIN, "BOOTSTRAP_COMPLETED", [B], [SubjectType.ORGANISATION], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("TURNOVER_INTENT_CREATED", AuditCategory.TURNOVER, "INTENT_CREATED", [U,W], [SubjectType.TURNOVER_OPERATION,SubjectType.WRITE_OPERATION], TenantRequirement.PARTICIPANT, snapshot=True),
    _ev("TURNOVER_REMOTE_RESULT", AuditCategory.TURNOVER, "REMOTE_RESULT", [W,A,R], [SubjectType.TURNOVER_OPERATION,SubjectType.WRITE_OPERATION], TenantRequirement.PARTICIPANT),
    _ev("TURNOVER_RECONCILED", AuditCategory.TURNOVER, "RECONCILED", [W,U], [SubjectType.TURNOVER_OPERATION,SubjectType.WRITE_OPERATION], TenantRequirement.PARTICIPANT),
    _ev("AGGREGATION_INTENT_CREATED", AuditCategory.AGGREGATION, "INTENT_CREATED", [U,W], [SubjectType.AGGREGATION_OPERATION], TenantRequirement.PARTICIPANT, snapshot=True),
    _ev("AGGREGATION_REMOTE_RESULT", AuditCategory.AGGREGATION, "REMOTE_RESULT", [W,A,R], [SubjectType.AGGREGATION_OPERATION], TenantRequirement.PARTICIPANT),
    _ev("AGGREGATION_RECONCILED", AuditCategory.AGGREGATION, "RECONCILED", [W,U], [SubjectType.AGGREGATION_OPERATION], TenantRequirement.PARTICIPANT),
    _ev("REPORT_REQUESTED", AuditCategory.REPORT, "REQUESTED", [U,W], [SubjectType.REPORT_JOB], TenantRequirement.PARTICIPANT, snapshot=True),
    _ev("REPORT_GENERATION_STARTED", AuditCategory.REPORT, "GENERATION_STARTED", [W], [SubjectType.REPORT_JOB], TenantRequirement.PARTICIPANT),
    _ev("REPORT_GENERATION_COMPLETED", AuditCategory.REPORT, "GENERATION_COMPLETED", [W], [SubjectType.REPORT_JOB], TenantRequirement.PARTICIPANT),
    _ev("REPORT_GENERATION_FAILED", AuditCategory.REPORT, "GENERATION_FAILED", [W], [SubjectType.REPORT_JOB], TenantRequirement.PARTICIPANT),
    _ev("REPORT_ARTIFACT_FINALIZED", AuditCategory.REPORT, "ARTIFACT_FINALIZED", [W,A], [SubjectType.REPORT_ARTIFACT], TenantRequirement.PARTICIPANT),
    _ev("REPORT_DOWNLOAD_AUTHORIZED", AuditCategory.REPORT, "DOWNLOAD_AUTHORIZED", [U], [SubjectType.REPORT_ARTIFACT], TenantRequirement.PARTICIPANT, snapshot=True),
    _ev("REPORT_DOWNLOAD_DENIED", AuditCategory.REPORT, "DOWNLOAD_DENIED", [U,S], [SubjectType.REPORT_ARTIFACT,SubjectType.ORGANISATION], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("REPORT_DOWNLOAD_COMPLETED", AuditCategory.REPORT, "DOWNLOAD_COMPLETED", [U], [SubjectType.REPORT_ARTIFACT], TenantRequirement.PARTICIPANT, snapshot=True),
    _ev("REPORT_DOWNLOAD_FAILED", AuditCategory.REPORT, "DOWNLOAD_FAILED", [U,S], [SubjectType.REPORT_ARTIFACT], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("REPORT_ARTIFACT_INTEGRITY_FAILED", AuditCategory.REPORT, "ARTIFACT_INTEGRITY_FAILED", [U,W,S], [SubjectType.REPORT_ARTIFACT,SubjectType.ORGANISATION], TenantRequirement.ORGANISATION, snapshot=True),
    _ev("REPORT_ARTIFACT_DELETED", AuditCategory.REPORT, "ARTIFACT_DELETED", [W,U], [SubjectType.REPORT_ARTIFACT], TenantRequirement.PARTICIPANT),
    _ev("REPORT_ARTIFACT_EXPIRED", AuditCategory.REPORT, "ARTIFACT_EXPIRED", [W,S], [SubjectType.REPORT_ARTIFACT], TenantRequirement.PARTICIPANT),
    _ev("AGENT_JOB_CREATED", AuditCategory.AGENT, "JOB_CREATED", [U,W,S], [SubjectType.AGENT_JOB], TenantRequirement.SYSTEM_OR_ORGANISATION),
    _ev("AGENT_JOB_CLAIMED", AuditCategory.AGENT, "JOB_CLAIMED", [A,W], [SubjectType.AGENT_JOB], TenantRequirement.SYSTEM_OR_ORGANISATION),
    _ev("AGENT_JOB_COMPLETED", AuditCategory.AGENT, "JOB_COMPLETED", [A,W], [SubjectType.AGENT_JOB], TenantRequirement.SYSTEM_OR_ORGANISATION),
    _ev("AGENT_JOB_FAILED", AuditCategory.AGENT, "JOB_FAILED", [A,W], [SubjectType.AGENT_JOB], TenantRequirement.SYSTEM_OR_ORGANISATION),
    _ev("AGENT_RESULT_AMBIGUOUS", AuditCategory.AGENT, "RESULT_AMBIGUOUS", [A,W], [SubjectType.AGENT_JOB], TenantRequirement.SYSTEM_OR_ORGANISATION),
    _ev("AGENT_REPLAY_CONVERGED", AuditCategory.AGENT, "REPLAY_CONVERGED", [A,W], [SubjectType.AGENT_JOB], TenantRequirement.SYSTEM_OR_ORGANISATION),
    _ev("AGENT_ARTIFACT_UPLOADED", AuditCategory.AGENT, "ARTIFACT_UPLOADED", [A], [SubjectType.AGENT_JOB,SubjectType.REPORT_ARTIFACT], TenantRequirement.PARTICIPANT),
    _ev("AGENT_DOCUMENT_SUBMITTED", AuditCategory.AGENT, "DOCUMENT_SUBMITTED", [A], [SubjectType.AGENT_JOB,SubjectType.WRITE_OPERATION], TenantRequirement.PARTICIPANT),
    _ev("CONNECTION_CREATED", AuditCategory.INTEGRATION, "CONNECTION_CREATED", [U,C], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_type","connection_id","enabled"]),
    _ev("CONNECTION_UPDATED", AuditCategory.INTEGRATION, "CONNECTION_UPDATED", [U,C], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_type","connection_id","changed_fields"]),
    _ev("CONNECTION_ENABLED", AuditCategory.INTEGRATION, "CONNECTION_ENABLED", [U,C], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_type","connection_id"]),
    _ev("CONNECTION_DISABLED", AuditCategory.INTEGRATION, "CONNECTION_DISABLED", [U,C], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_type","connection_id"]),
    _ev("CONNECTION_ARCHIVED", AuditCategory.INTEGRATION, "CONNECTION_ARCHIVED", [U,C], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_type","connection_id"]),
    _ev("SECRET_SET", AuditCategory.INTEGRATION, "SECRET_SET", [U,C], [SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_id","new_version","rotation_state"]),
    _ev("SECRET_ROTATED", AuditCategory.INTEGRATION, "SECRET_ROTATED", [U,C], [SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_id","old_version","new_version","rotation_state"]),
    _ev("SECRET_REVOKED", AuditCategory.INTEGRATION, "SECRET_REVOKED", [U,C], [SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_id","old_version"]),
    _ev("CONNECTION_CHECK_STARTED", AuditCategory.INTEGRATION, "CONNECTION_CHECK_STARTED", [U,W], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["integration_type","connection_id","check_kind","reused"]),
    _ev("CONNECTION_CHECK_COMPLETED", AuditCategory.INTEGRATION, "CONNECTION_CHECK_COMPLETED", [U,W,A], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, metadata=["integration_type","connection_id","check_kind","overall_status","component_statuses","capability_names","evidence_sha256"]),
    _ev("CONNECTION_CHECK_FAILED", AuditCategory.INTEGRATION, "CONNECTION_CHECK_FAILED", [U,W,A], [SubjectType.INTEGRATION_CONNECTION,SubjectType.WB_CONNECTION,SubjectType.OZON_CONNECTION,SubjectType.SUZ_CONNECTION], TenantRequirement.PARTICIPANT, metadata=["integration_type","connection_id","check_kind","error_code","redacted_message"]),
    _ev("CERTIFICATE_SELECTION_CHANGED", AuditCategory.INTEGRATION, "CERTIFICATE_SELECTION_CHANGED", [U,C,A], [SubjectType.INTEGRATION_CONNECTION], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["connection_id","certificate_thumbprint","selection_state"]),
    _ev("AGENT_BINDING_CREATED", AuditCategory.INTEGRATION, "AGENT_BINDING_CREATED", [U,C], [SubjectType.INTEGRATION_CONNECTION,SubjectType.PARTICIPANT], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["binding_id","installation_id","protocol_version","credential_version","is_primary"]),
    _ev("AGENT_BINDING_CHANGED", AuditCategory.INTEGRATION, "AGENT_BINDING_CHANGED", [U,C,A], [SubjectType.INTEGRATION_CONNECTION,SubjectType.PARTICIPANT], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["binding_id","changed_fields","credential_version","is_primary","state"]),
    _ev("AGENT_BINDING_DISABLED", AuditCategory.INTEGRATION, "AGENT_BINDING_DISABLED", [U,C], [SubjectType.INTEGRATION_CONNECTION,SubjectType.PARTICIPANT], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["binding_id","state"]),
    _ev("PRINT_TEMPLATE_CREATED", AuditCategory.PRINTING, "PRINT_TEMPLATE_CREATED", [U], [SubjectType.PRINT_TEMPLATE], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["template_id","template_version_id","layout_sha256"]),
    _ev("PRINT_TEMPLATE_VERSION_CREATED", AuditCategory.PRINTING, "PRINT_TEMPLATE_VERSION_CREATED", [U], [SubjectType.PRINT_TEMPLATE], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["template_id","template_version_id","layout_sha256"]),
    _ev("PRINT_TEMPLATE_ARCHIVED", AuditCategory.PRINTING, "PRINT_TEMPLATE_ARCHIVED", [U], [SubjectType.PRINT_TEMPLATE], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["template_id","template_version_id"]),
    _ev("PRINT_JOB_REQUESTED", AuditCategory.PRINTING, "PRINT_JOB_REQUESTED", [U], [SubjectType.PRINT_JOB], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["template_version_id","count","printer_profile_fingerprint","print_mode","payload_sha256"]),
    _ev("PRINT_JOB_COMPLETED", AuditCategory.PRINTING, "PRINT_JOB_COMPLETED", [A,W], [SubjectType.PRINT_JOB], TenantRequirement.PARTICIPANT, metadata=["template_version_id","count","printer_profile_fingerprint","print_mode","payload_sha256"]),
    _ev("PRINT_JOB_FAILED", AuditCategory.PRINTING, "PRINT_JOB_FAILED", [A,W,S], [SubjectType.PRINT_JOB], TenantRequirement.PARTICIPANT, metadata=["template_version_id","count","printer_profile_fingerprint","print_mode","payload_sha256","error_code"]),
    _ev("REPRINT_REQUESTED", AuditCategory.PRINTING, "REPRINT_REQUESTED", [U], [SubjectType.PRINT_JOB], TenantRequirement.PARTICIPANT, snapshot=True, metadata=["template_version_id","count","printer_profile_fingerprint","original_print_event_id","print_mode","payload_sha256"]),
    _ev("REPRINT_COMPLETED", AuditCategory.PRINTING, "REPRINT_COMPLETED", [A,W], [SubjectType.PRINT_JOB], TenantRequirement.PARTICIPANT, metadata=["template_version_id","count","printer_profile_fingerprint","original_print_event_id","print_mode","payload_sha256"]),
    _ev("REPRINT_FAILED", AuditCategory.PRINTING, "REPRINT_FAILED", [A,W,S], [SubjectType.PRINT_JOB], TenantRequirement.PARTICIPANT, metadata=["template_version_id","count","printer_profile_fingerprint","original_print_event_id","print_mode","payload_sha256","error_code"]),
]

AUDIT_EVENT_REGISTRY: dict[str, RegisteredAuditEvent] = {item.event_type: item for item in _EVENT_DEFINITIONS}
if len(AUDIT_EVENT_REGISTRY) != len(_EVENT_DEFINITIONS):
    raise RuntimeError("duplicate M13 audit event type")
if {item.value for item in AuditCategory} != set(AUDIT_CATEGORIES):
    raise RuntimeError("audit category registry drift")
if {item.value for item in ActorKind} != set(ACTOR_KINDS):
    raise RuntimeError("actor kind registry drift")
if {item.value for item in SubjectType} != set(SUBJECT_TYPES):
    raise RuntimeError("subject type registry drift")
if {item.value for item in AuditOutcome} != set(AUDIT_OUTCOMES):
    raise RuntimeError("audit outcome registry drift")
if {item.value for item in AuthorizationDecision} != set(AUTHORIZATION_DECISIONS):
    raise RuntimeError("authorization decision registry drift")


@dataclass(frozen=True, slots=True)
class ActorContext:
    kind: ActorKind
    user_id: int | None = None
    machine_principal: str | None = None


@dataclass(frozen=True, slots=True)
class AuditTenantScope:
    organisation_id: str | None = None
    participant_id: str | None = None

    @classmethod
    def system(cls) -> "AuditTenantScope":
        return cls(None, None)


@dataclass(frozen=True, slots=True)
class SubjectRef:
    type: SubjectType
    id: str
    plaintext_marking: bool = False


@dataclass(frozen=True, slots=True)
class TraceContext:
    request_id: str | None = None
    correlation_id: str | None = None
    causation_id: str | None = None
    operation_id: str | None = None
    agent_job_id: str | None = None
    event_key: str | None = None


@dataclass(frozen=True, slots=True)
class AuditReceipt:
    event_id: str
    chain_id: str
    sequence: int
    event_hash: str
    previous_event_hash: str
    converged: bool = False


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: str
    chain_id: str
    checked_from: int
    checked_to: int
    checked_count: int
    stored_head_sequence: int
    stored_head_hash: str
    first_invalid_sequence: int | None = None
    reason: str | None = None
    checkpoint_status: str = "VALID"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise AuditError("audit timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _storage_utc(value: datetime) -> datetime:
    """Normalize timestamps read from DBs that may drop tzinfo (legacy SQLite tests)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def rfc3339_microseconds(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_uuid(value: str) -> str:
    return str(UUID(str(value))).lower()


def _reject_surrogates(value: str) -> None:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise AuditSanitizationError("lone Unicode surrogate is not valid JCS input")


def _jcs_float(value: float) -> str:
    if not math.isfinite(value):
        raise AuditSanitizationError("NaN/Infinity are forbidden")
    if value == 0:
        return "0"
    raw = repr(value).lower()
    negative = raw.startswith("-")
    absolute = abs(value)
    if "e" in raw:
        mantissa, exponent_raw = raw.split("e", 1)
        exponent = int(exponent_raw)
        if 1e-6 <= absolute < 1e21:
            from decimal import Decimal
            out = format(Decimal(raw), "f")
            if "." in out:
                out = out.rstrip("0").rstrip(".")
            return out
        mantissa = mantissa.rstrip("0").rstrip(".")
        sign = "+" if exponent >= 0 else "-"
        return f"{mantissa}e{sign}{abs(exponent)}"
    if absolute >= 1e21:
        # repr normally uses scientific notation here; keep this defensive path.
        return _jcs_float(float(f"{value:.15e}"))
    if raw.endswith(".0"):
        return raw[:-2]
    return raw


def _jcs_value(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        _reject_surrogates(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if type(value) is int:
        if abs(value) > SAFE_JSON_INTEGER_MAX:
            raise AuditSanitizationError("unsafe JSON integer must be encoded as string")
        return str(value)
    if type(value) is float:
        return _jcs_float(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_value(item) for item in value) + "]"
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuditSanitizationError("JCS object keys must be strings")
            _reject_surrogates(key)
            items.append((key, item))
        items.sort(key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False, separators=(",", ":")) + ":" + _jcs_value(item)
            for key, item in items
        ) + "}"
    raise AuditSanitizationError("unsupported JCS value type")


def jcs_dumps(value: Any) -> str:
    return _jcs_value(value)


def jcs_bytes(value: Any) -> bytes:
    return jcs_dumps(value).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class AuditPseudonymizer:
    def __init__(self, key: bytes | None = None, *, key_id: str | None = None) -> None:
        if key is None:
            raw = os.getenv("WBCZ_AUDIT_PSEUDONYM_KEY", "")
            if raw:
                key = raw.encode("utf-8")
        if key is not None and len(key) < 32:
            raise AuditError("audit pseudonym key must be at least 32 bytes")
        self._key = key
        self.key_id = (key_id or os.getenv("WBCZ_AUDIT_PSEUDONYM_KEY_ID", "audit-v1")).strip() or "audit-v1"

    def _hmac(self, purpose: str, value: str) -> str:
        if self._key is None:
            raise AuditError("audit pseudonym key is required for sensitive pseudonymization")
        digest = hmac.new(self._key, f"{purpose}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        return f"hmac-sha256:{self.key_id}:{digest}"

    def marking(self, organisation_id: str, exact_value: str) -> str:
        return self._hmac("marking:v1", f"{organisation_id}:{exact_value}")

    def client_ip(self, raw_ip: str) -> str:
        return self._hmac("client-ip:v1", raw_ip)

    def user_agent(self, raw_user_agent: str) -> str:
        return self._hmac("user-agent:v1", raw_user_agent)

    def session_identifier(self, raw_session_identifier: str) -> str:
        return self._hmac("session-id:v1", raw_session_identifier)

    def machine_principal(self, raw_principal: str) -> str:
        return self._hmac("machine-principal:v1", raw_principal)


class AuditSanitizer:
    def __init__(self, pseudonymizer: AuditPseudonymizer) -> None:
        self.pseudonymizer = pseudonymizer

    @staticmethod
    def _secret_key(key: str) -> bool:
        lowered = key.casefold().replace("-", "_")
        return any(marker.replace("-", "_") in lowered for marker in _SECRET_MARKERS)

    @staticmethod
    def _marking_key(key: str) -> bool:
        lowered = key.casefold().replace("-", "_")
        return any(marker in lowered for marker in _MARKING_MARKERS)

    def sanitize(self, value: Any, *, organisation_id: str | None, depth: int = 0, path: tuple[str, ...] = ()) -> Any:
        if depth > MAX_SANITIZER_DEPTH:
            raise AuditSanitizationError("audit metadata depth exceeds limit")
        if value is None or type(value) is bool:
            return value
        if type(value) is int:
            return str(value) if abs(value) > SAFE_JSON_INTEGER_MAX else value
        if type(value) is float:
            if not math.isfinite(value):
                raise AuditSanitizationError("NaN/Infinity are forbidden")
            return value
        if isinstance(value, str):
            _reject_surrogates(value)
            if len(value) > MAX_STRING_CHARS:
                raise AuditSanitizationError("audit metadata string exceeds limit")
            return value
        if isinstance(value, (list, tuple)):
            if len(value) > MAX_ARRAY_ELEMENTS:
                raise AuditSanitizationError("audit metadata array exceeds limit")
            return [
                self.sanitize(item, organisation_id=organisation_id, depth=depth + 1, path=path)
                for item in value
            ]
        if isinstance(value, Mapping):
            if len(value) > MAX_METADATA_KEYS:
                raise AuditSanitizationError("audit metadata object exceeds key limit")
            result: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise AuditSanitizationError("audit metadata keys must be strings")
                if len(key) > 128:
                    raise AuditSanitizationError("audit metadata key exceeds limit")
                if self._secret_key(key):
                    result[key] = "[REDACTED]"
                    continue
                if self._marking_key(key):
                    if organisation_id is None:
                        result[key] = "[REDACTED_MARKING]"
                    elif isinstance(item, str):
                        result[key] = self.pseudonymizer.marking(organisation_id, item)
                    elif isinstance(item, (list, tuple)):
                        if len(item) > MAX_ARRAY_ELEMENTS:
                            raise AuditSanitizationError("marking array exceeds limit")
                        result[key] = [
                            self.pseudonymizer.marking(organisation_id, exact)
                            if isinstance(exact, str) else "[REDACTED_MARKING]"
                            for exact in item
                        ]
                    else:
                        result[key] = "[REDACTED_MARKING]"
                    continue
                result[key] = self.sanitize(
                    item,
                    organisation_id=organisation_id,
                    depth=depth + 1,
                    path=path + (key,),
                )
            return result
        raise AuditSanitizationError("unknown audit metadata object type")

    def metadata(self, value: Mapping[str, Any] | None, *, organisation_id: str | None) -> dict[str, Any]:
        sanitized = self.sanitize(dict(value or {}), organisation_id=organisation_id)
        if not isinstance(sanitized, dict):
            raise AuditSanitizationError("metadata must be an object")
        if len(jcs_bytes(sanitized)) > MAX_METADATA_BYTES:
            raise AuditSanitizationError("audit metadata exceeds 32 KiB canonical limit")
        return sanitized


def _safe_id(value: str | None, *, max_length: int = 256) -> str | None:
    if value is None:
        return None
    value = str(value)
    if not value or len(value) > max_length or any(ord(ch) < 32 for ch in value):
        raise AuditError("unsafe audit identifier")
    return value


def _safe_hash(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.lower()
    if not _HEX64.fullmatch(value):
        raise AuditError("expected lowercase sha256")
    return value


class AuditService:
    """Exclusive append boundary for M13 immutable, tamper-evident audit evidence."""

    def __init__(
        self,
        db: Session,
        *,
        pseudonym_key: bytes | None = None,
        pseudonym_key_id: str | None = None,
    ) -> None:
        self.db = db
        self.pseudonymizer = AuditPseudonymizer(pseudonym_key, key_id=pseudonym_key_id)
        self.sanitizer = AuditSanitizer(self.pseudonymizer)

    def _validate_tenant(self, definition: RegisteredAuditEvent, tenant: AuditTenantScope) -> None:
        org_id = tenant.organisation_id
        participant_id = tenant.participant_id
        if definition.tenant_requirement is TenantRequirement.SYSTEM:
            if org_id is not None or participant_id is not None:
                raise AuditError("system audit event cannot have tenant scope")
            return
        if definition.tenant_requirement is TenantRequirement.ORGANISATION and not org_id:
            raise AuditError("organisation audit scope required")
        if definition.tenant_requirement is TenantRequirement.PARTICIPANT and (not org_id or not participant_id):
            raise AuditError("participant audit scope required")
        if definition.tenant_requirement is TenantRequirement.SYSTEM_OR_ORGANISATION and participant_id and not org_id:
            raise AuditError("participant sub-scope requires organisation")
        if org_id:
            org = self.db.get(OrganisationRecord, org_id)
            if org is None:
                raise AuditError("audit organisation does not exist")
        if participant_id:
            participant = self.db.scalar(select(ParticipantRecord).where(
                ParticipantRecord.id == participant_id,
                ParticipantRecord.organisation_id == org_id,
            ))
            if participant is None:
                raise AuditError("audit participant is outside organisation")

    def _actor_snapshot(
        self,
        definition: RegisteredAuditEvent,
        actor: ActorContext,
        tenant: AuditTenantScope,
        metadata: dict[str, Any],
    ) -> tuple[int | None, str | None, str | None, list[str] | None, dict[str, Any]]:
        if actor.kind not in definition.allowed_actor_kinds:
            raise AuditError("actor kind not allowed for registered audit event")
        user_id = actor.user_id
        membership_id = role_snapshot = None
        permission_snapshot: list[str] | None = None
        if actor.kind is ActorKind.USER:
            if user_id is None:
                raise AuditError("USER actor requires stable user_id")
            if tenant.organisation_id:
                membership = self.db.scalar(select(MembershipRecord).where(
                    MembershipRecord.user_id == user_id,
                    MembershipRecord.organisation_id == tenant.organisation_id,
                    MembershipRecord.is_active.is_(True),
                ))
                if membership is None:
                    raise AuditError("USER actor lacks active organisation membership")
                membership_id = membership.id
                role_snapshot = membership.role
                if definition.permission_snapshot_required:
                    try:
                        role = Role(membership.role)
                    except ValueError as exc:
                        raise AuditError("unknown role snapshot") from exc
                    permission_snapshot = sorted(permission.value for permission in ROLE_PERMISSIONS[role])
            elif definition.permission_snapshot_required:
                permission_snapshot = []
        elif user_id is not None and actor.kind not in {ActorKind.CLI_ADMIN, ActorKind.BOOTSTRAP}:
            raise AuditError("machine/system actor cannot claim user identity")
        if actor.machine_principal:
            metadata = dict(metadata)
            metadata["machine_principal_hmac"] = self.pseudonymizer.machine_principal(actor.machine_principal)
        return user_id, membership_id, role_snapshot, permission_snapshot, metadata

    def _subject(self, subject: SubjectRef, tenant: AuditTenantScope) -> tuple[str, str]:
        if subject.type.value not in SUBJECT_TYPES:
            raise AuditRegistryError("unknown audit subject type")
        subject_id = _safe_id(subject.id)
        assert subject_id is not None
        if subject.type is SubjectType.MARKING_IDENTIFIER:
            if not tenant.organisation_id:
                raise AuditError("marking subject requires organisation scope")
            if subject.plaintext_marking:
                subject_id = self.pseudonymizer.marking(tenant.organisation_id, subject_id)
            elif not subject_id.startswith("hmac-sha256:"):
                raise AuditError("marking subject must be pseudonymized")
        return subject.type.value, subject_id

    @staticmethod
    def _metadata_schema(definition: RegisteredAuditEvent, metadata: Mapping[str, Any]) -> None:
        keys = frozenset(metadata)
        unknown = keys - definition.allowed_metadata_keys
        if unknown:
            raise AuditRegistryError("metadata key not registered for event type")
        missing = definition.required_metadata_keys - keys
        if missing:
            raise AuditRegistryError("required audit metadata is missing")

    def _chain(self, tenant: AuditTenantScope, *, lock: bool = True) -> AuditChainHeadRecord:
        scope_kind = "SYSTEM" if tenant.organisation_id is None else "ORGANISATION"
        stmt = select(AuditChainHeadRecord).where(AuditChainHeadRecord.scope_kind == scope_kind)
        if scope_kind == "ORGANISATION":
            stmt = stmt.where(AuditChainHeadRecord.organisation_id == tenant.organisation_id)
        else:
            stmt = stmt.where(AuditChainHeadRecord.organisation_id.is_(None))
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            chain_id = str(uuid4())
            self.db.execute(
                pg_insert(AuditChainHeadRecord)
                .values(
                    chain_id=chain_id,
                    scope_kind=scope_kind,
                    organisation_id=tenant.organisation_id,
                    head_sequence=0,
                    head_hash=ZERO_HASH,
                    audit_format_version=AUDIT_FORMAT_VERSION,
                )
                .on_conflict_do_nothing()
            )
            self.db.flush()
            row = self.db.scalar(stmt)
        if row is None:
            raise AuditError("could not resolve audit chain")
        if row.audit_format_version != AUDIT_FORMAT_VERSION:
            raise AuditIntegrityError("unsupported audit chain format")
        if row.head_sequence == 0:
            self._append_genesis_locked(row, tenant)
            self.db.flush()
        return row

    def _append_genesis_locked(self, head: AuditChainHeadRecord, tenant: AuditTenantScope) -> AuditReceipt:
        definition = AUDIT_EVENT_REGISTRY["AUDIT_CHAIN_GENESIS"]
        return self._insert_locked(
            head,
            definition=definition,
            actor=ActorContext(ActorKind.SYSTEM),
            tenant=tenant,
            subject=SubjectRef(SubjectType.AUDIT_CHAIN, head.chain_id),
            secondary_subject=None,
            outcome=AuditOutcome.SUCCESS,
            authorization_decision=AuthorizationDecision.NOT_APPLICABLE,
            trace=TraceContext(event_key="genesis:v1"),
            metadata={},
            evidence_hashes=(),
            before_sha256=None,
            after_sha256=None,
            occurred_at=datetime.now(timezone.utc),
            allow_checkpoint=False,
        )

    def append(
        self,
        *,
        event_type: str,
        actor: ActorContext,
        tenant: AuditTenantScope,
        subject: SubjectRef,
        outcome: AuditOutcome,
        authorization_decision: AuthorizationDecision = AuthorizationDecision.NOT_APPLICABLE,
        secondary_subject: SubjectRef | None = None,
        trace: TraceContext | None = None,
        metadata: Mapping[str, Any] | None = None,
        evidence_hashes: Iterable[str] = (),
        before_sha256: str | None = None,
        after_sha256: str | None = None,
        occurred_at: datetime | None = None,
        _allow_checkpoint: bool = True,
    ) -> AuditReceipt:
        definition = AUDIT_EVENT_REGISTRY.get(event_type)
        if definition is None:
            raise AuditRegistryError("unregistered audit event type")
        if definition.category.value not in AUDIT_CATEGORIES:
            raise AuditRegistryError("unregistered audit category")
        self._validate_tenant(definition, tenant)
        if subject.type not in definition.allowed_subject_types:
            raise AuditRegistryError("subject type not allowed for event")
        metadata_raw = dict(metadata or {})
        self._metadata_schema(definition, metadata_raw)
        user_id, membership_id, role_snapshot, permission_snapshot, metadata_raw = self._actor_snapshot(
            definition, actor, tenant, metadata_raw
        )
        metadata_sanitized = self.sanitizer.metadata(metadata_raw, organisation_id=tenant.organisation_id)
        subject_type, subject_id = self._subject(subject, tenant)
        secondary_type = secondary_id = None
        if secondary_subject is not None:
            secondary_type, secondary_id = self._subject(secondary_subject, tenant)
        evidence = []
        for item in evidence_hashes:
            digest = _safe_hash(item)
            if digest is None:
                continue
            evidence.append(digest)
        trace = trace or TraceContext()
        normalized_trace = TraceContext(
            request_id=_safe_id(trace.request_id, max_length=128),
            correlation_id=_safe_id(trace.correlation_id, max_length=128),
            causation_id=_safe_id(trace.causation_id, max_length=128),
            operation_id=_safe_id(trace.operation_id, max_length=128),
            agent_job_id=_safe_id(trace.agent_job_id, max_length=128),
            event_key=_safe_id(trace.event_key, max_length=256),
        )
        head = self._chain(tenant, lock=True)
        return self._insert_locked(
            head,
            definition=definition,
            actor=ActorContext(actor.kind, user_id, actor.machine_principal),
            tenant=tenant,
            subject=SubjectRef(SubjectType(subject_type), subject_id),
            secondary_subject=SubjectRef(SubjectType(secondary_type), secondary_id) if secondary_type else None,
            outcome=outcome,
            authorization_decision=authorization_decision,
            trace=normalized_trace,
            metadata=metadata_sanitized,
            evidence_hashes=tuple(evidence),
            before_sha256=_safe_hash(before_sha256),
            after_sha256=_safe_hash(after_sha256),
            occurred_at=_utc(occurred_at or datetime.now(timezone.utc)),
            allow_checkpoint=_allow_checkpoint,
            actor_snapshot=(membership_id, role_snapshot, permission_snapshot),
        )

    def _semantic_payload(
        self,
        *,
        definition: RegisteredAuditEvent,
        tenant: AuditTenantScope,
        actor_kind: str,
        actor_user_id: int | None,
        actor_membership_id: str | None,
        actor_role_snapshot: str | None,
        permission_snapshot: list[str] | None,
        subject_type: str,
        subject_id: str,
        secondary_subject_type: str | None,
        secondary_subject_id: str | None,
        outcome: str,
        authorization_decision: str,
        trace: TraceContext,
        metadata: Mapping[str, Any],
        evidence_hashes: Iterable[str],
        before_sha256: str | None,
        after_sha256: str | None,
    ) -> dict[str, Any]:
        return {
            "audit_format_version": AUDIT_FORMAT_VERSION,
            "category": definition.category.value,
            "event_type": definition.event_type,
            "action": definition.action,
            "outcome": outcome,
            "authorization_decision": authorization_decision,
            "tenant": {"organisation_id": tenant.organisation_id, "participant_id": tenant.participant_id},
            "actor": {
                "kind": actor_kind,
                "user_id": str(actor_user_id) if actor_user_id is not None else None,
                "membership_id": actor_membership_id,
                "role": actor_role_snapshot,
                "permissions": permission_snapshot,
            },
            "subject": {"type": subject_type, "id": subject_id},
            "secondary_subject": {
                "type": secondary_subject_type,
                "id": secondary_subject_id,
            },
            "trace": {
                "request_id": trace.request_id,
                "correlation_id": trace.correlation_id,
                "causation_id": trace.causation_id,
                "operation_id": trace.operation_id,
                "agent_job_id": trace.agent_job_id,
                "event_key": trace.event_key,
            },
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "evidence_hashes": list(evidence_hashes),
            "metadata": dict(metadata),
        }

    def _canonical_payload(
        self,
        *,
        semantic: Mapping[str, Any],
        chain_id: str,
        sequence: int,
        event_id: str,
        occurred_at: datetime,
        previous_event_hash: str,
    ) -> dict[str, Any]:
        return {
            "audit_format_version": semantic["audit_format_version"],
            "chain_id": canonical_uuid(chain_id),
            "sequence": str(sequence),
            "event_id": canonical_uuid(event_id),
            "occurred_at": rfc3339_microseconds(occurred_at),
            "category": semantic["category"],
            "event_type": semantic["event_type"],
            "action": semantic["action"],
            "outcome": semantic["outcome"],
            "authorization_decision": semantic["authorization_decision"],
            "tenant": semantic["tenant"],
            "actor": semantic["actor"],
            "subject": semantic["subject"],
            "secondary_subject": semantic["secondary_subject"],
            "trace": semantic["trace"],
            "before_sha256": semantic["before_sha256"],
            "after_sha256": semantic["after_sha256"],
            "evidence_hashes": semantic["evidence_hashes"],
            "metadata": semantic["metadata"],
            "previous_event_hash": previous_event_hash,
        }

    def _row_semantic(self, row: AuditEventRecord) -> dict[str, Any]:
        definition = AUDIT_EVENT_REGISTRY.get(row.event_type)
        if definition is None:
            raise AuditIntegrityError("unknown event registry code")
        return self._semantic_payload(
            definition=definition,
            tenant=AuditTenantScope(row.organisation_id, row.participant_id),
            actor_kind=row.actor_kind,
            actor_user_id=row.actor_user_id,
            actor_membership_id=row.actor_membership_id,
            actor_role_snapshot=row.actor_role_snapshot,
            permission_snapshot=list(row.permission_snapshot_json) if row.permission_snapshot_json is not None else None,
            subject_type=row.subject_type,
            subject_id=row.subject_id,
            secondary_subject_type=row.secondary_subject_type,
            secondary_subject_id=row.secondary_subject_id,
            outcome=row.outcome,
            authorization_decision=row.authorization_decision,
            trace=TraceContext(
                request_id=row.request_id,
                correlation_id=row.correlation_id,
                causation_id=row.causation_id,
                operation_id=row.operation_id,
                agent_job_id=row.agent_job_id,
                event_key=row.event_key,
            ),
            metadata=dict(row.metadata_sanitized_json or {}),
            evidence_hashes=list(row.evidence_hashes_json or []),
            before_sha256=row.before_sha256,
            after_sha256=row.after_sha256,
        )

    def _receipt(self, row: AuditEventRecord, *, converged: bool = False) -> AuditReceipt:
        return AuditReceipt(
            event_id=row.event_id,
            chain_id=row.chain_id,
            sequence=row.sequence,
            event_hash=row.event_hash,
            previous_event_hash=row.previous_event_hash,
            converged=converged,
        )

    def _insert_locked(
        self,
        head: AuditChainHeadRecord,
        *,
        definition: RegisteredAuditEvent,
        actor: ActorContext,
        tenant: AuditTenantScope,
        subject: SubjectRef,
        secondary_subject: SubjectRef | None,
        outcome: AuditOutcome,
        authorization_decision: AuthorizationDecision,
        trace: TraceContext,
        metadata: Mapping[str, Any],
        evidence_hashes: Iterable[str],
        before_sha256: str | None,
        after_sha256: str | None,
        occurred_at: datetime,
        allow_checkpoint: bool,
        actor_snapshot: tuple[str | None, str | None, list[str] | None] | None = None,
    ) -> AuditReceipt:
        if actor_snapshot is None:
            actor_user_id, membership_id, role_snapshot, permission_snapshot, _ = self._actor_snapshot(
                definition, actor, tenant, dict(metadata)
            )
        else:
            membership_id, role_snapshot, permission_snapshot = actor_snapshot
            actor_user_id = actor.user_id
        subject_type, subject_id = self._subject(subject, tenant)
        secondary_type = secondary_id = None
        if secondary_subject is not None:
            secondary_type, secondary_id = self._subject(secondary_subject, tenant)
        semantic = self._semantic_payload(
            definition=definition,
            tenant=tenant,
            actor_kind=actor.kind.value,
            actor_user_id=actor_user_id,
            actor_membership_id=membership_id,
            actor_role_snapshot=role_snapshot,
            permission_snapshot=permission_snapshot,
            subject_type=subject_type,
            subject_id=subject_id,
            secondary_subject_type=secondary_type,
            secondary_subject_id=secondary_id,
            outcome=outcome.value,
            authorization_decision=authorization_decision.value,
            trace=trace,
            metadata=metadata,
            evidence_hashes=evidence_hashes,
            before_sha256=before_sha256,
            after_sha256=after_sha256,
        )
        if trace.event_key:
            existing = self.db.scalar(select(AuditEventRecord).where(
                AuditEventRecord.chain_id == head.chain_id,
                AuditEventRecord.event_key == trace.event_key,
            ))
            if existing is not None:
                if jcs_bytes(self._row_semantic(existing)) != jcs_bytes(semantic):
                    raise AuditEventKeyConflict("AUDIT_EVENT_KEY_CONFLICT")
                return self._receipt(existing, converged=True)

        sequence = int(head.head_sequence) + 1
        previous_hash = head.head_hash
        if sequence == 1 and previous_hash != ZERO_HASH:
            raise AuditIntegrityError("audit genesis head is inconsistent")
        event_id = str(uuid4())
        payload = self._canonical_payload(
            semantic=semantic,
            chain_id=head.chain_id,
            sequence=sequence,
            event_id=event_id,
            occurred_at=occurred_at,
            previous_event_hash=previous_hash,
        )
        event_hash = sha256_hex(jcs_bytes(payload))
        row = AuditEventRecord(
            event_id=event_id,
            chain_id=head.chain_id,
            sequence=sequence,
            organisation_id=tenant.organisation_id,
            participant_id=tenant.participant_id,
            category=definition.category.value,
            event_type=definition.event_type,
            action=definition.action,
            outcome=outcome.value,
            authorization_decision=authorization_decision.value,
            actor_kind=actor.kind.value,
            actor_user_id=actor_user_id,
            actor_membership_id=membership_id,
            actor_role_snapshot=role_snapshot,
            permission_snapshot_json=permission_snapshot,
            subject_type=subject_type,
            subject_id=subject_id,
            secondary_subject_type=secondary_type,
            secondary_subject_id=secondary_id,
            request_id=trace.request_id,
            correlation_id=trace.correlation_id,
            causation_id=trace.causation_id,
            operation_id=trace.operation_id,
            agent_job_id=trace.agent_job_id,
            event_key=trace.event_key,
            before_sha256=before_sha256,
            after_sha256=after_sha256,
            evidence_hashes_json=list(evidence_hashes),
            metadata_sanitized_json=dict(metadata),
            previous_event_hash=previous_hash,
            event_hash=event_hash,
            audit_format_version=AUDIT_FORMAT_VERSION,
            occurred_at=occurred_at,
        )
        self.db.add(row)
        self.db.flush()
        head.head_sequence = sequence
        head.head_hash = event_hash
        head.updated_at = datetime.now(timezone.utc)
        self.db.flush()
        receipt = self._receipt(row)
        if allow_checkpoint and definition.event_type not in {
            "AUDIT_CHAIN_GENESIS", "LEGACY_HISTORY_IMPORTED", "CHECKPOINT_CREATED"
        }:
            self._maybe_checkpoint_locked(head, row, tenant)
        return receipt

    def _checkpoint_payload(
        self,
        *,
        checkpoint_id: str,
        chain_id: str,
        through_sequence: int,
        head_event_hash: str,
        previous_checkpoint_hash: str,
        created_at: datetime,
    ) -> dict[str, Any]:
        return {
            "checkpoint_format_version": CHECKPOINT_FORMAT_VERSION,
            "checkpoint_id": canonical_uuid(checkpoint_id),
            "chain_id": canonical_uuid(chain_id),
            "through_sequence": str(through_sequence),
            "head_event_hash": head_event_hash,
            "previous_checkpoint_hash": previous_checkpoint_hash,
            "created_at": rfc3339_microseconds(created_at),
        }

    def _maybe_checkpoint_locked(
        self,
        head: AuditChainHeadRecord,
        event: AuditEventRecord,
        tenant: AuditTenantScope,
    ) -> AuditCheckpointRecord | None:
        last = self.db.scalar(
            select(AuditCheckpointRecord)
            .where(AuditCheckpointRecord.chain_id == head.chain_id)
            .order_by(AuditCheckpointRecord.through_sequence.desc())
            .limit(1)
        )
        due_count = event.sequence % 10_000 == 0
        due_day = last is None or _storage_utc(last.created_at).date() < _storage_utc(event.occurred_at).date()
        if not (due_count or due_day):
            return None
        checkpoint_id = str(uuid4())
        created_at = datetime.now(timezone.utc)
        previous_checkpoint_hash = last.checkpoint_hash if last is not None else ZERO_HASH
        payload = self._checkpoint_payload(
            checkpoint_id=checkpoint_id,
            chain_id=head.chain_id,
            through_sequence=event.sequence,
            head_event_hash=event.event_hash,
            previous_checkpoint_hash=previous_checkpoint_hash,
            created_at=created_at,
        )
        checkpoint_hash = sha256_hex(jcs_bytes(payload))
        row = AuditCheckpointRecord(
            id=checkpoint_id,
            chain_id=head.chain_id,
            through_sequence=event.sequence,
            head_event_hash=event.event_hash,
            previous_checkpoint_hash=previous_checkpoint_hash,
            checkpoint_hash=checkpoint_hash,
            checkpoint_format_version=CHECKPOINT_FORMAT_VERSION,
            created_at=created_at,
        )
        self.db.add(row)
        self.db.flush()
        definition = AUDIT_EVENT_REGISTRY["CHECKPOINT_CREATED"]
        self._insert_locked(
            head,
            definition=definition,
            actor=ActorContext(ActorKind.SYSTEM),
            tenant=tenant,
            subject=SubjectRef(SubjectType.AUDIT_CHECKPOINT, checkpoint_id),
            secondary_subject=SubjectRef(SubjectType.AUDIT_CHAIN, head.chain_id),
            outcome=AuditOutcome.SUCCESS,
            authorization_decision=AuthorizationDecision.NOT_APPLICABLE,
            trace=TraceContext(event_key=f"checkpoint:{checkpoint_id}"),
            metadata={
                "checkpoint_id": checkpoint_id,
                "checkpoint_hash": checkpoint_hash,
                "through_sequence": event.sequence,
            },
            evidence_hashes=(event.event_hash,),
            before_sha256=None,
            after_sha256=None,
            occurred_at=created_at,
            allow_checkpoint=False,
        )
        return row

    def chain_for_organisation(self, organisation_id: str) -> AuditChainHeadRecord:
        return self._chain(AuditTenantScope(organisation_id, None), lock=False)

    def system_chain(self) -> AuditChainHeadRecord:
        return self._chain(AuditTenantScope.system(), lock=False)

    def verify_chain(
        self,
        *,
        organisation_id: str | None = None,
        system: bool = False,
        from_sequence: int = 1,
        expected_previous_hash: str | None = None,
    ) -> VerificationResult:
        if system == (organisation_id is not None):
            raise ValueError("select exactly one audit chain scope")
        tenant = AuditTenantScope.system() if system else AuditTenantScope(organisation_id, None)
        head = self._chain(tenant, lock=False)
        if from_sequence < 1:
            raise ValueError("from_sequence must be >=1")
        rows = list(self.db.scalars(
            select(AuditEventRecord)
            .where(AuditEventRecord.chain_id == head.chain_id, AuditEventRecord.sequence >= from_sequence)
            .order_by(AuditEventRecord.sequence)
        ))
        previous = expected_previous_hash
        if from_sequence == 1:
            previous = ZERO_HASH
        elif previous is None:
            prior = self.db.scalar(select(AuditEventRecord).where(
                AuditEventRecord.chain_id == head.chain_id,
                AuditEventRecord.sequence == from_sequence - 1,
            ))
            if prior is None:
                return VerificationResult(
                    "INVALID", head.chain_id, from_sequence, from_sequence, 0,
                    head.head_sequence, head.head_hash, from_sequence, "missing previous sequence", "UNKNOWN",
                )
            previous = prior.event_hash
        expected_sequence = from_sequence
        checked = 0
        for row in rows:
            if row.audit_format_version != AUDIT_FORMAT_VERSION:
                return VerificationResult("INVALID", head.chain_id, from_sequence, row.sequence, checked, head.head_sequence, head.head_hash, row.sequence, "unknown audit format", "UNKNOWN")
            if row.event_type not in AUDIT_EVENT_REGISTRY:
                return VerificationResult("INVALID", head.chain_id, from_sequence, row.sequence, checked, head.head_sequence, head.head_hash, row.sequence, "unknown event registry code", "UNKNOWN")
            if row.sequence != expected_sequence:
                return VerificationResult("INVALID", head.chain_id, from_sequence, row.sequence, checked, head.head_sequence, head.head_hash, expected_sequence, "sequence gap or reorder", "UNKNOWN")
            if row.previous_event_hash != previous:
                return VerificationResult("INVALID", head.chain_id, from_sequence, row.sequence, checked, head.head_sequence, head.head_hash, row.sequence, "previous hash mismatch", "UNKNOWN")
            semantic = self._row_semantic(row)
            payload = self._canonical_payload(
                semantic=semantic,
                chain_id=row.chain_id,
                sequence=row.sequence,
                event_id=row.event_id,
                occurred_at=row.occurred_at,
                previous_event_hash=row.previous_event_hash,
            )
            computed = sha256_hex(jcs_bytes(payload))
            if computed != row.event_hash:
                return VerificationResult("INVALID", head.chain_id, from_sequence, row.sequence, checked, head.head_sequence, head.head_hash, row.sequence, "event hash mismatch", "UNKNOWN")
            if row.sequence == 1 and (row.event_type != "AUDIT_CHAIN_GENESIS" or row.previous_event_hash != ZERO_HASH):
                return VerificationResult("INVALID", head.chain_id, from_sequence, row.sequence, checked, head.head_sequence, head.head_hash, row.sequence, "invalid genesis", "UNKNOWN")
            previous = row.event_hash
            expected_sequence += 1
            checked += 1
        if rows and rows[-1].sequence == head.head_sequence and rows[-1].event_hash != head.head_hash:
            return VerificationResult("INVALID", head.chain_id, from_sequence, rows[-1].sequence, checked, head.head_sequence, head.head_hash, rows[-1].sequence, "chain head mismatch", "UNKNOWN")
        if from_sequence == 1 and head.head_sequence and (not rows or rows[-1].sequence != head.head_sequence):
            return VerificationResult("INVALID", head.chain_id, from_sequence, rows[-1].sequence if rows else 0, checked, head.head_sequence, head.head_hash, head.head_sequence, "tail sequence mismatch", "UNKNOWN")
        checkpoint_status = self._verify_checkpoints(head.chain_id)
        if checkpoint_status != "VALID":
            return VerificationResult("INVALID", head.chain_id, from_sequence, rows[-1].sequence if rows else 0, checked, head.head_sequence, head.head_hash, None, checkpoint_status, "INVALID")
        return VerificationResult(
            "VALID", head.chain_id, from_sequence,
            rows[-1].sequence if rows else from_sequence - 1,
            checked, head.head_sequence, head.head_hash, checkpoint_status="VALID",
        )

    def _verify_checkpoints(self, chain_id: str) -> str:
        previous = ZERO_HASH
        for row in self.db.scalars(
            select(AuditCheckpointRecord)
            .where(AuditCheckpointRecord.chain_id == chain_id)
            .order_by(AuditCheckpointRecord.through_sequence)
        ):
            if row.checkpoint_format_version != CHECKPOINT_FORMAT_VERSION:
                return "unknown checkpoint format"
            event = self.db.scalar(select(AuditEventRecord).where(
                AuditEventRecord.chain_id == chain_id,
                AuditEventRecord.sequence == row.through_sequence,
            ))
            if event is None or event.event_hash != row.head_event_hash:
                return "checkpoint head event mismatch"
            if row.previous_checkpoint_hash != previous:
                return "checkpoint previous hash mismatch"
            payload = self._checkpoint_payload(
                checkpoint_id=row.id,
                chain_id=row.chain_id,
                through_sequence=row.through_sequence,
                head_event_hash=row.head_event_hash,
                previous_checkpoint_hash=row.previous_checkpoint_hash,
                created_at=_storage_utc(row.created_at),
            )
            computed = sha256_hex(jcs_bytes(payload))
            if computed != row.checkpoint_hash:
                return "checkpoint hash mismatch"
            previous = row.checkpoint_hash
        return "VALID"


class LegacyHistorySealer:
    """Seal a deterministic manifest of pre-M13 rows without pretending they were historically chained."""

    CANDIDATE_SOURCES = (
        "audit_log", "write_audit", "report_job_events", "suz_reconciliation_events",
        "wb_events", "wb_paid_evidence", "ozon_events", "ozon_paid_evidence",
        "imports", "events", "checks", "control_runs", "agent_jobs",
        "document_lifecycle_ledger", "turnover_operation_ledger", "aggregation_operation_ledger",
    )
    TIME_CANDIDATES = (
        "occurred_at", "created_at", "updated_at", "imported_at", "checked_at",
        "requested_at", "recorded_at",
    )

    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

    def _entry(self, table_name: str, *, organisation_id: str | None) -> dict[str, Any] | None:
        inspector = inspect(self.db.bind)
        if table_name not in inspector.get_table_names():
            return None
        metadata = MetaData()
        table = Table(table_name, metadata, autoload_with=self.db.bind)
        columns = table.c
        org_scoped = "organisation_id" in columns
        if organisation_id is not None and not org_scoped:
            return None
        pk_cols = list(table.primary_key.columns)
        if not pk_cols:
            return None
        time_col = next((columns[name] for name in self.TIME_CANDIDATES if name in columns), None)
        selected = [*pk_cols]
        if time_col is not None:
            selected.append(time_col)
        stmt = select(*selected)
        if organisation_id is not None:
            stmt = stmt.where(columns.organisation_id == organisation_id)
        stmt = stmt.order_by(*pk_cols)
        digest = hashlib.sha256()
        count = 0
        first_key = last_key = None
        earliest = latest = None
        for row in self.db.execute(stmt):
            values = list(row)
            key_values = values[:len(pk_cols)]
            key = "|".join("" if value is None else str(value) for value in key_values)
            timestamp = values[-1] if time_col is not None else None
            line = {"key": key, "timestamp": rfc3339_microseconds(timestamp) if isinstance(timestamp, datetime) else None}
            digest.update(jcs_bytes(line))
            digest.update(b"\n")
            count += 1
            first_key = first_key or key
            last_key = key
            if isinstance(timestamp, datetime):
                normalized = _utc(timestamp)
                earliest = normalized if earliest is None or normalized < earliest else earliest
                latest = normalized if latest is None or normalized > latest else latest
        return {
            "source": table_name,
            "domain": table_name.split("_", 1)[0].upper(),
            "count": count,
            "range": {"first": first_key, "last": last_key},
            "earliest": rfc3339_microseconds(earliest) if earliest else None,
            "latest": rfc3339_microseconds(latest) if latest else None,
            "aggregate_sha256": digest.hexdigest(),
        }

    def manifest(self, *, organisation_id: str | None) -> list[dict[str, Any]]:
        values = []
        for source in self.CANDIDATE_SOURCES:
            entry = self._entry(source, organisation_id=organisation_id)
            if entry is not None:
                values.append(entry)
        return values

    @staticmethod
    def _cutoff(manifest: list[dict[str, Any]]) -> str | None:
        values = [entry["latest"] for entry in manifest if entry.get("latest")]
        return max(values) if values else None

    def _seal_scope(self, tenant: AuditTenantScope) -> AuditReceipt:
        head = self.audit._chain(tenant, lock=True)
        key = "legacy-history:v1"
        existing = self.db.scalar(select(AuditEventRecord).where(
            AuditEventRecord.chain_id == head.chain_id,
            AuditEventRecord.event_key == key,
        ))
        if existing is not None:
            return self.audit._receipt(existing, converged=True)
        manifest = self.manifest(organisation_id=tenant.organisation_id)
        return self.audit.append(
            event_type="LEGACY_HISTORY_IMPORTED",
            actor=ActorContext(ActorKind.SYSTEM),
            tenant=tenant,
            subject=SubjectRef(SubjectType.AUDIT_CHAIN, head.chain_id),
            outcome=AuditOutcome.SUCCESS,
            trace=TraceContext(event_key=key),
            metadata={
                "manifest": manifest,
                "semantics": "PRE_M13_UNSEALED_HISTORY",
                "cutoff": self._cutoff(manifest),
            },
            _allow_checkpoint=False,
        )

    def seal_all(self) -> list[AuditReceipt]:
        receipts = [self._seal_scope(AuditTenantScope.system())]
        for org_id in self.db.scalars(select(OrganisationRecord.id).order_by(OrganisationRecord.id)):
            receipts.append(self._seal_scope(AuditTenantScope(str(org_id), None)))
        self.db.flush()
        return receipts
