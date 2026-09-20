from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import secrets

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from wbcz.control_engine import validate_owner_inn
from wbcz_web.auth import hash_password, token_hash
from wbcz_web.models import SessionRecord, User
from wbcz_web.models.security import (
    BootstrapRecord,
    InvitationRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantRecord,
)


class Role(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


class Permission(StrEnum):
    IMPORTS_READ = "imports:read"
    IMPORTS_CREATE = "imports:create"
    CONTROL_RUN = "control:run"
    CIS_READ = "cis:read"
    REFERENCE_READ = "reference:read"
    DOCUMENTS_READ = "documents:read"
    DOCUMENTS_WRITE = "documents:write"
    TURNOVER_READ = "turnover:read"
    TURNOVER_WRITE = "turnover:write"
    AGGREGATION_READ = "aggregation:read"
    AGGREGATION_WRITE = "aggregation:write"
    EDO_READ = "edo:read"
    EDO_WRITE = "edo:write"
    SUZ_READ = "suz:read"
    SUZ_MANAGE = "suz:manage"
    WB_READ = "wb:read"
    OZON_READ = "ozon:read"
    REPORTS_CREATE = "reports:create"
    REPORTS_READ = "reports:read"
    REPORTS_DOWNLOAD = "reports:download"
    REPORTS_DOWNLOAD_SENSITIVE = "reports:download_sensitive"
    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_MANAGE = "integrations:manage"
    MEMBERS_READ = "members:read"
    MEMBERS_MANAGE = "members:manage"
    ROLES_MANAGE = "roles:manage"
    ORGANISATION_MANAGE = "organisation:manage"
    AUDIT_READ = "audit:read"
    PRINT_READ = "print:read"
    PRINT_EXECUTE = "print:execute"
    PRINT_TEMPLATES_MANAGE = "print:templates_manage"


PERMISSION_REGISTRY: dict[Permission, str] = {
    Permission.IMPORTS_READ: "Read tenant-scoped imports and WB events",
    Permission.IMPORTS_CREATE: "Create tenant-scoped imports",
    Permission.CONTROL_RUN: "Run marking control and previews",
    Permission.CIS_READ: "Read CIS inventory",
    Permission.REFERENCE_READ: "Read reference/product data",
    Permission.DOCUMENTS_READ: "Read document lifecycle data",
    Permission.DOCUMENTS_WRITE: "Stage document/write operations subject to domain safety and feature gates",
    Permission.TURNOVER_READ: "Read turnover operations",
    Permission.TURNOVER_WRITE: "Request turnover writes subject to domain safety gates",
    Permission.AGGREGATION_READ: "Read aggregation operations",
    Permission.AGGREGATION_WRITE: "Request aggregation writes subject to domain safety gates",
    Permission.EDO_READ: "Read EDO data",
    Permission.EDO_WRITE: "Future EDO write permission; feature gate remains authoritative",
    Permission.SUZ_READ: "Read SUZ data",
    Permission.SUZ_MANAGE: "Future SUZ management permission; feature gate remains authoritative",
    Permission.WB_READ: "Read WB data",
    Permission.OZON_READ: "Read Ozon data",
    Permission.REPORTS_CREATE: "Create reports",
    Permission.REPORTS_READ: "Read report metadata",
    Permission.REPORTS_DOWNLOAD: "Download non-sensitive report artifacts",
    Permission.REPORTS_DOWNLOAD_SENSITIVE: "Download marking-sensitive report artifacts",
    Permission.INTEGRATIONS_READ: "Read integration metadata without plaintext secrets",
    Permission.INTEGRATIONS_MANAGE: "Manage integration configuration without secret disclosure",
    Permission.MEMBERS_READ: "Read organisation membership",
    Permission.MEMBERS_MANAGE: "Invite, disable, or remove organisation members",
    Permission.ROLES_MANAGE: "Change organisation roles subject to escalation/last-owner rules",
    Permission.ORGANISATION_MANAGE: "Manage organisation lifecycle and ownership-level settings",
    Permission.AUDIT_READ: "Read organisation-scoped audit data",
    Permission.PRINT_READ: "Read local printability, templates, jobs and print history without plaintext FULL KM",
    Permission.PRINT_EXECUTE: "Create local print and reprint jobs subject to printability and feature gates",
    Permission.PRINT_TEMPLATES_MANAGE: "Create immutable template versions and archive print templates",
}

_READ = {
    Permission.IMPORTS_READ, Permission.CIS_READ, Permission.REFERENCE_READ,
    Permission.DOCUMENTS_READ, Permission.TURNOVER_READ, Permission.AGGREGATION_READ,
    Permission.EDO_READ, Permission.SUZ_READ, Permission.WB_READ, Permission.OZON_READ,
    Permission.REPORTS_READ, Permission.REPORTS_DOWNLOAD, Permission.INTEGRATIONS_READ,
    Permission.MEMBERS_READ, Permission.PRINT_READ,
}
_OPERATOR = _READ | {
    Permission.IMPORTS_CREATE, Permission.CONTROL_RUN, Permission.TURNOVER_WRITE,
    Permission.DOCUMENTS_WRITE, Permission.AGGREGATION_WRITE, Permission.REPORTS_CREATE,
    Permission.REPORTS_DOWNLOAD_SENSITIVE, Permission.PRINT_EXECUTE,
}
_ADMIN = _OPERATOR | {
    Permission.INTEGRATIONS_MANAGE, Permission.MEMBERS_MANAGE, Permission.ROLES_MANAGE,
    Permission.AUDIT_READ, Permission.PRINT_TEMPLATES_MANAGE,
}
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(_READ),
    Role.OPERATOR: frozenset(_OPERATOR),
    Role.ADMIN: frozenset(_ADMIN),
    Role.OWNER: frozenset(set(Permission)),
}


class AuthorizationError(PermissionError):
    pass


class ScopeRequired(AuthorizationError):
    pass


@dataclass(frozen=True, slots=True)
class ActiveScope:
    user_id: int
    organisation_id: str
    participant_id: str | None
    participant_inn: str | None
    role: Role
    permissions: frozenset[Permission]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalise_username(value: str) -> str:
    return value.strip().casefold()


def _invitation_token() -> str:
    return secrets.token_urlsafe(48)


class AuthorizationService:
    """Central server-side authorization and tenant-scope resolver."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def membership(self, user_id: int, organisation_id: str, *, lock: bool = False) -> MembershipRecord | None:
        stmt = select(MembershipRecord).where(
            MembershipRecord.user_id == user_id,
            MembershipRecord.organisation_id == organisation_id,
            MembershipRecord.is_active.is_(True),
        )
        if lock:
            stmt = stmt.with_for_update()
        return self.db.scalar(stmt)

    def participant(self, organisation_id: str, participant_id: str | None) -> ParticipantRecord | None:
        if not participant_id:
            return None
        return self.db.scalar(select(ParticipantRecord).where(
            ParticipantRecord.id == participant_id,
            ParticipantRecord.organisation_id == organisation_id,
            ParticipantRecord.is_active.is_(True),
        ))

    def available_memberships(self, user_id: int) -> list[MembershipRecord]:
        return list(self.db.scalars(
            select(MembershipRecord)
            .join(OrganisationRecord, OrganisationRecord.id == MembershipRecord.organisation_id)
            .where(
                MembershipRecord.user_id == user_id,
                MembershipRecord.is_active.is_(True),
                OrganisationRecord.is_active.is_(True),
            )
            .order_by(MembershipRecord.created_at, MembershipRecord.id)
        ))

    def participants(self, organisation_id: str, *, verified_only: bool = False) -> list[ParticipantRecord]:
        stmt = select(ParticipantRecord).where(
            ParticipantRecord.organisation_id == organisation_id,
            ParticipantRecord.is_active.is_(True),
        )
        if verified_only:
            stmt = stmt.where(ParticipantRecord.verification_state == "VERIFIED")
        return list(self.db.scalars(stmt.order_by(ParticipantRecord.created_at, ParticipantRecord.id)))

    def resolve_session_scope(self, user: User, session: SessionRecord, *, require_participant: bool = False) -> ActiveScope:
        memberships = self.available_memberships(user.id)
        if not memberships:
            raise ScopeRequired("active organisation scope is required")
        membership: MembershipRecord | None = None
        if session.active_organisation_id:
            membership = next((m for m in memberships if m.organisation_id == session.active_organisation_id), None)
            if membership is None:
                session.active_organisation_id = None
                session.active_participant_id = None
                self.db.flush()
                raise ScopeRequired("active organisation scope is no longer authorised")
        elif len(memberships) == 1:
            membership = memberships[0]
            session.active_organisation_id = membership.organisation_id
        else:
            raise ScopeRequired("select an active organisation")

        try:
            role = Role(membership.role)
        except ValueError as exc:
            raise AuthorizationError("unknown role") from exc

        participant = self.participant(membership.organisation_id, session.active_participant_id)
        if session.active_participant_id and (
            participant is None or participant.verification_state != "VERIFIED"
        ):
            session.active_participant_id = None
            participant = None
            self.db.flush()
            if require_participant:
                raise ScopeRequired("active participant scope is no longer authorised")
        if participant is None:
            candidates = self.participants(membership.organisation_id, verified_only=True)
            if len(candidates) == 1:
                participant = candidates[0]
                session.active_participant_id = participant.id
        if require_participant and participant is None:
            raise ScopeRequired("select a verified active participant")

        self.db.info["tenant_scope"] = {
            "user_id": user.id,
            "organisation_id": membership.organisation_id,
            "participant_id": participant.id if participant else None,
            "participant_inn": participant.inn if participant else None,
            "role": role.value,
        }
        return ActiveScope(
            user_id=user.id,
            organisation_id=membership.organisation_id,
            participant_id=participant.id if participant else None,
            participant_inn=participant.inn if participant else None,
            role=role,
            permissions=ROLE_PERMISSIONS[role],
        )

    def set_active_scope(
        self,
        user: User,
        session: SessionRecord,
        *,
        organisation_id: str,
        participant_id: str | None,
    ) -> ActiveScope:
        membership = self.membership(user.id, organisation_id)
        organisation = self.db.get(OrganisationRecord, organisation_id)
        if membership is None or organisation is None or not organisation.is_active:
            raise AuthorizationError("scope not available")
        participant = None
        if participant_id is not None:
            participant = self.participant(organisation_id, participant_id)
            if participant is None or participant.verification_state != "VERIFIED":
                raise AuthorizationError("scope not available")
        session.active_organisation_id = organisation_id
        session.active_participant_id = participant.id if participant else None
        self.db.flush()
        return self.resolve_session_scope(user, session, require_participant=False)

    def authorize(
        self,
        *,
        user_id: int,
        organisation_id: str,
        participant_id: str | None,
        permission: Permission,
        object_type: str | None = None,
        object_id: str | int | None = None,
    ) -> ActiveScope:
        user=self.db.get(User,user_id)
        if user is None or not user.is_active or user.account_state!="ACTIVE":
            raise AuthorizationError("permission denied")
        membership=self.membership(user_id,organisation_id)
        organisation=self.db.get(OrganisationRecord,organisation_id)
        if membership is None or organisation is None or not organisation.is_active:
            raise AuthorizationError("permission denied")
        try:role=Role(membership.role)
        except ValueError as exc:raise AuthorizationError("permission denied") from exc
        participant=self.participant(organisation_id,participant_id) if participant_id else None
        if participant_id is not None and (participant is None or participant.verification_state!="VERIFIED"):
            raise AuthorizationError("permission denied")
        scope=ActiveScope(
            user_id=user_id,organisation_id=organisation_id,
            participant_id=participant.id if participant else None,
            participant_inn=participant.inn if participant else None,
            role=role,permissions=ROLE_PERMISSIONS[role],
        )
        self.require(scope,permission)
        if object_type is not None:
            if object_id is None:raise AuthorizationError("object id required")
            self.authorize_object(scope,permission,object_type,object_id)
        return scope

    @staticmethod
    def require(scope: ActiveScope, permission: Permission) -> None:
        if permission not in scope.permissions:
            raise AuthorizationError("permission denied")

    @staticmethod
    def require_object_scope(
        scope: ActiveScope,
        *,
        organisation_id: str | None,
        participant_id: str | None = None,
        permission: Permission,
    ) -> None:
        AuthorizationService.require(scope, permission)
        if not organisation_id or organisation_id != scope.organisation_id:
            raise KeyError("object not found")
        if participant_id is not None and participant_id != scope.participant_id:
            raise KeyError("object not found")

    def object_scope(self, object_type: str, object_id: str | int) -> tuple[str, str | None]:
        from wbcz_web.models import (
            AgentJobRecord, AggregationOperationLedgerRecord, ControlRun, DocumentLifecycleLedgerRecord,
            EdoLiteLedgerRecord, EventRecord, ImportRecord, MembershipRecord as MembershipModel,
            OzonConnectionRecord, OzonPostingRecord, ParticipantRecord as ParticipantModel,
            PreviewRecord, ReportArtifactRecord, ReportJobRecord, SuzConnectionRecord, SuzOrderRecord,
            TurnoverOperationLedgerRecord, WbConnectionRecord, WbOrderRecord, WriteOperationRecord,
        )
        direct = {
            "import": (ImportRecord, ImportRecord.id),
            "event": (EventRecord, EventRecord.event_id),
            "control_run": (ControlRun, ControlRun.id),
            "preview": (PreviewRecord, PreviewRecord.id),
            "agent_job": (AgentJobRecord, AgentJobRecord.job_id),
            "write_operation": (WriteOperationRecord, WriteOperationRecord.operation_id),
            "document_lifecycle": (DocumentLifecycleLedgerRecord, DocumentLifecycleLedgerRecord.operation_id),
            "turnover_operation": (TurnoverOperationLedgerRecord, TurnoverOperationLedgerRecord.operation_id),
            "aggregation_operation": (AggregationOperationLedgerRecord, AggregationOperationLedgerRecord.operation_id),
            "edo_lite": (EdoLiteLedgerRecord, EdoLiteLedgerRecord.id),
            "report_job": (ReportJobRecord, ReportJobRecord.id),
        }
        if object_type in direct:
            model,key=direct[object_type]
            row=self.db.scalar(select(model).where(key==object_id))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="report_artifact":
            row=self.db.scalar(
                select(ReportJobRecord)
                .join(ReportArtifactRecord,ReportArtifactRecord.report_job_id==ReportJobRecord.id)
                .where(ReportArtifactRecord.artifact_id==object_id)
            )
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="wb_connection":
            row=self.db.get(WbConnectionRecord,int(object_id))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="wb_order":
            row=self.db.scalar(select(WbConnectionRecord).join(WbOrderRecord,WbOrderRecord.connection_id==WbConnectionRecord.id).where(WbOrderRecord.id==int(object_id)))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="ozon_connection":
            row=self.db.get(OzonConnectionRecord,int(object_id))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="ozon_posting":
            row=self.db.scalar(select(OzonConnectionRecord).join(OzonPostingRecord,OzonPostingRecord.connection_id==OzonConnectionRecord.id).where(OzonPostingRecord.id==int(object_id)))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="suz_connection":
            row=self.db.get(SuzConnectionRecord,int(object_id))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="suz_order":
            order=self.db.get(SuzOrderRecord,int(object_id))
            if order is None:raise KeyError("object not found")
            row=self.db.get(SuzConnectionRecord,order.connection_id)
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.participant_id
        if object_type=="membership":
            row=self.db.get(MembershipModel,str(object_id))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,None
        if object_type=="participant":
            row=self.db.get(ParticipantModel,str(object_id))
            if row is None:raise KeyError("object not found")
            return row.organisation_id,row.id
        if object_type=="organisation":
            row=self.db.get(OrganisationRecord,str(object_id))
            if row is None:raise KeyError("object not found")
            return row.id,None
        raise KeyError("object type not registered")

    def authorize_object(self, scope: ActiveScope, permission: Permission, object_type: str, object_id: str | int) -> None:
        self.require(scope,permission)
        organisation_id,participant_id=self.object_scope(object_type,object_id)
        if organisation_id!=scope.organisation_id:
            raise KeyError("object not found")
        if participant_id is not None and participant_id!=scope.participant_id:
            raise KeyError("object not found")
        if organisation_id is None:
            raise KeyError("object not found")

    def list_scopes(self, user_id: int) -> list[dict]:
        result: list[dict] = []
        for membership in self.available_memberships(user_id):
            org = self.db.get(OrganisationRecord, membership.organisation_id)
            result.append({
                "organisation_id": membership.organisation_id,
                "organisation_name": org.name if org else "",
                "role": membership.role,
                "participants": [
                    {
                        "id": p.id,
                        "participant_id": p.id,
                        "inn": p.inn,
                        "display_name": p.display_name,
                        "verification_state": p.verification_state,
                    }
                    for p in self.participants(membership.organisation_id)
                ],
            })
        return result


class MembershipService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.authz = AuthorizationService(db)

    def _owner_count(self, organisation_id: str) -> int:
        return int(self.db.scalar(
            select(func.count()).select_from(MembershipRecord).where(
                MembershipRecord.organisation_id == organisation_id,
                MembershipRecord.role == Role.OWNER.value,
                MembershipRecord.is_active.is_(True),
            )
        ) or 0)

    def change_role(self, actor: ActiveScope, membership_id: str, role: Role) -> MembershipRecord:
        AuthorizationService.require(actor, Permission.ROLES_MANAGE)
        self.db.scalar(select(OrganisationRecord).where(OrganisationRecord.id == actor.organisation_id).with_for_update())
        row = self.db.scalar(select(MembershipRecord).where(
            MembershipRecord.id == membership_id,
            MembershipRecord.organisation_id == actor.organisation_id,
        ).with_for_update())
        if row is None:
            raise KeyError("membership not found")
        if role is Role.OWNER and actor.role is not Role.OWNER:
            raise AuthorizationError("only OWNER may grant OWNER")
        if actor.role is Role.ADMIN and (
            row.role in {Role.OWNER.value, Role.ADMIN.value}
            or role in {Role.OWNER, Role.ADMIN}
        ):
            raise AuthorizationError("ADMIN may manage only OPERATOR/VIEWER roles")
        if row.role == Role.OWNER.value and role is not Role.OWNER and self._owner_count(actor.organisation_id) <= 1:
            raise AuthorizationError("last OWNER cannot be demoted")
        row.role = role.value
        for session in self.db.scalars(select(SessionRecord).where(
            SessionRecord.user_id == row.user_id,
            SessionRecord.active_organisation_id == actor.organisation_id,
            SessionRecord.revoked_at.is_(None),
        )):
            session.revoked_at = _now()
        self.db.flush()
        return row

    def remove(self, actor: ActiveScope, membership_id: str) -> None:
        AuthorizationService.require(actor, Permission.MEMBERS_MANAGE)
        self.db.scalar(select(OrganisationRecord).where(OrganisationRecord.id == actor.organisation_id).with_for_update())
        row = self.db.scalar(select(MembershipRecord).where(
            MembershipRecord.id == membership_id,
            MembershipRecord.organisation_id == actor.organisation_id,
        ).with_for_update())
        if row is None:
            raise KeyError("membership not found")
        if actor.role is Role.ADMIN and row.role in {Role.OWNER.value, Role.ADMIN.value}:
            raise AuthorizationError("ADMIN may remove only OPERATOR/VIEWER memberships")
        if row.role == Role.OWNER.value and self._owner_count(actor.organisation_id) <= 1:
            raise AuthorizationError("last OWNER cannot be removed")
        row.is_active = False
        for session in self.db.scalars(select(SessionRecord).where(
            SessionRecord.user_id == row.user_id,
            SessionRecord.active_organisation_id == actor.organisation_id,
            SessionRecord.revoked_at.is_(None),
        )):
            session.revoked_at = _now()
        self.db.flush()

    def create_invitation(
        self,
        actor: ActiveScope,
        *,
        invitee_username: str | None = None,
        invited_user_id: int | None = None,
        invited_email_normalized: str | None = None,
        role: Role,
        participant_id: str | None,
        expires_at: datetime,
    ) -> tuple[InvitationRecord, str]:
        AuthorizationService.require(actor, Permission.MEMBERS_MANAGE)
        if role is Role.OWNER and actor.role is not Role.OWNER:
            raise AuthorizationError("only OWNER may invite OWNER")
        if actor.role is Role.ADMIN and role not in {Role.OPERATOR, Role.VIEWER}:
            raise AuthorizationError("ADMIN may invite only OPERATOR/VIEWER")
        if participant_id is not None:
            participant = self.authz.participant(actor.organisation_id, participant_id)
            if participant is None or participant.verification_state != "VERIFIED":
                raise AuthorizationError("participant scope unavailable")
        username = _normalise_username(invitee_username or "") or None
        email = (invited_email_normalized or "").strip().casefold() or None
        if invited_user_id is not None and self.db.get(User, invited_user_id) is None:
            raise AuthorizationError("invited user not found")
        if username is None and invited_user_id is None and email is None:
            raise ValueError("invitation must be bound to an intended identity")
        raw = _invitation_token()
        row = InvitationRecord(
            organisation_id=actor.organisation_id,
            participant_id=participant_id,
            token_hash=token_hash(raw),
            invitee_username=username,
            invited_user_id=invited_user_id,
            invited_email_normalized=email,
            role=role.value,
            state="PENDING",
            invited_by_user_id=actor.user_id,
            expires_at=expires_at.astimezone(timezone.utc),
        )
        self.db.add(row)
        self.db.flush()
        return row, raw

    def revoke_invitation(self, actor: ActiveScope, invitation_id: str) -> None:
        AuthorizationService.require(actor, Permission.MEMBERS_MANAGE)
        row = self.db.scalar(select(InvitationRecord).where(
            InvitationRecord.id == invitation_id,
            InvitationRecord.organisation_id == actor.organisation_id,
        ).with_for_update())
        if row is None:
            raise KeyError("invitation not found")
        if row.state != "PENDING":
            raise AuthorizationError("invitation is not revocable")
        if actor.role is Role.ADMIN and row.role in {Role.OWNER.value, Role.ADMIN.value}:
            raise AuthorizationError("ADMIN cannot revoke elevated invitation")
        row.state = "REVOKED"
        row.revoked_at = _now()
        self.db.flush()

    def accept_invitation(self, user: User, raw_token: str) -> MembershipRecord:
        row = self.db.scalar(select(InvitationRecord).where(
            InvitationRecord.token_hash == token_hash(raw_token),
        ).with_for_update())
        now = _now()
        if row is None or row.state != "PENDING" or row.revoked_at is not None:
            raise AuthorizationError("invitation is invalid")
        self.db.scalar(select(OrganisationRecord).where(
            OrganisationRecord.id == row.organisation_id
        ).with_for_update())
        if row.expires_at <= now:
            row.state = "EXPIRED"
            self.db.flush()
            raise AuthorizationError("invitation is invalid")
        identity_bound = False
        if row.invitee_username is not None:
            identity_bound = True
            if _normalise_username(user.username) != _normalise_username(row.invitee_username):
                raise AuthorizationError("invitation is invalid")
        if row.invited_user_id is not None:
            identity_bound = True
            if user.id != row.invited_user_id:
                raise AuthorizationError("invitation is invalid")
        if row.invited_email_normalized is not None:
            identity_bound = True
            if (
                user.email_verified_at is None
                or not user.email_normalized
                or user.email_normalized.casefold() != row.invited_email_normalized.casefold()
            ):
                raise AuthorizationError("invitation is invalid")
        if not identity_bound:
            raise AuthorizationError("invitation is invalid")
        inviter = self.authz.membership(row.invited_by_user_id, row.organisation_id, lock=True)
        if inviter is None:
            raise AuthorizationError("invitation is invalid")
        try:
            inviter_role = Role(inviter.role)
            invite_role = Role(row.role)
        except ValueError as exc:
            raise AuthorizationError("invitation is invalid") from exc
        if inviter_role is Role.ADMIN and invite_role not in {Role.OPERATOR, Role.VIEWER}:
            raise AuthorizationError("invitation is invalid")
        if inviter_role not in {Role.OWNER, Role.ADMIN}:
            raise AuthorizationError("invitation is invalid")
        if row.participant_id is not None:
            participant = self.authz.participant(row.organisation_id, row.participant_id)
            if participant is None or participant.verification_state != "VERIFIED":
                raise AuthorizationError("invitation is invalid")
        existing = self.db.scalar(select(MembershipRecord).where(
            MembershipRecord.user_id == user.id,
            MembershipRecord.organisation_id == row.organisation_id,
        ).with_for_update())
        if existing is not None and existing.is_active:
            raise AuthorizationError("invitation is invalid")
        if existing is None:
            existing = MembershipRecord(
                organisation_id=row.organisation_id,
                user_id=user.id,
                role=row.role,
                is_active=True,
                created_by_user_id=row.invited_by_user_id,
            )
            self.db.add(existing)
        else:
            existing.role = row.role
            existing.is_active = True
            existing.created_by_user_id = row.invited_by_user_id
        row.state = "ACCEPTED"
        row.accepted_by_user_id = user.id
        row.accepted_at = now
        self.db.flush()
        return existing


class BootstrapService:
    """One-time, transaction-locked conversion of the legacy single tenant."""

    _ROOT_TABLES = (
        "imports","events","control_runs","previews","audit_log","agent_jobs",
        "write_operations","document_lifecycle_ledger","turnover_operation_ledger",
        "aggregation_operation_ledger","edo_lite_ledger","edo_lite_annual_quota",
        "suz_connections","wb_connections","ozon_connections","report_jobs",
    )
    _BUSINESS_ROOTS = tuple(name for name in _ROOT_TABLES if name != "audit_log")
    _INN_EVIDENCE = (
        ("write_operations", "SELECT DISTINCT expected_inn AS inn FROM write_operations WHERE expected_inn IS NOT NULL"),
        ("agent_jobs", "SELECT DISTINCT payload_json ->> 'expected_inn' AS inn FROM agent_jobs WHERE payload_json ->> 'expected_inn' IS NOT NULL"),
        ("suz_connections", "SELECT DISTINCT participant_inn AS inn FROM suz_connections WHERE participant_inn IS NOT NULL"),
        ("wb_connections", "SELECT DISTINCT participant_inn AS inn FROM wb_connections WHERE participant_inn IS NOT NULL"),
        ("ozon_connections", "SELECT DISTINCT participant_inn AS inn FROM ozon_connections WHERE participant_inn IS NOT NULL"),
        ("report_jobs", "SELECT DISTINCT participant_inn AS inn FROM report_jobs WHERE participant_inn IS NOT NULL"),
    )

    def __init__(self, db: Session) -> None:
        self.db = db

    def _lock(self) -> None:
        self.db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 120120120013})

    def _historical_inns(self) -> set[str]:
        values:set[str]=set()
        for _,sql in self._INN_EVIDENCE:
            for value in self.db.scalars(text(sql)):
                if value:
                    candidate=str(value).strip()
                    validate_owner_inn(candidate)
                    values.add(candidate)
        return values

    def _business_row_count(self) -> int:
        total=0
        for table in self._BUSINESS_ROOTS:
            total+=int(self.db.scalar(text(f"SELECT count(*) FROM {table}")) or 0)
        return total

    def _preflight_tenant_columns(self) -> None:
        for table in self._ROOT_TABLES:
            ambiguous=int(self.db.scalar(text(
                f"SELECT count(*) FROM {table} WHERE "
                "(organisation_id IS NULL) <> (participant_id IS NULL)"
            )) or 0)
            assigned=int(self.db.scalar(text(
                f"SELECT count(*) FROM {table} WHERE organisation_id IS NOT NULL OR participant_id IS NOT NULL"
            )) or 0)
            if ambiguous or assigned:
                raise AuthorizationError(f"legacy tenant backfill is not pristine for {table}")

    def preflight(self, *, participant_inn:str) -> dict:
        validate_owner_inn(participant_inn)
        evidence=self._historical_inns()
        if len(evidence)>1:
            raise AuthorizationError("conflicting historical participant INNs")
        if evidence and evidence!={participant_inn}:
            raise AuthorizationError("historical participant INN does not match bootstrap INN")
        business_rows=self._business_row_count()
        if business_rows and not evidence:
            raise AuthorizationError("legacy business data has no deterministic participant INN evidence")
        self._preflight_tenant_columns()
        return {"historical_inns":sorted(evidence),"business_rows":business_rows}

    def _backfill_roots(self, organisation_id:str, participant_id:str) -> dict[str,int]:
        counts:dict[str,int]={}
        for table in self._ROOT_TABLES:
            result=self.db.execute(text(
                f"UPDATE {table} SET organisation_id=:org, participant_id=:participant "
                "WHERE organisation_id IS NULL AND participant_id IS NULL"
            ),{"org":organisation_id,"participant":participant_id})
            counts[table]=int(result.rowcount or 0)
        return counts

    def bootstrap(
        self,
        *,
        username: str,
        password: str,
        organisation_name: str,
        participant_inn: str,
        participant_name: str | None = None,
    ) -> tuple[User, OrganisationRecord, ParticipantRecord, MembershipRecord]:
        self._lock()
        if self.db.get(BootstrapRecord,1) is not None:
            raise AuthorizationError("security bootstrap already completed")
        if self.db.scalar(select(func.count()).select_from(MembershipRecord).where(
            MembershipRecord.role==Role.OWNER.value,MembershipRecord.is_active.is_(True)
        )):
            raise AuthorizationError("security bootstrap already completed")
        preflight=self.preflight(participant_inn=participant_inn)
        username=_normalise_username(username)
        if not username:raise ValueError("username is required")
        if self.db.scalar(select(ParticipantRecord).where(ParticipantRecord.inn==participant_inn)) is not None:
            raise AuthorizationError("participant INN is already claimed")

        user=self.db.scalar(select(User).where(func.lower(User.username)==username).with_for_update())
        if user is None:
            user=User(
                username=username,password_hash=hash_password(password),is_active=True,is_admin=False,
                account_state="ACTIVE",password_version=1,password_changed_at=_now(),password_must_change=False,
            )
            self.db.add(user);self.db.flush()
        else:
            if not user.is_active or user.account_state!="ACTIVE":raise AuthorizationError("bootstrap user is disabled")
            user.password_hash=hash_password(password)
            user.password_changed_at=_now()
            user.password_version=int(user.password_version or 0)+1
            user.password_must_change=False
            self.db.flush()

        org=OrganisationRecord(
            name=organisation_name.strip(),is_active=True,created_by_user_id=user.id
        )
        if not org.name:raise ValueError("organisation name is required")
        self.db.add(org);self.db.flush()
        participant=ParticipantRecord(
            organisation_id=org.id,inn=participant_inn,
            display_name=(participant_name or "").strip() or None,
            verification_state="VERIFIED",is_active=True,
        )
        self.db.add(participant);self.db.flush()

        users=list(self.db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.id).with_for_update()))
        owner_membership:MembershipRecord|None=None
        for legacy_user in users:
            role=Role.OWNER if legacy_user.id==user.id else Role.ADMIN if legacy_user.is_admin else Role.OPERATOR
            membership=MembershipRecord(
                organisation_id=org.id,user_id=legacy_user.id,role=role.value,is_active=True,
                created_by_user_id=user.id,
            )
            self.db.add(membership)
            if legacy_user.id==user.id:owner_membership=membership
        self.db.flush()
        if owner_membership is None:raise AuthorizationError("bootstrap OWNER membership was not created")

        backfilled=self._backfill_roots(org.id,participant.id)
        revoked=self.db.execute(text(
            "UPDATE sessions SET revoked_at=now() WHERE revoked_at IS NULL"
        )).rowcount or 0
        self.db.add(BootstrapRecord(
            id=1,organisation_id=org.id,owner_user_id=user.id,participant_id=participant.id,
            metadata_json={
                "method":"one_time_cli",
                "historical_inns":preflight["historical_inns"],
                "business_rows":preflight["business_rows"],
                "legacy_sessions_revoked":int(revoked),
                "backfilled_roots":backfilled,
            },
        ))
        self.db.info["tenant_scope"]={
            "user_id":user.id,"organisation_id":org.id,"participant_id":participant.id,
            "participant_inn":participant.inn,"role":Role.OWNER.value,
        }
        from wbcz_web.repositories import AuditRepository
        audit=AuditRepository(self.db)
        audit.append(
            "BOOTSTRAP_COMPLETED",user_id=user.id,entity_type="organisation",entity_id=org.id,
            metadata={"participant_id":participant.id,"legacy_sessions_revoked":int(revoked)},
        )
        for membership in self.db.scalars(select(MembershipRecord).where(
            MembershipRecord.organisation_id==org.id
        )):
            audit.append(
                "MEMBERSHIP_ADDED",user_id=user.id,entity_type="membership",entity_id=membership.id,
                metadata={"member_user_id":membership.user_id,"role":membership.role},
            )
        self.db.flush()
        return user,org,participant,owner_membership

