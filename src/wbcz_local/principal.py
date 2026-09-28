from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz_web.api.dependencies import AuthenticatedIdentity
from wbcz_web.config import WebConfig
from wbcz_web.models import User
from wbcz_web.models.security import (
    BootstrapRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantRecord,
)
from wbcz_web.services.authorization import ROLE_PERMISSIONS, Role

from .browser_session import is_well_formed_local_browser_session_id


class LocalOwnerResolutionError(PermissionError):
    """Local single-user identity is missing, ambiguous, or inconsistent."""


def resolve_local_owner_identity(
    db: Session,
    config: WebConfig,
    browser_session_id: str | None = None,
) -> AuthenticatedIdentity:
    """Resolve one bootstrapped OWNER and bind it to a verified local browser session."""
    if not is_well_formed_local_browser_session_id(browser_session_id):
        raise LocalOwnerResolutionError("local browser session is unavailable")
    rows = list(
        db.execute(
            select(User, MembershipRecord, OrganisationRecord)
            .join(MembershipRecord, MembershipRecord.user_id == User.id)
            .join(
                OrganisationRecord,
                OrganisationRecord.id == MembershipRecord.organisation_id,
            )
            .where(
                MembershipRecord.role == Role.OWNER.value,
                MembershipRecord.is_active.is_(True),
                User.is_active.is_(True),
                User.account_state == "ACTIVE",
                OrganisationRecord.is_active.is_(True),
            )
            .order_by(User.id, MembershipRecord.id)
        ).all()
    )
    if not rows:
        raise LocalOwnerResolutionError("local OWNER is missing")
    if len(rows) != 1:
        raise LocalOwnerResolutionError("local OWNER is ambiguous")

    user, membership, organisation = rows[0]
    bootstrap = db.get(BootstrapRecord, 1)
    if bootstrap is None:
        raise LocalOwnerResolutionError("local security bootstrap is missing")
    if (
        bootstrap.owner_user_id != user.id
        or bootstrap.organisation_id != organisation.id
        or membership.organisation_id != organisation.id
    ):
        raise LocalOwnerResolutionError("local OWNER does not match security bootstrap")

    participant = db.scalar(
        select(ParticipantRecord).where(
            ParticipantRecord.id == bootstrap.participant_id,
            ParticipantRecord.organisation_id == organisation.id,
            ParticipantRecord.is_active.is_(True),
            ParticipantRecord.verification_state == "VERIFIED",
        )
    )
    if participant is None:
        raise LocalOwnerResolutionError("bootstrapped local participant is unavailable")
    if participant.inn != config.own_inn:
        raise LocalOwnerResolutionError("bootstrapped local participant INN does not match runtime")

    db.info["tenant_scope"] = {
        "user_id": user.id,
        "organisation_id": organisation.id,
        "participant_id": participant.id,
        "participant_inn": participant.inn,
        "role": Role.OWNER.value,
    }
    return AuthenticatedIdentity(
        user_id=user.id,
        username=user.username,
        session_id=browser_session_id,
        organisation_id=organisation.id,
        participant_id=participant.id,
        participant_inn=participant.inn,
        role=Role.OWNER.value,
        permissions=frozenset(
            permission.value for permission in ROLE_PERMISSIONS[Role.OWNER]
        ),
        is_admin=False,
    )
