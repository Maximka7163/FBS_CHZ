from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from wbcz.control_engine import validate_owner_inn
from wbcz_web.models import OrganisationRecord, ParticipantClaimRecord, User


PUBLIC_REGISTRATION_ARCHITECTURE = True
PUBLIC_REGISTRATION_RUNTIME_ENABLED = False
PUBLIC_REGISTRATION_EXISTING_TENANT_JOIN_BY_INN = False
PUBLIC_REGISTRATION_REQUIRES_NEW_ORGANISATION = True


class PublicRegistrationDisabled(PermissionError):
    pass


RegistrationDisabled = PublicRegistrationDisabled


def normalize_email(value: str) -> str:
    normalized = value.strip().casefold()
    if not normalized or len(normalized) > 320 or "@" not in normalized:
        raise ValueError("email is invalid")
    return normalized


@dataclass(frozen=True, slots=True)
class PublicRegistrationPolicy:
    architecture_ready: bool = PUBLIC_REGISTRATION_ARCHITECTURE
    enabled: bool = PUBLIC_REGISTRATION_RUNTIME_ENABLED
    new_organisation_only: bool = True
    existing_tenant_join_requires_invitation: bool = True
    participant_claim_unlocks_existing_data: bool = False
    email_verification_available: bool = False
    password_recovery_available: bool = False
    anti_abuse_prerequisites_complete: bool = False


class ParticipantClaimService:
    """Durable future onboarding claim. Creating a claim never grants tenant access."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_pending(
        self,
        *,
        claimant_user_id: int,
        claimed_inn: str,
        target_organisation_id: str | None = None,
        evidence_refs: list | None = None,
    ) -> ParticipantClaimRecord:
        validate_owner_inn(claimed_inn)
        user = self.db.get(User, claimant_user_id)
        if user is None:
            raise KeyError("claimant user not found")
        if target_organisation_id is not None and self.db.get(OrganisationRecord, target_organisation_id) is None:
            raise KeyError("target organisation not found")
        row = ParticipantClaimRecord(
            claimant_user_id=claimant_user_id,
            target_organisation_id=target_organisation_id,
            claimed_inn=claimed_inn,
            state="PENDING_VERIFICATION",
            verification_method=None,
            verification_metadata={},
            evidence_refs=list(evidence_refs or []),
            decided_at=None,
        )
        self.db.add(row)
        self.db.flush()
        return row

    def reject(self, claim_id: str, *, metadata: dict | None = None) -> ParticipantClaimRecord:
        row = self.db.get(ParticipantClaimRecord, claim_id)
        if row is None:
            raise KeyError("claim not found")
        if row.state != "PENDING_VERIFICATION":
            raise ValueError("claim is not pending")
        row.state = "REJECTED"
        row.decided_at = datetime.now(timezone.utc)
        row.verification_metadata = dict(metadata or {})
        self.db.flush()
        return row


class PublicRegistrationService:
    """Phase-C architecture boundary. Runtime remains deliberately OFF in M12."""

    policy = PublicRegistrationPolicy()

    def __init__(
        self,
        *,
        runtime_enabled: bool = False,
        email_verification_available: bool = False,
        password_recovery_available: bool = False,
        anti_abuse_prerequisites_complete: bool = False,
    ) -> None:
        if runtime_enabled and not (
            email_verification_available
            and password_recovery_available
            and anti_abuse_prerequisites_complete
        ):
            raise PublicRegistrationDisabled("public registration prerequisites are not accepted")
        if runtime_enabled:
            raise PublicRegistrationDisabled("public registration runtime remains disabled in M12")

    def register(self, *args, **kwargs):
        raise PublicRegistrationDisabled("public registration is disabled")
