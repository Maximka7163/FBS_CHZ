from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, uuid_text


ROLE_VALUES = ("OWNER", "ADMIN", "OPERATOR", "VIEWER")
PARTICIPANT_STATES = ("UNVERIFIED", "PENDING_VERIFICATION", "VERIFIED", "REJECTED")
INVITATION_STATES = ("PENDING", "ACCEPTED", "REVOKED", "EXPIRED")
CLAIM_STATES = ("PENDING_VERIFICATION", "VERIFIED", "REJECTED", "CANCELLED")


class OrganisationRecord(Base):
    __tablename__ = "organisations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class ParticipantRecord(Base):
    __tablename__ = "participants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True)
    inn: Mapped[str] = mapped_column(String(12), nullable=False, unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    verification_state: Mapped[str] = mapped_column(String(24), nullable=False, default="UNVERIFIED", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("organisation_id", "inn", name="uq_participants_organisation_inn"),
        UniqueConstraint("id", "organisation_id", name="uq_participants_id_organisation_m13"),
        CheckConstraint(
            "verification_state IN ('UNVERIFIED','PENDING_VERIFICATION','VERIFIED','REJECTED')",
            name="ck_participants_verification_state",
        ),
    )


class ParticipantClaimRecord(Base):
    __tablename__ = "participant_claims"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    claimant_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_organisation_id: Mapped[str | None] = mapped_column(ForeignKey("organisations.id", ondelete="CASCADE"), nullable=True, index=True)
    claimed_inn: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING_VERIFICATION", index=True)
    verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_refs: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint(
            "state IN ('PENDING_VERIFICATION','VERIFIED','REJECTED','CANCELLED')",
            name="ck_participant_claim_state",
        ),
    )


class MembershipRecord(Base):
    __tablename__ = "organisation_memberships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("organisation_id", "user_id", name="uq_membership_organisation_user"),
        CheckConstraint("role IN ('OWNER','ADMIN','OPERATOR','VIEWER')", name="ck_membership_role"),
    )


class PermissionRecord(Base):
    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False)


class RolePermissionRecord(Base):
    __tablename__ = "role_permissions"

    role: Mapped[str] = mapped_column(String(16), primary_key=True)
    permission_code: Mapped[str] = mapped_column(ForeignKey("permissions.code", ondelete="CASCADE"), primary_key=True)
    __table_args__ = (
        CheckConstraint("role IN ('OWNER','ADMIN','OPERATOR','VIEWER')", name="ck_role_permissions_role"),
    )


class InvitationRecord(Base):
    __tablename__ = "organisation_invitations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_text)
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="CASCADE"), nullable=False, index=True)
    participant_id: Mapped[str | None] = mapped_column(ForeignKey("participants.id", ondelete="SET NULL"), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    invitee_username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    invited_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    invited_email_normalized: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    invited_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    accepted_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        CheckConstraint("role IN ('OWNER','ADMIN','OPERATOR','VIEWER')", name="ck_invitations_role"),
        CheckConstraint("state IN ('PENDING','ACCEPTED','REVOKED','EXPIRED')", name="ck_invitations_state"),
        CheckConstraint(
            "invitee_username IS NOT NULL OR invited_user_id IS NOT NULL OR invited_email_normalized IS NOT NULL",
            name="ck_invitations_intended_identity",
        ),
    )


class PasswordHistoryRecord(Base):
    __tablename__ = "password_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class LoginAttemptRecord(Base):
    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    remote_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    successful: Mapped[bool] = mapped_column(Boolean, nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)


class LoginThrottleStateRecord(Base):
    __tablename__ = "login_throttle_state"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    password_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("consecutive_failures >= 0", name="ck_login_throttle_nonnegative"),
    )


class BootstrapRecord(Base):
    __tablename__ = "security_bootstrap"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    organisation_id: Mapped[str] = mapped_column(ForeignKey("organisations.id", ondelete="RESTRICT"), nullable=False)
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    participant_id: Mapped[str] = mapped_column(ForeignKey("participants.id", ondelete="RESTRICT"), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
