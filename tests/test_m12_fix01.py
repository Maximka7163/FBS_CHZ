from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from wbcz_web.auth import (
    NEW_PASSWORD_MAX_LENGTH,
    hash_password,
    normalize_new_password,
    verify_password,
)
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.models import (
    LoginThrottleStateRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantClaimRecord,
    ParticipantRecord,
    SessionRecord,
    User,
)
from wbcz_web.services import AuthService, AuthenticationError
from wbcz_web.services.authorization import (
    ActiveScope,
    AuthorizationError,
    AuthorizationService,
    MembershipService,
    Permission,
    Role,
    ROLE_PERMISSIONS,
)
from wbcz_web.services.registration import (
    PUBLIC_REGISTRATION_ARCHITECTURE,
    PUBLIC_REGISTRATION_RUNTIME_ENABLED,
    ParticipantClaimService,
    PublicRegistrationDisabled,
    PublicRegistrationService,
)
from wbcz_web.services.tenant import TenantScopeRequired, bind_tenant_scope
from wbcz_web.api.security_routes import InviteRequest


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL") or os.getenv("WBCZ_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M12 FIX-01 requires PostgreSQL")
NOW = lambda: datetime.now(timezone.utc)
PASSWORD = "correct horse battery staple"


@pytest.fixture
def db() -> Session:
    session = build_session_factory(WebConfig.from_env())()
    tx = session.begin()
    session.execute(text("TRUNCATE TABLE users, organisations RESTART IDENTITY CASCADE"))
    try:
        yield session
    finally:
        tx.rollback()
        session.close()


def _user(
    db: Session,
    name: str,
    *,
    email: str | None = None,
    verified_email: bool = False,
    account_state: str = "ACTIVE",
    legacy_admin: bool = False,
) -> User:
    row = User(
        username=name,
        email_normalized=email,
        email_verified_at=NOW() if verified_email else None,
        account_state=account_state,
        password_hash=hash_password(PASSWORD),
        is_active=True,
        is_admin=legacy_admin,
        password_changed_at=NOW(),
        password_version=1,
        password_must_change=False,
    )
    db.add(row)
    db.flush()
    return row


def _org(db: Session, name: str, inn: str, state: str = "VERIFIED"):
    org = OrganisationRecord(name=name, is_active=True)
    db.add(org)
    db.flush()
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn=inn,
        display_name=name,
        verification_state=state,
        is_active=True,
    )
    db.add(participant)
    db.flush()
    return org, participant


def _membership(db: Session, user: User, org: OrganisationRecord, role: Role):
    row = MembershipRecord(
        organisation_id=org.id,
        user_id=user.id,
        role=role.value,
        is_active=True,
    )
    db.add(row)
    db.flush()
    return row


def _session(db: Session, user: User):
    row = SessionRecord(
        user_id=user.id,
        token_hash=uuid4().hex + uuid4().hex,
        password_version=user.password_version,
        created_at=NOW(),
        last_seen_at=NOW(),
        expires_at=NOW() + timedelta(hours=2),
    )
    db.add(row)
    db.flush()
    return row


def test_identity_schema_and_normalized_email_uniqueness(db: Session):
    assert {"email_normalized", "email_verified_at", "account_state"}.issubset(User.__table__.columns.keys())
    assert {
        "claimant_user_id", "target_organisation_id", "claimed_inn", "state",
        "verification_method", "verification_metadata", "evidence_refs", "decided_at",
    }.issubset(ParticipantClaimRecord.__table__.columns.keys())

    _user(db, "email-a", email="future@example.invalid")
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            _user(db, "email-b", email="future@example.invalid")

    with pytest.raises(IntegrityError):
        with db.begin_nested():
            _user(db, "bad-state", account_state="UNKNOWN")


def test_public_registration_architecture_is_present_but_runtime_hard_off():
    assert PUBLIC_REGISTRATION_ARCHITECTURE is True
    assert PUBLIC_REGISTRATION_RUNTIME_ENABLED is False
    with pytest.raises(PublicRegistrationDisabled):
        PublicRegistrationService(runtime_enabled=True)
    with pytest.raises(PublicRegistrationDisabled):
        PublicRegistrationService(
            runtime_enabled=True,
            email_verification_available=True,
            password_recovery_available=True,
            anti_abuse_prerequisites_complete=True,
        )
    with pytest.raises(PublicRegistrationDisabled):
        PublicRegistrationService().register()


def test_existing_inn_claim_grants_no_existing_tenant_access(db: Session):
    owner = _user(db, "claim-owner")
    outsider = _user(
        db,
        "claim-outsider",
        email="claimant@example.invalid",
        verified_email=True,
        account_state="ACTIVE",
    )
    existing_org, existing_participant = _org(db, "Existing", "7707083893")
    _membership(db, owner, existing_org, Role.OWNER)

    new_org = OrganisationRecord(name="Prospective", is_active=True, created_by_user_id=outsider.id)
    db.add(new_org)
    db.flush()
    claim = ParticipantClaimService(db).create_pending(
        claimant_user_id=outsider.id,
        claimed_inn=existing_participant.inn,
        target_organisation_id=new_org.id,
        evidence_refs=["future-verifier-placeholder"],
    )
    assert claim.state == "PENDING_VERIFICATION"
    assert list(AuthorizationService(db).available_memberships(outsider.id)) == []
    outsider_session = _session(db, outsider)
    with pytest.raises(AuthorizationError):
        AuthorizationService(db).set_active_scope(
            outsider,
            outsider_session,
            organisation_id=existing_org.id,
            participant_id=existing_participant.id,
        )


def test_future_new_org_onboarding_is_representable_without_schema_change(db: Session):
    user = _user(
        db,
        "future-user",
        email="future-user@example.invalid",
        account_state="PENDING_VERIFICATION",
    )
    org = OrganisationRecord(name="Future Org", is_active=True, created_by_user_id=user.id)
    db.add(org)
    db.flush()
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn="781201234567",
        display_name="Future participant",
        verification_state="PENDING_VERIFICATION",
        is_active=True,
    )
    db.add(participant)
    db.flush()
    claim = ParticipantClaimService(db).create_pending(
        claimant_user_id=user.id,
        claimed_inn=participant.inn,
        target_organisation_id=org.id,
    )
    assert claim.target_organisation_id == org.id
    assert participant.verification_state == "PENDING_VERIFICATION"
    assert user.account_state == "PENDING_VERIFICATION"


@pytest.mark.parametrize("state", ["UNVERIFIED", "PENDING_VERIFICATION", "REJECTED"])
def test_non_verified_participant_cannot_unlock_sensitive_tenant_runtime(db: Session, state: str):
    user = _user(db, "gate-" + state.lower())
    org, participant = _org(db, "Gate " + state, str(810000000000 + len(state)), state=state)
    _membership(db, user, org, Role.OPERATOR)
    session = _session(db, user)
    with pytest.raises(AuthorizationError):
        AuthorizationService(db).set_active_scope(
            user, session, organisation_id=org.id, participant_id=participant.id
        )
    with pytest.raises(TenantScopeRequired):
        bind_tenant_scope(db, organisation_id=org.id, participant_id=participant.id)


def test_verified_participant_works_with_permission_and_feature_gates(db: Session):
    user = _user(db, "gate-verified")
    org, participant = _org(db, "Gate Verified", "810000000099", state="VERIFIED")
    _membership(db, user, org, Role.OPERATOR)
    session = _session(db, user)
    scope = AuthorizationService(db).set_active_scope(
        user, session, organisation_id=org.id, participant_id=participant.id
    )
    assert scope.participant_id == participant.id
    AuthorizationService.require(scope, Permission.DOCUMENTS_WRITE)


def test_exact_permission_contract_and_legacy_admin_is_not_authority(db: Session):
    assert Permission.DOCUMENTS_WRITE in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.DOCUMENTS_WRITE not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.ORGANISATION_MANAGE in ROLE_PERMISSIONS[Role.OWNER]
    assert Permission.ORGANISATION_MANAGE not in ROLE_PERMISSIONS[Role.ADMIN]

    legacy = _user(db, "legacy-admin", legacy_admin=True)
    org, participant = _org(db, "Legacy role", "810000000100")
    _membership(db, legacy, org, Role.VIEWER)
    scope = AuthorizationService(db).set_active_scope(
        legacy, _session(db, legacy), organisation_id=org.id, participant_id=participant.id
    )
    with pytest.raises(AuthorizationError):
        AuthorizationService.require(scope, Permission.DOCUMENTS_WRITE)
    with pytest.raises(AuthorizationError):
        AuthorizationService.require(scope, Permission.ORGANISATION_MANAGE)
    with pytest.raises(AuthorizationError):
        AuthorizationService.require(scope, "unknown:permission")  # type: ignore[arg-type]


def test_invitation_email_ready_schema_verified_email_binding_and_default_expiry(db: Session):
    owner = _user(db, "invite-owner")
    org, participant = _org(db, "Invite org", "810000000101")
    _membership(db, owner, org, Role.OWNER)
    scope = AuthorizationService(db).set_active_scope(
        owner, _session(db, owner), organisation_id=org.id, participant_id=participant.id
    )

    verified = _user(
        db,
        "invite-verified",
        email="verified@example.invalid",
        verified_email=True,
    )
    row, raw = MembershipService(db).create_invitation(
        scope,
        invited_email_normalized="VERIFIED@example.invalid",
        role=Role.VIEWER,
        participant_id=participant.id,
        expires_at=NOW() + timedelta(days=7),
    )
    assert row.invitee_username is None
    assert row.invited_email_normalized == "verified@example.invalid"
    accepted = MembershipService(db).accept_invitation(verified, raw)
    assert accepted.user_id == verified.id

    unverified = _user(
        db,
        "invite-unverified",
        email="unverified@example.invalid",
        verified_email=False,
    )
    _, raw2 = MembershipService(db).create_invitation(
        scope,
        invited_email_normalized=unverified.email_normalized,
        role=Role.VIEWER,
        participant_id=None,
        expires_at=NOW() + timedelta(days=7),
    )
    with pytest.raises(AuthorizationError):
        MembershipService(db).accept_invitation(unverified, raw2)

    with pytest.raises(ValueError):
        MembershipService(db).create_invitation(
            scope,
            role=Role.VIEWER,
            participant_id=None,
            expires_at=NOW() + timedelta(days=7),
        )

    dto = InviteRequest(username="compat-user", role=Role.VIEWER)
    assert dto.expires_in_hours == 168


def _throttle_state(db: Session, user: User) -> LoginThrottleStateRecord:
    row = db.get(LoginThrottleStateRecord, user.id)
    assert row is not None
    return row


def test_login_throttle_first_five_progressive_cap_lock_and_controlled_reset(db: Session):
    cfg = replace(
        WebConfig.from_env(),
        login_throttle_max_failures=100,
        login_account_free_failures=5,
        login_account_initial_delay_seconds=30,
        login_account_delay_cap_seconds=900,
        login_account_lock_failures=100,
    )
    user = _user(db, "throttle-contract")
    svc = AuthService(db, cfg)
    remote = "192.0.2.50"

    for expected in range(1, 6):
        with pytest.raises(AuthenticationError):
            svc.login(user.username, "wrong-password", remote_address=remote)
        state = _throttle_state(db, user)
        assert state.consecutive_failures == expected
        assert state.blocked_until is None

    before = NOW()
    with pytest.raises(AuthenticationError):
        svc.login(user.username, "wrong-password", remote_address=remote)
    state = _throttle_state(db, user)
    assert state.consecutive_failures == 6
    assert state.blocked_until is not None
    delay = (state.blocked_until - before).total_seconds()
    assert 29 <= delay <= 31

    state.blocked_until = NOW() - timedelta(seconds=1)
    db.flush()
    before = NOW()
    with pytest.raises(AuthenticationError):
        svc.login(user.username, "wrong-password", remote_address=remote)
    state = _throttle_state(db, user)
    assert state.consecutive_failures == 7
    assert 59 <= (state.blocked_until - before).total_seconds() <= 61

    state.consecutive_failures = 10
    state.blocked_until = NOW() - timedelta(seconds=1)
    db.flush()
    before = NOW()
    with pytest.raises(AuthenticationError):
        svc.login(user.username, "wrong-password", remote_address=remote)
    state = _throttle_state(db, user)
    assert state.consecutive_failures == 11
    assert 899 <= (state.blocked_until - before).total_seconds() <= 901

    state.consecutive_failures = 99
    state.blocked_until = NOW() - timedelta(seconds=1)
    state.password_locked = False
    db.flush()
    with pytest.raises(AuthenticationError):
        svc.login(user.username, "wrong-password", remote_address=remote)
    assert state.consecutive_failures == 100
    assert state.password_locked is True

    with pytest.raises(AuthenticationError):
        svc.login(user.username, PASSWORD, remote_address="192.0.2.51")
    svc.reset_password_authenticator_lock(user.id, actor_user_id=user.id)
    assert state.consecutive_failures == 0
    assert state.password_locked is False
    assert state.blocked_until is None
    _, token = svc.login(user.username, PASSWORD, remote_address="192.0.2.51")
    assert token


def test_success_resets_account_progression_and_source_isolation(db: Session):
    cfg = replace(WebConfig.from_env(), login_throttle_max_failures=3)
    first = _user(db, "source-a")
    second = _user(db, "source-b")
    svc = AuthService(db, cfg)

    for _ in range(3):
        with pytest.raises(AuthenticationError):
            svc.login(first.username, "wrong", remote_address="198.51.100.10")

    _, token = svc.login(second.username, PASSWORD, remote_address="198.51.100.11")
    assert token
    state2 = _throttle_state(db, second)
    assert state2.consecutive_failures == 0

    _, token2 = svc.login(first.username, PASSWORD, remote_address="198.51.100.11")
    assert token2
    state1 = _throttle_state(db, first)
    assert state1.consecutive_failures == 0
    assert state1.blocked_until is None


def test_login_throttle_state_persists_across_database_sessions():
    engine = create_engine(DB_URL, future=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    username = "restart-" + uuid4().hex
    cfg = replace(WebConfig.from_env(), login_throttle_max_failures=100)
    try:
        with factory() as first:
            user = User(
                username=username,
                account_state="ACTIVE",
                password_hash=hash_password(PASSWORD),
                is_active=True,
                is_admin=False,
                password_changed_at=NOW(),
                password_version=1,
                password_must_change=False,
            )
            first.add(user)
            first.commit()
            user_id = user.id
            with pytest.raises(AuthenticationError):
                AuthService(first, cfg).login(username, "wrong", remote_address="203.0.113.70")
            first.commit()

        with factory() as second:
            state = second.get(LoginThrottleStateRecord, user_id)
            assert state is not None and state.consecutive_failures == 1
            with pytest.raises(AuthenticationError):
                AuthService(second, cfg).login(username, "wrong", remote_address="203.0.113.71")
            second.commit()

        with factory() as third:
            state = third.get(LoginThrottleStateRecord, user_id)
            assert state is not None and state.consecutive_failures == 2
    finally:
        with factory() as cleanup:
            user = cleanup.scalar(select(User).where(User.username == username))
            if user is not None:
                cleanup.delete(user)
                cleanup.commit()
        engine.dispose()


def test_password_policy_256_nfc_and_legacy_verify_compatibility(db: Session):
    assert NEW_PASSWORD_MAX_LENGTH == 256
    with pytest.raises(ValueError):
        hash_password("x" * 257)

    decomposed = ("e\u0301" * 15) + "-safe-password"
    normalized = normalize_new_password(decomposed)
    assert normalized != decomposed
    stored = hash_password(decomposed)
    assert verify_password(stored, normalized)

    legacy_password = "L" * 300
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    user = _user(db, "legacy-long-password")
    user.password_hash = weak.hash(legacy_password)
    db.flush()
    _, token = AuthService(db, replace(WebConfig.from_env(), login_throttle_max_failures=100)).login(
        user.username,
        legacy_password,
        remote_address="192.0.2.90",
    )
    assert token
    assert verify_password(user.password_hash, legacy_password)


def test_idle_timeout_default_is_thirty_minutes_and_absolute_ttl_is_independent(db: Session):
    cfg = WebConfig.from_env()
    assert cfg.session_idle_timeout_seconds == 1800
    custom = replace(cfg, session_ttl_seconds=7200, session_idle_timeout_seconds=1800)
    user = _user(db, "idle-default")
    _, token = AuthService(db, custom).login(user.username, PASSWORD, remote_address="192.0.2.91")
    session = AuthService(db, custom).sessions.active_by_hash(
        __import__("wbcz_web.auth", fromlist=["token_hash"]).token_hash(token)
    )
    assert session is not None
    session.last_seen_at = NOW() - timedelta(seconds=1800)
    db.flush()
    with pytest.raises(AuthenticationError):
        AuthService(db, custom).authenticate_token(token)

    _, token2 = AuthService(db, custom).login(user.username, PASSWORD, remote_address="192.0.2.92")
    session2 = AuthService(db, custom).sessions.active_by_hash(
        __import__("wbcz_web.auth", fromlist=["token_hash"]).token_hash(token2)
    )
    assert session2 is not None
    session2.expires_at = NOW() - timedelta(seconds=1)
    session2.last_seen_at = NOW()
    db.flush()
    with pytest.raises(AuthenticationError):
        AuthService(db, custom).authenticate_token(token2)
