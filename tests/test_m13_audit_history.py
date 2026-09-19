from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.models import (
    AuditCheckpointRecord,
    AuditEventRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantRecord,
    User,
)
from wbcz_web.services.audit_history import (
    AUDIT_EVENT_REGISTRY,
    MAX_METADATA_BYTES,
    MAX_SANITIZER_DEPTH,
    ActorContext,
    ActorKind,
    AuditError,
    AuditEventKeyConflict,
    AuditOutcome,
    AuditSanitizationError,
    AuditService,
    AuditTenantScope,
    AuthorizationDecision,
    SubjectRef,
    SubjectType,
    TraceContext,
    jcs_bytes,
    jcs_dumps,
)


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL") or os.getenv("WBCZ_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M13 tests require PostgreSQL")
PSEUDONYM_KEY = b"m13-test-only-pseudonym-key-0123456789abcdef"
NOW = lambda: datetime.now(timezone.utc)


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


def _user(db: Session, name: str) -> User:
    row = User(
        username=name,
        account_state="ACTIVE",
        password_hash=hash_password("correct horse battery staple"),
        is_active=True,
        is_admin=False,
        password_changed_at=NOW(),
        password_version=1,
        password_must_change=False,
    )
    db.add(row)
    db.flush()
    return row


def _tenant(db: Session, name: str, inn: str, role: str = "OWNER"):
    user = _user(db, "u-" + uuid4().hex[:8])
    org = OrganisationRecord(name=name, is_active=True, created_by_user_id=user.id)
    db.add(org)
    db.flush()
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn=inn,
        display_name=name,
        verification_state="VERIFIED",
        is_active=True,
    )
    db.add(participant)
    db.flush()
    membership = MembershipRecord(
        organisation_id=org.id,
        user_id=user.id,
        role=role,
        is_active=True,
        created_by_user_id=user.id,
    )
    db.add(membership)
    db.flush()
    return user, org, participant, membership


def _service(db: Session) -> AuditService:
    return AuditService(db, pseudonym_key=PSEUDONYM_KEY, pseudonym_key_id="test-v1")


def test_registry_contains_required_codes_and_unknown_fails_closed(db: Session):
    required = {
        "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_THROTTLED", "LOGOUT", "LOGOUT_ALL",
        "SESSION_REVOKED", "PASSWORD_CHANGED", "USER_DISABLED", "MEMBERSHIP_ADDED",
        "MEMBERSHIP_REMOVED", "ROLE_CHANGED", "INVITATION_CREATED", "INVITATION_ACCEPTED",
        "INVITATION_REVOKED", "SCOPE_CHANGED", "BOOTSTRAP_COMPLETED",
        "TURNOVER_INTENT_CREATED", "TURNOVER_REMOTE_RESULT", "TURNOVER_RECONCILED",
        "AGGREGATION_INTENT_CREATED", "AGGREGATION_REMOTE_RESULT", "AGGREGATION_RECONCILED",
        "REPORT_REQUESTED", "REPORT_GENERATION_STARTED", "REPORT_GENERATION_COMPLETED",
        "REPORT_GENERATION_FAILED", "REPORT_ARTIFACT_FINALIZED", "REPORT_DOWNLOAD_AUTHORIZED",
        "REPORT_DOWNLOAD_DENIED", "REPORT_DOWNLOAD_COMPLETED", "REPORT_DOWNLOAD_FAILED",
        "REPORT_ARTIFACT_INTEGRITY_FAILED", "REPORT_ARTIFACT_DELETED", "REPORT_ARTIFACT_EXPIRED",
        "AGENT_JOB_CREATED", "AGENT_JOB_CLAIMED", "AGENT_JOB_COMPLETED", "AGENT_JOB_FAILED",
        "AGENT_RESULT_AMBIGUOUS", "AGENT_REPLAY_CONVERGED", "AGENT_ARTIFACT_UPLOADED",
        "AGENT_DOCUMENT_SUBMITTED", "AUDIT_CHAIN_GENESIS", "LEGACY_HISTORY_IMPORTED",
        "AUDIT_QUERY_EXECUTED", "CHAIN_VERIFICATION_FAILED", "CHECKPOINT_CREATED",
    }
    assert required <= set(AUDIT_EVENT_REGISTRY)
    with pytest.raises(Exception):
        _service(db).append(
            event_type="USER_DEFINED_ARBITRARY_EVENT",
            actor=ActorContext(ActorKind.SYSTEM),
            tenant=AuditTenantScope.system(),
            subject=SubjectRef(SubjectType.AUDIT_CHAIN, str(uuid4())),
            outcome=AuditOutcome.SUCCESS,
        )


def test_jcs_conformance_key_order_unicode_arrays_numbers_and_null():
    left = {
        "z": None,
        "a": {"β": [True, False, "é", 1, -0.0, 1e-7], "A": "x"},
        "😀": "supplementary",
    }
    right = {
        "😀": "supplementary",
        "a": {"A": "x", "β": [True, False, "é", 1, 0.0, 0.0000001]},
        "z": None,
    }
    assert jcs_bytes(left) == jcs_bytes(right)
    encoded = jcs_dumps(left)
    assert encoded.startswith('{"a":')
    assert '"z":null' in encoded
    assert "NaN" not in encoded and "Infinity" not in encoded
    with pytest.raises(AuditSanitizationError):
        jcs_dumps({"x": float("nan")})
    with pytest.raises(AuditSanitizationError):
        jcs_dumps({"x": float("inf")})
    with pytest.raises(AuditSanitizationError):
        jcs_dumps({"x": 9_007_199_254_740_992})


def test_recursive_sanitizer_redacts_secrets_pseudonymizes_marking_and_rejects_limits(db: Session):
    _, org, _, _ = _tenant(db, "Sanitizer", "7707083893")
    service = _service(db)
    data = {
        "nested": {
            "password": "secret-password",
            "Authorization": "Bearer secret",
            "list": [{"api_key": "secret-api-key"}, {"kiz": "010123456789012321ABCDEF"}],
        },
        "cookie": "session=secret",
        "normal": "ok",
    }
    sanitized = service.sanitizer.metadata(data, organisation_id=org.id)
    blob = jcs_dumps(sanitized)
    assert "secret-password" not in blob
    assert "Bearer secret" not in blob
    assert "secret-api-key" not in blob
    assert "010123456789012321ABCDEF" not in blob
    assert "hmac-sha256:test-v1:" in blob
    assert sanitized["normal"] == "ok"

    deep = value = {}
    for i in range(MAX_SANITIZER_DEPTH + 2):
        child = {}
        value[f"k{i}"] = child
        value = child
    with pytest.raises(AuditSanitizationError):
        service.sanitizer.metadata(deep, organisation_id=org.id)

    with pytest.raises(AuditSanitizationError):
        service.sanitizer.metadata({"x": ["v"] * 101}, organisation_id=org.id)
    with pytest.raises(AuditSanitizationError):
        service.sanitizer.metadata({"x": "v" * 4097}, organisation_id=org.id)
    with pytest.raises(AuditSanitizationError):
        service.sanitizer.metadata({"x": object()}, organisation_id=org.id)
    with pytest.raises(AuditSanitizationError):
        service.sanitizer.metadata({"x": "v" * (MAX_METADATA_BYTES + 1)}, organisation_id=org.id)


def test_genesis_chain_event_key_convergence_conflict_and_verification(db: Session):
    user, org, participant, _ = _tenant(db, "Chain", "500100732259", role="ADMIN")
    service = _service(db)
    tenant = AuditTenantScope(org.id, participant.id)
    receipt = service.append(
        event_type="REPORT_REQUESTED",
        actor=ActorContext(ActorKind.USER, user_id=user.id),
        tenant=tenant,
        subject=SubjectRef(SubjectType.REPORT_JOB, "rpt-test"),
        outcome=AuditOutcome.PENDING,
        authorization_decision=AuthorizationDecision.ALLOW,
        trace=TraceContext(
            request_id="req-1",
            correlation_id="corr-1",
            event_key="report-request:rpt-test",
        ),
        metadata={
            "report_job_id": "rpt-test",
            "report_type": "DOCUMENT_LIFECYCLE",
            "format": "CSV",
            "sensitivity_class": "NORMAL",
            "schema_version": "1",
            "request_fingerprint_sha256": "a" * 64,
            "origin": "LOCAL",
        },
    )
    assert receipt.sequence >= 2
    chain = service.chain_for_organisation(org.id)
    genesis = db.scalar(select(AuditEventRecord).where(
        AuditEventRecord.chain_id == chain.chain_id,
        AuditEventRecord.sequence == 1,
    ))
    assert genesis is not None
    assert genesis.event_type == "AUDIT_CHAIN_GENESIS"
    assert genesis.previous_event_hash == "0" * 64

    same = service.append(
        event_type="REPORT_REQUESTED",
        actor=ActorContext(ActorKind.USER, user_id=user.id),
        tenant=tenant,
        subject=SubjectRef(SubjectType.REPORT_JOB, "rpt-test"),
        outcome=AuditOutcome.PENDING,
        authorization_decision=AuthorizationDecision.ALLOW,
        trace=TraceContext(
            request_id="req-1",
            correlation_id="corr-1",
            event_key="report-request:rpt-test",
        ),
        metadata={
            "report_job_id": "rpt-test",
            "report_type": "DOCUMENT_LIFECYCLE",
            "format": "CSV",
            "sensitivity_class": "NORMAL",
            "schema_version": "1",
            "request_fingerprint_sha256": "a" * 64,
            "origin": "LOCAL",
        },
    )
    assert same.converged is True
    assert same.event_id == receipt.event_id

    with pytest.raises(AuditEventKeyConflict):
        service.append(
            event_type="REPORT_REQUESTED",
            actor=ActorContext(ActorKind.USER, user_id=user.id),
            tenant=tenant,
            subject=SubjectRef(SubjectType.REPORT_JOB, "rpt-test"),
            outcome=AuditOutcome.PENDING,
            authorization_decision=AuthorizationDecision.ALLOW,
            trace=TraceContext(
                request_id="req-1",
                correlation_id="corr-1",
                event_key="report-request:rpt-test",
            ),
            metadata={
                "report_job_id": "rpt-test",
                "report_type": "DOCUMENT_LIFECYCLE",
                "format": "JSON",
                "sensitivity_class": "NORMAL",
                "schema_version": "1",
                "request_fingerprint_sha256": "a" * 64,
                "origin": "LOCAL",
            },
        )

    result = service.verify_chain(organisation_id=org.id)
    assert result.status == "VALID"


def test_participant_cross_org_rejected_and_role_snapshot_is_immutable(db: Session):
    user_a, org_a, part_a, membership_a = _tenant(db, "A", "7707083893", role="ADMIN")
    _, org_b, part_b, _ = _tenant(db, "B", "500100732259", role="OWNER")
    service = _service(db)

    with pytest.raises(AuditError):
        service.append(
            event_type="REPORT_REQUESTED",
            actor=ActorContext(ActorKind.USER, user_id=user_a.id),
            tenant=AuditTenantScope(org_a.id, part_b.id),
            subject=SubjectRef(SubjectType.REPORT_JOB, "foreign"),
            outcome=AuditOutcome.PENDING,
            authorization_decision=AuthorizationDecision.ALLOW,
            metadata={
                "report_job_id": "foreign",
                "report_type": "DOCUMENT_LIFECYCLE",
                "format": "CSV",
                "sensitivity_class": "NORMAL",
                "schema_version": "1",
                "request_fingerprint_sha256": "b" * 64,
                "origin": "LOCAL",
            },
        )

    receipt = service.append(
        event_type="REPORT_REQUESTED",
        actor=ActorContext(ActorKind.USER, user_id=user_a.id),
        tenant=AuditTenantScope(org_a.id, part_a.id),
        subject=SubjectRef(SubjectType.REPORT_JOB, "snapshot"),
        outcome=AuditOutcome.PENDING,
        authorization_decision=AuthorizationDecision.ALLOW,
        metadata={
            "report_job_id": "snapshot",
            "report_type": "DOCUMENT_LIFECYCLE",
            "format": "CSV",
            "sensitivity_class": "NORMAL",
            "schema_version": "1",
            "request_fingerprint_sha256": "c" * 64,
            "origin": "LOCAL",
        },
    )
    row = db.get(AuditEventRecord, receipt.event_id)
    assert row is not None
    assert row.actor_user_id == user_a.id
    assert row.actor_membership_id == membership_a.id
    assert row.actor_role_snapshot == "ADMIN"
    assert "audit:read" in (row.permission_snapshot_json or [])

    membership_a.role = "VIEWER"
    user_a.is_active = False
    db.flush()
    db.refresh(row)
    assert row.actor_role_snapshot == "ADMIN"
    assert "audit:read" in (row.permission_snapshot_json or [])


def test_marking_identifier_subject_is_keyed_and_plaintext_absent(db: Session):
    user, org, participant, _ = _tenant(db, "Marking", "7722334455", role="ADMIN")
    service = _service(db)
    exact = "010123456789012321SYNTHETIC-SERIAL"
    receipt = service.append(
        event_type="AUDIT_QUERY_EXECUTED",
        actor=ActorContext(ActorKind.USER, user_id=user.id),
        tenant=AuditTenantScope(org.id, None),
        subject=SubjectRef(SubjectType.AUDIT_CHAIN, service.chain_for_organisation(org.id).chain_id),
        secondary_subject=SubjectRef(SubjectType.MARKING_IDENTIFIER, exact, plaintext_marking=True),
        outcome=AuditOutcome.SUCCESS,
        authorization_decision=AuthorizationDecision.ALLOW,
        metadata={"filter_summary": {"marking_code": exact}, "limit": 1, "returned_count": 0, "query_kind": "DETAIL"},
    )
    row = db.get(AuditEventRecord, receipt.event_id)
    assert row is not None
    serialized = jcs_dumps({
        "subject_id": row.subject_id,
        "secondary_subject_id": row.secondary_subject_id,
        "metadata": row.metadata_sanitized_json,
    })
    assert exact not in serialized
    assert "hmac-sha256:test-v1:" in serialized


def test_database_append_only_guards_reject_update_and_delete(db: Session):
    service = _service(db)
    chain = service.system_chain()
    event = db.scalar(select(AuditEventRecord).where(
        AuditEventRecord.chain_id == chain.chain_id,
        AuditEventRecord.sequence == 1,
    ))
    assert event is not None

    with pytest.raises(DBAPIError):
        with db.begin_nested():
            db.execute(text("UPDATE audit_events SET action='tampered' WHERE event_id=:id"), {"id": event.event_id})

    with pytest.raises(DBAPIError):
        with db.begin_nested():
            db.execute(text("DELETE FROM audit_events WHERE event_id=:id"), {"id": event.event_id})


def test_chain_tamper_detection_via_head_mismatch(db: Session):
    _, org, _, _ = _tenant(db, "Tamper", "7722445566")
    service = _service(db)
    chain = service.chain_for_organisation(org.id)
    original = chain.head_hash
    # chain_heads are mutable by design; verifier must detect a mismatched head.
    chain.head_hash = "f" * 64 if original != "f" * 64 else "e" * 64
    db.flush()
    result = service.verify_chain(organisation_id=org.id)
    assert result.status == "INVALID"
    assert result.reason in {"chain head mismatch", "tail sequence mismatch"}


def test_different_organisation_chains_are_independent(db: Session):
    _, org_a, _, _ = _tenant(db, "Independent A", "7722556677")
    _, org_b, _, _ = _tenant(db, "Independent B", "7722667788")
    service = _service(db)
    a = service.chain_for_organisation(org_a.id)
    b = service.chain_for_organisation(org_b.id)
    assert a.chain_id != b.chain_id
    assert a.organisation_id == org_a.id
    assert b.organisation_id == org_b.id


def test_real_postgres_concurrent_appends_same_org_are_contiguous():
    engine = create_engine(DB_URL, future=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    suffix = uuid4().hex[:8]
    try:
        with factory() as seed:
            user = User(
                username="conc-" + suffix,
                account_state="ACTIVE",
                password_hash=hash_password("correct horse battery staple"),
                is_active=True,
                is_admin=False,
                password_changed_at=NOW(),
                password_version=1,
                password_must_change=False,
            )
            seed.add(user)
            seed.flush()
            org = OrganisationRecord(name="Concurrent " + suffix, is_active=True, created_by_user_id=user.id)
            seed.add(org)
            seed.flush()
            participant = ParticipantRecord(
                organisation_id=org.id,
                inn=str(780000000000 + int(suffix[:4], 16) % 999999),
                display_name="Concurrent",
                verification_state="VERIFIED",
                is_active=True,
            )
            seed.add(participant)
            seed.flush()
            seed.add(MembershipRecord(
                organisation_id=org.id,
                user_id=user.id,
                role="ADMIN",
                is_active=True,
                created_by_user_id=user.id,
            ))
            seed.commit()
            ids = (user.id, org.id, participant.id)

        def append_one(n: int) -> int:
            with factory() as session:
                user_id, org_id, participant_id = ids
                service = AuditService(session, pseudonym_key=PSEUDONYM_KEY, pseudonym_key_id="test-v1")
                receipt = service.append(
                    event_type="REPORT_REQUESTED",
                    actor=ActorContext(ActorKind.USER, user_id=user_id),
                    tenant=AuditTenantScope(org_id, participant_id),
                    subject=SubjectRef(SubjectType.REPORT_JOB, f"concurrent-{n}"),
                    outcome=AuditOutcome.PENDING,
                    authorization_decision=AuthorizationDecision.ALLOW,
                    trace=TraceContext(event_key=f"concurrent:{n}"),
                    metadata={
                        "report_job_id": f"concurrent-{n}",
                        "report_type": "DOCUMENT_LIFECYCLE",
                        "format": "CSV",
                        "sensitivity_class": "NORMAL",
                        "schema_version": "1",
                        "request_fingerprint_sha256": f"{n:064x}"[-64:],
                        "origin": "LOCAL",
                    },
                )
                session.commit()
                return receipt.sequence

        with ThreadPoolExecutor(max_workers=6) as pool:
            sequences = list(pool.map(append_one, range(12)))
        assert len(set(sequences)) == 12

        with factory() as verify:
            result = AuditService(verify, pseudonym_key=PSEUDONYM_KEY).verify_chain(organisation_id=ids[1])
            assert result.status == "VALID"
            rows = list(verify.scalars(
                select(AuditEventRecord)
                .where(AuditEventRecord.organisation_id == ids[1])
                .order_by(AuditEventRecord.sequence)
            ))
            assert [r.sequence for r in rows] == list(range(1, len(rows) + 1))
    finally:
        with factory() as cleanup:
            org = cleanup.scalar(select(OrganisationRecord).where(OrganisationRecord.name == "Concurrent " + suffix))
            if org is not None:
                cleanup.delete(org)
            user = cleanup.scalar(select(User).where(User.username == "conc-" + suffix))
            if user is not None:
                cleanup.delete(user)
            cleanup.commit()
        engine.dispose()
