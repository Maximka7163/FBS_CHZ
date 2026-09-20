from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import os
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from wbcz.wb_fbs import WbEnvironment, WbTokenType
from wbcz.windows_agent import AgentAuthError
from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.models import (
    AgentBindingRecord,
    AgentEnrollmentTokenRecord,
    ManualReviewCaseRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantRecord,
    RemoteRateLimitStateRecord,
    ReportJobRecord,
    User,
    WorkerHeartbeatRecord,
)
from wbcz_web.repositories.reports import SqlReportRepository
from wbcz_web.services.agent_bindings import AgentBindingService
from wbcz_web.services.agent_enrollment import AgentEnrollmentService
from wbcz_web.services.integration_secrets import ReadOnlySecretProvider
from wbcz_web.services.production_hardening import (
    ManualReviewService,
    PostgresWbRateLimiter,
    RetryClassification,
)
from wbcz_web.services.runtime_health import DeepHealthService, ReadinessService
from wbcz_web.services.tenant import bind_tenant_scope


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL") or os.getenv("WBCZ_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M15 PostgreSQL tests require WBCZ_TEST_DATABASE_URL")
NOW = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
AUDIT_KEY = b"m15-postgres-test-audit-key-0123456789abcdef"


@pytest.fixture
def factory():
    cfg = WebConfig.from_env()
    fac = build_session_factory(cfg)
    with fac() as db:
        db.execute(text("TRUNCATE TABLE users, organisations RESTART IDENTITY CASCADE"))
        db.commit()
    yield fac
    with fac() as db:
        db.execute(text("TRUNCATE TABLE users, organisations RESTART IDENTITY CASCADE"))
        db.commit()


def _prime(db: Session) -> None:
    db.info["audit_pseudonym_key"] = AUDIT_KEY
    db.info["audit_pseudonym_key_id"] = "m15-test-v1"


def _tenant(db: Session, label: str, inn: str):
    user = User(
        username=f"m15-{label}-{uuid4().hex[:6]}",
        password_hash=hash_password("correct horse battery staple"),
        is_active=True,
        is_admin=False,
        password_changed_at=NOW,
        password_version=1,
        password_must_change=False,
        account_state="ACTIVE",
    )
    db.add(user)
    db.flush()
    org = OrganisationRecord(name=f"org-{label}", is_active=True, created_by_user_id=user.id)
    db.add(org)
    db.flush()
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn=inn,
        display_name=f"participant-{label}",
        verification_state="VERIFIED",
        is_active=True,
    )
    db.add(participant)
    db.flush()
    db.add(MembershipRecord(
        organisation_id=org.id,
        user_id=user.id,
        role="OWNER",
        is_active=True,
        created_by_user_id=user.id,
    ))
    db.flush()
    return user, org, participant


def _scope(db: Session, user: User, org: OrganisationRecord, participant: ParticipantRecord) -> None:
    _prime(db)
    bind_tenant_scope(
        db,
        organisation_id=org.id,
        participant_id=participant.id,
        user_id=user.id,
        role="OWNER",
    )
    db.info["audit_trace"] = {
        "request_id": "req-" + uuid4().hex,
        "correlation_id": "corr-" + uuid4().hex,
        "causation_id": None,
    }


def _seed_tenant_and_job(factory, *, job_id: str = "rpt_m15_claim"):
    with factory() as db:
        _prime(db)
        user, org, participant = _tenant(db, job_id[-6:], "7707083893")
        row = ReportJobRecord(
            id=job_id,
            organisation_id=org.id,
            participant_id=participant.id,
            correlation_id="corr-" + job_id,
            causation_id="req-" + job_id,
            origin="LOCAL",
            participant_inn=participant.inn,
            report_type="M15_SYNTHETIC_LOCAL",
            report_schema_version="1",
            output_format="CSV",
            sensitivity_class="NORMAL",
            filters_sanitized_json={},
            sensitive_filter_ref=None,
            request_fingerprint_sha256=hashlib.sha256(job_id.encode()).hexdigest(),
            state="QUEUED",
            remote_metadata_sanitized={},
            remote_create_ambiguous=False,
            requested_by_user_id=str(user.id),
            requested_at=NOW,
            attempt_count=0,
            delivery_count=0,
            semantic_retry_count=0,
            priority=100,
        )
        db.add(row)
        db.commit()
        return user.id, org.id, participant.id


def test_two_worker_claim_contention_uses_skip_locked_and_no_duplicate_delivery(factory):
    _seed_tenant_and_job(factory, job_id="rpt_m15_contention")
    first = factory()
    second = factory()
    try:
        _prime(first)
        _prime(second)
        claim_a = SqlReportRepository(first).claim_next(
            worker_id="worker-a", lease_seconds=60, max_attempts=3, now=NOW
        )
        assert claim_a is not None
        # first transaction intentionally remains open: second must SKIP LOCKED,
        # not block and not duplicate-deliver the same durable row.
        claim_b = SqlReportRepository(second).claim_next(
            worker_id="worker-b", lease_seconds=60, max_attempts=3, now=NOW
        )
        assert claim_b is None
        first.commit()
        second.rollback()
        with factory() as verify:
            row = verify.get(ReportJobRecord, "rpt_m15_contention")
            assert row.state == "GENERATING"
            assert row.lease_owner == "worker-a"
            assert row.delivery_count == 1
            assert row.attempt_count == 1
    finally:
        first.rollback()
        second.rollback()
        first.close()
        second.close()


def test_expired_lease_is_reclaimed_after_crash_and_delivery_is_distinct(factory):
    _seed_tenant_and_job(factory, job_id="rpt_m15_reclaim")
    with factory() as db:
        _prime(db)
        first = SqlReportRepository(db).claim_next(
            worker_id="crashed-worker", lease_seconds=10, max_attempts=3, now=NOW
        )
        assert first is not None
        db.commit()
    with factory() as db:
        _prime(db)
        reclaimed = SqlReportRepository(db).claim_next(
            worker_id="replacement-worker",
            lease_seconds=30,
            max_attempts=3,
            now=NOW + timedelta(seconds=11),
        )
        assert reclaimed is not None
        assert reclaimed.job_id == "rpt_m15_reclaim"
        db.commit()
        row = db.get(ReportJobRecord, reclaimed.job_id)
        assert row.lease_owner == "replacement-worker"
        assert row.delivery_count == 2
        assert row.attempt_count == 2
        assert row.semantic_retry_count == 0


def test_semantic_retry_schedule_is_bounded_and_not_same_as_delivery(factory):
    _seed_tenant_and_job(factory, job_id="rpt_m15_retry")
    with factory() as db:
        _prime(db)
        repo = SqlReportRepository(db)
        claim = repo.claim_next(worker_id="worker-a", lease_seconds=60, max_attempts=3, now=NOW)
        assert claim is not None
        db.commit()

    with factory() as db:
        _prime(db)
        repo = SqlReportRepository(db)
        row = repo.schedule_retry(
            "rpt_m15_retry",
            classification=RetryClassification.REMOTE_5XX.value,
            available_at=NOW + timedelta(seconds=20),
            consumes_semantic_attempt=True,
            error_code="REMOTE_5XX",
        )
        db.commit()
        assert row.state == "QUEUED"
        assert row.semantic_retry_count == 1
        assert row.delivery_count == 1

    with factory() as db:
        _prime(db)
        assert SqlReportRepository(db).claim_next(
            worker_id="too-early", lease_seconds=60, max_attempts=3, now=NOW + timedelta(seconds=19)
        ) is None
        db.rollback()
    with factory() as db:
        _prime(db)
        claim = SqlReportRepository(db).claim_next(
            worker_id="retry-worker", lease_seconds=60, max_attempts=3, now=NOW + timedelta(seconds=21)
        )
        assert claim is not None
        db.commit()
        row = db.get(ReportJobRecord, "rpt_m15_retry")
        assert row.semantic_retry_count == 1
        assert row.delivery_count == 2


def test_manual_review_repeated_failure_converges_and_metadata_is_sanitized(factory):
    with factory() as db:
        user, org, participant = _tenant(db, "review", "500100732259")
        _scope(db, user, org, participant)
        service = ManualReviewService(db)
        one = service.open_or_converge(
            domain="M11",
            reason_code="AMBIGUOUS_AFTER_SEND",
            subject_type="REPORT_JOB",
            subject_id="rpt-ambiguous",
            operation_id="op-ambiguous",
            evidence_hashes=("a" * 64,),
            metadata={"session_token": "SESSION-CANARY-SHOULD-NOT-PERSIST"},
        )
        two = service.open_or_converge(
            domain="M11",
            reason_code="AMBIGUOUS_AFTER_SEND",
            subject_type="REPORT_JOB",
            subject_id="rpt-ambiguous",
            operation_id="op-ambiguous",
            evidence_hashes=("b" * 64,),
            metadata={"wb_token": "WB-CANARY-SHOULD-NOT-PERSIST"},
        )
        db.commit()
        assert one.id == two.id
        assert two.occurrence_count == 2
        assert sorted(two.evidence_hashes_json) == ["a" * 64, "b" * 64]
        rendered = repr(two.metadata_sanitized_json)
        assert "SESSION-CANARY" not in rendered
        assert "WB-CANARY" not in rendered
        assert db.scalar(select(func.count()).select_from(ManualReviewCaseRecord)) == 1


def test_agent_enrollment_is_single_use_participant_bound_hashed_rotatable_and_revocable(factory):
    cfg = replace(
        WebConfig.from_env(),
        environment="test",
        agent_enabled=True,
        agent_legacy_bootstrap_enabled=False,
        agent_machine_token="",
        agent_protocol_current="m15-v1",
        agent_protocol_minimum="m14-v1",
        agent_minimum_version="0.5.1",
        agent_enrollment_ttl_seconds=600,
    ).validate_for_startup()
    with factory() as db:
        user, org, participant = _tenant(db, "agent", "7800000000")
        db.commit()
        _scope(db, user, org, participant)
        enrollment = AgentEnrollmentService(db, config=cfg)
        intent, raw_enrollment = enrollment.create_intent(
            display_name="M15 Agent",
            user_id=user.id,
            requested_protocol_version="m15-v1",
        )
        assert raw_enrollment != intent.token_hash
        assert raw_enrollment not in repr(intent.__dict__)
        assert len(intent.token_hash) == 64
        db.commit()

        with pytest.raises(PermissionError, match="participant"):
            enrollment.exchange(
                raw_enrollment,
                installation_id=str(uuid4()),
                participant_inn="7707083893",
                protocol_version="m15-v1",
                agent_version="0.5.1",
                supported_job_types=("CIS_INFO",),
                supported_capabilities=("TYPED_JOBS",),
            )
        db.rollback()
        _scope(db, user, org, participant)
        binding, permanent, compatibility = enrollment.exchange(
            raw_enrollment,
            installation_id=str(uuid4()),
            participant_inn=participant.inn,
            protocol_version="m15-v1",
            agent_version="0.5.1",
            supported_job_types=("CIS_INFO", "INTEGRATION_HEALTH"),
            supported_capabilities=("TYPED_JOBS", "DPAPI_CREDENTIAL"),
        )
        assert compatibility == "COMPATIBLE"
        assert binding is not None and permanent is not None
        assert binding.organisation_id == org.id
        assert binding.participant_id == participant.id
        assert permanent not in binding.credential_hash
        assert len(binding.credential_hash) == 64
        assert binding.credential_version == 1
        assert intent.state == "USED"
        assert db.scalar(select(func.count()).select_from(AgentEnrollmentTokenRecord)) == 1

        with pytest.raises(PermissionError, match="used"):
            enrollment.exchange(
                raw_enrollment,
                installation_id=str(uuid4()),
                participant_inn=participant.inn,
                protocol_version="m15-v1",
                agent_version="0.5.1",
                supported_job_types=("CIS_INFO",),
                supported_capabilities=("TYPED_JOBS",),
            )

        principal = AgentBindingService(db).authenticate(permanent)
        assert principal.binding_id == binding.id
        _scope(db, user, org, participant)
        binding, rotated = AgentBindingService(db).rotate_credential(binding.id, user_id=user.id)
        assert binding.credential_version == 2
        with pytest.raises(AgentAuthError):
            AgentBindingService(db).authenticate(permanent)
        assert AgentBindingService(db).authenticate(rotated).binding_id == binding.id
        _scope(db, user, org, participant)
        AgentBindingService(db).disable(binding.id, user_id=user.id)
        with pytest.raises(AgentAuthError):
            AgentBindingService(db).authenticate(rotated)
        db.commit()


def test_postgres_wb_rate_limiter_is_shared_by_connection_credential_and_environment(factory):
    clock = lambda: NOW
    with factory() as first:
        limiter = PostgresWbRateLimiter(first, clock=clock)
        # Accepted SELLER_INFO policy has burst=10. Consume the whole
        # shared burst in process A, then process B must observe exhaustion.
        for _ in range(10):
            allowed = limiter.consume(
                family="SELLER_INFO",
                token_type=WbTokenType.PERSONAL,
                environment=WbEnvironment.PRODUCTION,
                token_secret_ref="wb:connection-a:v7",
                now_monotonic=0.0,
            )
            assert allowed.allowed is True
        first.commit()
    with factory() as second:
        limiter = PostgresWbRateLimiter(second, clock=clock)
        denied = limiter.consume(
            family="SELLER_INFO",
            token_type=WbTokenType.PERSONAL,
            environment=WbEnvironment.PRODUCTION,
            token_secret_ref="wb:connection-a:v7",
            now_monotonic=123.0,
        )
        assert denied.allowed is False
        assert denied.retry_after_seconds > 0
        assert second.scalar(select(func.count()).select_from(RemoteRateLimitStateRecord)) == 1

        independent = limiter.consume(
            family="SELLER_INFO",
            token_type=WbTokenType.PERSONAL,
            environment=WbEnvironment.PRODUCTION,
            token_secret_ref="wb:connection-a:v8",
            now_monotonic=123.0,
        )
        assert independent.allowed is True
        second.commit()
        assert second.scalar(select(func.count()).select_from(RemoteRateLimitStateRecord)) == 2


def test_readiness_exact_revision_is_independent_of_agent_and_remote_availability(factory, tmp_path):
    cfg = replace(
        WebConfig.from_env(),
        environment="test",
        report_artifact_root=str(tmp_path / "artifacts"),
    ).validate_for_startup()
    ready, payload = ReadinessService(
        session_factory=factory,
        config=cfg,
        secret_provider=ReadOnlySecretProvider(),
    ).evaluate()
    assert ready is True
    assert payload["actual_migration_revision"] == "0018_printing_sensitive_delivery"

    with factory() as db:
        current = datetime.now(timezone.utc)
        db.add(WorkerHeartbeatRecord(
            worker_id="worker-stale",
            role="worker",
            instance_id="instance-stale",
            state="RUNNING",
            build_sha="a" * 40,
            started_at=current - timedelta(hours=1),
            heartbeat_at=current - timedelta(hours=1),
            scheduler_heartbeat_at=current - timedelta(hours=1),
            metadata_json={},
        ))
        db.commit()
        snapshot = DeepHealthService(
            db,
            config=replace(cfg, worker_stale_seconds=90, scheduler_interval_seconds=30),
            secret_provider=ReadOnlySecretProvider(),
        ).snapshot()
        assert snapshot["database"]["migration_match"] is True
        assert snapshot["production_true_api_write_enabled"] is False
        assert snapshot["blocked_contracts"]["M7"] == "M7_FULL_XML_WRITE_BLOCKED_ON_OFFICIAL_XSD"
        assert snapshot["blocked_contracts"]["M8"] == "M8_FULL_SUZ_WIRE_BLOCKED_ON_OFFICIAL_CORE_SUZ_ARTIFACTS"
        assert snapshot["blocked_contracts"]["M10"] == "M10_EXECUTABLE_READ_CAPABILITIES_NONE"
        assert any(item["code"] == "WORKER_STALLED" for item in snapshot["alerts"])
