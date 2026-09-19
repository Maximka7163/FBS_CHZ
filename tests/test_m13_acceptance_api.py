from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from io import BytesIO
import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from wbcz.aggregation import (
    AggregationDocument,
    AggregationOperationKind,
    AggregationReconciliationResult,
    AggregationReconciliationState,
    AggregationUnit,
    UnitSerialNumberType,
    prepare_aggregation_document,
)
from wbcz.m11_reports import ReportSensitivity
from wbcz.turnover import (
    CisSnapshot,
    LkReceiptDistanceDocument,
    LpReturnDocument,
    ModLocation,
    ReturnProduct,
    TurnoverOperationKind,
    WithdrawalProduct,
    prepare_turnover_document,
)
from wbcz_web.auth import hash_password, token_hash
from wbcz_web.config import WebConfig
from wbcz_web.main import create_app
from wbcz_web.models import (
    AgentJobRecord,
    AggregationOperationLedgerRecord,
    AuditEventRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantRecord,
    ReportArtifactRecord,
    ReportJobRecord,
    SessionRecord,
    TurnoverOperationLedgerRecord,
    User,
)
from wbcz_web.services import AuthService
from wbcz_web.services.aggregation import AggregationApplicationService
from wbcz_web.services.audit_history import (
    ActorContext,
    ActorKind,
    AuditError,
    AuditOutcome,
    AuditService,
    AuditTenantScope,
    AuthorizationDecision,
    SubjectRef,
    SubjectType,
)
from wbcz_web.services.authorization import ActiveScope, Role, ROLE_PERMISSIONS
from wbcz_web.services.report_downloads import ReportDownloadService
from wbcz_web.services.turnover import TurnoverApplicationService


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL") or os.getenv("WBCZ_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="M13 acceptance tests require PostgreSQL")
AUDIT_KEY_TEXT = "m13-test-only-audit-pseudonym-key-0000000000000001"
AUDIT_KEY = AUDIT_KEY_TEXT.encode("utf-8")
PASSWORD = "correct horse battery staple"
NOW = lambda: datetime.now(timezone.utc)


def _factory():
    engine = create_engine(DB_URL, future=True)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def _random_inn() -> str:
    return str(700_000_000_000 + (int(uuid4().hex[:10], 16) % 90_000_000_000))


def _seed_tenant(db: Session, *, role: Role, org_name: str | None = None):
    username = "m13-" + uuid4().hex
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
    db.add(user)
    db.flush()
    org = OrganisationRecord(
        name=org_name or ("Org " + uuid4().hex[:8]),
        is_active=True,
        created_by_user_id=user.id,
    )
    db.add(org)
    db.flush()
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn=_random_inn(),
        display_name=org.name,
        verification_state="VERIFIED",
        is_active=True,
    )
    db.add(participant)
    db.flush()
    membership = MembershipRecord(
        organisation_id=org.id,
        user_id=user.id,
        role=role.value,
        is_active=True,
        created_by_user_id=user.id,
    )
    db.add(membership)
    db.flush()
    return user, org, participant, membership


def _add_user_to_org(db: Session, org: OrganisationRecord, participant: ParticipantRecord, role: Role):
    user = User(
        username="m13-" + uuid4().hex,
        account_state="ACTIVE",
        password_hash=hash_password(PASSWORD),
        is_active=True,
        is_admin=False,
        password_changed_at=NOW(),
        password_version=1,
        password_must_change=False,
    )
    db.add(user)
    db.flush()
    membership = MembershipRecord(
        organisation_id=org.id,
        user_id=user.id,
        role=role.value,
        is_active=True,
        created_by_user_id=user.id,
    )
    db.add(membership)
    db.flush()
    return user, membership


def _session(db: Session, user: User, org: OrganisationRecord, participant: ParticipantRecord):
    raw = "m13-session-" + uuid4().hex
    row = SessionRecord(
        user_id=user.id,
        token_hash=token_hash(raw),
        active_organisation_id=org.id,
        active_participant_id=participant.id,
        password_version=user.password_version,
        created_at=NOW(),
        last_seen_at=NOW(),
        expires_at=NOW() + timedelta(hours=2),
    )
    db.add(row)
    db.flush()
    return row, raw


def _config(**changes):
    cfg = WebConfig.from_env()
    return replace(
        cfg,
        audit_pseudonym_key=AUDIT_KEY_TEXT,
        audit_pseudonym_key_id="m13-test-v1",
        **changes,
    )


def test_audit_query_api_is_tenant_scoped_role_gated_keyset_and_audited():
    engine, factory = _factory()
    try:
        with factory() as db:
            admin, org_a, part_a, _ = _seed_tenant(db, role=Role.ADMIN, org_name="Audit API A " + uuid4().hex[:6])
            viewer, _ = _add_user_to_org(db, org_a, part_a, Role.VIEWER)
            foreign, org_b, part_b, _ = _seed_tenant(db, role=Role.ADMIN, org_name="Audit API B " + uuid4().hex[:6])
            _, admin_raw = _session(db, admin, org_a, part_a)
            _, viewer_raw = _session(db, viewer, org_a, part_a)
            service = AuditService(db, pseudonym_key=AUDIT_KEY, pseudonym_key_id="m13-test-v1")
            own = service.append(
                event_type="REPORT_REQUESTED",
                actor=ActorContext(ActorKind.USER, user_id=admin.id),
                tenant=AuditTenantScope(org_a.id, part_a.id),
                subject=SubjectRef(SubjectType.REPORT_JOB, "own-report-" + uuid4().hex),
                outcome=AuditOutcome.PENDING,
                authorization_decision=AuthorizationDecision.ALLOW,
                metadata={
                    "report_job_id": "own-report",
                    "report_type": "DOCUMENT_LIFECYCLE",
                    "format": "CSV",
                    "sensitivity_class": "NORMAL",
                    "schema_version": "1",
                    "request_fingerprint_sha256": "a" * 64,
                    "origin": "LOCAL",
                },
            )
            foreign_event = service.append(
                event_type="REPORT_REQUESTED",
                actor=ActorContext(ActorKind.USER, user_id=foreign.id),
                tenant=AuditTenantScope(org_b.id, part_b.id),
                subject=SubjectRef(SubjectType.REPORT_JOB, "foreign-report-" + uuid4().hex),
                outcome=AuditOutcome.PENDING,
                authorization_decision=AuthorizationDecision.ALLOW,
                metadata={
                    "report_job_id": "foreign-report",
                    "report_type": "DOCUMENT_LIFECYCLE",
                    "format": "CSV",
                    "sensitivity_class": "NORMAL",
                    "schema_version": "1",
                    "request_fingerprint_sha256": "b" * 64,
                    "origin": "LOCAL",
                },
            )
            db.commit()

        app = create_app(_config(), session_factory=factory)
        admin_client = TestClient(app, raise_server_exceptions=False)
        admin_client.cookies.set(app.state.config.session_cookie_name, admin_raw)

        listed = admin_client.get("/api/audit/events", params={"category": "REPORT", "limit": 1})
        assert listed.status_code == 200
        body = listed.json()
        assert body["limit"] == 1
        assert len(body["events"]) == 1
        assert body["events"][0]["event_id"] == own.event_id
        assert body["next_before_sequence"] == body["events"][0]["sequence"]

        foreign_detail = admin_client.get(f"/api/audit/events/{foreign_event.event_id}")
        assert foreign_detail.status_code == 404
        foreign_participant = admin_client.get("/api/audit/events", params={"participant_id": part_b.id})
        assert foreign_participant.status_code == 404
        invalid_limit = admin_client.get("/api/audit/events", params={"limit": 201})
        assert invalid_limit.status_code == 422

        viewer_client = TestClient(app, raise_server_exceptions=False)
        viewer_client.cookies.set(app.state.config.session_cookie_name, viewer_raw)
        denied = viewer_client.get("/api/audit/events")
        assert denied.status_code == 403

        with factory() as db:
            own_chain = AuditService(db, pseudonym_key=AUDIT_KEY).chain_for_organisation(org_a.id)
            events = list(db.scalars(
                select(AuditEventRecord)
                .where(AuditEventRecord.chain_id == own_chain.chain_id)
                .order_by(AuditEventRecord.sequence)
            ))
            assert any(row.event_type == "AUDIT_QUERY_EXECUTED" for row in events)
            denials = [row for row in events if row.event_type == "AUTHORIZATION_DENIED"]
            assert len(denials) >= 3
            denial_blob = repr([
                (row.subject_id, row.metadata_sanitized_json)
                for row in denials
            ])
            assert foreign_event.event_id not in denial_blob
            assert org_b.id not in denial_blob
            assert part_b.id not in denial_blob
    finally:
        engine.dispose()


def test_login_success_audit_failure_rolls_back_usable_session(monkeypatch):
    engine, factory = _factory()
    try:
        with factory() as seed:
            user = User(
                username="audit-login-" + uuid4().hex,
                account_state="ACTIVE",
                password_hash=hash_password(PASSWORD),
                is_active=True,
                is_admin=False,
                password_changed_at=NOW(),
                password_version=1,
                password_must_change=False,
            )
            seed.add(user)
            seed.commit()
            user_id = user.id
            username = user.username

        def fail_append(*args, **kwargs):
            raise AuditError("forced immutable audit failure")

        monkeypatch.setattr(AuditService, "append", fail_append)
        with factory() as db:
            db.info["audit_pseudonym_key"] = AUDIT_KEY
            db.info["audit_pseudonym_key_id"] = "m13-test-v1"
            with pytest.raises(AuditError):
                AuthService(db, _config()).login(
                    username,
                    PASSWORD,
                    csrf_token="synthetic-csrf",
                    remote_address="192.0.2.44",
                    user_agent="synthetic-agent",
                )
            db.rollback()

        with factory() as check:
            assert check.scalar(
                select(SessionRecord).where(
                    SessionRecord.user_id == user_id,
                    SessionRecord.revoked_at.is_(None),
                )
            ) is None
    finally:
        engine.dispose()


def test_sensitive_report_download_audit_failure_releases_no_handle(monkeypatch, tmp_path: Path):
    engine, factory = _factory()
    try:
        with factory() as db:
            user, org, part, _ = _seed_tenant(db, role=Role.OPERATOR)
            job = ReportJobRecord(
                id="m13-rpt-" + uuid4().hex,
                organisation_id=org.id,
                participant_id=part.id,
                origin="LOCAL",
                participant_inn=part.inn,
                report_type="DOCUMENT_LIFECYCLE",
                report_schema_version="1",
                output_format="CSV",
                sensitivity_class=ReportSensitivity.MARKING_SENSITIVE.value,
                filters_sanitized_json={},
                request_fingerprint_sha256="c" * 64,
                state="READY",
                remote_metadata_sanitized={},
                remote_create_ambiguous=False,
                requested_at=NOW(),
                attempt_count=0,
            )
            db.add(job)
            db.flush()
            artifact = ReportArtifactRecord(
                artifact_id="m13-art-" + uuid4().hex,
                report_job_id=job.id,
                artifact_role="OUTPUT",
                publication_key="pub-" + uuid4().hex,
                state="READY",
                storage_backend="FILESYSTEM",
                storage_key="synthetic.bin",
                format="CSV",
                mime="text/csv",
                safe_filename="synthetic.csv",
                byte_size=6,
                sha256="d" * 64,
                sensitivity_class=ReportSensitivity.MARKING_SENSITIVE.value,
                encryption_metadata={},
            )
            db.add(artifact)
            db.flush()
            db.info["tenant_scope"] = {
                "user_id": user.id,
                "organisation_id": org.id,
                "participant_id": part.id,
                "participant_inn": part.inn,
                "role": Role.OPERATOR.value,
            }
            db.info["audit_pseudonym_key"] = AUDIT_KEY
            db.info["audit_pseudonym_key_id"] = "m13-test-v1"
            scope = ActiveScope(
                user.id,
                org.id,
                part.id,
                part.inn,
                Role.OPERATOR,
                ROLE_PERMISSIONS[Role.OPERATOR],
            )
            service = ReportDownloadService(
                db,
                _config(report_artifact_root=str(tmp_path), report_temp_root=str(tmp_path / "tmp")),
            )
            monkeypatch.setattr(service, "_open_verified", lambda job_row, art_row: BytesIO(b"secret"))

            def fail_append(*args, **kwargs):
                raise AuditError("forced immutable audit failure")

            monkeypatch.setattr(AuditService, "append", fail_append)
            with pytest.raises(AuditError):
                service.open_download(scope, job_id=job.id, artifact_id=artifact.artifact_id)
            db.rollback()
    finally:
        engine.dispose()


@pytest.mark.parametrize("operation_kind", ["DISTANCE", "REMOTE_SALE_RETURN"])
def test_m5_business_intent_remote_result_reconciliation_are_immutable_and_sanitized(operation_kind: str):
    engine, factory = _factory()
    try:
        with factory() as db:
            user, org, part, _ = _seed_tenant(db, role=Role.OPERATOR)
            db.info["tenant_scope"] = {
                "user_id": user.id,
                "organisation_id": org.id,
                "participant_id": part.id,
                "participant_inn": part.inn,
                "role": Role.OPERATOR.value,
            }
            db.info["audit_pseudonym_key"] = AUDIT_KEY
            db.info["audit_pseudonym_key_id"] = "m13-test-v1"
            cfg = _config(agent_enabled=True, agent_machine_token="0123456789abcdef")
            cis = "010123456789012321SYNTHETIC-M13"
            if operation_kind == "DISTANCE":
                prepared = prepare_turnover_document(
                    TurnoverOperationKind.WITHDRAW_DISTANCE,
                    LkReceiptDistanceDocument(
                        inn=part.inn,
                        action_date=date(2026, 9, 19),
                        products=(WithdrawalProduct(cis, 100),),
                        mod=ModLocation(
                            fias_id="550e8400-e29b-41d4-a716-446655440000",
                            legal_entity=True,
                            kpp="123456789",
                        ),
                    ),
                )
                post = CisSnapshot(
                    cis=cis,
                    status="RETIRED",
                    status_ex=None,
                    owner_inn=part.inn,
                    withdraw_reason="DISTANCE",
                    fetched_at=NOW(),
                )
            else:
                prepared = prepare_turnover_document(
                    TurnoverOperationKind.RETURN_REMOTE_SALE,
                    LpReturnDocument(
                        trade_participant_inn=part.inn,
                        products_list=(ReturnProduct(cis),),
                        paid=False,
                        return_type="REMOTE_SALE_RETURN",
                    ),
                )
                post = CisSnapshot(
                    cis=cis,
                    status="INTRODUCED",
                    status_ex=None,
                    owner_inn=part.inn,
                    withdraw_reason=None,
                    fetched_at=NOW(),
                )

            service = TurnoverApplicationService(db, cfg)
            queued = service.queue_prevalidated(
                prepared,
                operation_id="acceptance-" + uuid4().hex,
                precondition_snapshot={"verified_fresh": True, "observed": []},
            )
            service.record_remote_document(queued["operation_id"], "remote-doc-" + uuid4().hex)
            service.reconcile(
                queued["operation_id"],
                document_status_raw="CHECKED_OK",
                cis_snapshots=(post,),
            )
            events = list(db.scalars(
                select(AuditEventRecord).where(
                    AuditEventRecord.organisation_id == org.id,
                    AuditEventRecord.operation_id == queued["operation_id"],
                    AuditEventRecord.event_type.in_([
                        "TURNOVER_INTENT_CREATED",
                        "TURNOVER_REMOTE_RESULT",
                        "TURNOVER_RECONCILED",
                    ]),
                )
            ))
            assert {row.event_type for row in events} == {
                "TURNOVER_INTENT_CREATED",
                "TURNOVER_REMOTE_RESULT",
                "TURNOVER_RECONCILED",
            }
            persisted = repr([
                (row.metadata_sanitized_json, row.evidence_hashes_json)
                for row in events
            ])
            assert cis not in persisted
            assert prepared.exact_document.product_document_base64 not in persisted
            db.rollback()
    finally:
        engine.dispose()


def test_m6_business_intent_remote_result_reconciliation_are_immutable_and_sanitized():
    engine, factory = _factory()
    try:
        with factory() as db:
            user, org, part, _ = _seed_tenant(db, role=Role.OPERATOR)
            db.info["tenant_scope"] = {
                "user_id": user.id,
                "organisation_id": org.id,
                "participant_id": part.id,
                "participant_inn": part.inn,
                "role": Role.OPERATOR.value,
            }
            db.info["audit_pseudonym_key"] = AUDIT_KEY
            db.info["audit_pseudonym_key_id"] = "m13-test-v1"
            cfg = _config(agent_enabled=True, agent_machine_token="0123456789abcdef")
            parent = "010123456789012321SYNTHETIC-PARENT"
            child = "010123456789012321SYNTHETIC-CHILD"
            prepared = prepare_aggregation_document(
                AggregationOperationKind.FORM_TRANSPORT_PACKAGE,
                AggregationDocument(
                    part.inn,
                    (AggregationUnit(parent, UnitSerialNumberType.BOX, (child,)),),
                ),
            )
            service = AggregationApplicationService(db, cfg)
            queued = service.queue_prevalidated(
                prepared,
                operation_id="acceptance-" + uuid4().hex,
                precondition_snapshot={"verified_fresh": True, "observed": []},
                parent_cis=parent,
                child_cises=(child,),
                expected_relation_delta={"action": "FORM"},
            )
            service.record_remote_document(queued["operation_id"], "remote-doc-" + uuid4().hex)
            service.record_reconciliation(
                queued["operation_id"],
                AggregationReconciliationResult(
                    AggregationReconciliationState.RECONCILED,
                    "EXACT_RELATION_CONFIRMED",
                    parent,
                ),
            )
            events = list(db.scalars(
                select(AuditEventRecord).where(
                    AuditEventRecord.organisation_id == org.id,
                    AuditEventRecord.operation_id == queued["operation_id"],
                    AuditEventRecord.event_type.in_([
                        "AGGREGATION_INTENT_CREATED",
                        "AGGREGATION_REMOTE_RESULT",
                        "AGGREGATION_RECONCILED",
                    ]),
                )
            ))
            assert {row.event_type for row in events} == {
                "AGGREGATION_INTENT_CREATED",
                "AGGREGATION_REMOTE_RESULT",
                "AGGREGATION_RECONCILED",
            }
            persisted = repr([
                (row.metadata_sanitized_json, row.evidence_hashes_json)
                for row in events
            ])
            assert parent not in persisted
            assert child not in persisted
            assert prepared.exact_document.product_document_base64 not in persisted
            db.rollback()
    finally:
        engine.dispose()


def test_remote_intent_audit_failure_rolls_back_domain_intent_and_agent_job(monkeypatch):
    engine, factory = _factory()
    try:
        with factory() as db:
            user, org, part, _ = _seed_tenant(db, role=Role.OPERATOR)
            org_id = org.id
            db.info["tenant_scope"] = {
                "user_id": user.id,
                "organisation_id": org.id,
                "participant_id": part.id,
                "participant_inn": part.inn,
                "role": Role.OPERATOR.value,
            }
            db.info["audit_pseudonym_key"] = AUDIT_KEY
            db.info["audit_pseudonym_key_id"] = "m13-test-v1"
            cis = "010123456789012321SYNTHETIC-FAIL"
            prepared = prepare_turnover_document(
                TurnoverOperationKind.WITHDRAW_DISTANCE,
                LkReceiptDistanceDocument(
                    inn=part.inn,
                    action_date=date(2026, 9, 19),
                    products=(WithdrawalProduct(cis, 100),),
                    mod=ModLocation(
                        fias_id="550e8400-e29b-41d4-a716-446655440000",
                        legal_entity=True,
                        kpp="123456789",
                    ),
                ),
            )

            def fail_append(*args, **kwargs):
                raise AuditError("forced immutable audit failure")

            monkeypatch.setattr(AuditService, "append", fail_append)
            with pytest.raises(AuditError):
                TurnoverApplicationService(
                    db,
                    _config(agent_enabled=True, agent_machine_token="0123456789abcdef"),
                ).queue_prevalidated(
                    prepared,
                    operation_id="fail-" + uuid4().hex,
                    precondition_snapshot={"verified_fresh": True, "observed": []},
                )
            db.rollback()

        with factory() as check:
            assert check.scalar(
                select(TurnoverOperationLedgerRecord).where(
                    TurnoverOperationLedgerRecord.organisation_id == org_id
                )
            ) is None
            assert check.scalar(
                select(AgentJobRecord).where(AgentJobRecord.organisation_id == org_id)
            ) is None
    finally:
        engine.dispose()
