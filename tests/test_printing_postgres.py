from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from wbcz.suz_foundation import KmVault, VaultBinding, envelope_to_persistence
from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.models import (
    AuditEventRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantRecord,
    PrintEventRecord,
    PrintJobItemRecord,
    PrintJobRecord,
    PrintTemplateVersionRecord,
    StoredFullKmItemRecord,
    SuzCodeBlockRecord,
    SuzConnectionRecord,
    SuzKmVaultRecord,
    SuzOrderItemRecord,
    SuzOrderRecord,
    User,
)
from wbcz_web.services.printing import (
    LocalPrintingService,
    MANUAL_REVIEW,
    NOT_PRINTABLE,
    PRINTABLE,
    PrintingIntegrityError,
)
from wbcz_web.services.tenant import bind_tenant_scope


DB_URL = os.getenv("WBCZ_TEST_DATABASE_URL") or os.getenv("WBCZ_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="printing PostgreSQL tests require WBCZ_TEST_DATABASE_URL")
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
AUDIT_KEY = b"printing-test-audit-and-cis-hmac-key-0123456789abcdef"
VAULT_KEY = b"K" * 32
SYNTHETIC_CIS = "010460000000001221SYNTHETIC01"
SYNTHETIC_FULL_KM = (SYNTHETIC_CIS + "\x1d91TEST\x1d92SYNTHETIC-SIGNATURE").encode("utf-8")
GTIN = "04600000000012"


class StaticKeyProvider:
    def get_key(self, key_version: str) -> bytes:
        assert key_version == "printing-test-v1"
        return VAULT_KEY


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


def _tenant(db: Session, label: str, inn: str):
    user = User(
        username=f"print-{label}-{uuid4().hex[:8]}",
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
    org = OrganisationRecord(name=f"Printing {label}", is_active=True, created_by_user_id=user.id)
    db.add(org)
    db.flush()
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn=inn,
        display_name=f"Printing {label}",
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


def _second_participant(db: Session, org: OrganisationRecord, inn: str):
    participant = ParticipantRecord(
        organisation_id=org.id,
        inn=inn,
        display_name="Second printing participant",
        verification_state="VERIFIED",
        is_active=True,
    )
    db.add(participant)
    db.flush()
    return participant


def _scope(db: Session, user: User, org: OrganisationRecord, participant: ParticipantRecord) -> None:
    db.info["audit_pseudonym_key"] = AUDIT_KEY
    db.info["audit_pseudonym_key_id"] = "printing-test-v1"
    db.info["audit_trace"] = {
        "request_id": "req-" + uuid4().hex,
        "correlation_id": "corr-" + uuid4().hex,
        "causation_id": None,
    }
    bind_tenant_scope(
        db,
        organisation_id=org.id,
        participant_id=participant.id,
        user_id=user.id,
        role="OWNER",
    )


def _cfg(*, execute: bool = False) -> WebConfig:
    return replace(
        WebConfig.from_env(),
        environment="test",
        printing_enabled=True,
        print_execution_enabled=execute,
        suz_full_km_remote_acquisition_enabled=False,
        agent_enabled=execute,
        agent_legacy_bootstrap_enabled=False if execute else WebConfig.from_env().agent_legacy_bootstrap_enabled,
    ).validate_for_startup()


def _layout(text_value: str = "Synthetic") -> dict:
    return {
        "schema_version": "printing-layout-v1",
        "elements": [
            {
                "type": "DATA_MATRIX_KM",
                "x": 2, "y": 2, "width": 24, "height": 24,
                "module_size_mm": 0.34,
                "quiet_zone_modules": 1,
                "payload_source": "SYSTEM_FULL_KM",
                "rotation": 0,
            },
            {
                "type": "STATIC_TEXT",
                "x": 2, "y": 28, "width": 40, "height": 5,
                "text": text_value,
                "font_family": "Arial",
                "font_size_pt": 8,
                "alignment": "LEFT",
                "rotation": 0,
            },
        ],
    }


def _seed_vault(
    db: Session,
    *,
    user: User,
    org: OrganisationRecord,
    participant: ParticipantRecord,
    cis: str = SYNTHETIC_CIS,
    full_km: bytes = SYNTHETIC_FULL_KM,
):
    _scope(db, user, org, participant)
    connection = SuzConnectionRecord(
        organisation_id=org.id,
        participant_id=participant.id,
        display_name="Synthetic SUZ",
        is_enabled=True,
        participant_inn=participant.inn,
        oms_id="synthetic-oms",
        oms_connection="synthetic-connection-" + participant.id,
        environment="SANDBOX",
        installation_name="synthetic",
        connection_state="ACTIVE",
        local_config_state="CONFIGURED",
        wire_readiness="BLOCKED",
        blocker_code="OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED",
        health_metadata_json={},
    )
    db.add(connection)
    db.flush()
    operation_id = "suz-print-" + uuid4().hex
    order = SuzOrderRecord(
        operation_id=operation_id,
        connection_id=connection.id,
        remote_order_id=None,
        request_sha256=hashlib.sha256(operation_id.encode()).hexdigest(),
        raw_release_method="SYNTHETIC_TEST_ONLY",
        raw_order_status="READY",
        raw_buffer_status="READY",
        requested_count=1,
        generated_count=1,
        fetched_count=1,
        reconciliation_state="LOCAL_VERIFIED",
        submission_state="REMOTE_CONFIRMED",
    )
    db.add(order)
    db.flush()
    item = SuzOrderItemRecord(
        order_id=order.id,
        order_operation_id=order.operation_id,
        gtin=GTIN,
        quantity=1,
        serial_mode="OPERATOR",
        serial_count=0,
    )
    db.add(item)
    db.flush()
    binding = VaultBinding(
        participant_inn=participant.inn,
        oms_connection=connection.oms_connection,
        order_local_id=order.operation_id,
        gtin=GTIN,
        remote_block_id="synthetic-block",
    )
    envelope = KmVault(StaticKeyProvider(), "printing-test-v1").encrypt(
        full_km,
        binding=binding,
        code_count=1,
    )
    vault = SuzKmVaultRecord(
        order_id=order.id,
        order_operation_id=order.operation_id,
        gtin=GTIN,
        remote_block_id="synthetic-block",
        **envelope_to_persistence(envelope),
    )
    db.add(vault)
    db.flush()
    block = SuzCodeBlockRecord(
        local_block_id="local-" + uuid4().hex,
        order_id=order.id,
        order_operation_id=order.operation_id,
        gtin=GTIN,
        remote_block_id="synthetic-block",
        remote_package_id=None,
        code_count=1,
        exact_payload_sha256=envelope.plaintext_sha256,
        vault_entry_id=vault.id,
        fetch_state="COMMITTED",
        recovery_state="NOT_REQUIRED",
        received_at=NOW,
        committed_at=NOW,
    )
    db.add(block)
    db.flush()
    service = LocalPrintingService(
        db,
        _cfg(execute=False),
        key_provider=StaticKeyProvider(),
        cis_hmac_key=AUDIT_KEY,
    )
    stored = service.index_trusted_full_km(
        cis=cis,
        full_km=full_km,
        suz_order_id=order.id,
        suz_order_item_id=item.id,
        suz_code_block_id=block.id,
        vault_entry_id=vault.id,
        gtin=GTIN,
        vault_item_ordinal=0,
        vault_item_offset=0,
        source="MIGRATED_TRUSTED_SOURCE",
        received_at=NOW,
    )
    return service, stored, order, block, vault


def _service(db: Session, *, execute: bool = False) -> LocalPrintingService:
    return LocalPrintingService(
        db,
        _cfg(execute=execute),
        key_provider=StaticKeyProvider(),
        cis_hmac_key=AUDIT_KEY,
    )


def test_0017_schema_has_tenant_constraints_no_plaintext_full_km_and_immutable_triggers(factory):
    with factory() as db:
        inspector = inspect(db.get_bind())
        for table in (
            "stored_full_km_items", "print_templates", "print_template_versions",
            "print_jobs", "print_job_items", "print_events",
        ):
            assert inspector.has_table(table)
        cols = {c["name"] for c in inspector.get_columns("stored_full_km_items")}
        assert "full_km" not in cols
        assert "cis" not in cols
        assert "cis_tail" not in cols
        assert {"cis_hmac", "full_km_sha256", "organisation_id", "participant_id"}.issubset(cols)

        stored_uniques = {tuple(u["column_names"]) for u in inspector.get_unique_constraints("stored_full_km_items")}
        assert ("organisation_id", "participant_id", "cis_hmac") in stored_uniques
        fk_names = {fk["name"] for fk in inspector.get_foreign_keys("stored_full_km_items")}
        assert "fk_stored_full_km_participant_organisation" in fk_names

        checks = {c["name"] for c in inspector.get_check_constraints("stored_full_km_items")}
        assert {"ck_stored_full_km_provenance", "ck_stored_full_km_source"}.issubset(checks)

        triggers = set(db.execute(text(
            "select tgname from pg_trigger where not tgisinternal and tgrelid in "
            "('print_template_versions'::regclass,'print_events'::regclass)"
        )).scalars())
        assert "trg_print_template_versions_immutable" in triggers
        assert "trg_print_events_append_only" in triggers


def test_printability_requires_proven_tenant_bound_valid_encrypted_vault_and_m1_existence_alone_is_not_printable(factory):
    with factory() as db:
        user, org, participant = _tenant(db, "printability", "7707083893")
        service, stored, _, _, _ = _seed_vault(db, user=user, org=org, participant=participant)
        assert service.resolve_printability(SYNTHETIC_CIS).state == PRINTABLE
        assert service.resolve_printability("010460000000001221NOLOCALMAP").state == NOT_PRINTABLE

        raw_remote_result = {
            "items": [{"normalized": {"cis": "010460000000001221REMOTEONLY", "status": "INTRODUCED"}}],
            "raw": {"cis": "010460000000001221REMOTEONLY", "exists": True},
        }
        enriched = service.enrich_m1_result(raw_remote_result)
        assert enriched["items"][0]["normalized"]["printability"]["state"] == NOT_PRINTABLE
        assert "printability" not in enriched["raw"]

        stored.provenance_state = "CONFLICT"
        db.flush()
        assert service.resolve_printability(SYNTHETIC_CIS).state == MANUAL_REVIEW
        stored.provenance_state = "UNKNOWN"
        db.flush()
        assert service.resolve_printability(SYNTHETIC_CIS).state == MANUAL_REVIEW
        stored.provenance_state = "PROVEN"
        stored.full_km_sha256 = "f" * 64
        db.flush()
        projection = service.resolve_printability(SYNTHETIC_CIS)
        assert projection.state == MANUAL_REVIEW
        assert "FULL_KM" in projection.reason


def test_cross_tenant_and_participant_ids_are_non_enumerating_and_unusable(factory):
    with factory() as db:
        user_a, org_a, part_a = _tenant(db, "tenant-a", "500100732259")
        service_a, stored_a, _, _, _ = _seed_vault(db, user=user_a, org=org_a, participant=part_a)
        template_a = service_a.create_template(
            name="Tenant A",
            label_width_mm=50,
            label_height_mm=40,
            layout=_layout(),
            user_id=user_a.id,
        )
        version_a = template_a.current_version_id
        assert version_a

        user_b, org_b, part_b = _tenant(db, "tenant-b", "7800000000")
        _scope(db, user_b, org_b, part_b)
        service_b = _service(db)
        with pytest.raises(KeyError):
            service_b.template_detail(template_a.id)
        template_b = service_b.create_template(
            name="Tenant B",
            label_width_mm=50,
            label_height_mm=40,
            layout=_layout(),
            user_id=user_b.id,
        )
        with pytest.raises(KeyError):
            service_b.create_print_job(
                stored_item_ids=[stored_a.id],
                template_version_id=template_b.current_version_id,
                user_id=user_b.id,
            )

        part_a2 = _second_participant(db, org_a, "7707083894")
        _scope(db, user_a, org_a, part_a2)
        service_a2 = _service(db)
        with pytest.raises(KeyError):
            service_a2.template_detail(template_a.id)
        with pytest.raises(KeyError):
            service_a2._stored_by_id(stored_a.id)


def test_template_versions_are_db_immutable_archive_preserves_history(factory):
    with factory() as db:
        user, org, participant = _tenant(db, "templates", "7712345678")
        _scope(db, user, org, participant)
        service = _service(db)
        template = service.create_template(
            name="Immutable",
            label_width_mm=50,
            label_height_mm=40,
            layout=_layout("v1"),
            user_id=user.id,
        )
        v1_id = template.current_version_id
        v2 = service.create_template_version(
            template.id,
            label_width_mm=50,
            label_height_mm=40,
            layout=_layout("v2"),
            user_id=user.id,
        )
        assert v1_id != v2.id
        assert v2.version_number == 2
        service.archive_template(template.id, user_id=user.id)
        assert template.state == "ARCHIVED"
        db.commit()

    with factory() as db:
        # The database, not only the service, protects historical versions.
        with pytest.raises(DBAPIError):
            db.execute(
                text("update print_template_versions set layout_sha256=:h where id=:id"),
                {"h": "f" * 64, "id": v1_id},
            )
            db.commit()
        db.rollback()
        assert db.get(PrintTemplateVersionRecord, v1_id) is not None
        with pytest.raises(DBAPIError):
            db.execute(text("delete from print_template_versions where id=:id"), {"id": v1_id})
            db.commit()
        db.rollback()


def test_print_job_uses_only_verified_local_km_reprint_keeps_original_version_and_current_is_explicit(factory):
    with factory() as db:
        user, org, participant = _tenant(db, "jobs", "7722334455")
        _, stored, order, block, _ = _seed_vault(db, user=user, org=org, participant=participant)
        service = _service(db, execute=True)
        template = service.create_template(
            name="Jobs",
            label_width_mm=50,
            label_height_mm=40,
            layout=_layout("v1"),
            user_id=user.id,
        )
        v1 = template.current_version_id
        job = service.create_print_job_for_cis(
            cis_values=[SYNTHETIC_CIS],
            template_version_id=v1,
            user_id=user.id,
            printer_profile_id="approved-logical-printer",
        )
        assert job.state == "READY_FOR_AGENT"
        assert job.item_count == 1
        service.mark_completed(job.id, success=True)
        db.flush()
        completed = db.scalar(select(PrintEventRecord).where(
            PrintEventRecord.print_job_id == job.id,
            PrintEventRecord.event_type == "PRINT_JOB_COMPLETED",
        ))
        assert completed is not None
        assert completed.template_version_id == v1

        v2 = service.create_template_version(
            template.id,
            label_width_mm=50,
            label_height_mm=40,
            layout=_layout("v2"),
            user_id=user.id,
        )
        original = service.reprint(completed.id, user_id=user.id, use_current_template=False)
        current = service.reprint(completed.id, user_id=user.id, use_current_template=True)
        assert original.mode == "REPRINT_ORIGINAL_TEMPLATE"
        assert original.template_version_id == v1
        assert current.mode == "PRINT_USING_CURRENT_TEMPLATE"
        assert current.template_version_id == v2.id
        assert original.original_print_event_id == completed.id
        assert current.original_print_event_id == completed.id

        # No local print/reprint mutates CIS/SUZ state or fetches a replacement KM.
        assert stored.provenance_state == "PROVEN"
        assert order.submission_state == "REMOTE_CONFIRMED"
        assert block.fetch_state == "COMMITTED"
        assert service.config.suz_full_km_remote_acquisition_enabled is False

        contract = service.agent_contract(job.id)
        contract_blob = json.dumps(contract, sort_keys=True)
        assert SYNTHETIC_FULL_KM.decode("utf-8") not in contract_blob
        assert contract["sensitive_payload_delivery"] == "BLOCKED_NOT_IMPLEMENTED"
        assert set(contract) == {
            "contract_version", "job_id", "organisation_id", "participant_id",
            "template_version_id", "mode", "printer_profile_id",
            "printer_profile_fingerprint", "items", "sensitive_payload_delivery",
        }
        assert set(contract["items"][0]) == {
            "print_job_item_id", "stored_full_km_item_id", "ordinal", "payload_sha256",
        }

        rows_blob = json.dumps({
            "job": service.job_detail(job.id),
            "stored": {
                "id": stored.id,
                "cis_hmac": stored.cis_hmac,
                "payload_hash": stored.full_km_sha256,
                "provenance": stored.provenance_state,
            },
        }, sort_keys=True)
        assert SYNTHETIC_FULL_KM.decode("utf-8") not in rows_blob


def test_non_printable_job_error_and_audit_print_events_do_not_leak_synthetic_full_km(factory):
    with factory() as db:
        user, org, participant = _tenant(db, "redaction", "7733445566")
        service, stored, _, _, _ = _seed_vault(db, user=user, org=org, participant=participant)
        service = _service(db, execute=True)
        template = service.create_template(
            name="Redaction",
            label_width_mm=50,
            label_height_mm=40,
            layout=_layout(),
            user_id=user.id,
        )
        with pytest.raises(PrintingIntegrityError) as exc:
            service.create_print_job_for_cis(
                cis_values=["010460000000001221NOT-LOCALLY-STORED"],
                template_version_id=template.current_version_id,
                user_id=user.id,
            )
        assert "NOT-LOCALLY-STORED" not in str(exc.value)
        assert SYNTHETIC_FULL_KM.decode("utf-8") not in str(exc.value)

        job = service.create_print_job_for_cis(
            cis_values=[SYNTHETIC_CIS],
            template_version_id=template.current_version_id,
            user_id=user.id,
        )
        service.mark_completed(job.id, success=True)
        db.flush()

        audit_rows = list(db.scalars(select(AuditEventRecord).where(
            AuditEventRecord.category == "PRINTING",
            AuditEventRecord.organisation_id == org.id,
        )))
        assert audit_rows
        audit_blob = json.dumps([
            {
                "event_type": row.event_type,
                "metadata": row.metadata_sanitized_json,
                "evidence_hashes": row.evidence_hashes_json,
            }
            for row in audit_rows
        ], sort_keys=True)
        assert SYNTHETIC_FULL_KM.decode("utf-8") not in audit_blob
        assert SYNTHETIC_CIS not in audit_blob

        print_events = list(db.scalars(select(PrintEventRecord).where(PrintEventRecord.organisation_id == org.id)))
        print_blob = json.dumps([
            {
                "payload_hash": row.payload_hash,
                "metadata": row.metadata_sanitized_json,
                "error_code": row.error_code,
            }
            for row in print_events
        ], sort_keys=True)
        assert SYNTHETIC_FULL_KM.decode("utf-8") not in print_blob
        assert SYNTHETIC_CIS not in print_blob


def test_printing_tables_have_no_plaintext_full_km_column(factory):
    with factory() as db:
        inspector = inspect(db.get_bind())
        for table in ("stored_full_km_items", "print_jobs", "print_job_items", "print_events"):
            names = {column["name"].lower() for column in inspector.get_columns(table)}
            assert "full_km" not in names
            assert "payload" not in names
        assert "full_km_sha256" in {c["name"] for c in inspector.get_columns("stored_full_km_items")}
