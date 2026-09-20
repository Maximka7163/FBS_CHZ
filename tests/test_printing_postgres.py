from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from cryptography.hazmat.primitives.asymmetric import x25519

from wbcz.printing_sensitive import open_full_km
from wbcz.suz_foundation import KmVault, VaultBinding, envelope_to_persistence
from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.models import (
    AgentBindingEncryptionKeyRecord,
    AgentBindingRecord,
    AuditEventRecord,
    MembershipRecord,
    OrganisationRecord,
    ParticipantRecord,
    PrintEncryptionKeyIntentRecord,
    PrintExecutionRecord,
    PrintEventRecord,
    PrintJobItemRecord,
    PrintJobRecord,
    PrintPayloadDeliveryReservationRecord,
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
from wbcz_web.services.agent_bindings import AgentBindingService
from wbcz_web.services.printing_sensitive_delivery import (
    SensitiveDeliveryRejected,
    SensitivePrintingDeliveryService,
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


PRINTING_MIGRATION = "0018_printing_sensitive_delivery"
PRINTING_TABLES = {
    "users",
    "organisations",
    "stored_full_km_items",
    "print_templates",
    "print_template_versions",
    "print_jobs",
    "print_job_items",
    "print_events",
    "agent_binding_encryption_keys",
    "print_encryption_key_intents",
    "print_executions",
    "print_payload_delivery_reservations",
}
PRINTING_TRIGGERS = {
    "trg_print_template_versions_immutable",
    "trg_print_events_append_only",
}


def _ensure_printing_schema(engine) -> None:
    inspector = inspect(engine)
    revision = None
    if inspector.has_table("alembic_version"):
        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()

    tables = set(inspector.get_table_names())
    with engine.connect() as connection:
        triggers = set(connection.execute(text(
            "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal "
            "AND tgname IN ('trg_print_template_versions_immutable', 'trg_print_events_append_only')"
        )).scalars())

    schema_valid = (
        revision == PRINTING_MIGRATION
        and PRINTING_TABLES.issubset(tables)
        and triggers == PRINTING_TRIGGERS
    )
    if schema_valid:
        return

    # Full-suite legacy PostgreSQL fixtures may call Base.metadata.drop_all/create_all
    # against the shared test database while leaving alembic_version untouched.
    # A migration upgrade from an already-stamped head is then a no-op, so rebuild
    # the test schema deterministically before exercising migration-specific invariants.
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")

    alembic = AlembicConfig(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(alembic, PRINTING_MIGRATION)

    inspector = inspect(engine)
    with engine.connect() as connection:
        restored_revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        restored_triggers = set(connection.execute(text(
            "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal "
            "AND tgname IN ('trg_print_template_versions_immutable', 'trg_print_events_append_only')"
        )).scalars())
    assert restored_revision == PRINTING_MIGRATION
    assert PRINTING_TABLES.issubset(set(inspector.get_table_names()))
    assert restored_triggers == PRINTING_TRIGGERS


@pytest.fixture
def factory():
    cfg = WebConfig.from_env()
    fac = build_session_factory(cfg)
    engine = fac.kw["bind"]
    _ensure_printing_schema(engine)
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



def _v2_binding(db: Session, org: OrganisationRecord, participant: ParticipantRecord) -> AgentBindingRecord:
    row = AgentBindingRecord(
        organisation_id=org.id,
        participant_id=participant.id,
        installation_id=str(uuid4()),
        display_name="Printing v2 synthetic agent",
        protocol_version="m15-v1",
        agent_version="0.5.1",
        credential_hash=hashlib.sha256(uuid4().bytes).hexdigest(),
        credential_version=1,
        state="ACTIVE",
        is_primary=True,
        last_seen_at=datetime.now(timezone.utc),
        protocol_compatibility_state="COMPATIBLE",
        supported_job_types_json=[],
        supported_capabilities_json=[
            "PRINTING_SENSITIVE_DELIVERY_V1",
            "HPKE_X25519_AES128GCM_V1",
        ],
        capabilities_sanitized={},
    )
    db.add(row)
    db.flush()
    return row


def _sensitive_ready(db: Session, *, full_km: bytes = SYNTHETIC_FULL_KM):
    user, org, participant = _tenant(db, "v2", "7707083893")
    _, stored, _, _, vault = _seed_vault(
        db, user=user, org=org, participant=participant, full_km=full_km
    )
    printing = _service(db, execute=True)
    template = printing.create_template(
        name="Sensitive delivery",
        label_width_mm=50,
        label_height_mm=35,
        layout=_layout("Sensitive"),
        user_id=user.id,
    )
    version = db.get(PrintTemplateVersionRecord, template.current_version_id)
    assert version is not None
    job = printing.create_print_job(
        stored_item_ids=[stored.id],
        template_version_id=version.id,
        user_id=user.id,
    )
    item = db.scalar(select(PrintJobItemRecord).where(PrintJobItemRecord.print_job_id == job.id))
    assert item is not None
    binding = _v2_binding(db, org, participant)
    sensitive = SensitivePrintingDeliveryService(
        db, _cfg(execute=True), key_provider=StaticKeyProvider()
    )
    private = x25519.X25519PrivateKey.generate()
    intent, raw = sensitive.create_key_intent(binding.id, purpose="FIRST_REGISTRATION", user_id=user.id)
    key = sensitive.register_public_key(
        agent_binding_id=binding.id,
        intent_token=raw,
        public_key_raw=private.public_key().public_bytes_raw(),
    )
    execution, reservation = sensitive.authorize_delivery(
        print_job_id=job.id,
        print_job_item_id=item.id,
        agent_binding_id=binding.id,
        user_id=user.id,
    )
    return user, org, participant, stored, vault, job, item, binding, key, private, sensitive, execution, reservation


def test_0018_sensitive_delivery_schema_has_no_secret_payload_columns(factory):
    with factory() as db:
        inspector = inspect(db.get_bind())
        expected = {
            "agent_binding_encryption_keys",
            "print_encryption_key_intents",
            "print_executions",
            "print_payload_delivery_reservations",
        }
        assert expected.issubset(set(inspector.get_table_names()))
        for table in expected:
            names = {column["name"].lower() for column in inspector.get_columns(table)}
            assert "full_km" not in names
            assert "private_key" not in names
            assert "ciphertext" not in names
            assert "cek" not in names
        key_columns = {column["name"] for column in inspector.get_columns("agent_binding_encryption_keys")}
        assert {"public_key", "public_key_fingerprint", "key_version", "state"}.issubset(key_columns)


def test_sensitive_delivery_exact_hpke_roundtrip_reissue_ack_and_canary_redaction(factory):
    canary = (
        SYNTHETIC_CIS + "\x1d91PHASEA\x1d92SENSITIVE-CANARY-7f193a"
    ).encode("utf-8")
    with factory() as db:
        (
            _, _, _, _, _, _, item, binding, key, private, sensitive, execution, reservation
        ) = _sensitive_ready(db, full_km=canary)

        envelopes = [
            sensitive.issue(reservation.id, machine_binding_id=binding.id)
            for _ in range(3)
        ]
        for envelope in envelopes:
            plaintext = open_full_km(
                recipient_private_key_raw=private.private_bytes_raw(),
                enc_b64=envelope["enc"],
                ciphertext_b64=envelope["ciphertext"],
                context=envelope["context"],
            )
            assert plaintext == canary
            assert hashlib.sha256(plaintext).hexdigest() == item.payload_hash
        with pytest.raises(SensitiveDeliveryRejected, match="DELIVERY_ISSUE_LIMIT_REACHED"):
            sensitive.issue(reservation.id, machine_binding_id=binding.id)

        # A max-issue rejection blocks that reservation, so create a second
        # execution only after explicitly terminalizing the first synthetic attempt.
        reservation.state = "REVOKED"
        execution.state = "CANCELLED_PRE_SPOOL"
        execution.terminal_at = datetime.now(timezone.utc)
        db.flush()
        second_execution, second_reservation = sensitive.authorize_delivery(
            print_job_id=execution.print_job_id,
            print_job_item_id=execution.print_job_item_id,
            agent_binding_id=binding.id,
            user_id=db.scalar(select(User.id).where(User.username.like("print-v2-%"))),
        )
        envelope = sensitive.issue(second_reservation.id, machine_binding_id=binding.id)
        ack = sensitive.acknowledge(
            second_reservation.id,
            machine_binding_id=binding.id,
            payload_sha256=envelope["payload_sha256"],
            context_sha256=envelope["context_sha256"],
        )
        assert ack["state"] == "ACKNOWLEDGED"
        assert second_execution.state == "PAYLOAD_DELIVERED"
        assert second_reservation.state == "ACKNOWLEDGED"

        needle = "SENSITIVE-CANARY-7f193a"
        for model in (
            PrintExecutionRecord,
            PrintPayloadDeliveryReservationRecord,
            AgentBindingEncryptionKeyRecord,
            PrintEncryptionKeyIntentRecord,
            AuditEventRecord,
        ):
            rows = list(db.scalars(select(model)))
            assert needle not in json.dumps([str(row.__dict__) for row in rows], ensure_ascii=False)
        agent_payloads = list(db.execute(text("SELECT payload_json::text FROM agent_jobs")).scalars())
        assert all(needle not in (value or "") for value in agent_payloads)
        assert key.public_key != canary


def test_print_key_intent_is_one_use_and_rotation_retires_old_key(factory):
    with factory() as db:
        user, _, _, _, _, _, _, binding, first, _, sensitive, execution, reservation = _sensitive_ready(db)
        with pytest.raises(SensitiveDeliveryRejected, match="INVALID_PRINT_KEY_INTENT"):
            # Verify bearer-only replacement fails without an operator-created intent.
            sensitive.register_public_key(
                agent_binding_id=binding.id,
                intent_token="x" * 64,
                public_key_raw=x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
            )
        intent, raw = sensitive.create_key_intent(binding.id, purpose="ROTATE", user_id=user.id)
        second_private = x25519.X25519PrivateKey.generate()
        second = sensitive.register_public_key(
            agent_binding_id=binding.id,
            intent_token=raw,
            public_key_raw=second_private.public_key().public_bytes_raw(),
        )
        with pytest.raises(SensitiveDeliveryRejected, match="PRINT_KEY_INTENT_ALREADY_USED"):
            sensitive.register_public_key(
                agent_binding_id=binding.id,
                intent_token=raw,
                public_key_raw=x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
            )
        assert first.state == "RETIRING"
        assert first.retiring_at is not None
        assert second.state == "ACTIVE"
        assert second.key_version == first.key_version + 1
        assert reservation.agent_encryption_key_id == first.id
        # Already-bound reservation remains usable with the retiring key.
        envelope = sensitive.issue(reservation.id, machine_binding_id=binding.id)
        assert envelope["recipient_key_version"] == first.key_version

        expired, expired_raw = sensitive.create_key_intent(binding.id, purpose="ROTATE", user_id=user.id)
        expired.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.flush()
        with pytest.raises(SensitiveDeliveryRejected, match="PRINT_KEY_INTENT_EXPIRED"):
            sensitive.register_public_key(
                agent_binding_id=binding.id,
                intent_token=expired_raw,
                public_key_raw=x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
            )


def test_binding_disable_revokes_recipient_keys_and_active_reservation(factory):
    with factory() as db:
        user, _, _, _, _, _, _, binding, key, _, _, execution, reservation = _sensitive_ready(db)
        AgentBindingService(db).disable(binding.id, user_id=user.id)
        assert key.state == "REVOKED"
        assert reservation.state == "REVOKED"
        assert reservation.safe_error_code == "AGENT_BINDING_DISABLED"
        assert execution.state == "BLOCKED"
        assert execution.safe_error_code == "AGENT_BINDING_DISABLED"


def test_wrong_ack_fails_closed_before_spool(factory):
    with factory() as db:
        _, _, _, _, _, _, _, binding, _, _, sensitive, execution, reservation = _sensitive_ready(db)
        envelope = sensitive.issue(reservation.id, machine_binding_id=binding.id)
        with pytest.raises(SensitiveDeliveryRejected, match="DELIVERY_ACK_INTEGRITY_MISMATCH"):
            sensitive.acknowledge(
                reservation.id,
                machine_binding_id=binding.id,
                payload_sha256="0" * 64,
                context_sha256=envelope["context_sha256"],
            )
        assert reservation.state == "BLOCKED"
        assert execution.state == "FAILED_PRE_SPOOL"


def test_oversized_encrypted_vault_entry_is_blocked_before_delivery(factory):
    oversized = SYNTHETIC_CIS.encode("utf-8") + b"A" * 4096
    with factory() as db:
        user, org, participant = _tenant(db, "oversized", "7707083893")
        _, stored, _, _, _ = _seed_vault(
            db, user=user, org=org, participant=participant, full_km=oversized
        )
        printing = _service(db, execute=True)
        template = printing.create_template(
            name="Oversized",
            label_width_mm=50,
            label_height_mm=35,
            layout=_layout("Oversized"),
            user_id=user.id,
        )
        job = printing.create_print_job(
            stored_item_ids=[stored.id],
            template_version_id=template.current_version_id,
            user_id=user.id,
        )
        item = db.scalar(select(PrintJobItemRecord).where(PrintJobItemRecord.print_job_id == job.id))
        binding = _v2_binding(db, org, participant)
        cfg = replace(_cfg(execute=True), max_print_delivery_vault_entry_bytes=1024).validate_for_startup()
        sensitive = SensitivePrintingDeliveryService(db, cfg, key_provider=StaticKeyProvider())
        private = x25519.X25519PrivateKey.generate()
        _, raw = sensitive.create_key_intent(binding.id, purpose="FIRST_REGISTRATION", user_id=user.id)
        sensitive.register_public_key(
            agent_binding_id=binding.id,
            intent_token=raw,
            public_key_raw=private.public_key().public_bytes_raw(),
        )
        with pytest.raises(SensitiveDeliveryRejected, match="VAULT_ENTRY_TOO_LARGE_FOR_SAFE_PRINT_DELIVERY"):
            sensitive.authorize_delivery(
                print_job_id=job.id,
                print_job_item_id=item.id,
                agent_binding_id=binding.id,
                user_id=user.id,
            )


def test_foreign_participant_binding_cannot_authorize_delivery(factory):
    with factory() as db:
        user, org, participant = _tenant(db, "tenant-a", "7707083893")
        _, stored, _, _, _ = _seed_vault(db, user=user, org=org, participant=participant)
        printing = _service(db, execute=True)
        template = printing.create_template(
            name="Tenant A",
            label_width_mm=50,
            label_height_mm=35,
            layout=_layout("Tenant A"),
            user_id=user.id,
        )
        job = printing.create_print_job(
            stored_item_ids=[stored.id],
            template_version_id=template.current_version_id,
            user_id=user.id,
        )
        item = db.scalar(select(PrintJobItemRecord).where(PrintJobItemRecord.print_job_id == job.id))
        participant_b = _second_participant(db, org, "500100732259")
        bind_tenant_scope(
            db, organisation_id=org.id, participant_id=participant_b.id, user_id=user.id, role="OWNER"
        )
        foreign_binding = _v2_binding(db, org, participant_b)
        bind_tenant_scope(
            db, organisation_id=org.id, participant_id=participant.id, user_id=user.id, role="OWNER"
        )
        sensitive = SensitivePrintingDeliveryService(db, _cfg(execute=True), key_provider=StaticKeyProvider())
        with pytest.raises(SensitiveDeliveryRejected, match="AGENT_BINDING_NOT_FOUND"):
            sensitive.authorize_delivery(
                print_job_id=job.id,
                print_job_item_id=item.id,
                agent_binding_id=foreign_binding.id,
                user_id=user.id,
            )



def test_concurrent_payload_issue_is_serialized_and_never_loses_issue_count(factory):
    with factory() as db:
        (
            _, org, participant, _, _, _, _, binding, _, _, _, _, reservation
        ) = _sensitive_ready(db)
        org_id, participant_id, binding_id, reservation_id = (
            org.id, participant.id, binding.id, reservation.id
        )
        db.commit()

    def issue_once() -> str:
        with factory() as db:
            bind_tenant_scope(
                db,
                organisation_id=org_id,
                participant_id=participant_id,
                user_id=None,
                role=None,
            )
            envelope = SensitivePrintingDeliveryService(
                db, _cfg(execute=True), key_provider=StaticKeyProvider()
            ).issue(reservation_id, machine_binding_id=binding_id)
            db.commit()
            return envelope["context_sha256"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(issue_once), pool.submit(issue_once)]
        context_hashes = [future.result(timeout=20) for future in results]
    assert len(context_hashes) == 2
    assert context_hashes[0] == context_hashes[1]

    with factory() as db:
        row = db.get(PrintPayloadDeliveryReservationRecord, reservation_id)
        execution = db.get(PrintExecutionRecord, row.print_execution_id)
        assert row.issue_count == 2
        assert row.state == "ISSUED"
        assert execution.state == "PAYLOAD_ISSUED"


def test_expired_reservation_is_not_disclosed(factory, monkeypatch):
    with factory() as db:
        _, _, _, _, _, _, _, binding, _, _, sensitive, execution, reservation = _sensitive_ready(db)
        # Keep the durable reservation valid according to the DB invariant
        # (expires_at > authorized_at), then advance the service clock beyond
        # that deadline. Expiry is a runtime transition, not an invalid row.
        expiry = reservation.authorized_at + timedelta(seconds=1)
        reservation.expires_at = expiry
        db.flush()
        monkeypatch.setattr(
            "wbcz_web.services.printing_sensitive_delivery._now",
            lambda: expiry + timedelta(seconds=1),
        )
        with pytest.raises(SensitiveDeliveryRejected, match="DELIVERY_RESERVATION_EXPIRED"):
            sensitive.issue(reservation.id, machine_binding_id=binding.id)
        assert reservation.state == "EXPIRED"
        assert reservation.issue_count == 0
        assert execution.state == "PAYLOAD_AVAILABLE"


def test_lost_private_key_reenrollment_revokes_old_key_reservation_and_execution(factory):
    with factory() as db:
        user, _, _, _, _, _, _, binding, old_key, _, sensitive, execution, reservation = _sensitive_ready(db)
        intent, raw = sensitive.create_key_intent(
            binding.id, purpose="REPLACE_LOST", user_id=user.id
        )
        assert intent.expected_active_key_id == old_key.id
        new_private = x25519.X25519PrivateKey.generate()
        new_key = sensitive.register_public_key(
            agent_binding_id=binding.id,
            intent_token=raw,
            public_key_raw=new_private.public_key().public_bytes_raw(),
        )
        assert old_key.state == "REVOKED"
        assert old_key.revoked_at is not None
        assert new_key.state == "ACTIVE"
        assert reservation.state == "REVOKED"
        assert reservation.safe_error_code == "PRINT_RECIPIENT_KEY_LOST"
        assert execution.state == "BLOCKED"
        assert execution.safe_error_code == "PRINT_RECIPIENT_KEY_LOST"


def test_issue_revalidates_provenance_and_vault_authentication_immediately_before_disclosure(factory):
    with factory() as db:
        _, _, _, stored, vault, _, _, binding, _, _, sensitive, execution, reservation = _sensitive_ready(db)
        stored.provenance_state = "CONFLICT"
        db.flush()
        with pytest.raises(SensitiveDeliveryRejected, match="FULL_KM_PROVENANCE_NOT_PROVEN"):
            sensitive.issue(reservation.id, machine_binding_id=binding.id)
        assert reservation.issue_count == 0
        stored.provenance_state = "PROVEN"
        original_tag = bytes(vault.auth_tag)
        vault.auth_tag = bytes([original_tag[0] ^ 1]) + original_tag[1:]
        db.flush()
        with pytest.raises(SensitiveDeliveryRejected, match="FULL_KM_VAULT_INTEGRITY_FAILED"):
            sensitive.issue(reservation.id, machine_binding_id=binding.id)
        assert reservation.issue_count == 0
        assert execution.state == "PAYLOAD_AVAILABLE"


def test_sensitive_delivery_feature_gates_block_before_payload_disclosure(factory):
    with factory() as db:
        _, _, _, _, _, _, _, binding, _, _, _, _, reservation = _sensitive_ready(db)
        printing_off = replace(
            _cfg(execute=True),
            printing_enabled=False,
            print_execution_enabled=False,
        ).validate_for_startup()
        with pytest.raises(SensitiveDeliveryRejected, match="PRINTING_DISABLED"):
            SensitivePrintingDeliveryService(
                db, printing_off, key_provider=StaticKeyProvider()
            ).issue(reservation.id, machine_binding_id=binding.id)

        execution_off = replace(
            _cfg(execute=True),
            print_execution_enabled=False,
        ).validate_for_startup()
        with pytest.raises(SensitiveDeliveryRejected, match="PRINT_EXECUTION_DISABLED"):
            SensitivePrintingDeliveryService(
                db, execution_off, key_provider=StaticKeyProvider()
            ).issue(reservation.id, machine_binding_id=binding.id)
