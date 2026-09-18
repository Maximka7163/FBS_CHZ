from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from wbcz.m11_reports import (
    REMOTE_CREATE_AMBIGUOUS,
    ReportArtifactUploadBinding,
    ArtifactIntegrityConflict,
    ArtifactKeyProvider,
    ArtifactRole,
    BinaryArtifactIngress,
    FilesystemReportArtifactStore,
    LOCAL_REPORT_CATALOG,
    LocalReconciliationResult,
    LocalReportType,
    ReportOutputFormat,
    ReportSensitivity,
    SnapshotStrategy,
    StreamingReportRenderer,
    artifact_reuse_allowed,
    build_append_only_snapshot,
    build_reconciliation_row,
    canonical_request_fingerprint,
    format_timestamp_preserving_unknown,
    materialize_jsonl_snapshot,
    safe_filename,
    sanitize_report_evidence,
    validate_report_agent_payload,
)
from wbcz.models import canonical_json
from wbcz.windows_agent import AgentJob, AgentJobType, AgentResult, P0_PG
from wbcz_web.models.reports import ReportArtifactRecord, ReportJobRecord, ReportSnapshotRecord
from wbcz_web.repositories.agent import SqlAlchemyAgentJobStore
from wbcz_web.repositories.reports import ClaimedReportJob, SqlReportRepository, SqlUploadBindingStore


class EnvironmentArtifactKeyProvider(ArtifactKeyProvider):
    """Runtime-only key provider. Secret material is never persisted by M11."""

    def __init__(self, *, env_name: str = "WBCZ_REPORT_ARTIFACT_KEY_HEX") -> None:
        self.env_name = env_name

    def get_key(self, key_version: str) -> bytes:
        raw = os.getenv(self.env_name, "")
        if not raw:
            raise RuntimeError("report artifact encryption key is not configured")
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise RuntimeError("report artifact encryption key is invalid") from exc
        if len(key) != 32:
            raise RuntimeError("report artifact encryption key must be 32 bytes")
        return key


def _mask(value: Any) -> str:
    if value is None:
        return ""
    text_value = str(value)
    if len(text_value) <= 4:
        return "*" * len(text_value)
    return "*" * (len(text_value) - 4) + text_value[-4:]


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


class LocalReportSourceRegistry:
    """Read-only source adapters. No method mutates M1-M10 business tables."""

    def __init__(self, participant_inn: str) -> None:
        self.participant_inn = participant_inn

    def rows(self, connection: Any, report_type: LocalReportType, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        method = getattr(self, "_rows_" + report_type.value.lower())
        yield from method(connection, filters=filters)

    def _rows_cis_inventory_stored_snapshot(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT job_id, result_json, updated_at
            FROM agent_jobs
            WHERE job_type IN ('CIS_INFO','CIS_SEARCH','CIS_HISTORY','CIS_AGGREGATED_LIST','CIS_AGGREGATION_HISTORY')
              AND state='COMPLETED'
            ORDER BY updated_at, job_id
        """)
        for row in connection.execute(query).mappings():
            result = row["result_json"] or {}
            cises = result.get("cises") if isinstance(result, dict) else None
            if not isinstance(cises, list):
                read_result = result.get("read_result") if isinstance(result, dict) else None
                cises = read_result.get("cises") if isinstance(read_result, dict) else None
            if not isinstance(cises, list):
                continue
            for item in cises:
                if not isinstance(item, Mapping):
                    continue
                cis = item.get("cis")
                yield {
                    "participant_inn": self.participant_inn,
                    "cis_masked": _mask(cis),
                    "cis_fingerprint": _fingerprint(cis),
                    "raw_state": item.get("status"),
                    "observed_at": format_timestamp_preserving_unknown(row["updated_at"]),
                    "observation_semantics": "LATEST_STORED_OBSERVATION",
                }

    def _rows_product_reference_readiness(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT job_id, result_json, updated_at, payload_json
            FROM agent_jobs
            WHERE purpose='REFERENCE_PRODUCTS' AND state='COMPLETED'
            ORDER BY updated_at, job_id
        """)
        for row in connection.execute(query).mappings():
            payload = row["payload_json"] or {}
            result = row["result_json"] or {}
            gtins = []
            read_payload = payload.get("read_payload") if isinstance(payload, dict) else None
            if isinstance(read_payload, dict):
                gtins = read_payload.get("gtins") or []
            for gtin in gtins if isinstance(gtins, list) else []:
                yield {
                    "participant_inn": self.participant_inn,
                    "gtin": str(gtin),
                    "product_group": "lp",
                    "readiness": "STORED_EVIDENCE_PRESENT",
                    "source_fingerprint": _fingerprint(row["job_id"]),
                    "observed_at": format_timestamp_preserving_unknown(row["updated_at"]),
                }

    def _rows_document_lifecycle(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT operation_id, remote_document_id, request_json, created_at, updated_at
            FROM document_lifecycle_ledger ORDER BY created_at, operation_id
        """)
        for row in connection.execute(query).mappings():
            request = row["request_json"] or {}
            yield {
                "participant_inn": self.participant_inn,
                "document_id": row["remote_document_id"],
                "raw_remote_state": request.get("raw_status") if isinstance(request, dict) else None,
                "local_project_state": "STORED_LIFECYCLE_EVIDENCE",
                "errors": None,
                "observed_at": format_timestamp_preserving_unknown(row["updated_at"]),
            }

    def _rows_turnover_operations(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT operation_id, operation_kind, remote_document_id, reconciliation_state, updated_at
            FROM turnover_operation_ledger ORDER BY created_at, operation_id
        """)
        for row in connection.execute(query).mappings():
            yield {
                "participant_inn": self.participant_inn,
                "operation_id": row["operation_id"],
                "operation_kind": row["operation_kind"],
                "remote_document_id": row["remote_document_id"],
                "reconciliation_state": row["reconciliation_state"],
                "observed_at": format_timestamp_preserving_unknown(row["updated_at"]),
            }

    def _rows_aggregation_operations(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT operation_id, operation_kind, relation_delta, reconciliation_state, updated_at
            FROM aggregation_operation_ledger ORDER BY created_at, operation_id
        """)
        for row in connection.execute(query).mappings():
            yield {
                "participant_inn": self.participant_inn,
                "operation_id": row["operation_id"],
                "operation_kind": row["operation_kind"],
                "relation_delta": row["relation_delta"],
                "reconciliation_state": row["reconciliation_state"],
                "observed_at": format_timestamp_preserving_unknown(row["updated_at"]),
            }

    def _rows_edo_foundation_status(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        yield {
            "participant_inn": self.participant_inn,
            "foundation_state": "FOUNDATION_COMPLETE",
            "full_xml_write_blocked": True,
            "blocker_reason": "M7_FULL_XML_WRITE_BLOCKED",
        }

    def _rows_suz_foundation_status(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        yield {
            "participant_inn": self.participant_inn,
            "foundation_state": "FOUNDATION_COMPLETE",
            "full_suz_wire_blocked": True,
            "km_decrypted": False,
            "blocker_reason": "M8_FULL_SUZ_WIRE_BLOCKED",
        }

    def _rows_wb_reconciliation_evidence(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT r.state, r.decision, r.reason, r.observed_at,
                   o.assembly_order_id, o.source_fingerprint,
                   e.raw_status, e.source_fingerprint AS event_fingerprint
            FROM wb_reconciliation r
            LEFT JOIN wb_orders o ON o.id=r.order_id
            LEFT JOIN wb_events e ON e.connection_id=r.connection_id AND e.assembly_order_id=o.assembly_order_id
            JOIN wb_connections c ON c.id=r.connection_id
            WHERE c.participant_inn=:inn
            ORDER BY r.observed_at, r.id
        """)
        for row in connection.execute(query, {"inn": self.participant_inn}).mappings():
            yield {
                "participant_inn": self.participant_inn,
                "assembly_order_id": str(row["assembly_order_id"]) if row["assembly_order_id"] is not None else None,
                "raw_remote_state": row["raw_status"],
                "local_project_state": row["state"],
                "conflict_state": "CONFLICT" if row["decision"] == "MANUAL_REVIEW" else None,
                "source_fingerprint": row["source_fingerprint"] or row["event_fingerprint"],
                "observed_at": format_timestamp_preserving_unknown(row["observed_at"]),
            }

    def _rows_ozon_foundation_status(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        yield {
            "participant_inn": self.participant_inn,
            "foundation_state": "SAFE_FOUNDATION_ONLY",
            "m10_wire_ready": False,
            "m10_executable_read_capabilities": "NONE",
        }

    def _rows_manual_review_and_conflicts(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        wb = text("""
            SELECT r.reason, r.state, r.evidence_redacted, r.observed_at
            FROM wb_reconciliation r JOIN wb_connections c ON c.id=r.connection_id
            WHERE c.participant_inn=:inn AND (r.state='MANUAL_REVIEW' OR r.decision='MANUAL_REVIEW')
            ORDER BY r.observed_at, r.id
        """)
        for row in connection.execute(wb, {"inn": self.participant_inn}).mappings():
            yield {
                "participant_inn": self.participant_inn,
                "domain": "WB",
                "remote_raw_state": None,
                "local_project_state": row["state"],
                "final_reconciliation_result": LocalReconciliationResult.MANUAL_REVIEW.value,
                "reason": row["reason"],
                "evidence_fingerprint": _fingerprint(row["evidence_redacted"]),
            }
        ozon = text("""
            SELECT r.reason, r.state, r.evidence_redacted, r.observed_at
            FROM ozon_reconciliation r JOIN ozon_connections c ON c.id=r.connection_id
            WHERE c.participant_inn=:inn AND (r.state='MANUAL_REVIEW' OR r.decision='MANUAL_REVIEW')
            ORDER BY r.observed_at, r.id
        """)
        for row in connection.execute(ozon, {"inn": self.participant_inn}).mappings():
            yield {
                "participant_inn": self.participant_inn,
                "domain": "OZON_FOUNDATION",
                "remote_raw_state": None,
                "local_project_state": row["state"],
                "final_reconciliation_result": LocalReconciliationResult.MANUAL_REVIEW.value,
                "reason": row["reason"],
                "evidence_fingerprint": _fingerprint(row["evidence_redacted"]),
            }

    def _rows_end_to_end_reconciliation(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT r.state, r.decision, r.reason, r.observed_at,
                   o.assembly_order_id, o.source, o.source_fingerprint
            FROM wb_reconciliation r
            LEFT JOIN wb_orders o ON o.id=r.order_id
            JOIN wb_connections c ON c.id=r.connection_id
            WHERE c.participant_inn=:inn
            ORDER BY r.observed_at, r.id
        """)
        for row in connection.execute(query, {"inn": self.participant_inn}).mappings():
            final = (
                LocalReconciliationResult.MANUAL_REVIEW
                if row["state"] == "MANUAL_REVIEW" or row["decision"] == "MANUAL_REVIEW"
                else LocalReconciliationResult.PENDING_EVIDENCE
                if row["state"] not in {"DISTANCE_RECONCILED", "REMOTE_RETURN_RECONCILED"}
                else LocalReconciliationResult.MATCHED
            )
            yield build_reconciliation_row(
                participant_inn=self.participant_inn,
                domain="WB_FBS",
                source=row["source"] or "WB",
                source_fingerprint=row["source_fingerprint"],
                local_operation_id=None,
                remote_id=str(row["assembly_order_id"]) if row["assembly_order_id"] is not None else None,
                remote_raw_state=None,
                local_project_state=row["state"],
                final_result=final,
                evidence_missing=final is LocalReconciliationResult.PENDING_EVIDENCE,
                conflict_state="CONFLICT" if final is LocalReconciliationResult.MANUAL_REVIEW else None,
                observed_at=row["observed_at"],
            )

    def _rows_p0_import_control_quality(self, connection: Any, *, filters: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        query = text("""
            SELECT i.id AS import_id, ir.row_number, c.decision, c.reason, c.checked_at, ir.error
            FROM imports i
            JOIN import_rows ir ON ir.import_id=i.id
            LEFT JOIN checks c ON c.event_id=ir.event_id
            ORDER BY i.imported_at, ir.row_number, c.checked_at
        """)
        for row in connection.execute(query).mappings():
            yield {
                "participant_inn": self.participant_inn,
                "import_id": row["import_id"],
                "row_index": row["row_number"],
                "decision": row["decision"] or ("REJECTED" if row["error"] else "UNCHECKED"),
                "reason": row["reason"] or row["error"],
                "source_fingerprint": _fingerprint((row["import_id"], row["row_number"])),
                "observed_at": format_timestamp_preserving_unknown(row["checked_at"]),
            }


@dataclass(frozen=True, slots=True)
class LocalGenerationResult:
    job_id: str
    artifact_id: str
    row_count: int
    sha256: str
    byte_size: int
    snapshot_hash: str


class SynchronousReportExecutor:
    """Deterministic local executor used by the DB-backed worker and tests."""

    def __init__(
        self,
        db: Session,
        *,
        artifact_store: FilesystemReportArtifactStore,
        temp_root: Path,
        participant_inn: str,
        max_rows: int = 1_000_000,
        max_artifact_bytes: int = 2 * 1024 * 1024 * 1024,
    ) -> None:
        self.db = db
        self.repo = SqlReportRepository(db)
        self.artifact_store = artifact_store
        self.temp_root = temp_root
        self.participant_inn = participant_inn
        self.renderer = StreamingReportRenderer(
            temp_root=temp_root,
            max_rows=max_rows,
            max_bytes=max_artifact_bytes,
        )
        self.sources = LocalReportSourceRegistry(participant_inn)

    def _materialize_source(self, claimed: ClaimedReportJob, definition: Any) -> tuple[Any, Any]:
        engine = self.db.get_bind()
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as connection:
            transaction = connection.begin()
            try:
                connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                snapshot_at = datetime.now(timezone.utc)
                rows = self.sources.rows(
                    connection,
                    LocalReportType(claimed.report_type),
                    filters=claimed.filters_sanitized,
                )
                materialized = materialize_jsonl_snapshot(
                    rows,
                    temp_root=self.temp_root,
                    max_rows=self.renderer.max_rows,
                    max_bytes=self.renderer.max_bytes,
                )
                transaction.commit()
            except BaseException:
                transaction.rollback()
                raise
        descriptor = build_append_only_snapshot(
            source_domains=(definition.source_adapter,),
            source_tables=tuple(),
            high_water_metadata={"materialized_sha256": materialized.sha256, "row_count": materialized.row_count},
            source_filter_sanitized=claimed.filters_sanitized,
            schema_version=definition.schema_version,
            snapshot_at=snapshot_at,
        )
        if definition.snapshot_strategy is SnapshotStrategy.POSTGRES_CONSISTENT_SNAPSHOT:
            descriptor = descriptor.__class__(
                SnapshotStrategy.POSTGRES_CONSISTENT_SNAPSHOT,
                descriptor.snapshot_at,
                descriptor.source_domains,
                descriptor.source_tables,
                descriptor.high_water_metadata,
                descriptor.source_filter_sanitized,
                descriptor.schema_version,
                None,
                materialized.row_count,
            )
        elif definition.snapshot_strategy is SnapshotStrategy.MATERIALIZED_IMMUTABLE:
            descriptor = descriptor.__class__(
                SnapshotStrategy.MATERIALIZED_IMMUTABLE,
                descriptor.snapshot_at,
                descriptor.source_domains,
                descriptor.source_tables,
                descriptor.high_water_metadata,
                descriptor.source_filter_sanitized,
                descriptor.schema_version,
                None,
                materialized.row_count,
            )
        return materialized, descriptor

    @staticmethod
    def _snapshot_rows(path: Path) -> Iterator[dict[str, Any]]:
        with path.open("r", encoding="utf-8") as source:
            for line in source:
                if line:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        yield value

    def execute_claimed(self, claimed: ClaimedReportJob) -> LocalGenerationResult:
        if claimed.participant_inn != self.participant_inn:
            raise PermissionError("participant isolation mismatch")
        definition = LOCAL_REPORT_CATALOG[LocalReportType(claimed.report_type)]
        if claimed.report_schema_version != definition.schema_version:
            raise ValueError("report schema version mismatch")
        fmt = ReportOutputFormat(claimed.output_format)
        if fmt not in definition.output_formats:
            raise ValueError("report output format not allowed")
        materialized = None
        rendered = None
        try:
            materialized, descriptor = self._materialize_source(claimed, definition)
            snapshot = self.repo.record_snapshot(claimed.job_id, descriptor)
            rows = self._snapshot_rows(materialized.path)
            rendered = self.renderer.render(rows, columns=definition.columns, output_format=fmt)
            artifact_id = "art_" + hashlib.sha256(
                (claimed.job_id + ":" + descriptor.descriptor_sha256 + ":" + fmt.value).encode("utf-8")
            ).hexdigest()[:32]
            publication_key = hashlib.sha256(
                (claimed.job_id + ":OUTPUT:" + descriptor.descriptor_sha256 + ":" + fmt.value).encode("utf-8")
            ).hexdigest()
            sensitive = definition.sensitivity in {
                ReportSensitivity.BUSINESS_SENSITIVE,
                ReportSensitivity.MARKING_SENSITIVE,
            }
            storage = self.artifact_store.put_file(
                rendered.path,
                sensitive=sensitive,
                aad_context={
                    "artifact_id": artifact_id,
                    "report_job_id": claimed.job_id,
                    "snapshot_sha256": descriptor.descriptor_sha256,
                    "role": ArtifactRole.OUTPUT.value,
                },
                safe_suffix="." + fmt.value.lower() + (".enc" if sensitive else ""),
            )
            if storage.plaintext_sha256 != rendered.sha256 or storage.plaintext_byte_size != rendered.byte_size:
                raise ArtifactIntegrityConflict("artifact store plaintext metadata mismatch")
            artifact = self.repo.finalize_artifact(
                job_id=claimed.job_id,
                artifact_id=artifact_id,
                artifact_role=ArtifactRole.OUTPUT.value,
                publication_key=publication_key,
                storage_backend=storage.storage_backend,
                storage_key=storage.storage_key,
                format=fmt.value,
                mime=rendered.mime,
                safe_filename=safe_filename(claimed.report_type, fmt.value),
                byte_size=storage.plaintext_byte_size,
                sha256=storage.plaintext_sha256,
                sensitivity_class=definition.sensitivity.value,
                encryption_metadata=storage.encryption_metadata,
                encryption_version=storage.encryption_version,
            )
            self.repo.mark_ready(claimed.job_id, worker_id=claimed.lease_owner)
            self.db.flush()
            return LocalGenerationResult(
                claimed.job_id,
                artifact.artifact_id,
                rendered.row_count,
                rendered.sha256,
                rendered.byte_size,
                descriptor.descriptor_sha256,
            )
        except BaseException as exc:
            self.repo.fail(claimed.job_id, code=type(exc).__name__, message_redacted="local report generation failed")
            self.db.flush()
            raise
        finally:
            if rendered is not None:
                rendered.path.unlink(missing_ok=True)
            if materialized is not None:
                materialized.path.unlink(missing_ok=True)


class ReportJobService:
    def __init__(self, db: Session, *, participant_inn: str) -> None:
        self.db = db
        self.participant_inn = participant_inn
        self.repo = SqlReportRepository(db)

    def request_local(
        self,
        *,
        report_type: LocalReportType,
        output_format: ReportOutputFormat,
        filters: Mapping[str, Any] | None = None,
        requested_by_user_id: str | None = None,
        sensitivity_mode: str | None = None,
    ) -> ReportJobRecord:
        definition = LOCAL_REPORT_CATALOG[report_type]
        if output_format not in definition.output_formats:
            raise ValueError("unsupported report output format")
        filters = dict(filters or {})
        unknown = set(filters) - set(definition.allowed_filters)
        if unknown:
            raise ValueError("unsupported report filters")
        safe_filters = sanitize_report_evidence(filters)
        fingerprint = canonical_request_fingerprint(
            report_type=report_type.value,
            report_schema_version=definition.schema_version,
            participant_scope={"participant_inn": self.participant_inn},
            normalized_filters=safe_filters if isinstance(safe_filters, dict) else {},
            output_format=output_format.value,
            sensitivity_mode=sensitivity_mode or definition.sensitivity.value,
            snapshot_policy_version="m11-v1",
        )
        row = self.repo.create_job(
            origin="LOCAL",
            participant_inn=self.participant_inn,
            report_type=report_type.value,
            report_schema_version=definition.schema_version,
            output_format=output_format.value,
            sensitivity_class=definition.sensitivity.value,
            filters_sanitized=safe_filters if isinstance(safe_filters, dict) else {},
            sensitive_filter_ref=None,
            request_fingerprint_sha256=fingerprint,
            requested_by_user_id=requested_by_user_id,
        )
        return self.repo.queue(row.id)


class ReportArtifactIngressService:
    def __init__(
        self,
        db: Session,
        *,
        artifact_store: FilesystemReportArtifactStore,
        temp_root: Path,
    ) -> None:
        self.db = db
        self.repo = SqlReportRepository(db)
        self.bindings = SqlUploadBindingStore(db)
        self.ingress = BinaryArtifactIngress(
            binding_store=self.bindings,
            artifact_store=artifact_store,
            temp_root=temp_root,
        )

    def prepare_download(
        self,
        *,
        report_job_id: str,
        remote_result_id: str,
        remote_result_part_id: str | None,
        product_group_code: str | None,
        expected_archive_size: int | None,
    ):
        return self.ingress.prepare(
            report_job_id=report_job_id,
            remote_result_id=remote_result_id,
            remote_result_part_id=remote_result_part_id,
            product_group_code=product_group_code,
            expected_archive_size=expected_archive_size,
        )

    def ingest_stream(
        self,
        *,
        artifact_upload_id: str,
        report_job_id: str,
        remote_result_id: str,
        remote_result_part_id: str | None,
        chunks: Iterable[bytes],
        observed_mime: str | None,
    ) -> ReportArtifactRecord:
        artifact = self.ingress.ingest(
            artifact_upload_id=artifact_upload_id,
            report_job_id=report_job_id,
            remote_result_id=remote_result_id,
            remote_result_part_id=remote_result_part_id,
            chunks=chunks,
            observed_mime=observed_mime,
        )
        binding = self.bindings.get(artifact_upload_id)
        if binding is None:
            raise KeyError(artifact_upload_id)
        publication_key = hashlib.sha256(
            (report_job_id + ":REMOTE_TRUE_API_ARCHIVE:" + remote_result_id + ":" + str(remote_result_part_id)).encode("utf-8")
        ).hexdigest()
        row = self.repo.finalize_artifact(
            job_id=report_job_id,
            artifact_id=artifact.artifact_id,
            artifact_role=ArtifactRole.REMOTE_TRUE_API_ARCHIVE.value,
            publication_key=publication_key,
            storage_backend=artifact.storage.storage_backend,
            storage_key=artifact.storage.storage_key,
            format="ZIP",
            mime=observed_mime or "application/zip",
            safe_filename=safe_filename("true_api_result", "ZIP"),
            byte_size=artifact.byte_size,
            sha256=artifact.sha256,
            sensitivity_class=ReportSensitivity.MARKING_SENSITIVE.value,
            encryption_metadata=artifact.storage.encryption_metadata,
            encryption_version=artifact.storage.encryption_version,
            remote_result_id=remote_result_id,
            remote_result_part_id=remote_result_part_id,
        )
        self.db.flush()
        return row


REPORT_AGENT_PURPOSE = "REPORTS_EXPORTS"


def _stable_report_agent_job_id(job_type: str, report_job_id: str, seed: str) -> str:
    return "job_" + hashlib.sha256(
        f"m11-report:v1:{job_type}:{report_job_id}:{seed}".encode("utf-8")
    ).hexdigest()[:32]


class TrueApiReportOrchestrator:
    """VPS-side durable control plane. Contains no True API HTTP client or bearer token."""

    def __init__(
        self,
        db: Session,
        *,
        participant_inn: str,
        agent_lease_seconds: int = 90,
        reports_enabled: bool = False,
        poll_delay_seconds: int = 30,
    ) -> None:
        self.db = db
        self.participant_inn = participant_inn
        self.reports_enabled = bool(reports_enabled)
        self.poll_delay_seconds = max(5, int(poll_delay_seconds))
        self.repo = SqlReportRepository(db)
        self.jobs = SqlAlchemyAgentJobStore(db, lease_seconds=agent_lease_seconds)
        self.bindings = SqlUploadBindingStore(db)

    def _enqueue(
        self,
        *,
        report_job_id: str,
        job_type: AgentJobType,
        payload: Mapping[str, Any],
        seed: str,
        attempt: int = 0,
        delay_seconds: int = 0,
    ) -> AgentJob:
        normalized = validate_report_agent_payload(job_type.value, payload)
        job = AgentJob(
            job_id=_stable_report_agent_job_id(job_type.value, report_job_id, seed),
            job_type=job_type,
            operation_id=report_job_id,
            pg=P0_PG,
            expected_inn=self.participant_inn,
            read_payload=normalized,
        )
        available_at = datetime.now(timezone.utc) + timedelta(seconds=max(0, delay_seconds))
        return self.jobs.enqueue(
            job,
            purpose=REPORT_AGENT_PURPOSE,
            poll_attempt=attempt,
            available_at=available_at,
        )

    def request_filtered_cis_report(
        self,
        *,
        product_group_code: str | int,
        participant_inn: str,
        package_type: list[str],
        status: str,
        include_gtin: list[str] | None = None,
        requested_by_user_id: str | None = None,
    ) -> tuple[ReportJobRecord, AgentJob]:
        if not self.reports_enabled:
            raise PermissionError("production True API reports are disabled")
        if participant_inn != self.participant_inn:
            raise PermissionError("participant isolation mismatch")
        raw_payload = {
            "local_report_job_id": "placeholder",
            "recipe": "FILTERED_CIS_REPORT",
            "product_group_code": product_group_code,
            "filters": {
                "participant_inn": participant_inn,
                "package_type": list(package_type),
                "status": status,
                "include_gtin": list(include_gtin or []),
            },
        }
        # Normalize recipe fields before creating the durable intent.
        probe = validate_report_agent_payload("REPORT_CREATE", raw_payload)
        fingerprint = canonical_request_fingerprint(
            report_type="TRUE_API_FILTERED_CIS_REPORT",
            report_schema_version="198.0",
            participant_scope={"participant_inn": participant_inn},
            normalized_filters={
                "recipe": probe["recipe"],
                "product_group_code": probe["product_group_code"],
                "filters": probe["filters"],
            },
            output_format="CSV",
            sensitivity_mode=ReportSensitivity.MARKING_SENSITIVE.value,
            snapshot_policy_version="remote-crpt-dispenser-v198",
        )
        row = self.repo.create_job(
            origin="TRUE_API_REMOTE",
            participant_inn=participant_inn,
            report_type="TRUE_API_FILTERED_CIS_REPORT",
            report_schema_version="198.0",
            output_format="ZIP",
            sensitivity_class=ReportSensitivity.MARKING_SENSITIVE.value,
            filters_sanitized={
                "recipe": probe["recipe"],
                "product_group_code": probe["product_group_code"],
                "filters": sanitize_report_evidence(probe["filters"]),
            },
            sensitive_filter_ref=None,
            request_fingerprint_sha256=fingerprint,
            requested_by_user_id=requested_by_user_id,
        )
        self.repo.queue(row.id)
        payload = dict(probe)
        payload["local_report_job_id"] = row.id
        normalized = validate_report_agent_payload("REPORT_CREATE", payload)
        job = self._enqueue(
            report_job_id=row.id,
            job_type=AgentJobType.REPORT_CREATE,
            payload=normalized,
            seed=fingerprint,
        )
        self.repo.event(row.id, "remote_create_intent_queued", details={"recipe": "FILTERED_CIS_REPORT"})
        self.db.flush()
        return row, job

    def _job_row(self, report_job_id: str) -> ReportJobRecord:
        row = self.db.get(ReportJobRecord, report_job_id)
        if row is None:
            raise KeyError(report_job_id)
        if row.participant_inn != self.participant_inn:
            raise PermissionError("participant isolation mismatch")
        return row

    def handle_agent_result(self, metadata: Any, result: AgentResult) -> None:
        job = metadata.job
        if job.operation_id != result.operation_id:
            raise ValueError("report result operation mismatch")
        report = self._job_row(job.operation_id)

        if result.outcome == REMOTE_CREATE_AMBIGUOUS:
            self.repo.set_remote_create_ambiguous(report.id)
            self.repo.fail(
                report.id,
                code=REMOTE_CREATE_AMBIGUOUS,
                message_redacted="remote create outcome is ambiguous; operator evidence required",
            )
            return

        if result.outcome == "RETRY_SCHEDULED":
            retry = 60
            if isinstance(result.read_result, Mapping):
                raw_retry = result.read_result.get("retry_after_seconds")
                if isinstance(raw_retry, (int, float)):
                    retry = max(1, min(3600, int(raw_retry) + 1))
            self._enqueue(
                report_job_id=report.id,
                job_type=job.job_type,
                payload=job.read_payload or {},
                seed=f"retry:{metadata.poll_attempt + 1}:{job.job_id}",
                attempt=metadata.poll_attempt + 1,
                delay_seconds=retry,
            )
            self.repo.event(report.id, "retry_scheduled", details={"job_type": job.job_type.value, "delay_seconds": retry})
            return

        if job.job_type is AgentJobType.REPORT_CREATE:
            if result.outcome != "REPORT_TASK_CREATED" or not isinstance(result.read_result, Mapping):
                self.repo.fail(report.id, code=result.error_code or "REMOTE_CREATE_FAILED", message_redacted="remote create did not yield deterministic task identity")
                return
            task_id = result.read_result.get("task_id")
            if not isinstance(task_id, str) or not task_id:
                self.repo.fail(report.id, code="REMOTE_TASK_ID_MISSING", message_redacted="remote create task identity missing")
                return
            self.repo.set_remote_task(
                report.id,
                task_id=task_id,
                raw_status=result.remote_status,
                metadata=result.read_result,
            )
            product_group = str(report.filters_sanitized_json.get("product_group_code") or "")
            self._enqueue(
                report_job_id=report.id,
                job_type=AgentJobType.REPORT_TASK_GET,
                payload={
                    "local_report_job_id": report.id,
                    "task_id": task_id,
                    "product_group_code": product_group,
                },
                seed=f"task:{task_id}:0",
                attempt=0,
                delay_seconds=self.poll_delay_seconds,
            )
            return

        if job.job_type is AgentJobType.REPORT_TASK_GET:
            raw_status = result.remote_status
            report.raw_remote_status = raw_status
            self.repo.event(report.id, "remote_status_observed", remote_task_id=report.remote_task_id, details={"raw_status": raw_status})
            if result.outcome not in {"REPORT_TASK_OBSERVED", "REPORT_READ_COMPLETED"}:
                self.repo.fail(report.id, code=result.error_code or "REMOTE_TASK_GET_FAILED", message_redacted="remote task status request failed")
                return
            if raw_status == "PREPARATION":
                self._enqueue(
                    report_job_id=report.id,
                    job_type=AgentJobType.REPORT_TASK_GET,
                    payload=job.read_payload or {},
                    seed=f"task:{report.remote_task_id}:{metadata.poll_attempt + 1}",
                    attempt=metadata.poll_attempt + 1,
                    delay_seconds=self.poll_delay_seconds,
                )
                return
            if raw_status == "COMPLETED":
                product_group = str(report.filters_sanitized_json.get("product_group_code") or "")
                self._enqueue(
                    report_job_id=report.id,
                    job_type=AgentJobType.REPORT_RESULTS,
                    payload={
                        "local_report_job_id": report.id,
                        "page": 0,
                        "size": 100,
                        "product_group_code": product_group,
                        "task_ids": [report.remote_task_id],
                    },
                    seed=f"results:{report.remote_task_id}:0",
                    attempt=0,
                    delay_seconds=0,
                )
                return
            if raw_status in {"CANCELED", "ARCHIVE", "FAILED"}:
                self.repo.fail(report.id, code=f"REMOTE_TASK_{raw_status}", message_redacted="remote report task reached terminal non-success state")
                return
            self.repo.fail(report.id, code="UNKNOWN_REMOTE_TASK_STATUS", message_redacted="unknown remote task status preserved for review")
            return

        if job.job_type is AgentJobType.REPORT_RESULTS:
            if result.outcome != "REPORT_RESULTS_OBSERVED" or not isinstance(result.read_result, Mapping):
                self.repo.fail(report.id, code=result.error_code or "REMOTE_RESULTS_FAILED", message_redacted="remote results request failed")
                return
            items = result.read_result.get("results")
            if not isinstance(items, list):
                items = []
            matching = [
                item for item in items
                if isinstance(item, Mapping)
                and item.get("task_id") == report.remote_task_id
                and item.get("result_id")
            ]
            self.repo.event(
                report.id,
                "remote_result_observed",
                remote_task_id=report.remote_task_id,
                details={"matching_result_count": len(matching)},
            )
            if not matching:
                self._enqueue(
                    report_job_id=report.id,
                    job_type=AgentJobType.REPORT_RESULTS,
                    payload=job.read_payload or {},
                    seed=f"results:{report.remote_task_id}:{metadata.poll_attempt + 1}",
                    attempt=metadata.poll_attempt + 1,
                    delay_seconds=self.poll_delay_seconds,
                )
                return
            unique_ids = {str(item["result_id"]) for item in matching}
            if len(unique_ids) != 1:
                self.repo.fail(report.id, code="REMOTE_RESULT_IDENTITY_AMBIGUOUS", message_redacted="multiple remote result identities matched one task")
                return
            item = matching[0]
            availability = item.get("raw_availability") or {}
            download_status = item.get("raw_download_status") or {}
            availability_raw = availability.get("raw") if isinstance(availability, Mapping) else None
            download_raw = download_status.get("raw") if isinstance(download_status, Mapping) else None
            if availability_raw == "AVAILABLE" and download_raw == "SUCCESS":
                result_id = str(item["result_id"])
                parts = item.get("result_file_parts") or []
                if parts and not isinstance(parts, list):
                    self.repo.fail(report.id, code="REMOTE_RESULT_PARTS_INVALID", message_redacted="remote result parts contract invalid")
                    return
                # A result-level archive is deterministic when no parts are present.
                if isinstance(parts, list) and len(parts) > 1:
                    self.repo.fail(report.id, code="REMOTE_RESULT_MULTIPART_REQUIRES_MANIFEST", message_redacted="multi-part remote result requires explicit part orchestration")
                    return
                part_id = None
                if isinstance(parts, list) and len(parts) == 1 and isinstance(parts[0], Mapping):
                    raw_part = parts[0].get("id")
                    part_id = str(raw_part) if raw_part is not None else None
                binding = ReportArtifactUploadBinding(
                    "upl_" + uuid.uuid4().hex,
                    report.id,
                    result_id,
                    part_id,
                    str(report.filters_sanitized_json.get("product_group_code") or "") or None,
                    item.get("archive_size") if isinstance(item.get("archive_size"), int) else None,
                )
                self.bindings.put(binding)
                self._enqueue(
                    report_job_id=report.id,
                    job_type=AgentJobType.REPORT_DOWNLOAD,
                    payload={
                        "local_report_job_id": report.id,
                        "result_id": result_id,
                        "result_part_id": part_id,
                        "product_group_code": binding.product_group_code,
                        "artifact_upload_id": binding.artifact_upload_id,
                        "expected_archive_size": binding.expected_archive_size,
                        "download_format": None,
                    },
                    seed=f"download:{result_id}:{part_id or '-'}",
                )
                return
            if availability_raw == "NOT_AVAILABLE" or download_raw == "PREPARATION":
                self._enqueue(
                    report_job_id=report.id,
                    job_type=AgentJobType.REPORT_RESULTS,
                    payload=job.read_payload or {},
                    seed=f"results:{report.remote_task_id}:{metadata.poll_attempt + 1}",
                    attempt=metadata.poll_attempt + 1,
                    delay_seconds=self.poll_delay_seconds,
                )
                return
            if download_raw == "FAILED":
                self.repo.fail(report.id, code="REMOTE_DOWNLOAD_PREPARATION_FAILED", message_redacted="remote result preparation failed")
                return
            self.repo.fail(report.id, code="UNKNOWN_REMOTE_RESULT_STATUS", message_redacted="unknown remote result status preserved for review")
            return

        if job.job_type is AgentJobType.REPORT_DOWNLOAD:
            if result.outcome != "REPORT_ARTIFACT_UPLOADED":
                self.repo.fail(report.id, code=result.error_code or "REMOTE_DOWNLOAD_FAILED", message_redacted="remote report archive download failed")
                return
            ready_artifact = self.db.scalar(
                select(ReportArtifactRecord).where(
                    ReportArtifactRecord.report_job_id == report.id,
                    ReportArtifactRecord.artifact_role == ArtifactRole.REMOTE_TRUE_API_ARCHIVE.value,
                    ReportArtifactRecord.state == "READY",
                ).limit(1)
            )
            if ready_artifact is None:
                self.repo.fail(report.id, code="ARTIFACT_INGRESS_NOT_FINALIZED", message_redacted="agent reported upload but backend artifact is not finalized")
                return
            self.repo.mark_ready(report.id)
            return

        # LIST_TASKS is diagnostics only. Quota calls never bind task identity.
        self.repo.event(
            report.id,
            "remote_read_observed",
            details={"job_type": job.job_type.value, "outcome": result.outcome},
        )
