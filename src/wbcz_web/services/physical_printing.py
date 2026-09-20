from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz.physical_printing import (
    PHYSICAL_CAPABILITY,
    PHYSICAL_OPERATION,
    PRINT_PROTOCOL_VERSION,
    SAFE_WINDOWS_STATUS,
)
from wbcz.printing import PRINTING_CONTRACT_VERSION, PRINT_LAYOUT_SCHEMA_VERSION, RENDERER_VERSION, canonical_layout_sha256
from wbcz_web.config import WebConfig
from wbcz_web.models import (
    AgentBindingRecord,
    PrintEventRecord,
    PrintExecutionRecord,
    PrintJobItemRecord,
    PrintJobRecord,
    PrintPayloadDeliveryReservationRecord,
    PrintTemplateVersionRecord,
    PrinterProfileRecord,
    StoredFullKmItemRecord,
)
from wbcz_web.services.audit_history import (
    ActorContext,
    ActorKind,
    AuditOutcome,
    AuditService,
    AuditTenantScope,
    AuthorizationDecision,
    SubjectRef,
    SubjectType,
    TraceContext,
)
from wbcz_web.services.printer_profiles import COMPATIBLE, PrinterProfileRejected, PrinterProfileService
from wbcz_web.services.printing import LocalPrintingService
from wbcz_web.services.tenant import active_tenant


UNKNOWN_REPRINT_WARNING = (
    "Предыдущая попытка могла попасть в очередь печати. "
    "Повторная печать может создать второй экземпляр этикетки."
)


class PhysicalExecutionRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code[:96]
        super().__init__(self.code)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class PhysicalPrintingService:
    def __init__(self, db: Session, config: WebConfig) -> None:
        self.db = db
        self.config = config
        self.scope = active_tenant(db)

    def _require_gate(self) -> None:
        if not self.config.printing_enabled:
            raise PhysicalExecutionRejected("PRINTING_DISABLED")
        if not self.config.print_execution_enabled:
            raise PhysicalExecutionRejected("PRINT_EXECUTION_DISABLED")
        if self.config.environment == "production":
            raise PhysicalExecutionRejected("PRODUCTION_PRINT_EXECUTION_BLOCKED")

    def _audit(
        self,
        event_type: str,
        *,
        execution: PrintExecutionRecord,
        outcome: AuditOutcome,
        metadata: dict[str, Any],
        event_key: str,
    ) -> None:
        trace_data = self.db.info.get("audit_trace")
        trace = trace_data if isinstance(trace_data, dict) else {}
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=ActorContext(ActorKind.WINDOWS_AGENT, machine_principal="printing-agent"),
            tenant=AuditTenantScope(self.scope.organisation_id, self.scope.participant_id),
            subject=SubjectRef(SubjectType.PRINT_JOB, execution.print_job_id),
            outcome=outcome,
            authorization_decision=AuthorizationDecision.NOT_APPLICABLE,
            trace=TraceContext(
                request_id=trace.get("request_id"),
                correlation_id=trace.get("correlation_id"),
                causation_id=trace.get("causation_id"),
                event_key=event_key[:256],
            ),
            metadata=metadata,
        )

    def _binding(self, binding_id: str) -> AgentBindingRecord:
        row = self.db.scalar(select(AgentBindingRecord).where(
            AgentBindingRecord.id == binding_id,
            AgentBindingRecord.organisation_id == self.scope.organisation_id,
            AgentBindingRecord.participant_id == self.scope.participant_id,
        ))
        if row is None:
            raise PhysicalExecutionRejected("AGENT_BINDING_NOT_FOUND")
        if row.state != "ACTIVE" or row.protocol_compatibility_state != "COMPATIBLE":
            raise PhysicalExecutionRejected("AGENT_BINDING_NOT_ACTIVE")
        if row.last_seen_at is None or (
            _now() - _aware(row.last_seen_at)
        ).total_seconds() > self.config.agent_health_stale_seconds:
            raise PhysicalExecutionRejected("AGENT_BINDING_NOT_FRESH")
        if PHYSICAL_CAPABILITY not in set(row.supported_capabilities_json or ()):
            raise PhysicalExecutionRejected("PRINTING_PHYSICAL_V1_REQUIRED")
        return row

    def _execution(self, execution_id: str, *, lock: bool = False) -> PrintExecutionRecord:
        stmt = select(PrintExecutionRecord).where(
            PrintExecutionRecord.id == execution_id,
            PrintExecutionRecord.organisation_id == self.scope.organisation_id,
            PrintExecutionRecord.participant_id == self.scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError(execution_id)
        return row

    def _graph(
        self,
        execution: PrintExecutionRecord,
    ) -> tuple[
        PrintJobRecord,
        PrintJobItemRecord,
        PrintPayloadDeliveryReservationRecord,
        PrintTemplateVersionRecord,
        StoredFullKmItemRecord,
        PrinterProfileRecord,
    ]:
        job = self.db.scalar(select(PrintJobRecord).where(
            PrintJobRecord.id == execution.print_job_id,
            PrintJobRecord.organisation_id == self.scope.organisation_id,
            PrintJobRecord.participant_id == self.scope.participant_id,
        ))
        item = self.db.scalar(select(PrintJobItemRecord).where(
            PrintJobItemRecord.id == execution.print_job_item_id,
            PrintJobItemRecord.print_job_id == execution.print_job_id,
            PrintJobItemRecord.organisation_id == self.scope.organisation_id,
            PrintJobItemRecord.participant_id == self.scope.participant_id,
        ))
        reservation = self.db.scalar(select(PrintPayloadDeliveryReservationRecord).where(
            PrintPayloadDeliveryReservationRecord.print_execution_id == execution.id,
            PrintPayloadDeliveryReservationRecord.organisation_id == self.scope.organisation_id,
            PrintPayloadDeliveryReservationRecord.participant_id == self.scope.participant_id,
        ))
        version = self.db.scalar(select(PrintTemplateVersionRecord).where(
            PrintTemplateVersionRecord.id == execution.template_version_id,
            PrintTemplateVersionRecord.organisation_id == self.scope.organisation_id,
        ))
        stored = self.db.scalar(select(StoredFullKmItemRecord).where(
            StoredFullKmItemRecord.id == execution.stored_full_km_item_id,
            StoredFullKmItemRecord.organisation_id == self.scope.organisation_id,
            StoredFullKmItemRecord.participant_id == self.scope.participant_id,
        ))
        profile = self.db.scalar(select(PrinterProfileRecord).where(
            PrinterProfileRecord.id == execution.printer_profile_id,
            PrinterProfileRecord.organisation_id == self.scope.organisation_id,
            PrinterProfileRecord.participant_id == self.scope.participant_id,
        )) if execution.printer_profile_id else None
        if any(value is None for value in (job, item, reservation, version, stored, profile)):
            raise PhysicalExecutionRejected("PHYSICAL_EXECUTION_GRAPH_INVALID")
        assert job and item and reservation and version and stored and profile
        if item.stored_full_km_item_id != stored.id:
            raise PhysicalExecutionRejected("PHYSICAL_STORED_ITEM_CONFLICT")
        if reservation.state != "ACKNOWLEDGED":
            raise PhysicalExecutionRejected("PHYSICAL_PAYLOAD_NOT_ACKNOWLEDGED")
        if reservation.payload_sha256 != execution.payload_sha256 or item.payload_hash != execution.payload_sha256:
            raise PhysicalExecutionRejected("PHYSICAL_PAYLOAD_HASH_CONFLICT")
        if profile.agent_binding_id != execution.agent_binding_id:
            raise PhysicalExecutionRejected("PRINTER_PROFILE_AGENT_BINDING_MISMATCH")
        if profile.state != "ACTIVE":
            raise PhysicalExecutionRejected("PRINTER_PROFILE_NOT_ACTIVE")
        if execution.printer_profile_fingerprint != profile.local_printer_fingerprint:
            raise PhysicalExecutionRejected("PRINTER_PROFILE_FINGERPRINT_CHANGED")
        _, layout_hash = canonical_layout_sha256(
            version.layout_json,
            label_width_mm=float(version.label_width_mm),
            label_height_mm=float(version.label_height_mm),
        )
        if layout_hash != version.layout_sha256 or layout_hash != execution.layout_sha256:
            raise PhysicalExecutionRejected("PHYSICAL_LAYOUT_HASH_CONFLICT")
        compatibility = PrinterProfileService(self.db, self.config).compatibility(profile.id, version.id)
        if compatibility["result"] != COMPATIBLE:
            raise PhysicalExecutionRejected(str(compatibility["result"]))
        return job, item, reservation, version, stored, profile

    def next_control(self, *, machine_binding_id: str) -> dict[str, Any] | None:
        self._require_gate()
        binding = self._binding(machine_binding_id)
        execution = self.db.scalar(
            select(PrintExecutionRecord)
            .where(
                PrintExecutionRecord.organisation_id == self.scope.organisation_id,
                PrintExecutionRecord.participant_id == self.scope.participant_id,
                PrintExecutionRecord.agent_binding_id == binding.id,
                PrintExecutionRecord.state == "PAYLOAD_DELIVERED",
                PrintExecutionRecord.printer_profile_id.is_not(None),
            )
            .order_by(PrintExecutionRecord.payload_delivered_at, PrintExecutionRecord.id)
            .limit(1)
        )
        if execution is None:
            return None
        _, _, reservation, _, _, profile = self._graph(execution)
        return {
            "contract_version": PRINT_PROTOCOL_VERSION,
            "operation": PHYSICAL_OPERATION,
            "execution_id": execution.id,
            "print_job_item_id": execution.print_job_item_id,
            "delivery_reservation_id": reservation.id,
            "payload_sha256": execution.payload_sha256,
            "layout_sha256": execution.layout_sha256,
            "template_version_id": execution.template_version_id,
            "printer_profile_id": profile.id,
            "printer_profile_fingerprint": profile.local_printer_fingerprint,
            "agent_printer_id": profile.agent_printer_id,
            "organisation_id": execution.organisation_id,
            "participant_id": execution.participant_id,
            "agent_binding_id": execution.agent_binding_id,
            "printing_contract_version": PRINTING_CONTRACT_VERSION,
            "layout_schema_version": PRINT_LAYOUT_SCHEMA_VERSION,
            "renderer_version": RENDERER_VERSION,
            "copies": 1,
        }

    def render_contract(self, execution_id: str, *, machine_binding_id: str) -> dict[str, Any]:
        self._require_gate()
        self._binding(machine_binding_id)
        execution = self._execution(execution_id)
        if execution.agent_binding_id != machine_binding_id or execution.state != "PAYLOAD_DELIVERED":
            raise PhysicalExecutionRejected("PHYSICAL_EXECUTION_NOT_RENDERABLE")
        _, _, _, version, stored, profile = self._graph(execution)
        return {
            "execution_id": execution.id,
            "layout": version.layout_json,
            "label_width_mm": float(version.label_width_mm),
            "label_height_mm": float(version.label_height_mm),
            "dpi_x": profile.dpi_x,
            "dpi_y": profile.dpi_y,
            "media_width_mm": float(profile.media_width_mm),
            "media_height_mm": float(profile.media_height_mm),
            "physical_width_px": profile.physical_width_px,
            "physical_height_px": profile.physical_height_px,
            "printable_width_px": profile.printable_width_px,
            "printable_height_px": profile.printable_height_px,
            "offset_x_px": profile.offset_x_px,
            "offset_y_px": profile.offset_y_px,
            "printer_profile_state": profile.state,
            "printer_profile_fingerprint": profile.local_printer_fingerprint,
            "agent_printer_id": profile.agent_printer_id,
            "field_values": {"GTIN": stored.gtin},
        }

    def mark_rendered(
        self,
        execution_id: str,
        *,
        machine_binding_id: str,
        payload_sha256: str,
        layout_sha256: str,
        printer_profile_id: str,
        printer_profile_fingerprint: str,
        renderer_version: str,
        decoder_version: str,
    ) -> dict[str, Any]:
        self._require_gate()
        self._binding(machine_binding_id)
        execution = self._execution(execution_id, lock=True)
        if execution.agent_binding_id != machine_binding_id or execution.state != "PAYLOAD_DELIVERED":
            raise PhysicalExecutionRejected("PHYSICAL_RENDER_TRANSITION_NOT_ALLOWED")
        _, item, _, _, _, profile = self._graph(execution)
        if (
            payload_sha256 != execution.payload_sha256
            or layout_sha256 != execution.layout_sha256
            or printer_profile_id != profile.id
            or printer_profile_fingerprint != profile.local_printer_fingerprint
            or renderer_version != RENDERER_VERSION
        ):
            raise PhysicalExecutionRejected("PHYSICAL_RENDER_EVIDENCE_MISMATCH")
        if not decoder_version or len(decoder_version) > 64:
            raise PhysicalExecutionRejected("DECODER_VERSION_REQUIRED")
        now = _now()
        execution.state = "RENDERED_VERIFIED"
        execution.renderer_version = renderer_version
        execution.rendered_at = now
        item.state = "RENDERED"
        self.db.flush()
        self._audit(
            "PRINT_RENDER_VERIFIED",
            execution=execution,
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "print_execution_id": execution.id,
                "print_job_item_id": execution.print_job_item_id,
                "binding_id": execution.agent_binding_id,
                "printer_profile_id": profile.id,
                "printer_profile_fingerprint": profile.local_printer_fingerprint,
                "payload_sha256": execution.payload_sha256,
                "layout_sha256": execution.layout_sha256,
                "renderer_version": renderer_version,
                "decoder_version": decoder_version,
                "attempt_count": execution.attempt_number,
            },
            event_key=f"physical-print:{execution.id}:rendered",
        )
        return {"state": execution.state, "execution_id": execution.id}

    def begin_spool(
        self,
        execution_id: str,
        *,
        machine_binding_id: str,
        payload_sha256: str,
        layout_sha256: str,
        printer_profile_id: str,
        printer_profile_fingerprint: str,
    ) -> dict[str, Any]:
        self._require_gate()
        self._binding(machine_binding_id)
        execution = self._execution(execution_id, lock=True)
        if execution.agent_binding_id != machine_binding_id or execution.state != "RENDERED_VERIFIED":
            raise PhysicalExecutionRejected("SPOOL_BOUNDARY_NOT_ALLOWED")
        _, _, _, _, _, profile = self._graph(execution)
        if (
            payload_sha256 != execution.payload_sha256
            or layout_sha256 != execution.layout_sha256
            or printer_profile_id != profile.id
            or printer_profile_fingerprint != profile.local_printer_fingerprint
        ):
            raise PhysicalExecutionRejected("SPOOL_BOUNDARY_EVIDENCE_MISMATCH")
        now = _now()
        execution.state = "SPOOL_SUBMITTING"
        execution.spool_submitting_at = now
        self.db.flush()
        self._audit(
            "PRINT_SPOOL_SUBMITTED",
            execution=execution,
            outcome=AuditOutcome.PENDING,
            metadata={
                "print_execution_id": execution.id,
                "print_job_item_id": execution.print_job_item_id,
                "binding_id": execution.agent_binding_id,
                "printer_profile_id": profile.id,
                "printer_profile_fingerprint": profile.local_printer_fingerprint,
                "payload_sha256": execution.payload_sha256,
                "layout_sha256": execution.layout_sha256,
                "attempt_count": execution.attempt_number,
                "safe_status": "SPOOL_SUBMITTING",
            },
            event_key=f"physical-print:{execution.id}:spool-submitting",
        )
        return {"state": execution.state, "execution_id": execution.id}

    def report_result(
        self,
        execution_id: str,
        *,
        machine_binding_id: str,
        state: str,
        windows_spool_job_id: int | None = None,
        last_windows_status: str | None = None,
        safe_error_code: str | None = None,
    ) -> dict[str, Any]:
        self._require_gate()
        self._binding(machine_binding_id)
        execution = self._execution(execution_id, lock=True)
        if execution.agent_binding_id != machine_binding_id:
            raise PhysicalExecutionRejected("PRINT_EXECUTION_BINDING_MISMATCH")
        job, item, _, _, _, profile = self._graph(execution)
        now = _now()
        safe_status = (last_windows_status or "UNKNOWN")[:64]
        if safe_status not in SAFE_WINDOWS_STATUS:
            safe_status = "UNKNOWN"

        if state == "SPOOL_JOB_CREATED":
            if execution.state not in {"SPOOL_SUBMITTING", "SPOOL_JOB_CREATED"}:
                raise PhysicalExecutionRejected("SPOOL_JOB_CREATED_TRANSITION_NOT_ALLOWED")
            if type(windows_spool_job_id) is not int or windows_spool_job_id <= 0:
                raise PhysicalExecutionRejected("WINDOWS_SPOOL_JOB_ID_REQUIRED")
            if execution.windows_spool_job_id not in {None, windows_spool_job_id}:
                raise PhysicalExecutionRejected("WINDOWS_SPOOL_JOB_ID_CONFLICT")
            execution.state = "SPOOL_JOB_CREATED"
            execution.windows_spool_job_id = windows_spool_job_id
            execution.last_windows_status = safe_status
            execution.spool_job_created_at = execution.spool_job_created_at or now
            self.db.flush()
            return self.execution_status(execution.id)

        if state == "FAILED_PRE_SPOOL":
            if execution.state not in {"PAYLOAD_DELIVERED", "RENDERED_VERIFIED", "SPOOL_SUBMITTING"}:
                raise PhysicalExecutionRejected("FAILED_PRE_SPOOL_NOT_PROVEN")
            if windows_spool_job_id is not None or execution.windows_spool_job_id is not None:
                raise PhysicalExecutionRejected("FAILED_PRE_SPOOL_NOT_PROVEN")
            execution.state = "FAILED_PRE_SPOOL"
            execution.safe_error_code = (safe_error_code or "PHYSICAL_EXECUTION_FAILED_PRE_SPOOL")[:96]
            execution.terminal_at = now
            item.state = "FAILED"
            item.error_code = execution.safe_error_code
            job.state = "FAILED"
            event_type, audit_outcome = "PRINT_EXECUTION_FAILED", AuditOutcome.FAILED
        elif state == "BLOCKED":
            if execution.state not in {"PAYLOAD_DELIVERED", "RENDERED_VERIFIED"}:
                raise PhysicalExecutionRejected("PHYSICAL_BLOCKED_TRANSITION_NOT_ALLOWED")
            if execution.spool_submitting_at is not None or execution.windows_spool_job_id is not None:
                raise PhysicalExecutionRejected("PHYSICAL_BLOCKED_AFTER_SPOOL_BOUNDARY")
            execution.state = "BLOCKED"
            execution.safe_error_code = (safe_error_code or "PHYSICAL_EXECUTION_BLOCKED")[:96]
            execution.terminal_at = now
            item.state = "BLOCKED"
            item.error_code = execution.safe_error_code
            job.state = "BLOCKED"
            event_type, audit_outcome = "PRINT_EXECUTION_FAILED", AuditOutcome.FAILED
        elif state == "UNKNOWN_AFTER_SPOOL":
            if execution.state not in {"SPOOL_SUBMITTING", "SPOOL_JOB_CREATED"}:
                raise PhysicalExecutionRejected("UNKNOWN_AFTER_SPOOL_TRANSITION_NOT_ALLOWED")
            if windows_spool_job_id is not None:
                if type(windows_spool_job_id) is not int or windows_spool_job_id <= 0:
                    raise PhysicalExecutionRejected("WINDOWS_SPOOL_JOB_ID_INVALID")
                if execution.windows_spool_job_id not in {None, windows_spool_job_id}:
                    raise PhysicalExecutionRejected("WINDOWS_SPOOL_JOB_ID_CONFLICT")
                execution.windows_spool_job_id = windows_spool_job_id
                execution.spool_job_created_at = execution.spool_job_created_at or now
            execution.state = "UNKNOWN_AFTER_SPOOL"
            execution.last_windows_status = safe_status
            execution.safe_error_code = (safe_error_code or "UNKNOWN_AFTER_SPOOL")[:96]
            execution.terminal_at = now
            item.state = "BLOCKED"
            item.error_code = "UNKNOWN_AFTER_SPOOL"
            job.state = "BLOCKED"
            event_type, audit_outcome = "PRINT_EXECUTION_UNKNOWN", AuditOutcome.AMBIGUOUS
        elif state == "SPOOLER_ACCEPTED":
            if execution.state != "SPOOL_JOB_CREATED":
                raise PhysicalExecutionRejected("SPOOLER_ACCEPTED_TRANSITION_NOT_ALLOWED")
            if type(windows_spool_job_id) is not int or windows_spool_job_id <= 0:
                raise PhysicalExecutionRejected("WINDOWS_SPOOL_JOB_ID_REQUIRED")
            if execution.windows_spool_job_id != windows_spool_job_id:
                raise PhysicalExecutionRejected("WINDOWS_SPOOL_JOB_ID_CONFLICT")
            execution.state = "SPOOLER_ACCEPTED"
            execution.last_windows_status = safe_status
            execution.spooler_accepted_at = now
            execution.terminal_at = now
            item.state = "COMPLETED"
            item.error_code = None
            event_type, audit_outcome = "PRINT_SPOOL_ACCEPTED", AuditOutcome.SUCCESS
        else:
            raise PhysicalExecutionRejected("UNSUPPORTED_PHYSICAL_RESULT_STATE")

        self.db.flush()
        self._audit(
            event_type,
            execution=execution,
            outcome=audit_outcome,
            metadata={
                "print_execution_id": execution.id,
                "print_job_item_id": execution.print_job_item_id,
                "binding_id": execution.agent_binding_id,
                "printer_profile_id": profile.id,
                "printer_profile_fingerprint": profile.local_printer_fingerprint,
                "payload_sha256": execution.payload_sha256,
                "layout_sha256": execution.layout_sha256,
                "windows_spool_job_id": execution.windows_spool_job_id,
                "safe_status": execution.last_windows_status,
                "error_code": execution.safe_error_code,
                "attempt_count": execution.attempt_number,
            },
            event_key=f"physical-print:{execution.id}:{execution.state.lower()}",
        )

        if execution.state == "SPOOLER_ACCEPTED":
            remaining = list(self.db.scalars(select(PrintJobItemRecord).where(
                PrintJobItemRecord.print_job_id == job.id,
                PrintJobItemRecord.organisation_id == self.scope.organisation_id,
                PrintJobItemRecord.participant_id == self.scope.participant_id,
            )))
            if remaining and all(row.state == "COMPLETED" for row in remaining):
                job.state = "COMPLETED"
                existing_event = self.db.scalar(select(PrintEventRecord).where(
                    PrintEventRecord.print_job_id == job.id,
                    PrintEventRecord.event_type.in_(("PRINT_JOB_COMPLETED", "REPRINT_COMPLETED")),
                    PrintEventRecord.outcome == "SUCCESS",
                ))
                if existing_event is None:
                    event = PrintEventRecord(
                        id=str(uuid4()),
                        organisation_id=job.organisation_id,
                        participant_id=job.participant_id,
                        print_job_id=job.id,
                        template_version_id=job.template_version_id,
                        payload_hash=(job.metadata_sanitized_json or {}).get("payload_set_sha256"),
                        actor_kind="WINDOWS_AGENT",
                        printer_profile_fingerprint=execution.printer_profile_fingerprint,
                        event_type="REPRINT_COMPLETED" if job.mode != "INITIAL_PRINT" else "PRINT_JOB_COMPLETED",
                        outcome="SUCCESS",
                        error_code=None,
                        original_print_event_id=job.original_print_event_id,
                        evidence_sha256=(job.metadata_sanitized_json or {}).get("payload_set_sha256"),
                        metadata_sanitized_json={
                            "count": job.item_count,
                            "mode": job.mode,
                            "completion_semantics": "SPOOLER_ACCEPTED_NOT_PHYSICAL_PROOF",
                        },
                    )
                    self.db.add(event)
                    self.db.flush()
        return self.execution_status(execution.id)

    def status_control(
        self,
        execution_id: str,
        *,
        machine_binding_id: str,
    ) -> dict[str, Any]:
        self._require_gate()
        self._binding(machine_binding_id)
        execution = self._execution(execution_id)
        if execution.agent_binding_id != machine_binding_id:
            raise PhysicalExecutionRejected("PRINT_EXECUTION_BINDING_MISMATCH")
        if execution.state not in {"SPOOL_JOB_CREATED", "SPOOLER_ACCEPTED", "UNKNOWN_AFTER_SPOOL"}:
            raise PhysicalExecutionRejected("PRINT_STATUS_NOT_AVAILABLE")
        if execution.windows_spool_job_id is None or not execution.printer_profile_id:
            raise PhysicalExecutionRejected("PRINT_STATUS_TARGET_INCOMPLETE")
        profile = self.db.scalar(select(PrinterProfileRecord).where(
            PrinterProfileRecord.id == execution.printer_profile_id,
            PrinterProfileRecord.organisation_id == self.scope.organisation_id,
            PrinterProfileRecord.participant_id == self.scope.participant_id,
            PrinterProfileRecord.agent_binding_id == machine_binding_id,
        ))
        if profile is None:
            raise PhysicalExecutionRejected("PRINTER_PROFILE_NOT_FOUND")
        if execution.printer_profile_fingerprint != profile.local_printer_fingerprint:
            raise PhysicalExecutionRejected("PRINTER_PROFILE_FINGERPRINT_CHANGED")
        return {
            "contract_version": PRINT_PROTOCOL_VERSION,
            "operation": "PRINT_STATUS",
            "execution_id": execution.id,
            "printer_profile_id": profile.id,
            "printer_profile_fingerprint": profile.local_printer_fingerprint,
            "agent_printer_id": profile.agent_printer_id,
            "windows_spool_job_id": execution.windows_spool_job_id,
        }

    def observe_status(
        self,
        execution_id: str,
        *,
        machine_binding_id: str,
        windows_spool_job_id: int,
        normalized_state: str,
        safe_error_code: str | None = None,
    ) -> dict[str, Any]:
        self._require_gate()
        self._binding(machine_binding_id)
        execution = self._execution(execution_id, lock=True)
        if execution.agent_binding_id != machine_binding_id:
            raise PhysicalExecutionRejected("PRINT_EXECUTION_BINDING_MISMATCH")
        if execution.windows_spool_job_id != windows_spool_job_id:
            raise PhysicalExecutionRejected("WINDOWS_SPOOL_JOB_ID_CONFLICT")
        status = normalized_state if normalized_state in SAFE_WINDOWS_STATUS else "UNKNOWN"
        execution.last_windows_status = status
        if safe_error_code:
            execution.safe_error_code = safe_error_code[:96]
        self.db.flush()
        return self.execution_status(execution.id)

    def execution_status(self, execution_id: str) -> dict[str, Any]:
        execution = self._execution(execution_id)
        warning = UNKNOWN_REPRINT_WARNING if execution.state == "UNKNOWN_AFTER_SPOOL" else None
        display = "Отправлено на принтер" if execution.state == "SPOOLER_ACCEPTED" else None
        return {
            "execution_id": execution.id,
            "print_job_id": execution.print_job_id,
            "print_job_item_id": execution.print_job_item_id,
            "state": execution.state,
            "payload_sha256": execution.payload_sha256,
            "layout_sha256": execution.layout_sha256,
            "printer_profile_id": execution.printer_profile_id,
            "printer_profile_fingerprint": execution.printer_profile_fingerprint,
            "windows_spool_job_id": execution.windows_spool_job_id,
            "last_windows_status": execution.last_windows_status,
            "safe_error_code": execution.safe_error_code,
            "attempt_number": execution.attempt_number,
            "display_status": display,
            "reprint_warning": warning,
            "physical_output_proven": False,
        }

    def explicit_reprint_unknown(
        self,
        execution_id: str,
        *,
        user_id: int,
        acknowledge_duplicate_risk: bool,
    ) -> dict[str, Any]:
        self._require_gate()
        execution = self._execution(execution_id, lock=True)
        if execution.state != "UNKNOWN_AFTER_SPOOL":
            raise PhysicalExecutionRejected("AMBIGUOUS_REPRINT_REQUIRES_UNKNOWN_EXECUTION")
        if not acknowledge_duplicate_risk:
            raise PhysicalExecutionRejected("DUPLICATE_LABEL_RISK_ACK_REQUIRED")
        if not execution.printer_profile_id:
            raise PhysicalExecutionRejected("PRINTER_PROFILE_REQUIRED")
        new_job = LocalPrintingService(self.db, self.config).create_print_job(
            stored_item_ids=[execution.stored_full_km_item_id],
            template_version_id=execution.template_version_id,
            user_id=user_id,
            mode="REPRINT_ORIGINAL_TEMPLATE",
            printer_profile_id=execution.printer_profile_id,
        )
        return {
            "new_print_job_id": new_job.id,
            "state": new_job.state,
            "warning": UNKNOWN_REPRINT_WARNING,
            "source_execution_id": execution.id,
        }
