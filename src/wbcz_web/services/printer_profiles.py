from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz.printer_profiles import (
    COMPATIBLE,
    DISCOVERY_CAPABILITY,
    MAX_PRINTERS_DEFAULT,
    PRINT_PROTOCOL_VERSION,
    PrinterObservation,
    PrinterProfileContractError,
    evaluate_template_compatibility,
)
from wbcz_web.config import WebConfig
from wbcz_web.models import (
    AgentBindingRecord,
    AgentJobRecord,
    PrinterDiscoveryObservationRecord,
    PrinterDiscoveryRunRecord,
    PrinterProfileRecord,
    PrintTemplateVersionRecord,
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
from wbcz_web.services.tenant import active_tenant


class PrinterProfileRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code[:96]
        super().__init__(self.code)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _json_sha(value: Mapping[str, Any] | list[Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class PrinterProfileService:
    def __init__(self, db: Session, config: WebConfig) -> None:
        self.db = db
        self.config = config
        self.scope = active_tenant(db)

    def _require_printing(self) -> None:
        if not self.config.printing_enabled:
            raise PrinterProfileRejected("PRINTING_DISABLED")

    def _audit(
        self,
        event_type: str,
        *,
        subject_id: str,
        metadata: dict[str, Any],
        user_id: int | None = None,
        actor_kind: ActorKind = ActorKind.USER,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        event_key: str,
    ) -> None:
        trace_data = self.db.info.get("audit_trace")
        trace = trace_data if isinstance(trace_data, dict) else {}
        actor = (
            ActorContext(ActorKind.USER, user_id=user_id)
            if user_id is not None
            else ActorContext(
                actor_kind,
                machine_principal="printing-agent" if actor_kind is ActorKind.WINDOWS_AGENT else None,
            )
        )
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=actor,
            tenant=AuditTenantScope(self.scope.organisation_id, self.scope.participant_id),
            subject=SubjectRef(SubjectType.INTEGRATION_CONNECTION, subject_id),
            outcome=outcome,
            authorization_decision=(
                AuthorizationDecision.ALLOW if user_id is not None
                else AuthorizationDecision.NOT_APPLICABLE
            ),
            trace=TraceContext(
                request_id=trace.get("request_id"),
                correlation_id=trace.get("correlation_id"),
                causation_id=trace.get("causation_id"),
                event_key=event_key[:256],
            ),
            metadata=metadata,
        )

    def _binding(self, binding_id: str, *, lock: bool = False) -> AgentBindingRecord:
        stmt = select(AgentBindingRecord).where(
            AgentBindingRecord.id == binding_id,
            AgentBindingRecord.organisation_id == self.scope.organisation_id,
            AgentBindingRecord.participant_id == self.scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise PrinterProfileRejected("AGENT_BINDING_NOT_FOUND")
        return row

    def _validate_discovery_binding(self, binding: AgentBindingRecord) -> None:
        if binding.state != "ACTIVE" or binding.protocol_compatibility_state != "COMPATIBLE":
            raise PrinterProfileRejected("AGENT_BINDING_NOT_ACTIVE")
        if binding.last_seen_at is None or (
            _now() - _aware(binding.last_seen_at)
        ).total_seconds() > self.config.agent_health_stale_seconds:
            raise PrinterProfileRejected("AGENT_BINDING_NOT_FRESH")
        caps = set(binding.supported_capabilities_json or ())
        if DISCOVERY_CAPABILITY not in caps:
            raise PrinterProfileRejected("PRINT_DISCOVER_PRINTERS_CAPABILITY_REQUIRED")

    def request_discovery(self, *, agent_binding_id: str, user_id: int) -> PrinterDiscoveryRunRecord:
        self._require_printing()
        binding = self._binding(agent_binding_id, lock=True)
        self._validate_discovery_binding(binding)
        existing = self.db.scalar(
            select(PrinterDiscoveryRunRecord)
            .where(
                PrinterDiscoveryRunRecord.organisation_id == self.scope.organisation_id,
                PrinterDiscoveryRunRecord.participant_id == self.scope.participant_id,
                PrinterDiscoveryRunRecord.agent_binding_id == binding.id,
                PrinterDiscoveryRunRecord.state.in_(("PENDING", "RUNNING")),
            )
            .with_for_update()
        )
        if existing is not None:
            return existing

        now = _now()
        run = PrinterDiscoveryRunRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            agent_binding_id=binding.id,
            state="PENDING",
            requested_by_user_id=user_id,
            requested_at=now,
            correlation_id=(
                self.db.info.get("audit_trace", {}).get("correlation_id")
                if isinstance(self.db.info.get("audit_trace"), dict) else None
            ),
        )
        self.db.add(run)
        self.db.flush()
        payload = {
            "contract_version": PRINT_PROTOCOL_VERSION,
            "operation": "LIST",
            "discovery_request_id": run.id,
            "agent_printer_id": None,
        }
        job = AgentJobRecord(
            job_id="printer-discovery-" + run.id,
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            correlation_id=run.correlation_id,
            agent_binding_id=binding.id,
            job_type="PRINTER_DISCOVERY",
            operation_id=run.id,
            purpose="PRINTER_DISCOVERY",
            payload_sha256=_json_sha(payload),
            payload_json=payload,
            state="PENDING",
            available_at=now,
            priority=50,
        )
        self.db.add(job)
        self.db.flush()
        run.agent_job_id = job.job_id
        self._audit(
            "PRINTER_DISCOVERY_REQUESTED",
            subject_id=binding.id,
            user_id=user_id,
            metadata={
                "binding_id": binding.id,
                "state": run.state,
                "discovery_request_id": run.id,
            },
            event_key=f"printer-discovery:{run.id}:requested",
        )
        return run

    def _run(self, run_id: str, *, lock: bool = False) -> PrinterDiscoveryRunRecord:
        stmt = select(PrinterDiscoveryRunRecord).where(
            PrinterDiscoveryRunRecord.id == run_id,
            PrinterDiscoveryRunRecord.organisation_id == self.scope.organisation_id,
            PrinterDiscoveryRunRecord.participant_id == self.scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError(run_id)
        return row

    def discovery_status(self, run_id: str) -> dict[str, Any]:
        run = self._run(run_id)
        observations = list(self.db.scalars(
            select(PrinterDiscoveryObservationRecord)
            .where(
                PrinterDiscoveryObservationRecord.discovery_run_id == run.id,
                PrinterDiscoveryObservationRecord.organisation_id == self.scope.organisation_id,
                PrinterDiscoveryObservationRecord.participant_id == self.scope.participant_id,
            )
            .order_by(
                PrinterDiscoveryObservationRecord.display_name_sanitized,
                PrinterDiscoveryObservationRecord.agent_printer_id,
            )
        ))
        return {
            "id": run.id,
            "agent_binding_id": run.agent_binding_id,
            "state": run.state,
            "requested_at": run.requested_at.isoformat(),
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "printer_count": run.printer_count,
            "safe_error_code": run.safe_error_code,
            "observations": [self._observation_dto(row) for row in observations],
        }

    @staticmethod
    def _observation_dto(row: PrinterDiscoveryObservationRecord) -> dict[str, Any]:
        return {
            "id": row.id,
            "agent_printer_id": row.agent_printer_id,
            "display_name": row.display_name_sanitized,
            "driver_display_name": row.driver_name_sanitized,
            "availability_state": row.availability_state,
            "dpi_x": row.dpi_x,
            "dpi_y": row.dpi_y,
            "media_width_mm": float(row.media_width_mm),
            "media_height_mm": float(row.media_height_mm),
            "orientation": row.orientation,
            "printable_width_px": row.printable_width_px,
            "printable_height_px": row.printable_height_px,
            "offset_x_px": row.offset_x_px,
            "offset_y_px": row.offset_y_px,
            "observed_at": row.observed_at.isoformat(),
            "safe_error_code": row.safe_error_code,
        }

    def fetch_agent_job(self, *, machine_binding_id: str) -> dict[str, Any] | None:
        self._require_printing()
        binding = self._binding(machine_binding_id, lock=True)
        self._validate_discovery_binding(binding)
        now = _now()
        stmt = (
            select(AgentJobRecord)
            .where(
                AgentJobRecord.organisation_id == self.scope.organisation_id,
                AgentJobRecord.participant_id == self.scope.participant_id,
                AgentJobRecord.agent_binding_id == binding.id,
                AgentJobRecord.job_type == "PRINTER_DISCOVERY",
                (
                    (AgentJobRecord.state == "PENDING")
                    | (
                        (AgentJobRecord.state == "LEASED")
                        & (AgentJobRecord.lease_expires_at.is_not(None))
                        & (AgentJobRecord.lease_expires_at <= now)
                    )
                ),
                AgentJobRecord.available_at <= now,
            )
            .order_by(AgentJobRecord.priority, AgentJobRecord.created_at, AgentJobRecord.job_id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job = self.db.scalar(stmt)
        if job is None:
            return None
        run = self._run(job.operation_id, lock=True)
        if run.agent_binding_id != binding.id:
            raise PrinterProfileRejected("PRINTER_DISCOVERY_JOB_BINDING_MISMATCH")
        job.state = "LEASED"
        job.leased_at = now
        job.lease_expires_at = now + timedelta(seconds=self.config.agent_job_lease_seconds)
        job.delivery_count += 1
        run.state = "RUNNING"
        self.db.flush()
        return {
            "job_id": job.job_id,
            **dict(job.payload_json or {}),
        }

    def complete_agent_job(
        self,
        *,
        job_id: str,
        machine_binding_id: str,
        observations: list[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require_printing()
        binding = self._binding(machine_binding_id, lock=True)
        self._validate_discovery_binding(binding)
        job = self.db.scalar(
            select(AgentJobRecord)
            .where(
                AgentJobRecord.job_id == job_id,
                AgentJobRecord.organisation_id == self.scope.organisation_id,
                AgentJobRecord.participant_id == self.scope.participant_id,
                AgentJobRecord.agent_binding_id == binding.id,
                AgentJobRecord.job_type == "PRINTER_DISCOVERY",
            )
            .with_for_update()
        )
        if job is None:
            raise PrinterProfileRejected("PRINTER_DISCOVERY_JOB_NOT_FOUND")
        if len(observations) > MAX_PRINTERS_DEFAULT:
            raise PrinterProfileRejected("PRINTER_DISCOVERY_RESULT_TOO_LARGE")

        parsed = [PrinterObservation.from_mapping(value) for value in observations]
        ids = [item.agent_printer_id for item in parsed]
        if len(ids) != len(set(ids)):
            raise PrinterProfileRejected("DUPLICATE_AGENT_PRINTER_ID")
        result_hash = _json_sha([item.safe_dict() for item in parsed])
        if job.state == "COMPLETED":
            if job.result_sha256 == result_hash:
                return {"state": "COMPLETED", "printer_count": len(parsed)}
            raise PrinterProfileRejected("PRINTER_DISCOVERY_RESULT_REPLAY_CONFLICT")
        now = _now()
        if (
            job.state != "LEASED"
            or job.lease_expires_at is None
            or _aware(job.lease_expires_at) <= now
        ):
            raise PrinterProfileRejected("PRINTER_DISCOVERY_JOB_NOT_LEASED")

        run = self._run(job.operation_id, lock=True)
        if run.agent_binding_id != binding.id:
            raise PrinterProfileRejected("PRINTER_DISCOVERY_JOB_BINDING_MISMATCH")

        existing_rows = list(self.db.scalars(
            select(PrinterDiscoveryObservationRecord).where(
                PrinterDiscoveryObservationRecord.discovery_run_id == run.id
            )
        ))
        if existing_rows:
            raise PrinterProfileRejected("PRINTER_DISCOVERY_RESULT_ALREADY_PARTIAL")

        observed_ids: set[str] = set()
        for item in parsed:
            observed_at = datetime.fromisoformat(item.observed_at.replace("Z", "+00:00"))
            row = PrinterDiscoveryObservationRecord(
                id=str(uuid4()),
                organisation_id=self.scope.organisation_id,
                participant_id=self.scope.participant_id,
                agent_binding_id=binding.id,
                discovery_run_id=run.id,
                agent_printer_id=item.agent_printer_id,
                local_printer_fingerprint=item.local_printer_fingerprint,
                display_name_sanitized=item.display_name_sanitized,
                driver_name_sanitized=item.driver_name_sanitized,
                dpi_x=item.dpi_x,
                dpi_y=item.dpi_y,
                media_width_mm=item.media_width_mm,
                media_height_mm=item.media_height_mm,
                orientation=item.orientation,
                physical_width_px=item.physical_width_px,
                physical_height_px=item.physical_height_px,
                printable_width_px=item.printable_width_px,
                printable_height_px=item.printable_height_px,
                offset_x_px=item.offset_x_px,
                offset_y_px=item.offset_y_px,
                capability_hash=item.capability_hash,
                availability_state=item.availability_state,
                observed_at=observed_at,
                safe_error_code=item.safe_error_code,
            )
            self.db.add(row)
            observed_ids.add(item.agent_printer_id)
            self._reconcile_profile(binding.id, item, observed_at)
        self.db.flush()

        profiles = list(self.db.scalars(
            select(PrinterProfileRecord)
            .where(
                PrinterProfileRecord.organisation_id == self.scope.organisation_id,
                PrinterProfileRecord.participant_id == self.scope.participant_id,
                PrinterProfileRecord.agent_binding_id == binding.id,
            )
            .with_for_update()
        ))
        for profile in profiles:
            if profile.state != "DISABLED" and profile.agent_printer_id not in observed_ids:
                if profile.state != "MISSING":
                    profile.state = "MISSING"
                    self._audit(
                        "PRINTER_PROFILE_STALE",
                        subject_id=profile.id,
                        actor_kind=ActorKind.WINDOWS_AGENT,
                        metadata={
                            "printer_profile_id": profile.id,
                            "binding_id": binding.id,
                            "state": "MISSING",
                            "safe_reason_code": "PRINTER_NOT_OBSERVED",
                        },
                        event_key=f"printer-profile:{profile.id}:missing:{run.id}",
                    )

        now = _now()
        run.state = "COMPLETED"
        run.completed_at = now
        run.printer_count = len(parsed)
        run.safe_error_code = None
        job.state = "COMPLETED"
        job.result_sha256 = result_hash
        job.result_json = {"printer_count": len(parsed), "discovery_request_id": run.id}
        job.lease_expires_at = None
        self.db.flush()
        self._audit(
            "PRINTER_DISCOVERY_COMPLETED",
            subject_id=binding.id,
            actor_kind=ActorKind.WINDOWS_AGENT,
            metadata={
                "binding_id": binding.id,
                "state": run.state,
                "discovery_request_id": run.id,
                "printer_count": len(parsed),
            },
            event_key=f"printer-discovery:{run.id}:completed",
        )
        return {"state": "COMPLETED", "printer_count": len(parsed)}

    def fail_agent_job(
        self,
        *,
        job_id: str,
        machine_binding_id: str,
        safe_error_code: str,
    ) -> dict[str, Any]:
        self._require_printing()
        binding = self._binding(machine_binding_id, lock=True)
        job = self.db.scalar(
            select(AgentJobRecord)
            .where(
                AgentJobRecord.job_id == job_id,
                AgentJobRecord.organisation_id == self.scope.organisation_id,
                AgentJobRecord.participant_id == self.scope.participant_id,
                AgentJobRecord.agent_binding_id == binding.id,
                AgentJobRecord.job_type == "PRINTER_DISCOVERY",
            )
            .with_for_update()
        )
        if job is None:
            raise PrinterProfileRejected("PRINTER_DISCOVERY_JOB_NOT_FOUND")
        if (
            job.state != "LEASED"
            or job.lease_expires_at is None
            or _aware(job.lease_expires_at) <= _now()
        ):
            raise PrinterProfileRejected("PRINTER_DISCOVERY_JOB_NOT_LEASED")
        run = self._run(job.operation_id, lock=True)
        code = (safe_error_code or "PRINTER_DISCOVERY_FAILED")[:80]
        run.state = "FAILED"
        run.completed_at = _now()
        run.safe_error_code = code
        job.state = "COMPLETED"
        job.last_error_code = code
        job.result_sha256 = _json_sha({"status": "FAILED", "safe_error_code": code})
        job.result_json = {"status": "FAILED", "safe_error_code": code}
        job.lease_expires_at = None
        self.db.flush()
        self._audit(
            "PRINTER_DISCOVERY_COMPLETED",
            subject_id=binding.id,
            actor_kind=ActorKind.WINDOWS_AGENT,
            outcome=AuditOutcome.FAILED,
            metadata={
                "binding_id": binding.id,
                "state": run.state,
                "discovery_request_id": run.id,
                "printer_count": 0,
                "safe_reason_code": code,
            },
            event_key=f"printer-discovery:{run.id}:failed:{code}",
        )
        return {"state": "FAILED", "safe_error_code": code}


    def _reconcile_profile(
        self,
        binding_id: str,
        observation: PrinterObservation,
        observed_at: datetime,
    ) -> None:
        profile = self.db.scalar(
            select(PrinterProfileRecord)
            .where(
                PrinterProfileRecord.organisation_id == self.scope.organisation_id,
                PrinterProfileRecord.participant_id == self.scope.participant_id,
                PrinterProfileRecord.agent_binding_id == binding_id,
                PrinterProfileRecord.agent_printer_id == observation.agent_printer_id,
            )
            .with_for_update()
        )
        if profile is None or profile.state == "DISABLED":
            return
        profile.last_seen_at = observed_at
        if observation.availability_state != "AVAILABLE":
            if profile.state != "MISSING":
                profile.state = "MISSING"
                self._audit(
                    "PRINTER_PROFILE_STALE",
                    subject_id=profile.id,
                    actor_kind=ActorKind.WINDOWS_AGENT,
                    metadata={
                        "printer_profile_id": profile.id,
                        "binding_id": binding_id,
                        "state": "MISSING",
                        "safe_reason_code": observation.safe_error_code or "PRINTER_UNAVAILABLE",
                    },
                    event_key=f"printer-profile:{profile.id}:missing:{observation.capability_hash}",
                )
            return
        current_matches = (
            profile.local_printer_fingerprint == observation.local_printer_fingerprint
            and profile.capability_hash == observation.capability_hash
        )
        basic_compatible = self._basic_observation_compatible(observation)
        if not current_matches:
            if profile.state != "STALE":
                profile.state = "STALE"
                self._audit(
                    "PRINTER_PROFILE_STALE",
                    subject_id=profile.id,
                    actor_kind=ActorKind.WINDOWS_AGENT,
                    metadata={
                        "printer_profile_id": profile.id,
                        "binding_id": binding_id,
                        "state": "STALE",
                        "capability_hash": observation.capability_hash,
                        "safe_reason_code": "PRINTER_FINGERPRINT_CHANGED",
                    },
                    event_key=f"printer-profile:{profile.id}:stale:{observation.local_printer_fingerprint}",
                )
            return
        profile.state = "ACTIVE" if basic_compatible else "INCOMPATIBLE"

    @staticmethod
    def _basic_observation_compatible(observation: PrinterObservation) -> bool:
        return (
            observation.availability_state == "AVAILABLE"
            and observation.dpi_x == observation.dpi_y
            and 150 <= observation.dpi_x <= 1200
            and observation.printable_width_px > 0
            and observation.printable_height_px > 0
            and observation.offset_x_px + observation.printable_width_px <= observation.physical_width_px
            and observation.offset_y_px + observation.printable_height_px <= observation.physical_height_px
        )

    def _observation(self, observation_id: str, *, lock: bool = False) -> PrinterDiscoveryObservationRecord:
        stmt = select(PrinterDiscoveryObservationRecord).where(
            PrinterDiscoveryObservationRecord.id == observation_id,
            PrinterDiscoveryObservationRecord.organisation_id == self.scope.organisation_id,
            PrinterDiscoveryObservationRecord.participant_id == self.scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError(observation_id)
        return row

    @staticmethod
    def _observation_domain(row: PrinterDiscoveryObservationRecord) -> PrinterObservation:
        raw = {
            "agent_printer_id": row.agent_printer_id,
            "local_printer_fingerprint": row.local_printer_fingerprint,
            "display_name_sanitized": row.display_name_sanitized,
            "driver_name_sanitized": row.driver_name_sanitized,
            "dpi_x": row.dpi_x,
            "dpi_y": row.dpi_y,
            "media_width_mm": float(row.media_width_mm),
            "media_height_mm": float(row.media_height_mm),
            "orientation": row.orientation,
            "physical_width_px": row.physical_width_px,
            "physical_height_px": row.physical_height_px,
            "printable_width_px": row.printable_width_px,
            "printable_height_px": row.printable_height_px,
            "offset_x_px": row.offset_x_px,
            "offset_y_px": row.offset_y_px,
            "capability_hash": row.capability_hash,
            "observed_at": row.observed_at.isoformat(),
            "availability_state": row.availability_state,
            "safe_error_code": row.safe_error_code,
        }
        return PrinterObservation.from_mapping(raw)

    def approve_observation(
        self,
        observation_id: str,
        *,
        user_id: int,
    ) -> PrinterProfileRecord:
        self._require_printing()
        observation_row = self._observation(observation_id, lock=True)
        observation = self._observation_domain(observation_row)
        if observation.availability_state != "AVAILABLE":
            raise PrinterProfileRejected("PRINTER_NOT_AVAILABLE_FOR_APPROVAL")
        binding = self._binding(observation_row.agent_binding_id, lock=True)
        self._validate_discovery_binding(binding)
        profile = self.db.scalar(
            select(PrinterProfileRecord)
            .where(
                PrinterProfileRecord.organisation_id == self.scope.organisation_id,
                PrinterProfileRecord.participant_id == self.scope.participant_id,
                PrinterProfileRecord.agent_binding_id == binding.id,
                PrinterProfileRecord.agent_printer_id == observation.agent_printer_id,
            )
            .with_for_update()
        )
        state = "ACTIVE" if self._basic_observation_compatible(observation) else "INCOMPATIBLE"
        created = profile is None
        if profile is None:
            profile = PrinterProfileRecord(
                id=str(uuid4()),
                organisation_id=self.scope.organisation_id,
                participant_id=self.scope.participant_id,
                agent_binding_id=binding.id,
                agent_printer_id=observation.agent_printer_id,
                capability_revision=1,
                created_by_user_id=user_id,
                last_seen_at=observation_row.observed_at,
            )
            self.db.add(profile)
        else:
            profile.capability_revision += 1

        profile.local_printer_fingerprint = observation.local_printer_fingerprint
        profile.display_name_sanitized = observation.display_name_sanitized
        profile.driver_name_sanitized = observation.driver_name_sanitized
        profile.dpi_x = observation.dpi_x
        profile.dpi_y = observation.dpi_y
        profile.media_width_mm = observation.media_width_mm
        profile.media_height_mm = observation.media_height_mm
        profile.orientation = observation.orientation
        profile.physical_width_px = observation.physical_width_px
        profile.physical_height_px = observation.physical_height_px
        profile.printable_width_px = observation.printable_width_px
        profile.printable_height_px = observation.printable_height_px
        profile.offset_x_px = observation.offset_x_px
        profile.offset_y_px = observation.offset_y_px
        profile.capability_hash = observation.capability_hash
        profile.state = state
        profile.last_seen_at = observation_row.observed_at
        self.db.flush()
        event = "PRINTER_PROFILE_CREATED" if created else "PRINTER_PROFILE_UPDATED"
        self._audit(
            event,
            subject_id=profile.id,
            user_id=user_id,
            metadata={
                "printer_profile_id": profile.id,
                "binding_id": binding.id,
                "state": profile.state,
                "capability_hash": profile.capability_hash,
                "dpi_x": profile.dpi_x,
                "dpi_y": profile.dpi_y,
                "media_width_mm": float(profile.media_width_mm),
                "media_height_mm": float(profile.media_height_mm),
                "capability_revision": profile.capability_revision,
            },
            event_key=f"printer-profile:{profile.id}:{event}:{profile.capability_revision}",
        )
        return profile

    def _profile(self, profile_id: str, *, lock: bool = False) -> PrinterProfileRecord:
        stmt = select(PrinterProfileRecord).where(
            PrinterProfileRecord.id == profile_id,
            PrinterProfileRecord.organisation_id == self.scope.organisation_id,
            PrinterProfileRecord.participant_id == self.scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise KeyError(profile_id)
        return row

    def disable_profile(self, profile_id: str, *, user_id: int) -> PrinterProfileRecord:
        self._require_printing()
        row = self._profile(profile_id, lock=True)
        row.state = "DISABLED"
        self.db.flush()
        self._audit(
            "PRINTER_PROFILE_DISABLED",
            subject_id=row.id,
            user_id=user_id,
            metadata={
                "printer_profile_id": row.id,
                "binding_id": row.agent_binding_id,
                "state": row.state,
                "capability_revision": row.capability_revision,
            },
            event_key=f"printer-profile:{row.id}:disabled:{row.capability_revision}",
        )
        return row

    @staticmethod
    def _profile_dto(row: PrinterProfileRecord) -> dict[str, Any]:
        return {
            "printer_profile_id": row.id,
            "display_name": row.display_name_sanitized,
            "driver_display_name": row.driver_name_sanitized,
            "state": row.state,
            "dpi_x": row.dpi_x,
            "dpi_y": row.dpi_y,
            "media_width_mm": float(row.media_width_mm),
            "media_height_mm": float(row.media_height_mm),
            "orientation": row.orientation,
            "printable_width_px": row.printable_width_px,
            "printable_height_px": row.printable_height_px,
            "offset_x_px": row.offset_x_px,
            "offset_y_px": row.offset_y_px,
            "last_seen_at": row.last_seen_at.isoformat(),
            "capability_revision": row.capability_revision,
            "synthetic_test_state": "PHYSICAL_EXECUTION_BLOCKED_PHASE_C",
        }

    def list_profiles(self) -> list[dict[str, Any]]:
        rows = list(self.db.scalars(
            select(PrinterProfileRecord)
            .where(
                PrinterProfileRecord.organisation_id == self.scope.organisation_id,
                PrinterProfileRecord.participant_id == self.scope.participant_id,
            )
            .order_by(PrinterProfileRecord.display_name_sanitized, PrinterProfileRecord.id)
        ))
        return [self._profile_dto(row) for row in rows]

    def profile_detail(self, profile_id: str) -> dict[str, Any]:
        return self._profile_dto(self._profile(profile_id))

    def refresh_profile(self, profile_id: str, *, user_id: int) -> PrinterDiscoveryRunRecord:
        row = self._profile(profile_id)
        return self.request_discovery(agent_binding_id=row.agent_binding_id, user_id=user_id)

    def compatibility(self, profile_id: str, template_version_id: str) -> dict[str, Any]:
        profile = self._profile(profile_id)
        version = self.db.scalar(select(PrintTemplateVersionRecord).where(
            PrintTemplateVersionRecord.id == template_version_id,
            PrintTemplateVersionRecord.organisation_id == self.scope.organisation_id,
        ))
        if version is None or version.participant_id not in {None, self.scope.participant_id}:
            raise KeyError(template_version_id)
        result = evaluate_template_compatibility(
            profile_state=profile.state,
            dpi_x=profile.dpi_x,
            dpi_y=profile.dpi_y,
            media_width_mm=float(profile.media_width_mm),
            media_height_mm=float(profile.media_height_mm),
            physical_width_px=profile.physical_width_px,
            physical_height_px=profile.physical_height_px,
            printable_width_px=profile.printable_width_px,
            printable_height_px=profile.printable_height_px,
            offset_x_px=profile.offset_x_px,
            offset_y_px=profile.offset_y_px,
            template_layout=version.layout_json,
            label_width_mm=float(version.label_width_mm),
            label_height_mm=float(version.label_height_mm),
        )
        return {
            "printer_profile_id": profile.id,
            "template_version_id": version.id,
            **result,
        }

    def validate_future_execution_profile(
        self,
        *,
        profile_id: str,
        template_version_id: str,
        agent_binding_id: str | None = None,
    ) -> tuple[PrinterProfileRecord, dict[str, Any]]:
        profile = self._profile(profile_id)
        if agent_binding_id is not None and profile.agent_binding_id != agent_binding_id:
            raise PrinterProfileRejected("PRINTER_PROFILE_AGENT_BINDING_MISMATCH")
        result = self.compatibility(profile.id, template_version_id)
        if result["result"] != COMPATIBLE:
            raise PrinterProfileRejected(str(result["result"]))
        return profile, result
