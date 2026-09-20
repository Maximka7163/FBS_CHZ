from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import x25519
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from wbcz.printing import canonical_layout_sha256
from wbcz.printing_sensitive import (
    ENVELOPE_VERSION,
    PRINT_PROTOCOL_VERSION,
    PUBLIC_KEY_ALGORITHM,
    REQUIRED_CAPABILITIES,
    SUITE_ID,
    public_key_fingerprint,
    seal_full_km,
)
from wbcz_web.config import WebConfig
from wbcz_web.models import (
    AgentBindingEncryptionKeyRecord,
    AgentBindingRecord,
    PrintEncryptionKeyIntentRecord,
    PrintExecutionRecord,
    PrintJobItemRecord,
    PrintJobRecord,
    PrintPayloadDeliveryReservationRecord,
    PrintTemplateVersionRecord,
    StoredFullKmItemRecord,
    SuzKmVaultRecord,
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
from wbcz_web.services.printing import LocalPrintingService, PrintingIntegrityError
from wbcz_web.services.tenant import active_tenant


_NONTERMINAL_EXECUTION = {
    "REQUESTED", "AUTHORIZED", "PAYLOAD_AVAILABLE", "PAYLOAD_ISSUED", "PAYLOAD_DELIVERED",
}
_PRE_SPOOL_ISSUABLE = {"PAYLOAD_AVAILABLE", "PAYLOAD_ISSUED"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _intent_hash(raw: str) -> str:
    if not isinstance(raw, str) or len(raw) < 43:
        return hashlib.sha256(b"invalid-print-key-intent").hexdigest()
    return hashlib.sha256(("sellari-print-key-intent:v1:" + raw).encode("utf-8")).hexdigest()


class SensitiveDeliveryRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code[:96]
        super().__init__(self.code)


class SensitivePrintingDeliveryService:
    def __init__(self, db: Session, config: WebConfig, *, key_provider=None) -> None:
        self.db = db
        self.config = config
        self.scope = active_tenant(db)
        self._printing = LocalPrintingService(db, config, key_provider=key_provider)

    def _audit(
        self,
        event_type: str,
        *,
        subject_type: SubjectType,
        subject_id: str,
        outcome: AuditOutcome,
        metadata: dict[str, Any],
        user_id: int | None = None,
        actor_kind: ActorKind = ActorKind.SYSTEM,
        event_key: str,
    ) -> None:
        trace_data = self.db.info.get("audit_trace")
        trace = trace_data if isinstance(trace_data, dict) else {}
        actor = (
            ActorContext(ActorKind.USER, user_id=user_id)
            if user_id is not None
            else ActorContext(actor_kind, machine_principal="printing-agent" if actor_kind is ActorKind.WINDOWS_AGENT else None)
        )
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=actor,
            tenant=AuditTenantScope(self.scope.organisation_id, self.scope.participant_id),
            subject=SubjectRef(subject_type, subject_id),
            outcome=outcome,
            authorization_decision=AuthorizationDecision.ALLOW if user_id is not None else AuthorizationDecision.NOT_APPLICABLE,
            trace=TraceContext(
                request_id=trace.get("request_id"),
                correlation_id=trace.get("correlation_id"),
                causation_id=trace.get("causation_id"),
                event_key=event_key[:256],
            ),
            metadata=metadata,
        )

    def _require_delivery_gate(self) -> None:
        if not self.config.printing_enabled:
            raise SensitiveDeliveryRejected("PRINTING_DISABLED")
        if not self.config.print_execution_enabled:
            raise SensitiveDeliveryRejected("PRINT_EXECUTION_DISABLED")
        if self.config.environment == "production":
            # Startup validation already rejects this combination; keep a second
            # fail-closed service boundary for tests and accidental construction.
            raise SensitiveDeliveryRejected("PRODUCTION_PRINT_EXECUTION_BLOCKED")

    def _binding(self, binding_id: str, *, lock: bool = False) -> AgentBindingRecord:
        stmt = select(AgentBindingRecord).where(
            AgentBindingRecord.id == binding_id,
            AgentBindingRecord.organisation_id == self.scope.organisation_id,
            AgentBindingRecord.participant_id == self.scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        binding = self.db.scalar(stmt)
        if binding is None:
            raise SensitiveDeliveryRejected("AGENT_BINDING_NOT_FOUND")
        return binding

    def _validate_binding(self, binding: AgentBindingRecord) -> None:
        if binding.state != "ACTIVE" or binding.protocol_compatibility_state != "COMPATIBLE":
            raise SensitiveDeliveryRejected("AGENT_BINDING_NOT_ACTIVE")
        if binding.last_seen_at is None:
            raise SensitiveDeliveryRejected("AGENT_BINDING_NOT_FRESH")
        if (_now() - _aware(binding.last_seen_at)).total_seconds() > self.config.agent_health_stale_seconds:
            raise SensitiveDeliveryRejected("AGENT_BINDING_NOT_FRESH")
        capabilities = set(binding.supported_capabilities_json or ())
        if not REQUIRED_CAPABILITIES.issubset(capabilities):
            raise SensitiveDeliveryRejected("AGENT_PRINTING_V2_CAPABILITY_REQUIRED")
        if not binding.agent_version:
            raise SensitiveDeliveryRejected("AGENT_VERSION_REQUIRED")

    def _active_key(self, binding_id: str, *, lock: bool = False) -> AgentBindingEncryptionKeyRecord | None:
        stmt = select(AgentBindingEncryptionKeyRecord).where(
            AgentBindingEncryptionKeyRecord.agent_binding_id == binding_id,
            AgentBindingEncryptionKeyRecord.organisation_id == self.scope.organisation_id,
            AgentBindingEncryptionKeyRecord.participant_id == self.scope.participant_id,
            AgentBindingEncryptionKeyRecord.state == "ACTIVE",
        )
        if lock:
            stmt = stmt.with_for_update()
        return self.db.scalar(stmt)

    def create_key_intent(self, binding_id: str, *, purpose: str, user_id: int) -> tuple[PrintEncryptionKeyIntentRecord, str]:
        if purpose not in {"FIRST_REGISTRATION", "ROTATE", "REPLACE_LOST"}:
            raise ValueError("unsupported print encryption key intent purpose")
        binding = self._binding(binding_id, lock=True)
        self._validate_binding(binding)
        active = self._active_key(binding.id, lock=True)
        if purpose == "FIRST_REGISTRATION" and active is not None:
            raise SensitiveDeliveryRejected("PRINT_ENCRYPTION_KEY_ALREADY_REGISTERED")
        if purpose in {"ROTATE", "REPLACE_LOST"} and active is None:
            raise SensitiveDeliveryRejected("ACTIVE_PRINT_ENCRYPTION_KEY_REQUIRED")
        raw = secrets.token_urlsafe(48)
        now = _now()
        trace = self.db.info.get("audit_trace") if isinstance(self.db.info.get("audit_trace"), dict) else {}
        row = PrintEncryptionKeyIntentRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            agent_binding_id=binding.id,
            token_hash=_intent_hash(raw),
            purpose=purpose,
            state="PENDING",
            expected_active_key_id=active.id if active else None,
            expires_at=now + timedelta(seconds=self.config.print_key_intent_ttl_seconds),
            created_by_user_id=user_id,
            correlation_id=trace.get("correlation_id"),
        )
        self.db.add(row)
        self.db.flush()
        return row, raw

    def register_public_key(
        self,
        *,
        agent_binding_id: str,
        intent_token: str,
        public_key_raw: bytes,
    ) -> AgentBindingEncryptionKeyRecord:
        binding = self._binding(agent_binding_id, lock=True)
        self._validate_binding(binding)
        try:
            x25519.X25519PublicKey.from_public_bytes(public_key_raw)
            fingerprint = public_key_fingerprint(public_key_raw)
        except Exception as exc:
            raise SensitiveDeliveryRejected("INVALID_PRINT_ENCRYPTION_PUBLIC_KEY") from exc
        digest = _intent_hash(intent_token)
        intent = self.db.scalar(
            select(PrintEncryptionKeyIntentRecord)
            .where(PrintEncryptionKeyIntentRecord.token_hash == digest)
            .with_for_update()
        )
        if intent is None or not hmac.compare_digest(intent.token_hash, digest):
            raise SensitiveDeliveryRejected("INVALID_PRINT_KEY_INTENT")
        if (
            intent.organisation_id != self.scope.organisation_id
            or intent.participant_id != self.scope.participant_id
            or intent.agent_binding_id != binding.id
        ):
            raise SensitiveDeliveryRejected("PRINT_KEY_INTENT_BINDING_MISMATCH")
        now = _now()
        if intent.state != "PENDING":
            raise SensitiveDeliveryRejected("PRINT_KEY_INTENT_ALREADY_USED")
        if _aware(intent.expires_at) <= now:
            intent.state = "EXPIRED"
            self.db.flush()
            raise SensitiveDeliveryRejected("PRINT_KEY_INTENT_EXPIRED")

        active = self._active_key(binding.id, lock=True)
        if intent.purpose == "FIRST_REGISTRATION":
            if active is not None or intent.expected_active_key_id is not None:
                raise SensitiveDeliveryRejected("PRINT_KEY_FIRST_REGISTRATION_CONFLICT")
        else:
            if active is None or active.id != intent.expected_active_key_id:
                raise SensitiveDeliveryRejected("PRINT_KEY_ROTATION_BASE_CHANGED")

        if active is not None:
            if intent.purpose == "REPLACE_LOST":
                active.state = "REVOKED"
                active.revoked_at = now
                self._revoke_key_reservations(active.id, code="PRINT_RECIPIENT_KEY_LOST")
            else:
                active.state = "RETIRING"
                active.retiring_at = now

        highest = int(self.db.scalar(
            select(func.coalesce(func.max(AgentBindingEncryptionKeyRecord.key_version), 0)).where(
                AgentBindingEncryptionKeyRecord.agent_binding_id == binding.id
            )
        ) or 0)
        row = AgentBindingEncryptionKeyRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            agent_binding_id=binding.id,
            algorithm=PUBLIC_KEY_ALGORITHM,
            public_key=public_key_raw,
            public_key_fingerprint=fingerprint,
            key_version=highest + 1,
            state="ACTIVE",
            registered_at=now,
        )
        self.db.add(row)
        intent.state = "USED"
        intent.used_at = now
        self.db.flush()

        event_type = "PRINT_AGENT_KEY_REGISTERED" if intent.purpose == "FIRST_REGISTRATION" else "PRINT_AGENT_KEY_ROTATED"
        self._audit(
            event_type,
            subject_type=SubjectType.INTEGRATION_CONNECTION,
            subject_id=binding.id,
            outcome=AuditOutcome.SUCCESS,
            actor_kind=ActorKind.WINDOWS_AGENT,
            metadata={
                "binding_id": binding.id,
                "key_fingerprint": row.public_key_fingerprint,
                "key_version": row.key_version,
                "old_key_version": active.key_version if active else None,
                "rotation_state": intent.purpose,
            },
            event_key=f"print-key:{binding.id}:{row.key_version}:{event_type}",
        )
        if active is not None and intent.purpose == "REPLACE_LOST":
            self._audit(
                "PRINT_AGENT_KEY_REVOKED",
                subject_type=SubjectType.INTEGRATION_CONNECTION,
                subject_id=binding.id,
                outcome=AuditOutcome.SUCCESS,
                actor_kind=ActorKind.WINDOWS_AGENT,
                metadata={
                    "binding_id": binding.id,
                    "key_fingerprint": active.public_key_fingerprint,
                    "key_version": active.key_version,
                    "error_code": "PRINT_RECIPIENT_KEY_LOST",
                },
                event_key=f"print-key:{binding.id}:{active.key_version}:revoked",
            )
        return row

    def _revoke_key_reservations(self, key_id: str, *, code: str) -> None:
        now = _now()
        reservations = list(self.db.scalars(
            select(PrintPayloadDeliveryReservationRecord)
            .where(
                PrintPayloadDeliveryReservationRecord.agent_encryption_key_id == key_id,
                PrintPayloadDeliveryReservationRecord.state.in_(("AVAILABLE", "ISSUED")),
            )
            .with_for_update()
        ))
        for reservation in reservations:
            reservation.state = "REVOKED"
            reservation.revoked_at = now
            reservation.safe_error_code = code
            execution = self.db.get(PrintExecutionRecord, reservation.print_execution_id)
            if execution is not None and execution.state in _NONTERMINAL_EXECUTION:
                execution.state = "BLOCKED"
                execution.safe_error_code = code
                execution.terminal_at = now

    def revoke_expired_retiring_keys(self, binding_id: str) -> int:
        cutoff = _now() - timedelta(seconds=self.config.print_delivery_reservation_ttl_seconds)
        keys = list(self.db.scalars(
            select(AgentBindingEncryptionKeyRecord)
            .where(
                AgentBindingEncryptionKeyRecord.agent_binding_id == binding_id,
                AgentBindingEncryptionKeyRecord.organisation_id == self.scope.organisation_id,
                AgentBindingEncryptionKeyRecord.participant_id == self.scope.participant_id,
                AgentBindingEncryptionKeyRecord.state == "RETIRING",
                AgentBindingEncryptionKeyRecord.retiring_at.is_not(None),
                AgentBindingEncryptionKeyRecord.retiring_at <= cutoff,
            )
            .with_for_update()
        ))
        now = _now()
        for key in keys:
            key.state = "REVOKED"
            key.revoked_at = now
            self._revoke_key_reservations(key.id, code="PRINT_RECIPIENT_KEY_RETIRED")
            self._audit(
                "PRINT_AGENT_KEY_REVOKED",
                subject_type=SubjectType.INTEGRATION_CONNECTION,
                subject_id=binding_id,
                outcome=AuditOutcome.SUCCESS,
                metadata={
                    "binding_id": binding_id,
                    "key_fingerprint": key.public_key_fingerprint,
                    "key_version": key.key_version,
                    "error_code": "PRINT_RECIPIENT_KEY_RETIRED",
                },
                event_key=f"print-key:{binding_id}:{key.key_version}:retired",
            )
        return len(keys)

    def _enforce_vault_size(self, stored: StoredFullKmItemRecord) -> None:
        vault = self.db.get(SuzKmVaultRecord, stored.vault_entry_id)
        if vault is None:
            raise SensitiveDeliveryRejected("VAULT_LINKAGE_BROKEN")
        encrypted_entry_bytes = len(vault.ciphertext) + len(vault.nonce) + len(vault.auth_tag)
        if encrypted_entry_bytes > self.config.max_print_delivery_vault_entry_bytes:
            raise SensitiveDeliveryRejected("VAULT_ENTRY_TOO_LARGE_FOR_SAFE_PRINT_DELIVERY")

    def _validate_execution_graph(
        self,
        execution: PrintExecutionRecord,
    ) -> tuple[PrintJobRecord, PrintJobItemRecord, StoredFullKmItemRecord, PrintTemplateVersionRecord]:
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
        stored = self.db.scalar(select(StoredFullKmItemRecord).where(
            StoredFullKmItemRecord.id == execution.stored_full_km_item_id,
            StoredFullKmItemRecord.organisation_id == self.scope.organisation_id,
            StoredFullKmItemRecord.participant_id == self.scope.participant_id,
        ))
        version = self.db.scalar(select(PrintTemplateVersionRecord).where(
            PrintTemplateVersionRecord.id == execution.template_version_id,
            PrintTemplateVersionRecord.organisation_id == self.scope.organisation_id,
        ))
        if job is None or item is None or stored is None or version is None:
            raise SensitiveDeliveryRejected("PRINT_EXECUTION_GRAPH_INVALID")
        if item.stored_full_km_item_id != stored.id or job.template_version_id != version.id:
            raise SensitiveDeliveryRejected("PRINT_EXECUTION_GRAPH_CONFLICT")
        if version.participant_id not in {None, self.scope.participant_id}:
            raise SensitiveDeliveryRejected("TEMPLATE_PARTICIPANT_MISMATCH")
        if item.payload_hash != stored.full_km_sha256 or execution.payload_sha256 != item.payload_hash:
            raise SensitiveDeliveryRejected("PRINT_PAYLOAD_HASH_BINDING_MISMATCH")
        _, layout_hash = canonical_layout_sha256(
            version.layout_json,
            label_width_mm=float(version.label_width_mm),
            label_height_mm=float(version.label_height_mm),
        )
        if layout_hash != version.layout_sha256 or execution.layout_sha256 != version.layout_sha256:
            raise SensitiveDeliveryRejected("PRINT_LAYOUT_HASH_BINDING_MISMATCH")
        if stored.provenance_state != "PROVEN":
            raise SensitiveDeliveryRejected("FULL_KM_PROVENANCE_NOT_PROVEN")
        return job, item, stored, version

    def authorize_delivery(
        self,
        *,
        print_job_id: str,
        print_job_item_id: str,
        agent_binding_id: str | None,
        user_id: int,
    ) -> tuple[PrintExecutionRecord, PrintPayloadDeliveryReservationRecord]:
        self._require_delivery_gate()
        item = self.db.scalar(
            select(PrintJobItemRecord)
            .where(
                PrintJobItemRecord.id == print_job_item_id,
                PrintJobItemRecord.print_job_id == print_job_id,
                PrintJobItemRecord.organisation_id == self.scope.organisation_id,
                PrintJobItemRecord.participant_id == self.scope.participant_id,
            )
            .with_for_update()
        )
        job = self.db.scalar(select(PrintJobRecord).where(
            PrintJobRecord.id == print_job_id,
            PrintJobRecord.organisation_id == self.scope.organisation_id,
            PrintJobRecord.participant_id == self.scope.participant_id,
        ))
        if job is None or item is None:
            raise SensitiveDeliveryRejected("PRINT_JOB_ITEM_NOT_FOUND")
        if job.state != "READY_FOR_AGENT" or item.state != "PENDING":
            raise SensitiveDeliveryRejected("PRINT_JOB_ITEM_NOT_AUTHORIZABLE")

        if agent_binding_id:
            binding = self._binding(agent_binding_id, lock=True)
        else:
            binding = self.db.scalar(
                select(AgentBindingRecord)
                .where(
                    AgentBindingRecord.organisation_id == self.scope.organisation_id,
                    AgentBindingRecord.participant_id == self.scope.participant_id,
                    AgentBindingRecord.state == "ACTIVE",
                    AgentBindingRecord.is_primary.is_(True),
                )
                .with_for_update()
            )
            if binding is None:
                raise SensitiveDeliveryRejected("PRIMARY_AGENT_BINDING_REQUIRED")
        self._validate_binding(binding)
        self.revoke_expired_retiring_keys(binding.id)
        key = self._active_key(binding.id, lock=True)
        if key is None:
            raise SensitiveDeliveryRejected("ACTIVE_PRINT_ENCRYPTION_KEY_REQUIRED")

        stored = self.db.scalar(select(StoredFullKmItemRecord).where(
            StoredFullKmItemRecord.id == item.stored_full_km_item_id,
            StoredFullKmItemRecord.organisation_id == self.scope.organisation_id,
            StoredFullKmItemRecord.participant_id == self.scope.participant_id,
        ))
        version = self.db.scalar(select(PrintTemplateVersionRecord).where(
            PrintTemplateVersionRecord.id == job.template_version_id,
            PrintTemplateVersionRecord.organisation_id == self.scope.organisation_id,
        ))
        if stored is None or version is None:
            raise SensitiveDeliveryRejected("PRINT_AUTHORIZATION_GRAPH_INVALID")
        if version.participant_id not in {None, self.scope.participant_id}:
            raise SensitiveDeliveryRejected("TEMPLATE_PARTICIPANT_MISMATCH")
        if stored.provenance_state != "PROVEN" or item.payload_hash != stored.full_km_sha256:
            raise SensitiveDeliveryRejected("PRINT_PAYLOAD_NOT_PROVEN")
        _, layout_hash = canonical_layout_sha256(
            version.layout_json,
            label_width_mm=float(version.label_width_mm),
            label_height_mm=float(version.label_height_mm),
        )
        if layout_hash != version.layout_sha256:
            raise SensitiveDeliveryRejected("TEMPLATE_LAYOUT_INTEGRITY_FAILED")

        existing = self.db.scalar(select(PrintExecutionRecord).where(
            PrintExecutionRecord.print_job_item_id == item.id,
            PrintExecutionRecord.state.in_(tuple(_NONTERMINAL_EXECUTION)),
        ))
        if existing is not None:
            raise SensitiveDeliveryRejected("PRINT_EXECUTION_ALREADY_ACTIVE")

        self._enforce_vault_size(stored)
        try:
            full_km = self._printing._decrypt_and_verify(stored)
        except (PrintingIntegrityError, RuntimeError) as exc:
            raise SensitiveDeliveryRejected("FULL_KM_VAULT_INTEGRITY_FAILED") from exc
        try:
            if hashlib.sha256(full_km).hexdigest() != item.payload_hash:
                raise SensitiveDeliveryRejected("PRINT_PAYLOAD_HASH_BINDING_MISMATCH")
        finally:
            full_km = b""

        attempt = int(self.db.scalar(
            select(func.coalesce(func.max(PrintExecutionRecord.attempt_number), 0)).where(
                PrintExecutionRecord.print_job_item_id == item.id
            )
        ) or 0) + 1
        now = _now()
        trace = self.db.info.get("audit_trace") if isinstance(self.db.info.get("audit_trace"), dict) else {}
        execution = PrintExecutionRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            print_job_id=job.id,
            print_job_item_id=item.id,
            stored_full_km_item_id=stored.id,
            template_version_id=version.id,
            agent_binding_id=binding.id,
            attempt_number=attempt,
            state="PAYLOAD_AVAILABLE",
            payload_sha256=item.payload_hash,
            layout_sha256=version.layout_sha256,
            agent_version=binding.agent_version or "unknown",
            print_protocol_version=PRINT_PROTOCOL_VERSION,
            authorized_at=now,
            correlation_id=trace.get("correlation_id"),
        )
        reservation = PrintPayloadDeliveryReservationRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            print_execution_id=execution.id,
            print_job_id=job.id,
            print_job_item_id=item.id,
            stored_full_km_item_id=stored.id,
            agent_binding_id=binding.id,
            agent_encryption_key_id=key.id,
            payload_sha256=item.payload_hash,
            state="AVAILABLE",
            issue_count=0,
            max_issue_count=self.config.print_delivery_max_issuance,
            authorized_at=now,
            expires_at=now + timedelta(seconds=self.config.print_delivery_reservation_ttl_seconds),
        )
        self.db.add(execution)
        self.db.add(reservation)
        self.db.flush()
        self._audit(
            "PRINT_PAYLOAD_AUTHORIZED",
            subject_type=SubjectType.PRINT_JOB,
            subject_id=job.id,
            outcome=AuditOutcome.SUCCESS,
            user_id=user_id,
            metadata={
                "print_execution_id": execution.id,
                "delivery_reservation_id": reservation.id,
                "print_job_item_id": item.id,
                "stored_km_item_id": stored.id,
                "binding_id": binding.id,
                "key_fingerprint": key.public_key_fingerprint,
                "key_version": key.key_version,
                "payload_sha256": item.payload_hash,
                "layout_sha256": version.layout_sha256,
                "attempt_count": attempt,
            },
            event_key=f"print-payload:{execution.id}:authorized",
        )
        return execution, reservation

    @staticmethod
    def _expires_text(value: datetime) -> str:
        return _aware(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _delivery_context(
        self,
        reservation: PrintPayloadDeliveryReservationRecord,
        execution: PrintExecutionRecord,
        key: AgentBindingEncryptionKeyRecord,
    ) -> dict[str, Any]:
        return {
            "delivery_reservation_id": reservation.id,
            "print_execution_id": execution.id,
            "print_job_id": execution.print_job_id,
            "print_job_item_id": execution.print_job_item_id,
            "stored_full_km_item_id": execution.stored_full_km_item_id,
            "organisation_id": execution.organisation_id,
            "participant_id": execution.participant_id,
            "agent_binding_id": execution.agent_binding_id,
            "payload_sha256": execution.payload_sha256,
            "template_version_id": execution.template_version_id,
            "layout_sha256": execution.layout_sha256,
            "recipient_key_version": key.key_version,
            "expires_at": self._expires_text(reservation.expires_at),
        }

    def issue(self, reservation_id: str, *, machine_binding_id: str) -> dict[str, Any]:
        self._require_delivery_gate()
        reservation = self.db.scalar(
            select(PrintPayloadDeliveryReservationRecord)
            .where(
                PrintPayloadDeliveryReservationRecord.id == reservation_id,
                PrintPayloadDeliveryReservationRecord.organisation_id == self.scope.organisation_id,
                PrintPayloadDeliveryReservationRecord.participant_id == self.scope.participant_id,
            )
            .with_for_update()
        )
        if reservation is None:
            raise SensitiveDeliveryRejected("DELIVERY_RESERVATION_NOT_FOUND")
        now = _now()
        if reservation.agent_binding_id != machine_binding_id:
            raise SensitiveDeliveryRejected("DELIVERY_AGENT_BINDING_MISMATCH")
        if reservation.state not in {"AVAILABLE", "ISSUED"}:
            raise SensitiveDeliveryRejected("DELIVERY_RESERVATION_NOT_ISSUABLE")
        if _aware(reservation.expires_at) <= now:
            reservation.state = "EXPIRED"
            reservation.safe_error_code = "DELIVERY_RESERVATION_EXPIRED"
            raise SensitiveDeliveryRejected("DELIVERY_RESERVATION_EXPIRED")
        if reservation.issue_count >= reservation.max_issue_count:
            reservation.state = "BLOCKED"
            reservation.safe_error_code = "DELIVERY_ISSUE_LIMIT_REACHED"
            raise SensitiveDeliveryRejected("DELIVERY_ISSUE_LIMIT_REACHED")

        execution = self.db.scalar(
            select(PrintExecutionRecord)
            .where(
                PrintExecutionRecord.id == reservation.print_execution_id,
                PrintExecutionRecord.organisation_id == self.scope.organisation_id,
                PrintExecutionRecord.participant_id == self.scope.participant_id,
            )
            .with_for_update()
        )
        if execution is None or execution.agent_binding_id != machine_binding_id:
            raise SensitiveDeliveryRejected("PRINT_EXECUTION_BINDING_MISMATCH")
        if execution.state not in _PRE_SPOOL_ISSUABLE:
            raise SensitiveDeliveryRejected("PRINT_EXECUTION_NOT_PRE_SPOOL")

        binding = self._binding(machine_binding_id, lock=True)
        self._validate_binding(binding)
        key = self.db.scalar(
            select(AgentBindingEncryptionKeyRecord)
            .where(
                AgentBindingEncryptionKeyRecord.id == reservation.agent_encryption_key_id,
                AgentBindingEncryptionKeyRecord.agent_binding_id == binding.id,
                AgentBindingEncryptionKeyRecord.organisation_id == self.scope.organisation_id,
                AgentBindingEncryptionKeyRecord.participant_id == self.scope.participant_id,
            )
            .with_for_update()
        )
        if key is None or key.state not in {"ACTIVE", "RETIRING"}:
            raise SensitiveDeliveryRejected("DELIVERY_RECIPIENT_KEY_UNAVAILABLE")
        if key.state == "RETIRING":
            if key.retiring_at is None or _aware(reservation.authorized_at) > _aware(key.retiring_at):
                raise SensitiveDeliveryRejected("DELIVERY_RECIPIENT_KEY_ROTATION_CONFLICT")

        _, item, stored, version = self._validate_execution_graph(execution)
        if reservation.print_job_item_id != item.id or reservation.stored_full_km_item_id != stored.id:
            raise SensitiveDeliveryRejected("DELIVERY_RESERVATION_GRAPH_CONFLICT")
        if reservation.payload_sha256 != execution.payload_sha256:
            raise SensitiveDeliveryRejected("DELIVERY_PAYLOAD_HASH_CONFLICT")

        self._enforce_vault_size(stored)
        try:
            full_km = self._printing._decrypt_and_verify(stored)
        except (PrintingIntegrityError, RuntimeError) as exc:
            raise SensitiveDeliveryRejected("FULL_KM_VAULT_INTEGRITY_FAILED") from exc
        try:
            if hashlib.sha256(full_km).hexdigest() != reservation.payload_sha256:
                raise SensitiveDeliveryRejected("FULL_KM_ITEM_HASH_MISMATCH")
            context = self._delivery_context(reservation, execution, key)
            envelope = seal_full_km(
                recipient_public_key_raw=key.public_key,
                plaintext_full_km=full_km,
                context=context,
            )
        finally:
            # CPython does not guarantee memory zeroization; this only minimizes
            # application references and is documented as such.
            full_km = b""

        reservation.issue_count += 1
        reservation.state = "ISSUED"
        reservation.first_issued_at = reservation.first_issued_at or now
        reservation.last_issued_at = now
        reservation.last_context_sha256 = envelope["context_sha256"]
        execution.state = "PAYLOAD_ISSUED"
        self.db.flush()
        self._audit(
            "PRINT_PAYLOAD_ISSUED",
            subject_type=SubjectType.PRINT_JOB,
            subject_id=execution.print_job_id,
            outcome=AuditOutcome.SUCCESS,
            actor_kind=ActorKind.WINDOWS_AGENT,
            metadata={
                "print_execution_id": execution.id,
                "delivery_reservation_id": reservation.id,
                "print_job_item_id": execution.print_job_item_id,
                "binding_id": binding.id,
                "key_fingerprint": key.public_key_fingerprint,
                "key_version": key.key_version,
                "payload_sha256": reservation.payload_sha256,
                "context_sha256": envelope["context_sha256"],
                "issue_count": reservation.issue_count,
            },
            event_key=f"print-payload:{reservation.id}:issued:{reservation.issue_count}",
        )
        return {**envelope, "delivery_reservation_id": reservation.id, "print_execution_id": execution.id}

    def acknowledge(
        self,
        reservation_id: str,
        *,
        machine_binding_id: str,
        payload_sha256: str,
        context_sha256: str,
    ) -> dict[str, Any]:
        self._require_delivery_gate()
        reservation = self.db.scalar(
            select(PrintPayloadDeliveryReservationRecord)
            .where(
                PrintPayloadDeliveryReservationRecord.id == reservation_id,
                PrintPayloadDeliveryReservationRecord.organisation_id == self.scope.organisation_id,
                PrintPayloadDeliveryReservationRecord.participant_id == self.scope.participant_id,
            )
            .with_for_update()
        )
        if reservation is None or reservation.agent_binding_id != machine_binding_id:
            raise SensitiveDeliveryRejected("DELIVERY_RESERVATION_NOT_FOUND")
        if reservation.state == "ACKNOWLEDGED":
            if reservation.payload_sha256 == payload_sha256 and reservation.last_context_sha256 == context_sha256:
                return {"state": "ACKNOWLEDGED", "delivery_reservation_id": reservation.id}
            raise SensitiveDeliveryRejected("DELIVERY_ACK_REPLAY_CONFLICT")
        if reservation.state != "ISSUED":
            raise SensitiveDeliveryRejected("DELIVERY_ACK_NOT_ALLOWED")
        execution = self.db.scalar(
            select(PrintExecutionRecord)
            .where(PrintExecutionRecord.id == reservation.print_execution_id)
            .with_for_update()
        )
        if execution is None or execution.agent_binding_id != machine_binding_id:
            raise SensitiveDeliveryRejected("PRINT_EXECUTION_BINDING_MISMATCH")
        if payload_sha256 != reservation.payload_sha256 or context_sha256 != reservation.last_context_sha256:
            reservation.state = "BLOCKED"
            reservation.safe_error_code = "DELIVERY_ACK_INTEGRITY_MISMATCH"
            execution.state = "FAILED_PRE_SPOOL"
            execution.safe_error_code = "DELIVERY_ACK_INTEGRITY_MISMATCH"
            execution.terminal_at = _now()
            raise SensitiveDeliveryRejected("DELIVERY_ACK_INTEGRITY_MISMATCH")

        now = _now()
        reservation.state = "ACKNOWLEDGED"
        reservation.acknowledged_at = now
        execution.state = "PAYLOAD_DELIVERED"
        execution.payload_delivered_at = now
        self.db.flush()
        self._audit(
            "PRINT_PAYLOAD_DELIVERED",
            subject_type=SubjectType.PRINT_JOB,
            subject_id=execution.print_job_id,
            outcome=AuditOutcome.SUCCESS,
            actor_kind=ActorKind.WINDOWS_AGENT,
            metadata={
                "print_execution_id": execution.id,
                "delivery_reservation_id": reservation.id,
                "print_job_item_id": execution.print_job_item_id,
                "binding_id": machine_binding_id,
                "payload_sha256": reservation.payload_sha256,
                "context_sha256": context_sha256,
                "issue_count": reservation.issue_count,
            },
            event_key=f"print-payload:{reservation.id}:delivered",
        )
        return {
            "state": "ACKNOWLEDGED",
            "delivery_reservation_id": reservation.id,
            "print_execution_id": execution.id,
            "payload_sha256": reservation.payload_sha256,
            "context_sha256": context_sha256,
        }
