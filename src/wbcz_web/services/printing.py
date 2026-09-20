from __future__ import annotations

from dataclasses import dataclass
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Iterable, Mapping, Protocol
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from wbcz.printing import canonical_layout_sha256, render_synthetic_preview
from wbcz.suz_foundation import KmVault, VaultBinding, VaultEnvelope
from wbcz_web.config import WebConfig
from wbcz_web.models import (
    PrintEventRecord,
    PrintJobItemRecord,
    PrintJobRecord,
    PrintTemplateRecord,
    PrintTemplateVersionRecord,
    StoredFullKmItemRecord,
    SuzCodeBlockRecord,
    SuzConnectionRecord,
    SuzKmVaultRecord,
    SuzOrderItemRecord,
    SuzOrderRecord,
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
from wbcz_web.services.production_hardening import sanitize_operational_data
from wbcz_web.services.production_secrets import VersionedFilesystemKeyProvider
from wbcz_web.services.tenant import active_tenant


PRINTABLE = "PRINTABLE_LOCAL_FULL_KM_AVAILABLE"
NOT_PRINTABLE = "NOT_PRINTABLE_FULL_KM_UNAVAILABLE"
MANUAL_REVIEW = "MANUAL_REVIEW"


class PrintingUnavailable(RuntimeError):
    pass


class PrintingIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PrintabilityProjection:
    state: str
    reason: str
    stored_full_km_item_id: str | None = None
    payload_sha256: str | None = None

    def public(self) -> dict[str, str]:
        # Internal ids/hashes are deliberately omitted from browser projection.
        return {"state": self.state, "reason": self.reason}


class KmKeyProvider(Protocol):
    def get_key(self, key_version: str) -> bytes: ...


def cis_index_hmac(cis: str, key: bytes) -> str:
    if not isinstance(cis, str) or not cis or len(cis) > 512:
        raise ValueError("cis must be a non-empty bounded string")
    if not isinstance(key, bytes) or len(key) < 32:
        raise PrintingIntegrityError("printing CIS index key unavailable")
    return hmac.new(key, b"sellari-print-cis-index-v1\0" + cis.encode("utf-8"), hashlib.sha256).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LocalPrintingService:
    def __init__(
        self,
        db: Session,
        config: WebConfig,
        *,
        key_provider: KmKeyProvider | None = None,
        cis_hmac_key: bytes | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.scope = active_tenant(db)
        self._key_provider = key_provider or (
            VersionedFilesystemKeyProvider(config.suz_km_keyring_root)
            if config.suz_km_keyring_root else None
        )
        configured = cis_hmac_key or db.info.get("audit_pseudonym_key")
        if isinstance(configured, str):
            configured = configured.encode("utf-8")
        self._cis_hmac_key = configured if isinstance(configured, bytes) else None

    def _audit(
        self,
        event_type: str,
        *,
        subject_type: SubjectType,
        subject_id: str,
        user_id: int | None,
        outcome: AuditOutcome,
        metadata: Mapping[str, Any],
        evidence_hashes: Iterable[str] = (),
        event_key: str,
        actor_kind: ActorKind | None = None,
    ) -> None:
        trace_data = self.db.info.get("audit_trace")
        trace = trace_data if isinstance(trace_data, dict) else {}
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=(
                ActorContext(ActorKind.USER, user_id=user_id)
                if user_id is not None
                else ActorContext(actor_kind or ActorKind.SYSTEM, machine_principal="printing-agent" if actor_kind is ActorKind.WINDOWS_AGENT else None)
            ),
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
            metadata=dict(metadata),
            evidence_hashes=tuple(evidence_hashes),
        )

    def _hmac(self, cis: str) -> str:
        if self._cis_hmac_key is None:
            raise PrintingIntegrityError("printing CIS index key unavailable")
        return cis_index_hmac(cis, self._cis_hmac_key)

    def _stored_by_cis(self, cis: str) -> StoredFullKmItemRecord | None:
        digest = self._hmac(cis)
        return self.db.scalar(
            select(StoredFullKmItemRecord).where(
                StoredFullKmItemRecord.organisation_id == self.scope.organisation_id,
                StoredFullKmItemRecord.participant_id == self.scope.participant_id,
                StoredFullKmItemRecord.cis_hmac == digest,
            )
        )

    def _stored_by_id(self, item_id: str) -> StoredFullKmItemRecord:
        row = self.db.scalar(
            select(StoredFullKmItemRecord).where(
                StoredFullKmItemRecord.id == item_id,
                StoredFullKmItemRecord.organisation_id == self.scope.organisation_id,
                StoredFullKmItemRecord.participant_id == self.scope.participant_id,
            )
        )
        if row is None:
            raise KeyError(item_id)
        return row

    def _decrypt_and_verify(self, row: StoredFullKmItemRecord) -> bytes:
        if row.provenance_state != "PROVEN":
            raise PrintingIntegrityError("FULL_KM_PROVENANCE_NOT_PROVEN")
        if self._key_provider is None:
            raise PrintingIntegrityError("VAULT_KEY_PROVIDER_UNAVAILABLE")

        vault = self.db.get(SuzKmVaultRecord, row.vault_entry_id)
        block = self.db.get(SuzCodeBlockRecord, row.suz_code_block_id)
        order = self.db.get(SuzOrderRecord, row.suz_order_id)
        order_item = self.db.get(SuzOrderItemRecord, row.suz_order_item_id) if row.suz_order_item_id is not None else None
        if vault is None or block is None or order is None:
            raise PrintingIntegrityError("VAULT_LINKAGE_BROKEN")
        if (
            vault.id != block.vault_entry_id
            or vault.order_id != order.id
            or block.order_id != order.id
            or vault.order_operation_id != order.operation_id
            or block.order_operation_id != order.operation_id
            or vault.gtin != row.gtin
            or block.gtin != row.gtin
        ):
            raise PrintingIntegrityError("VAULT_LINKAGE_CONFLICT")
        if order_item is not None and (order_item.order_id != order.id or order_item.gtin != row.gtin):
            raise PrintingIntegrityError("ORDER_ITEM_LINKAGE_CONFLICT")
        connection = self.db.get(SuzConnectionRecord, order.connection_id)
        if connection is None:
            raise PrintingIntegrityError("SUZ_CONNECTION_LINKAGE_BROKEN")
        if connection.organisation_id != self.scope.organisation_id or connection.participant_id != self.scope.participant_id:
            raise PrintingIntegrityError("VAULT_TENANT_PROVENANCE_CONFLICT")
        if connection.participant_inn != self.scope.participant_inn:
            raise PrintingIntegrityError("VAULT_PARTICIPANT_PROVENANCE_CONFLICT")
        if block.exact_payload_sha256 != vault.plaintext_sha256:
            raise PrintingIntegrityError("BLOCK_VAULT_HASH_CONFLICT")
        if block.code_count != vault.code_count:
            raise PrintingIntegrityError("BLOCK_VAULT_COUNT_CONFLICT")

        envelope = VaultEnvelope(
            ciphertext=vault.ciphertext,
            nonce=vault.nonce,
            auth_tag=vault.auth_tag,
            key_version=vault.key_version,
            vault_format_version=vault.vault_format_version,
            aad_hash=vault.aad_hash,
            plaintext_sha256=vault.plaintext_sha256,
            ciphertext_sha256=vault.ciphertext_sha256,
            code_count=vault.code_count,
        )
        binding = VaultBinding(
            participant_inn=connection.participant_inn,
            oms_connection=connection.oms_connection,
            order_local_id=order.operation_id,
            gtin=row.gtin,
            remote_block_id=block.remote_block_id,
            vault_format_version=vault.vault_format_version,
        )
        raw_block = KmVault(self._key_provider, vault.key_version).decrypt(envelope, binding=binding)
        if hashlib.sha256(raw_block).hexdigest() != block.exact_payload_sha256:
            raise PrintingIntegrityError("BLOCK_PLAINTEXT_HASH_MISMATCH")
        start = row.vault_item_offset
        end = start + row.vault_item_length
        if start < 0 or end > len(raw_block) or end <= start:
            raise PrintingIntegrityError("VAULT_ITEM_LOCATOR_INVALID")
        full_km = raw_block[start:end]
        if hashlib.sha256(full_km).hexdigest() != row.full_km_sha256:
            raise PrintingIntegrityError("FULL_KM_ITEM_HASH_MISMATCH")
        return full_km

    def resolve_printability(self, cis: str) -> PrintabilityProjection:
        try:
            row = self._stored_by_cis(cis)
        except PrintingIntegrityError as exc:
            return PrintabilityProjection(MANUAL_REVIEW, str(exc))
        if row is None:
            return PrintabilityProjection(NOT_PRINTABLE, "LOCAL_FULL_KM_MAPPING_NOT_FOUND")
        if row.provenance_state != "PROVEN":
            return PrintabilityProjection(MANUAL_REVIEW, f"PROVENANCE_{row.provenance_state}")
        try:
            full_km = self._decrypt_and_verify(row)
        except (PrintingIntegrityError, RuntimeError) as exc:
            return PrintabilityProjection(MANUAL_REVIEW, str(exc))
        # This is a linkage check only; it does not reconstruct or normalize KM.
        if hashlib.sha256(full_km).hexdigest() != row.full_km_sha256:
            return PrintabilityProjection(MANUAL_REVIEW, "FULL_KM_ITEM_HASH_MISMATCH")
        return PrintabilityProjection(PRINTABLE, "PROVEN_LOCAL_FULL_KM", row.id, row.full_km_sha256)

    def resolve_printability_public(self, cis: str) -> dict[str, Any]:
        return {"cis": cis, "printability": self.resolve_printability(cis).public()}

    def enrich_m1_result(self, result: Any) -> Any:
        """Add safe local printability only to normalized M1 objects.

        The remote/raw section is preserved and no FULL KM is added anywhere.
        """
        value = copy.deepcopy(result)

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                normalized = node.get("normalized")
                if isinstance(normalized, dict):
                    cis = normalized.get("cis") or normalized.get("requested_cis") or normalized.get("sgtin")
                    if isinstance(cis, str) and cis:
                        normalized["printability"] = self.resolve_printability(cis).public()
                for nested in node.values():
                    walk(nested)
            elif isinstance(node, list):
                for nested in node:
                    walk(nested)

        walk(value)
        return value

    def index_trusted_full_km(
        self,
        *,
        cis: str,
        full_km: bytes,
        suz_order_id: int,
        suz_order_item_id: int | None,
        suz_code_block_id: int,
        vault_entry_id: int,
        gtin: str,
        vault_item_ordinal: int,
        vault_item_offset: int,
        source: str,
        received_at: datetime,
        provenance_state: str = "PROVEN",
    ) -> StoredFullKmItemRecord:
        if source not in {"INITIAL_SUZ_FETCH", "REPEAT_SUZ_FETCH", "MIGRATED_TRUSTED_SOURCE"}:
            raise ValueError("unsupported FULL KM source")
        if provenance_state not in {"PROVEN", "CONFLICT", "UNKNOWN"}:
            raise ValueError("unsupported provenance state")
        if not isinstance(full_km, bytes) or not full_km:
            raise ValueError("full_km must be exact non-empty bytes")
        if provenance_state == "PROVEN" and not full_km.startswith(cis.encode("utf-8")):
            raise PrintingIntegrityError("CIS_FULL_KM_PREFIX_PROOF_FAILED")
        row = StoredFullKmItemRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            suz_order_id=suz_order_id,
            suz_order_item_id=suz_order_item_id,
            suz_code_block_id=suz_code_block_id,
            vault_entry_id=vault_entry_id,
            gtin=gtin,
            cis_hmac=self._hmac(cis),
            cis_tail=cis[-8:] if len(cis) >= 8 else None,
            vault_item_ordinal=vault_item_ordinal,
            vault_item_offset=vault_item_offset,
            vault_item_length=len(full_km),
            full_km_sha256=hashlib.sha256(full_km).hexdigest(),
            provenance_state=provenance_state,
            source=source,
            received_at=received_at,
        )
        self.db.add(row)
        self.db.flush()
        if provenance_state == "PROVEN":
            # A PROVEN row is not accepted merely because the caller says so.
            checked = self._decrypt_and_verify(row)
            if checked != full_km:
                raise PrintingIntegrityError("FULL_KM_INDEX_EXACT_BYTES_MISMATCH")
        return row

    def _template(self, template_id: str, *, allow_archived: bool = True) -> PrintTemplateRecord:
        stmt = select(PrintTemplateRecord).where(
            PrintTemplateRecord.id == template_id,
            PrintTemplateRecord.organisation_id == self.scope.organisation_id,
        )
        row = self.db.scalar(stmt)
        if row is None or (row.participant_id is not None and row.participant_id != self.scope.participant_id):
            raise KeyError(template_id)
        if not allow_archived and row.state != "ACTIVE":
            raise PrintingUnavailable("template is archived")
        return row

    def _version(self, version_id: str) -> PrintTemplateVersionRecord:
        row = self.db.scalar(
            select(PrintTemplateVersionRecord).where(
                PrintTemplateVersionRecord.id == version_id,
                PrintTemplateVersionRecord.organisation_id == self.scope.organisation_id,
            )
        )
        if row is None or (row.participant_id is not None and row.participant_id != self.scope.participant_id):
            raise KeyError(version_id)
        return row

    def create_template(
        self,
        *,
        name: str,
        label_width_mm: float,
        label_height_mm: float,
        layout: Mapping[str, Any],
        user_id: int,
        organisation_wide: bool = False,
    ) -> PrintTemplateRecord:
        if not self.config.printing_enabled:
            raise PrintingUnavailable("local printing capability is disabled")
        name = name.strip()
        if not 1 <= len(name) <= 160:
            raise ValueError("template name must be 1..160 characters")
        normalized, layout_hash = canonical_layout_sha256(
            layout, label_width_mm=label_width_mm, label_height_mm=label_height_mm
        )
        participant_id = None if organisation_wide else self.scope.participant_id
        template = PrintTemplateRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=participant_id,
            name=name,
            state="ACTIVE",
            created_by_user_id=user_id,
        )
        self.db.add(template)
        self.db.flush()
        version = PrintTemplateVersionRecord(
            id=str(uuid4()),
            template_id=template.id,
            organisation_id=self.scope.organisation_id,
            participant_id=participant_id,
            version_number=1,
            schema_version=normalized["schema_version"],
            label_width_mm=label_width_mm,
            label_height_mm=label_height_mm,
            layout_json=normalized,
            layout_sha256=layout_hash,
            created_by_user_id=user_id,
        )
        self.db.add(version)
        self.db.flush()
        template.current_version_id = version.id
        self._audit(
            "PRINT_TEMPLATE_CREATED",
            subject_type=SubjectType.PRINT_TEMPLATE,
            subject_id=template.id,
            user_id=user_id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"template_id": template.id, "template_version_id": version.id, "layout_sha256": layout_hash},
            evidence_hashes=(layout_hash,),
            event_key=f"print-template:{template.id}:created",
        )
        return template

    def create_template_version(
        self,
        template_id: str,
        *,
        label_width_mm: float,
        label_height_mm: float,
        layout: Mapping[str, Any],
        user_id: int,
    ) -> PrintTemplateVersionRecord:
        template = self._template(template_id, allow_archived=False)
        normalized, layout_hash = canonical_layout_sha256(
            layout, label_width_mm=label_width_mm, label_height_mm=label_height_mm
        )
        current_max = self.db.scalar(
            select(func.max(PrintTemplateVersionRecord.version_number)).where(
                PrintTemplateVersionRecord.template_id == template.id
            )
        ) or 0
        version = PrintTemplateVersionRecord(
            id=str(uuid4()),
            template_id=template.id,
            organisation_id=template.organisation_id,
            participant_id=template.participant_id,
            version_number=current_max + 1,
            schema_version=normalized["schema_version"],
            label_width_mm=label_width_mm,
            label_height_mm=label_height_mm,
            layout_json=normalized,
            layout_sha256=layout_hash,
            created_by_user_id=user_id,
        )
        self.db.add(version)
        self.db.flush()
        template.current_version_id = version.id
        self._audit(
            "PRINT_TEMPLATE_VERSION_CREATED",
            subject_type=SubjectType.PRINT_TEMPLATE,
            subject_id=template.id,
            user_id=user_id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"template_id": template.id, "template_version_id": version.id, "layout_sha256": layout_hash},
            evidence_hashes=(layout_hash,),
            event_key=f"print-template:{template.id}:version:{version.version_number}",
        )
        return version

    def archive_template(self, template_id: str, *, user_id: int) -> PrintTemplateRecord:
        template = self._template(template_id)
        if template.state == "ARCHIVED":
            return template
        template.state = "ARCHIVED"
        template.archived_at = _utcnow()
        self._audit(
            "PRINT_TEMPLATE_ARCHIVED",
            subject_type=SubjectType.PRINT_TEMPLATE,
            subject_id=template.id,
            user_id=user_id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"template_id": template.id, "template_version_id": template.current_version_id},
            event_key=f"print-template:{template.id}:archived",
        )
        return template

    def list_templates(self) -> list[dict[str, Any]]:
        rows = list(self.db.scalars(
            select(PrintTemplateRecord).where(
                PrintTemplateRecord.organisation_id == self.scope.organisation_id,
                (PrintTemplateRecord.participant_id.is_(None) | (PrintTemplateRecord.participant_id == self.scope.participant_id)),
            ).order_by(PrintTemplateRecord.created_at, PrintTemplateRecord.id)
        ))
        return [
            {
                "id": row.id,
                "name": row.name,
                "state": row.state,
                "participant_scope": "ORGANISATION" if row.participant_id is None else "PARTICIPANT",
                "current_version_id": row.current_version_id,
                "created_at": row.created_at.isoformat(),
                "archived_at": row.archived_at.isoformat() if row.archived_at else None,
            }
            for row in rows
        ]

    def template_detail(self, template_id: str) -> dict[str, Any]:
        template = self._template(template_id)
        versions = list(self.db.scalars(
            select(PrintTemplateVersionRecord)
            .where(PrintTemplateVersionRecord.template_id == template.id)
            .order_by(PrintTemplateVersionRecord.version_number)
        ))
        return {
            "id": template.id,
            "name": template.name,
            "state": template.state,
            "participant_scope": "ORGANISATION" if template.participant_id is None else "PARTICIPANT",
            "current_version_id": template.current_version_id,
            "versions": [
                {
                    "id": v.id,
                    "version_number": v.version_number,
                    "schema_version": v.schema_version,
                    "label_width_mm": float(v.label_width_mm),
                    "label_height_mm": float(v.label_height_mm),
                    "layout": v.layout_json,
                    "layout_sha256": v.layout_sha256,
                    "created_at": v.created_at.isoformat(),
                }
                for v in versions
            ],
        }

    def preview(self, version_id: str, *, dpi: int = 300) -> dict[str, Any]:
        version = self._version(version_id)
        result = render_synthetic_preview(
            version.layout_json,
            label_width_mm=float(version.label_width_mm),
            label_height_mm=float(version.label_height_mm),
            dpi=dpi,
        )
        return {
            "template_version_id": version.id,
            "layout_sha256": version.layout_sha256,
            **result,
        }

    def _job(self, job_id: str) -> PrintJobRecord:
        row = self.db.scalar(
            select(PrintJobRecord).where(
                PrintJobRecord.id == job_id,
                PrintJobRecord.organisation_id == self.scope.organisation_id,
                PrintJobRecord.participant_id == self.scope.participant_id,
            )
        )
        if row is None:
            raise KeyError(job_id)
        return row

    @staticmethod
    def _aggregate_payload_hash(items: list[StoredFullKmItemRecord], template_version_id: str, mode: str) -> str:
        payload = {
            "item_hashes": [row.full_km_sha256 for row in items],
            "template_version_id": template_version_id,
            "mode": mode,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def create_print_job(
        self,
        *,
        stored_item_ids: list[str],
        template_version_id: str,
        user_id: int,
        mode: str = "INITIAL_PRINT",
        printer_profile_id: str | None = None,
        original_print_event_id: str | None = None,
    ) -> PrintJobRecord:
        if not self.config.printing_enabled:
            raise PrintingUnavailable("local printing capability is disabled")
        if mode not in {"INITIAL_PRINT", "REPRINT_ORIGINAL_TEMPLATE", "PRINT_USING_CURRENT_TEMPLATE"}:
            raise ValueError("unsupported print mode")
        if not 1 <= len(stored_item_ids) <= 1000 or len(set(stored_item_ids)) != len(stored_item_ids):
            raise ValueError("stored_item_ids must contain 1..1000 unique items")
        version = self._version(template_version_id)
        template = self._template(version.template_id, allow_archived=(mode == "REPRINT_ORIGINAL_TEMPLATE"))
        if mode != "REPRINT_ORIGINAL_TEMPLATE" and template.state != "ACTIVE":
            raise PrintingUnavailable("new print jobs require an active template")

        items: list[StoredFullKmItemRecord] = []
        for item_id in stored_item_ids:
            item = self._stored_by_id(item_id)
            try:
                self._decrypt_and_verify(item)
            except (PrintingIntegrityError, RuntimeError) as exc:
                raise PrintingIntegrityError(f"item is not printable: {exc}") from exc
            items.append(item)

        profile_fingerprint = (
            hashlib.sha256(("print-profile-v1\0" + printer_profile_id).encode("utf-8")).hexdigest()
            if printer_profile_id else None
        )
        aggregate_hash = self._aggregate_payload_hash(items, version.id, mode)
        trace = self.db.info.get("audit_trace")
        correlation_id = trace.get("correlation_id") if isinstance(trace, dict) else None
        job = PrintJobRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            template_version_id=version.id,
            mode=mode,
            requested_by_user_id=user_id,
            state="READY_FOR_AGENT" if self.config.print_execution_enabled else "BLOCKED",
            item_count=len(items),
            output_kind="WINDOWS_AGENT",
            printer_profile_id=printer_profile_id,
            printer_profile_fingerprint=profile_fingerprint,
            metadata_sanitized_json={
                "execution_capability": "ENABLED" if self.config.print_execution_enabled else "BLOCKED_PHYSICAL_PRINT_EXECUTION_DISABLED",
                "payload_set_sha256": aggregate_hash,
            },
            correlation_id=correlation_id,
            original_print_event_id=original_print_event_id,
        )
        self.db.add(job)
        self.db.flush()
        for ordinal, item in enumerate(items):
            self.db.add(PrintJobItemRecord(
                id=str(uuid4()),
                print_job_id=job.id,
                organisation_id=self.scope.organisation_id,
                participant_id=self.scope.participant_id,
                stored_full_km_item_id=item.id,
                ordinal=ordinal,
                payload_hash=item.full_km_sha256,
                state="PENDING" if self.config.print_execution_enabled else "BLOCKED",
                error_code=None if self.config.print_execution_enabled else "PHYSICAL_PRINT_EXECUTION_DISABLED",
            ))
        event_type = "REPRINT_REQUESTED" if mode != "INITIAL_PRINT" else "PRINT_JOB_REQUESTED"
        event = PrintEventRecord(
            id=str(uuid4()),
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            print_job_id=job.id,
            template_version_id=version.id,
            payload_hash=aggregate_hash,
            actor_kind="USER",
            actor_user_id=user_id,
            printer_profile_fingerprint=profile_fingerprint,
            event_type=event_type,
            outcome="PENDING" if self.config.print_execution_enabled else "BLOCKED",
            error_code=None if self.config.print_execution_enabled else "PHYSICAL_PRINT_EXECUTION_DISABLED",
            original_print_event_id=original_print_event_id,
            evidence_sha256=aggregate_hash,
            metadata_sanitized_json={"count": len(items), "mode": mode},
        )
        self.db.add(event)
        self.db.flush()
        self._audit(
            event_type,
            subject_type=SubjectType.PRINT_JOB,
            subject_id=job.id,
            user_id=user_id,
            outcome=AuditOutcome.PENDING if self.config.print_execution_enabled else AuditOutcome.FAILED,
            metadata={
                "template_version_id": version.id,
                "count": len(items),
                "printer_profile_fingerprint": profile_fingerprint,
                "original_print_event_id": original_print_event_id,
                "print_mode": mode,
                "payload_sha256": aggregate_hash,
            },
            evidence_hashes=(aggregate_hash,),
            event_key=f"print-job:{job.id}:requested",
        )
        return job

    def reprint(self, original_print_event_id: str, *, user_id: int, use_current_template: bool = False) -> PrintJobRecord:
        event = self.db.scalar(
            select(PrintEventRecord).where(
                PrintEventRecord.id == original_print_event_id,
                PrintEventRecord.organisation_id == self.scope.organisation_id,
                PrintEventRecord.participant_id == self.scope.participant_id,
            )
        )
        if event is None:
            raise KeyError(original_print_event_id)
        if event.event_type not in {"PRINT_JOB_COMPLETED", "REPRINT_COMPLETED"} or event.outcome != "SUCCESS":
            raise PrintingUnavailable("reprint requires a successful original print event")
        original_job = self._job(event.print_job_id)
        stored_ids = list(self.db.scalars(
            select(PrintJobItemRecord.stored_full_km_item_id)
            .where(PrintJobItemRecord.print_job_id == original_job.id)
            .order_by(PrintJobItemRecord.ordinal)
        ))
        if use_current_template:
            original_version = self._version(event.template_version_id)
            template = self._template(original_version.template_id, allow_archived=False)
            if not template.current_version_id:
                raise PrintingUnavailable("template has no current version")
            version_id = template.current_version_id
            mode = "PRINT_USING_CURRENT_TEMPLATE"
        else:
            version_id = event.template_version_id
            mode = "REPRINT_ORIGINAL_TEMPLATE"
        return self.create_print_job(
            stored_item_ids=stored_ids,
            template_version_id=version_id,
            user_id=user_id,
            mode=mode,
            printer_profile_id=original_job.printer_profile_id,
            original_print_event_id=event.id,
        )

    def job_detail(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        items = list(self.db.scalars(
            select(PrintJobItemRecord)
            .where(
                PrintJobItemRecord.print_job_id == job.id,
                PrintJobItemRecord.organisation_id == self.scope.organisation_id,
                PrintJobItemRecord.participant_id == self.scope.participant_id,
            )
            .order_by(PrintJobItemRecord.ordinal)
        ))
        events = list(self.db.scalars(
            select(PrintEventRecord)
            .where(
                PrintEventRecord.print_job_id == job.id,
                PrintEventRecord.organisation_id == self.scope.organisation_id,
                PrintEventRecord.participant_id == self.scope.participant_id,
            )
            .order_by(PrintEventRecord.created_at, PrintEventRecord.id)
        ))
        return {
            "id": job.id,
            "template_version_id": job.template_version_id,
            "mode": job.mode,
            "state": job.state,
            "item_count": job.item_count,
            "output_kind": job.output_kind,
            "printer_profile_fingerprint": job.printer_profile_fingerprint,
            "correlation_id": job.correlation_id,
            "original_print_event_id": job.original_print_event_id,
            "requested_at": job.requested_at.isoformat(),
            "items": [
                {
                    "id": item.id,
                    "stored_full_km_item_id": item.stored_full_km_item_id,
                    "ordinal": item.ordinal,
                    "payload_sha256": item.payload_hash,
                    "state": item.state,
                    "safe_error_code": item.error_code,
                }
                for item in items
            ],
            "events": [
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "outcome": event.outcome,
                    "template_version_id": event.template_version_id,
                    "payload_sha256": event.payload_hash,
                    "printer_profile_fingerprint": event.printer_profile_fingerprint,
                    "safe_error_code": event.error_code,
                    "original_print_event_id": event.original_print_event_id,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ],
        }

    def list_jobs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be 1..500")
        rows = list(self.db.scalars(
            select(PrintJobRecord)
            .where(
                PrintJobRecord.organisation_id == self.scope.organisation_id,
                PrintJobRecord.participant_id == self.scope.participant_id,
            )
            .order_by(PrintJobRecord.requested_at.desc(), PrintJobRecord.id.desc())
            .limit(limit)
        ))
        return [
            {
                "id": row.id,
                "template_version_id": row.template_version_id,
                "mode": row.mode,
                "state": row.state,
                "item_count": row.item_count,
                "printer_profile_fingerprint": row.printer_profile_fingerprint,
                "requested_at": row.requested_at.isoformat(),
            }
            for row in rows
        ]

    def mark_completed(self, job_id: str, *, success: bool, error_code: str | None = None) -> PrintJobRecord:
        job = self._job(job_id)
        if job.state not in {"READY_FOR_AGENT", "PENDING"}:
            raise PrintingUnavailable("print job is not executable")
        safe_error = None if success else (error_code or "PRINT_EXECUTION_FAILED")[:96]
        job.state = "COMPLETED" if success else "FAILED"
        event_type = (
            "REPRINT_COMPLETED" if success and job.mode != "INITIAL_PRINT"
            else "REPRINT_FAILED" if job.mode != "INITIAL_PRINT"
            else "PRINT_JOB_COMPLETED" if success
            else "PRINT_JOB_FAILED"
        )
        aggregate_hash = str((job.metadata_sanitized_json or {}).get("payload_set_sha256") or "")
        event = PrintEventRecord(
            id=str(uuid4()),
            organisation_id=job.organisation_id,
            participant_id=job.participant_id,
            print_job_id=job.id,
            template_version_id=job.template_version_id,
            payload_hash=aggregate_hash or None,
            actor_kind="WINDOWS_AGENT",
            printer_profile_fingerprint=job.printer_profile_fingerprint,
            event_type=event_type,
            outcome="SUCCESS" if success else "FAILED",
            error_code=safe_error,
            original_print_event_id=job.original_print_event_id,
            evidence_sha256=aggregate_hash or None,
            metadata_sanitized_json={"count": job.item_count, "mode": job.mode},
        )
        self.db.add(event)
        item_state = "COMPLETED" if success else "FAILED"
        items = list(self.db.scalars(select(PrintJobItemRecord).where(PrintJobItemRecord.print_job_id == job.id)))
        for item in items:
            item.state = item_state
            item.error_code = safe_error
        self._audit(
            event_type,
            subject_type=SubjectType.PRINT_JOB,
            subject_id=job.id,
            user_id=None,
            outcome=AuditOutcome.SUCCESS if success else AuditOutcome.FAILED,
            metadata={
                "template_version_id": job.template_version_id,
                "count": job.item_count,
                "printer_profile_fingerprint": job.printer_profile_fingerprint,
                "original_print_event_id": job.original_print_event_id,
                "print_mode": job.mode,
                "payload_sha256": aggregate_hash or None,
                "error_code": safe_error,
            },
            evidence_hashes=(aggregate_hash,) if aggregate_hash else (),
            event_key=f"print-job:{job.id}:{'completed' if success else 'failed'}",
            actor_kind=ActorKind.WINDOWS_AGENT,
        )
        return job

    def agent_contract(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        items = list(self.db.scalars(
            select(PrintJobItemRecord)
            .where(PrintJobItemRecord.print_job_id == job.id)
            .order_by(PrintJobItemRecord.ordinal)
        ))
        return {
            "contract_version": "printing-agent-v1",
            "job_id": job.id,
            "organisation_id": job.organisation_id,
            "participant_id": job.participant_id,
            "template_version_id": job.template_version_id,
            "mode": job.mode,
            "printer_profile_id": job.printer_profile_id,
            "printer_profile_fingerprint": job.printer_profile_fingerprint,
            "items": [
                {
                    "print_job_item_id": item.id,
                    "stored_full_km_item_id": item.stored_full_km_item_id,
                    "ordinal": item.ordinal,
                    "payload_sha256": item.payload_hash,
                }
                for item in items
            ],
            "sensitive_payload_delivery": "BLOCKED_NOT_IMPLEMENTED",
        }
