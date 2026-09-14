from __future__ import annotations

from copy import deepcopy

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from wbcz.p0_write import (
    AuditTransition,
    OperationNotFound,
    PipelineOperation,
    SigningRequestRecord,
    SigningRequestStatus,
    StoreConflict,
    WriteState,
)
from wbcz_web.models.write_pipeline import (
    SigningRequestDbRecord,
    WriteOperationAuditRecord,
    WriteOperationRecord,
)


class SqlWritePipelineStore:
    """PostgreSQL persistence adapter for the P0 write state machine.

    State updates use compare-and-set predicates so two workers cannot both
    advance the same operation from SIGNED into a second submission path.
    Transactions are owned by the caller's SQLAlchemy Session.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    @staticmethod
    def _to_operation(row: WriteOperationRecord) -> PipelineOperation:
        return PipelineOperation(
            operation_id=row.operation_id,
            business_fingerprint=row.business_fingerprint,
            source_event_id=row.source_event_id,
            source_decision=row.source_decision,
            document_type=row.document_type,
            operation_reason=row.operation_reason,
            pg=row.pg,
            expected_inn=row.expected_inn,
            document_sha256=row.document_sha256,
            product_document_base64=row.product_document_base64,
            prepared_at=row.prepared_at,
            state=WriteState(row.state),
            signature_base64=row.signature_base64,
            signature_sha256=row.signature_sha256,
            certificate_thumbprint=row.certificate_thumbprint,
            certificate_subject=row.certificate_subject,
            certificate_inn=row.certificate_inn,
            certificate_valid_from=row.certificate_valid_from,
            certificate_valid_to=row.certificate_valid_to,
            signed_at=row.signed_at,
            submit_started_at=row.submit_started_at,
            submitted_at=row.submitted_at,
            doc_id=row.doc_id,
            last_http_status=row.last_http_status,
            last_response_meta=dict(row.last_response_meta or {}),
            last_poll_status=row.last_poll_status,
            terminal_at=row.terminal_at,
            reconciliation_required=row.reconciliation_required,
        )

    @staticmethod
    def _operation_values(operation: PipelineOperation) -> dict:
        return {
            "business_fingerprint": operation.business_fingerprint,
            "source_event_id": operation.source_event_id,
            "source_decision": operation.source_decision,
            "document_type": operation.document_type,
            "operation_reason": operation.operation_reason,
            "pg": operation.pg,
            "expected_inn": operation.expected_inn,
            "document_sha256": operation.document_sha256,
            "product_document_base64": operation.product_document_base64,
            "prepared_at": operation.prepared_at,
            "state": operation.state.value,
            "signature_base64": operation.signature_base64,
            "signature_sha256": operation.signature_sha256,
            "certificate_thumbprint": operation.certificate_thumbprint,
            "certificate_subject": operation.certificate_subject,
            "certificate_inn": operation.certificate_inn,
            "certificate_valid_from": operation.certificate_valid_from,
            "certificate_valid_to": operation.certificate_valid_to,
            "signed_at": operation.signed_at,
            "submit_started_at": operation.submit_started_at,
            "submitted_at": operation.submitted_at,
            "doc_id": operation.doc_id,
            "last_http_status": operation.last_http_status,
            "last_response_meta": deepcopy(operation.last_response_meta),
            "last_poll_status": operation.last_poll_status,
            "terminal_at": operation.terminal_at,
            "reconciliation_required": operation.reconciliation_required,
        }

    def create_or_get_operation(self, operation: PipelineOperation) -> tuple[PipelineOperation, bool]:
        existing = self.db.scalar(
            select(WriteOperationRecord).where(
                WriteOperationRecord.business_fingerprint == operation.business_fingerprint
            )
        )
        if existing is not None:
            return self._to_operation(existing), False

        record = WriteOperationRecord(
            operation_id=operation.operation_id,
            **self._operation_values(operation),
        )
        try:
            with self.db.begin_nested():
                self.db.add(record)
                self.db.flush()
            return self._to_operation(record), True
        except IntegrityError:
            existing = self.db.scalar(
                select(WriteOperationRecord).where(
                    WriteOperationRecord.business_fingerprint == operation.business_fingerprint
                )
            )
            if existing is None:
                raise
            return self._to_operation(existing), False

    def get_operation(self, operation_id: str) -> PipelineOperation | None:
        row = self.db.get(WriteOperationRecord, operation_id)
        return self._to_operation(row) if row is not None else None

    def compare_and_save_operation(self, operation: PipelineOperation, *, expected_state: WriteState) -> None:
        result = self.db.execute(
            update(WriteOperationRecord)
            .where(
                WriteOperationRecord.operation_id == operation.operation_id,
                WriteOperationRecord.state == expected_state.value,
            )
            .values(**self._operation_values(operation))
        )
        if result.rowcount != 1:
            current = self.db.scalar(
                select(WriteOperationRecord.state).where(
                    WriteOperationRecord.operation_id == operation.operation_id
                )
            )
            if current is None:
                raise OperationNotFound(operation.operation_id)
            raise StoreConflict(
                f"operation state changed concurrently: expected {expected_state.value}, got {current}"
            )
        self.db.flush()

    @staticmethod
    def _to_signing(row: SigningRequestDbRecord) -> SigningRequestRecord:
        return SigningRequestRecord(
            request_id=row.request_id,
            operation_id=row.operation_id,
            status=SigningRequestStatus(row.status),
            created_at=row.created_at,
            fulfilled_at=row.fulfilled_at,
        )

    def get_or_create_signing_request(self, request: SigningRequestRecord) -> tuple[SigningRequestRecord, bool]:
        existing = self.db.scalar(
            select(SigningRequestDbRecord).where(
                SigningRequestDbRecord.operation_id == request.operation_id
            )
        )
        if existing is not None:
            return self._to_signing(existing), False
        row = SigningRequestDbRecord(
            request_id=request.request_id,
            operation_id=request.operation_id,
            status=request.status.value,
            created_at=request.created_at,
            fulfilled_at=request.fulfilled_at,
        )
        try:
            with self.db.begin_nested():
                self.db.add(row)
                self.db.flush()
            return self._to_signing(row), True
        except IntegrityError:
            existing = self.db.scalar(
                select(SigningRequestDbRecord).where(
                    SigningRequestDbRecord.operation_id == request.operation_id
                )
            )
            if existing is None:
                raise
            return self._to_signing(existing), False

    def get_signing_request_for_operation(self, operation_id: str) -> SigningRequestRecord | None:
        row = self.db.scalar(
            select(SigningRequestDbRecord).where(
                SigningRequestDbRecord.operation_id == operation_id
            )
        )
        return self._to_signing(row) if row is not None else None

    def compare_and_save_signing_request(self, request: SigningRequestRecord, *, expected_status: SigningRequestStatus) -> None:
        result = self.db.execute(
            update(SigningRequestDbRecord)
            .where(
                SigningRequestDbRecord.request_id == request.request_id,
                SigningRequestDbRecord.status == expected_status.value,
            )
            .values(
                status=request.status.value,
                fulfilled_at=request.fulfilled_at,
            )
        )
        if result.rowcount != 1:
            raise StoreConflict("signing request status changed concurrently")
        self.db.flush()

    def list_pending_signing_requests(self, *, limit: int) -> list[SigningRequestRecord]:
        rows = self.db.scalars(
            select(SigningRequestDbRecord)
            .where(SigningRequestDbRecord.status == SigningRequestStatus.PENDING.value)
            .order_by(SigningRequestDbRecord.created_at, SigningRequestDbRecord.request_id)
            .limit(limit)
        ).all()
        return [self._to_signing(row) for row in rows]

    def append_audit(self, entry: AuditTransition) -> None:
        self.db.add(
            WriteOperationAuditRecord(
                operation_id=entry.operation_id,
                action=entry.action,
                from_state=entry.from_state,
                to_state=entry.to_state,
                occurred_at=entry.occurred_at,
                metadata_json=deepcopy(entry.metadata),
            )
        )
        self.db.flush()

    def audit_for_operation(self, operation_id: str) -> list[AuditTransition]:
        rows = self.db.scalars(
            select(WriteOperationAuditRecord)
            .where(WriteOperationAuditRecord.operation_id == operation_id)
            .order_by(WriteOperationAuditRecord.id)
        ).all()
        return [
            AuditTransition(
                operation_id=row.operation_id,
                action=row.action,
                from_state=row.from_state,
                to_state=row.to_state,
                occurred_at=row.occurred_at,
                metadata=dict(row.metadata_json or {}),
            )
            for row in rows
        ]
