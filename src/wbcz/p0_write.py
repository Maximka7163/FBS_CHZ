from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import base64
import binascii
import hashlib
import json
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import quote
from uuid import uuid4

from .models import Decision, canonical_json

P0_PG = "lp"
SUPPORTED_DOCUMENT_TYPES = frozenset({"LK_RECEIPT", "LP_RETURN"})
SUPPORTED_REASON_BY_DECISION = {
    Decision.READY_TO_WITHDRAW: ("LK_RECEIPT", "DISTANCE"),
    Decision.READY_TO_RETURN: ("LP_RETURN", "REMOTE_SALE_RETURN"),
}


class P0DocumentType(StrEnum):
    LK_RECEIPT = "LK_RECEIPT"
    LP_RETURN = "LP_RETURN"


class WriteState(StrEnum):
    PREPARED = "PREPARED"
    AWAITING_SIGNATURE = "AWAITING_SIGNATURE"
    SIGNED = "SIGNED"
    SUBMITTING = "SUBMITTING"
    SUBMITTED = "SUBMITTED"
    PROCESSING = "PROCESSING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class SigningRequestStatus(StrEnum):
    PENDING = "PENDING"
    FULFILLED = "FULFILLED"


class CreateAttemptKind(StrEnum):
    ACCEPTED = "ACCEPTED"
    IMMEDIATE_FAILURE = "IMMEDIATE_FAILURE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class PollClassification(StrEnum):
    INTERMEDIATE = "INTERMEDIATE"
    TERMINAL_SUCCESS = "TERMINAL_SUCCESS"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class WritePipelineError(RuntimeError): pass
class UnsupportedP0Operation(WritePipelineError): pass
class OperationNotFound(WritePipelineError): pass
class InvalidStateTransition(WritePipelineError): pass
class IdempotencyConflict(WritePipelineError): pass
class StoreConflict(WritePipelineError): pass
class SignatureRejected(WritePipelineError): pass
class DuplicateSubmitBlocked(WritePipelineError): pass
class ProductionWriteDisabled(WritePipelineError): pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_inn(value: str) -> None:
    if not value.isdigit() or len(value) not in {10, 12}:
        raise ValueError("expected_inn must contain 10 or 12 digits")


def _normalize_signature(value: str) -> str:
    normalized = value.replace("\r", "").replace("\n", "").strip()
    if not normalized:
        raise SignatureRejected("signature_base64 is empty")
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureRejected("signature_base64 is not valid Base64") from exc
    if not decoded:
        raise SignatureRejected("signature_base64 decodes to empty bytes")
    return normalized


@dataclass(frozen=True, slots=True)
class PreparedDocument:
    operation_id: str
    source_event_id: str
    source_decision: Decision
    document_type: P0DocumentType
    operation_reason: str
    pg: str
    expected_inn: str
    document_sha256: str
    product_document_base64: str
    bytes_for_signature: bytes
    prepared_at: datetime
    business_fingerprint: str


class P0ExactDocumentBuilder:
    """Serialize an already approved P0 document body exactly once."""
    def __init__(self, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock

    def prepare(self, *, source_event_id: str, decision: Decision, operation_reason: str,
                expected_inn: str, document_body: Mapping[str, Any]) -> PreparedDocument:
        expected = SUPPORTED_REASON_BY_DECISION.get(decision)
        if expected is None:
            raise UnsupportedP0Operation(f"decision {decision.value} cannot enter P0 write pipeline")
        document_type_raw, required_reason = expected
        if operation_reason != required_reason:
            raise UnsupportedP0Operation(f"{decision.value} requires operation reason {required_reason}")
        if not source_event_id:
            raise ValueError("source_event_id is required")
        _validate_inn(expected_inn)
        if not isinstance(document_body, Mapping) or not document_body:
            raise ValueError("approved document_body must be a non-empty mapping")
        payload = canonical_json(dict(document_body)).encode("utf-8")
        b64 = base64.b64encode(payload).decode("ascii")
        digest = hashlib.sha256(payload).hexdigest()
        document_type = P0DocumentType(document_type_raw)
        fp_payload = canonical_json({
            "v": 1,
            "source_event_id": source_event_id,
            "source_decision": decision.value,
            "document_type": document_type.value,
            "pg": P0_PG,
            "expected_inn": expected_inn,
        }).encode("utf-8")
        fingerprint = hashlib.sha256(b"wbcz-p0-operation:v1:" + fp_payload).hexdigest()
        return PreparedDocument(str(uuid4()), source_event_id, decision, document_type,
            operation_reason, P0_PG, expected_inn, digest, b64, payload,
            self._clock(), fingerprint)


@dataclass(slots=True)
class PipelineOperation:
    operation_id: str
    business_fingerprint: str
    source_event_id: str
    source_decision: str
    document_type: str
    operation_reason: str
    pg: str
    expected_inn: str
    document_sha256: str
    product_document_base64: str
    prepared_at: datetime
    state: WriteState = WriteState.PREPARED
    signature_base64: str | None = None
    signature_sha256: str | None = None
    certificate_thumbprint: str | None = None
    certificate_subject: str | None = None
    certificate_inn: str | None = None
    certificate_valid_from: datetime | None = None
    certificate_valid_to: datetime | None = None
    signed_at: datetime | None = None
    submit_started_at: datetime | None = None
    submitted_at: datetime | None = None
    doc_id: str | None = None
    last_http_status: int | None = None
    last_response_meta: dict[str, Any] = field(default_factory=dict)
    last_poll_status: str | None = None
    terminal_at: datetime | None = None
    reconciliation_required: bool = False

    @classmethod
    def from_prepared(cls, p: PreparedDocument) -> "PipelineOperation":
        return cls(p.operation_id, p.business_fingerprint, p.source_event_id,
            p.source_decision.value, p.document_type.value, p.operation_reason,
            p.pg, p.expected_inn, p.document_sha256, p.product_document_base64,
            p.prepared_at)


@dataclass(slots=True)
class SigningRequestRecord:
    request_id: str
    operation_id: str
    status: SigningRequestStatus
    created_at: datetime
    fulfilled_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SigningRequest:
    request_id: str
    operation_id: str
    document_type: str
    pg: str
    expected_inn: str
    document_sha256: str
    product_document_base64: str


@dataclass(frozen=True, slots=True)
class CertificateMetadata:
    certificate_inn: str
    certificate_thumbprint: str | None = None
    certificate_subject: str | None = None
    certificate_valid_from: datetime | None = None
    certificate_valid_to: datetime | None = None


@dataclass(frozen=True, slots=True)
class SigningResponse:
    operation_id: str
    document_sha256: str
    signature_base64: str
    certificate: CertificateMetadata


@dataclass(frozen=True, slots=True)
class AuditTransition:
    operation_id: str
    action: str
    from_state: str | None
    to_state: str
    occurred_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


class WritePipelineStore(Protocol):
    def create_or_get_operation(self, operation: PipelineOperation) -> tuple[PipelineOperation, bool]: ...
    def get_operation(self, operation_id: str) -> PipelineOperation | None: ...
    def compare_and_save_operation(self, operation: PipelineOperation, *, expected_state: WriteState) -> None: ...
    def get_or_create_signing_request(self, request: SigningRequestRecord) -> tuple[SigningRequestRecord, bool]: ...
    def get_signing_request_for_operation(self, operation_id: str) -> SigningRequestRecord | None: ...
    def compare_and_save_signing_request(self, request: SigningRequestRecord, *, expected_status: SigningRequestStatus) -> None: ...
    def list_pending_signing_requests(self, *, limit: int) -> list[SigningRequestRecord]: ...
    def append_audit(self, entry: AuditTransition) -> None: ...
    def audit_for_operation(self, operation_id: str) -> list[AuditTransition]: ...


class InMemoryWritePipelineStore:
    def __init__(self) -> None:
        self._operations: dict[str, PipelineOperation] = {}
        self._by_fingerprint: dict[str, str] = {}
        self._signing: dict[str, SigningRequestRecord] = {}
        self._signing_by_operation: dict[str, str] = {}
        self._audit: list[AuditTransition] = []

    def create_or_get_operation(self, operation: PipelineOperation) -> tuple[PipelineOperation, bool]:
        oid = self._by_fingerprint.get(operation.business_fingerprint)
        if oid is not None:
            return deepcopy(self._operations[oid]), False
        self._operations[operation.operation_id] = deepcopy(operation)
        self._by_fingerprint[operation.business_fingerprint] = operation.operation_id
        return deepcopy(operation), True

    def get_operation(self, operation_id: str) -> PipelineOperation | None:
        value = self._operations.get(operation_id)
        return deepcopy(value) if value is not None else None

    def compare_and_save_operation(self, operation: PipelineOperation, *, expected_state: WriteState) -> None:
        current = self._operations.get(operation.operation_id)
        if current is None:
            raise OperationNotFound(operation.operation_id)
        if current.state is not expected_state:
            raise StoreConflict(f"operation state changed concurrently: expected {expected_state.value}, got {current.state.value}")
        self._operations[operation.operation_id] = deepcopy(operation)

    def get_or_create_signing_request(self, request: SigningRequestRecord) -> tuple[SigningRequestRecord, bool]:
        rid = self._signing_by_operation.get(request.operation_id)
        if rid is not None:
            return deepcopy(self._signing[rid]), False
        self._signing[request.request_id] = deepcopy(request)
        self._signing_by_operation[request.operation_id] = request.request_id
        return deepcopy(request), True

    def get_signing_request_for_operation(self, operation_id: str) -> SigningRequestRecord | None:
        rid = self._signing_by_operation.get(operation_id)
        return deepcopy(self._signing[rid]) if rid is not None else None

    def compare_and_save_signing_request(self, request: SigningRequestRecord, *, expected_status: SigningRequestStatus) -> None:
        current = self._signing.get(request.request_id)
        if current is None or current.status is not expected_status:
            raise StoreConflict("signing request status changed concurrently")
        self._signing[request.request_id] = deepcopy(request)

    def list_pending_signing_requests(self, *, limit: int) -> list[SigningRequestRecord]:
        items = [x for x in self._signing.values() if x.status is SigningRequestStatus.PENDING]
        items.sort(key=lambda x: (x.created_at, x.request_id))
        return [deepcopy(x) for x in items[:limit]]

    def append_audit(self, entry: AuditTransition) -> None:
        self._audit.append(deepcopy(entry))

    def audit_for_operation(self, operation_id: str) -> list[AuditTransition]:
        return [deepcopy(x) for x in self._audit if x.operation_id == operation_id]


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class HttpTransport(Protocol):
    def request(self, *, method: str, path: str, headers: Mapping[str, str], body: bytes | None) -> HttpResponse: ...


class CreateResponseParser(Protocol):
    contract_name: str
    def parse_document_id(self, response: HttpResponse) -> str | None: ...


class UnconfirmedCreateResponseParser:
    contract_name = "UNCONFIRMED"
    def parse_document_id(self, response: HttpResponse) -> str | None:
        return None


@dataclass(frozen=True, slots=True)
class CreateAttemptResult:
    kind: CreateAttemptKind
    http_status: int | None
    doc_id: str | None
    reason: str
    safe_response_meta: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PollResult:
    classification: PollClassification
    status: str | None
    reason: str
    http_status: int
    safe_response_meta: dict[str, Any]


def _safe_response_meta(response: HttpResponse) -> dict[str, Any]:
    content_type = next((v[:128] for k, v in response.headers.items() if k.lower() == "content-type"), None)
    return {"http_status": response.status_code, "body_length": len(response.body),
            "body_sha256": hashlib.sha256(response.body).hexdigest(), "content_type": content_type}


class TrueApiWriteAdapter:
    def __init__(self, transport: HttpTransport, *, create_response_parser: CreateResponseParser | None = None,
                 write_enabled: bool = False) -> None:
        self._transport = transport
        self._parser = create_response_parser or UnconfirmedCreateResponseParser()
        self.write_enabled = write_enabled

    def create(self, operation: PipelineOperation, *, bearer_token: str) -> CreateAttemptResult:
        if not self.write_enabled:
            raise ProductionWriteDisabled("True API production write is disabled")
        if operation.pg != P0_PG or operation.document_type not in SUPPORTED_DOCUMENT_TYPES:
            raise UnsupportedP0Operation("P0 create is restricted to pg=lp and LK_RECEIPT/LP_RETURN")
        if not operation.signature_base64:
            raise SignatureRejected("operation has no detached signature")
        if not bearer_token:
            raise ValueError("bearer token is required")
        body = canonical_json({
            "document_format": "MANUAL",
            "product_document": operation.product_document_base64,
            "type": operation.document_type,
            "signature": _normalize_signature(operation.signature_base64),
        }).encode("utf-8")
        try:
            response = self._transport.request(method="POST",
                path="/api/v3/true-api/lk/documents/create?pg=lp",
                headers={"Authorization": f"Bearer {bearer_token}", "Content-Type": "application/json"}, body=body)
        except Exception as exc:
            return CreateAttemptResult(CreateAttemptKind.MANUAL_REVIEW, None, None,
                f"TRANSPORT_ERROR:{type(exc).__name__}", {"transport_error_type": type(exc).__name__})
        meta = _safe_response_meta(response)
        status = response.status_code
        if status in {400, 401, 403, 422}:
            return CreateAttemptResult(CreateAttemptKind.IMMEDIATE_FAILURE, status, None, f"HTTP_{status}", meta)
        if 500 <= status <= 599:
            return CreateAttemptResult(CreateAttemptKind.MANUAL_REVIEW, status, None, "HTTP_5XX_AMBIGUOUS", meta)
        if status in {200, 201}:
            try:
                doc_id = self._parser.parse_document_id(response)
            except Exception as exc:
                return CreateAttemptResult(CreateAttemptKind.MANUAL_REVIEW, status, None,
                    f"CREATE_RESPONSE_PARSER_ERROR:{type(exc).__name__}", {**meta, "parser_contract": self._parser.contract_name})
            if not doc_id:
                return CreateAttemptResult(CreateAttemptKind.MANUAL_REVIEW, status, None,
                    "CREATE_RESPONSE_CONTRACT_UNCONFIRMED", {**meta, "parser_contract": self._parser.contract_name})
            return CreateAttemptResult(CreateAttemptKind.ACCEPTED, status, doc_id,
                "ASYNC_DOCUMENT_ACCEPTED", {**meta, "parser_contract": self._parser.contract_name})
        return CreateAttemptResult(CreateAttemptKind.MANUAL_REVIEW, status, None, "UNEXPECTED_CREATE_HTTP_STATUS", meta)

    def poll(self, doc_id: str, *, bearer_token: str) -> PollResult:
        if not self.write_enabled:
            raise ProductionWriteDisabled("True API production write/polling is disabled")
        if not doc_id or not bearer_token:
            raise ValueError("doc_id and bearer token are required")
        response = self._transport.request(method="GET",
            path=f"/api/v4/true-api/doc/{quote(doc_id, safe='')}/info",
            headers={"Authorization": f"Bearer {bearer_token}"}, body=None)
        meta = _safe_response_meta(response)
        if response.status_code != 200:
            return PollResult(PollClassification.MANUAL_REVIEW, None, "POLL_HTTP_ERROR", response.status_code, meta)
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except Exception:
            return PollResult(PollClassification.MANUAL_REVIEW, None, "POLL_RESPONSE_NOT_JSON", response.status_code, meta)
        status = payload.get("status") if isinstance(payload, dict) else None
        if not isinstance(status, str):
            return PollResult(PollClassification.MANUAL_REVIEW, None, "POLL_STATUS_MISSING", response.status_code, meta)
        if status in {"IN_PROGRESS", "WAIT_FOR_CONTINUATION"}:
            cls = PollClassification.INTERMEDIATE
        elif status == "CHECKED_OK":
            cls = PollClassification.TERMINAL_SUCCESS
        elif status in {"CHECKED_NOT_OK", "PARSE_ERROR", "PROCESSING_ERROR"}:
            cls = PollClassification.TERMINAL_FAILURE
        else:
            cls = PollClassification.MANUAL_REVIEW
        return PollResult(cls, status, "POLL_STATUS_" + status, response.status_code, meta)


class P0WritePipeline:
    def __init__(self, store: WritePipelineStore, *, builder: P0ExactDocumentBuilder | None = None,
                 true_api: TrueApiWriteAdapter | None = None, clock: Callable[[], datetime] = _utc_now) -> None:
        self.store = store
        self.builder = builder or P0ExactDocumentBuilder(clock=clock)
        self.true_api = true_api
        self._clock = clock

    def prepare(self, *, source_event_id: str, decision: Decision, operation_reason: str,
                expected_inn: str, document_body: Mapping[str, Any]) -> PipelineOperation:
        prepared = self.builder.prepare(source_event_id=source_event_id, decision=decision,
            operation_reason=operation_reason, expected_inn=expected_inn, document_body=document_body)
        candidate = PipelineOperation.from_prepared(prepared)
        stored, created = self.store.create_or_get_operation(candidate)
        if not created:
            if stored.document_sha256 != candidate.document_sha256:
                raise IdempotencyConflict("same business operation fingerprint already exists with different document bytes")
            return stored
        self.store.append_audit(AuditTransition(candidate.operation_id, "PREPARED", None,
            WriteState.PREPARED.value, self._clock(), {"document_type": candidate.document_type, "pg": candidate.pg}))
        return candidate

    def create_signing_request(self, operation_id: str) -> SigningRequest:
        op = self._require_operation(operation_id)
        self._validate_whitelist(op)
        if op.state is WriteState.AWAITING_SIGNATURE:
            record = self.store.get_signing_request_for_operation(operation_id)
            if record is None:
                raise StoreConflict("operation awaits signature but signing request is missing")
            return self._contract(record, op)
        if op.state is not WriteState.PREPARED:
            raise InvalidStateTransition(f"cannot request signature from state {op.state.value}")
        record, _ = self.store.get_or_create_signing_request(SigningRequestRecord(
            str(uuid4()), operation_id, SigningRequestStatus.PENDING, self._clock()))
        old = op.state
        op.state = WriteState.AWAITING_SIGNATURE
        self.store.compare_and_save_operation(op, expected_state=old)
        self._audit(op, old, "SIGNING_REQUEST_CREATED")
        return self._contract(record, op)

    def pending_signing_requests(self, *, limit: int = 50) -> list[SigningRequest]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        out = []
        for record in self.store.list_pending_signing_requests(limit=limit):
            op = self._require_operation(record.operation_id)
            if op.state is WriteState.AWAITING_SIGNATURE:
                self._validate_whitelist(op)
                out.append(self._contract(record, op))
        return out

    def accept_signature(self, response: SigningResponse) -> PipelineOperation:
        op = self._require_operation(response.operation_id)
        self._validate_whitelist(op)
        if response.document_sha256 != op.document_sha256:
            raise SignatureRejected("document_sha256 does not match prepared immutable document")
        if response.certificate.certificate_inn != op.expected_inn:
            raise SignatureRejected("certificate INN does not match operation expected_inn")
        normalized = _normalize_signature(response.signature_base64)
        signature_sha256 = hashlib.sha256(normalized.encode("ascii")).hexdigest()
        if op.signature_base64 is not None:
            if op.signature_base64 == normalized and op.signature_sha256 == signature_sha256:
                return op
            raise SignatureRejected("operation already has a different signature")
        if op.state is not WriteState.AWAITING_SIGNATURE:
            raise InvalidStateTransition(f"cannot accept signature in state {op.state.value}")
        req = self.store.get_signing_request_for_operation(op.operation_id)
        if req is None or req.status is not SigningRequestStatus.PENDING:
            raise SignatureRejected("no pending signing request for operation")
        old = op.state
        op.signature_base64 = normalized
        op.signature_sha256 = signature_sha256
        op.certificate_thumbprint = response.certificate.certificate_thumbprint
        op.certificate_subject = response.certificate.certificate_subject
        op.certificate_inn = response.certificate.certificate_inn
        op.certificate_valid_from = response.certificate.certificate_valid_from
        op.certificate_valid_to = response.certificate.certificate_valid_to
        op.signed_at = self._clock()
        op.state = WriteState.SIGNED
        self.store.compare_and_save_operation(op, expected_state=old)
        req_old = req.status
        req.status = SigningRequestStatus.FULFILLED
        req.fulfilled_at = op.signed_at
        self.store.compare_and_save_signing_request(req, expected_status=req_old)
        self._audit(op, old, "SIGNATURE_ACCEPTED", {"certificate_inn_match": True})
        return op

    def submit(self, operation_id: str, *, bearer_token: str) -> PipelineOperation:
        op = self._require_operation(operation_id)
        self._validate_whitelist(op)
        if op.source_decision not in {Decision.READY_TO_WITHDRAW.value, Decision.READY_TO_RETURN.value}:
            raise InvalidStateTransition("only approved READY decisions may be submitted")
        if self.true_api is None or not self.true_api.write_enabled:
            raise ProductionWriteDisabled("production True API write remains disabled")
        if op.state is not WriteState.SIGNED:
            if op.state in {WriteState.SUBMITTING, WriteState.SUBMITTED, WriteState.PROCESSING,
                            WriteState.SUCCEEDED, WriteState.RECONCILIATION_REQUIRED}:
                raise DuplicateSubmitBlocked(f"second True API create blocked from state {op.state.value}")
            raise InvalidStateTransition(f"cannot submit from state {op.state.value}")
        old = op.state
        op.state = WriteState.SUBMITTING
        op.submit_started_at = self._clock()
        self.store.compare_and_save_operation(op, expected_state=old)
        self._audit(op, old, "SUBMITTING")
        result = self.true_api.create(op, bearer_token=bearer_token)
        op = self._require_operation(operation_id)
        if op.state is not WriteState.SUBMITTING:
            raise StoreConflict("operation state changed during submit")
        op.last_http_status = result.http_status
        op.last_response_meta = dict(result.safe_response_meta)
        old = op.state
        if result.kind is CreateAttemptKind.ACCEPTED:
            op.doc_id = result.doc_id
            op.submitted_at = self._clock()
            op.state = WriteState.SUBMITTED
            self.store.compare_and_save_operation(op, expected_state=old)
            self._audit(op, old, "ASYNC_DOCUMENT_ACCEPTED", {"http_status": result.http_status})
            return op
        op.state = WriteState.FAILED if result.kind is CreateAttemptKind.IMMEDIATE_FAILURE else WriteState.MANUAL_REVIEW
        op.terminal_at = self._clock()
        self.store.compare_and_save_operation(op, expected_state=old)
        self._audit(op, old, result.reason, {"http_status": result.http_status})
        return op

    def poll(self, operation_id: str, *, bearer_token: str) -> PipelineOperation:
        op = self._require_operation(operation_id)
        if self.true_api is None or not self.true_api.write_enabled:
            raise ProductionWriteDisabled("production True API write/polling remains disabled")
        if op.state not in {WriteState.SUBMITTED, WriteState.PROCESSING} or not op.doc_id:
            raise InvalidStateTransition(f"cannot poll from state {op.state.value}")
        result = self.true_api.poll(op.doc_id, bearer_token=bearer_token)
        op = self._require_operation(operation_id)
        old = op.state
        if old not in {WriteState.SUBMITTED, WriteState.PROCESSING}:
            raise StoreConflict("operation state changed during polling")
        op.last_http_status = result.http_status
        op.last_response_meta = dict(result.safe_response_meta)
        op.last_poll_status = result.status
        if result.classification is PollClassification.INTERMEDIATE:
            op.state = WriteState.PROCESSING
        elif result.classification is PollClassification.TERMINAL_FAILURE:
            op.state = WriteState.FAILED; op.terminal_at = self._clock()
        elif result.classification is PollClassification.MANUAL_REVIEW:
            op.state = WriteState.MANUAL_REVIEW; op.terminal_at = self._clock()
        else:
            op.state = WriteState.SUCCEEDED; op.terminal_at = self._clock()
        self.store.compare_and_save_operation(op, expected_state=old)
        self._audit(op, old, result.reason)
        if result.classification is not PollClassification.TERMINAL_SUCCESS:
            return op
        op = self._require_operation(operation_id)
        old = op.state
        op.state = WriteState.RECONCILIATION_REQUIRED
        op.reconciliation_required = True
        self.store.compare_and_save_operation(op, expected_state=old)
        self._audit(op, old, "RECONCILIATION_REQUIRED")
        return op

    def _require_operation(self, operation_id: str) -> PipelineOperation:
        op = self.store.get_operation(operation_id)
        if op is None:
            raise OperationNotFound(operation_id)
        return op

    @staticmethod
    def _validate_whitelist(op: PipelineOperation) -> None:
        if op.pg != P0_PG:
            raise UnsupportedP0Operation("P0 signing/submission is restricted to pg=lp")
        if op.document_type not in SUPPORTED_DOCUMENT_TYPES:
            raise UnsupportedP0Operation("unsupported P0 document_type")

    @staticmethod
    def _contract(record: SigningRequestRecord, op: PipelineOperation) -> SigningRequest:
        return SigningRequest(record.request_id, op.operation_id, op.document_type, op.pg,
            op.expected_inn, op.document_sha256, op.product_document_base64)

    def _audit(self, op: PipelineOperation, old: WriteState, action: str,
               metadata: dict[str, Any] | None = None) -> None:
        self.store.append_audit(AuditTransition(op.operation_id, action, old.value,
            op.state.value, self._clock(), dict(metadata or {})))
