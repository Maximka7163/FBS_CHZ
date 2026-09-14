from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping, Protocol

from .models import Decision, canonical_json, utc_now


ALLOWED_DOCUMENT_TYPES = frozenset({"LK_RECEIPT", "LP_RETURN"})
ALLOWED_PRODUCT_GROUP = "lp"

_DECISION_DOCUMENT = {
    Decision.READY_TO_WITHDRAW: ("LK_RECEIPT", "DISTANCE"),
    Decision.READY_TO_RETURN: ("LP_RETURN", "REMOTE_SALE_RETURN"),
}


class WriteState(StrEnum):
    PREPARED = "PREPARED"
    AWAITING_SIGNATURE = "AWAITING_SIGNATURE"
    SIGNED = "SIGNED"
    SUBMITTING = "SUBMITTING"
    SUBMITTED = "SUBMITTED"
    PROCESSING = "PROCESSING"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"


class PollClassification(StrEnum):
    INTERMEDIATE = "INTERMEDIATE"
    TERMINAL_SUCCESS = "TERMINAL_SUCCESS"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class CreateCategory(StrEnum):
    SUCCESS_WITH_ID = "SUCCESS_WITH_ID"
    SUCCESS_CONTRACT_UNCONFIRMED = "SUCCESS_CONTRACT_UNCONFIRMED"
    BAD_REQUEST = "BAD_REQUEST"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    UNPROCESSABLE = "UNPROCESSABLE"
    SERVER_ERROR = "SERVER_ERROR"
    HTTP_ERROR = "HTTP_ERROR"


class WritePipelineError(RuntimeError):
    pass


class ProductionWriteDisabled(WritePipelineError):
    pass


class InvalidWriteOperation(WritePipelineError):
    pass


class ReplayConflict(WritePipelineError):
    pass


class DuplicateSubmitBlocked(WritePipelineError):
    pass


@dataclass(frozen=True, slots=True)
class ExactDocument:
    payload: bytes
    sha256: str
    product_document_base64: str

    @property
    def bytes_for_signature(self) -> bytes:
        return self.payload


class ExactDocumentBuilder:
    """Freeze the exact UTF-8 bytes once. Submission never serializes them again."""

    @staticmethod
    def from_json_value(value: Mapping[str, Any]) -> ExactDocument:
        payload = canonical_json(value).encode("utf-8")
        return ExactDocumentBuilder.from_utf8_json_bytes(payload)

    @staticmethod
    def from_utf8_json_bytes(payload: bytes) -> ExactDocument:
        if not isinstance(payload, bytes) or not payload:
            raise ValueError("document payload must be non-empty bytes")
        try:
            text = payload.decode("utf-8")
            parsed = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("document payload must be valid UTF-8 JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("document payload JSON root must be an object")
        encoded = base64.b64encode(payload).decode("ascii")
        return ExactDocument(
            payload=payload,
            sha256=hashlib.sha256(payload).hexdigest(),
            product_document_base64=encoded,
        )


@dataclass(frozen=True, slots=True)
class SigningRequest:
    operation_id: str
    document_type: str
    pg: str
    expected_inn: str
    document_sha256: str
    product_document_base64: str


@dataclass(frozen=True, slots=True)
class SigningResponse:
    operation_id: str
    document_sha256: str
    signature_base64: str
    certificate_thumbprint: str | None = None
    certificate_subject: str | None = None
    certificate_inn: str | None = None
    certificate_valid_from: str | None = None
    certificate_valid_to: str | None = None


@dataclass(frozen=True, slots=True)
class OperationRecord:
    operation_id: str
    business_fingerprint: str
    event_id: str
    decision: Decision
    document_type: str
    operation_reason: str
    pg: str
    expected_inn: str
    document_sha256: str
    product_document_base64: str
    prepared_at: str
    state: WriteState
    signature_base64: str | None
    document_id: str | None


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status_code: int
    body: bytes = b""
    headers: Mapping[str, str] | None = None


class HttpTransport(Protocol):
    def post_json(
        self, url: str, *, headers: Mapping[str, str], body: Mapping[str, str]
    ) -> HttpResponse:
        ...

    def get(self, url: str, *, headers: Mapping[str, str]) -> HttpResponse:
        ...


class SuccessDocumentIdParser(Protocol):
    def parse_document_id(self, response: HttpResponse) -> str | None:
        ...


class UnconfirmedSuccessEnvelopeParser:
    """Fail closed until runtime contract testing confirms the success envelope."""

    def parse_document_id(self, response: HttpResponse) -> str | None:
        return None


class PollStatusParser(Protocol):
    def parse_status(self, response: HttpResponse) -> str | None:
        ...


class UnconfirmedPollEnvelopeParser:
    def parse_status(self, response: HttpResponse) -> str | None:
        return None


@dataclass(frozen=True, slots=True)
class CreateResult:
    category: CreateCategory
    http_status: int
    document_id: str | None
    body_sha256: str
    content_type: str | None


@dataclass(frozen=True, slots=True)
class PollResult:
    http_status: int
    raw_status: str | None
    body_sha256: str


def _validate_base64_ascii(value: str, *, label: str) -> str:
    if not value or "\r" in value or "\n" in value:
        raise ValueError(f"{label} must be non-empty Base64 without CR/LF")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is not valid Base64") from exc
    if not raw:
        raise ValueError(f"{label} decodes to empty bytes")
    return base64.b64encode(raw).decode("ascii")


def _safe_document_id(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("document id parser must return str or None")
    value = value.strip()
    if not value or len(value) > 512 or any(ord(ch) < 32 for ch in value):
        raise ValueError("unsafe document identifier from parser")
    return value


class TrueApiWriteAdapter:
    CREATE_PATH = "/api/v3/true-api/lk/documents/create?pg=lp"

    def __init__(
        self,
        *,
        base_url: str,
        authorization: str,
        transport: HttpTransport,
        success_parser: SuccessDocumentIdParser | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._authorization = authorization
        self._transport = transport
        self._success_parser = success_parser or UnconfirmedSuccessEnvelopeParser()

    def create(
        self,
        *,
        document_type: str,
        product_document_base64: str,
        signature_base64: str,
    ) -> CreateResult:
        if document_type not in ALLOWED_DOCUMENT_TYPES:
            raise InvalidWriteOperation("unsupported document_type")
        product_document_base64 = _validate_base64_ascii(
            product_document_base64, label="product_document"
        )
        signature_base64 = _validate_base64_ascii(
            signature_base64, label="signature"
        )
        body = {
            "document_format": "MANUAL",
            "product_document": product_document_base64,
            "type": document_type,
            "signature": signature_base64,
        }
        response = self._transport.post_json(
            self._base_url + self.CREATE_PATH,
            headers={
                "Authorization": self._authorization,
                "Content-Type": "application/json",
            },
            body=body,
        )
        body_sha = hashlib.sha256(response.body).hexdigest()
        content_type = None
        if response.headers:
            content_type = response.headers.get("Content-Type") or response.headers.get(
                "content-type"
            )
        if response.status_code in (200, 201):
            document_id = _safe_document_id(
                self._success_parser.parse_document_id(response)
            )
            return CreateResult(
                CreateCategory.SUCCESS_WITH_ID
                if document_id is not None
                else CreateCategory.SUCCESS_CONTRACT_UNCONFIRMED,
                response.status_code,
                document_id,
                body_sha,
                content_type,
            )
        category = {
            400: CreateCategory.BAD_REQUEST,
            401: CreateCategory.UNAUTHORIZED,
            403: CreateCategory.FORBIDDEN,
            422: CreateCategory.UNPROCESSABLE,
        }.get(response.status_code)
        if category is None:
            category = (
                CreateCategory.SERVER_ERROR
                if response.status_code >= 500
                else CreateCategory.HTTP_ERROR
            )
        return CreateResult(
            category, response.status_code, None, body_sha, content_type
        )


class TrueApiPollingAdapter:
    def __init__(
        self,
        *,
        base_url: str,
        authorization: str,
        transport: HttpTransport,
        status_parser: PollStatusParser | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._authorization = authorization
        self._transport = transport
        self._status_parser = status_parser or UnconfirmedPollEnvelopeParser()

    def poll(self, document_id: str) -> PollResult:
        document_id = _safe_document_id(document_id)
        assert document_id is not None
        response = self._transport.get(
            f"{self._base_url}/api/v4/true-api/doc/{document_id}/info",
            headers={"Authorization": self._authorization},
        )
        status = self._status_parser.parse_status(response)
        if status is not None and not isinstance(status, str):
            raise TypeError("poll status parser must return str or None")
        return PollResult(
            response.status_code,
            status.strip() if isinstance(status, str) else None,
            hashlib.sha256(response.body).hexdigest(),
        )


def classify_poll_status(status: str | None) -> PollClassification:
    if status in {"IN_PROGRESS", "WAIT_FOR_CONTINUATION"}:
        return PollClassification.INTERMEDIATE
    if status == "CHECKED_OK":
        return PollClassification.TERMINAL_SUCCESS
    if status in {"CHECKED_NOT_OK", "PARSE_ERROR", "PROCESSING_ERROR"}:
        return PollClassification.TERMINAL_FAILURE
    return PollClassification.MANUAL_REVIEW


WRITE_SCHEMA = """
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS write_operations (
    operation_id TEXT PRIMARY KEY,
    business_fingerprint TEXT NOT NULL UNIQUE,
    event_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('READY_TO_WITHDRAW','READY_TO_RETURN')),
    document_type TEXT NOT NULL CHECK (document_type IN ('LK_RECEIPT','LP_RETURN')),
    operation_reason TEXT NOT NULL CHECK (
        operation_reason IN ('DISTANCE','REMOTE_SALE_RETURN')
    ),
    pg TEXT NOT NULL CHECK (pg = 'lp'),
    expected_inn TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    product_document_base64 TEXT NOT NULL,
    prepared_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'PREPARED','AWAITING_SIGNATURE','SIGNED','SUBMITTING','SUBMITTED',
        'PROCESSING','RECONCILIATION_REQUIRED','SUCCEEDED','FAILED',
        'MANUAL_REVIEW','ERROR'
    )),
    signature_base64 TEXT,
    certificate_thumbprint TEXT,
    certificate_subject TEXT,
    certificate_inn TEXT,
    certificate_valid_from TEXT,
    certificate_valid_to TEXT,
    document_id TEXT UNIQUE,
    submit_http_status INTEGER,
    submit_category TEXT,
    submit_body_sha256 TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS write_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS write_audit_no_update
BEFORE UPDATE ON write_audit
BEGIN SELECT RAISE(ABORT, 'write_audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS write_audit_no_delete
BEFORE DELETE ON write_audit
BEGIN SELECT RAISE(ABORT, 'write_audit is append-only'); END;
COMMIT;
"""


class WriteOperationStore:
    """Durable write outbox/state store. It does not contain secrets or key material."""

    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(
            str(path), timeout=10, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout = 10000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(WRITE_SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "WriteOperationStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _audit(
        self,
        operation_id: str,
        action: str,
        *,
        from_state: WriteState | None = None,
        to_state: WriteState | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self._connection.execute(
            """INSERT INTO write_audit
            (operation_id, action, from_state, to_state, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                operation_id,
                action,
                from_state.value if from_state else None,
                to_state.value if to_state else None,
                canonical_json(dict(details or {})),
                utc_now(),
            ),
        )

    def _row(self, operation_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM write_operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"operation not found: {operation_id}")
        return row

    @staticmethod
    def _record(row: sqlite3.Row) -> OperationRecord:
        return OperationRecord(
            operation_id=row["operation_id"],
            business_fingerprint=row["business_fingerprint"],
            event_id=row["event_id"],
            decision=Decision(row["decision"]),
            document_type=row["document_type"],
            operation_reason=row["operation_reason"],
            pg=row["pg"],
            expected_inn=row["expected_inn"],
            document_sha256=row["document_sha256"],
            product_document_base64=row["product_document_base64"],
            prepared_at=row["prepared_at"],
            state=WriteState(row["state"]),
            signature_base64=row["signature_base64"],
            document_id=row["document_id"],
        )

    def get(self, operation_id: str) -> OperationRecord:
        return self._record(self._row(operation_id))

    def _transition(
        self,
        operation_id: str,
        *,
        expected: set[WriteState],
        target: WriteState,
        action: str,
        details: Mapping[str, Any] | None = None,
    ) -> OperationRecord:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._row(operation_id)
            current = WriteState(row["state"])
            if current not in expected:
                raise InvalidWriteOperation(
                    f"{action} not allowed from state {current.value}"
                )
            self._connection.execute(
                "UPDATE write_operations SET state = ?, updated_at = ? WHERE operation_id = ?",
                (target.value, utc_now(), operation_id),
            )
            self._audit(
                operation_id,
                action,
                from_state=current,
                to_state=target,
                details=details,
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self.get(operation_id)

    def prepare(
        self,
        *,
        event_id: str,
        decision: Decision,
        document_type: str,
        operation_reason: str,
        pg: str,
        expected_inn: str,
        document: ExactDocument,
    ) -> OperationRecord:
        if decision not in _DECISION_DOCUMENT:
            raise InvalidWriteOperation("control decision is not approved for write")
        expected_type, expected_reason = _DECISION_DOCUMENT[decision]
        if document_type != expected_type or operation_reason != expected_reason:
            raise InvalidWriteOperation("decision/document mapping mismatch")
        if document_type not in ALLOWED_DOCUMENT_TYPES:
            raise InvalidWriteOperation("unsupported document_type")
        if pg != ALLOWED_PRODUCT_GROUP:
            raise InvalidWriteOperation("wrong product group")
        if not expected_inn:
            raise InvalidWriteOperation("expected_inn is required")
        decoded = base64.b64decode(document.product_document_base64, validate=True)
        if decoded != document.bytes_for_signature:
            raise InvalidWriteOperation(
                "bytes_for_signature != Base64Decode(product_document)"
            )
        if hashlib.sha256(decoded).hexdigest() != document.sha256:
            raise InvalidWriteOperation("document hash mismatch")
        fingerprint_source = {
            "event_id": event_id,
            "decision": decision.value,
            "document_type": document_type,
            "operation_reason": operation_reason,
            "pg": pg,
        }
        fingerprint = hashlib.sha256(
            ("wb-fbs-write:v1:" + canonical_json(fingerprint_source)).encode("utf-8")
        ).hexdigest()
        operation_id = "op_" + fingerprint[:32]
        prepared_at = utc_now()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._connection.execute(
                "SELECT * FROM write_operations WHERE business_fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if existing is not None:
                existing_record = self._record(existing)
                immutable_matches = (
                    existing_record.document_sha256 == document.sha256
                    and existing_record.product_document_base64
                    == document.product_document_base64
                    and existing_record.expected_inn == expected_inn
                )
                if not immutable_matches:
                    raise ReplayConflict(
                        "same business operation has different immutable document data"
                    )
                self._audit(
                    existing_record.operation_id,
                    "PREPARE_REPLAY_IDEMPOTENT",
                    details={"document_sha256": document.sha256},
                )
                self._connection.commit()
                return existing_record
            self._connection.execute(
                """INSERT INTO write_operations (
                    operation_id, business_fingerprint, event_id, decision,
                    document_type, operation_reason, pg, expected_inn,
                    document_sha256, product_document_base64, prepared_at, state,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    operation_id,
                    fingerprint,
                    event_id,
                    decision.value,
                    document_type,
                    operation_reason,
                    pg,
                    expected_inn,
                    document.sha256,
                    document.product_document_base64,
                    prepared_at,
                    WriteState.PREPARED.value,
                    prepared_at,
                ),
            )
            self._audit(
                operation_id,
                "OPERATION_PREPARED",
                to_state=WriteState.PREPARED,
                details={
                    "document_type": document_type,
                    "pg": pg,
                    "document_sha256": document.sha256,
                },
            )
            self._connection.execute(
                "UPDATE write_operations SET state = ?, updated_at = ? WHERE operation_id = ?",
                (WriteState.AWAITING_SIGNATURE.value, utc_now(), operation_id),
            )
            self._audit(
                operation_id,
                "SIGNING_REQUEST_PENDING",
                from_state=WriteState.PREPARED,
                to_state=WriteState.AWAITING_SIGNATURE,
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self.get(operation_id)

    def signing_request(self, operation_id: str) -> SigningRequest:
        operation = self.get(operation_id)
        if operation.state is not WriteState.AWAITING_SIGNATURE:
            raise InvalidWriteOperation(
                f"signing request unavailable from state {operation.state.value}"
            )
        if operation.document_type not in ALLOWED_DOCUMENT_TYPES or operation.pg != "lp":
            raise InvalidWriteOperation("operation is outside signing whitelist")
        return SigningRequest(
            operation.operation_id,
            operation.document_type,
            operation.pg,
            operation.expected_inn,
            operation.document_sha256,
            operation.product_document_base64,
        )

    def accept_signature(
        self, response: SigningResponse, *, own_inn: str
    ) -> OperationRecord:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._row(response.operation_id)
            op = self._record(row)
            if op.document_sha256 != response.document_sha256:
                raise InvalidWriteOperation("document_sha256 mismatch")
            if op.document_type not in ALLOWED_DOCUMENT_TYPES:
                raise InvalidWriteOperation("unsupported document_type")
            if op.pg != ALLOWED_PRODUCT_GROUP:
                raise InvalidWriteOperation("wrong product group")
            if op.expected_inn != own_inn:
                raise InvalidWriteOperation("expected_inn mismatch")
            if response.certificate_inn and response.certificate_inn != op.expected_inn:
                raise InvalidWriteOperation("certificate INN mismatch")
            normalized_signature = _validate_base64_ascii(
                response.signature_base64, label="signature"
            )
            if op.state is not WriteState.AWAITING_SIGNATURE:
                if (
                    row["signature_base64"] == normalized_signature
                    and op.state
                    in {
                        WriteState.SIGNED,
                        WriteState.SUBMITTING,
                        WriteState.SUBMITTED,
                        WriteState.PROCESSING,
                        WriteState.RECONCILIATION_REQUIRED,
                        WriteState.SUCCEEDED,
                        WriteState.FAILED,
                        WriteState.MANUAL_REVIEW,
                    }
                ):
                    self._audit(
                        op.operation_id,
                        "SIGNATURE_REPLAY_IDEMPOTENT",
                        details={"document_sha256": op.document_sha256},
                    )
                    self._connection.commit()
                    return op
                raise InvalidWriteOperation(
                    f"signature not accepted from state {op.state.value}"
                )
            self._connection.execute(
                """UPDATE write_operations SET
                    signature_base64 = ?,
                    certificate_thumbprint = ?,
                    certificate_subject = ?,
                    certificate_inn = ?,
                    certificate_valid_from = ?,
                    certificate_valid_to = ?,
                    state = ?,
                    updated_at = ?
                WHERE operation_id = ?""",
                (
                    normalized_signature,
                    response.certificate_thumbprint,
                    response.certificate_subject,
                    response.certificate_inn,
                    response.certificate_valid_from,
                    response.certificate_valid_to,
                    WriteState.SIGNED.value,
                    utc_now(),
                    op.operation_id,
                ),
            )
            self._audit(
                op.operation_id,
                "SIGNATURE_ACCEPTED",
                from_state=WriteState.AWAITING_SIGNATURE,
                to_state=WriteState.SIGNED,
                details={
                    "document_sha256": op.document_sha256,
                    "certificate_thumbprint": response.certificate_thumbprint,
                    "certificate_inn": response.certificate_inn,
                },
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self.get(response.operation_id)

    def reserve_submit(self, operation_id: str) -> OperationRecord:
        op = self.get(operation_id)
        if op.state is not WriteState.SIGNED:
            if op.state in {
                WriteState.SUBMITTING,
                WriteState.SUBMITTED,
                WriteState.PROCESSING,
                WriteState.RECONCILIATION_REQUIRED,
                WriteState.SUCCEEDED,
            }:
                raise DuplicateSubmitBlocked("second True API create is prohibited")
            raise InvalidWriteOperation(
                f"submit not allowed from state {op.state.value}"
            )
        if not op.signature_base64:
            raise InvalidWriteOperation("signature missing")
        return self._transition(
            operation_id,
            expected={WriteState.SIGNED},
            target=WriteState.SUBMITTING,
            action="SUBMIT_RESERVED",
        )

    def complete_submit(
        self, operation_id: str, result: CreateResult
    ) -> OperationRecord:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._row(operation_id)
            current = WriteState(row["state"])
            if current is not WriteState.SUBMITTING:
                raise InvalidWriteOperation(
                    f"submit result not allowed from state {current.value}"
                )
            if result.category is CreateCategory.SUCCESS_WITH_ID:
                if not result.document_id:
                    raise InvalidWriteOperation("success parser returned no document id")
                target = WriteState.SUBMITTED
            elif result.category is CreateCategory.SERVER_ERROR:
                target = WriteState.MANUAL_REVIEW
            elif result.category is CreateCategory.SUCCESS_CONTRACT_UNCONFIRMED:
                target = WriteState.MANUAL_REVIEW
            else:
                target = WriteState.FAILED
            self._connection.execute(
                """UPDATE write_operations SET
                    state = ?, document_id = ?, submit_http_status = ?,
                    submit_category = ?, submit_body_sha256 = ?, updated_at = ?
                WHERE operation_id = ?""",
                (
                    target.value,
                    result.document_id if target is WriteState.SUBMITTED else None,
                    result.http_status,
                    result.category.value,
                    result.body_sha256,
                    utc_now(),
                    operation_id,
                ),
            )
            self._audit(
                operation_id,
                "SUBMIT_RESULT",
                from_state=WriteState.SUBMITTING,
                to_state=target,
                details={
                    "http_status": result.http_status,
                    "category": result.category.value,
                    "body_sha256": result.body_sha256,
                    "content_type": result.content_type,
                    "document_id_present": result.document_id is not None,
                },
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return self.get(operation_id)

    def mark_submit_ambiguous(
        self, operation_id: str, *, error_type: str
    ) -> OperationRecord:
        return self._transition(
            operation_id,
            expected={WriteState.SUBMITTING},
            target=WriteState.MANUAL_REVIEW,
            action="SUBMIT_TRANSPORT_AMBIGUOUS",
            details={"error_type": error_type[:200]},
        )

    def mark_manual_review(
        self, operation_id: str, *, reason: str
    ) -> OperationRecord:
        return self._transition(
            operation_id,
            expected={
                WriteState.AWAITING_SIGNATURE,
                WriteState.SIGNED,
                WriteState.SUBMITTING,
                WriteState.SUBMITTED,
                WriteState.PROCESSING,
                WriteState.RECONCILIATION_REQUIRED,
            },
            target=WriteState.MANUAL_REVIEW,
            action="MANUAL_REVIEW_REQUIRED",
            details={"reason": reason[:500]},
        )

    def mark_error(
        self, operation_id: str, *, error_type: str
    ) -> OperationRecord:
        return self._transition(
            operation_id,
            expected={WriteState.AWAITING_SIGNATURE, WriteState.SIGNED},
            target=WriteState.ERROR,
            action="PIPELINE_ERROR",
            details={"error_type": error_type[:200]},
        )

    def audit_note(
        self, operation_id: str, action: str, details: Mapping[str, Any]
    ) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._audit(operation_id, action, details=details)
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def apply_poll_status(
        self,
        operation_id: str,
        *,
        status: str | None,
        http_status: int | None = None,
        body_sha256: str | None = None,
    ) -> tuple[OperationRecord, PollClassification]:
        classification = classify_poll_status(status)
        op = self.get(operation_id)
        if op.state not in {WriteState.SUBMITTED, WriteState.PROCESSING}:
            raise InvalidWriteOperation(
                f"polling not allowed from state {op.state.value}"
            )
        details = {
            "remote_status": status,
            "http_status": http_status,
            "body_sha256": body_sha256,
            "classification": classification.value,
        }
        if classification is PollClassification.INTERMEDIATE:
            if op.state is WriteState.SUBMITTED:
                op = self._transition(
                    operation_id,
                    expected={WriteState.SUBMITTED},
                    target=WriteState.PROCESSING,
                    action="POLL_INTERMEDIATE",
                    details=details,
                )
            else:
                self._connection.execute("BEGIN IMMEDIATE")
                try:
                    self._audit(
                        operation_id, "POLL_INTERMEDIATE", details=details
                    )
                    self._connection.commit()
                except BaseException:
                    self._connection.rollback()
                    raise
                op = self.get(operation_id)
            return op, classification
        if classification is PollClassification.TERMINAL_SUCCESS:
            target = WriteState.RECONCILIATION_REQUIRED
        elif classification is PollClassification.TERMINAL_FAILURE:
            target = WriteState.FAILED
        else:
            target = WriteState.MANUAL_REVIEW
        op = self._transition(
            operation_id,
            expected={WriteState.SUBMITTED, WriteState.PROCESSING},
            target=target,
            action="POLL_TERMINAL",
            details=details,
        )
        return op, classification

    def reconciliation_result(
        self,
        operation_id: str,
        *,
        confirmed: bool,
        details: Mapping[str, Any] | None = None,
    ) -> OperationRecord:
        return self._transition(
            operation_id,
            expected={WriteState.RECONCILIATION_REQUIRED},
            target=WriteState.SUCCEEDED if confirmed else WriteState.MANUAL_REVIEW,
            action="RECONCILIATION_RESULT",
            details={"confirmed": confirmed, **dict(details or {})},
        )

    def audit_entries(self, operation_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self._connection.execute(
                "SELECT * FROM write_audit WHERE operation_id = ? ORDER BY id",
                (operation_id,),
            )
        ]


class WritePipeline:
    """Approved WB-FBS decision -> signature -> create -> poll -> reconciliation."""

    def __init__(
        self,
        *,
        store: WriteOperationStore,
        own_inn: str,
        writer: TrueApiWriteAdapter | None = None,
        poller: TrueApiPollingAdapter | None = None,
        true_api_write: bool = False,
    ) -> None:
        self._store = store
        self._own_inn = own_inn
        self._writer = writer
        self._poller = poller
        self.true_api_write = bool(true_api_write)

    def prepare(
        self,
        *,
        event_id: str,
        decision: Decision,
        document_type: str,
        operation_reason: str,
        pg: str,
        expected_inn: str,
        document: ExactDocument,
    ) -> OperationRecord:
        if expected_inn != self._own_inn:
            raise InvalidWriteOperation("wrong expected_inn")
        return self._store.prepare(
            event_id=event_id,
            decision=decision,
            document_type=document_type,
            operation_reason=operation_reason,
            pg=pg,
            expected_inn=expected_inn,
            document=document,
        )

    def pending_signing_request(self, operation_id: str) -> SigningRequest:
        return self._store.signing_request(operation_id)

    def accept_signature(self, response: SigningResponse) -> OperationRecord:
        return self._store.accept_signature(response, own_inn=self._own_inn)

    def submit(self, operation_id: str) -> OperationRecord:
        if not self.true_api_write:
            raise ProductionWriteDisabled("true_api_write=false")
        if self._writer is None:
            raise InvalidWriteOperation("True API write adapter is not configured")
        op = self._store.reserve_submit(operation_id)
        assert op.signature_base64 is not None
        try:
            result = self._writer.create(
                document_type=op.document_type,
                product_document_base64=op.product_document_base64,
                signature_base64=op.signature_base64,
            )
        except Exception as exc:
            return self._store.mark_submit_ambiguous(
                operation_id, error_type=type(exc).__name__
            )
        return self._store.complete_submit(operation_id, result)

    def poll_once(
        self, operation_id: str
    ) -> tuple[OperationRecord, PollClassification]:
        if self._poller is None:
            raise InvalidWriteOperation("True API polling adapter is not configured")
        op = self._store.get(operation_id)
        if not op.document_id:
            raise InvalidWriteOperation("document_id unavailable")
        try:
            result = self._poller.poll(op.document_id)
        except Exception as exc:
            self._store.audit_note(
                operation_id,
                "POLL_TRANSPORT_ERROR",
                {"error_type": type(exc).__name__},
            )
            return self._store.get(operation_id), PollClassification.INTERMEDIATE
        if result.http_status != 200:
            return self._store.apply_poll_status(
                operation_id,
                status=None,
                http_status=result.http_status,
                body_sha256=result.body_sha256,
            )
        return self._store.apply_poll_status(
            operation_id,
            status=result.raw_status,
            http_status=result.http_status,
            body_sha256=result.body_sha256,
        )
