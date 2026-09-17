from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import hashlib
import io
import json
import posixpath
import re
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, quote, urlencode, urlsplit
import zipfile


M7_SOURCE_VERSION = "true-api-v726.0"
M7_PRODUCT_GROUP = "lp"
M7_PRODUCT_GROUP_WIRE_VALUE = 1
EDO_LITE_ANNUAL_OUTGOING_LIMIT = 1000
TRUE_API_ENDPOINT_FORMAT_UKD = "736"
CURRENT_FNS_736_STATUS = "REPEALED"
REPLACEMENT_FNS_ORDER = "ЕД-1-26/29@"
UKD_FORMAT_COMPATIBILITY = "UNRESOLVED"


class EdoLiteContractError(ValueError):
    pass


class EdoLiteSecurityError(EdoLiteContractError):
    pass


class M7SchemaNotEnabled(EdoLiteContractError):
    pass


class M7ReconciliationError(EdoLiteContractError):
    pass


class BlobSource(StrEnum):
    LOCAL_BUILT = "LOCAL_BUILT"
    REMOTE_DRAFT = "REMOTE_DRAFT"
    REMOTE_CONTENT = "REMOTE_CONTENT"


class LocalEdoState(StrEnum):
    LOCAL_FOUNDATION = "LOCAL_FOUNDATION"
    REMOTE_DRAFT_KNOWN = "REMOTE_DRAFT_KNOWN"
    SIGNED_SENT_KNOWN = "SIGNED_SENT_KNOWN"
    COUNTERPARTY_ACTION_REQUIRED = "COUNTERPARTY_ACTION_REQUIRED"
    COUNTERPARTY_COMPLETED = "COUNTERPARTY_COMPLETED"
    COUNTERPARTY_REJECTED = "COUNTERPARTY_REJECTED"
    GIS_SUBMITTING = "GIS_SUBMITTING"
    GIS_SUBMITTED = "GIS_SUBMITTED"
    GIS_PROCESSING = "GIS_PROCESSING"
    GIS_FAILED = "GIS_FAILED"
    GIS_SUCCEEDED = "GIS_SUCCEEDED"
    MARKING_RECONCILED = "MARKING_RECONCILED"
    ANNULMENT_PENDING = "ANNULMENT_PENDING"
    ANNULMENT_GIS_PROCESSING = "ANNULMENT_GIS_PROCESSING"
    ANNULMENT_RECONCILED = "ANNULMENT_RECONCILED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


M7_READ_JOB_TYPES = frozenset({
    "EDO_PARTICIPANT",
    "EDO_OUTGOING_LIST",
    "EDO_INCOMING_LIST",
    "EDO_OUTGOING_CONTENT",
    "EDO_INCOMING_CONTENT",
    "EDO_OUTGOING_PRINT",
    "EDO_INCOMING_PRINT",
    "EDO_OUTGOING_LEGAL_ZIP",
    "EDO_INCOMING_LEGAL_ZIP",
    "EDO_OUTGOING_UNSIGNED_EVENTS",
    "EDO_INCOMING_UNSIGNED_EVENTS",
    "EDO_EVENT_CONTENT",
    "EDO_OUTGOING_RECEIPT",
    "EDO_INCOMING_RECEIPT",
    "EDO_OUTGOING_MCHD",
    "EDO_INCOMING_MCHD",
    "EDO_GIS_PROCESSING",
})


BINARY_EDO_READ_JOB_TYPES = frozenset({
    "EDO_OUTGOING_CONTENT",
    "EDO_INCOMING_CONTENT",
    "EDO_OUTGOING_PRINT",
    "EDO_INCOMING_PRINT",
    "EDO_OUTGOING_LEGAL_ZIP",
    "EDO_INCOMING_LEGAL_ZIP",
    "EDO_EVENT_CONTENT",
})


@dataclass(frozen=True, slots=True)
class EdoReadSpec:
    job_type: str
    method: str
    target: str
    audit_endpoint: str


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EdoLiteContractError(f"{label} must be an object")
    return dict(value)


def opaque_remote_id(value: Any, label: str = "remote_id") -> str:
    if not isinstance(value, str) or not value:
        raise EdoLiteContractError(f"{label} must be a non-empty opaque string")
    if "\x00" in value or len(value) > 2048:
        raise EdoLiteContractError(f"{label} is outside supported opaque-string bounds")
    return value


def _inn(value: Any, label: str = "inn") -> str:
    if not isinstance(value, str) or not value.isdigit() or len(value) not in {10, 12}:
        raise EdoLiteContractError(f"{label} must be 10 or 12 digits")
    return value


def _string(value: Any, label: str, *, max_len: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise EdoLiteContractError(f"{label} must be a non-empty string")
    return value


def _path_id(value: Any, label: str) -> str:
    return quote(opaque_remote_id(value, label), safe="")


def _query(path: str, pairs: Sequence[tuple[str, str]]) -> str:
    return path + ("?" + urlencode(list(pairs)) if pairs else "")


def validate_edo_read_payload(job_type: str, payload: Any) -> dict[str, Any]:
    if job_type not in M7_READ_JOB_TYPES:
        raise EdoLiteContractError("unsupported M7 EDO read job type")
    root = _object(payload, "read_payload")

    if job_type == "EDO_PARTICIPANT":
        if set(root) != {"inn"}:
            raise EdoLiteContractError("EDO_PARTICIPANT requires only inn")
        return {"inn": _inn(root["inn"])}

    if job_type in {"EDO_OUTGOING_LIST", "EDO_INCOMING_LIST"}:
        allowed = {
            "limit", "offset", "created_from", "created_to", "partner_inn", "partner_id",
            "status", "type", "folder", "asc", "product_group",
        }
        unknown = set(root) - allowed
        if unknown:
            raise EdoLiteContractError(f"EDO list has unknown fields: {sorted(unknown)}")
        limit = root.get("limit", 10)
        offset = root.get("offset", 0)
        if type(limit) is not int or limit < 1:
            raise EdoLiteContractError("limit must be a positive integer")
        if type(offset) is not int or offset < 0:
            raise EdoLiteContractError("offset must be a non-negative integer")
        out: dict[str, Any] = {"limit": limit, "offset": offset}
        for key in ("created_from", "created_to"):
            if key in root and root[key] is not None:
                value = root[key]
                if type(value) is not int or value < 0:
                    raise EdoLiteContractError(f"{key} must be a non-negative integer timestamp")
                out[key] = value
        if "partner_id" in root and root["partner_id"] is not None:
            out["partner_id"] = _string(root["partner_id"], "partner_id")
        if "partner_inn" in root and root["partner_inn"] is not None:
            out["partner_inn"] = _inn(root["partner_inn"], "partner_inn")
        if "status" in root and root["status"] is not None:
            status = root["status"]
            if type(status) is not int or status not in KNOWN_EDO_RAW_STATUSES:
                raise EdoLiteContractError("status must be a documented numeric EDO status code")
            out["status"] = status
        if "type" in root and root["type"] is not None:
            document_type = root["type"]
            if type(document_type) is not int or document_type < 0:
                raise EdoLiteContractError("type must be a non-negative integer official document code")
            out["type"] = document_type
        if "folder" in root and root["folder"] is not None:
            folder = root["folder"]
            if type(folder) is not int or not 0 <= folder <= 8:
                raise EdoLiteContractError("folder must be an integer in range 0..8")
            out["folder"] = folder
        asc = root.get("asc", False)
        if type(asc) is not bool:
            raise EdoLiteContractError("asc must be boolean")
        out["asc"] = asc
        if "product_group" in root and root["product_group"] is not None:
            pg = root["product_group"]
            if type(pg) is not int or pg != M7_PRODUCT_GROUP_WIRE_VALUE:
                raise EdoLiteContractError("M7 foundation requires numeric product_group=1 for lp")
            out["product_group"] = pg
        return out

    if job_type in {
        "EDO_OUTGOING_CONTENT", "EDO_INCOMING_CONTENT",
        "EDO_OUTGOING_PRINT", "EDO_INCOMING_PRINT",
        "EDO_OUTGOING_LEGAL_ZIP", "EDO_INCOMING_LEGAL_ZIP",
        "EDO_OUTGOING_MCHD", "EDO_INCOMING_MCHD",
    }:
        if set(root) != {"document_id"}:
            raise EdoLiteContractError(f"{job_type} requires only document_id")
        return {"document_id": opaque_remote_id(root["document_id"], "document_id")}

    if job_type in {"EDO_OUTGOING_UNSIGNED_EVENTS", "EDO_INCOMING_UNSIGNED_EVENTS"}:
        if root:
            raise EdoLiteContractError(f"{job_type} takes no caller-selected fields")
        return {}

    if job_type == "EDO_EVENT_CONTENT":
        if set(root) != {"document_id", "event_id"}:
            raise EdoLiteContractError("EDO_EVENT_CONTENT requires document_id and event_id")
        return {
            "document_id": opaque_remote_id(root["document_id"], "document_id"),
            "event_id": opaque_remote_id(root["event_id"], "event_id"),
        }

    if job_type in {"EDO_OUTGOING_RECEIPT", "EDO_INCOMING_RECEIPT"}:
        if set(root) != {"document_id", "receipt_type"}:
            raise EdoLiteContractError(f"{job_type} requires document_id and receipt_type")
        return {
            "document_id": opaque_remote_id(root["document_id"], "document_id"),
            "receipt_type": _string(root["receipt_type"], "receipt_type", max_len=128),
        }

    if job_type == "EDO_GIS_PROCESSING":
        if set(root) != {"file_id"}:
            raise EdoLiteContractError("EDO_GIS_PROCESSING requires only file_id")
        return {"file_id": opaque_remote_id(root["file_id"], "file_id")}

    raise EdoLiteContractError("unsupported M7 EDO read job type")


def build_edo_read_spec(job_type: str, payload: Mapping[str, Any]) -> EdoReadSpec:
    canonical = validate_edo_read_payload(job_type, dict(payload))
    if canonical != dict(payload):
        raise EdoLiteContractError("M7 read payload must already be canonical")

    if job_type == "EDO_PARTICIPANT":
        return EdoReadSpec(job_type, "GET", f"/api/v4/true-api/edo/inn/{canonical['inn']}", "/api/v4/true-api/edo/inn/{inn}")

    if job_type in {"EDO_OUTGOING_LIST", "EDO_INCOMING_LIST"}:
        direction = "outgoing" if job_type == "EDO_OUTGOING_LIST" else "incoming"
        pairs: list[tuple[str, str]] = [
            ("limit", str(canonical["limit"])),
            ("offset", str(canonical["offset"])),
            ("sortBy", "created_at"),
            ("asc", "true" if canonical["asc"] else "false"),
        ]
        for key in ("created_from", "created_to", "partner_inn", "partner_id", "status", "type", "folder", "product_group"):
            if key in canonical:
                pairs.append((key, str(canonical[key])))
        path = f"/api/v3/true-api/elk/{direction}-documents"
        return EdoReadSpec(job_type, "GET", _query(path, pairs), f"/api/v3/true-api/elk/{direction}-documents")

    direction = "outgoing" if "OUTGOING" in job_type else "incoming"
    if job_type in {"EDO_OUTGOING_CONTENT", "EDO_INCOMING_CONTENT"}:
        did = _path_id(canonical["document_id"], "document_id")
        path = f"/elk/{direction}-documents/{did}/content"
        return EdoReadSpec(job_type, "GET", path, f"/elk/{direction}-documents/{{documentId}}/content")
    if job_type in {"EDO_OUTGOING_PRINT", "EDO_INCOMING_PRINT"}:
        did = _path_id(canonical["document_id"], "document_id")
        path = f"/api/v3/true-api/edo/{direction}-documents/{did}/print"
        return EdoReadSpec(job_type, "GET", path, f"/api/v3/true-api/edo/{direction}-documents/{{doc_id}}/print")
    if job_type in {"EDO_OUTGOING_LEGAL_ZIP", "EDO_INCOMING_LEGAL_ZIP"}:
        did = _path_id(canonical["document_id"], "document_id")
        path = f"/elk/{direction}-documents/{did}"
        return EdoReadSpec(job_type, "GET", path, f"/elk/{direction}-documents/{{documentId}}")
    if job_type in {"EDO_OUTGOING_UNSIGNED_EVENTS", "EDO_INCOMING_UNSIGNED_EVENTS"}:
        path = f"/api/v3/true-api/edo/{direction}-documents/unsigned-events"
        return EdoReadSpec(job_type, "GET", path, f"/api/v3/true-api/edo/{direction}-documents/unsigned-events")
    if job_type == "EDO_EVENT_CONTENT":
        did = _path_id(canonical["document_id"], "document_id")
        eid = _path_id(canonical["event_id"], "event_id")
        path = f"/api/v3/true-api/edo/incoming-documents/{did}/events/{eid}/content"
        return EdoReadSpec(job_type, "GET", path, "/api/v3/true-api/edo/incoming-documents/{doc_id}/events/{event_id}/content")
    if job_type in {"EDO_OUTGOING_RECEIPT", "EDO_INCOMING_RECEIPT"}:
        did = _path_id(canonical["document_id"], "document_id")
        receipt = _path_id(canonical["receipt_type"], "receipt_type")
        path = f"/api/v3/true-api/edo/{direction}-documents/{did}/events/{receipt}"
        return EdoReadSpec(job_type, "GET", path, f"/api/v3/true-api/edo/{direction}-documents/{{doc_id}}/events/{{receiptType}}")
    if job_type in {"EDO_OUTGOING_MCHD", "EDO_INCOMING_MCHD"}:
        did = _path_id(canonical["document_id"], "document_id")
        path = f"/api/v3/true-api/edo/{direction}-documents/{did}/mchd-list"
        return EdoReadSpec(job_type, "GET", path, f"/api/v3/true-api/edo/{direction}-documents/{{doc_id}}/mchd-list")
    if job_type == "EDO_GIS_PROCESSING":
        path = "/documents/edo/tpr/ud"
        return EdoReadSpec(job_type, "GET", _query(path, [("fileId", canonical["file_id"])]), "/documents/edo/tpr/ud?fileId={IdFile}")
    raise EdoLiteContractError("unsupported M7 EDO read job type")


def is_allowed_edo_read_target(spec: EdoReadSpec) -> bool:
    """Verify the final wire target against the exact typed M7 read contract."""
    if spec.job_type not in M7_READ_JOB_TYPES or spec.method != "GET":
        return False
    target = spec.target
    if "://" in target or "\r" in target or "\n" in target or not target.startswith("/"):
        return False
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    path = parsed.path
    query = parse_qs(parsed.query, keep_blank_values=True)
    encoded = r"[^/?#]+"

    if spec.job_type == "EDO_PARTICIPANT":
        return re.fullmatch(r"/api/v4/true-api/edo/inn/\d{10}|/api/v4/true-api/edo/inn/\d{12}", path) is not None and not query

    if spec.job_type in {"EDO_OUTGOING_LIST", "EDO_INCOMING_LIST"}:
        direction = "outgoing" if spec.job_type == "EDO_OUTGOING_LIST" else "incoming"
        if path != f"/api/v3/true-api/elk/{direction}-documents":
            return False
        allowed = {"limit", "offset", "sortBy", "asc", "created_from", "created_to", "partner_inn", "partner_id", "status", "type", "folder", "product_group"}
        if set(query) - allowed:
            return False
        if any(len(values) != 1 for values in query.values()):
            return False
        def one_uint(name: str) -> int | None:
            values = query.get(name)
            if values is None:
                return None
            raw = values[0]
            if re.fullmatch(r"0|[1-9]\d*", raw) is None:
                return -1
            return int(raw)

        limit = one_uint("limit")
        offset = one_uint("offset")
        if limit is None or limit < 1 or offset is None or offset < 0:
            return False
        for name in ("created_from", "created_to"):
            if name in query and one_uint(name) < 0:
                return False
        if "partner_inn" in query and re.fullmatch(r"\d{10}|\d{12}", query["partner_inn"][0]) is None:
            return False
        if "partner_id" in query and not query["partner_id"][0]:
            return False
        if "status" in query:
            status = one_uint("status")
            if status not in KNOWN_EDO_RAW_STATUSES:
                return False
        if "type" in query and one_uint("type") < 0:
            return False
        if "folder" in query:
            folder = one_uint("folder")
            if folder is None or not 0 <= folder <= 8:
                return False
        if "product_group" in query and one_uint("product_group") != M7_PRODUCT_GROUP_WIRE_VALUE:
            return False
        return query.get("sortBy") == ["created_at"] and query.get("asc") in (["true"], ["false"])

    direction = "outgoing" if "OUTGOING" in spec.job_type else "incoming"
    exact_patterns = {
        "EDO_OUTGOING_CONTENT": rf"/elk/outgoing-documents/{encoded}/content",
        "EDO_INCOMING_CONTENT": rf"/elk/incoming-documents/{encoded}/content",
        "EDO_OUTGOING_PRINT": rf"/api/v3/true-api/edo/outgoing-documents/{encoded}/print",
        "EDO_INCOMING_PRINT": rf"/api/v3/true-api/edo/incoming-documents/{encoded}/print",
        "EDO_OUTGOING_LEGAL_ZIP": rf"/elk/outgoing-documents/{encoded}",
        "EDO_INCOMING_LEGAL_ZIP": rf"/elk/incoming-documents/{encoded}",
        "EDO_OUTGOING_UNSIGNED_EVENTS": r"/api/v3/true-api/edo/outgoing-documents/unsigned-events",
        "EDO_INCOMING_UNSIGNED_EVENTS": r"/api/v3/true-api/edo/incoming-documents/unsigned-events",
        "EDO_EVENT_CONTENT": rf"/api/v3/true-api/edo/incoming-documents/{encoded}/events/{encoded}/content",
        "EDO_OUTGOING_RECEIPT": rf"/api/v3/true-api/edo/outgoing-documents/{encoded}/events/{encoded}",
        "EDO_INCOMING_RECEIPT": rf"/api/v3/true-api/edo/incoming-documents/{encoded}/events/{encoded}",
        "EDO_OUTGOING_MCHD": rf"/api/v3/true-api/edo/outgoing-documents/{encoded}/mchd-list",
        "EDO_INCOMING_MCHD": rf"/api/v3/true-api/edo/incoming-documents/{encoded}/mchd-list",
    }
    if spec.job_type in exact_patterns:
        return re.fullmatch(exact_patterns[spec.job_type], path) is not None and not query
    if spec.job_type == "EDO_GIS_PROCESSING":
        return path == "/documents/edo/tpr/ud" and set(query) == {"fileId"} and len(query["fileId"]) == 1 and bool(query["fileId"][0])
    return False


def parse_json_bytes(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EdoLiteContractError("EDO response is not valid UTF-8 JSON") from exc


def capture_edo_read_success(job_type: str, request_payload: Mapping[str, Any], raw: bytes, content_type: str | None) -> dict[str, Any]:
    digest = hashlib.sha256(raw).hexdigest()
    if job_type in BINARY_EDO_READ_JOB_TYPES:
        return {
            "job_type": job_type,
            "content_type": content_type,
            "sha256": digest,
            "raw_base64": base64.b64encode(raw).decode("ascii"),
            "remote_ids": {k: v for k, v in request_payload.items() if k.endswith("_id")},
        }
    parsed = parse_json_bytes(raw)
    return {"job_type": job_type, "content_type": content_type, "sha256": digest, "payload": parsed}


KNOWN_EDO_RAW_STATUSES = frozenset({0, 1, 2, 3, 4, 5, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 41, 42, 43, 44, 61, 62, 63, 64, 65, 66})


@dataclass(frozen=True, slots=True)
class EdoRawStatus:
    raw_numeric: int
    remote_label: str | None
    known: bool
    normalized_local_state: LocalEdoState | None = None


def parse_edo_raw_status(value: Any, remote_label: Any = None) -> EdoRawStatus:
    if type(value) is not int:
        raise EdoLiteContractError("EDO raw status must remain a numeric integer")
    label = None if remote_label is None else _string(remote_label, "remote_label", max_len=1024)
    return EdoRawStatus(value, label, value in KNOWN_EDO_RAW_STATUSES, None)


class GisProcessingState(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"


@dataclass(frozen=True, slots=True)
class GisProcessingResult:
    state: GisProcessingState
    result_doc_id: str | None
    result_doc_date: Any
    source_doc_id: str | None
    source_doc_date: Any
    code: Any
    description: Any
    operations: tuple[Any, ...]
    raw: Mapping[str, Any]


def parse_gis_processing_result(value: Any) -> GisProcessingResult:
    root = _object(value, "gis_processing")
    try:
        state = GisProcessingState(root.get("state"))
    except Exception as exc:
        raise EdoLiteContractError("unknown GIS processing state") from exc
    result_id = root.get("resultDocId")
    source_id = root.get("sourceDocId")
    operations = root.get("operations", [])
    if not isinstance(operations, list):
        raise EdoLiteContractError("GIS operations must be an array")
    return GisProcessingResult(
        state,
        None if result_id is None else opaque_remote_id(result_id, "resultDocId"),
        root.get("resultDocDate"),
        None if source_id is None else opaque_remote_id(source_id, "sourceDocId"),
        root.get("sourceDocDate"),
        root.get("code"),
        root.get("description"),
        tuple(operations),
        dict(root),
    )


MCHD_RAW_STATUSES = frozenset({"ACTIVE", "CREATED", "PROCESSING", "EXPIRED", "REVOKED", "REJECTED", "NONE"})


@dataclass(frozen=True, slots=True)
class ReconciliationEvidence:
    counterparty_completed: bool
    gis_state: GisProcessingState | None
    m1_owner_status_reconciled: bool
    m6_aggregate_reconciled: bool
    counterparty_rejected: bool = False
    raw_edo_status: int | None = None


def final_business_success(evidence: ReconciliationEvidence) -> bool:
    return (
        evidence.counterparty_completed
        and not evidence.counterparty_rejected
        and evidence.gis_state is GisProcessingState.SUCCESS
        and evidence.m1_owner_status_reconciled
        and evidence.m6_aggregate_reconciled
    )


def reconcile_local_state(evidence: ReconciliationEvidence) -> LocalEdoState:
    if evidence.counterparty_rejected:
        return LocalEdoState.COUNTERPARTY_REJECTED
    if evidence.gis_state is GisProcessingState.FAILED:
        return LocalEdoState.GIS_FAILED
    if evidence.gis_state is GisProcessingState.IN_PROGRESS:
        return LocalEdoState.GIS_PROCESSING
    if final_business_success(evidence):
        return LocalEdoState.MARKING_RECONCILED
    if evidence.gis_state is GisProcessingState.SUCCESS:
        return LocalEdoState.GIS_SUCCEEDED
    if evidence.counterparty_completed:
        return LocalEdoState.COUNTERPARTY_COMPLETED
    return LocalEdoState.MANUAL_REVIEW


@dataclass(frozen=True, slots=True)
class M1ReconciliationAdapter:
    fresh_snapshot: bool
    owner_reconciled: bool
    status_reconciled: bool
    status_ex_reconciled: bool

    @property
    def reconciled(self) -> bool:
        return self.fresh_snapshot and self.owner_reconciled and self.status_reconciled and self.status_ex_reconciled


@dataclass(frozen=True, slots=True)
class M6ReconciliationAdapter:
    relation_read_complete: bool
    aggregate_relation_reconciled: bool

    @property
    def reconciled(self) -> bool:
        return self.relation_read_complete and self.aggregate_relation_reconciled


@dataclass(frozen=True, slots=True)
class AnnualQuotaObservation:
    year: int
    local_observed_outgoing_count: int
    last_updated_at: datetime
    source_evidence: str
    authoritative_remote_remaining: None = None

    def __post_init__(self) -> None:
        if not 2000 <= self.year <= 9999:
            raise EdoLiteContractError("quota year is invalid")
        if type(self.local_observed_outgoing_count) is not int or self.local_observed_outgoing_count < 0:
            raise EdoLiteContractError("local observed outgoing count must be non-negative")
        if self.last_updated_at.tzinfo is None:
            raise EdoLiteContractError("quota observation timestamp must include timezone")
        _string(self.source_evidence, "source_evidence", max_len=1024)

    def safe_for_future_batch(self, batch_size: int, *, independent_evidence_confirmed: bool) -> bool:
        if type(batch_size) is not int or batch_size < 1:
            raise EdoLiteContractError("batch_size must be positive")
        if not independent_evidence_confirmed:
            return False
        return self.local_observed_outgoing_count + batch_size <= EDO_LITE_ANNUAL_OUTGOING_LIMIT


@dataclass(frozen=True, slots=True)
class ImmutableDocumentBlob:
    exact_bytes: bytes
    sha256: str
    document_family: str
    schema_identity: str | None
    source: BlobSource
    content_type: str | None = None

    @classmethod
    def capture_remote(
        cls,
        raw: bytes,
        *,
        document_family: str,
        schema_identity: str | None,
        source: BlobSource = BlobSource.REMOTE_CONTENT,
        content_type: str | None = None,
    ) -> "ImmutableDocumentBlob":
        if source not in {BlobSource.REMOTE_CONTENT, BlobSource.REMOTE_DRAFT}:
            raise EdoLiteSecurityError("M7 foundation does not build local XML")
        if not isinstance(raw, bytes):
            raise EdoLiteContractError("exact bytes are required")
        return cls(raw, hashlib.sha256(raw).hexdigest(), _string(document_family, "document_family"), schema_identity, source, content_type)

    def verify(self) -> None:
        if hashlib.sha256(self.exact_bytes).hexdigest() != self.sha256:
            raise EdoLiteSecurityError("immutable blob hash mismatch")


@dataclass(frozen=True, slots=True)
class SchemaDefinition:
    schema_identity: str
    family: str
    official_type_code: str | None
    title_role: str | None
    function: str | None
    official_order: str | None
    artifact_filename: str | None
    artifact_sha256: str | None
    xsd_filename: str | None
    xsd_sha256: str | None
    root: str | None
    target_namespace: str | None
    encoding: str | None
    filename_grammar: str | None
    parent_link_rule: str | None
    marking_capability: str | None
    enabled_for_lp: bool
    production: bool = True
    disabled_reason: str | None = "OFFICIAL_SCHEMA_NOT_PINNED"


def _schema(identity: str, family: str, type_code: str | None, role: str | None = None, function: str | None = None, *, reason: str = "OFFICIAL_SCHEMA_NOT_PINNED") -> SchemaDefinition:
    return SchemaDefinition(identity, family, type_code, role, function, None, None, None, None, None, None, None, None, None, None, None, False, True, reason)


PRODUCTION_SCHEMA_REGISTRY: Mapping[str, SchemaDefinition] = {
    "UPD_970_520_SELLER": _schema("UPD_970_520_SELLER", "UPD", "520", "SELLER", "ДОП"),
    "UPD_970_521_BUYER": _schema("UPD_970_521_BUYER", "UPD", "521", "BUYER", "ДОП"),
    "UPD_970_522_SELLER": _schema("UPD_970_522_SELLER", "UPD", "522", "SELLER", "СЧФ"),
    "UPD_970_524_SELLER": _schema("UPD_970_524_SELLER", "UPD", "524", "SELLER", "СЧФДОП"),
    "UPD_970_525_BUYER": _schema("UPD_970_525_BUYER", "UPD", "525", "BUYER", "СЧФДОП"),
    "UPDI_970_820_SELLER": _schema("UPDI_970_820_SELLER", "UPDI", "820", "SELLER", "ДОП"),
    "UPDI_970_821_BUYER": _schema("UPDI_970_821_BUYER", "UPDI", "821", "BUYER", "ДОП"),
    "UPDI_970_822_SELLER": _schema("UPDI_970_822_SELLER", "UPDI", "822", "SELLER", "СЧФ"),
    "UPDI_970_824_SELLER": _schema("UPDI_970_824_SELLER", "UPDI", "824", "SELLER", "СЧФДОП"),
    "UPDI_970_825_BUYER": _schema("UPDI_970_825_BUYER", "UPDI", "825", "BUYER", "СЧФДОП"),
    "UKD_736_600_SELLER": _schema("UKD_736_600_SELLER", "UKD", "600", "SELLER", "ДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKD_736_601_BUYER": _schema("UKD_736_601_BUYER", "UKD", "601", "BUYER", "ДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKD_736_602_SELLER": _schema("UKD_736_602_SELLER", "UKD", "602", "SELLER", "КСЧФ", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKD_736_604_SELLER": _schema("UKD_736_604_SELLER", "UKD", "604", "SELLER", "КСФДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKD_736_605_BUYER": _schema("UKD_736_605_BUYER", "UKD", "605", "BUYER", "КСФДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKDI_736_700_SELLER": _schema("UKDI_736_700_SELLER", "UKDI", "700", "SELLER", "ДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKDI_736_701_BUYER": _schema("UKDI_736_701_BUYER", "UKDI", "701", "BUYER", "ДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKDI_736_702_SELLER": _schema("UKDI_736_702_SELLER", "UKDI", "702", "SELLER", "КСЧФ", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKDI_736_704_SELLER": _schema("UKDI_736_704_SELLER", "UKDI", "704", "SELLER", "КСФДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "UKDI_736_705_BUYER": _schema("UKDI_736_705_BUYER", "UKDI", "705", "BUYER", "КСФДИС", reason="TRUE_API_FNS_FORMAT_CONFLICT"),
    "DP_UVUTOCH": _schema("DP_UVUTOCH", "SERVICE", None, function="UVTOCH"),
    "DP_PRANNUL": _schema("DP_PRANNUL", "SERVICE", None, function="PRANNUL"),
    "DP_UNISOOBSCH": _schema("DP_UNISOOBSCH", "SERVICE", None, function="UNISOOBSCH"),
}


@dataclass(frozen=True, slots=True)
class MutationCapability:
    name: str
    enabled: bool
    reason: str


_MUTATIONS = (
    "CREATE_UPD_970", "CREATE_UPDI_970", "CREATE_UPDI_970_EXTENDED",
    "CREATE_UKD_736", "CREATE_UKDI_736",
    "CREATE_BUYER_UPD_TITLE_970", "CREATE_BUYER_UPDI_TITLE_970",
    "CREATE_BUYER_UKD_TITLE_736", "CREATE_BUYER_UKDI_TITLE_736",
    "CREATE_UVTOCH", "CREATE_ANNULMENT_PROPOSAL", "ACCEPT_ANNULMENT",
    "REJECT_ANNULMENT", "CREATE_UNIVERSAL_MESSAGE", "SIGN_EDO_EVENT",
)
M7_MUTATION_REGISTRY: Mapping[str, MutationCapability] = {
    name: MutationCapability(name, False, "TRUE_API_FNS_FORMAT_CONFLICT" if "UKD" in name else "OFFICIAL_SCHEMA_NOT_PINNED")
    for name in _MUTATIONS
}


def require_m7_mutation_enabled(name: str) -> MutationCapability:
    capability = M7_MUTATION_REGISTRY.get(name)
    if capability is None:
        raise EdoLiteContractError("unknown M7 mutation capability")
    if not capability.enabled:
        raise M7SchemaNotEnabled(f"M7_SCHEMA_NOT_ENABLED:{capability.reason}")
    return capability


@dataclass(frozen=True, slots=True)
class PinnedSchemaArtifact:
    definition: SchemaDefinition
    xsd_bytes: bytes
    dependency_bytes: Mapping[str, bytes] = field(default_factory=dict)

    def verify(self) -> None:
        if not self.definition.xsd_sha256:
            raise EdoLiteSecurityError("pinned schema checksum is required")
        if hashlib.sha256(self.xsd_bytes).hexdigest() != self.definition.xsd_sha256:
            raise EdoLiteSecurityError("pinned schema checksum mismatch")
        if not self.definition.root or not self.definition.target_namespace:
            raise EdoLiteSecurityError("pinned root and target namespace are required")


class OfflineXmlValidator:
    """Offline-only XSD validator. Caller cannot choose schema path/root/namespace."""

    def __init__(self, artifacts: Mapping[str, PinnedSchemaArtifact] | None = None) -> None:
        self._artifacts = dict(artifacts or {})

    def register_test_only_schema(
        self,
        *,
        schema_identity: str,
        xsd_bytes: bytes,
        expected_sha256: str,
        root: str,
        target_namespace: str,
        dependencies: Mapping[str, bytes] | None = None,
    ) -> None:
        if not schema_identity.startswith("TEST_ONLY_"):
            raise EdoLiteSecurityError("test-only schema identity must be isolated")
        definition = SchemaDefinition(
            schema_identity, "TEST_ONLY", None, None, None, None, None, None,
            f"{schema_identity}.xsd", expected_sha256, root, target_namespace, "UTF-8",
            None, None, None, False, False, "TEST_ONLY_NOT_PRODUCTION_CAPABILITY",
        )
        artifact = PinnedSchemaArtifact(definition, xsd_bytes, dict(dependencies or {}))
        artifact.verify()
        self._artifacts[schema_identity] = artifact

    def validate(self, xml_bytes: bytes, *, schema_identity: str) -> None:
        if not isinstance(xml_bytes, bytes) or not xml_bytes:
            raise EdoLiteContractError("exact XML bytes are required")
        lowered = xml_bytes.lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            raise EdoLiteSecurityError("DTD/entities are forbidden")
        if b"schemalocation" in lowered:
            raise EdoLiteSecurityError("caller-supplied schemaLocation is forbidden")
        artifact = self._artifacts.get(schema_identity)
        if artifact is None:
            raise EdoLiteSecurityError("unknown/unpinned schema")
        artifact.verify()
        try:
            from lxml import etree
        except ImportError as exc:
            raise EdoLiteSecurityError("offline XSD engine dependency unavailable") from exc

        class _PinnedResolver(etree.Resolver):
            def resolve(self, system_url: str, public_id: str, context: Any):
                name = system_url.rsplit("/", 1)[-1]
                if name not in artifact.dependency_bytes:
                    raise EdoLiteSecurityError("unpinned XSD dependency")
                return self.resolve_string(artifact.dependency_bytes[name], context)

        parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True, huge_tree=False, remove_blank_text=False)
        parser.resolvers.add(_PinnedResolver())
        try:
            schema_doc = etree.fromstring(artifact.xsd_bytes, parser=parser)
            schema = etree.XMLSchema(schema_doc)
            xml_doc = etree.fromstring(xml_bytes, parser=parser)
        except (etree.XMLSyntaxError, etree.XMLSchemaParseError) as exc:
            raise EdoLiteSecurityError("XML/XSD parsing failed closed") from exc
        qname = etree.QName(xml_doc)
        if qname.localname != artifact.definition.root or qname.namespace != artifact.definition.target_namespace:
            raise EdoLiteSecurityError("XML root/namespace does not match pinned schema")
        if not schema.validate(xml_doc):
            raise EdoLiteContractError("XML does not validate against pinned schema")


@dataclass(frozen=True, slots=True)
class M7SigningEnvelope:
    operation_id: str
    edo_document_id: str | None
    edo_event_id: str | None
    document_family: str
    official_type_code: str | None
    schema_identity: str
    participant_inn: str
    exact_xml_sha256: str
    exact_xml_bytes: bytes
    reference: str


def create_m7_signing_envelope(
    *,
    operation_id: str,
    blob: ImmutableDocumentBlob,
    schema_identity: str,
    participant_inn: str,
    reference: str,
    edo_document_id: str | None = None,
    edo_event_id: str | None = None,
    registry: Mapping[str, SchemaDefinition] = PRODUCTION_SCHEMA_REGISTRY,
) -> M7SigningEnvelope:
    definition = registry.get(schema_identity)
    if definition is None or not definition.production or not definition.enabled_for_lp:
        raise M7SchemaNotEnabled("M7_SCHEMA_NOT_ENABLED")
    blob.verify()
    if blob.schema_identity != schema_identity:
        raise EdoLiteSecurityError("schema identity/blob mismatch")
    return M7SigningEnvelope(
        _string(operation_id, "operation_id"),
        None if edo_document_id is None else opaque_remote_id(edo_document_id, "edo_document_id"),
        None if edo_event_id is None else opaque_remote_id(edo_event_id, "edo_event_id"),
        blob.document_family,
        definition.official_type_code,
        schema_identity,
        _inn(participant_inn, "participant_inn"),
        blob.sha256,
        blob.exact_bytes,
        _string(reference, "reference", max_len=2048),
    )


class IdFileConflict(StrEnum):
    NEW = "NEW"
    RECONCILE_EXISTING = "RECONCILE_EXISTING"
    HARD_CONFLICT = "HARD_CONFLICT"


def classify_id_file_conflict(existing_sha256: str | None, new_sha256: str) -> IdFileConflict:
    if not re.fullmatch(r"[0-9a-f]{64}", new_sha256):
        raise EdoLiteContractError("new SHA256 is invalid")
    if existing_sha256 is None:
        return IdFileConflict.NEW
    if not re.fullmatch(r"[0-9a-f]{64}", existing_sha256):
        raise EdoLiteContractError("existing SHA256 is invalid")
    return IdFileConflict.RECONCILE_EXISTING if existing_sha256 == new_sha256 else IdFileConflict.HARD_CONFLICT


@dataclass(frozen=True, slots=True)
class ZipInspection:
    entries: tuple[str, ...]
    total_uncompressed: int


def inspect_legal_zip_safely(raw: bytes, *, max_entries: int = 256, max_uncompressed: int = 64 * 1024 * 1024) -> ZipInspection:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError) as exc:
        raise EdoLiteSecurityError("invalid legal ZIP") from exc
    names: list[str] = []
    total = 0
    for info in archive.infolist():
        if len(names) >= max_entries:
            raise EdoLiteSecurityError("ZIP entry limit exceeded")
        name = info.filename.replace("\\", "/")
        if not name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
            raise EdoLiteSecurityError("unsafe ZIP path")
        normalized = posixpath.normpath(name)
        if normalized == ".." or normalized.startswith("../"):
            raise EdoLiteSecurityError("ZIP path traversal")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise EdoLiteSecurityError("ZIP symlink rejected")
        total += int(info.file_size)
        if total > max_uncompressed:
            raise EdoLiteSecurityError("ZIP expansion limit exceeded")
        if info.compress_size > 0 and info.file_size > 10_000_000 and info.file_size / info.compress_size > 200:
            raise EdoLiteSecurityError("ZIP compression ratio rejected")
        names.append(name)
    return ZipInspection(tuple(names), total)


@dataclass(frozen=True, slots=True)
class EdoHttpError:
    http_status: int
    raw_body: bytes
    content_type: str | None

    @property
    def raw_body_sha256(self) -> str:
        return hashlib.sha256(self.raw_body).hexdigest()


@dataclass(frozen=True, slots=True)
class EdoServiceError:
    raw: Any


@dataclass(frozen=True, slots=True)
class GisProcessingError:
    code: Any
    description: Any
    raw_operation_data: Any


@dataclass(frozen=True, slots=True)
class LocalSchemaDisabledError:
    schema_identity: str
    reason: str


@dataclass(frozen=True, slots=True)
class LocalReconciliationError:
    reason: str
    evidence: Mapping[str, Any]
