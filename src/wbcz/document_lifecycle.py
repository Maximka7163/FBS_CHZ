from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
import hashlib
import json
import re
from typing import Any, Iterable, Mapping
from urllib.parse import quote, urlencode


M4_SOURCE_VERSION = "true-api-v726.0"
M4_PRODUCT_GROUP = "lp"
DOCUMENT_LIST_PATH = "/api/v4/true-api/doc/list"
DOCUMENT_CISES_PATH = "/api/v3/true-api/doc/cises"
_DOCUMENT_INFO_RE = re.compile(r"^/api/v4/true-api/doc/([A-Za-z0-9._:-]{1,256})/info(?:\?.*)?$")
_DOCUMENT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")

M4_READ_JOB_TYPES = frozenset({"DOCUMENT_LIST", "DOCUMENT_INFO", "DOCUMENT_CISES"})


class DocumentLifecycleContractError(ValueError):
    pass


class DocumentFormat(StrEnum):
    MANUAL = "MANUAL"
    XML = "XML"
    CSV = "CSV"


class DocumentListFormat(StrEnum):
    MANUAL = "MANUAL"
    UPD = "UPD"
    XML = "XML"
    CSV = "CSV"


@dataclass(frozen=True, slots=True)
class DocumentTypeDefinition:
    type_code: str
    formats: tuple[DocumentFormat, ...]
    create_supported: bool = True
    view_supported: bool = True


# Official §4.1 create/view registry from True API v726.0. JSON is represented by
# the Unified Create wire value MANUAL. Product-group applicability remains
# type-specific and is intentionally not inferred from the code name.
_DOCUMENT_TYPES: tuple[tuple[str, DocumentFormat], ...] = (
    ("UNIVERSAL_TRANSFER_DOCUMENT", DocumentFormat.XML),
    ("AGGREGATION_DOCUMENT", DocumentFormat.MANUAL),
    ("DISAGGREGATION_DOCUMENT", DocumentFormat.MANUAL),
    ("UNIVERSAL_CORRECTION_DOCUMENT", DocumentFormat.XML),
    ("WRITE_OFF", DocumentFormat.MANUAL),
    ("UNIVERSAL_TRANSFER_DOCUMENT_FIX", DocumentFormat.XML),
    ("UNIVERSAL_CORRECTION_DOCUMENT_FIX", DocumentFormat.XML),
    ("LP_INTRODUCE_GOODS", DocumentFormat.MANUAL),
    ("LP_SHIP_GOODS", DocumentFormat.MANUAL),
    ("LP_ACCEPT_GOODS", DocumentFormat.MANUAL),
    ("LP_INTRODUCE_GOODS_CSV", DocumentFormat.CSV),
    ("LP_INTRODUCE_GOODS_XML", DocumentFormat.XML),
    ("LP_SHIP_GOODS_CSV", DocumentFormat.CSV),
    ("LP_SHIP_GOODS_XML", DocumentFormat.XML),
    ("LP_ACCEPT_GOODS_XML", DocumentFormat.XML),
    ("LK_REMARK", DocumentFormat.MANUAL),
    ("LK_REMARK_XML", DocumentFormat.XML),
    ("LK_RECEIPT_XML", DocumentFormat.XML),
    ("LK_RECEIPT_CSV", DocumentFormat.CSV),
    ("LK_RECEIPT", DocumentFormat.MANUAL),
    ("LP_GOODS_IMPORT", DocumentFormat.MANUAL),
    ("LP_CANCEL_SHIPMENT", DocumentFormat.MANUAL),
    ("LK_KM_CANCELLATION", DocumentFormat.MANUAL),
    ("LK_CONTRACT_COMMISSIONING", DocumentFormat.MANUAL),
    ("LK_CONTRACT_COMMISSIONING_XML", DocumentFormat.XML),
    ("LK_INDI_COMMISSIONING", DocumentFormat.MANUAL),
    ("LK_INDI_COMMISSIONING_XML", DocumentFormat.XML),
    ("AGGREGATION_DOCUMENT_XML", DocumentFormat.XML),
    ("DISAGGREGATION_DOCUMENT_XML", DocumentFormat.XML),
    ("REAGGREGATION_DOCUMENT", DocumentFormat.MANUAL),
    ("CROSSBORDER", DocumentFormat.MANUAL),
    ("LP_INTRODUCE_OST", DocumentFormat.MANUAL),
    ("LP_RETURN", DocumentFormat.MANUAL),
    ("LP_RETURN_XML", DocumentFormat.XML),
    ("ATK_DISAGGREGATION", DocumentFormat.MANUAL),
    ("ATK_TRANSFORMATION", DocumentFormat.MANUAL),
    ("LP_FTS_INTRODUCE", DocumentFormat.MANUAL),
    ("LP_FTS_INTRODUCE_XML", DocumentFormat.XML),
    ("ATK_AGGREGATION", DocumentFormat.MANUAL),
    ("ATK_AGGREGATION_XML", DocumentFormat.XML),
    ("EAS_GTIN_CROSSBORDER_EXPORT", DocumentFormat.MANUAL),
    ("EAS_GTIN_CROSSBORDER_EXPORT_CSV", DocumentFormat.CSV),
    ("SETS_AGGREGATION", DocumentFormat.MANUAL),
    ("SETS_AGGREGATION_XML", DocumentFormat.XML),
    ("CIS_INFORMATION_CHANGE", DocumentFormat.MANUAL),
    ("EAS_GTIN_CROSSBORDER_ACCEPTANCE", DocumentFormat.MANUAL),
    ("EAS_GTIN_CROSSBORDER_ACCEPTANCE_CSV", DocumentFormat.CSV),
    ("LK_INDIVIDUALIZATION", DocumentFormat.MANUAL),
    ("LK_INDIVIDUALIZATION_XML", DocumentFormat.XML),
    ("FURS_FTS_INTRODUCE", DocumentFormat.MANUAL),
    ("FURS_CROSSBORDER", DocumentFormat.MANUAL),
    ("EAS_CROSSBORDER_EXPORT", DocumentFormat.MANUAL),
    ("EAS_CROSSBORDER_EXPORT_CSV", DocumentFormat.CSV),
    ("LK_GTIN_RECEIPT", DocumentFormat.MANUAL),
    ("REPORT_REWEIGHING", DocumentFormat.MANUAL),
    ("LK_GTIN_RECEIPT_CANCEL", DocumentFormat.MANUAL),
    ("CONNECT_TAP", DocumentFormat.MANUAL),
    ("LK_RECEIPT_CANCEL", DocumentFormat.MANUAL),
    ("FIXATION_CANCEL", DocumentFormat.MANUAL),
    ("FIXATION", DocumentFormat.XML),
    ("CIS_NOTICE", DocumentFormat.MANUAL),
    ("ALCO_UTILISED", DocumentFormat.MANUAL),
    ("LK_UNIVERSAL_INTRODUCE", DocumentFormat.MANUAL),
)

DOCUMENT_TYPE_REGISTRY: Mapping[str, DocumentTypeDefinition] = {
    code: DocumentTypeDefinition(type_code=code, formats=(fmt,)) for code, fmt in _DOCUMENT_TYPES
}


class StatusScope(StrEnum):
    GENERAL = "GENERAL"
    SHIPMENT = "SHIPMENT"
    SHIPMENT_EDO = "SHIPMENT_EDO"


class DirectStatusClass(StrEnum):
    INTERMEDIATE = "INTERMEDIATE"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class DocumentStatusDefinition:
    raw: str
    display: str
    scope: StatusScope


DOCUMENT_STATUS_REGISTRY: Mapping[str, DocumentStatusDefinition] = {
    "IN_PROGRESS": DocumentStatusDefinition("IN_PROGRESS", "Проверяется", StatusScope.GENERAL),
    "CHECKED_OK": DocumentStatusDefinition("CHECKED_OK", "Обработан", StatusScope.GENERAL),
    "CHECKED_NOT_OK": DocumentStatusDefinition("CHECKED_NOT_OK", "Обработан с ошибками", StatusScope.GENERAL),
    "PROCESSING_ERROR": DocumentStatusDefinition("PROCESSING_ERROR", "Техническая ошибка", StatusScope.GENERAL),
    "UNDEFINED": DocumentStatusDefinition("UNDEFINED", "Не определён", StatusScope.GENERAL),
    "ACCEPTED": DocumentStatusDefinition("ACCEPTED", "Принят", StatusScope.SHIPMENT),
    "CANCELLED": DocumentStatusDefinition("CANCELLED", "Аннулирован", StatusScope.SHIPMENT_EDO),
    "WAIT_ACCEPTANCE": DocumentStatusDefinition("WAIT_ACCEPTANCE", "Ожидает приёмку", StatusScope.SHIPMENT),
    "PARSE_ERROR": DocumentStatusDefinition("PARSE_ERROR", "Обработан с ошибками", StatusScope.GENERAL),
    "WAIT_PARTICIPANT_REGISTRATION": DocumentStatusDefinition("WAIT_PARTICIPANT_REGISTRATION", "Ожидает регистрации", StatusScope.SHIPMENT),
    "WAIT_FOR_CONTINUATION": DocumentStatusDefinition("WAIT_FOR_CONTINUATION", "Проверяется", StatusScope.GENERAL),
    # Official v726.0 inconsistency: LK_RECEIPT_CANCEL text uses CANCELED.
    "CANCELED": DocumentStatusDefinition("CANCELED", "Аннулирован (raw variant)", StatusScope.SHIPMENT_EDO),
}


def classify_direct_status(raw_status: Any) -> DirectStatusClass:
    if raw_status in {"IN_PROGRESS", "WAIT_FOR_CONTINUATION"}:
        return DirectStatusClass.INTERMEDIATE
    if raw_status == "CHECKED_OK":
        return DirectStatusClass.SUCCESS
    if raw_status in {"CHECKED_NOT_OK", "PARSE_ERROR", "PROCESSING_ERROR"}:
        return DirectStatusClass.FAILURE
    return DirectStatusClass.UNKNOWN


def status_display(raw_status: Any) -> str:
    if not isinstance(raw_status, str) or not raw_status:
        return "Неизвестный статус"
    item = DOCUMENT_STATUS_REGISTRY.get(raw_status)
    return item.display if item else raw_status


@dataclass(frozen=True, slots=True)
class OperationProcessingError:
    raw_message: str


@dataclass(frozen=True, slots=True)
class CommonProcessingError:
    raw_code: str | None
    message: str | None
    error_object: Any


@dataclass(frozen=True, slots=True)
class DocumentReadSpec:
    job_type: str
    method: str
    target: str
    audit_endpoint: str


@dataclass(frozen=True, slots=True)
class CreateResponseCapture:
    http_status: int
    content_type: str | None
    body_sha256: str
    raw_body_base64: str
    parsed_json: Any | None


def _expect_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DocumentLifecycleContractError(f"{label} must be an object")
    return dict(value)


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DocumentLifecycleContractError(f"{label} must be a non-empty string")
    return value


def _document_id(value: Any, label: str = "document_id") -> str:
    value = _expect_string(value, label)
    if _DOCUMENT_ID_RE.fullmatch(value) is None:
        raise DocumentLifecycleContractError(f"{label} contains unsupported characters")
    return value


def _timestamp(value: Any, label: str) -> str:
    text = _expect_string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DocumentLifecycleContractError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise DocumentLifecycleContractError(f"{label} must include timezone")
    return text


def _inn(value: Any, label: str) -> str:
    text = _expect_string(value, label)
    if not text.isdigit() or len(text) not in {10, 12}:
        raise DocumentLifecycleContractError(f"{label} must contain 10 or 12 digits")
    return text


def _query(path: str, pairs: Iterable[tuple[str, str]]) -> str:
    encoded = urlencode(list(pairs), doseq=False, quote_via=quote, safe="")
    return f"{path}?{encoded}" if encoded else path


def validate_m4_job_payload(job_type: str, payload: Any) -> dict[str, Any]:
    if job_type not in M4_READ_JOB_TYPES:
        raise DocumentLifecycleContractError("unsupported M4 read job type")
    root = _expect_object(payload, "read_payload")

    if job_type == "DOCUMENT_LIST":
        allowed = {
            "document_id", "did", "number", "document_type_code", "document_status_code",
            "document_format", "date_from", "date_to", "limit", "order",
            "ordered_column_value", "page_dir", "sender_inn", "receiver_inn",
        }
        unknown = set(root) - allowed
        if unknown:
            raise DocumentLifecycleContractError(f"DOCUMENT_LIST has unknown fields: {sorted(unknown)}")
        normalized: dict[str, Any] = {}
        if "document_id" in root and root["document_id"] is not None:
            if "did" in root and root["did"] is not None:
                raise DocumentLifecycleContractError("document_id is a local alias for did; provide only one")
            normalized["did"] = _document_id(root["document_id"])
        elif "did" in root and root["did"] is not None:
            normalized["did"] = _expect_string(root["did"], "did")
        if "number" in root and root["number"] is not None:
            normalized["number"] = _expect_string(root["number"], "number")
        if "document_type_code" in root and root["document_type_code"] is not None:
            value = root["document_type_code"]
            values = value if isinstance(value, list) else [value]
            if not values:
                raise DocumentLifecycleContractError("document_type_code cannot be empty")
            normalized_types = []
            for index, code in enumerate(values):
                code = _expect_string(code, f"document_type_code[{index}]")
                # Read endpoints can expose view-only/unknown future types. Preserve them
                # instead of incorrectly rejecting a participant-visible document.
                normalized_types.append(code)
            normalized["document_type_code"] = normalized_types
        if "document_status_code" in root and root["document_status_code"] is not None:
            normalized["document_status_code"] = _expect_string(root["document_status_code"], "document_status_code")
        if "document_format" in root and root["document_format"] is not None:
            fmt = _expect_string(root["document_format"], "document_format").upper()
            if fmt not in {item.value for item in DocumentListFormat}:
                raise DocumentLifecycleContractError("document_format must be MANUAL, UPD, XML or CSV")
            normalized["document_format"] = fmt
        if "date_from" in root and root["date_from"] is not None:
            normalized["date_from"] = _timestamp(root["date_from"], "date_from")
        if "date_to" in root and root["date_to"] is not None:
            normalized["date_to"] = _timestamp(root["date_to"], "date_to")
        limit = root.get("limit", 50)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise DocumentLifecycleContractError("limit must be 1..1000")
        normalized["limit"] = limit
        order = _expect_string(root.get("order", "DESC"), "order").upper()
        if order not in {"ASC", "DESC"}:
            raise DocumentLifecycleContractError("order must be ASC or DESC")
        normalized["order"] = order
        if "ordered_column_value" in root and root["ordered_column_value"] is not None:
            normalized["ordered_column_value"] = _expect_string(root["ordered_column_value"], "ordered_column_value")
        if "page_dir" in root and root["page_dir"] is not None:
            page_dir = _expect_string(root["page_dir"], "page_dir").upper()
            if page_dir not in {"PREV", "NEXT"}:
                raise DocumentLifecycleContractError("page_dir must be PREV or NEXT")
            normalized["page_dir"] = page_dir
        if "sender_inn" in root and root["sender_inn"] is not None:
            normalized["sender_inn"] = _inn(root["sender_inn"], "sender_inn")
        if "receiver_inn" in root and root["receiver_inn"] is not None:
            normalized["receiver_inn"] = _inn(root["receiver_inn"], "receiver_inn")
        if "sender_inn" in normalized and "receiver_inn" in normalized:
            raise DocumentLifecycleContractError("sender_inn and receiver_inn cannot be supplied together")
        return normalized

    if job_type == "DOCUMENT_INFO":
        allowed = {"document_id", "body", "content"}
        unknown = set(root) - allowed
        if unknown:
            raise DocumentLifecycleContractError(f"DOCUMENT_INFO has unknown fields: {sorted(unknown)}")
        document_id = _document_id(root.get("document_id"))
        body = root.get("body", False)
        content = root.get("content", False)
        if type(body) is not bool or type(content) is not bool:
            raise DocumentLifecycleContractError("body/content must be boolean")
        return {"document_id": document_id, "body": body, "content": content}

    if job_type == "DOCUMENT_CISES":
        allowed = {"document_id", "product_group"}
        unknown = set(root) - allowed
        if unknown:
            raise DocumentLifecycleContractError(f"DOCUMENT_CISES has unknown fields: {sorted(unknown)}")
        document_id = _document_id(root.get("document_id"))
        pg = _expect_string(root.get("product_group", M4_PRODUCT_GROUP), "product_group")
        if pg != M4_PRODUCT_GROUP:
            raise DocumentLifecycleContractError("M4 direct-document CIS reads are scoped to productGroup=lp")
        return {"document_id": document_id, "product_group": pg}

    raise AssertionError(job_type)


def build_document_read_spec(job_type: str, payload: Any) -> DocumentReadSpec:
    normalized = validate_m4_job_payload(job_type, payload)
    if job_type == "DOCUMENT_LIST":
        pairs: list[tuple[str, str]] = [("pg", M4_PRODUCT_GROUP)]
        if "date_from" in normalized:
            pairs.append(("dateFrom", normalized["date_from"]))
        if "date_to" in normalized:
            pairs.append(("dateTo", normalized["date_to"]))
        if "did" in normalized:
            pairs.append(("did", normalized["did"]))
        if "document_format" in normalized:
            pairs.append(("documentFormat", normalized["document_format"]))
        if "document_status_code" in normalized:
            pairs.append(("documentStatus", normalized["document_status_code"]))
        for code in normalized.get("document_type_code", []):
            pairs.append(("documentType", code))
        pairs.extend((("limit", str(normalized["limit"])), ("order", normalized["order"])))
        if "number" in normalized:
            pairs.append(("number", normalized["number"]))
        if "ordered_column_value" in normalized:
            pairs.append(("orderedColumnValue", normalized["ordered_column_value"]))
        if "page_dir" in normalized:
            pairs.append(("pageDir", normalized["page_dir"]))
        if "sender_inn" in normalized:
            pairs.append(("senderInn", normalized["sender_inn"]))
        if "receiver_inn" in normalized:
            pairs.append(("receiverInn", normalized["receiver_inn"]))
        return DocumentReadSpec(job_type, "GET", _query(DOCUMENT_LIST_PATH, pairs), "/doc/list")

    if job_type == "DOCUMENT_INFO":
        pairs = [
            ("body", "true" if normalized["body"] else "false"),
            ("content", "true" if normalized["content"] else "false"),
        ]
        target = _query(f"/api/v4/true-api/doc/{quote(normalized['document_id'], safe='')}/info", pairs)
        return DocumentReadSpec(job_type, "GET", target, "/doc/{docId}/info")

    if job_type == "DOCUMENT_CISES":
        pairs = [("documentId", normalized["document_id"]), ("productGroup", normalized["product_group"])]
        return DocumentReadSpec(job_type, "GET", _query(DOCUMENT_CISES_PATH, pairs), "/doc/cises")

    raise AssertionError(job_type)


def is_allowed_document_target(spec: DocumentReadSpec) -> bool:
    if spec.job_type not in M4_READ_JOB_TYPES or spec.method != "GET":
        return False
    if spec.job_type == "DOCUMENT_LIST":
        return spec.target.startswith(DOCUMENT_LIST_PATH + "?") and "pg=lp" in spec.target
    if spec.job_type == "DOCUMENT_INFO":
        return _DOCUMENT_INFO_RE.fullmatch(spec.target) is not None
    if spec.job_type == "DOCUMENT_CISES":
        return spec.target.startswith(DOCUMENT_CISES_PATH + "?") and "productGroup=lp" in spec.target
    return False


def _raw_status_envelope(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, str) else None
    return {
        "raw": raw,
        "display": status_display(raw),
        "direct_class": classify_direct_status(raw).value,
        "known": raw in DOCUMENT_STATUS_REGISTRY if raw else False,
    }


def _parse_errors(value: Any) -> list[OperationProcessingError]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise DocumentLifecycleContractError("errors must be an array")
    result = []
    for item in value:
        result.append(OperationProcessingError(raw_message=str(item)))
    return result


def _parse_common_errors(value: Any) -> list[CommonProcessingError]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise DocumentLifecycleContractError("commonErrors must be an array")
    result: list[CommonProcessingError] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise DocumentLifecycleContractError(f"commonErrors[{index}] must be an object")
        code = item.get("errorCode")
        message = item.get("errorMessage")
        result.append(
            CommonProcessingError(
                raw_code=str(code) if code is not None else None,
                message=str(message) if message is not None else None,
                error_object=item.get("errorObject"),
            )
        )
    return result


def parse_document_list(payload: Any) -> dict[str, Any]:
    root = _expect_object(payload, "doc/list response")
    results = root.get("results")
    if not isinstance(results, list):
        raise DocumentLifecycleContractError("doc/list results must be an array")
    parsed = []
    for index, item in enumerate(results):
        row = _expect_object(item, f"results[{index}]")
        parsed.append({
            "number": row.get("number"),
            "docDate": row.get("docDate"),
            "receivedAt": row.get("receivedAt"),
            "type": row.get("type"),
            "status": _raw_status_envelope(row.get("status")),
            "senderInn": row.get("senderInn"),
            "senderName": row.get("senderName"),
            "receiverInn": row.get("receiverInn"),
            "receiverName": row.get("receiverName"),
            "invoiceNumber": row.get("invoiceNumber"),
            "relatedDocId": row.get("relatedDocId"),
            "downloadDesc": row.get("downloadDesc"),
            "input": row.get("input"),
            "errors": [asdict(v) for v in _parse_errors(row.get("errors"))],
            "productGroup": row.get("productGroup"),
            "productGroupId": row.get("productGroupId"),
            "eliminationReason": row.get("eliminationReason"),
            "raw": row,
        })
    return {"results": parsed, "nextPage": bool(root.get("nextPage", False)), "raw": root}


def parse_document_info(payload: Any) -> dict[str, Any]:
    root = _expect_object(payload, "doc/info response")
    errors = [asdict(v) for v in _parse_errors(root.get("errors"))]
    common = [asdict(v) for v in _parse_common_errors(root.get("commonErrors"))]
    return {
        "number": root.get("number"),
        "docDate": root.get("docDate"),
        "receivedAt": root.get("receivedAt"),
        "type": root.get("type"),
        "status": _raw_status_envelope(root.get("status")),
        "senderInn": root.get("senderInn"),
        "senderName": root.get("senderName"),
        "senderMod": root.get("senderMod"),
        "receiverInn": root.get("receiverInn"),
        "receiverName": root.get("receiverName"),
        "receiverMod": root.get("receiverMod"),
        "invoiceNumber": root.get("invoiceNumber"),
        "invoiceDate": root.get("invoiceDate"),
        "relatedDocId": root.get("relatedDocId"),
        "turnoverType": root.get("turnoverType"),
        "body": root.get("body"),
        "content": root.get("content"),
        "input": root.get("input"),
        "errors": errors,
        "commonErrors": common,
        "productGroup": root.get("productGroup"),
        "productGroupId": root.get("productGroupId"),
        "eliminationReason": root.get("eliminationReason"),
        "raw": root,
    }


def parse_document_cises(payload: Any) -> dict[str, Any]:
    root = _expect_object(payload, "doc/cises response")
    return {
        "senderInn": root.get("senderInn"),
        "receiverInn": root.get("receiverInn"),
        "type": root.get("type"),
        "status": _raw_status_envelope(root.get("status")),
        "receivedAt": root.get("receivedAt"),
        "documentId": root.get("documentId"),
        "turnoverType": root.get("turnoverType"),
        "relatedDocId": root.get("relatedDocId"),
        "cisList": root.get("cisList") if isinstance(root.get("cisList"), list) else [],
        "products": root.get("products") if isinstance(root.get("products"), list) else [],
        "raw": root,
    }


def parse_m4_success_payload(job_type: str, payload: Any) -> dict[str, Any]:
    if job_type == "DOCUMENT_LIST":
        return parse_document_list(payload)
    if job_type == "DOCUMENT_INFO":
        return parse_document_info(payload)
    if job_type == "DOCUMENT_CISES":
        return parse_document_cises(payload)
    raise DocumentLifecycleContractError("unsupported M4 read job type")


def request_sha256(body: bytes) -> str:
    if not isinstance(body, bytes):
        raise TypeError("request body must be bytes")
    return hashlib.sha256(body).hexdigest()


def local_idempotency_key(operation_id: str, body: bytes) -> str:
    operation_id = _expect_string(operation_id, "operation_id")
    return f"{operation_id}:{request_sha256(body)}"


def capture_create_response(status: int, headers: Mapping[str, str], body: bytes) -> CreateResponseCapture:
    content_type = next((str(v) for k, v in headers.items() if str(k).casefold() == "content-type"), None)
    parsed: Any | None = None
    if body:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
    return CreateResponseCapture(
        http_status=int(status),
        content_type=content_type,
        body_sha256=hashlib.sha256(body).hexdigest(),
        raw_body_base64=base64.b64encode(body).decode("ascii"),
        parsed_json=parsed,
    )


def edo_reprocess_stub(*_: Any, **__: Any) -> None:
    raise NotImplementedError("TODO M4 optional-later: EDO-specific /document/reprocess")


def edo_receipts_stub(*_: Any, **__: Any) -> None:
    raise NotImplementedError("TODO M4 optional-later: EDO processing receipts/history")


def edo_validator_stub(*_: Any, **__: Any) -> None:
    raise NotImplementedError("TODO M4 optional-later: /doc/validator/*")


def fns_register_stub(*_: Any, **__: Any) -> None:
    raise NotImplementedError("TODO business-specific: FNS register is outside generic M4")


def operator_reconciliation_stub(*_: Any, **__: Any) -> None:
    raise NotImplementedError("TODO business-specific: operator reconciliation is outside generic M4")
