from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Iterable
from urllib.parse import quote, urlencode

from wbcz.cis_inventory import TrueApiReadSpec


M2_SOURCE_VERSION = "true-api-v726.0"
M2_PRODUCT_GROUP = "lp"

PARTICIPANTS_PATH = "/api/v3/true-api/participants"
MODS_LIST_PATH = "/api/v3/true-api/mods/list"
TN_VED_SEARCH_PATH = "/api/v4/true-api/tn-ved/search"
PRODUCT_GTIN_PATH = "/api/v4/true-api/product/gtin"
RD_LIST_PATH = "/api/v4/true-api/rd/list"

M2_READ_JOB_TYPES = frozenset({
    "PARTICIPANTS",
    "MODS_LIST",
    "TN_VED_SEARCH",
    "PRODUCT_GTIN_LIST",
    "RD_LIST",
})

RD_TYPES_WITH_REQUIRED_DATE_FROM = frozenset({
    "CONFORMITY_CERTIFICATE",
    "CONFORMITY_DECLARATION",
})
RD_TYPES_WITH_OPTIONAL_DATE_FROM = frozenset({"STATE_REGISTRATION_CERTIFICATE"})
KNOWN_RD_TYPES = RD_TYPES_WITH_REQUIRED_DATE_FROM | RD_TYPES_WITH_OPTIONAL_DATE_FROM

REFERENCE_CATEGORIES = (
    "PRODUCT_GROUPS",
    "CIS_BASE_STATUSES",
    "CIS_SPECIAL_STATUSES",
    "EMISSION_TYPES",
    "PACKAGE_TYPES",
    "PERMIT_DOCUMENT_TYPES",
    "WITHDRAWAL_REASONS",
    "RETURN_REASON_MAPPING",
    "PARTICIPANT_ROLES",
    "PARTICIPANT_STATUSES",
)


class ReferenceProductsContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TrueApiParticipantWire:
    raw: dict[str, Any]
    inn: str | None = None
    name: str | None = None
    statusInn: str | None = None
    status: str | None = None
    chief: Any = None
    role: Any = None
    is_registered: bool | None = None
    is_kfh: bool | None = None
    okopf: Any = None
    productGroups: Any = None
    productGroupInfo: Any = None
    errorCode: Any = None
    errorMessage: Any = None


@dataclass(frozen=True, slots=True)
class TrueApiModWire:
    raw: dict[str, Any]
    address: Any = None
    kpp: str | None = None
    fiasId: str | None = None
    isBlockedEgais: bool | None = None
    inn: str | None = None
    productGroups: Any = None


@dataclass(frozen=True, slots=True)
class TrueApiTnVedWire:
    raw: dict[str, Any]
    tnved: str | None = None
    description: str | None = None
    pg: Any = None


@dataclass(frozen=True, slots=True)
class TrueApiProductGtinWire:
    raw: dict[str, Any]
    goodStatus: Any = None
    gtin: str | None = None
    isGtinSubaccount: bool | None = None
    isKit: bool | None = None
    isSet: bool | None = None
    permittedInns: Any = None
    setDescription: Any = None
    setGtin: Any = None


@dataclass(frozen=True, slots=True)
class TrueApiRegulatoryDocumentWire:
    raw: dict[str, Any]
    type: str | None = None
    number: str | None = None
    dateFrom: Any = None
    dateTo: Any = None
    productType: Any = None
    productName: Any = None
    productCountry: Any = None
    applicant: Any = None
    manufacturer: Any = None
    recipient: Any = None
    productTnved: Any = None
    trademark: Any = None
    model: Any = None
    article: Any = None
    sort: Any = None
    technical_regulations: Any = None
    status: Any = None
    active: Any = None
    updateDate: Any = None
    indx: Any = None
    errors: Any = None


def _expect_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReferenceProductsContractError(f"{label} must be an object")
    return dict(value)


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReferenceProductsContractError(f"{label} must be a non-empty string")
    return value


def _expect_strings(value: Any, label: str, *, min_items: int = 0, max_items: int | None = None) -> list[str]:
    if not isinstance(value, list):
        raise ReferenceProductsContractError(f"{label} must be an array")
    if len(value) < min_items:
        raise ReferenceProductsContractError(f"{label} must contain at least {min_items} values")
    if max_items is not None and len(value) > max_items:
        raise ReferenceProductsContractError(f"{label} exceeds max {max_items}")
    return [_expect_string(item, f"{label}[{index}]") for index, item in enumerate(value)]


def _expect_nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ReferenceProductsContractError(f"{label} must be a non-negative integer")
    return value


def _expect_limited_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReferenceProductsContractError(f"{label} must be {minimum}..{maximum}")
    return value


def _validate_inn(value: Any, label: str = "inn") -> str:
    inn = _expect_string(value, label)
    if not inn.isdigit() or len(inn) not in (10, 12):
        raise ReferenceProductsContractError(f"{label} must contain 10 or 12 digits")
    return inn


def _validate_tnved(value: Any, label: str) -> str:
    code = _expect_string(value, label)
    if re.fullmatch(r"\d{4,10}", code) is None:
        raise ReferenceProductsContractError(f"{label} must contain 4..10 digits")
    return code


def _validate_date(value: Any, label: str) -> str:
    text = _expect_string(value, label)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text) is None:
        raise ReferenceProductsContractError(f"{label} must use yyyy-MM-dd")
    return text


def validate_m2_job_payload(job_type: str, payload: Any) -> dict[str, Any]:
    if job_type not in M2_READ_JOB_TYPES:
        raise ReferenceProductsContractError("unsupported M2 read job type")
    root = _expect_object(payload, "read_payload")

    if job_type == "PARTICIPANTS":
        if set(root) != {"inns"}:
            raise ReferenceProductsContractError("PARTICIPANTS payload must contain only inns")
        inns = [_validate_inn(v, f"inns[{i}]") for i, v in enumerate(_expect_strings(root["inns"], "inns", min_items=1, max_items=100))]
        return {"inns": inns}

    if job_type == "MODS_LIST":
        allowed = {"productGroups", "kpp", "fiasId", "inns", "limit", "page"}
        unknown = set(root) - allowed
        if unknown:
            raise ReferenceProductsContractError(f"MODS_LIST has unknown fields: {sorted(unknown)}")
        groups = root.get("productGroups", [M2_PRODUCT_GROUP])
        groups = _expect_strings(groups, "productGroups", min_items=1)
        if groups != [M2_PRODUCT_GROUP]:
            raise ReferenceProductsContractError('productGroups must be exactly ["lp"] for M2')
        normalized: dict[str, Any] = {"productGroups": groups}
        if "kpp" in root and root["kpp"] is not None:
            normalized["kpp"] = _expect_string(root["kpp"], "kpp")
        if "fiasId" in root and root["fiasId"] is not None:
            normalized["fiasId"] = _expect_string(root["fiasId"], "fiasId")
        if "inns" in root and root["inns"] is not None:
            values = _expect_strings(root["inns"], "inns", min_items=1, max_items=10)
            normalized["inns"] = [_validate_inn(v, f"inns[{i}]") for i, v in enumerate(values)]
        normalized["limit"] = _expect_limited_int(root.get("limit", 100), "limit", minimum=1, maximum=1000)
        normalized["page"] = _expect_nonnegative_int(root.get("page", 0), "page")
        return normalized

    if job_type == "TN_VED_SEARCH":
        allowed = {"pg", "tnveds", "page", "limit", "sort", "direction"}
        unknown = set(root) - allowed
        if unknown:
            raise ReferenceProductsContractError(f"TN_VED_SEARCH has unknown fields: {sorted(unknown)}")
        if "pg" not in root and "tnveds" not in root:
            raise ReferenceProductsContractError("TN_VED_SEARCH requires pg or tnveds")
        normalized: dict[str, Any] = {}
        if "pg" in root:
            normalized["pg"] = _expect_string(root["pg"], "pg")
        if "tnveds" in root:
            values = _expect_strings(root["tnveds"], "tnveds", min_items=1)
            normalized["tnveds"] = [_validate_tnved(v, f"tnveds[{i}]") for i, v in enumerate(values)]
        if "page" in root:
            normalized["page"] = _expect_nonnegative_int(root["page"], "page")
        if "limit" in root:
            normalized["limit"] = _expect_limited_int(root["limit"], "limit", minimum=1, maximum=1000)
        if "sort" in root:
            sort = _expect_string(root["sort"], "sort")
            if sort != "tnved":
                raise ReferenceProductsContractError("sort must be tnved")
            normalized["sort"] = sort
        if "direction" in root:
            direction = _expect_string(root["direction"], "direction").upper()
            if direction not in {"ASC", "DESC"}:
                raise ReferenceProductsContractError("direction must be ASC or DESC")
            normalized["direction"] = direction
        return normalized

    if job_type == "PRODUCT_GTIN_LIST":
        allowed = {"pg", "includeSubaccount", "limit", "page"}
        unknown = set(root) - allowed
        if unknown:
            raise ReferenceProductsContractError(f"PRODUCT_GTIN_LIST has unknown fields: {sorted(unknown)}")
        if root.get("pg", M2_PRODUCT_GROUP) != M2_PRODUCT_GROUP:
            raise ReferenceProductsContractError("product/gtin pg is forced to lp")
        include = root.get("includeSubaccount", False)
        if type(include) is not bool:
            raise ReferenceProductsContractError("includeSubaccount must be boolean")
        return {
            "pg": M2_PRODUCT_GROUP,
            "includeSubaccount": include,
            "limit": _expect_limited_int(root.get("limit", 10), "limit", minimum=1, maximum=10_000),
            "page": _expect_nonnegative_int(root.get("page", 0), "page"),
        }

    if job_type == "RD_LIST":
        if set(root) != {"documents"}:
            raise ReferenceProductsContractError("RD_LIST payload must contain only documents")
        documents = root["documents"]
        if not isinstance(documents, list) or not 1 <= len(documents) <= 25:
            raise ReferenceProductsContractError("documents must contain 1..25 items")
        normalized_documents: list[dict[str, Any]] = []
        for index, value in enumerate(documents):
            item = _expect_object(value, f"documents[{index}]")
            unknown = set(item) - {"type", "number", "dateFrom"}
            if unknown:
                raise ReferenceProductsContractError(f"documents[{index}] has unknown fields: {sorted(unknown)}")
            doc_type = _expect_string(item.get("type"), f"documents[{index}].type")
            if doc_type not in KNOWN_RD_TYPES:
                raise ReferenceProductsContractError(f"documents[{index}].type is not in accepted v726.0 M2 set")
            number = _expect_string(item.get("number"), f"documents[{index}].number")
            normalized_item: dict[str, Any] = {"type": doc_type, "number": number}
            if doc_type in RD_TYPES_WITH_REQUIRED_DATE_FROM:
                if "dateFrom" not in item:
                    raise ReferenceProductsContractError(f"documents[{index}].dateFrom is required for {doc_type}")
                normalized_item["dateFrom"] = _validate_date(item["dateFrom"], f"documents[{index}].dateFrom")
            elif "dateFrom" in item and item["dateFrom"] is not None:
                normalized_item["dateFrom"] = _validate_date(item["dateFrom"], f"documents[{index}].dateFrom")
            normalized_documents.append(normalized_item)
        return {"documents": normalized_documents}

    raise AssertionError(job_type)


def _query_target(path: str, pairs: Iterable[tuple[str, str]]) -> str:
    encoded = urlencode(list(pairs), doseq=False, quote_via=quote, safe="")
    return f"{path}?{encoded}" if encoded else path


def build_reference_read_spec(job_type: str, payload: Any) -> TrueApiReadSpec:
    normalized = validate_m2_job_payload(job_type, payload)
    if job_type == "PARTICIPANTS":
        target = _query_target(PARTICIPANTS_PATH, [("inns", inn) for inn in normalized["inns"]])
        return TrueApiReadSpec(job_type, "GET", target, None, "/participants", 0)
    if job_type == "MODS_LIST":
        pairs: list[tuple[str, str]] = [("productGroups", M2_PRODUCT_GROUP)]
        if "kpp" in normalized:
            pairs.append(("kpp", normalized["kpp"]))
        if "fiasId" in normalized:
            pairs.append(("fiasId", normalized["fiasId"]))
        for inn in normalized.get("inns", []):
            pairs.append(("inns", inn))
        pairs.extend((("limit", str(normalized["limit"])), ("page", str(normalized["page"]))))
        return TrueApiReadSpec(job_type, "GET", _query_target(MODS_LIST_PATH, pairs), None, "/mods/list", 0)
    if job_type == "TN_VED_SEARCH":
        return TrueApiReadSpec(job_type, "POST", TN_VED_SEARCH_PATH, normalized, "/tn-ved/search", 0)
    if job_type == "PRODUCT_GTIN_LIST":
        pairs = [
            ("pg", M2_PRODUCT_GROUP),
            ("includeSubaccount", "true" if normalized["includeSubaccount"] else "false"),
            ("limit", str(normalized["limit"])),
            ("page", str(normalized["page"])),
        ]
        return TrueApiReadSpec(job_type, "GET", _query_target(PRODUCT_GTIN_PATH, pairs), None, "/product/gtin", 0)
    if job_type == "RD_LIST":
        return TrueApiReadSpec(job_type, "POST", RD_LIST_PATH, normalized, "/rd/list", 0)
    raise AssertionError(job_type)


def is_allowed_reference_target(spec: TrueApiReadSpec) -> bool:
    if spec.job_type not in M2_READ_JOB_TYPES:
        return False
    try:
        rebuilt = build_reference_read_spec(spec.job_type, _payload_from_spec(spec))
    except ReferenceProductsContractError:
        return False
    return rebuilt.method == spec.method and rebuilt.target == spec.target and rebuilt.body == spec.body


def _payload_from_spec(spec: TrueApiReadSpec) -> dict[str, Any]:
    if spec.job_type in {"TN_VED_SEARCH", "RD_LIST"}:
        if not isinstance(spec.body, dict):
            raise ReferenceProductsContractError("POST spec body must be an object")
        return dict(spec.body)
    from urllib.parse import parse_qs, urlsplit

    split = urlsplit(spec.target)
    query = parse_qs(split.query, keep_blank_values=True)
    if spec.job_type == "PARTICIPANTS":
        if split.path != PARTICIPANTS_PATH or set(query) != {"inns"}:
            raise ReferenceProductsContractError("invalid participants target")
        return {"inns": query["inns"]}
    if spec.job_type == "MODS_LIST":
        if split.path != MODS_LIST_PATH:
            raise ReferenceProductsContractError("invalid mods target")
        allowed = {"productGroups", "kpp", "fiasId", "inns", "limit", "page"}
        if set(query) - allowed:
            raise ReferenceProductsContractError("invalid mods query")
        payload: dict[str, Any] = {"productGroups": query.get("productGroups", [])}
        for key in ("kpp", "fiasId"):
            if key in query:
                payload[key] = query[key][0]
        if "inns" in query:
            payload["inns"] = query["inns"]
        if "limit" in query:
            payload["limit"] = int(query["limit"][0])
        if "page" in query:
            payload["page"] = int(query["page"][0])
        return payload
    if spec.job_type == "PRODUCT_GTIN_LIST":
        if split.path != PRODUCT_GTIN_PATH:
            raise ReferenceProductsContractError("invalid product/gtin target")
        if set(query) - {"pg", "includeSubaccount", "limit", "page"}:
            raise ReferenceProductsContractError("invalid product/gtin query")
        return {
            "pg": query.get("pg", [M2_PRODUCT_GROUP])[0],
            "includeSubaccount": query.get("includeSubaccount", ["false"])[0].lower() == "true",
            "limit": int(query.get("limit", ["10"])[0]),
            "page": int(query.get("page", ["0"])[0]),
        }
    raise ReferenceProductsContractError("unsupported spec")


def _rows(payload: Any, *, keys: tuple[str, ...], label: str) -> tuple[list[Any], dict[str, Any] | None]:
    if isinstance(payload, list):
        return payload, None
    root = _expect_object(payload, label)
    for key in keys:
        if isinstance(root.get(key), list):
            return root[key], root
    raise ReferenceProductsContractError(f"{label} does not contain documented result array")


def validate_exact_lp_activity_location(
    mods: Iterable[dict[str, Any]],
    *,
    inn: str,
    kpp: str | None = None,
    fias_id: str | None = None,
) -> dict[str, Any]:
    expected_inn = _validate_inn(inn)
    matches: list[dict[str, Any]] = []
    for raw in mods:
        if not isinstance(raw, dict):
            continue
        groups = raw.get("productGroups")
        if not isinstance(groups, list) or M2_PRODUCT_GROUP not in groups:
            continue
        if raw.get("inn") != expected_inn:
            continue
        if kpp is not None and raw.get("kpp") != kpp:
            continue
        if fias_id is not None and raw.get("fiasId") != fias_id:
            continue
        matches.append(dict(raw))
    return {
        "valid": bool(matches),
        "matches": matches,
        "criteria": {"inn": expected_inn, "kpp": kpp, "fiasId": fias_id, "productGroup": M2_PRODUCT_GROUP},
        "kpp_required": kpp is not None,
        "active_status_invented": False,
    }


def parse_reference_success_payload(job_type: str, request_payload: dict[str, Any], payload: Any) -> dict[str, Any]:
    normalized_request = validate_m2_job_payload(job_type, request_payload)

    if job_type == "PARTICIPANTS":
        rows, root = _rows(payload, keys=("result", "results"), label="participants response")
        parsed = []
        for value in rows:
            raw = _expect_object(value, "participant item")
            wire = TrueApiParticipantWire(
                raw=raw,
                inn=raw.get("inn"),
                name=raw.get("name"),
                statusInn=raw.get("statusInn"),
                status=raw.get("status"),
                chief=raw.get("chief"),
                role=raw.get("role"),
                is_registered=raw.get("is_registered") if type(raw.get("is_registered")) is bool else None,
                is_kfh=raw.get("is_kfh") if type(raw.get("is_kfh")) is bool else None,
                okopf=raw.get("okopf"),
                productGroups=raw.get("productGroups"),
                productGroupInfo=raw.get("productGroupInfo"),
                errorCode=raw.get("errorCode"),
                errorMessage=raw.get("errorMessage"),
            )
            parsed.append({"wire": asdict(wire), "privacy_scope": "OFFICIAL_PARTICIPANT_RESPONSE", "kpp_invented": False, "fias_invented": False})
        return {"type": job_type, "items": parsed, "requested_inns": normalized_request["inns"], "partial_item_errors_preserved": True, "root": root}

    if job_type == "MODS_LIST":
        root = _expect_object(payload, "mods/list response")
        rows = root.get("result")
        if not isinstance(rows, list):
            raise ReferenceProductsContractError("mods/list response requires result array")
        parsed = []
        raw_rows: list[dict[str, Any]] = []
        for value in rows:
            raw = _expect_object(value, "mods/list item")
            raw_rows.append(raw)
            wire = TrueApiModWire(
                raw=raw,
                address=raw.get("address"),
                kpp=raw.get("kpp"),
                fiasId=raw.get("fiasId"),
                isBlockedEgais=raw.get("isBlockedEgais") if type(raw.get("isBlockedEgais")) is bool else None,
                inn=raw.get("inn"),
                productGroups=raw.get("productGroups"),
            )
            parsed.append({"wire": asdict(wire), "general_active_status_invented": False})
        validation = None
        if len(normalized_request.get("inns", [])) == 1:
            validation = validate_exact_lp_activity_location(
                raw_rows,
                inn=normalized_request["inns"][0],
                kpp=normalized_request.get("kpp"),
                fias_id=normalized_request.get("fiasId"),
            )
        return {
            "type": job_type,
            "result": parsed,
            "total": root.get("total"),
            "nextPage": root.get("nextPage"),
            "lp_activity_location_validation": validation,
            "mods_info_used": False,
        }

    if job_type == "TN_VED_SEARCH":
        root = _expect_object(payload, "tn-ved/search response")
        rows = root.get("tnveds")
        if not isinstance(rows, list):
            raise ReferenceProductsContractError("tn-ved/search response requires tnveds array")
        parsed = []
        for value in rows:
            raw = _expect_object(value, "tnved item")
            wire = TrueApiTnVedWire(raw=raw, tnved=raw.get("tnved"), description=raw.get("description"), pg=raw.get("pg"))
            parsed.append({"wire": asdict(wire)})
        return {
            "type": job_type,
            "tnveds": parsed,
            "total": root.get("total"),
            "last": root.get("last"),
            "errorMessage": root.get("errorMessage"),
            "errorCode": root.get("errorCode"),
        }

    if job_type == "PRODUCT_GTIN_LIST":
        root = _expect_object(payload, "product/gtin response")
        rows = root.get("results")
        if not isinstance(rows, list):
            raise ReferenceProductsContractError("product/gtin response requires results array")
        parsed = []
        for value in rows:
            raw = _expect_object(value, "product/gtin item")
            wire = TrueApiProductGtinWire(
                raw=raw,
                goodStatus=raw.get("goodStatus"),
                gtin=raw.get("gtin"),
                isGtinSubaccount=raw.get("isGtinSubaccount") if type(raw.get("isGtinSubaccount")) is bool else None,
                isKit=raw.get("isKit") if type(raw.get("isKit")) is bool else None,
                isSet=raw.get("isSet") if type(raw.get("isSet")) is bool else None,
                permittedInns=raw.get("permittedInns"),
                setDescription=raw.get("setDescription"),
                setGtin=raw.get("setGtin"),
            )
            parsed.append({"wire": asdict(wire)})
        return {"type": job_type, "results": parsed, "total": root.get("total"), "errorCode": root.get("errorCode"), "own_inventory": True, "pg": M2_PRODUCT_GROUP}

    if job_type == "RD_LIST":
        rows, root = _rows(payload, keys=("documents", "result", "results"), label="rd/list response")
        parsed = []
        for value in rows:
            raw = _expect_object(value, "rd/list item")
            wire = TrueApiRegulatoryDocumentWire(
                raw=raw,
                type=raw.get("type"),
                number=raw.get("number"),
                dateFrom=raw.get("dateFrom"),
                dateTo=raw.get("dateTo"),
                productType=raw.get("productType"),
                productName=raw.get("productName"),
                productCountry=raw.get("productCountry"),
                applicant=raw.get("applicant"),
                manufacturer=raw.get("manufacturer"),
                recipient=raw.get("recipient"),
                productTnved=raw.get("productTnved"),
                trademark=raw.get("trademark"),
                model=raw.get("model"),
                article=raw.get("article"),
                sort=raw.get("sort"),
                technical_regulations=raw.get("technical regulations", raw.get("technicalRegulations")),
                status=raw.get("status"),
                active=raw.get("active"),
                updateDate=raw.get("updateDate"),
                indx=raw.get("indx"),
                errors=raw.get("errors"),
            )
            parsed.append({"wire": asdict(wire), "issuer_invented": False})
        return {"type": job_type, "documents": parsed, "root": root, "per_document_errors_preserved": True}

    raise ReferenceProductsContractError(f"no parser for {job_type}")


_BASE_STATUSES = (
    "EMITTED", "APPLIED", "INTRODUCED", "WRITTEN_OFF", "RETIRED", "WITHDRAWN",
    "DISAGGREGATION", "DISAGGREGATED", "APPLIED_NOT_PAID",
)
_SPECIAL_STATUSES = (
    "IN_GRAY_ZONE", "EMPTY", "RESERVED_NOT_USED", "INDIVIDUAL", "NON_INDIVIDUAL",
    "WAIT_SHIPMENT", "EXPORTED", "LOAN_RETIRED", "LOST_INVENTORY", "REMARK_RETIRED",
    "WAIT_TRANSFER_TO_OWNER", "WAIT_REMARK", "RETIRED_CANCELLATION", "FTS_RESPOND_NOT_OK",
    "FTS_RESPOND_WAITING", "FTS_CONTROL", "EAS_RESPOND_NOT_OK", "EAS_RESPOND_WAITING",
    "CONNECT_TAP", "PRIM_RESPONSE_WAITING", "MOVING_BY_UD",
)
_EMISSION_TYPES = ("LOCAL", "FOREIGN", "REMAINS", "CROSSBORDER", "REMARK", "COMMISSION", "REAPPLY")

_REFERENCE_DATA: dict[str, tuple[dict[str, Any], ...]] = {
    "PRODUCT_GROUPS": ({"numeric_id": 1, "code": "lp", "name": "Лёгкая промышленность", "source_version": M2_SOURCE_VERSION},),
    "CIS_BASE_STATUSES": tuple({"code": code, "source_version": M2_SOURCE_VERSION} for code in _BASE_STATUSES),
    "CIS_SPECIAL_STATUSES": tuple({"code": code, "source_version": M2_SOURCE_VERSION} for code in _SPECIAL_STATUSES),
    "EMISSION_TYPES": tuple({"code": code, "source_version": M2_SOURCE_VERSION} for code in _EMISSION_TYPES),
    "PACKAGE_TYPES": (),
    "PERMIT_DOCUMENT_TYPES": tuple({"code": code, "source_version": M2_SOURCE_VERSION} for code in sorted(KNOWN_RD_TYPES)),
    "WITHDRAWAL_REASONS": ({"code": "DISTANCE", "allowed_document_types": ["LK_RECEIPT"], "allowed_product_groups": ["lp"], "source_version": M2_SOURCE_VERSION},),
    "RETURN_REASON_MAPPING": ({"code": "REMOTE_SALE_RETURN", "allowed_document_types": ["LP_RETURN"], "allowed_product_groups": ["lp"], "source_version": M2_SOURCE_VERSION},),
    "PARTICIPANT_ROLES": (),
    "PARTICIPANT_STATUSES": (),
}

_INCOMPLETE_REFERENCE_CATEGORIES = frozenset({"PACKAGE_TYPES", "PARTICIPANT_ROLES", "PARTICIPANT_STATUSES", "WITHDRAWAL_REASONS", "RETURN_REASON_MAPPING"})


def reference_categories() -> list[dict[str, Any]]:
    return [
        {
            "category": category,
            "source_version": M2_SOURCE_VERSION,
            "entry_count": len(_REFERENCE_DATA[category]),
            "source_complete": category not in _INCOMPLETE_REFERENCE_CATEGORIES,
        }
        for category in REFERENCE_CATEGORIES
    ]


def reference_entries(category: str) -> dict[str, Any]:
    if category not in _REFERENCE_DATA:
        raise KeyError(category)
    return {
        "category": category,
        "source_version": M2_SOURCE_VERSION,
        "source_complete": category not in _INCOMPLETE_REFERENCE_CATEGORIES,
        "entries": [dict(row) for row in _REFERENCE_DATA[category]],
    }


def lookup_reference_value(category: str, raw_value: Any) -> dict[str, Any]:
    if category not in _REFERENCE_DATA:
        raise KeyError(category)
    raw = None if raw_value is None else str(raw_value)
    for row in _REFERENCE_DATA[category]:
        candidate = row.get("code", row.get("name"))
        if candidate is not None and str(candidate) == raw:
            return {"raw_value": raw_value, "known": True, "reference": dict(row), "source_version": M2_SOURCE_VERSION}
    return {"raw_value": raw_value, "known": False, "reference": None, "source_version": M2_SOURCE_VERSION, "coerced": False}
