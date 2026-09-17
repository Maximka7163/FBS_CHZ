from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import re
import time
import threading
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote

from wbcz.true_api import normalize_cis, normalize_cises


M1_PRODUCT_GROUP = "lp"
MAX_BATCH = 1000
SEARCH_DEFAULT_PER_PAGE = 100
SEARCH_MAX_PER_PAGE = 1000
SEARCH_RESULT_CEILING = 10_000
GLOBAL_TRUE_API_RPS = 50

CIS_INFO_TARGET = "/api/v3/true-api/cises/info?pg=lp"
CIS_SEARCH_TARGET = "/api/v4/true-api/cises/search"
CIS_HISTORY_PREFIX = "/api/v3/true-api/cises/history?cis="
AGGREGATED_LIST_TARGET = "/api/v3/true-api/cises/aggregated/list?pg=lp"
AGGREGATION_HISTORY_TARGET = "/api/v3/true-api/cises/history/list"
PRODUCT_INFO_TARGET = "/api/v4/true-api/product/info"

M1_READ_JOB_TYPES = frozenset({
    "CIS_INFO",
    "CIS_SEARCH",
    "CIS_HISTORY",
    "CIS_AGGREGATED_LIST",
    "CIS_AGGREGATION_HISTORY",
    "PRODUCT_INFO",
    "CIS_TO_PRODUCT",
})

_SEARCH_FILTER_FIELDS = frozenset({
    "emissionDatePeriod",
    "applicationDatePeriod",
    "productionDatePeriod",
    "introducedDatePeriod",
    "gtins",
    "producerInns",
    "generalPackageTypes",
    "turnoverTypes",
    "states",
    "tnVed",
    "tnVed10",
    "emissionTypes",
    "isAggregated",
    "productGroups",
    "eliminationReasons",
    "prVetDoc",
    "haveChildren",
    "serviceProviderIdPresented",
    "serviceProviderTypes",
    "orderIds",
    "partyNumber",
    "mods",
    "manufacturerInns",
    "importerInns",
})

_SEARCH_STRING_ARRAY_FIELDS = frozenset({
    "gtins",
    "producerInns",
    "generalPackageTypes",
    "turnoverTypes",
    "emissionTypes",
    "productGroups",
    "eliminationReasons",
    "serviceProviderTypes",
    "orderIds",
})

_SEARCH_BOOL_FIELDS = frozenset({
    "isAggregated",
    "haveChildren",
    "serviceProviderIdPresented",
})

_SEARCH_PERIOD_FIELDS = frozenset({
    "emissionDatePeriod",
    "applicationDatePeriod",
    "productionDatePeriod",
    "introducedDatePeriod",
})

_SAFE_ERROR_KEYS = ("errorCode", "code", "message", "errorMessage", "description", "error")


class CisInventoryContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TrueApiReadSpec:
    job_type: str
    method: str
    target: str
    body: Any
    audit_endpoint: str
    cis_count: int = 0


@dataclass(frozen=True, slots=True)
class SafeTransportError:
    http_status: int
    content_type: str | None
    safe_error_code: str | None
    safe_error_message: str | None
    body_sha256: str
    raw_body_preview: str | None = None


@dataclass(frozen=True, slots=True)
class TrueApiCisInfoWire:
    requested_cis: str
    cis_info: dict[str, Any] | None
    error_code: str | None
    error_message: str | None
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TrueApiCisSearchWire:
    raw: dict[str, Any]
    cis: str | None = None
    sgtin: str | None = None
    gtin: str | None = None
    ownerInn: str | None = None
    status: str | None = None
    statusExt: str | None = None
    eliminationReason: str | None = None


@dataclass(frozen=True, slots=True)
class TrueApiCisHistoryWire:
    raw: dict[str, Any]
    cis: str | None = None
    gtin: str | None = None
    status: str | None = None
    ownerInn: str | None = None
    operationDate: Any = None
    timestamp: Any = None


@dataclass(frozen=True, slots=True)
class TrueApiAggregateWire:
    requested_cis: str
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TrueApiAggregationHistoryWire:
    raw: dict[str, Any]
    cis: str | None = None
    operationType: str | None = None
    operationDate: Any = None
    packageType: str | None = None
    extendedPackageType: str | None = None
    parent: str | None = None


@dataclass(frozen=True, slots=True)
class TrueApiProductInfoWire:
    raw: dict[str, Any]
    gtin: str | None = None
    name: str | None = None
    brand: str | None = None
    productGroup: str | None = None
    goodMarkFlag: bool | None = None
    goodTurnFlag: bool | None = None
    subBrand: Any = None
    privateBrand: Any = None
    packageType: Any = None
    innerUnitCount: Any = None
    model: Any = None
    inn: Any = None
    permittedInns: Any = None
    productGroupId: Any = None
    goodSignedFlag: Any = None
    goodStatus: Any = None
    isKit: Any = None
    isTechGtin: Any = None
    isSet: Any = None
    setGtin: Any = None
    setDescription: Any = None
    level: Any = None
    mainGtin: Any = None
    multiplier: Any = None
    foreignProducer: Any = None
    exporter: Any = None
    standardNumber: Any = None
    tnVedCode: Any = None
    tnVedCode10: Any = None
    fullName: Any = None
    basicUnit: Any = None
    quantityInPack: Any = None
    quantityInPackType: Any = None
    reasonCertMissing: Any = None
    reasonCertMissingDetails: Any = None
    certDocList: Any = None


@dataclass(frozen=True, slots=True)
class CisInventoryState:
    requested_cis: str
    cis: str | None
    gtin: str | None
    product_name: str | None
    product_group: str | None
    owner_inn: str | None
    owner_name: str | None
    status: str | None
    status_ex: str | None
    withdraw_reason: str | None
    withdraw_reason_other: str | None
    parent: Any
    child: Any
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ProductEnrichmentState:
    gtin: str
    state: str
    product: dict[str, Any] | None


class SharedRateLimiter:
    """Deterministic spacing limiter. One shared instance caps transport to <= max_rps."""

    def __init__(
        self,
        max_rps: int = GLOBAL_TRUE_API_RPS,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(max_rps, int) or max_rps <= 0:
            raise ValueError("max_rps must be a positive integer")
        self.max_rps = max_rps
        self._interval = 1.0 / max_rps
        self._clock = clock
        self._sleeper = sleeper
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = self._clock()
            wait = max(0.0, self._next_allowed - now)
            if wait:
                self._sleeper(wait)
                now = self._clock()
            self._next_allowed = max(self._next_allowed, now) + self._interval


def _expect_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CisInventoryContractError(f"{label} must be an object")
    return dict(value)


def _expect_string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CisInventoryContractError(f"{label} must be a string")
    if not allow_empty and not value:
        raise CisInventoryContractError(f"{label} must not be empty")
    return value


def _expect_string_array(value: Any, label: str, *, max_items: int | None = None) -> list[str]:
    if not isinstance(value, list):
        raise CisInventoryContractError(f"{label} must be an array")
    if max_items is not None and len(value) > max_items:
        raise CisInventoryContractError(f"{label} exceeds max {max_items}")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_expect_string(item, f"{label}[{index}]"))
    return result


def _validate_period(value: Any, label: str) -> dict[str, Any]:
    period = _expect_object(value, label)
    # v726.0 documents only from/to. Their per-key requiredness is not proven,
    # so M1 accepts either or both but never invents another period key.
    if not period:
        raise CisInventoryContractError(f"{label} must not be empty")
    unknown = set(period) - {"from", "to"}
    if unknown:
        raise CisInventoryContractError(f"{label} has unknown fields: {sorted(unknown)}")
    for key, item in period.items():
        _expect_string(item, f"{label}.{key}")
    return period


def _validate_states(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CisInventoryContractError("filter.states must be an array")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        state = _expect_object(item, f"filter.states[{index}]")
        unknown = set(state) - {"status", "statusExt", "isStatusExtNull"}
        if unknown:
            raise CisInventoryContractError(
                f"filter.states[{index}] has unknown fields: {sorted(unknown)}"
            )
        normalized: dict[str, Any] = {}
        for key in ("status", "statusExt"):
            if key in state:
                normalized[key] = _expect_string(state[key], f"filter.states[{index}].{key}")
        if "isStatusExtNull" in state:
            if type(state["isStatusExtNull"]) is not bool:
                raise CisInventoryContractError(
                    f"filter.states[{index}].isStatusExtNull must be boolean"
                )
            normalized["isStatusExtNull"] = state["isStatusExtNull"]
        result.append(normalized)
    return result


def _validate_mods(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise CisInventoryContractError("filter.mods must be an array")
    if len(value) > 50:
        raise CisInventoryContractError("filter.mods exceeds max 50")
    result: list[dict[str, str]] = []
    for index, item in enumerate(value):
        mod = _expect_object(item, f"filter.mods[{index}]")
        unknown = set(mod) - {"kpp", "fiasId"}
        if unknown:
            raise CisInventoryContractError(
                f"filter.mods[{index}] has unknown fields: {sorted(unknown)}"
            )
        normalized: dict[str, str] = {}
        for key in ("kpp", "fiasId"):
            if key in mod:
                normalized[key] = _expect_string(mod[key], f"filter.mods[{index}].{key}")
        result.append(normalized)
    return result


def validate_search_request(value: Any) -> dict[str, Any]:
    root = _expect_object(value, "search request")
    unknown_root = set(root) - {"filter", "pagination"}
    if unknown_root:
        raise CisInventoryContractError(f"unknown search request fields: {sorted(unknown_root)}")
    if "filter" not in root:
        raise CisInventoryContractError("filter is required")
    filters = _expect_object(root["filter"], "filter")
    unknown_filters = set(filters) - _SEARCH_FILTER_FIELDS
    if unknown_filters:
        raise CisInventoryContractError(f"unknown search filters: {sorted(unknown_filters)}")
    if filters.get("productGroups") != [M1_PRODUCT_GROUP]:
        raise CisInventoryContractError('filter.productGroups must be exactly ["lp"]')

    normalized_filter: dict[str, Any] = {}
    for key, item in filters.items():
        if key in _SEARCH_STRING_ARRAY_FIELDS:
            normalized_filter[key] = _expect_string_array(item, f"filter.{key}")
        elif key in _SEARCH_BOOL_FIELDS:
            if type(item) is not bool:
                raise CisInventoryContractError(f"filter.{key} must be boolean")
            normalized_filter[key] = item
        elif key in _SEARCH_PERIOD_FIELDS:
            normalized_filter[key] = _validate_period(item, f"filter.{key}")
        elif key == "states":
            normalized_filter[key] = _validate_states(item)
        elif key == "mods":
            normalized_filter[key] = _validate_mods(item)
        elif key in {"manufacturerInns", "importerInns", "partyNumber", "tnVed", "tnVed10", "prVetDoc"}:
            # Official v726.0 keeps these singular values as strings, including
            # the plural manufacturerInns/importerInns field names.
            normalized_filter[key] = _expect_string(item, f"filter.{key}")
        else:
            raise AssertionError(key)

    normalized: dict[str, Any] = {"filter": normalized_filter}
    if "pagination" in root and root["pagination"] is not None:
        pagination = _expect_object(root["pagination"], "pagination")
        unknown = set(pagination) - {"perPage", "lastEmissionDate", "sgtin", "direction"}
        if unknown:
            raise CisInventoryContractError(f"unknown pagination fields: {sorted(unknown)}")
        if "lastEmissionDate" not in pagination or "sgtin" not in pagination:
            raise CisInventoryContractError("pagination requires lastEmissionDate and sgtin")
        per_page = pagination.get("perPage", SEARCH_DEFAULT_PER_PAGE)
        if type(per_page) is not int or not 1 <= per_page <= SEARCH_MAX_PER_PAGE:
            raise CisInventoryContractError("pagination.perPage must be 1..1000")
        direction = pagination.get("direction", 0)
        if type(direction) is not int or direction not in (0, 1):
            raise CisInventoryContractError("pagination.direction must be 0 or 1")
        normalized["pagination"] = {
            "perPage": per_page,
            "lastEmissionDate": _expect_string(pagination["lastEmissionDate"], "pagination.lastEmissionDate"),
            "sgtin": _expect_string(pagination["sgtin"], "pagination.sgtin"),
            "direction": direction,
        }
    return normalized


def validate_m1_job_payload(job_type: str, payload: Any) -> dict[str, Any]:
    if job_type not in M1_READ_JOB_TYPES:
        raise CisInventoryContractError("unsupported M1 read job type")
    root = _expect_object(payload, "read_payload")
    if job_type in {"CIS_INFO", "CIS_AGGREGATED_LIST", "CIS_TO_PRODUCT"}:
        if set(root) != {"cises"}:
            raise CisInventoryContractError(f"{job_type} payload must contain only cises")
        normalized = normalize_cises(_expect_string_array(root["cises"], "cises", max_items=MAX_BATCH))
        return {"cises": list(normalized)}
    if job_type in {"CIS_HISTORY", "CIS_AGGREGATION_HISTORY"}:
        if set(root) != {"cis"}:
            raise CisInventoryContractError(f"{job_type} payload must contain only cis")
        return {"cis": normalize_cis(_expect_string(root["cis"], "cis"))}
    if job_type == "PRODUCT_INFO":
        unknown = set(root) - {"gtins", "rdInfo"}
        if unknown or "gtins" not in root:
            raise CisInventoryContractError("PRODUCT_INFO payload allows only gtins and rdInfo")
        gtins = _expect_string_array(root["gtins"], "gtins", max_items=MAX_BATCH)
        if not 1 <= len(gtins) <= MAX_BATCH:
            raise CisInventoryContractError("product/info gtins must contain 1..1000 values")
        rd_info = root.get("rdInfo", False)
        if type(rd_info) is not bool:
            raise CisInventoryContractError("rdInfo must be boolean")
        return {"gtins": gtins, "rdInfo": rd_info}
    if job_type == "CIS_SEARCH":
        if set(root) != {"request"}:
            raise CisInventoryContractError("CIS_SEARCH payload must contain only request")
        return {"request": validate_search_request(root["request"])}
    raise AssertionError(job_type)


def build_read_spec(job_type: str, payload: Any) -> TrueApiReadSpec:
    normalized = validate_m1_job_payload(job_type, payload)
    if job_type == "CIS_INFO":
        cises = normalized["cises"]
        return TrueApiReadSpec(job_type, "POST", CIS_INFO_TARGET, cises, "/cises/info?pg=lp", len(cises))
    if job_type == "CIS_SEARCH":
        return TrueApiReadSpec(job_type, "POST", CIS_SEARCH_TARGET, normalized["request"], "/cises/search", 0)
    if job_type == "CIS_HISTORY":
        cis = normalized["cis"]
        target = CIS_HISTORY_PREFIX + quote(cis, safe="")
        return TrueApiReadSpec(job_type, "POST", target, None, "/cises/history?cis={CIS}", 1)
    if job_type == "CIS_AGGREGATED_LIST":
        cises = normalized["cises"]
        return TrueApiReadSpec(job_type, "POST", AGGREGATED_LIST_TARGET, cises, "/cises/aggregated/list?pg=lp", len(cises))
    if job_type == "CIS_AGGREGATION_HISTORY":
        return TrueApiReadSpec(job_type, "POST", AGGREGATION_HISTORY_TARGET, {"cis": normalized["cis"]}, "/cises/history/list", 1)
    if job_type == "PRODUCT_INFO":
        return TrueApiReadSpec(job_type, "POST", PRODUCT_INFO_TARGET, normalized, "/product/info", 0)
    raise CisInventoryContractError("CIS_TO_PRODUCT is a composite job and has no single request spec")


def is_allowed_read_target(spec: TrueApiReadSpec) -> bool:
    if spec.method != "POST":
        return False
    if spec.target in {
        CIS_INFO_TARGET,
        CIS_SEARCH_TARGET,
        AGGREGATED_LIST_TARGET,
        AGGREGATION_HISTORY_TARGET,
        PRODUCT_INFO_TARGET,
    }:
        return True
    if spec.job_type == "CIS_HISTORY" and spec.target.startswith(CIS_HISTORY_PREFIX):
        encoded = spec.target[len(CIS_HISTORY_PREFIX):]
        return bool(encoded) and "&" not in encoded and "#" not in encoded
    return False


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, dict) else None


def _wire_info(requested_cis: str, item: Any) -> TrueApiCisInfoWire:
    raw = _expect_object(item, "cises/info result item")
    info = _dict_or_none(raw.get("cisInfo"))
    return TrueApiCisInfoWire(
        requested_cis=requested_cis,
        cis_info=info,
        error_code=str(raw["errorCode"]) if raw.get("errorCode") is not None else None,
        error_message=str(raw["errorMessage"]) if raw.get("errorMessage") is not None else None,
        raw=raw,
    )


def _normalized_info(wire: TrueApiCisInfoWire) -> CisInventoryState | None:
    info = wire.cis_info
    if info is None:
        return None
    return CisInventoryState(
        requested_cis=wire.requested_cis,
        cis=info.get("cis"),
        gtin=info.get("gtin"),
        product_name=info.get("productName"),
        product_group=info.get("productGroup"),
        owner_inn=info.get("ownerInn"),
        owner_name=info.get("ownerName"),
        status=info.get("status"),
        status_ex=info.get("statusEx"),
        withdraw_reason=info.get("withdrawReason"),
        withdraw_reason_other=info.get("withdrawReasonOther"),
        parent=info.get("parent"),
        child=info.get("child"),
        raw=info,
    )


def parse_success_payload(job_type: str, request_payload: dict[str, Any], payload: Any) -> dict[str, Any]:
    """Parse official source-specific wire response while preserving unknown fields."""
    if job_type == "CIS_INFO":
        requested = validate_m1_job_payload(job_type, request_payload)["cises"]
        if not isinstance(payload, list):
            raise CisInventoryContractError("cises/info response must be an array")
        if len(payload) != len(requested):
            raise CisInventoryContractError("cises/info response item count mismatch")
        items = []
        for cis, raw_item in zip(requested, payload, strict=True):
            wire = _wire_info(cis, raw_item)
            normalized = _normalized_info(wire)
            items.append({
                "wire": asdict(wire),
                "normalized": asdict(normalized) if normalized else None,
                "item_error": (
                    {"code": wire.error_code, "message": wire.error_message}
                    if wire.error_code is not None or wire.error_message is not None else None
                ),
            })
        return {"type": job_type, "items": items, "partial_item_errors_supported": True}

    if job_type == "CIS_SEARCH":
        root = _expect_object(payload, "cises/search response")
        if type(root.get("isLastPage")) is not bool or not isinstance(root.get("result"), list):
            raise CisInventoryContractError("cises/search response requires isLastPage and result")
        result = []
        for item in root["result"]:
            raw = _expect_object(item, "cises/search result item")
            wire = TrueApiCisSearchWire(
                raw=raw,
                cis=raw.get("cis"),
                sgtin=raw.get("sgtin"),
                gtin=raw.get("gtin"),
                ownerInn=raw.get("ownerInn"),
                status=raw.get("status"),
                statusExt=raw.get("statusExt"),
                eliminationReason=raw.get("eliminationReason"),
            )
            result.append({
                "wire": asdict(wire),
                "normalized": {
                    "cis": wire.cis,
                    "sgtin": wire.sgtin,
                    "gtin": wire.gtin,
                    "status": wire.status,
                    "status_ext": wire.statusExt,
                    "elimination_reason": wire.eliminationReason,
                    "search_owner_inn": wire.ownerInn,
                    "owner_authoritative": False,
                },
            })
        return {
            "type": job_type,
            "isLastPage": root["isLastPage"],
            "result": result,
            "pagination": validate_m1_job_payload(job_type, request_payload)["request"].get("pagination"),
            "auto_pagination": False,
            "cursor_advancement": "UNKNOWN",
            "result_ceiling": SEARCH_RESULT_CEILING,
        }

    if job_type == "CIS_HISTORY":
        if not isinstance(payload, list):
            raise CisInventoryContractError("cises/history response must be an array")
        records = []
        for item in payload:
            raw = _expect_object(item, "cises/history item")
            wire = TrueApiCisHistoryWire(
                raw=raw,
                cis=raw.get("cis"),
                gtin=raw.get("gtin"),
                status=raw.get("status"),
                ownerInn=raw.get("ownerInn"),
                operationDate=raw.get("operationDate"),
                timestamp=raw.get("timestamp"),
            )
            records.append({"wire": asdict(wire)})
        return {"type": job_type, "history": records}

    if job_type == "CIS_AGGREGATED_LIST":
        root = _expect_object(payload, "cises/aggregated/list response")
        requested = validate_m1_job_payload(job_type, request_payload)["cises"]
        result: list[dict[str, Any]] = []
        for cis in requested:
            raw = root.get(cis, {})
            if not isinstance(raw, dict):
                raise CisInventoryContractError("aggregated/list item must be an object")
            wire = TrueApiAggregateWire(cis, dict(raw))
            result.append({"wire": asdict(wire), "direct_layer_only": True, "recursive": False})
        return {"type": job_type, "items": result}

    if job_type == "CIS_AGGREGATION_HISTORY":
        root = _expect_object(payload, "cises/history/list response")
        rows = root.get("cisAggregation")
        if not isinstance(rows, list):
            raise CisInventoryContractError("cises/history/list response requires cisAggregation array")
        result = []
        for item in rows:
            raw = _expect_object(item, "aggregation history item")
            operation_type = raw.get("operationType")
            if operation_type in {"AUTODISAGGREGATED", "AUTODISAGGREGATION"}:
                semantic = "AUTODISAGGREGATION"
            elif operation_type is None:
                semantic = None
            else:
                semantic = None
            wire = TrueApiAggregationHistoryWire(
                raw=raw,
                cis=raw.get("cis"),
                operationType=operation_type,
                operationDate=raw.get("operationDate"),
                packageType=raw.get("packageType"),
                extendedPackageType=raw.get("extendedPackageType"),
                parent=raw.get("parent"),
            )
            result.append({
                "wire": asdict(wire),
                "normalized_operation_type": semantic,
                "operation_type_known": semantic is not None,
            })
        return {"type": job_type, "cisAggregation": result, "operationDate_nullable": True}

    if job_type == "PRODUCT_INFO":
        root = _expect_object(payload, "product/info response")
        results = root.get("results")
        if not isinstance(results, list):
            raise CisInventoryContractError("product/info response requires results array")
        requested = validate_m1_job_payload(job_type, request_payload)["gtins"]
        returned: dict[str, dict[str, Any]] = {}
        parsed: list[dict[str, Any]] = []
        for item in results:
            raw = _expect_object(item, "product/info result item")
            wire = TrueApiProductInfoWire(
                raw=raw,
                gtin=raw.get("gtin"),
                name=raw.get("name"),
                brand=raw.get("brand"),
                productGroup=raw.get("productGroup"),
                goodMarkFlag=raw.get("goodMarkFlag") if type(raw.get("goodMarkFlag")) is bool else None,
                goodTurnFlag=raw.get("goodTurnFlag") if type(raw.get("goodTurnFlag")) is bool else None,
                subBrand=raw.get("subBrand"), privateBrand=raw.get("privateBrand"),
                packageType=raw.get("packageType"), innerUnitCount=raw.get("innerUnitCount"),
                model=raw.get("model"), inn=raw.get("inn"), permittedInns=raw.get("permittedInns"),
                productGroupId=raw.get("productGroupId"), goodSignedFlag=raw.get("goodSignedFlag"),
                goodStatus=raw.get("goodStatus"), isKit=raw.get("isKit"), isTechGtin=raw.get("isTechGtin"),
                isSet=raw.get("isSet"), setGtin=raw.get("setGtin"), setDescription=raw.get("setDescription"),
                level=raw.get("level"), mainGtin=raw.get("mainGtin"), multiplier=raw.get("multiplier"),
                foreignProducer=raw.get("foreignProducer"), exporter=raw.get("exporter"),
                standardNumber=raw.get("standardNumber"), tnVedCode=raw.get("tnVedCode"),
                tnVedCode10=raw.get("tnVedCode10"), fullName=raw.get("fullName"), basicUnit=raw.get("basicUnit"),
                quantityInPack=raw.get("quantityInPack"), quantityInPackType=raw.get("quantityInPackType"),
                reasonCertMissing=raw.get("reasonCertMissing"), reasonCertMissingDetails=raw.get("reasonCertMissingDetails"),
                certDocList=raw.get("certDocList"),
            )
            parsed.append({"wire": asdict(wire)})
            if wire.gtin:
                returned[str(wire.gtin)] = raw
        enrichment = [
            asdict(ProductEnrichmentState(
                gtin=gtin,
                state="RETURNED" if gtin in returned else "NOT_RETURNED_BY_PRODUCT_INFO",
                product=returned.get(gtin),
            ))
            for gtin in requested
        ]
        return {
            "type": job_type,
            "results": parsed,
            "total": root.get("total"),
            "errorCode": root.get("errorCode"),
            "requested": enrichment,
            "absence_does_not_mean_nonexistent": True,
        }
    raise CisInventoryContractError(f"no parser for {job_type}")


def parse_json_bytes(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CisInventoryContractError("successful True API response is not valid UTF-8 JSON") from exc


def _redact_secret_text(value: str) -> str:
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+\-/]+=*", "Bearer [REDACTED]", value)
    text = re.sub(r"(?i)(token|pin)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)
    text = re.sub(r"(?is)(<\s*(?:uuidtoken|token|pin)\b[^>]*>).*?(</\s*(?:uuidtoken|token|pin)\s*>)", r"\1[REDACTED]\2", text)
    return text


def safe_transport_error(http_status: int, headers: Mapping[str, str], body: bytes) -> SafeTransportError:
    body_sha = hashlib.sha256(body).hexdigest()
    content_type = next((v for k, v in headers.items() if str(k).casefold() == "content-type"), None)
    code: str | None = None
    message: str | None = None
    preview: str | None = None
    if body:
        lowered = (content_type or "").casefold()
        if "json" in lowered:
            try:
                parsed = json.loads(body.decode("utf-8"))
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                for key in _SAFE_ERROR_KEYS:
                    value = parsed.get(key)
                    if value is None:
                        continue
                    text = _redact_secret_text(str(value))
                    if key.casefold().endswith("code") and code is None:
                        code = text[:128]
                    elif message is None:
                        message = text[:500]
        else:
            text = body.decode("utf-8", errors="replace")
            # Bounded diagnostic only; never persist bearer-like strings.
            text = _redact_secret_text(text)
            preview = text[:500]
            message = preview or None
    if http_status == 406 and not body:
        message = "HTTP 406 with empty body"
    return SafeTransportError(
        http_status=http_status,
        content_type=content_type,
        safe_error_code=code,
        safe_error_message=message,
        body_sha256=body_sha,
        raw_body_preview=preview,
    )


def build_cis_to_product_info_request(cis_info_payload: Any, requested_cises: Iterable[str]) -> tuple[dict[str, Any], list[str]]:
    requested = list(normalize_cises(requested_cises))
    parsed = parse_success_payload("CIS_INFO", {"cises": requested}, cis_info_payload)
    gtins: list[str] = []
    seen: set[str] = set()
    for item in parsed["items"]:
        normalized = item.get("normalized")
        gtin = normalized.get("gtin") if isinstance(normalized, dict) else None
        if isinstance(gtin, str) and gtin and gtin not in seen:
            seen.add(gtin)
            gtins.append(gtin)
    return parsed, gtins
