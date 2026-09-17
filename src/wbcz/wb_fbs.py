from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PRODUCTION_WB_WRITE_ENABLED = False
AUTO_DISTANCE_READY_ENABLED = False
PAID_SOURCE_CONTRACT_PINNED = False
WB_API_SGTIN_AUTOBIND_ENABLED = False
FRONTEND_FREEZE_ACTIVE = True

MARKETPLACE_PROD_HOST = "marketplace-api.wildberries.ru"
ANALYTICS_PROD_HOST = "seller-analytics-api.wildberries.ru"
STATISTICS_PROD_HOST = "statistics-api.wildberries.ru"
COMMON_PROD_HOST = "common-api.wildberries.ru"
MARKETPLACE_SANDBOX_HOST = "marketplace-api-sandbox.wildberries.ru"
STATISTICS_SANDBOX_HOST = "statistics-api-sandbox.wildberries.ru"

CURRENT_MAX_WINDOW_DAYS = 30
ORDER_FEED_MAX_WINDOW_DAYS = 31
GOODS_RETURN_MAX_WINDOW_DAYS = 31
SUPPLIER_SALES_GUARANTEED_STORAGE_DAYS = 90
WB_MARKING_VAULT_FORMAT = "M9_AES256_GCM_V1"


class WbError(RuntimeError):
    pass


class WbContractError(WbError):
    pass


class WbSecurityError(WbError):
    pass


class WbCapabilityDisabled(WbError):
    pass


def _opaque(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or not value.strip():
        raise WbContractError(f"{field} must be a non-empty opaque string")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise WbContractError("timezone-aware datetime required")
    return value.astimezone(timezone.utc)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_hash(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()
    return _sha(raw)


class WbEnvironment(str, Enum):
    PRODUCTION = "PRODUCTION"
    SANDBOX = "SANDBOX"


class WbTokenType(str, Enum):
    PERSONAL = "PERSONAL"
    TEST = "TEST"
    SERVICE = "SERVICE"
    BASE = "BASE"
    BASE_WITH_SECRET = "BASE_WITH_SECRET"


class WbTokenCategory(str, Enum):
    MARKETPLACE = "MARKETPLACE"
    ANALYTICS = "ANALYTICS"
    STATISTICS = "STATISTICS"
    COMMON = "COMMON"
    ANY = "ANY"


class WbConnectionState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    HEALTHY = "HEALTHY"
    CONNECTION_BLOCKED = "CONNECTION_BLOCKED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class WbConnection:
    environment: WbEnvironment
    participant_inn: str
    secret_ref: str
    token_type: WbTokenType
    token_categories: tuple[WbTokenCategory, ...]
    wb_sid: str | None = None
    wb_tin: str | None = None
    token_expires_at: datetime | None = None
    rate_profile: str | None = None
    connection_state: WbConnectionState = WbConnectionState.UNVERIFIED

    def __post_init__(self) -> None:
        _opaque(self.participant_inn, "participant_inn")
        _opaque(self.secret_ref, "secret_ref")
        if self.environment is WbEnvironment.PRODUCTION and self.token_type is WbTokenType.TEST:
            raise WbContractError("TEST token is sandbox-only")
        if self.environment is WbEnvironment.SANDBOX and self.token_type is not WbTokenType.TEST:
            raise WbContractError("sandbox requires TEST token")


class WbSecretProvider(Protocol):
    def get_secret(self, secret_ref: str) -> str: ...


class WbRuntimeToken:
    __slots__ = ("_secret", "secret_ref", "token_type", "categories")

    def __init__(self, secret: str, *, secret_ref: str, token_type: WbTokenType, categories: Sequence[WbTokenCategory]) -> None:
        self._secret = _opaque(secret, "WB token")
        self.secret_ref = _opaque(secret_ref, "secret_ref")
        self.token_type = token_type
        self.categories = tuple(categories)

    def _auth(self) -> str:
        return self._secret

    def __repr__(self) -> str:
        return f"WbRuntimeToken(secret=<REDACTED>, secret_ref={self.secret_ref!r}, token_type={self.token_type.value!r})"

    __str__ = __repr__


def runtime_token(connection: WbConnection, provider: WbSecretProvider) -> WbRuntimeToken:
    return WbRuntimeToken(
        provider.get_secret(connection.secret_ref),
        secret_ref=connection.secret_ref,
        token_type=connection.token_type,
        categories=connection.token_categories,
    )


@dataclass(frozen=True, slots=True)
class SellerIdentity:
    sid: str
    tin: str
    name: str | None = None
    trade_mark: str | None = None


def verify_seller_identity(connection: WbConnection, payload: Mapping[str, object]) -> tuple[WbConnection, SellerIdentity]:
    identity = SellerIdentity(
        sid=_opaque(str(payload.get("sid", "")), "sid"),
        tin=_opaque(str(payload.get("tin", "")), "tin"),
        name=str(payload["name"]) if payload.get("name") is not None else None,
        trade_mark=str(payload["tradeMark"]) if payload.get("tradeMark") is not None else None,
    )
    state = WbConnectionState.HEALTHY if identity.tin == connection.participant_inn else WbConnectionState.CONNECTION_BLOCKED
    return replace(connection, wb_sid=identity.sid, wb_tin=identity.tin, connection_state=state), identity


class WbCapabilityName(str, Enum):
    FBS_NEW = "FBS_NEW"
    FBS_CURRENT = "FBS_CURRENT"
    FBS_ARCHIVE = "FBS_ARCHIVE"
    ORDER_STATUS = "ORDER_STATUS"
    ORDER_META = "ORDER_META"
    SUPPLIES = "SUPPLIES"
    SUPPLY = "SUPPLY"
    SUPPLY_ORDER_IDS = "SUPPLY_ORDER_IDS"
    ORDER_FEED = "ORDER_FEED"
    GOODS_RETURN = "GOODS_RETURN"
    SELLER_INFO = "SELLER_INFO"
    SUPPLIER_SALES_COMPAT = "SUPPLIER_SALES_COMPAT"


@dataclass(frozen=True, slots=True)
class WbReadCapability:
    name: WbCapabilityName
    family: str
    host: str
    method: str
    path_template: str
    auth_category: WbTokenCategory
    production: bool
    sandbox: bool
    rate_family: str
    read_only: bool = True


WB_READ_CAPABILITIES: Mapping[WbCapabilityName, WbReadCapability] = {
    WbCapabilityName.FBS_NEW: WbReadCapability(WbCapabilityName.FBS_NEW, "MARKETPLACE", MARKETPLACE_PROD_HOST, "GET", "/api/v3/orders/new", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.FBS_CURRENT: WbReadCapability(WbCapabilityName.FBS_CURRENT, "MARKETPLACE", MARKETPLACE_PROD_HOST, "GET", "/api/v3/orders", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.FBS_ARCHIVE: WbReadCapability(WbCapabilityName.FBS_ARCHIVE, "MARKETPLACE", MARKETPLACE_PROD_HOST, "GET", "/api/marketplace/v3/fbs/orders/archive", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.ORDER_STATUS: WbReadCapability(WbCapabilityName.ORDER_STATUS, "MARKETPLACE", MARKETPLACE_PROD_HOST, "POST", "/api/v3/orders/status", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.ORDER_META: WbReadCapability(WbCapabilityName.ORDER_META, "MARKETPLACE", MARKETPLACE_PROD_HOST, "POST", "/api/marketplace/v3/orders/meta", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.SUPPLIES: WbReadCapability(WbCapabilityName.SUPPLIES, "MARKETPLACE", MARKETPLACE_PROD_HOST, "GET", "/api/v3/supplies", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.SUPPLY: WbReadCapability(WbCapabilityName.SUPPLY, "MARKETPLACE", MARKETPLACE_PROD_HOST, "GET", "/api/v3/supplies/{supplyId}", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.SUPPLY_ORDER_IDS: WbReadCapability(WbCapabilityName.SUPPLY_ORDER_IDS, "MARKETPLACE", MARKETPLACE_PROD_HOST, "GET", "/api/marketplace/v3/supplies/{supplyId}/order-ids", WbTokenCategory.MARKETPLACE, True, True, "MARKETPLACE_FBS"),
    WbCapabilityName.ORDER_FEED: WbReadCapability(WbCapabilityName.ORDER_FEED, "ANALYTICS", ANALYTICS_PROD_HOST, "POST", "/api/analytics/v1/order-feed", WbTokenCategory.ANALYTICS, True, False, "ORDER_FEED"),
    WbCapabilityName.GOODS_RETURN: WbReadCapability(WbCapabilityName.GOODS_RETURN, "ANALYTICS", ANALYTICS_PROD_HOST, "GET", "/api/v1/analytics/goods-return", WbTokenCategory.ANALYTICS, True, False, "GOODS_RETURN"),
    WbCapabilityName.SELLER_INFO: WbReadCapability(WbCapabilityName.SELLER_INFO, "COMMON", COMMON_PROD_HOST, "GET", "/api/v1/seller-info", WbTokenCategory.ANY, True, False, "SELLER_INFO"),
    WbCapabilityName.SUPPLIER_SALES_COMPAT: WbReadCapability(WbCapabilityName.SUPPLIER_SALES_COMPAT, "STATISTICS", STATISTICS_PROD_HOST, "GET", "/api/v1/supplier/sales", WbTokenCategory.STATISTICS, True, True, "SUPPLIER_SALES"),
}

WB_MUTATION_CAPABILITIES = {
    name: {"enabled": False, "disabled_reason": "M9_READ_ONLY_SCOPE"}
    for name in (
        "PUT_ORDER_SGTIN", "DELETE_ORDER_META", "CANCEL_ORDER", "UPDATE_ORDER_STATUS",
        "CREATE_SUPPLY", "ADD_ORDER_TO_SUPPLY", "REMOVE_ORDER_FROM_SUPPLY", "DELIVER_SUPPLY", "CLAIM_DECISION",
    )
}


@dataclass(frozen=True, slots=True)
class FbsCurrentQuery:
    limit: int
    next_cursor: int = 0
    date_from: int | None = None
    date_to: int | None = None

    def params(self) -> dict[str, object]:
        if type(self.limit) is not int or not 1 <= self.limit <= 1000:
            raise WbContractError("limit must be 1..1000")
        if type(self.next_cursor) is not int or self.next_cursor < 0:
            raise WbContractError("next must be >=0")
        if (self.date_from is None) != (self.date_to is None):
            raise WbContractError("dateFrom/dateTo must be paired")
        out: dict[str, object] = {"limit": self.limit, "next": self.next_cursor}
        if self.date_from is not None:
            if type(self.date_from) is not int or type(self.date_to) is not int:
                raise WbContractError("dateFrom/dateTo must be Unix UTC integers")
            if self.date_to < self.date_from or self.date_to - self.date_from > CURRENT_MAX_WINDOW_DAYS * 86400:
                raise WbContractError("current window exceeds 30 days")
            out.update({"dateFrom": self.date_from, "dateTo": self.date_to})
        return out


@dataclass(frozen=True, slots=True)
class FbsArchiveQuery:
    year: int
    month: int
    limit: int
    next_cursor: int = 0

    def params(self) -> dict[str, object]:
        if type(self.year) is not int or type(self.month) is not int or not 1 <= self.month <= 12:
            raise WbContractError("archive year/month invalid")
        if type(self.limit) is not int or not 100 <= self.limit <= 1000:
            raise WbContractError("archive limit must be 100..1000")
        if type(self.next_cursor) is not int or self.next_cursor < 0:
            raise WbContractError("archive next invalid")
        return {"year": self.year, "month": self.month, "limit": self.limit, "next": self.next_cursor}


@dataclass(frozen=True, slots=True)
class OrderFeedQuery:
    start: datetime
    end: datetime
    snapshot_time: str | None = None
    offset: int = 0
    limit: int | None = None
    nm_ids: tuple[int, ...] = ()
    subject_ids: tuple[int, ...] = ()
    brand_names: tuple[str, ...] = ()
    tag_ids: tuple[int, ...] = ()

    def body(self) -> dict[str, object]:
        start, end = _utc(self.start), _utc(self.end)
        if end < start or end - start > timedelta(days=ORDER_FEED_MAX_WINDOW_DAYS):
            raise WbContractError("order-feed period exceeds 31 days")
        if type(self.offset) is not int or self.offset < 0:
            raise WbContractError("offset must be >=0")
        if self.limit is not None and (type(self.limit) is not int or self.limit <= 0):
            raise WbContractError("limit must be positive")
        pagination: dict[str, object] = {"offset": self.offset}
        if self.snapshot_time is not None:
            pagination["snapshotTime"] = _opaque(self.snapshot_time, "snapshotTime")
        if self.limit is not None:
            pagination["limit"] = self.limit
        filters: dict[str, object] = {}
        if self.nm_ids: filters["nmIds"] = list(self.nm_ids)
        if self.subject_ids: filters["subjectIds"] = list(self.subject_ids)
        if self.brand_names: filters["brandNames"] = list(self.brand_names)
        if self.tag_ids: filters["tagIds"] = list(self.tag_ids)
        out: dict[str, object] = {
            "selectedPeriod": {"start": start.isoformat().replace("+00:00", "Z"), "end": end.isoformat().replace("+00:00", "Z")},
            "pagination": pagination,
        }
        if filters: out["filters"] = filters
        return out


@dataclass(frozen=True, slots=True)
class GoodsReturnQuery:
    start: datetime
    end: datetime

    def params(self) -> dict[str, object]:
        start, end = _utc(self.start), _utc(self.end)
        if end < start or end - start > timedelta(days=GOODS_RETURN_MAX_WINDOW_DAYS):
            raise WbContractError("goods-return period exceeds 31 days")
        return {"dateFrom": start.isoformat().replace("+00:00", "Z"), "dateTo": end.isoformat().replace("+00:00", "Z")}


@dataclass(frozen=True, slots=True)
class SupplierSalesQuery:
    date_from: str
    flag: int = 0

    def params(self) -> dict[str, object]:
        _opaque(self.date_from, "dateFrom")
        if self.flag not in {0, 1}:
            raise WbContractError("flag must be 0 or 1")
        return {"dateFrom": self.date_from, "flag": self.flag}


@dataclass(frozen=True, slots=True)
class WbHttpResponse:
    status_code: int
    content_type: str
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class WbHttpAdapter(Protocol):
    def send(self, *, method: str, url: str, headers: Mapping[str, str], params: Mapping[str, object] | None, json_body: object | None) -> WbHttpResponse: ...


class WbReadTransport:
    def __init__(self, adapter: WbHttpAdapter, environment: WbEnvironment) -> None:
        self._adapter = adapter
        self._environment = environment

    def _dispatch(self, cap_name: WbCapabilityName, token: WbRuntimeToken, *, path_values: Mapping[str, str] | None = None, params: Mapping[str, object] | None = None, json_body: object | None = None) -> WbHttpResponse:
        cap = WB_READ_CAPABILITIES[cap_name]
        if not cap.read_only:
            raise WbSecurityError("write capability rejected")
        if self._environment is WbEnvironment.SANDBOX:
            if token.token_type is not WbTokenType.TEST or not cap.sandbox:
                raise WbSecurityError("sandbox capability/token rejected")
            host = MARKETPLACE_SANDBOX_HOST if cap.family == "MARKETPLACE" else STATISTICS_SANDBOX_HOST
        else:
            if token.token_type is WbTokenType.TEST or not cap.production:
                raise WbSecurityError("production capability/token rejected")
            host = cap.host
        if cap.auth_category is not WbTokenCategory.ANY and cap.auth_category not in token.categories:
            raise WbSecurityError("token category mismatch")
        path = cap.path_template
        for key, value in (path_values or {}).items():
            safe = _opaque(value, key)
            if any(x in safe for x in ("/", "?", "#")):
                raise WbContractError("invalid typed path identifier")
            path = path.replace("{" + key + "}", safe)
        if "{" in path:
            raise WbContractError("unresolved typed path")
        headers = {"Authorization": token._auth(), "Accept": "application/json"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        return self._adapter.send(method=cap.method, url=f"https://{host}{path}", headers=headers, params=params or {}, json_body=json_body)

    def fbs_new(self, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.FBS_NEW, token)

    def fbs_current(self, q: FbsCurrentQuery, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.FBS_CURRENT, token, params=q.params())

    def fbs_archive(self, q: FbsArchiveQuery, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.FBS_ARCHIVE, token, params=q.params())

    def order_status(self, ids: Sequence[int], token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.ORDER_STATUS, token, json_body={"orders": _order_ids(ids)})

    def order_meta(self, ids: Sequence[int], token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.ORDER_META, token, json_body={"orders": _order_ids(ids, 100)})

    def supplies(self, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.SUPPLIES, token)

    def supply(self, supply_id: str, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.SUPPLY, token, path_values={"supplyId": supply_id})

    def supply_order_ids(self, supply_id: str, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.SUPPLY_ORDER_IDS, token, path_values={"supplyId": supply_id})

    def order_feed(self, q: OrderFeedQuery, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.ORDER_FEED, token, json_body=q.body())

    def goods_return(self, q: GoodsReturnQuery, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.GOODS_RETURN, token, params=q.params())

    def seller_info(self, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.SELLER_INFO, token)

    def supplier_sales(self, q: SupplierSalesQuery, token: WbRuntimeToken) -> WbHttpResponse:
        return self._dispatch(WbCapabilityName.SUPPLIER_SALES_COMPAT, token, params=q.params())


def _order_ids(ids: Sequence[int], max_count: int = 1000) -> list[int]:
    out = list(ids)
    if not out or len(out) > max_count or any(type(x) is not int or x <= 0 for x in out):
        raise WbContractError("assembly order ids invalid")
    return out


@dataclass(frozen=True, slots=True)
class RateRule:
    period_seconds: int
    limit: int
    interval_seconds: float
    burst: int
    four_x_weight: int = 1


RATE_RULES: Mapping[tuple[str, WbTokenType], RateRule] = {
    **{("MARKETPLACE_FBS", t): RateRule(60, 300, 0.2, 20, 10) for t in (WbTokenType.PERSONAL, WbTokenType.SERVICE, WbTokenType.BASE, WbTokenType.BASE_WITH_SECRET)},
    **{("ORDER_FEED", t): RateRule(60, 1, 60.0, 1) for t in (WbTokenType.PERSONAL, WbTokenType.SERVICE, WbTokenType.BASE_WITH_SECRET)},
    ("ORDER_FEED", WbTokenType.BASE): RateRule(10800, 1, 10800.0, 1),
    **{("SUPPLIER_SALES", t): RateRule(60, 1, 60.0, 1) for t in (WbTokenType.PERSONAL, WbTokenType.SERVICE, WbTokenType.BASE_WITH_SECRET)},
    ("SUPPLIER_SALES", WbTokenType.BASE): RateRule(7200, 1, 7200.0, 1),
    **{("GOODS_RETURN", t): RateRule(60, 1, 60.0, 10) for t in (WbTokenType.PERSONAL, WbTokenType.SERVICE, WbTokenType.BASE_WITH_SECRET)},
    ("GOODS_RETURN", WbTokenType.BASE): RateRule(3600, 2, 1800.0, 1),
    **{("SELLER_INFO", t): RateRule(60, 1, 60.0, 10) for t in (WbTokenType.PERSONAL, WbTokenType.SERVICE, WbTokenType.BASE, WbTokenType.BASE_WITH_SECRET, WbTokenType.TEST)},
}


class WbRateLimiter:
    def rule(self, family: str, token_type: WbTokenType, environment: WbEnvironment) -> RateRule:
        if environment is WbEnvironment.SANDBOX and family == "MARKETPLACE_FBS":
            return RateRule(1, 1, 1.0, 1)
        try:
            return RATE_RULES[(family, token_type)]
        except KeyError as exc:
            raise WbContractError("accepted rate rule unavailable") from exc

    @staticmethod
    def response_weight(family: str, status_code: int, environment: WbEnvironment) -> int:
        return 10 if environment is WbEnvironment.PRODUCTION and family == "MARKETPLACE_FBS" and 400 <= status_code <= 499 else 1


SENSITIVE_KEYS = frozenset({"authorization", "token", "secret", "sgtin", "cis", "kiz", "marking", "marking_code", "signature", "pin", "private_key"})


def redact_mapping(value: Mapping[str, object]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, item in value.items():
        if key.lower() in SENSITIVE_KEYS:
            out[key] = "REDACTED"
        elif isinstance(item, Mapping):
            out[key] = redact_mapping(item)
        elif isinstance(item, list):
            out[key] = [redact_mapping(v) if isinstance(v, Mapping) else v for v in item]
        else:
            out[key] = item
    return out


@dataclass(frozen=True, slots=True)
class WbErrorEvidence:
    http_status: int
    content_type: str
    code: str | None
    message: str | None
    title: str | None
    detail: str | None
    request_id: str | None
    origin: str | None
    status_text: str | None
    timestamp: str | None
    raw_sanitized: object
    known_format: bool


def parse_wb_error(response: WbHttpResponse, *, secret_canaries: Sequence[str] = ()) -> WbErrorEvidence:
    text = response.body.decode("utf-8", errors="replace")
    for secret in secret_canaries:
        if secret:
            text = text.replace(secret, "REDACTED")
    ctype = response.content_type.split(";", 1)[0].lower().strip()
    known = ctype in {"application/json", "application/problem+json"}
    try:
        payload = json.loads(text) if known else {"raw": text[:8192]}
    except json.JSONDecodeError:
        payload, known = {"raw": text[:8192]}, False
    safe = redact_mapping(payload) if isinstance(payload, Mapping) else {"raw": str(payload)[:8192]}
    def pick(*keys: str) -> str | None:
        for key in keys:
            if safe.get(key) is not None:
                return str(safe[key])
        return None
    return WbErrorEvidence(response.status_code, response.content_type, pick("code"), pick("message"), pick("title"), pick("detail"), pick("requestId", "request_id"), pick("origin"), pick("statusText", "status"), pick("timestamp"), safe, known)


class WbEvidenceSource(str, Enum):
    WB_API = "WB_API"
    WB_XLSX = "WB_XLSX"


class FulfillmentModel(str, Enum):
    FBS = "FBS"
    FBO = "FBO"
    FBW = "FBW"
    DBS = "DBS"
    DBW = "DBW"


def require_fbs(model: FulfillmentModel) -> None:
    if model is not FulfillmentModel.FBS:
        raise WbContractError("M9 is FBS-only")


@dataclass(frozen=True, slots=True)
class FbsOrderIdentity:
    connection_id: int
    assembly_order_id: int
    order_uid: str | None = None
    rid: str | None = None
    srid: str | None = None

    def __post_init__(self) -> None:
        if type(self.connection_id) is not int or self.connection_id <= 0:
            raise WbContractError("connection_id invalid")
        if type(self.assembly_order_id) is not int or self.assembly_order_id <= 0:
            raise WbContractError("assembly_order_id invalid")


def rid_srid_equality_is_join_rule() -> bool:
    return False


KNOWN_ORDER_FEED_STATUSES = frozenset({"cancel"})
KNOWN_ORDER_FEED_CANCEL_TYPES = frozenset({"app"})


@dataclass(frozen=True, slots=True)
class RawWbValue:
    raw: str
    known: bool


def parse_order_feed_status(value: object) -> RawWbValue:
    raw = "" if value is None else str(value)
    return RawWbValue(raw, raw in KNOWN_ORDER_FEED_STATUSES)


def parse_order_feed_cancel_type(value: object) -> RawWbValue:
    raw = "" if value is None else str(value)
    return RawWbValue(raw, raw in KNOWN_ORDER_FEED_CANCEL_TYPES)


@dataclass(frozen=True, slots=True)
class OrderFeedCycle:
    connection_id: int
    period_start: datetime
    period_end: datetime
    cycle_id: str
    snapshot_time: str | None = None
    offset: int = 0
    last_committed_page: int = -1
    last_success_at: datetime | None = None

    def establish_snapshot(self, snapshot_time: str) -> "OrderFeedCycle":
        if self.snapshot_time is not None and self.snapshot_time != snapshot_time:
            raise WbContractError("snapshotTime changed inside cycle")
        return replace(self, snapshot_time=_opaque(snapshot_time, "snapshotTime"))

    def commit_page(self, *, next_offset: int, page: int, durable_batch_committed: bool, now: datetime) -> "OrderFeedCycle":
        if not durable_batch_committed:
            return self
        if self.snapshot_time is None:
            raise WbContractError("snapshotTime must be established")
        return replace(self, offset=next_offset, last_committed_page=page, last_success_at=_utc(now))

    def restart(self, new_cycle_id: str) -> "OrderFeedCycle":
        return OrderFeedCycle(self.connection_id, self.period_start, self.period_end, _opaque(new_cycle_id, "cycle_id"))


@dataclass(frozen=True, slots=True)
class CurrentCursor:
    connection_id: int
    date_from: int
    date_to: int
    next_cursor: int = 0

    def commit(self, response_next: int, *, durable_batch_committed: bool) -> "CurrentCursor":
        return replace(self, next_cursor=response_next) if durable_batch_committed else self


@dataclass(frozen=True, slots=True)
class ArchiveCursor:
    connection_id: int
    year: int
    month: int
    next_cursor: int = 0
    overlap_required: bool = True

    def commit(self, response_next: int, *, durable_batch_committed: bool) -> "ArchiveCursor":
        return replace(self, next_cursor=response_next) if durable_batch_committed else self


@dataclass(frozen=True, slots=True)
class TransitionOverlapPolicy:
    enabled: bool = True
    current_disappearance_means_cancel: bool = False
    archive_absence_means_delete: bool = False
    archive_conflict_overwrites_current: bool = False


CURRENT_ARCHIVE_TRANSITION_POLICY = TransitionOverlapPolicy()
SUPPLIER_SALES_ROLE = "TEMPORARY_PAYMENT_CONFIRMATION_COMPATIBILITY_EVIDENCE"
SUPPLIER_SALES_DEPRECATION_STATE = ("CURRENTLY_CALLABLE", "FUTURE_SHUTDOWN_ANNOUNCED")


@dataclass(frozen=True, slots=True)
class PaidAmountEvidence:
    source: str
    raw_amount: object
    currency: str | None
    scale: int | None
    observed_at: datetime
    contract_status: str = "CONTRACT_NOT_PINNED"


@dataclass(frozen=True, slots=True)
class MetaDetailsEvidence:
    raw_sanitized: Mapping[str, object]
    legacy_meta_present: bool


def parse_meta_details(payload: Mapping[str, object]) -> MetaDetailsEvidence:
    details = payload.get("metaDetails")
    safe = redact_mapping(details) if isinstance(details, Mapping) else {"value": details}
    return MetaDetailsEvidence(safe, "meta" in payload)


def mask_marking(value: str) -> str:
    return "*" * max(0, len(value) - 4) + value[-4:]


class MarkingValidationState(str, Enum):
    CANDIDATE = "CANDIDATE"
    M1_VERIFIED = "M1_VERIFIED"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


class MarkingConflictState(str, Enum):
    NONE = "NONE"
    CONFLICT = "CONFLICT"
    MULTIPLE_CANDIDATES = "MULTIPLE_CANDIDATES"
    LIVE_ORDER_REUSE = "LIVE_ORDER_REUSE"


@dataclass(frozen=True, slots=True)
class MarkingBinding:
    connection_id: int
    assembly_order_id: int
    source: WbEvidenceSource
    observed_at: datetime


class MarkingKeyProvider(Protocol):
    def get_key(self, key_version: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class MarkingEnvelope:
    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    auth_tag: bytes = field(repr=False)
    key_version: str
    vault_format: str
    aad_hash: str
    fingerprint_sha256: str
    masked_value: str
    source: WbEvidenceSource
    observed_at: datetime
    validation_state: MarkingValidationState
    conflict_state: MarkingConflictState

    def __repr__(self) -> str:
        return f"MarkingEnvelope(value=<REDACTED>, key_version={self.key_version!r}, fingerprint_sha256={self.fingerprint_sha256!r}, masked_value={self.masked_value!r})"


class MarkingVault:
    def __init__(self, provider: MarkingKeyProvider, key_version: str) -> None:
        self._provider = provider
        self._key_version = _opaque(key_version, "key_version")

    @staticmethod
    def _aad(binding: MarkingBinding, fingerprint: str) -> bytes:
        return json.dumps({"connection_id": binding.connection_id, "assembly_order_id": binding.assembly_order_id, "source": binding.source.value, "fingerprint": fingerprint, "vault_format": WB_MARKING_VAULT_FORMAT}, sort_keys=True, separators=(",", ":")).encode()

    def encrypt(self, exact_value: str, *, binding: MarkingBinding, validation_state: MarkingValidationState = MarkingValidationState.CANDIDATE, conflict_state: MarkingConflictState = MarkingConflictState.NONE) -> MarkingEnvelope:
        raw = _opaque(exact_value, "marking").encode()
        key = self._provider.get_key(self._key_version)
        if len(key) != 32:
            raise WbSecurityError("AES-256 key required")
        fingerprint = _sha(raw)
        aad = self._aad(binding, fingerprint)
        nonce = os.urandom(12)
        encrypted = AESGCM(key).encrypt(nonce, raw, aad)
        return MarkingEnvelope(encrypted[:-16], nonce, encrypted[-16:], self._key_version, WB_MARKING_VAULT_FORMAT, _sha(aad), fingerprint, mask_marking(exact_value), binding.source, _utc(binding.observed_at), validation_state, conflict_state)

    def decrypt(self, envelope: MarkingEnvelope, *, binding: MarkingBinding) -> str:
        key = self._provider.get_key(envelope.key_version)
        aad = self._aad(binding, envelope.fingerprint_sha256)
        if _sha(aad) != envelope.aad_hash:
            raise WbSecurityError("AAD mismatch")
        try:
            raw = AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext + envelope.auth_tag, aad)
        except InvalidTag as exc:
            raise WbSecurityError("marking authentication failed") from exc
        if _sha(raw) != envelope.fingerprint_sha256:
            raise WbSecurityError("marking fingerprint mismatch")
        return raw.decode()


class M9Decision(str, Enum):
    NO_ACTION = "NO_ACTION"
    CIS_PREFLIGHT = "CIS_PREFLIGHT"
    WAIT_FOR_EVIDENCE = "WAIT_FOR_EVIDENCE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    DISTANCE_READY = "DISTANCE_READY"
    REMOTE_SALE_RETURN_READY = "REMOTE_SALE_RETURN_READY"


class M9ReconciliationState(str, Enum):
    WB_ORDER_DISCOVERED = "WB_ORDER_DISCOVERED"
    WB_CIS_MISSING = "WB_CIS_MISSING"
    WB_CIS_CAPTURED = "WB_CIS_CAPTURED"
    WB_CIS_VERIFIED = "WB_CIS_VERIFIED"
    WB_SALE_PENDING = "WB_SALE_PENDING"
    WB_SALE_CONFIRMED = "WB_SALE_CONFIRMED"
    DISTANCE_PENDING = "DISTANCE_PENDING"
    DISTANCE_SUBMITTED = "DISTANCE_SUBMITTED"
    DISTANCE_RECONCILED = "DISTANCE_RECONCILED"
    WB_RETURN_PENDING = "WB_RETURN_PENDING"
    WB_ITEM_RETURNED = "WB_ITEM_RETURNED"
    REMOTE_RETURN_PENDING = "REMOTE_RETURN_PENDING"
    REMOTE_RETURN_RECONCILED = "REMOTE_RETURN_RECONCILED"
    CANCELLED_NO_MARKING_ACTION = "CANCELLED_NO_MARKING_ACTION"
    MANUAL_REVIEW = "MANUAL_REVIEW"


def decide_cis_cardinality(values: Sequence[str], *, deterministic_validated_count: int, reused_on_live_order: bool = False) -> M9Decision:
    if reused_on_live_order or len(values) > 1:
        return M9Decision.MANUAL_REVIEW
    if not values:
        return M9Decision.WAIT_FOR_EVIDENCE
    return M9Decision.CIS_PREFLIGHT if deterministic_validated_count == 1 else M9Decision.MANUAL_REVIEW


def reconcile_source_marking(api_fp: str | None, xlsx_fp: str | None, *, identity_conflict: bool = False) -> M9Decision:
    if identity_conflict:
        return M9Decision.MANUAL_REVIEW
    if api_fp and xlsx_fp and api_fp != xlsx_fp:
        return M9Decision.MANUAL_REVIEW
    if api_fp or xlsx_fp:
        return M9Decision.CIS_PREFLIGHT
    return M9Decision.WAIT_FOR_EVIDENCE


class TimestampSemantics(str, Enum):
    OFFSET_EXPLICIT = "OFFSET_EXPLICIT"
    TIMEZONE_UNKNOWN = "TIMEZONE_UNKNOWN"


@dataclass(frozen=True, slots=True)
class ParsedTimestamp:
    raw: str | None
    parsed: datetime | None
    semantics: TimestampSemantics


def parse_goods_return_timestamp(raw: str | None) -> ParsedTimestamp:
    if not raw or not re.search(r"(Z|[+-]\d\d:\d\d)$", raw):
        return ParsedTimestamp(raw, None, TimestampSemantics.TIMEZONE_UNKNOWN)
    candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return ParsedTimestamp(raw, None, TimestampSemantics.TIMEZONE_UNKNOWN)
    return ParsedTimestamp(raw, dt if dt.tzinfo is not None else None, TimestampSemantics.OFFSET_EXPLICIT if dt.tzinfo is not None else TimestampSemantics.TIMEZONE_UNKNOWN)


def evaluate_distance_candidate(*, marketplace_sold: bool, supplier_sales_match: bool, m1_ok: bool, m2_ok: bool, m6_safe: bool, duplicate_completed_m5: bool, identity_conflict: bool) -> M9Decision:
    if identity_conflict or not m1_ok or not m2_ok or not m6_safe:
        return M9Decision.MANUAL_REVIEW
    if duplicate_completed_m5:
        return M9Decision.NO_ACTION
    if not marketplace_sold or not supplier_sales_match:
        return M9Decision.WAIT_FOR_EVIDENCE
    if not PAID_SOURCE_CONTRACT_PINNED or not AUTO_DISTANCE_READY_ENABLED:
        return M9Decision.WAIT_FOR_EVIDENCE
    return M9Decision.DISTANCE_READY


def evaluate_remote_sale_return_candidate(*, previous_distance_reconciled: bool, completed_dt_present: bool, deterministic_cis: bool, m1_fresh_ok: bool, m1_return_state_ok: bool, m2_ok: bool, m6_safe: bool, duplicate_completed_return: bool, identity_conflict: bool) -> M9Decision:
    if identity_conflict:
        return M9Decision.MANUAL_REVIEW
    if not completed_dt_present or not previous_distance_reconciled:
        return M9Decision.WAIT_FOR_EVIDENCE
    if duplicate_completed_return:
        return M9Decision.NO_ACTION
    if not deterministic_cis or not (m1_fresh_ok and m1_return_state_ok and m2_ok and m6_safe):
        return M9Decision.MANUAL_REVIEW
    return M9Decision.REMOTE_SALE_RETURN_READY


def cancellation_decision(case: str, *, prior_confirmed_sale: bool, existing_distance: bool = False) -> M9Decision:
    no_action = {"seller_cancel_before_sale", "buyer_early_cancel", "declined_by_client_before_sale", "pickup_refusal", "canceled_by_client", "defect_refusal"}
    if case in no_action and not prior_confirmed_sale:
        return M9Decision.NO_ACTION
    if case in {"handover", "sorted", "delivery", "return_requested", "return_in_transit", "ready_to_seller"}:
        return M9Decision.WAIT_FOR_EVIDENCE
    if case == "physically_returned_completed_dt":
        return M9Decision.MANUAL_REVIEW if existing_distance else M9Decision.CIS_PREFLIGHT
    return M9Decision.MANUAL_REVIEW


class M1PreflightAdapter(Protocol):
    def lookup_cis(self, working_copy: str) -> object: ...


class M2PreflightAdapter(Protocol):
    def lookup_product(self, gtin: str) -> object: ...


class M6AggregateAdapter(Protocol):
    def relation_for_cis(self, cis: str) -> object: ...


class M5DecisionAdapter(Protocol):
    def prepare_distance_decision(self, evidence: Mapping[str, object]) -> object: ...
    def prepare_remote_sale_return_decision(self, evidence: Mapping[str, object]) -> object: ...


@dataclass(frozen=True, slots=True)
class P0XlsxEvidence:
    source: WbEvidenceSource
    fingerprint: str
    assembly_order_id: int | None
    marking_fingerprint: str | None
    normalized: Mapping[str, object]


def adapt_p0_xlsx_row(row: Mapping[str, object]) -> P0XlsxEvidence:
    marking = row.get("kiz", row.get("cis"))
    normalized = {k: v for k, v in row.items() if k not in {"kiz", "cis", "sgtin"}}
    return P0XlsxEvidence(
        WbEvidenceSource.WB_XLSX,
        stable_hash(redact_mapping(row)),
        row.get("assembly_order_id") if type(row.get("assembly_order_id")) is int else None,
        _sha(str(marking).encode()) if marking else None,
        normalized,
    )


def retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except ValueError:
                return None
    return None


def read_retry_candidate(status_code: int | None, *, network_error: bool = False) -> bool:
    return network_error or status_code == 429 or (status_code is not None and 500 <= status_code <= 599)
