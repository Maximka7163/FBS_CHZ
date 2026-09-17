from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import StrEnum
import re
from typing import Any, Callable, Mapping, Sequence
from uuid import UUID

from wbcz.write_pipeline import ExactDocument, ExactDocumentBuilder


M5_SOURCE_VERSION = "true-api-v726.0"
M5_PG = "lp"
EAEU_DIRECT_SUBFLOW_IMPLEMENTED = False
EAEU_DIRECT_SUBFLOW_DEFER_REASON = "EXACT_WIRE_CONTRACT_NOT_PRESENT"

_CIS_RE = re.compile(r"^[^\s]{18,74}$")
_INN_RE = re.compile(r"^(?:\d{10}|\d{12})$")
_KPP_RE = re.compile(r"^\d{9}$")
_TNVED_RE = re.compile(r"^\d{10}$")
_COUNTRY_RE = re.compile(r"^\d{3}$")
_DECLARATION_8_RE = re.compile(r"^\d{8}/\d{6}/\d{7}$")
_DECLARATION_FLEX_RE = re.compile(r"^(?:\d{2}|\d{5}|\d{8})/\d{6}/\d{7}$")
_RETURN_PRIMARY_TYPES = frozenset({"RECEIPT", "SALES_RECEIPT", "OTHER"})
_RETURN_PRIMARY_TYPES_BY_RETURN_TYPE: Mapping[str, frozenset[str]] = {
    "REMOTE_SALE_RETURN": _RETURN_PRIMARY_TYPES,
    "RETAIL_RETURN": _RETURN_PRIMARY_TYPES,
    "NOT_FOR_SALE_RETURN": frozenset({"OTHER"}),
    "OWN_USE_RETURN": frozenset(),
    "STATE_CONTRACT_RETURN": frozenset(),
}
_STATE_CONTRACT_ID_RE = re.compile(r"^\d{25}$")
_WITHDRAW_DISTANCE_PRIMARY_TYPES = frozenset(
    {"RECEIPT", "SALES_RECEIPT", "OTHER", "CONSIGNMENT_NOTE", "UTD"}
)
_WRITE_OFF_SOURCE_TYPES = frozenset({"DESTRUCTION_ACT", "CUSTOMS_DECLARATION", "OTHER"})
WRITE_OFF_START_STATES = frozenset({"EMITTED", "APPLIED", "INTRODUCED", "APPLIED_NOT_PAID"})
KNOWN_LP_RETURN_TYPES = frozenset(
    {"REMOTE_SALE_RETURN", "RETAIL_RETURN", "OWN_USE_RETURN", "STATE_CONTRACT_RETURN", "NOT_FOR_SALE_RETURN"}
)
UNSUPPORTED_LP_RETURN_TYPES = frozenset({"VENDING_RETURN"})


class TurnoverContractError(ValueError):
    pass


class TurnoverManualReview(TurnoverContractError):
    pass


class TurnoverOperationKind(StrEnum):
    INTRODUCE_DOMESTIC = "INTRODUCE_DOMESTIC"
    INTRODUCE_FROM_INDIVIDUAL = "INTRODUCE_FROM_INDIVIDUAL"
    INTRODUCE_IMPORT_PRE_MANDATORY = "INTRODUCE_IMPORT_PRE_MANDATORY"
    INTRODUCE_EAEU = "INTRODUCE_EAEU"
    INTRODUCE_REMAINS = "INTRODUCE_REMAINS"
    INTRODUCE_CONTRACT = "INTRODUCE_CONTRACT"
    INTRODUCE_FTS = "INTRODUCE_FTS"
    WITHDRAW = "WITHDRAW"
    WITHDRAW_DISTANCE = "WITHDRAW_DISTANCE"
    RETURN_TO_CIRCULATION = "RETURN_TO_CIRCULATION"
    RETURN_REMOTE_SALE = "RETURN_REMOTE_SALE"
    REMARK = "REMARK"
    WRITE_OFF = "WRITE_OFF"
    CANCEL_WITHDRAWAL = "CANCEL_WITHDRAWAL"


class ReconciliationState(StrEnum):
    PENDING = "RECONCILIATION_PENDING"
    RECONCILED = "RECONCILED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class TurnoverOperationDefinition:
    operation_kind: TurnoverOperationKind
    document_type: str
    formats: tuple[str, ...]
    pg: tuple[str, ...]
    supported_reasons: tuple[str, ...]
    precondition_class: str
    postcondition_class: str
    cancellation_relation: str | None
    source_version: str = M5_SOURCE_VERSION
    capability: str = "IMPLEMENTED"


TURNOVER_OPERATION_REGISTRY: Mapping[TurnoverOperationKind, TurnoverOperationDefinition] = {
    TurnoverOperationKind.INTRODUCE_DOMESTIC: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_DOMESTIC, "LP_INTRODUCE_GOODS", ("MANUAL",), (M5_PG,), (),
        "DOMESTIC_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL, "LK_INDI_COMMISSIONING", ("MANUAL",), (M5_PG,), (),
        "INDIVIDUAL_COMMISSIONING", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY, "LP_GOODS_IMPORT", ("MANUAL",), (M5_PG,), (),
        "IMPORT_PRE_MANDATORY", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_EAEU: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_EAEU, "CROSSBORDER", ("MANUAL",), (M5_PG,), (),
        "EAEU_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_REMAINS: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_REMAINS, "LP_INTRODUCE_OST", ("MANUAL",), (M5_PG,), ("REMAINS",),
        "REMAINS_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_CONTRACT: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_CONTRACT, "LK_CONTRACT_COMMISSIONING", ("MANUAL",), (M5_PG,),
        ("CONTRACT_PRODUCTION",), "CONTRACT_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_FTS: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_FTS, "LP_FTS_INTRODUCE", ("MANUAL",), (M5_PG,), (),
        "FTS_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.WITHDRAW: TurnoverOperationDefinition(
        TurnoverOperationKind.WITHDRAW, "LK_RECEIPT", ("MANUAL",), (M5_PG,), (),
        "WITHDRAWAL_REFERENCE_ONLY", "UNKNOWN", "LK_RECEIPT_CANCEL",
        capability="NOT_EXECUTABLE_EXACT_REASON_CONTRACTS_UNAVAILABLE"),
    TurnoverOperationKind.WITHDRAW_DISTANCE: TurnoverOperationDefinition(
        TurnoverOperationKind.WITHDRAW_DISTANCE, "LK_RECEIPT", ("MANUAL",), (M5_PG,), ("DISTANCE",),
        "DISTANCE_WITHDRAWAL", "RETIRED:DISTANCE", "LK_RECEIPT_CANCEL"),
    TurnoverOperationKind.RETURN_TO_CIRCULATION: TurnoverOperationDefinition(
        TurnoverOperationKind.RETURN_TO_CIRCULATION, "LP_RETURN", ("MANUAL",), (M5_PG,),
        tuple(sorted(KNOWN_LP_RETURN_TYPES)), "RETURN_REASON_MATRIX", "INTRODUCED", None,
        capability="FAIL_CLOSED_MATRIX_GATED"),
    TurnoverOperationKind.RETURN_REMOTE_SALE: TurnoverOperationDefinition(
        TurnoverOperationKind.RETURN_REMOTE_SALE, "LP_RETURN", ("MANUAL",), (M5_PG,), ("REMOTE_SALE_RETURN",),
        "REMOTE_SALE_RETURN", "INTRODUCED", None),
    TurnoverOperationKind.REMARK: TurnoverOperationDefinition(
        TurnoverOperationKind.REMARK, "LK_REMARK", ("MANUAL",), (M5_PG,),
        ("DESCRIPTION_ERRORS", "RETAIL_RETURN", "REMOTE_SALE_RETURN", "KM_SPOILED"),
        "REMARK", "INTRODUCED", None),
    TurnoverOperationKind.WRITE_OFF: TurnoverOperationDefinition(
        TurnoverOperationKind.WRITE_OFF, "WRITE_OFF", ("MANUAL",), (M5_PG,), (),
        "WRITE_OFF", "WRITTEN_OFF", None),
    TurnoverOperationKind.CANCEL_WITHDRAWAL: TurnoverOperationDefinition(
        TurnoverOperationKind.CANCEL_WITHDRAWAL, "LK_RECEIPT_CANCEL", ("MANUAL",), (M5_PG,), (),
        "CANCEL_ELIGIBLE_LK_RECEIPT", "RESTORE_FROM_ORIGINAL", "LK_RECEIPT"),
}

M5_DOCUMENT_TYPES = frozenset(item.document_type for item in TURNOVER_OPERATION_REGISTRY.values())
M5_AGENT_WRITE_JOB_TYPES = frozenset(M5_DOCUMENT_TYPES)
KNOWN_FAIL_CLOSED_DOCUMENT_TYPES: Mapping[str, str] = {
    "LP_CANCEL_SHIPMENT": "SOURCE_DOCUMENT_REQUIRED",
    "LK_UNIVERSAL_INTRODUCE": "NOT_EXPOSED_FOR_LP",
    "LP_FTS_INTRODUCE_AUTO": "SYSTEM_GENERATED_NOT_CLIENT_SUBMIT",
}


def document_type_for_operation(kind: TurnoverOperationKind | str) -> str:
    try:
        normalized = kind if isinstance(kind, TurnoverOperationKind) else TurnoverOperationKind(kind)
    except ValueError as exc:
        raise TurnoverContractError("unsupported turnover operation") from exc
    return TURNOVER_OPERATION_REGISTRY[normalized].document_type


def _nonempty(value: Any, label: str, *, max_len: int = 255) -> str:
    if not isinstance(value, str):
        raise TurnoverContractError(f"{label} must be a string")
    text = value.strip()
    if text != value or not 1 <= len(text) <= max_len:
        raise TurnoverContractError(f"{label} must be 1..{max_len} chars without outer whitespace")
    return text


def _inn(value: Any, label: str = "inn") -> str:
    text = _nonempty(value, label, max_len=12)
    if _INN_RE.fullmatch(text) is None:
        raise TurnoverContractError(f"{label} must be a 10 or 12 digit INN")
    return text


def _kpp(value: Any, label: str = "kpp") -> str:
    text = _nonempty(value, label, max_len=9)
    if _KPP_RE.fullmatch(text) is None:
        raise TurnoverContractError(f"{label} must be 9 digits")
    return text


def _fias(value: Any, label: str = "fias_id") -> str:
    text = _nonempty(value, label, max_len=36)
    try:
        return str(UUID(text))
    except (ValueError, AttributeError) as exc:
        raise TurnoverContractError(f"{label} must be UUID") from exc


def _cis(value: Any, label: str = "cis") -> str:
    text = _nonempty(value, label, max_len=74)
    if _CIS_RE.fullmatch(text) is None:
        raise TurnoverContractError(f"{label} must be 18..74 non-whitespace chars")
    return text


def _tnved(value: Any, label: str = "tnved_code") -> str:
    text = _nonempty(value, label, max_len=10)
    if _TNVED_RE.fullmatch(text) is None:
        raise TurnoverContractError(f"{label} must be a 10 digit TN VED code")
    return text


def _country(value: Any, label: str = "country_oksm") -> str:
    text = _nonempty(value, label, max_len=3)
    if _COUNTRY_RE.fullmatch(text) is None:
        raise TurnoverContractError(f"{label} must be a three digit country code")
    return text


def _day(value: Any, label: str) -> str:
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise TurnoverContractError(f"{label} must be yyyy-MM-dd") from exc
        if parsed.isoformat() != value:
            raise TurnoverContractError(f"{label} must be canonical yyyy-MM-dd")
        return value
    raise TurnoverContractError(f"{label} must be a date")


def _utc_millis(value: Any, label: str) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise TurnoverContractError(f"{label} must be yyyy-MM-ddTHH:mm:ss.SSSZ") from exc
    elif isinstance(value, datetime) and value.tzinfo is not None:
        parsed = value.astimezone(timezone.utc)
    else:
        raise TurnoverContractError(f"{label} must be timezone-aware datetime")
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.") + f"{parsed.microsecond // 1000:03d}Z"


def _shift_year(value: date, years: int) -> date:
    try:
        return value.replace(year=value.year + years)
    except ValueError:
        return value.replace(year=value.year + years, day=28)


def _bounded_day(value: Any, label: str, *, min_day: date | None = None, max_day: date | None = None) -> str:
    text = _day(value, label)
    parsed = date.fromisoformat(text)
    if min_day is not None and parsed < min_day:
        raise TurnoverContractError(f"{label} is earlier than the official range")
    if max_day is not None and parsed > max_day:
        raise TurnoverContractError(f"{label} is later than the official range")
    return text


def _declaration(value: Any, label: str, *, flexible_prefix: bool = False) -> str:
    text = _nonempty(value, label, max_len=23)
    pattern = _DECLARATION_FLEX_RE if flexible_prefix else _DECLARATION_8_RE
    if pattern.fullmatch(text) is None:
        raise TurnoverContractError(f"{label} has invalid customs declaration format")
    return text


def _unique_cises(values: Sequence[str], label: str) -> tuple[str, ...]:
    if not values:
        raise TurnoverContractError(f"{label} must be non-empty")
    result = tuple(_cis(value, f"{label}[{index}]") for index, value in enumerate(values))
    if len(set(result)) != len(result):
        raise TurnoverContractError(f"{label} must contain unique codes")
    return result


@dataclass(frozen=True, slots=True)
class PermitDocument:
    certificate_type: str
    certificate_number: str
    certificate_date: date | str

    def to_wire(self) -> dict[str, Any]:
        return {
            "certificate_type": _nonempty(self.certificate_type, "certificate_type", max_len=64),
            "certificate_number": _nonempty(self.certificate_number, "certificate_number"),
            "certificate_date": _day(self.certificate_date, "certificate_date"),
        }


@dataclass(frozen=True, slots=True)
class PrimaryDocument:
    document_type: str
    number: str
    document_date: date | str
    custom_name: str | None = None

    def _common(self, *, kind_label: str, number_label: str, date_label: str, allowed: frozenset[str]) -> dict[str, Any]:
        kind = _nonempty(self.document_type, kind_label, max_len=32).upper()
        if kind not in allowed:
            raise TurnoverContractError(f"unsupported {kind_label}")
        result: dict[str, Any] = {
            kind_label: kind,
            number_label: _nonempty(self.number, number_label),
            date_label: _day(self.document_date, date_label),
        }
        if kind == "OTHER":
            result["primary_document_custom_name"] = _nonempty(self.custom_name, "primary_document_custom_name")
        elif self.custom_name not in (None, ""):
            raise TurnoverContractError("primary_document_custom_name must be absent unless type=OTHER")
        return result

    def to_return_wire(self, *, allowed: frozenset[str] = _RETURN_PRIMARY_TYPES) -> dict[str, Any]:
        return self._common(
            kind_label="primary_document_type",
            number_label="primary_document_number",
            date_label="primary_document_date",
            allowed=allowed,
        )

    def to_withdrawal_wire(self) -> dict[str, Any]:
        return self._common(
            kind_label="document_type",
            number_label="document_number",
            date_label="document_date",
            allowed=_WITHDRAW_DISTANCE_PRIMARY_TYPES,
        )

    def to_remark_wire(self, cause: str) -> dict[str, Any]:
        if cause not in {"RETAIL_RETURN", "REMOTE_SALE_RETURN"}:
            raise TurnoverContractError("primary document is unsupported for this M5 remarking cause")
        return self.to_return_wire()


@dataclass(frozen=True, slots=True)
class ModLocation:
    fias_id: str
    legal_entity: bool
    kpp: str | None = None

    def to_withdrawal_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"fias_id": _fias(self.fias_id)}
        if self.legal_entity:
            if self.kpp is None:
                raise TurnoverContractError("legal entity MOD requires kpp")
            result["kpp"] = _kpp(self.kpp)
        elif self.kpp is not None:
            raise TurnoverContractError("individual entrepreneur MOD must not contain kpp")
        return result


@dataclass(frozen=True, slots=True)
class IntroduceProduct:
    uit_code: str
    tnved_code: str
    permit_documents: tuple[PermitDocument, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"uit_code": _cis(self.uit_code, "uit_code"), "tnved_code": _tnved(self.tnved_code)}
        if self.permit_documents:
            result["certificate_document_data"] = [item.to_wire() for item in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class LpIntroduceGoodsDocument:
    participant_inn: str
    producer_inn: str
    owner_inn: str
    products: tuple[IntroduceProduct, ...]
    production_date: date | str | None = None
    production_type: str = "OWN_PRODUCTION"
    document_type = "LP_INTRODUCE_GOODS"

    def to_wire(self) -> dict[str, Any]:
        if self.production_type != "OWN_PRODUCTION":
            raise TurnoverContractError("LP_INTRODUCE_GOODS production_type must be OWN_PRODUCTION")
        if not self.products:
            raise TurnoverContractError("products must be non-empty")
        result: dict[str, Any] = {
            "participant_inn": _inn(self.participant_inn, "participant_inn"),
            "producer_inn": _inn(self.producer_inn, "producer_inn"),
            "owner_inn": _inn(self.owner_inn, "owner_inn"),
            "production_type": "OWN_PRODUCTION",
            "products": [item.to_wire() for item in self.products],
        }
        if self.production_date is not None:
            result["production_date"] = _day(self.production_date, "production_date")
        return result


@dataclass(frozen=True, slots=True)
class IndividualProduct:
    uit: str | None = None
    uitu: str | None = None
    product_receiving_date: datetime | str | None = None
    product_name: str | None = None
    children: tuple["IndividualProduct", ...] = ()

    def to_wire(self) -> dict[str, Any]:
        if (self.uit is None) == (self.uitu is None):
            raise TurnoverContractError("individual product requires exactly one of uit/uitu")
        result: dict[str, Any] = {"uit": _cis(self.uit, "uit")} if self.uit is not None else {"uitu": _cis(self.uitu, "uitu")}
        if self.product_receiving_date is not None:
            result["product_receiving_date"] = _utc_millis(self.product_receiving_date, "product_receiving_date")
        if self.product_name is not None:
            result["productName"] = _nonempty(self.product_name, "productName")
        if self.children:
            result["children"] = [item.to_wire() for item in self.children]
        return result


@dataclass(frozen=True, slots=True)
class LkIndiCommissioningDocument:
    participant_inn: str
    products_list: tuple[IndividualProduct, ...]
    product_receiving_date: datetime | str | None = None
    document_type = "LK_INDI_COMMISSIONING"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        result: dict[str, Any] = {
            "participant_inn": _inn(self.participant_inn, "participant_inn"),
            "products_list": [item.to_wire() for item in self.products_list],
        }
        if self.product_receiving_date is not None:
            result["product_receiving_date"] = _utc_millis(self.product_receiving_date, "product_receiving_date")
        return result


@dataclass(frozen=True, slots=True)
class ImportProduct:
    uit_code: str
    tnved_code: str
    permit_documents: tuple[PermitDocument, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"uit_code": _cis(self.uit_code, "uit_code"), "tnved_code": _tnved(self.tnved_code)}
        if self.permit_documents:
            result["certificate_document_data"] = [item.to_wire() for item in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class LpGoodsImportDocument:
    participant_inn: str
    declaration_date: date | str
    declaration_number: str
    customs_code: str
    decision_code: str
    products: tuple[ImportProduct, ...]
    document_type = "LP_GOODS_IMPORT"

    def to_wire(self) -> dict[str, Any]:
        if not self.products:
            raise TurnoverContractError("products must be non-empty")
        customs = _nonempty(self.customs_code, "customs_code", max_len=8)
        if not customs.isdigit() or len(customs) != 8:
            raise TurnoverContractError("customs_code must be 8 digits")
        decision = _nonempty(str(self.decision_code), "decision_code", max_len=2)
        if not decision.isdigit() or len(decision) != 2:
            raise TurnoverContractError("decision_code must be a two digit classifier code")
        return {
            "participant_inn": _inn(self.participant_inn, "participant_inn"),
            "declaration_date": _day(self.declaration_date, "declaration_date"),
            "declaration_number": _declaration(self.declaration_number, "declaration_number"),
            "customs_code": customs,
            "decision_code": int(decision),
            "products": [item.to_wire() for item in self.products],
        }


@dataclass(frozen=True, slots=True)
class CrossborderProduct:
    ki: str
    tnved_code: str
    permit_documents: tuple[PermitDocument, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"ki": _cis(self.ki, "ki"), "tnved_code": _tnved(self.tnved_code)}
        if self.permit_documents:
            result["certificate_document_data"] = [item.to_wire() for item in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class CrossborderDocument:
    trade_participant_inn: str
    sender_tax_number: str
    exporter_name: str
    country_oksm: str
    import_date: date | str
    primary_document_number: str
    primary_document_date: date | str
    products_list: tuple[CrossborderProduct, ...]
    document_type = "CROSSBORDER"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        sender = _nonempty(self.sender_tax_number, "sender_tax_number", max_len=14)
        if not sender.isdigit() or len(sender) not in {8, 9, 12, 14}:
            raise TurnoverContractError("sender_tax_number must contain 8, 9, 12 or 14 digits")
        country = _country(self.country_oksm)
        if country not in {"051", "112", "398", "417"}:
            raise TurnoverContractError("country_oksm is not a supported EAEU source country")
        return {
            "trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"),
            "sender_tax_number": sender,
            "exporter_name": _nonempty(self.exporter_name, "exporter_name"),
            "country_oksm": country,
            "import_date": _day(self.import_date, "import_date"),
            "primary_document_number": _nonempty(self.primary_document_number, "primary_document_number"),
            "primary_document_date": _day(self.primary_document_date, "primary_document_date"),
            "products_list": [item.to_wire() for item in self.products_list],
        }


@dataclass(frozen=True, slots=True)
class RemainsProduct:
    ki: str
    country: str
    declaration_number: str
    declaration_date: date | str
    permit_documents: tuple[PermitDocument, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ki": _cis(self.ki, "ki"),
            "country": _country(self.country, "country"),
            "declaration_number": _declaration(self.declaration_number, "declaration_number", flexible_prefix=True),
            "declaration_date": _day(self.declaration_date, "declaration_date"),
        }
        if self.permit_documents:
            result["certificate_document_data"] = [item.to_wire() for item in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class LpIntroduceOstDocument:
    trade_participant_inn: str
    products_list: tuple[RemainsProduct, ...]
    document_type = "LP_INTRODUCE_OST"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        wires = [item.to_wire() for item in self.products_list]
        if len({item["ki"] for item in wires}) != len(wires):
            raise TurnoverContractError("products_list[].ki must be unique")
        return {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "products_list": wires}


@dataclass(frozen=True, slots=True)
class ContractProduct:
    uit: str
    tnved_code: str
    permit_documents: tuple[PermitDocument, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"uit": _cis(self.uit, "uit"), "tnved_code": _tnved(self.tnved_code)}
        if self.permit_documents:
            result["certificate_document_data"] = [item.to_wire() for item in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class LkContractCommissioningDocument:
    producer_inn: str
    owner_inn: str
    products_list: tuple[ContractProduct, ...]
    production_date: date | str | None = None
    document_type = "LK_CONTRACT_COMMISSIONING"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        result: dict[str, Any] = {
            "producer_inn": _inn(self.producer_inn, "producer_inn"),
            "owner_inn": _inn(self.owner_inn, "owner_inn"),
            "production_order": "CONTRACT_PRODUCTION",
            "products_list": [item.to_wire() for item in self.products_list],
        }
        if self.production_date is not None:
            result["production_date"] = _day(self.production_date, "production_date")
        return result


@dataclass(frozen=True, slots=True)
class FtsProduct:
    cis: str
    color: str
    product_size: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "cis": _cis(self.cis, "cis"),
            "color": _nonempty(self.color, "color", max_len=1024),
            "productSize": _nonempty(self.product_size, "productSize", max_len=1024),
        }


@dataclass(frozen=True, slots=True)
class LpFtsIntroduceDocument:
    trade_participant_inn: str
    declaration_number: str
    declaration_date: date | str
    products_list: tuple[FtsProduct, ...]
    document_type = "LP_FTS_INTRODUCE"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        return {
            "trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"),
            "declaration_number": _declaration(self.declaration_number, "declaration_number"),
            "declaration_date": _day(self.declaration_date, "declaration_date"),
            "products_list": [item.to_wire() for item in self.products_list],
        }


@dataclass(frozen=True, slots=True)
class WithdrawalProduct:
    cis: str
    product_cost: int

    def to_wire(self) -> dict[str, Any]:
        if type(self.product_cost) is not int or self.product_cost < 0 or self.product_cost > 99999999999999999:
            raise TurnoverContractError("product_cost must be integer kopecks in official 0..99999999999999999 range")
        return {"cis": _cis(self.cis, "cis"), "product_cost": self.product_cost}


@dataclass(frozen=True, slots=True)
class LkReceiptDistanceDocument:
    inn: str
    action_date: date | str
    products: tuple[WithdrawalProduct, ...]
    mod: ModLocation
    primary_document: PrimaryDocument | None = None
    document_type = "LK_RECEIPT"
    action = "DISTANCE"

    def to_wire(self) -> dict[str, Any]:
        if not self.products:
            raise TurnoverContractError("products must be non-empty")
        product_wires = [item.to_wire() for item in self.products]
        if len({item["cis"] for item in product_wires}) != len(product_wires):
            raise TurnoverContractError("products[].cis must be unique")
        today = datetime.now(timezone.utc).date()
        result: dict[str, Any] = {
            "inn": _inn(self.inn),
            "action": "DISTANCE",
            "action_date": _bounded_day(self.action_date, "action_date", min_day=_shift_year(today, -5), max_day=today),
            **self.mod.to_withdrawal_wire(),
            "products": product_wires,
        }
        if self.primary_document is not None:
            result.update(self.primary_document.to_withdrawal_wire())
        return result


@dataclass(frozen=True, slots=True)
class ReturnProduct:
    ki: str
    paid: bool | None = None
    primary_document: PrimaryDocument | None = None
    permit: PermitDocument | None = None

    def to_wire(self, *, allowed_primary_types: frozenset[str]) -> dict[str, Any]:
        result: dict[str, Any] = {"ki": _cis(self.ki, "ki")}
        if self.paid is not None:
            if type(self.paid) is not bool:
                raise TurnoverContractError("products_list[].paid must be boolean")
            result["paid"] = self.paid
        if self.primary_document is not None:
            result.update(self.primary_document.to_return_wire(allowed=allowed_primary_types))
        if self.permit is not None:
            result.update(self.permit.to_wire())
        return result


@dataclass(frozen=True, slots=True)
class LpReturnDocument:
    trade_participant_inn: str
    products_list: tuple[ReturnProduct, ...]
    paid: bool | None = None
    primary_document: PrimaryDocument | None = None
    permit: PermitDocument | None = None
    state_contract_id: str | None = None
    return_type: str = "REMOTE_SALE_RETURN"
    document_type = "LP_RETURN"

    @staticmethod
    def _validated_state_contract_id(value: str) -> str:
        text = _nonempty(value, "state_contract_id", max_len=25)
        if _STATE_CONTRACT_ID_RE.fullmatch(text) is None:
            raise TurnoverContractError("state_contract_id must contain exactly 25 digits")
        if text[12] not in {"1", "2", "3"}:
            raise TurnoverContractError("state_contract_id 13th character must be 1, 2, or 3")
        return text

    def to_wire(self) -> dict[str, Any]:
        return_type = self.return_type
        if return_type in UNSUPPORTED_LP_RETURN_TYPES:
            raise TurnoverManualReview("RETURN_TYPE_NOT_APPLICABLE_TO_LP")
        if return_type not in KNOWN_LP_RETURN_TYPES:
            raise TurnoverManualReview("RETURN_TYPE_MATRIX_NOT_CONFIRMED_FOR_LP")
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")

        item_paid_present = any(item.paid is not None for item in self.products_list)
        item_primary_present = any(item.primary_document is not None for item in self.products_list)
        item_permit_present = any(item.permit is not None for item in self.products_list)

        if return_type == "REMOTE_SALE_RETURN":
            if self.paid is not None and type(self.paid) is not bool:
                raise TurnoverContractError("paid must be boolean")
        else:
            if self.paid is not None or item_paid_present:
                raise TurnoverContractError("paid must be absent unless return_type=REMOTE_SALE_RETURN")

        if return_type == "STATE_CONTRACT_RETURN":
            if self.state_contract_id is None:
                raise TurnoverManualReview("STATE_CONTRACT_ID_REQUIRED")
            state_contract_id = self._validated_state_contract_id(self.state_contract_id)
        else:
            if self.state_contract_id is not None:
                raise TurnoverContractError("state_contract_id must be absent unless return_type=STATE_CONTRACT_RETURN")
            state_contract_id = None

        primary_forbidden = return_type in {"OWN_USE_RETURN", "STATE_CONTRACT_RETURN"}
        if primary_forbidden and (self.primary_document is not None or item_primary_present):
            raise TurnoverContractError(f"primary document must be absent for {return_type}")

        certificate_forbidden = return_type in {"OWN_USE_RETURN", "STATE_CONTRACT_RETURN"}
        if certificate_forbidden and (self.permit is not None or item_permit_present):
            raise TurnoverContractError(f"certificate data must be absent for {return_type}")
        if self.permit is not None and item_permit_present:
            raise TurnoverContractError("certificate data must be root-level or item-level, not both")

        allowed_primary_types = _RETURN_PRIMARY_TYPES_BY_RETURN_TYPE[return_type]
        root_primary_wire: dict[str, Any] | None = None
        if self.primary_document is not None:
            root_primary_wire = self.primary_document.to_return_wire(allowed=allowed_primary_types)

        wires: list[dict[str, Any]] = []
        for item in self.products_list:
            if item.paid is not None and type(item.paid) is not bool:
                raise TurnoverContractError("products_list[].paid must be boolean")

            effective_primary = item.primary_document if item.primary_document is not None else self.primary_document
            if return_type == "REMOTE_SALE_RETURN":
                effective_paid = item.paid if item.paid is not None else self.paid
                if effective_paid is None:
                    raise TurnoverManualReview("LP_RETURN_PAID_REQUIRED")
                if effective_paid is True and effective_primary is None:
                    raise TurnoverManualReview("LP_RETURN_PRIMARY_DOCUMENT_REQUIRED")
                if effective_paid is False and effective_primary is not None:
                    raise TurnoverContractError("primary document must be absent when REMOTE_SALE_RETURN effective paid=false")
            elif return_type in {"RETAIL_RETURN", "NOT_FOR_SALE_RETURN"}:
                if effective_primary is None:
                    raise TurnoverManualReview("LP_RETURN_PRIMARY_DOCUMENT_REQUIRED")

            wires.append(item.to_wire(allowed_primary_types=allowed_primary_types))

        if len({item["ki"] for item in wires}) != len(wires):
            raise TurnoverContractError("products_list[].ki must be unique")

        result: dict[str, Any] = {
            "trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"),
            "return_type": return_type,
            "products_list": wires,
        }
        if return_type == "REMOTE_SALE_RETURN" and self.paid is not None:
            result["paid"] = self.paid
        if root_primary_wire is not None:
            result.update(root_primary_wire)
        if self.permit is not None:
            result.update(self.permit.to_wire())
        if state_contract_id is not None:
            result["state_contract_id"] = state_contract_id
        return result


@dataclass(frozen=True, slots=True)
class RemarkProduct:
    new_uin: str
    last_uin: str | None = None
    tnved_10: str | None = None
    primary_document: PrimaryDocument | None = None
    permit_documents: tuple[PermitDocument, ...] = ()

    def to_wire(self, *, cause: str) -> dict[str, Any]:
        result: dict[str, Any] = {"new_uin": _cis(self.new_uin, "new_uin")}
        if self.last_uin is not None:
            result["last_uin"] = _cis(self.last_uin, "last_uin")
        if self.tnved_10 is not None:
            result["tnved_10"] = _tnved(self.tnved_10, "tnved_10")
        elif self.last_uin is None:
            raise TurnoverContractError("tnved_10 is required when last_uin is absent")
        if cause == "DESCRIPTION_ERRORS" and self.last_uin is None:
            raise TurnoverContractError("DESCRIPTION_ERRORS requires last_uin")
        if self.primary_document is not None:
            result.update(self.primary_document.to_remark_wire(cause))
        if self.permit_documents:
            result["certificate_document_data"] = [item.to_wire() for item in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class LkRemarkDocument:
    participant_inn: str
    remarking_date: date | str
    remarking_cause: str
    products: tuple[RemarkProduct, ...]
    document_type = "LK_REMARK"

    def to_wire(self) -> dict[str, Any]:
        cause = _nonempty(self.remarking_cause, "remarking_cause", max_len=64)
        if not self.products:
            raise TurnoverContractError("products must be non-empty")
        today = datetime.now(timezone.utc).date()
        return {
            "participant_inn": _inn(self.participant_inn, "participant_inn"),
            "remarking_date": _bounded_day(self.remarking_date, "remarking_date", min_day=_shift_year(today, -5), max_day=today),
            "remarking_cause": cause,
            "products": [item.to_wire(cause=cause) for item in self.products],
        }


@dataclass(frozen=True, slots=True)
class WriteOffDocument:
    participant_id: str
    dropout_reason: str
    source_doc_type: str
    source_doc_num: str
    source_doc_date: date | str
    sntins: tuple[str, ...]
    source_doc_name: str | None = None
    destination_country_code: str | None = None
    buyer_id: str | None = None
    fias_id: str | None = None
    kpp: str | None = None
    with_child: bool | None = None
    document_type = "WRITE_OFF"

    def to_wire(self) -> dict[str, Any]:
        codes = _unique_cises(self.sntins, "sntins")
        reason = _nonempty(self.dropout_reason, "dropoutReason", max_len=64)
        source_type = _nonempty(self.source_doc_type, "sourceDocType", max_len=64).upper()
        if source_type not in _WRITE_OFF_SOURCE_TYPES:
            raise TurnoverContractError("unsupported sourceDocType")
        if reason in {"EAS_TRADE", "BEYOND_EEC_EXPORT"}:
            if source_type not in {"CUSTOMS_DECLARATION", "OTHER"}:
                raise TurnoverContractError("export write-off sourceDocType must be CUSTOMS_DECLARATION or OTHER")
        elif source_type == "CUSTOMS_DECLARATION":
            raise TurnoverContractError("CUSTOMS_DECLARATION is only accepted for export write-off reasons")
        if source_type == "DESTRUCTION_ACT" and reason != "DESTRUCTION":
            raise TurnoverContractError("DESTRUCTION_ACT requires dropoutReason=DESTRUCTION")
        today = datetime.now(timezone.utc).date()
        result: dict[str, Any] = {
            "participantId": _inn(self.participant_id, "participantId"),
            "dropoutReason": reason,
            "sourceDocType": source_type,
            "sourceDocNum": _nonempty(self.source_doc_num, "sourceDocNum"),
            "sourceDocDate": _bounded_day(self.source_doc_date, "sourceDocDate", min_day=_shift_year(today, -5), max_day=today + timedelta(days=30)),
            "sntins": list(codes),
        }
        if source_type == "OTHER":
            result["sourceDocName"] = _nonempty(self.source_doc_name, "sourceDocName")
        elif self.source_doc_name not in (None, ""):
            raise TurnoverContractError("sourceDocName must be absent unless sourceDocType=OTHER")
        if reason == "EAS_TRADE":
            if self.destination_country_code is None or self.buyer_id is None:
                raise TurnoverContractError("EAS_TRADE requires destinationCountryCode and buyerId")
            result["destinationCountryCode"] = _country(self.destination_country_code, "destinationCountryCode")
            result["buyerId"] = _nonempty(self.buyer_id, "buyerId", max_len=64)
        elif self.destination_country_code is not None or self.buyer_id is not None:
            raise TurnoverContractError("destinationCountryCode/buyerId are only accepted for EAS_TRADE")
        if self.fias_id is not None:
            result["fiasId"] = _fias(self.fias_id, "fiasId")
        if self.kpp is not None:
            result["kpp"] = _kpp(self.kpp)
        if self.with_child is not None:
            if type(self.with_child) is not bool:
                raise TurnoverContractError("withChild must be boolean")
            result["withChild"] = self.with_child
        return result


@dataclass(frozen=True, slots=True)
class LkReceiptCancelDocument:
    inn: str
    lk_receipt_id: str
    document_type = "LK_RECEIPT_CANCEL"

    def to_wire(self) -> dict[str, Any]:
        return {"inn": _inn(self.inn), "lk_receipt_id": _nonempty(self.lk_receipt_id, "lk_receipt_id", max_len=512)}


TypedDocument = (
    LpIntroduceGoodsDocument | LkIndiCommissioningDocument | LpGoodsImportDocument |
    CrossborderDocument | LpIntroduceOstDocument | LkContractCommissioningDocument |
    LpFtsIntroduceDocument | LkReceiptDistanceDocument | LpReturnDocument |
    LkRemarkDocument | WriteOffDocument | LkReceiptCancelDocument
)

_EXPECTED_CLASS: Mapping[TurnoverOperationKind, type] = {
    TurnoverOperationKind.INTRODUCE_DOMESTIC: LpIntroduceGoodsDocument,
    TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL: LkIndiCommissioningDocument,
    TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY: LpGoodsImportDocument,
    TurnoverOperationKind.INTRODUCE_EAEU: CrossborderDocument,
    TurnoverOperationKind.INTRODUCE_REMAINS: LpIntroduceOstDocument,
    TurnoverOperationKind.INTRODUCE_CONTRACT: LkContractCommissioningDocument,
    TurnoverOperationKind.INTRODUCE_FTS: LpFtsIntroduceDocument,
    TurnoverOperationKind.WITHDRAW_DISTANCE: LkReceiptDistanceDocument,
    TurnoverOperationKind.RETURN_TO_CIRCULATION: LpReturnDocument,
    TurnoverOperationKind.RETURN_REMOTE_SALE: LpReturnDocument,
    TurnoverOperationKind.REMARK: LkRemarkDocument,
    TurnoverOperationKind.WRITE_OFF: WriteOffDocument,
    TurnoverOperationKind.CANCEL_WITHDRAWAL: LkReceiptCancelDocument,
}


@dataclass(frozen=True, slots=True)
class PreparedTurnoverDocument:
    operation_kind: TurnoverOperationKind
    document_type: str
    document_format: str
    pg: str
    exact_document: ExactDocument
    raw_business_reason: str | None
    expected_postcondition: str


def prepare_turnover_document(kind: TurnoverOperationKind | str, document: TypedDocument) -> PreparedTurnoverDocument:
    try:
        normalized = kind if isinstance(kind, TurnoverOperationKind) else TurnoverOperationKind(kind)
    except ValueError as exc:
        raise TurnoverContractError("unsupported turnover operation") from exc
    expected_cls = _EXPECTED_CLASS.get(normalized)
    if expected_cls is None:
        raise TurnoverManualReview("OPERATION_NOT_EXECUTABLE")
    if not isinstance(document, expected_cls):
        raise TurnoverContractError("operation/document DTO mismatch")
    if (
        normalized is TurnoverOperationKind.RETURN_REMOTE_SALE
        and isinstance(document, LpReturnDocument)
        and document.return_type != "REMOTE_SALE_RETURN"
    ):
        raise TurnoverContractError("RETURN_REMOTE_SALE requires return_type=REMOTE_SALE_RETURN")
    definition = TURNOVER_OPERATION_REGISTRY[normalized]
    if document.document_type != definition.document_type:
        raise TurnoverContractError("operation/document type registry mismatch")
    wire = document.to_wire()
    exact = ExactDocumentBuilder.from_json_value(wire)
    reason: str | None = None
    if isinstance(document, LkReceiptDistanceDocument):
        reason = "DISTANCE"
    elif isinstance(document, LpReturnDocument):
        reason = document.return_type
    elif isinstance(document, LkRemarkDocument):
        reason = document.remarking_cause
    elif isinstance(document, WriteOffDocument):
        reason = document.dropout_reason
    return PreparedTurnoverDocument(
        normalized, definition.document_type, "MANUAL", M5_PG, exact, reason, definition.postcondition_class
    )


@dataclass(frozen=True, slots=True)
class CisSnapshot:
    cis: str
    status: str | None
    status_ex: str | None
    owner_inn: str | None
    withdraw_reason: str | None
    emission_type: str | None = None
    commission_from_individual_confirmed: bool | None = None
    fetched_at: datetime | None = None

    def validated(self) -> "CisSnapshot":
        _cis(self.cis)
        if self.owner_inn is not None:
            _inn(self.owner_inn, "owner_inn")
        if self.fetched_at is None or self.fetched_at.tzinfo is None:
            raise TurnoverManualReview("FRESH_CIS_SNAPSHOT_REQUIRED")
        return self


@dataclass(frozen=True, slots=True)
class ProductReferenceSnapshot:
    gtin: str
    tnved_code: str | None
    product_ready: bool
    participant_mod_ready: bool
    rd_ready: bool | None
    fetched_at: datetime | None

    def validated(self) -> "ProductReferenceSnapshot":
        if not self.gtin:
            raise TurnoverContractError("gtin required")
        if self.tnved_code is not None:
            _tnved(self.tnved_code)
        if self.fetched_at is None or self.fetched_at.tzinfo is None:
            raise TurnoverManualReview("FRESH_REFERENCE_SNAPSHOT_REQUIRED")
        return self


@dataclass(frozen=True, slots=True)
class PreconditionEvidence:
    operation_kind: TurnoverOperationKind
    checked_cises: tuple[str, ...]
    observed: tuple[dict[str, Any], ...]
    verified_at: str

    def to_ledger(self) -> dict[str, Any]:
        return {
            "operation_kind": self.operation_kind.value,
            "checked_cises": list(self.checked_cises),
            "observed": list(self.observed),
            "verified_at": self.verified_at,
            "verified_fresh": True,
        }


RETURN_REASON_MATRIX: Mapping[tuple[str, str, str, str], str] = {
    (M5_PG, "RETIRED", "DISTANCE", "REMOTE_SALE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "BY_SAMPLES", "REMOTE_SALE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "RETAIL", "RETAIL_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "BY_SAMPLES", "RETAIL_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "DISTANCE", "RETAIL_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "OWN_USE", "OWN_USE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "PRODUCTION_USE", "OWN_USE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "MEDICAL_USE", "OWN_USE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "VETERINARY_USE", "OWN_USE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "STATE_SECRET", "STATE_CONTRACT_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "DONATION", "NOT_FOR_SALE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "OWN_USE", "NOT_FOR_SALE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "PRODUCTION_USE", "NOT_FOR_SALE_RETURN"): "SUPPORTED",
    (M5_PG, "RETIRED", "STATE_CONTRACT", "NOT_FOR_SALE_RETURN"): "SUPPORTED",
}


def validate_return_reason_matrix(*, pg: str, current_status: str | None, current_withdraw_reason: str | None, return_type: str) -> None:
    if return_type in UNSUPPORTED_LP_RETURN_TYPES:
        raise TurnoverManualReview("RETURN_TYPE_NOT_APPLICABLE_TO_LP")
    key = (pg, current_status or "", current_withdraw_reason or "", return_type)
    if RETURN_REASON_MATRIX.get(key) != "SUPPORTED":
        raise TurnoverManualReview("RETURN_REASON_MATRIX_NO_CONFIRMED_CELL")


class OperationPreconditionService:
    def __init__(
        self,
        *,
        participant_inn: str,
        now: Callable[[], datetime] | None = None,
        max_snapshot_age: timedelta = timedelta(minutes=5),
    ) -> None:
        self.participant_inn = _inn(participant_inn, "participant_inn")
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.max_snapshot_age = max_snapshot_age

    def _fresh(self, snapshot: CisSnapshot | ProductReferenceSnapshot) -> None:
        snapshot.validated()
        assert snapshot.fetched_at is not None
        now = self._now().astimezone(timezone.utc)
        fetched = snapshot.fetched_at.astimezone(timezone.utc)
        if fetched > now + timedelta(minutes=1) or now - fetched > self.max_snapshot_age:
            raise TurnoverManualReview("STALE_PRECONDITION_SNAPSHOT")

    def _owned(self, snapshot: CisSnapshot) -> None:
        if snapshot.owner_inn != self.participant_inn:
            raise TurnoverManualReview("CIS_NOT_OWNED_BY_PARTICIPANT")

    @staticmethod
    def _plain(snapshot: CisSnapshot) -> None:
        if snapshot.status_ex not in (None, ""):
            raise TurnoverManualReview("SPECIAL_STATE_NOT_ALLOWED")

    def _evidence(self, kind: TurnoverOperationKind, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        return PreconditionEvidence(
            operation_kind=kind,
            checked_cises=tuple(item.cis for item in snapshots),
            observed=tuple(
                {
                    "cis": item.cis,
                    "status": item.status,
                    "statusEx": item.status_ex,
                    "ownerInn": item.owner_inn,
                    "withdrawReason": item.withdraw_reason,
                    "emissionType": item.emission_type,
                }
                for item in snapshots
            ),
            verified_at=self._now().astimezone(timezone.utc).isoformat(),
        )

    def validate_product_references(
        self, refs: Sequence[ProductReferenceSnapshot], *, require_mod: bool = False
    ) -> None:
        if not refs:
            raise TurnoverManualReview("FRESH_PRODUCT_REFERENCE_REQUIRED")
        for ref in refs:
            self._fresh(ref)
            if not ref.product_ready or ref.tnved_code is None:
                raise TurnoverManualReview("PRODUCT_NOT_READY_FOR_MARKING_TURNOVER")
            if require_mod and not ref.participant_mod_ready:
                raise TurnoverManualReview("PARTICIPANT_MOD_NOT_READY")
            if ref.rd_ready is False:
                raise TurnoverManualReview("PERMIT_REFERENCE_NOT_READY")

    def _introduced_from_applied(
        self,
        kind: TurnoverOperationKind,
        snapshots: Sequence[CisSnapshot],
        *,
        emission: str,
    ) -> PreconditionEvidence:
        if not snapshots:
            raise TurnoverContractError("operation requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot)
            self._owned(snapshot)
            self._plain(snapshot)
            if snapshot.status != "APPLIED" or snapshot.emission_type != emission:
                raise TurnoverManualReview(f"{kind.value}_PRECONDITION_FAILED")
        return self._evidence(kind, snapshots)

    def validate_domestic(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        return self._introduced_from_applied(TurnoverOperationKind.INTRODUCE_DOMESTIC, snapshots, emission="LOCAL")

    def validate_individual(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        if not snapshots:
            raise TurnoverContractError("individual commissioning requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot)
            self._owned(snapshot)
            self._plain(snapshot)
            if snapshot.status != "APPLIED" or snapshot.commission_from_individual_confirmed is not True:
                raise TurnoverManualReview("INDIVIDUAL_COMMISSIONING_PRECONDITION_FAILED")
        return self._evidence(TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL, snapshots)

    def validate_import_pre_mandatory(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        return self._introduced_from_applied(
            TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY, snapshots, emission="FOREIGN"
        )

    def validate_crossborder(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        return self._introduced_from_applied(TurnoverOperationKind.INTRODUCE_EAEU, snapshots, emission="FOREIGN")

    def validate_remains(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        return self._introduced_from_applied(TurnoverOperationKind.INTRODUCE_REMAINS, snapshots, emission="REMAINS")

    def validate_contract(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        return self._introduced_from_applied(TurnoverOperationKind.INTRODUCE_CONTRACT, snapshots, emission="LOCAL")

    def validate_fts(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        if not snapshots:
            raise TurnoverContractError("FTS introduction requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot)
            self._owned(snapshot)
            if snapshot.status != "APPLIED" or snapshot.emission_type != "FOREIGN":
                raise TurnoverManualReview("FTS_INTRODUCTION_PRECONDITION_FAILED")
            if snapshot.status_ex not in (None, "", "FTS_RESPOND_NOT_OK", "FTS_CONTROL"):
                raise TurnoverManualReview("FTS_INTRODUCTION_SPECIAL_STATE_INVALID")
        return self._evidence(TurnoverOperationKind.INTRODUCE_FTS, snapshots)

    def validate_distance(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        if not snapshots:
            raise TurnoverContractError("distance requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot)
            self._owned(snapshot)  # Sellari backend policy; CRPT itself is not universally this strict.
            self._plain(snapshot)
            if snapshot.status != "INTRODUCED":
                raise TurnoverManualReview("DISTANCE_REQUIRES_INTRODUCED")
        return self._evidence(TurnoverOperationKind.WITHDRAW_DISTANCE, snapshots)

    def validate_return(
        self,
        snapshots: Sequence[CisSnapshot],
        *,
        return_type: str,
        operation_kind: TurnoverOperationKind = TurnoverOperationKind.RETURN_TO_CIRCULATION,
    ) -> PreconditionEvidence:
        if not snapshots:
            raise TurnoverContractError("return requires CIS snapshots")
        if return_type in UNSUPPORTED_LP_RETURN_TYPES:
            raise TurnoverManualReview("RETURN_TYPE_NOT_APPLICABLE_TO_LP")
        if return_type not in KNOWN_LP_RETURN_TYPES:
            raise TurnoverManualReview("RETURN_TYPE_MATRIX_NOT_CONFIRMED_FOR_LP")
        for snapshot in snapshots:
            self._fresh(snapshot)
            self._owned(snapshot)
            self._plain(snapshot)
            if snapshot.status != "RETIRED":
                raise TurnoverManualReview("RETURN_REQUIRES_RETIRED")
            validate_return_reason_matrix(
                pg=M5_PG,
                current_status=snapshot.status,
                current_withdraw_reason=snapshot.withdraw_reason,
                return_type=return_type,
            )
        return self._evidence(operation_kind, snapshots)

    def validate_remote_sale_return(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        return self.validate_return(
            snapshots,
            return_type="REMOTE_SALE_RETURN",
            operation_kind=TurnoverOperationKind.RETURN_REMOTE_SALE,
        )

    def validate_remark(
        self,
        *,
        new_codes: Sequence[CisSnapshot],
        old_codes: Sequence[CisSnapshot] = (),
        cause: str,
    ) -> PreconditionEvidence:
        if not new_codes:
            raise TurnoverContractError("remark requires new code snapshots")
        for snapshot in new_codes:
            self._fresh(snapshot)
            self._plain(snapshot)
            if snapshot.status != "APPLIED" or snapshot.emission_type not in {"REMARK", "REAPPLY"}:
                raise TurnoverManualReview("REMARK_NEW_CODE_PRECONDITION_FAILED")
        for snapshot in old_codes:
            self._fresh(snapshot)
            self._owned(snapshot)
            self._plain(snapshot)
            if snapshot.status not in {"INTRODUCED", "RETIRED"}:
                raise TurnoverManualReview("REMARK_OLD_CODE_STATE_INVALID")
            if cause in {"REMOTE_SALE_RETURN", "RETAIL_RETURN"} and snapshot.status != "RETIRED":
                raise TurnoverManualReview("RETURN_REMARK_OLD_CODE_REQUIRES_RETIRED")
        if cause == "DESCRIPTION_ERRORS" and not old_codes:
            raise TurnoverManualReview("DESCRIPTION_ERRORS_REQUIRES_OLD_CODE")
        return self._evidence(TurnoverOperationKind.REMARK, tuple(new_codes) + tuple(old_codes))

    def validate_write_off(self, snapshots: Sequence[CisSnapshot]) -> PreconditionEvidence:
        if not snapshots:
            raise TurnoverContractError("write-off requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot)
            self._owned(snapshot)
            if snapshot.status not in WRITE_OFF_START_STATES:
                raise TurnoverManualReview("WRITE_OFF_START_STATE_NOT_ALLOWED")
            if snapshot.status_ex not in (None, "", "IN_GRAY_ZONE"):
                raise TurnoverManualReview("WRITE_OFF_SPECIAL_STATE_NOT_ALLOWED")
        return self._evidence(TurnoverOperationKind.WRITE_OFF, snapshots)

    def validate_cancel_withdrawal(
        self,
        *,
        original_document_status: str | None,
        original_sender_inn: str | None,
        latest_operation_is_original: bool,
    ) -> PreconditionEvidence:
        if original_document_status != "CHECKED_OK":
            raise TurnoverManualReview("CANCEL_REQUIRES_CHECKED_OK_SOURCE")
        if original_sender_inn != self.participant_inn:
            raise TurnoverManualReview("CANCEL_SOURCE_SENDER_MISMATCH")
        if not latest_operation_is_original:
            raise TurnoverManualReview("CANCEL_SOURCE_NOT_LATEST_ELIGIBLE_OPERATION")
        return PreconditionEvidence(
            TurnoverOperationKind.CANCEL_WITHDRAWAL,
            (),
            ({"sourceDocumentStatus": original_document_status, "sourceSenderInn": original_sender_inn},),
            self._now().astimezone(timezone.utc).isoformat(),
        )


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    state: ReconciliationState
    document_status_raw: str | None
    reason: str
    observed: tuple[dict[str, Any], ...]


class OperationReconciliationService:
    def reconcile(
        self,
        *,
        operation_kind: TurnoverOperationKind | str,
        document_status_raw: str | None,
        snapshots: Sequence[CisSnapshot],
        expected_restore: Mapping[str, tuple[str | None, str | None]] | None = None,
    ) -> ReconciliationResult:
        try:
            kind = operation_kind if isinstance(operation_kind, TurnoverOperationKind) else TurnoverOperationKind(operation_kind)
        except ValueError:
            return ReconciliationResult(ReconciliationState.MANUAL_REVIEW, document_status_raw, "UNKNOWN_OPERATION_KIND", ())
        observed = tuple(
            {
                "cis": item.cis,
                "status": item.status,
                "statusEx": item.status_ex,
                "ownerInn": item.owner_inn,
                "withdrawReason": item.withdraw_reason,
            }
            for item in snapshots
        )
        if document_status_raw != "CHECKED_OK":
            if document_status_raw in {"CHECKED_NOT_OK", "PARSE_ERROR", "PROCESSING_ERROR"}:
                return ReconciliationResult(ReconciliationState.MANUAL_REVIEW, document_status_raw, "DOCUMENT_TERMINAL_FAILURE", observed)
            return ReconciliationResult(ReconciliationState.PENDING, document_status_raw, "DOCUMENT_NOT_CONFIRMED_SUCCESS", observed)
        if kind is TurnoverOperationKind.WITHDRAW:
            return ReconciliationResult(
                ReconciliationState.MANUAL_REVIEW, document_status_raw, "OPERATION_NOT_EXECUTABLE", observed
            )
        if not snapshots and kind is not TurnoverOperationKind.CANCEL_WITHDRAWAL:
            return ReconciliationResult(ReconciliationState.PENDING, document_status_raw, "FRESH_CIS_POSTCONDITION_REQUIRED", observed)
        if kind is TurnoverOperationKind.WITHDRAW_DISTANCE:
            ok = all(item.status == "RETIRED" and item.withdraw_reason == "DISTANCE" for item in snapshots)
        elif kind in {
            TurnoverOperationKind.RETURN_TO_CIRCULATION,
            TurnoverOperationKind.RETURN_REMOTE_SALE,
            TurnoverOperationKind.INTRODUCE_DOMESTIC,
            TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL,
            TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY,
            TurnoverOperationKind.INTRODUCE_EAEU,
            TurnoverOperationKind.INTRODUCE_REMAINS,
            TurnoverOperationKind.INTRODUCE_CONTRACT,
            TurnoverOperationKind.INTRODUCE_FTS,
            TurnoverOperationKind.REMARK,
        }:
            ok = all(item.status == "INTRODUCED" and item.status_ex in (None, "") for item in snapshots)
        elif kind is TurnoverOperationKind.WRITE_OFF:
            ok = all(item.status == "WRITTEN_OFF" and item.status_ex in (None, "") for item in snapshots)
        elif kind is TurnoverOperationKind.CANCEL_WITHDRAWAL:
            if not expected_restore:
                return ReconciliationResult(ReconciliationState.MANUAL_REVIEW, document_status_raw, "CANCEL_RESTORE_EXPECTATION_REQUIRED", observed)
            ok = bool(snapshots) and all(
                item.cis in expected_restore and (item.status, item.withdraw_reason) == expected_restore[item.cis]
                for item in snapshots
            )
        else:
            ok = False
        return ReconciliationResult(
            ReconciliationState.RECONCILED if ok else ReconciliationState.PENDING,
            document_status_raw,
            "POSTCONDITION_CONFIRMED" if ok else "POSTCONDITION_MISMATCH",
            observed,
        )


def remark_reason_readback_matches(submitted: str, observed: str | None) -> bool:
    if observed == submitted:
        return True
    return submitted == "KM_SPOILED" and observed == "KM_SPOILED_OR_LOST"
