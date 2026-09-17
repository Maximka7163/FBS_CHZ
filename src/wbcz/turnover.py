from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone, timedelta
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
_ALLOWED_PRIMARY_TYPES = frozenset({"RECEIPT", "SALES_RECEIPT", "OTHER"})
_ALLOWED_CERT_TYPES = frozenset({"CONFORMITY_CERTIFICATE", "CONFORMITY_DECLARATION"})
_WRITE_OFF_SOURCE_TYPES = frozenset({"DESTRUCTION_ACT", "CUSTOMS_DECLARATION", "OTHER"})
WRITE_OFF_START_STATES = frozenset({"EMITTED", "APPLIED", "INTRODUCED", "APPLIED_NOT_PAID"})


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
        TurnoverOperationKind.INTRODUCE_DOMESTIC, "LP_INTRODUCE_GOODS", ("MANUAL",), ("lp",),
        (), "DOMESTIC_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL, "LK_INDI_COMMISSIONING", ("MANUAL",), ("lp",),
        (), "INDIVIDUAL_COMMISSIONING", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY, "LP_GOODS_IMPORT", ("MANUAL",), ("lp",),
        (), "IMPORT_PRE_MANDATORY", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_EAEU: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_EAEU, "CROSSBORDER", ("MANUAL",), ("lp",),
        (), "EAEU_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_REMAINS: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_REMAINS, "LP_INTRODUCE_OST", ("MANUAL",), ("lp",),
        ("REMAINS",), "REMAINS_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_CONTRACT: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_CONTRACT, "LK_CONTRACT_COMMISSIONING", ("MANUAL",), ("lp",),
        ("CONTRACT_PRODUCTION",), "CONTRACT_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.INTRODUCE_FTS: TurnoverOperationDefinition(
        TurnoverOperationKind.INTRODUCE_FTS, "LP_FTS_INTRODUCE", ("MANUAL",), ("lp",),
        (), "FTS_INTRODUCTION", "INTRODUCED", None),
    TurnoverOperationKind.WITHDRAW: TurnoverOperationDefinition(
        TurnoverOperationKind.WITHDRAW, "LK_RECEIPT", ("MANUAL",), ("lp",),
        ("DISTANCE",), "WITHDRAWAL", "RETIRED", "LK_RECEIPT_CANCEL"),
    TurnoverOperationKind.WITHDRAW_DISTANCE: TurnoverOperationDefinition(
        TurnoverOperationKind.WITHDRAW_DISTANCE, "LK_RECEIPT", ("MANUAL",), ("lp",),
        ("DISTANCE",), "DISTANCE_WITHDRAWAL", "RETIRED:DISTANCE", "LK_RECEIPT_CANCEL"),
    TurnoverOperationKind.RETURN_TO_CIRCULATION: TurnoverOperationDefinition(
        TurnoverOperationKind.RETURN_TO_CIRCULATION, "LP_RETURN", ("MANUAL",), ("lp",),
        ("REMOTE_SALE_RETURN", "RETAIL_RETURN", "OWN_USE_RETURN", "STATE_CONTRACT_RETURN", "NOT_FOR_SALE_RETURN"),
        "RETURN_REASON_MATRIX", "INTRODUCED", None),
    TurnoverOperationKind.RETURN_REMOTE_SALE: TurnoverOperationDefinition(
        TurnoverOperationKind.RETURN_REMOTE_SALE, "LP_RETURN", ("MANUAL",), ("lp",),
        ("REMOTE_SALE_RETURN",), "REMOTE_SALE_RETURN", "INTRODUCED", None),
    TurnoverOperationKind.REMARK: TurnoverOperationDefinition(
        TurnoverOperationKind.REMARK, "LK_REMARK", ("MANUAL",), ("lp",),
        ("DESCRIPTION_ERRORS", "RETAIL_RETURN", "REMOTE_SALE_RETURN", "KM_SPOILED"),
        "REMARK", "INTRODUCED", None),
    TurnoverOperationKind.WRITE_OFF: TurnoverOperationDefinition(
        TurnoverOperationKind.WRITE_OFF, "WRITE_OFF", ("MANUAL",), ("lp",),
        (), "WRITE_OFF", "WRITTEN_OFF", None),
    TurnoverOperationKind.CANCEL_WITHDRAWAL: TurnoverOperationDefinition(
        TurnoverOperationKind.CANCEL_WITHDRAWAL, "LK_RECEIPT_CANCEL", ("MANUAL",), ("lp",),
        (), "CANCEL_ELIGIBLE_LK_RECEIPT", "RESTORE_FROM_ORIGINAL", "LK_RECEIPT"),
}

M5_DOCUMENT_TYPES = frozenset(defn.document_type for defn in TURNOVER_OPERATION_REGISTRY.values())
KNOWN_FAIL_CLOSED_DOCUMENT_TYPES: Mapping[str, str] = {
    "LP_CANCEL_SHIPMENT": "SOURCE_DOCUMENT_REQUIRED",
    "LK_UNIVERSAL_INTRODUCE": "NOT_EXPOSED_FOR_LP",
    "LP_FTS_INTRODUCE_AUTO": "SYSTEM_GENERATED_NOT_CLIENT_SUBMIT",
}
M5_AGENT_WRITE_JOB_TYPES = frozenset(M5_DOCUMENT_TYPES)


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
        parsed = UUID(text)
    except (ValueError, AttributeError) as exc:
        raise TurnoverContractError(f"{label} must be UUID") from exc
    return str(parsed)


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
        cert_type = _nonempty(self.certificate_type, "certificate_type", max_len=64)
        if cert_type not in _ALLOWED_CERT_TYPES:
            raise TurnoverContractError("unsupported certificate_type")
        return {
            "certificate_type": cert_type,
            "certificate_number": _nonempty(self.certificate_number, "certificate_number"),
            "certificate_date": _day(self.certificate_date, "certificate_date"),
        }


@dataclass(frozen=True, slots=True)
class PrimaryDocument:
    document_type: str
    number: str
    document_date: date | str
    custom_name: str | None = None

    def to_return_wire(self) -> dict[str, Any]:
        kind = _nonempty(self.document_type, "primary_document_type", max_len=32).upper()
        if kind not in _ALLOWED_PRIMARY_TYPES:
            raise TurnoverContractError("unsupported primary_document_type")
        result = {
            "primary_document_type": kind,
            "primary_document_number": _nonempty(self.number, "primary_document_number"),
            "primary_document_date": _day(self.document_date, "primary_document_date"),
        }
        if kind == "OTHER":
            result["primary_document_custom_name"] = _nonempty(self.custom_name, "primary_document_custom_name")
        elif self.custom_name not in (None, ""):
            raise TurnoverContractError("primary_document_custom_name must be absent unless type=OTHER")
        return result

    def to_withdrawal_wire(self) -> dict[str, Any]:
        kind = _nonempty(self.document_type, "document_type", max_len=32).upper()
        if kind not in _ALLOWED_PRIMARY_TYPES:
            raise TurnoverContractError("unsupported document_type")
        result = {
            "document_type": kind,
            "document_number": _nonempty(self.number, "document_number"),
            "document_date": _day(self.document_date, "document_date"),
        }
        if kind == "OTHER":
            result["primary_document_custom_name"] = _nonempty(self.custom_name, "primary_document_custom_name")
        elif self.custom_name not in (None, ""):
            raise TurnoverContractError("primary_document_custom_name must be absent unless type=OTHER")
        return result


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
            result["certificate_document_data"] = [doc.to_wire() for doc in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class LpIntroduceGoodsDocument:
    participant_inn: str
    producer_inn: str
    owner_inn: str
    production_type: str
    products: tuple[IntroduceProduct, ...]
    production_date: date | str | None = None
    document_type = "LP_INTRODUCE_GOODS"

    def to_wire(self) -> dict[str, Any]:
        if not self.products:
            raise TurnoverContractError("products must be non-empty")
        result: dict[str, Any] = {
            "participant_inn": _inn(self.participant_inn, "participant_inn"),
            "producer_inn": _inn(self.producer_inn, "producer_inn"),
            "owner_inn": _inn(self.owner_inn, "owner_inn"),
            "production_type": _nonempty(self.production_type, "production_type", max_len=64),
            "products": [item.to_wire() for item in self.products],
        }
        if self.production_date is not None:
            result["production_date"] = _day(self.production_date, "production_date")
        return result


@dataclass(frozen=True, slots=True)
class IndividualProduct:
    uit: str | None = None
    uitu: str | None = None
    product_name: str | None = None
    children: tuple[str, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        if (self.uit is None) == (self.uitu is None):
            raise TurnoverContractError("individual product requires exactly one of uit/uitu")
        result: dict[str, Any] = {"uit": _cis(self.uit, "uit")} if self.uit is not None else {"uitu": _cis(self.uitu, "uitu")}
        if self.product_name is not None:
            result["productName"] = _nonempty(self.product_name, "productName")
        if self.children:
            result["children"] = list(_unique_cises(self.children, "children"))
        return result


@dataclass(frozen=True, slots=True)
class LkIndiCommissioningDocument:
    participant_inn: str
    products_list: tuple[IndividualProduct, ...]
    product_receiving_date: date | str | None = None
    document_type = "LK_INDI_COMMISSIONING"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        result: dict[str, Any] = {"participant_inn": _inn(self.participant_inn, "participant_inn"), "products_list": [item.to_wire() for item in self.products_list]}
        if self.product_receiving_date is not None:
            result["product_receiving_date"] = _day(self.product_receiving_date, "product_receiving_date")
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
        return {"participant_inn": _inn(self.participant_inn, "participant_inn"), "declaration_date": _day(self.declaration_date, "declaration_date"), "declaration_number": _nonempty(self.declaration_number, "declaration_number"), "customs_code": _nonempty(self.customs_code, "customs_code", max_len=64), "decision_code": _nonempty(self.decision_code, "decision_code", max_len=64), "products": [item.to_wire() for item in self.products]}


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
        return {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "sender_tax_number": _nonempty(self.sender_tax_number, "sender_tax_number", max_len=64), "exporter_name": _nonempty(self.exporter_name, "exporter_name"), "country_oksm": _country(self.country_oksm), "import_date": _day(self.import_date, "import_date"), "primary_document_number": _nonempty(self.primary_document_number, "primary_document_number"), "primary_document_date": _day(self.primary_document_date, "primary_document_date"), "products_list": [item.to_wire() for item in self.products_list]}


@dataclass(frozen=True, slots=True)
class RemainsProduct:
    ki: str
    def to_wire(self) -> dict[str, Any]:
        return {"ki": _cis(self.ki, "ki")}


@dataclass(frozen=True, slots=True)
class LpIntroduceOstDocument:
    trade_participant_inn: str
    products_list: tuple[RemainsProduct, ...]
    document_type = "LP_INTRODUCE_OST"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        return {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "products_list": [item.to_wire() for item in self.products_list]}


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
        result: dict[str, Any] = {"producer_inn": _inn(self.producer_inn, "producer_inn"), "owner_inn": _inn(self.owner_inn, "owner_inn"), "production_order": "CONTRACT_PRODUCTION", "products_list": [item.to_wire() for item in self.products_list]}
        if self.production_date is not None:
            result["production_date"] = _day(self.production_date, "production_date")
        return result


@dataclass(frozen=True, slots=True)
class FtsProduct:
    cis: str
    color: str | None = None
    product_size: str | None = None
    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"cis": _cis(self.cis, "cis")}
        if self.color is not None:
            result["color"] = _nonempty(self.color, "color")
        if self.product_size is not None:
            result["productSize"] = _nonempty(self.product_size, "productSize")
        return result


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
        return {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "declaration_number": _nonempty(self.declaration_number, "declaration_number"), "declaration_date": _day(self.declaration_date, "declaration_date"), "products_list": [item.to_wire() for item in self.products_list]}


@dataclass(frozen=True, slots=True)
class WithdrawalProduct:
    cis: str
    product_cost: int
    def to_wire(self) -> dict[str, Any]:
        if type(self.product_cost) is not int or self.product_cost < 0:
            raise TurnoverContractError("product_cost must be a non-negative integer number of kopecks")
        if len(str(self.product_cost)) > 17:
            raise TurnoverContractError("product_cost exceeds official numeric range")
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
        result: dict[str, Any] = {"inn": _inn(self.inn), "action": "DISTANCE", "action_date": _day(self.action_date, "action_date"), **self.mod.to_withdrawal_wire(), "products": product_wires}
        if self.primary_document is not None:
            result.update(self.primary_document.to_withdrawal_wire())
        return result


@dataclass(frozen=True, slots=True)
class ReturnProduct:
    ki: str
    paid: bool | None = None
    primary_document: PrimaryDocument | None = None
    permit: PermitDocument | None = None
    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"ki": _cis(self.ki, "ki")}
        if self.paid is not None:
            if type(self.paid) is not bool:
                raise TurnoverContractError("item paid must be boolean")
            result["paid"] = self.paid
        if self.primary_document is not None:
            result.update(self.primary_document.to_return_wire())
        if self.permit is not None:
            result.update(self.permit.to_wire())
        return result


@dataclass(frozen=True, slots=True)
class LpReturnDocument:
    trade_participant_inn: str
    return_type: str
    products_list: tuple[ReturnProduct, ...]
    paid: bool | None = None
    primary_document: PrimaryDocument | None = None
    permit: PermitDocument | None = None
    document_type = "LP_RETURN"

    def to_wire(self) -> dict[str, Any]:
        return_type = _nonempty(self.return_type, "return_type", max_len=64)
        if return_type != "REMOTE_SALE_RETURN":
            raise TurnoverManualReview("RETURN_TYPE_MATRIX_NOT_IMPLEMENTED_FOR_WIRE_ASSEMBLY")
        if not self.products_list:
            raise TurnoverContractError("products_list must be non-empty")
        item_wires = [item.to_wire() for item in self.products_list]
        cises = [item["ki"] for item in item_wires]
        if len(set(cises)) != len(cises):
            raise TurnoverContractError("products_list[].ki must be unique")
        if self.paid is None:
            raise TurnoverManualReview("REMOTE_SALE_RETURN_PAID_REQUIRED")
        if type(self.paid) is not bool:
            raise TurnoverContractError("paid must be boolean")
        if any(item.paid is not None for item in self.products_list):
            raise TurnoverContractError("item-level paid cannot be mixed with required root paid in M5")
        if self.permit is not None and any(item.permit is not None for item in self.products_list):
            raise TurnoverContractError("permit data must be either root-level or item-level, not both")
        if self.primary_document is not None and any(item.primary_document is not None for item in self.products_list):
            raise TurnoverContractError("primary document must be either root-level or item-level, not both")
        if self.paid and self.primary_document is None:
            raise TurnoverManualReview("REMOTE_SALE_RETURN_PRIMARY_DOCUMENT_REQUIRED")
        if not self.paid and self.primary_document is not None:
            raise TurnoverContractError("primary document is not accepted by M5 when paid=false")
        result: dict[str, Any] = {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "return_type": return_type, "paid": self.paid, "products_list": item_wires}
        if self.primary_document is not None:
            result.update(self.primary_document.to_return_wire())
        if self.permit is not None:
            result.update(self.permit.to_wire())
        return result


@dataclass(frozen=True, slots=True)
class RemarkProduct:
    new_uin: str
    tnved_10: str
    production_country: str
    color: str
    product_size: str
    last_uin: str | None = None
    remarking_date: date | str | None = None
    remarking_cause: str | None = None
    permit_documents: tuple[PermitDocument, ...] = ()
    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"new_uin": _cis(self.new_uin, "new_uin"), "tnved_10": _tnved(self.tnved_10, "tnved_10"), "production_country": _country(self.production_country, "production_country"), "color": _nonempty(self.color, "color"), "product_size": _nonempty(self.product_size, "product_size")}
        if self.last_uin is not None:
            result["last_uin"] = _cis(self.last_uin, "last_uin")
        if self.remarking_date is not None:
            result["remarking_date"] = _day(self.remarking_date, "remarking_date")
        if self.remarking_cause is not None:
            result["remarking_cause"] = _nonempty(self.remarking_cause, "remarking_cause", max_len=64)
        if self.permit_documents:
            result["certificate_document_data"] = [item.to_wire() for item in self.permit_documents]
        return result


@dataclass(frozen=True, slots=True)
class LkRemarkDocument:
    participant_inn: str
    products: tuple[RemarkProduct, ...]
    remarking_date: date | str | None = None
    remarking_cause: str | None = None
    document_type = "LK_REMARK"

    def to_wire(self) -> dict[str, Any]:
        if not self.products:
            raise TurnoverContractError("products must be non-empty")
        if self.remarking_date is None and any(item.remarking_date is None for item in self.products):
            raise TurnoverContractError("remarking_date required at root or every product")
        if self.remarking_cause is None and any(item.remarking_cause is None for item in self.products):
            raise TurnoverContractError("remarking_cause required at root or every product")
        cause = _nonempty(self.remarking_cause, "remarking_cause", max_len=64) if self.remarking_cause is not None else None
        if cause == "DESCRIPTION_ERRORS" and any(item.last_uin is None for item in self.products):
            raise TurnoverContractError("DESCRIPTION_ERRORS requires last_uin")
        result: dict[str, Any] = {"participant_inn": _inn(self.participant_inn, "participant_inn"), "products": [item.to_wire() for item in self.products]}
        if self.remarking_date is not None:
            result["remarking_date"] = _day(self.remarking_date, "remarking_date")
        if cause is not None:
            result["remarking_cause"] = cause
        return result


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
        source_type = _nonempty(self.source_doc_type, "sourceDocType", max_len=64).upper()
        if source_type not in _WRITE_OFF_SOURCE_TYPES:
            raise TurnoverContractError("unsupported sourceDocType")
        result: dict[str, Any] = {"participantId": _inn(self.participant_id, "participantId"), "dropoutReason": _nonempty(self.dropout_reason, "dropoutReason", max_len=64), "sourceDocType": source_type, "sourceDocNum": _nonempty(self.source_doc_num, "sourceDocNum"), "sourceDocDate": _day(self.source_doc_date, "sourceDocDate"), "sntins": list(codes)}
        if source_type == "OTHER":
            result["sourceDocName"] = _nonempty(self.source_doc_name, "sourceDocName")
        elif self.source_doc_name not in (None, ""):
            raise TurnoverContractError("sourceDocName must be absent unless sourceDocType=OTHER")
        if self.destination_country_code is not None:
            result["destinationCountryCode"] = _country(self.destination_country_code, "destinationCountryCode")
        if self.buyer_id is not None:
            result["buyerId"] = _nonempty(self.buyer_id, "buyerId", max_len=64)
        if self.fias_id is not None:
            result["fiasId"] = _fias(self.fias_id, "fiasId")
        if self.kpp is not None:
            result["kpp"] = _kpp(self.kpp)
        if self.with_child is not None:
            if type(self.with_child) is not bool:
                raise TurnoverContractError("withChild must be boolean")
            result["withChild"] = self.with_child
        if result["dropoutReason"] == "EAS_TRADE" and ("destinationCountryCode" not in result or "buyerId" not in result):
            raise TurnoverContractError("EAS_TRADE requires destinationCountryCode and buyerId")
        return result


@dataclass(frozen=True, slots=True)
class LkReceiptCancelDocument:
    inn: str
    lk_receipt_id: str
    document_type = "LK_RECEIPT_CANCEL"
    def to_wire(self) -> dict[str, Any]:
        return {"inn": _inn(self.inn), "lk_receipt_id": _nonempty(self.lk_receipt_id, "lk_receipt_id", max_len=512)}


TypedDocument = LpIntroduceGoodsDocument | LkIndiCommissioningDocument | LpGoodsImportDocument | CrossborderDocument | LpIntroduceOstDocument | LkContractCommissioningDocument | LpFtsIntroduceDocument | LkReceiptDistanceDocument | LpReturnDocument | LkRemarkDocument | WriteOffDocument | LkReceiptCancelDocument

_EXPECTED_CLASS: Mapping[TurnoverOperationKind, type] = {
    TurnoverOperationKind.INTRODUCE_DOMESTIC: LpIntroduceGoodsDocument,
    TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL: LkIndiCommissioningDocument,
    TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY: LpGoodsImportDocument,
    TurnoverOperationKind.INTRODUCE_EAEU: CrossborderDocument,
    TurnoverOperationKind.INTRODUCE_REMAINS: LpIntroduceOstDocument,
    TurnoverOperationKind.INTRODUCE_CONTRACT: LkContractCommissioningDocument,
    TurnoverOperationKind.INTRODUCE_FTS: LpFtsIntroduceDocument,
    TurnoverOperationKind.WITHDRAW: LkReceiptDistanceDocument,
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
    expected_cls = _EXPECTED_CLASS[normalized]
    if not isinstance(document, expected_cls):
        raise TurnoverContractError("operation/document DTO mismatch")
    definition = TURNOVER_OPERATION_REGISTRY[normalized]
    if document.document_type != definition.document_type:
        raise TurnoverContractError("operation/document type registry mismatch")
    exact = ExactDocumentBuilder.from_json_value(document.to_wire())
    reason = None
    if isinstance(document, LkReceiptDistanceDocument):
        reason = "DISTANCE"
    elif isinstance(document, LpReturnDocument):
        reason = document.return_type
    elif isinstance(document, LkRemarkDocument):
        reason = document.remarking_cause
    elif isinstance(document, WriteOffDocument):
        reason = document.dropout_reason
    return PreparedTurnoverDocument(normalized, definition.document_type, "MANUAL", M5_PG, exact, reason, definition.postcondition_class)


@dataclass(frozen=True, slots=True)
class CisSnapshot:
    cis: str
    status: str | None
    status_ex: str | None
    owner_inn: str | None
    withdraw_reason: str | None
    emission_type: str | None = None
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


RETURN_REASON_MATRIX: Mapping[tuple[str, str, str, str], str] = {
    ("lp", "RETIRED", "DISTANCE", "REMOTE_SALE_RETURN"): "SUPPORTED",
    ("lp", "RETIRED", "BY_SAMPLES", "REMOTE_SALE_RETURN"): "SUPPORTED",
}
KNOWN_RETURN_TYPES = frozenset({"REMOTE_SALE_RETURN", "RETAIL_RETURN", "OWN_USE_RETURN", "STATE_CONTRACT_RETURN", "NOT_FOR_SALE_RETURN"})
UNSUPPORTED_LP_RETURN_TYPES = frozenset({"VENDING_RETURN"})


def validate_return_reason_matrix(*, pg: str, current_status: str | None, current_withdraw_reason: str | None, return_type: str) -> None:
    if return_type in UNSUPPORTED_LP_RETURN_TYPES:
        raise TurnoverManualReview("RETURN_TYPE_NOT_APPLICABLE_TO_LP")
    key = (pg, current_status or "", current_withdraw_reason or "", return_type)
    if RETURN_REASON_MATRIX.get(key) != "SUPPORTED":
        raise TurnoverManualReview("RETURN_REASON_MATRIX_NO_CONFIRMED_CELL")


class OperationPreconditionService:
    def __init__(self, *, participant_inn: str, now: Callable[[], datetime] | None = None, max_snapshot_age: timedelta = timedelta(minutes=5)) -> None:
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

    def validate_distance(self, snapshots: Sequence[CisSnapshot]) -> None:
        if not snapshots:
            raise TurnoverContractError("distance requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot); self._owned(snapshot)
            if snapshot.status != "INTRODUCED":
                raise TurnoverManualReview("DISTANCE_REQUIRES_INTRODUCED")
            if snapshot.status_ex not in (None, ""):
                raise TurnoverManualReview("DISTANCE_SPECIAL_STATE_NOT_ALLOWED")

    def validate_remote_sale_return(self, snapshots: Sequence[CisSnapshot]) -> None:
        if not snapshots:
            raise TurnoverContractError("return requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot); self._owned(snapshot)
            if snapshot.status != "RETIRED":
                raise TurnoverManualReview("REMOTE_RETURN_REQUIRES_RETIRED")
            if snapshot.status_ex not in (None, ""):
                raise TurnoverManualReview("REMOTE_RETURN_SPECIAL_STATE_NOT_ALLOWED")
            validate_return_reason_matrix(pg=M5_PG, current_status=snapshot.status, current_withdraw_reason=snapshot.withdraw_reason, return_type="REMOTE_SALE_RETURN")

    def validate_import_pre_mandatory(self, snapshots: Sequence[CisSnapshot]) -> None:
        for snapshot in snapshots:
            self._fresh(snapshot)
            if snapshot.status != "APPLIED" or snapshot.emission_type != "FOREIGN":
                raise TurnoverManualReview("PRE_MANDATORY_IMPORT_REQUIRES_APPLIED_FOREIGN")
            if snapshot.status_ex not in (None, ""):
                raise TurnoverManualReview("PRE_MANDATORY_IMPORT_SPECIAL_STATE_NOT_ALLOWED")

    def validate_remains(self, snapshots: Sequence[CisSnapshot]) -> None:
        for snapshot in snapshots:
            self._fresh(snapshot)
            if snapshot.status != "APPLIED" or snapshot.emission_type != "REMAINS":
                raise TurnoverManualReview("REMAINS_REQUIRES_APPLIED_REMAINS")
            if snapshot.status_ex not in (None, ""):
                raise TurnoverManualReview("REMAINS_SPECIAL_STATE_NOT_ALLOWED")

    def validate_remark(self, *, new_codes: Sequence[CisSnapshot], old_codes: Sequence[CisSnapshot] = (), cause: str, remote_sale_return: bool = False) -> None:
        if not new_codes:
            raise TurnoverContractError("remark requires new code snapshots")
        for snapshot in new_codes:
            self._fresh(snapshot)
            if snapshot.status != "APPLIED" or snapshot.status_ex not in (None, "") or snapshot.emission_type not in {"REMARK", "REAPPLY"}:
                raise TurnoverManualReview("REMARK_NEW_CODE_PRECONDITION_FAILED")
        for snapshot in old_codes:
            self._fresh(snapshot); self._owned(snapshot)
            if snapshot.status not in {"INTRODUCED", "RETIRED"}:
                raise TurnoverManualReview("REMARK_OLD_CODE_STATE_INVALID")
            if remote_sale_return and snapshot.status != "RETIRED":
                raise TurnoverManualReview("REMOTE_SALE_REMARK_OLD_CODE_REQUIRES_RETIRED")
        if cause == "DESCRIPTION_ERRORS" and not old_codes:
            raise TurnoverManualReview("DESCRIPTION_ERRORS_REQUIRES_OLD_CODE")

    def validate_write_off(self, snapshots: Sequence[CisSnapshot]) -> None:
        if not snapshots:
            raise TurnoverContractError("write-off requires CIS snapshots")
        for snapshot in snapshots:
            self._fresh(snapshot); self._owned(snapshot)
            if snapshot.status not in WRITE_OFF_START_STATES:
                raise TurnoverManualReview("WRITE_OFF_START_STATE_NOT_ALLOWED")
            if snapshot.status_ex not in (None, "", "IN_GRAY_ZONE"):
                raise TurnoverManualReview("WRITE_OFF_SPECIAL_STATE_NOT_ALLOWED")

    def validate_cancel_withdrawal(self, *, original_document_status: str | None, original_sender_inn: str | None, latest_operation_is_original: bool) -> None:
        if original_document_status != "CHECKED_OK":
            raise TurnoverManualReview("CANCEL_REQUIRES_CHECKED_OK_SOURCE")
        if original_sender_inn != self.participant_inn:
            raise TurnoverManualReview("CANCEL_SOURCE_SENDER_MISMATCH")
        if not latest_operation_is_original:
            raise TurnoverManualReview("CANCEL_SOURCE_NOT_LATEST_ELIGIBLE_OPERATION")


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    state: ReconciliationState
    document_status_raw: str | None
    reason: str
    observed: tuple[dict[str, Any], ...]


class OperationReconciliationService:
    def reconcile(self, *, operation_kind: TurnoverOperationKind | str, document_status_raw: str | None, snapshots: Sequence[CisSnapshot], expected_restore: Mapping[str, tuple[str | None, str | None]] | None = None) -> ReconciliationResult:
        try:
            kind = operation_kind if isinstance(operation_kind, TurnoverOperationKind) else TurnoverOperationKind(operation_kind)
        except ValueError:
            return ReconciliationResult(ReconciliationState.MANUAL_REVIEW, document_status_raw, "UNKNOWN_OPERATION_KIND", ())
        observed = tuple({"cis": item.cis, "status": item.status, "statusEx": item.status_ex, "ownerInn": item.owner_inn, "withdrawReason": item.withdraw_reason} for item in snapshots)
        if document_status_raw != "CHECKED_OK":
            if document_status_raw in {"CHECKED_NOT_OK", "PARSE_ERROR", "PROCESSING_ERROR"}:
                return ReconciliationResult(ReconciliationState.MANUAL_REVIEW, document_status_raw, "DOCUMENT_TERMINAL_FAILURE", observed)
            return ReconciliationResult(ReconciliationState.PENDING, document_status_raw, "DOCUMENT_NOT_CONFIRMED_SUCCESS", observed)
        if not snapshots and kind is not TurnoverOperationKind.CANCEL_WITHDRAWAL:
            return ReconciliationResult(ReconciliationState.PENDING, document_status_raw, "FRESH_CIS_POSTCONDITION_REQUIRED", observed)
        if kind in {TurnoverOperationKind.WITHDRAW, TurnoverOperationKind.WITHDRAW_DISTANCE}:
            ok = all(item.status == "RETIRED" and item.withdraw_reason == "DISTANCE" for item in snapshots)
        elif kind in {TurnoverOperationKind.RETURN_TO_CIRCULATION, TurnoverOperationKind.RETURN_REMOTE_SALE, TurnoverOperationKind.INTRODUCE_DOMESTIC, TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL, TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY, TurnoverOperationKind.INTRODUCE_EAEU, TurnoverOperationKind.INTRODUCE_REMAINS, TurnoverOperationKind.INTRODUCE_CONTRACT, TurnoverOperationKind.INTRODUCE_FTS, TurnoverOperationKind.REMARK}:
            ok = all(item.status == "INTRODUCED" for item in snapshots)
        elif kind is TurnoverOperationKind.WRITE_OFF:
            ok = all(item.status == "WRITTEN_OFF" for item in snapshots)
        elif kind is TurnoverOperationKind.CANCEL_WITHDRAWAL:
            if not expected_restore:
                return ReconciliationResult(ReconciliationState.MANUAL_REVIEW, document_status_raw, "CANCEL_RESTORE_EXPECTATION_REQUIRED", observed)
            ok = all(item.cis in expected_restore and (item.status, item.withdraw_reason) == expected_restore[item.cis] for item in snapshots)
        else:
            ok = False
        return ReconciliationResult(ReconciliationState.RECONCILED if ok else ReconciliationState.PENDING, document_status_raw, "POSTCONDITION_CONFIRMED" if ok else "POSTCONDITION_MISMATCH", observed)


def remark_reason_readback_matches(submitted: str, observed: str | None) -> bool:
    if observed == submitted:
        return True
    return submitted == "KM_SPOILED" and observed == "KM_SPOILED_OR_LOST"
