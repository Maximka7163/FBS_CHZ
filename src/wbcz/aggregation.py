from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
from typing import Any, Callable, Iterable, Mapping, Sequence

from wbcz.write_pipeline import ExactDocument, ExactDocumentBuilder

M6_SOURCE_VERSION = "true-api-v726.0"
M6_PG = "lp"
INTERNAL_SAFETY_MAX_TREE_DEPTH = 32


class AggregationContractError(ValueError):
    pass


class AggregationManualReview(AggregationContractError):
    pass


class PackageType(StrEnum):
    UNIT = "UNIT"
    GROUP = "GROUP"
    BUNDLE = "BUNDLE"
    SET = "SET"
    BOX = "BOX"
    ATK = "ATK"


class UnitSerialNumberType(StrEnum):
    BOX = "BOX"
    GROUP = "GROUP"
    PRODUCT_SET = "PRODUCT_SET"


class AggregationOperationKind(StrEnum):
    FORM_TRANSPORT_PACKAGE = "FORM_TRANSPORT_PACKAGE"
    FORM_MULTIPRODUCT_TRANSPORT_PACKAGE = "FORM_MULTIPRODUCT_TRANSPORT_PACKAGE"
    FORM_SET = "FORM_SET"
    FORM_SET_GENERIC_COMPATIBILITY = "FORM_SET_GENERIC_COMPATIBILITY"
    TRANSFORM_PACKAGE_ADD = "TRANSFORM_PACKAGE_ADD"
    TRANSFORM_PACKAGE_REMOVE = "TRANSFORM_PACKAGE_REMOVE"
    DISAGGREGATE_PACKAGE = "DISAGGREGATE_PACKAGE"
    FORM_ATK = "FORM_ATK"
    TRANSFORM_ATK_ADD = "TRANSFORM_ATK_ADD"
    TRANSFORM_ATK_REMOVE = "TRANSFORM_ATK_REMOVE"
    DISAGGREGATE_ATK = "DISAGGREGATE_ATK"
    READ_AGGREGATE_TREE = "READ_AGGREGATE_TREE"
    READ_AGGREGATION_HISTORY = "READ_AGGREGATION_HISTORY"
    RECONCILE_AGGREGATION_OPERATION = "RECONCILE_AGGREGATION_OPERATION"
    AUTO_DISAGGREGATION = "AUTO_DISAGGREGATION"


@dataclass(frozen=True, slots=True)
class AggregationOperationDefinition:
    operation_kind: AggregationOperationKind
    document_type: str | None
    executable: bool
    capability: str
    source_version: str = M6_SOURCE_VERSION


M6_OPERATION_REGISTRY: Mapping[AggregationOperationKind, AggregationOperationDefinition] = {
    AggregationOperationKind.FORM_TRANSPORT_PACKAGE: AggregationOperationDefinition(AggregationOperationKind.FORM_TRANSPORT_PACKAGE, "AGGREGATION_DOCUMENT", True, "BOX_SINGLE_PG"),
    AggregationOperationKind.FORM_MULTIPRODUCT_TRANSPORT_PACKAGE: AggregationOperationDefinition(AggregationOperationKind.FORM_MULTIPRODUCT_TRANSPORT_PACKAGE, "AGGREGATION_DOCUMENT", True, "BOX_MULTI_PG"),
    AggregationOperationKind.FORM_SET: AggregationOperationDefinition(AggregationOperationKind.FORM_SET, "SETS_AGGREGATION", True, "DEDICATED_SET"),
    AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY: AggregationOperationDefinition(AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY, "AGGREGATION_DOCUMENT", True, "EXPLICIT_COMPATIBILITY_ONLY"),
    AggregationOperationKind.TRANSFORM_PACKAGE_ADD: AggregationOperationDefinition(AggregationOperationKind.TRANSFORM_PACKAGE_ADD, "REAGGREGATION_DOCUMENT", True, "ADDING"),
    AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE: AggregationOperationDefinition(AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE, "REAGGREGATION_DOCUMENT", True, "REMOVING"),
    AggregationOperationKind.DISAGGREGATE_PACKAGE: AggregationOperationDefinition(AggregationOperationKind.DISAGGREGATE_PACKAGE, "DISAGGREGATION_DOCUMENT", True, "EXPLICIT_DISAGGREGATION"),
    AggregationOperationKind.FORM_ATK: AggregationOperationDefinition(AggregationOperationKind.FORM_ATK, "ATK_AGGREGATION", True, "IMPORTER_ONLY"),
    AggregationOperationKind.TRANSFORM_ATK_ADD: AggregationOperationDefinition(AggregationOperationKind.TRANSFORM_ATK_ADD, "ATK_TRANSFORMATION", True, "ADDING"),
    AggregationOperationKind.TRANSFORM_ATK_REMOVE: AggregationOperationDefinition(AggregationOperationKind.TRANSFORM_ATK_REMOVE, "ATK_TRANSFORMATION", True, "REMOVING"),
    AggregationOperationKind.DISAGGREGATE_ATK: AggregationOperationDefinition(AggregationOperationKind.DISAGGREGATE_ATK, "ATK_DISAGGREGATION", True, "IMPORTER_ONLY"),
    AggregationOperationKind.READ_AGGREGATE_TREE: AggregationOperationDefinition(AggregationOperationKind.READ_AGGREGATE_TREE, None, False, "READ_ONLY"),
    AggregationOperationKind.READ_AGGREGATION_HISTORY: AggregationOperationDefinition(AggregationOperationKind.READ_AGGREGATION_HISTORY, None, False, "READ_ONLY"),
    AggregationOperationKind.RECONCILE_AGGREGATION_OPERATION: AggregationOperationDefinition(AggregationOperationKind.RECONCILE_AGGREGATION_OPERATION, None, False, "RECONCILIATION_ONLY"),
    AggregationOperationKind.AUTO_DISAGGREGATION: AggregationOperationDefinition(AggregationOperationKind.AUTO_DISAGGREGATION, None, False, "EVENT_ONLY_NOT_SUBMITTABLE"),
}

M6_DOCUMENT_TYPES = frozenset(x.document_type for x in M6_OPERATION_REGISTRY.values() if x.document_type)

LP_PARENT_CHILDREN: Mapping[PackageType, frozenset[PackageType]] = {
    PackageType.SET: frozenset({PackageType.UNIT, PackageType.BUNDLE}),
    PackageType.BOX: frozenset({PackageType.UNIT, PackageType.BUNDLE, PackageType.SET, PackageType.BOX}),
    PackageType.ATK: frozenset({PackageType.UNIT, PackageType.BUNDLE, PackageType.SET, PackageType.BOX}),
}


def _text(value: Any, label: str, *, max_len: int = 255) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > max_len:
        raise AggregationContractError(f"{label} must be a non-empty trimmed string")
    return value


def _inn(value: Any, label: str) -> str:
    text = _text(value, label, max_len=12)
    if not (text.isdigit() and len(text) in (10, 12)):
        raise AggregationContractError(f"{label} must be 10 or 12 digits")
    return text


def _code(value: Any, label: str) -> str:
    text = _text(value, label, max_len=74)
    if not 18 <= len(text) <= 74 or any(ch.isspace() for ch in text):
        raise AggregationContractError(f"{label} must be 18..74 non-whitespace chars")
    return text


def validate_lp_relation(parent: PackageType, child: PackageType, *, child_pg: str = M6_PG, mixed_pg: bool = False) -> None:
    if parent is PackageType.GROUP:
        raise AggregationManualReview("GROUP_PARENT_NOT_EXPOSED_FOR_LP")
    if parent is PackageType.SET and child not in LP_PARENT_CHILDREN[PackageType.SET]:
        raise AggregationContractError("SET permits only UNIT or BUNDLE direct children for lp")
    if parent is PackageType.BOX:
        if child is PackageType.GROUP:
            if not mixed_pg or child_pg == M6_PG:
                raise AggregationContractError("GROUP child requires legitimate non-lp mixed-PG KITU")
        elif child not in LP_PARENT_CHILDREN[PackageType.BOX]:
            raise AggregationContractError("incompatible BOX child")
    if parent is PackageType.ATK:
        if child is PackageType.GROUP and child_pg == M6_PG:
            raise AggregationContractError("lp GROUP must not be fabricated")
        if child is not PackageType.GROUP and child not in LP_PARENT_CHILDREN[PackageType.ATK]:
            raise AggregationContractError("incompatible ATK child")


@dataclass(frozen=True, slots=True)
class CisAggregationSnapshot:
    cis: str
    package_type: PackageType | None
    product_group: str | None
    status_raw: str | None
    status_ex_raw: str | None
    owner_inn: str | None
    emission_type: str | None
    parent: str | None
    direct_children: tuple[str, ...] = ()
    gtin: str | None = None
    tnved: str | None = None
    fetched_at: datetime | None = None


class AggregationPreconditionService:
    def __init__(self, participant_inn: str, *, now: Callable[[], datetime] | None = None, max_age: timedelta = timedelta(minutes=5)) -> None:
        self.participant_inn = _inn(participant_inn, "participant_inn")
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.max_age = max_age

    def require_fresh(self, snapshots: Sequence[CisAggregationSnapshot]) -> None:
        if not snapshots:
            raise AggregationManualReview("FRESH_M1_M2_SNAPSHOT_REQUIRED")
        current = self.now().astimezone(timezone.utc)
        for item in snapshots:
            _code(item.cis, "cis")
            if item.fetched_at is None or item.fetched_at.tzinfo is None:
                raise AggregationManualReview("FRESH_M1_M2_SNAPSHOT_REQUIRED")
            ts = item.fetched_at.astimezone(timezone.utc)
            if ts > current + timedelta(minutes=1) or current - ts > self.max_age:
                raise AggregationManualReview("STALE_AGGREGATION_SNAPSHOT")

    def require_owner(self, snapshots: Sequence[CisAggregationSnapshot]) -> None:
        for item in snapshots:
            if item.owner_inn != self.participant_inn:
                raise AggregationManualReview("LEGACY_NON_OWNER_FLOW_NOT_ENABLED")


@dataclass(frozen=True, slots=True)
class AggregationUnit:
    unit_serial_number: str
    unit_serial_number_type: UnitSerialNumberType
    sntins: tuple[str, ...]
    part_number: str | None = None

    def to_wire(self) -> dict[str, Any]:
        parent = _code(self.unit_serial_number, "unitSerialNumber")
        if not self.sntins:
            raise AggregationContractError("sntins must be non-empty")
        children = tuple(_code(v, "sntins[]") for v in self.sntins)
        if len(set(children)) != len(children):
            raise AggregationContractError("sntins must be unique")
        out: dict[str, Any] = {
            "unitSerialNumber": parent,
            "unitSerialNumberType": self.unit_serial_number_type.value,
            "aggregationType": "AGGREGATION",
            "sntins": list(children),
        }
        if self.part_number is not None:
            raise AggregationManualReview("PART_NUMBER_NOT_ENABLED_FOR_LP")
        return out


@dataclass(frozen=True, slots=True)
class AggregationDocument:
    participant_id: str
    aggregation_units: tuple[AggregationUnit, ...]
    document_type = "AGGREGATION_DOCUMENT"

    def to_wire(self) -> dict[str, Any]:
        if not self.aggregation_units:
            raise AggregationContractError("aggregationUnits must be non-empty")
        wires = [x.to_wire() for x in self.aggregation_units]
        lengths = {len(x["unitSerialNumber"]) for x in wires}
        types = {x["unitSerialNumberType"] for x in wires}
        if len(lengths) != 1 or len(types) != 1:
            raise AggregationContractError("parents in one document must share code length and package type")
        return {"participantId": _inn(self.participant_id, "participantId"), "aggregationUnits": wires}


@dataclass(frozen=True, slots=True)
class SetAggregationUnit:
    unit_serial_number: str
    sntins: tuple[str, ...]

    def to_wire(self) -> dict[str, Any]:
        if not self.sntins:
            raise AggregationContractError("sntins must be non-empty")
        children = tuple(_code(v, "sntins[]") for v in self.sntins)
        if len(set(children)) != len(children):
            raise AggregationContractError("sntins must be unique")
        return {"unitSerialNumber": _code(self.unit_serial_number, "unitSerialNumber"), "sntins": list(children)}


@dataclass(frozen=True, slots=True)
class SetsAggregationDocument:
    participant_id: str
    aggregation_units: tuple[SetAggregationUnit, ...]
    document_type = "SETS_AGGREGATION"

    def to_wire(self) -> dict[str, Any]:
        if not self.aggregation_units:
            raise AggregationContractError("aggregationUnits must be non-empty")
        return {"participantId": _inn(self.participant_id, "participantId"), "aggregationUnits": [x.to_wire() for x in self.aggregation_units]}


@dataclass(frozen=True, slots=True)
class ReaggregationItem:
    uit_uitu: str | None = None
    kitu: str | None = None

    def to_wire(self) -> dict[str, Any]:
        if (self.uit_uitu is None) == (self.kitu is None):
            raise AggregationContractError("reaggregation item requires exactly one of uit_uitu or kitu")
        return {"uit_uitu": _code(self.uit_uitu, "uit_uitu")} if self.uit_uitu is not None else {"kitu": _code(self.kitu, "kitu")}


@dataclass(frozen=True, slots=True)
class ReaggregationDocument:
    participant_inn: str
    reaggregation_type: str
    uitu: str
    uit_uitu_list: tuple[ReaggregationItem, ...]
    document_type = "REAGGREGATION_DOCUMENT"

    def to_wire(self) -> dict[str, Any]:
        kind = _text(self.reaggregation_type, "reaggregation_type", max_len=16)
        if kind not in {"ADDING", "REMOVING"}:
            raise AggregationContractError("reaggregation_type must be ADDING or REMOVING")
        if not self.uit_uitu_list:
            raise AggregationContractError("uit_uitu_list must be non-empty")
        items = [x.to_wire() for x in self.uit_uitu_list]
        keys = [next(iter(x.values())) for x in items]
        if len(set(keys)) != len(keys):
            raise AggregationContractError("uit_uitu_list must be unique")
        return {"participant_inn": _inn(self.participant_inn, "participant_inn"), "reaggregation_type": kind, "uitu": _code(self.uitu, "uitu"), "uit_uitu_list": items}


@dataclass(frozen=True, slots=True)
class DisaggregationDocument:
    participant_inn: str
    products_list: tuple[str, ...]
    document_type = "DISAGGREGATION_DOCUMENT"

    def to_wire(self) -> dict[str, Any]:
        if not self.products_list:
            raise AggregationContractError("products_list must be non-empty")
        codes = tuple(_code(x, "products_list[].uitu") for x in self.products_list)
        if len(set(codes)) != len(codes):
            raise AggregationContractError("products_list[].uitu must be unique")
        return {"participant_inn": _inn(self.participant_inn, "participant_inn"), "products_list": [{"uitu": x} for x in codes]}


@dataclass(frozen=True, slots=True)
class AtkAggregationDocument:
    trade_participant_inn: str
    products_list: tuple[str, ...]
    document_type = "ATK_AGGREGATION"

    def to_wire(self) -> dict[str, Any]:
        codes = _unique_codes(self.products_list, "products_list[].ki")
        return {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "products_list": [{"ki": x} for x in codes]}


@dataclass(frozen=True, slots=True)
class AtkTransformationDocument:
    trade_participant_inn: str
    atk: str
    transformation_type: str
    products_list: tuple[str, ...]
    document_type = "ATK_TRANSFORMATION"

    def to_wire(self) -> dict[str, Any]:
        kind = _text(self.transformation_type, "transformation_type", max_len=16)
        if kind not in {"ADDING", "REMOVING"}:
            raise AggregationContractError("transformation_type must be ADDING or REMOVING")
        codes = _unique_codes(self.products_list, "products_list[].ki")
        return {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "atk": _code(self.atk, "atk"), "transformation_type": kind, "products_list": [{"ki": x} for x in codes]}


@dataclass(frozen=True, slots=True)
class AtkDisaggregationDocument:
    trade_participant_inn: str
    products_list: tuple[str, ...]
    document_type = "ATK_DISAGGREGATION"

    def to_wire(self) -> dict[str, Any]:
        codes = _unique_codes(self.products_list, "products_list[].atk")
        return {"trade_participant_inn": _inn(self.trade_participant_inn, "trade_participant_inn"), "products_list": [{"atk": x} for x in codes]}


def _unique_codes(values: Sequence[str], label: str) -> tuple[str, ...]:
    if not values:
        raise AggregationContractError(f"{label} must be non-empty")
    out = tuple(_code(x, label) for x in values)
    if len(set(out)) != len(out):
        raise AggregationContractError(f"{label} must be unique")
    return out


@dataclass(frozen=True, slots=True)
class SetCompositionRequirement:
    gtin_quantities: Mapping[str, int] | None = None
    marked_products_quantity_in_set: int | None = None
    published: bool = True


def validate_set_preconditions(*, parent: CisAggregationSnapshot, children: Sequence[CisAggregationSnapshot], composition: SetCompositionRequirement) -> None:
    if parent.package_type is not PackageType.SET:
        raise AggregationContractError("FORM_SET requires SET parent")
    if not composition.published:
        raise AggregationManualReview("SET_PRODUCT_CARD_NOT_PUBLISHED")
    if not children:
        raise AggregationContractError("set children required")
    for child in children:
        if child.package_type not in {PackageType.UNIT, PackageType.BUNDLE}:
            raise AggregationContractError("KIN accepts only UNIT/BUNDLE")
    statuses = {x.status_raw for x in children}
    if len(statuses) != 1 or statuses.pop() not in {"APPLIED", "INTRODUCED"}:
        raise AggregationManualReview("KIN_CHILD_STATUS_NOT_SUPPORTED")
    if any(x.status_ex_raw not in (None, "", "WAIT_TRANSFER_TO_OWNER") for x in children):
        raise AggregationManualReview("KIN_CHILD_STATUS_EX_NOT_SUPPORTED")
    status = children[0].status_raw
    if parent.status_raw != "APPLIED":
        raise AggregationManualReview("KIN_PARENT_MUST_BE_APPLIED")
    if status == "APPLIED":
        emissions = {x.emission_type for x in children}
        if len(emissions) != 1 or parent.emission_type not in emissions:
            raise AggregationManualReview("KIN_APPLIED_EMISSION_MISMATCH")
        if parent.emission_type in {"REMARK", "REAPPLY"} or any(x.emission_type in {"REMARK", "REAPPLY"} for x in children):
            raise AggregationManualReview("KIN_APPLIED_REMARK_REAPPLY_FORBIDDEN")
    else:
        if parent.emission_type not in {"LOCAL", "REMAINS"}:
            raise AggregationManualReview("KIN_INTRODUCED_PARENT_EMISSION_NOT_SUPPORTED")
        if parent.emission_type == "REMAINS" and any(x.emission_type != "REMAINS" for x in children):
            raise AggregationManualReview("KIN_REMAINS_CHILD_EMISSION_MISMATCH")
    if composition.gtin_quantities:
        counts: dict[str, int] = {}
        for child in children:
            if not child.gtin:
                raise AggregationManualReview("KIN_GTIN_REQUIRED_BY_NKMT")
            counts[child.gtin] = counts.get(child.gtin, 0) + 1
        if counts != dict(composition.gtin_quantities):
            raise AggregationManualReview("KIN_NKMT_COMPOSITION_MISMATCH")
    elif composition.marked_products_quantity_in_set is not None:
        if len(children) != composition.marked_products_quantity_in_set:
            raise AggregationManualReview("KIN_MARKED_PRODUCTS_QUANTITY_MISMATCH")
    else:
        raise AggregationManualReview("KIN_COMPOSITION_REFERENCE_REQUIRED")


def validate_box_preconditions(*, parent: CisAggregationSnapshot | None, children: Sequence[CisAggregationSnapshot], participant_inn: str, leading_pg: str = M6_PG, mixed_pg: bool = False) -> None:
    owner = _inn(participant_inn, "participant_inn")
    if not children:
        raise AggregationContractError("KITU children required")
    statuses = {x.status_raw for x in children}
    if len(statuses) != 1:
        raise AggregationManualReview("KITU_CHILD_STATUSES_MUST_MATCH")
    status = next(iter(statuses))
    if status not in {"APPLIED", "INTRODUCED"}:
        raise AggregationManualReview("KITU_CHILD_STATUS_NOT_SUPPORTED")
    if any(x.status_ex_raw not in (None, "", "WAIT_TRANSFER_TO_OWNER") for x in children):
        raise AggregationManualReview("KITU_CHILD_STATUS_EX_NOT_SUPPORTED")
    for child in children:
        if child.owner_inn != owner:
            raise AggregationManualReview("LEGACY_NON_OWNER_FLOW_NOT_ENABLED")
        if child.parent:
            raise AggregationManualReview("CHILD_ALREADY_AGGREGATED")
        if child.package_type is None:
            raise AggregationManualReview("UNKNOWN_RAW_PACKAGE_TYPE")
        validate_lp_relation(PackageType.BOX, child.package_type, child_pg=child.product_group or M6_PG, mixed_pg=mixed_pg)
    if status == "APPLIED" and len({x.emission_type for x in children}) != 1:
        raise AggregationManualReview("KITU_APPLIED_EMISSION_MISMATCH")
    if mixed_pg and not any(x.product_group == leading_pg for x in children):
        raise AggregationManualReview("KITU_LEADING_PG_CHILD_REQUIRED")


def validate_atk_preconditions(*, role: str, participant_inn: str, children: Sequence[CisAggregationSnapshot], allow_fts_control: bool = False) -> None:
    if role != "IMPORTER":
        raise AggregationManualReview("ATK_IMPORTER_ROLE_REQUIRED")
    owner = _inn(participant_inn, "participant_inn")
    if not children:
        raise AggregationContractError("ATK children required")
    pgs = {x.product_group for x in children}
    if len(pgs) != 1:
        raise AggregationManualReview("ATK_SINGLE_PRODUCT_GROUP_REQUIRED")
    prefixes: set[str] = set()
    for child in children:
        if child.owner_inn != owner:
            raise AggregationManualReview("ATK_OWNER_REQUIRED")
        if child.status_raw != "APPLIED" or child.emission_type != "FOREIGN":
            raise AggregationManualReview("ATK_CHILD_MUST_BE_APPLIED_FOREIGN")
        allowed_ex = {None, "", "FTS_RESPOND_NOT_OK"} | ({"FTS_CONTROL"} if allow_fts_control else set())
        if child.status_ex_raw not in allowed_ex:
            raise AggregationManualReview("ATK_STATUS_EX_NOT_ALLOWED")
        if child.parent:
            raise AggregationManualReview("ATK_CHILD_ALREADY_AGGREGATED")
        if not child.tnved or len(child.tnved) < 4:
            raise AggregationManualReview("ATK_TNVED_REQUIRED")
        prefixes.add(child.tnved[:4])
    if len(prefixes) != 1:
        raise AggregationManualReview("ATK_TNVED_FIRST4_MUST_MATCH")


@dataclass(frozen=True, slots=True)
class PreparedAggregationDocument:
    operation_kind: AggregationOperationKind
    document_type: str
    document_format: str
    pg: str
    exact_document: ExactDocument


M6TypedDocument = AggregationDocument | SetsAggregationDocument | ReaggregationDocument | DisaggregationDocument | AtkAggregationDocument | AtkTransformationDocument | AtkDisaggregationDocument

_EXPECTED_DOC_CLASS: Mapping[AggregationOperationKind, type] = {
    AggregationOperationKind.FORM_TRANSPORT_PACKAGE: AggregationDocument,
    AggregationOperationKind.FORM_MULTIPRODUCT_TRANSPORT_PACKAGE: AggregationDocument,
    AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY: AggregationDocument,
    AggregationOperationKind.FORM_SET: SetsAggregationDocument,
    AggregationOperationKind.TRANSFORM_PACKAGE_ADD: ReaggregationDocument,
    AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE: ReaggregationDocument,
    AggregationOperationKind.DISAGGREGATE_PACKAGE: DisaggregationDocument,
    AggregationOperationKind.FORM_ATK: AtkAggregationDocument,
    AggregationOperationKind.TRANSFORM_ATK_ADD: AtkTransformationDocument,
    AggregationOperationKind.TRANSFORM_ATK_REMOVE: AtkTransformationDocument,
    AggregationOperationKind.DISAGGREGATE_ATK: AtkDisaggregationDocument,
}


def prepare_aggregation_document(kind: AggregationOperationKind | str, document: M6TypedDocument) -> PreparedAggregationDocument:
    try:
        op = kind if isinstance(kind, AggregationOperationKind) else AggregationOperationKind(kind)
    except ValueError as exc:
        raise AggregationContractError("unsupported M6 operation") from exc
    expected = _EXPECTED_DOC_CLASS.get(op)
    if expected is None:
        raise AggregationManualReview("M6_OPERATION_NOT_SUBMITTABLE")
    if not isinstance(document, expected):
        raise AggregationContractError("operation/document DTO mismatch")
    definition = M6_OPERATION_REGISTRY[op]
    if document.document_type != definition.document_type:
        raise AggregationContractError("operation/document type mismatch")
    if op in {AggregationOperationKind.TRANSFORM_PACKAGE_ADD, AggregationOperationKind.TRANSFORM_ATK_ADD} and document.to_wire().get("reaggregation_type", document.to_wire().get("transformation_type")) != "ADDING":
        raise AggregationContractError("ADD operation requires ADDING wire type")
    if op in {AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE, AggregationOperationKind.TRANSFORM_ATK_REMOVE} and document.to_wire().get("reaggregation_type", document.to_wire().get("transformation_type")) != "REMOVING":
        raise AggregationContractError("REMOVE operation requires REMOVING wire type")
    return PreparedAggregationDocument(op, document.document_type, "MANUAL", M6_PG, ExactDocumentBuilder.from_json_value(document.to_wire()))


class AggregationHistorySemantic(StrEnum):
    AGGREGATION = "AGGREGATION"
    DISAGGREGATION = "DISAGGREGATION"
    AUTO_DISAGGREGATION = "AUTO_DISAGGREGATION"
    TRANSFORMATION = "TRANSFORMATION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class AggregationHistoryEvent:
    semantic: AggregationHistorySemantic
    raw_operation_type: Any
    raw_operation_date: Any
    raw_parent: Any = None
    raw_package_type: Any = None
    raw_extended_package_type: Any = None
    raw_document_id: Any = None
    parsed_operation_date: datetime | None = None


def _parse_operation_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    variants = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")
    for fmt in variants:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc) if value.endswith("Z") else dt
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_aggregation_history_event(raw: Mapping[str, Any]) -> AggregationHistoryEvent:
    operation = raw.get("operationType")
    if operation == "AGGREGATION": semantic = AggregationHistorySemantic.AGGREGATION
    elif operation == "DISAGGREGATION": semantic = AggregationHistorySemantic.DISAGGREGATION
    elif operation in {"AUTODISAGGREGATED", "AUTODISAGGREGATION"}: semantic = AggregationHistorySemantic.AUTO_DISAGGREGATION
    elif operation == "TRANSFORMATION": semantic = AggregationHistorySemantic.TRANSFORMATION
    else: semantic = AggregationHistorySemantic.UNKNOWN
    return AggregationHistoryEvent(semantic, operation, raw.get("operationDate"), raw.get("parent"), raw.get("packageType"), raw.get("extendedPackageType"), raw.get("docId") or raw.get("documentId"), _parse_operation_date(raw.get("operationDate")))


@dataclass(frozen=True, slots=True)
class AggregateTreeNode:
    cis: str
    package_type_raw: str | None
    children: tuple["AggregateTreeNode", ...]


@dataclass(frozen=True, slots=True)
class AggregateTreeResult:
    root: AggregateTreeNode
    complete: bool
    truncated: bool
    warnings: tuple[str, ...]


def build_aggregate_tree(root_cis: str, *, direct_children: Callable[[str], Sequence[str]], package_type_of: Callable[[str], str | None], safety_max_depth: int = INTERNAL_SAFETY_MAX_TREE_DEPTH) -> AggregateTreeResult:
    warnings: list[str] = []
    truncated = False
    visiting: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()
    def walk(cis: str, depth: int) -> AggregateTreeNode:
        nonlocal truncated
        if depth > safety_max_depth:
            truncated = True; warnings.append("INTERNAL_SAFETY_LIMIT"); return AggregateTreeNode(cis, package_type_of(cis), ())
        if cis in visiting:
            warnings.append("CYCLE_DETECTED"); return AggregateTreeNode(cis, package_type_of(cis), ())
        visiting.add(cis)
        children_nodes: list[AggregateTreeNode] = []
        for child in direct_children(cis):
            edge = (cis, child)
            if edge in seen_edges:
                warnings.append("DUPLICATE_EDGE_DROPPED"); continue
            seen_edges.add(edge)
            children_nodes.append(walk(child, depth + 1))
        visiting.remove(cis)
        return AggregateTreeNode(cis, package_type_of(cis), tuple(children_nodes))
    root = walk(_code(root_cis, "root_cis"), 0)
    return AggregateTreeResult(root, not truncated and "CYCLE_DETECTED" not in warnings, truncated, tuple(warnings))


class AggregationReconciliationState(StrEnum):
    RECONCILIATION_PENDING = "RECONCILIATION_PENDING"
    RECONCILED = "RECONCILED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class AggregationReconciliationResult:
    state: AggregationReconciliationState
    reason: str
    discovered_parent_cis: str | None = None


class AggregationReconciliationService:
    def reconcile_relation(self, *, operation: AggregationOperationKind, document_status_raw: str | None, expected_parent: str | None, expected_children: Sequence[str], actual_children: Sequence[str], removed_children: Sequence[str] = (), child_parents: Mapping[str, str | None] | None = None, history_events: Sequence[AggregationHistoryEvent] = ()) -> AggregationReconciliationResult:
        if document_status_raw != "CHECKED_OK":
            return AggregationReconciliationResult(AggregationReconciliationState.RECONCILIATION_PENDING, "DOCUMENT_NOT_CONFIRMED_SUCCESS")
        actual = set(actual_children); expected = set(expected_children); removed = set(removed_children)
        if operation in {AggregationOperationKind.FORM_TRANSPORT_PACKAGE, AggregationOperationKind.FORM_MULTIPRODUCT_TRANSPORT_PACKAGE, AggregationOperationKind.FORM_SET, AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY}:
            if actual == expected and (not child_parents or all(child_parents.get(c) == expected_parent for c in expected)):
                return AggregationReconciliationResult(AggregationReconciliationState.RECONCILED, "EXACT_RELATION_CONFIRMED", expected_parent)
        elif operation is AggregationOperationKind.TRANSFORM_PACKAGE_ADD:
            if expected <= actual:
                return AggregationReconciliationResult(AggregationReconciliationState.RECONCILED, "ADD_RELATION_CONFIRMED", expected_parent)
        elif operation is AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE:
            if actual == expected and not (removed & actual):
                return AggregationReconciliationResult(AggregationReconciliationState.RECONCILED, "REMOVE_RELATION_CONFIRMED", expected_parent)
        elif operation is AggregationOperationKind.DISAGGREGATE_PACKAGE:
            history_ok = any(x.semantic in {AggregationHistorySemantic.DISAGGREGATION, AggregationHistorySemantic.AUTO_DISAGGREGATION} for x in history_events)
            parents_clear = not child_parents or all(child_parents.get(c) != expected_parent for c in expected | removed)
            if not actual and parents_clear and history_ok:
                return AggregationReconciliationResult(AggregationReconciliationState.RECONCILED, "DISAGGREGATION_RELATION_AND_HISTORY_CONFIRMED", expected_parent)
        return AggregationReconciliationResult(AggregationReconciliationState.MANUAL_REVIEW, "RELATION_STATE_MISMATCH", expected_parent)

    def reconcile_atk_formation(self, *, document_status_raw: str | None, submitted_children: Sequence[str], child_parents: Mapping[str, str | None], parent_package_types: Mapping[str, str | None], parent_children: Mapping[str, Sequence[str]]) -> AggregationReconciliationResult:
        if document_status_raw != "CHECKED_OK":
            return AggregationReconciliationResult(AggregationReconciliationState.RECONCILIATION_PENDING, "DOCUMENT_NOT_CONFIRMED_SUCCESS")
        parents = {child_parents.get(c) for c in submitted_children}
        parents.discard(None)
        if len(parents) != 1:
            return AggregationReconciliationResult(AggregationReconciliationState.MANUAL_REVIEW, "ATK_PARENT_DISCOVERY_AMBIGUOUS")
        parent = next(iter(parents))
        if parent_package_types.get(parent) != PackageType.ATK.value:
            return AggregationReconciliationResult(AggregationReconciliationState.MANUAL_REVIEW, "DISCOVERED_PARENT_NOT_ATK")
        if set(parent_children.get(parent, ())) != set(submitted_children):
            return AggregationReconciliationResult(AggregationReconciliationState.MANUAL_REVIEW, "ATK_RELATION_MISMATCH", parent)
        return AggregationReconciliationResult(AggregationReconciliationState.RECONCILED, "ATK_PARENT_DISCOVERED_AND_RELATION_CONFIRMED", parent)


AUTO_DISAGGREGATION_EFFECTS: Mapping[str, Mapping[str, str]] = {
    "KITU_CHILD_ACTION": {"parent": "BOX", "effect": "EXPECT_AUTO_DISAGGREGATION", "exception": "FTS_COLOR_SIZE"},
    "INTRODUCE_NESTED_CHILD": {"effect": "EXPECT_AUTO_DISAGGREGATION"},
    "KIN_APPLIED_CHILD_INTRODUCE": {"parent": "SET", "effect": "EXPECT_AUTO_DISAGGREGATION"},
    "KIN_SALE_PARENT_OR_CHILD": {"parent": "SET", "effect": "EXPECT_AUTO_DISAGGREGATION"},
    "LP_RETURN_AGGREGATE": {"aggregate": "GROUP_OR_SET", "effect": "PRESERVE_RELATION_AND_RETURN_CHILDREN"},
    "LP_RETURN_NESTED_CHILD": {"effect": "EXPECT_AUTO_DISAGGREGATION"},
    "LK_RECEIPT_NESTED_CHILD": {"effect": "EXPECT_HIGHER_PARENT_DISAGGREGATION"},
    "LK_REMARK_KIN": {"effect": "TYPE_SPECIFIC_RECONCILIATION"},
    "ATK_CHILD_STATUS_OR_OWNER_CHANGE": {"parent": "ATK", "effect": "EXPECT_AUTO_DISAGGREGATION"},
    "WRITE_OFF_KITU_CHILD": {"parent": "BOX", "effect": "EXPECT_AUTO_DISAGGREGATION"},
    "WRITE_OFF_KIN_CHILD": {"parent": "SET", "effect": "MANUAL_REVIEW_EXACT_EFFECT_NOT_DOCUMENTED"},
}

M5_AGGREGATION_HARDENING: Mapping[str, str] = {
    "LK_RECEIPT_DISTANCE": "CAPTURE_PARENT_GRAPH_AND_RECONCILE_AUTO_DISAGGREGATION",
    "LP_RETURN": "DISTINGUISH_AGGREGATE_RETURN_FROM_NESTED_CHILD_RETURN",
    "WRITE_OFF_KITU": "RECONCILE_AUTO_DISAGGREGATION",
    "WRITE_OFF_KIN": "MANUAL_REVIEW_AND_RAW_RECONCILIATION",
    "LK_REMARK_KIN": "TYPE_SPECIFIC_INTRODUCED_RETIRED_RECONCILIATION",
    "INTRODUCTION": "CAPTURE_PARENT_AND_RECONCILE_CHILD_SEPARATE_INTRODUCTION",
    "LP_FTS_INTRODUCE": "USE_EXACT_AGGREGATE_EXCEPTION_PATHS",
    "LK_RECEIPT_CANCEL": "REREAD_RELATION_GRAPH_DO_NOT_ASSUME_RESTORATION",
}


def operation_evidence_hash(value: Mapping[str, Any]) -> str:
    import json
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
