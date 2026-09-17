from datetime import datetime, timezone

import pytest

from wbcz.aggregation import (
    AggregationContractError, AggregationDocument, AggregationHistorySemantic, AggregationManualReview,
    AggregationOperationKind, AggregationPreconditionService, AggregationReconciliationService,
    AggregationReconciliationState, AggregationUnit, AtkAggregationDocument, AtkDisaggregationDocument,
    AtkTransformationDocument, CisAggregationSnapshot, DisaggregationDocument, LP_PARENT_CHILDREN,
    M5_AGGREGATION_HARDENING, M6_DOCUMENT_TYPES, M6_OPERATION_REGISTRY, PackageType,
    ReaggregationDocument, ReaggregationItem, SetAggregationUnit, SetCompositionRequirement,
    SetsAggregationDocument, UnitSerialNumberType, build_aggregate_tree, normalize_aggregation_history_event,
    prepare_aggregation_document, validate_atk_preconditions, validate_box_preconditions,
    validate_aggregate_identifier, validate_lp_relation, validate_set_preconditions,
)


from wbcz.aggregation import (
    M5AggregationObservation, validate_atk_disaggregation_preconditions,
    validate_atk_transformation_preconditions, validate_disaggregation_preconditions,
    validate_reaggregation_preconditions, reconcile_m5_aggregation_side_effect,
)
from wbcz.turnover import CisSnapshot as TurnoverCisSnapshot, OperationReconciliationService, ReconciliationState, TurnoverOperationKind

INN = "1234567890"
C1 = "010123456789012321ABCDEF"
C2 = "010123456789012321ABCDEG"
C3 = "010123456789012321ABCDEH"
PARENT = "010123456789012321PARENT1"
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def snap(cis=C1, package=PackageType.UNIT, pg="lp", status="APPLIED", status_ex=None, owner=INN, emission="LOCAL", parent=None, children=(), gtin="04601234567890", tnved="6204430000"):
    return CisAggregationSnapshot(cis, package, pg, status, status_ex, owner, emission, parent, tuple(children), gtin, tnved, NOW)


def test_package_type_and_unit_serial_number_type_are_distinct_and_product_set_wire_value() -> None:
    assert PackageType.SET.value == "SET"
    assert UnitSerialNumberType.PRODUCT_SET.value == "PRODUCT_SET"
    assert PackageType.SET.value != UnitSerialNumberType.PRODUCT_SET.value
    assert PackageType.BUNDLE.value == "BUNDLE"


def test_lp_parent_child_matrix_group_parent_and_nested_set_fail_closed_nested_box_allowed() -> None:
    validate_lp_relation(PackageType.SET, PackageType.UNIT)
    validate_lp_relation(PackageType.SET, PackageType.BUNDLE)
    with pytest.raises(AggregationContractError): validate_lp_relation(PackageType.SET, PackageType.SET)
    with pytest.raises(AggregationManualReview): validate_lp_relation(PackageType.GROUP, PackageType.UNIT)
    validate_lp_relation(PackageType.BOX, PackageType.BOX)
    with pytest.raises(AggregationContractError): validate_lp_relation(PackageType.BOX, PackageType.GROUP, child_pg="lp", mixed_pg=True)
    validate_lp_relation(PackageType.BOX, PackageType.GROUP, child_pg="milk", mixed_pg=True)


def test_operation_registry_separates_dedicated_and_generic_set_and_auto_is_not_submit() -> None:
    assert M6_OPERATION_REGISTRY[AggregationOperationKind.FORM_SET].document_type == "SETS_AGGREGATION"
    assert M6_OPERATION_REGISTRY[AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY].document_type == "AGGREGATION_DOCUMENT"
    assert not M6_OPERATION_REGISTRY[AggregationOperationKind.AUTO_DISAGGREGATION].executable
    assert "ATK_AGGREGATION" in M6_DOCUMENT_TYPES


def test_aggregation_document_exact_names_no_partnumber_for_lp_and_same_parent_shape() -> None:
    doc = AggregationDocument(INN, (AggregationUnit(PARENT, UnitSerialNumberType.BOX, (C1, C2)),))
    wire = doc.to_wire()
    assert set(wire) == {"participantId", "aggregationUnits"}
    unit = wire["aggregationUnits"][0]
    assert set(unit) == {"unitSerialNumber", "unitSerialNumberType", "aggregationType", "sntins"}
    assert unit["unitSerialNumberType"] == "BOX" and unit["aggregationType"] == "AGGREGATION"
    with pytest.raises(AggregationManualReview):
        AggregationUnit(PARENT, UnitSerialNumberType.BOX, (C1,), part_number="x").to_wire()


def test_set_document_exact_wire_and_preconditions_applied_and_introduced() -> None:
    wire = SetsAggregationDocument(INN, (SetAggregationUnit(PARENT, (C1, C2)),)).to_wire()
    assert wire == {"participantId": INN, "aggregationUnits": [{"unitSerialNumber": PARENT, "sntins": [C1, C2]}]}
    parent = snap(PARENT, PackageType.SET, status="APPLIED", emission="LOCAL")
    validate_set_preconditions(parent=parent, children=(snap(C1), snap(C2)), composition=SetCompositionRequirement(gtin_quantities={"04601234567890": 2}), participant_inn=INN)
    introduced = (snap(C1, status="INTRODUCED", emission="FOREIGN"), snap(C2, status="INTRODUCED", emission="LOCAL"))
    validate_set_preconditions(parent=parent, children=introduced, composition=SetCompositionRequirement(marked_products_quantity_in_set=2), participant_inn=INN)


def test_set_rejects_invalid_children_remark_reapply_and_composition_mismatch() -> None:
    parent = snap(PARENT, PackageType.SET, status="APPLIED", emission="LOCAL")
    with pytest.raises(AggregationContractError):
        validate_set_preconditions(parent=parent, children=(snap(C1, PackageType.BOX),), composition=SetCompositionRequirement(marked_products_quantity_in_set=1), participant_inn=INN)
    with pytest.raises(AggregationManualReview, match="REMARK_REAPPLY"):
        validate_set_preconditions(parent=snap(PARENT, PackageType.SET, emission="REMARK"), children=(snap(C1, emission="REMARK"),), composition=SetCompositionRequirement(marked_products_quantity_in_set=1), participant_inn=INN)
    with pytest.raises(AggregationManualReview, match="QUANTITY"):
        validate_set_preconditions(parent=parent, children=(snap(C1),), composition=SetCompositionRequirement(marked_products_quantity_in_set=2), participant_inn=INN)


def test_box_preconditions_nested_box_mixed_pg_leading_rule_owner_status_ex() -> None:
    validate_box_preconditions(parent=None, children=(snap(C1), snap(C2, PackageType.BOX)), participant_inn=INN)
    mixed = (
        snap(C1, pg="lp", status="INTRODUCED", status_ex=None),
        snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER"),
    )
    validate_box_preconditions(parent=None, children=mixed, participant_inn=INN, mixed_pg=True, leading_pg="lp")
    with pytest.raises(AggregationManualReview, match="LEADING_PG"):
        validate_box_preconditions(parent=None, children=(snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED"),), participant_inn=INN, mixed_pg=True, leading_pg="lp")
    with pytest.raises(AggregationManualReview, match="NON_OWNER"):
        validate_box_preconditions(parent=None, children=(snap(C1, owner="9999999999"),), participant_inn=INN)
    with pytest.raises(AggregationManualReview, match="STATUS_EX"):
        validate_box_preconditions(parent=None, children=(snap(C1, status_ex="UNKNOWN"),), participant_inn=INN)


def test_reaggregation_exact_xor_and_add_remove_operation_lock() -> None:
    with pytest.raises(AggregationContractError): ReaggregationItem().to_wire()
    with pytest.raises(AggregationContractError): ReaggregationItem(C1, C2).to_wire()
    doc = ReaggregationDocument(INN, "ADDING", PARENT, (ReaggregationItem(uit_uitu=C1), ReaggregationItem(kitu=C2)))
    wire = doc.to_wire()
    assert wire["reaggregation_type"] == "ADDING"
    assert wire["uit_uitu_list"] == [{"uit_uitu": C1}, {"kitu": C2}]
    prepare_aggregation_document(AggregationOperationKind.TRANSFORM_PACKAGE_ADD, doc)
    with pytest.raises(AggregationContractError): prepare_aggregation_document(AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE, doc)


def test_disaggregation_exact_contract_and_no_formed_enum_or_result_assumption() -> None:
    wire = DisaggregationDocument(INN, (PARENT,)).to_wire()
    assert wire == {"participant_inn": INN, "products_list": [{"uitu": PARENT}]}
    import wbcz.aggregation as a
    assert not hasattr(a, "FORMED")
    assert "DISAGGREGATION" not in {x.value for x in a.AggregationReconciliationState}


def test_atk_importer_owner_foreign_applied_tnved_and_status_ex_rules() -> None:
    children = (snap(C1, emission="FOREIGN"), snap(C2, emission="FOREIGN"))
    validate_atk_preconditions(role="IMPORTER", participant_inn=INN, children=children)
    with pytest.raises(AggregationManualReview, match="IMPORTER"): validate_atk_preconditions(role="SELLER", participant_inn=INN, children=children)
    with pytest.raises(AggregationManualReview, match="FOREIGN"): validate_atk_preconditions(role="IMPORTER", participant_inn=INN, children=(snap(C1),))
    with pytest.raises(AggregationManualReview, match="STATUS_EX"): validate_atk_preconditions(role="IMPORTER", participant_inn=INN, children=(snap(C1, emission="FOREIGN", status_ex="FTS_CONTROL"),))
    validate_atk_preconditions(role="IMPORTER", participant_inn=INN, children=(snap(C1, emission="FOREIGN", status_ex="FTS_CONTROL"),), allow_fts_control=True)


def test_atk_wire_contracts_and_no_synthetic_parent_id() -> None:
    form = AtkAggregationDocument(INN, (C1, C2)).to_wire()
    assert set(form) == {"trade_participant_inn", "products_list"}
    assert "atk" not in form
    transform = AtkTransformationDocument(INN, PARENT, "REMOVING", (C1,)).to_wire()
    assert transform["atk"] == PARENT and transform["transformation_type"] == "REMOVING"
    dis = AtkDisaggregationDocument(INN, (PARENT,)).to_wire()
    assert dis["products_list"] == [{"atk": PARENT}]


def test_history_recognizes_both_auto_spellings_preserves_raw_and_tolerates_dates() -> None:
    for raw in ("AUTODISAGGREGATED", "AUTODISAGGREGATION"):
        ev = normalize_aggregation_history_event({"operationType": raw, "operationDate": "2021-08-10T10:11:01.000Z", "parent": PARENT})
        assert ev.semantic is AggregationHistorySemantic.AUTO_DISAGGREGATION
        assert ev.raw_operation_type == raw and ev.parsed_operation_date is not None
    ev = normalize_aggregation_history_event({"operationType": "TRANSFORMATION", "operationDate": "2021-08-10 10:11:01"})
    assert ev.semantic is AggregationHistorySemantic.TRANSFORMATION and ev.parsed_operation_date is not None
    unknown = normalize_aggregation_history_event({"operationType": 105, "operationDate": "not-a-date"})
    assert unknown.semantic is AggregationHistorySemantic.UNKNOWN and unknown.raw_operation_type == 105


def test_tree_recurses_nested_box_cycle_protection_and_internal_limit_metadata() -> None:
    edges = {PARENT: [C1, C2], C2: [C3], C3: [PARENT]}
    result = build_aggregate_tree(PARENT, direct_children=lambda x: edges.get(x, []), package_type_of=lambda x: "BOX" if x in {PARENT, C2} else "UNIT")
    assert not result.complete and "CYCLE_DETECTED" in result.warnings
    truncated = build_aggregate_tree(PARENT, direct_children=lambda x: [C1] if x == PARENT else [C2] if x == C1 else [], package_type_of=lambda x: "BOX", safety_max_depth=1)
    assert truncated.truncated and "INTERNAL_SAFETY_LIMIT" in truncated.warnings


def test_reconciliation_checked_ok_alone_is_insufficient_and_relation_required() -> None:
    svc = AggregationReconciliationService()
    pending = svc.reconcile_relation(operation=AggregationOperationKind.FORM_SET, document_status_raw="IN_PROGRESS", expected_parent=PARENT, expected_children=(C1,), actual_children=(C1,))
    assert pending.state is AggregationReconciliationState.RECONCILIATION_PENDING
    mismatch = svc.reconcile_relation(operation=AggregationOperationKind.FORM_SET, document_status_raw="CHECKED_OK", expected_parent=PARENT, expected_children=(C1,), actual_children=())
    assert mismatch.state is AggregationReconciliationState.MANUAL_REVIEW
    ok = svc.reconcile_relation(operation=AggregationOperationKind.FORM_SET, document_status_raw="CHECKED_OK", expected_parent=PARENT, expected_children=(C1,), actual_children=(C1,), child_parents={C1: PARENT})
    assert ok.state is AggregationReconciliationState.RECONCILED


def test_atk_parent_discovery_requires_one_remote_parent_and_atk_type_no_synthesis() -> None:
    svc = AggregationReconciliationService()
    ok = svc.reconcile_atk_formation(document_status_raw="CHECKED_OK", submitted_children=(C1, C2), child_parents={C1: PARENT, C2: PARENT}, parent_package_types={PARENT: "ATK"}, parent_children={PARENT: (C1, C2)})
    assert ok.state is AggregationReconciliationState.RECONCILED and ok.discovered_parent_cis == PARENT
    bad = svc.reconcile_atk_formation(document_status_raw="CHECKED_OK", submitted_children=(C1, C2), child_parents={C1: PARENT, C2: C3}, parent_package_types={PARENT: "ATK", C3: "ATK"}, parent_children={})
    assert bad.state is AggregationReconciliationState.MANUAL_REVIEW


def test_precondition_freshness_and_m5_hardening_registry() -> None:
    service = AggregationPreconditionService(INN, now=lambda: NOW)
    service.require_fresh((snap(C1),))
    service.require_owner((snap(C1),))
    stale = CisAggregationSnapshot(C1, PackageType.UNIT, "lp", "APPLIED", None, INN, "LOCAL", None, (), None, None, datetime(2020, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(AggregationManualReview, match="STALE"): service.require_fresh((stale,))
    assert M5_AGGREGATION_HARDENING["LK_RECEIPT_CANCEL"].startswith("REREAD_RELATION")
    assert M5_AGGREGATION_HARDENING["WRITE_OFF_KIN"].startswith("MANUAL_REVIEW")


def test_no_generic_move_cancel_or_generic_write_symbols() -> None:
    import wbcz.aggregation as a
    forbidden = {"MOVE_CHILD", "CANCEL_AGGREGATION", "GENERIC_AGGREGATION_WRITE", "GENERIC_DOCUMENT_SUBMIT", "RAW_URL", "RAW_PATH", "RAW_METHOD"}
    assert forbidden.isdisjoint(set(dir(a)))


def test_generic_set_compatibility_requires_product_set_and_transport_requires_box() -> None:
    generic = AggregationDocument(INN, (AggregationUnit(PARENT, UnitSerialNumberType.PRODUCT_SET, (C1,)),))
    prepare_aggregation_document(AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY, generic)
    with pytest.raises(AggregationContractError):
        prepare_aggregation_document(AggregationOperationKind.FORM_SET_GENERIC_COMPATIBILITY, AggregationDocument(INN, (AggregationUnit(PARENT, UnitSerialNumberType.BOX, (C1,)),)))
    with pytest.raises(AggregationContractError):
        prepare_aggregation_document(AggregationOperationKind.FORM_TRANSPORT_PACKAGE, generic)


def test_bundle_is_lp_only_and_tree_unknown_package_is_incomplete() -> None:
    with pytest.raises(AggregationContractError, match="only for lp"):
        validate_lp_relation(PackageType.BOX, PackageType.BUNDLE, child_pg="milk", mixed_pg=True)
    result=build_aggregate_tree(PARENT, direct_children=lambda _: (), package_type_of=lambda _: "FUTURE_PACKAGE")
    assert not result.complete and any(x.startswith("UNKNOWN_RAW_PACKAGE_TYPE") for x in result.warnings)


def test_reaggregation_preconditions_set_box_remove_and_leading_pg() -> None:
    set_parent=snap(PARENT, PackageType.SET, status="INTRODUCED")
    child=snap(C1, PackageType.UNIT, status="INTRODUCED", parent=PARENT)
    validate_reaggregation_preconditions(parent=set_parent, children=(child,), reaggregation_type="REMOVING", participant_inn=INN)
    with pytest.raises(AggregationContractError):
        validate_reaggregation_preconditions(parent=set_parent, children=(snap(C2, PackageType.BOX, status="INTRODUCED", parent=PARENT),), reaggregation_type="REMOVING", participant_inn=INN)
    box_parent=snap(PARENT, PackageType.BOX, status="RUNTIME_FORMED_VALUE")
    removed=snap(C1, PackageType.UNIT, status="INTRODUCED", parent=PARENT)
    with pytest.raises(AggregationManualReview, match="LEADING_PG"):
        validate_reaggregation_preconditions(
            parent=box_parent, children=(removed,), reaggregation_type="REMOVING", participant_inn=INN,
            remaining_children=(snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", parent=PARENT),),
            mixed_pg=True, leading_pg="lp", runtime_formed_status_values=frozenset({"RUNTIME_FORMED_VALUE"}),
        )



def test_aggregate_identifier_exact_charset_boundaries_and_generic_child_validator_separate() -> None:
    allowed_specials = "A%&'\"()*+,-_./:;<=>?!"
    assert len(allowed_specials) == 21
    assert validate_aggregate_identifier(allowed_specials) == allowed_specials
    assert validate_aggregate_identifier("A" * 18) == "A" * 18
    assert validate_aggregate_identifier("Z" * 74) == "Z" * 74
    for invalid in ("A" * 17, "A" * 75, "A" * 17 + "@", "A" * 17 + "Ж", "A" * 17 + " "):
        with pytest.raises(AggregationContractError):
            validate_aggregate_identifier(invalid)
    child_with_at = "010123456789012321@CHILD"
    wire = AggregationUnit(PARENT, UnitSerialNumberType.BOX, (child_with_at,)).to_wire()
    assert wire["sntins"] == [child_with_at]


def test_aggregate_identifier_validator_is_used_on_parent_wire_positions() -> None:
    bad = "A" * 17 + "@"
    with pytest.raises(AggregationContractError):
        AggregationUnit(bad, UnitSerialNumberType.BOX, (C1,)).to_wire()
    with pytest.raises(AggregationContractError):
        SetAggregationUnit(bad, (C1,)).to_wire()
    with pytest.raises(AggregationContractError):
        ReaggregationDocument(INN, "ADDING", bad, (ReaggregationItem(uit_uitu=C1),)).to_wire()
    with pytest.raises(AggregationContractError):
        ReaggregationItem(kitu=bad).to_wire()
    with pytest.raises(AggregationContractError):
        DisaggregationDocument(INN, (bad,)).to_wire()


def test_multiproduct_kitu_formation_uses_current_status_semantics_and_runtime_gate() -> None:
    introduced = (
        snap(C1, pg="lp", status="INTRODUCED", status_ex=None),
        snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER"),
    )
    validate_box_preconditions(parent=None, children=introduced, participant_inn=INN, mixed_pg=True, leading_pg="lp")
    with pytest.raises(AggregationManualReview, match="STATUS_NOT_CONFIRMED"):
        validate_box_preconditions(
            parent=None,
            children=(snap(C1, pg="lp", status="APPLIED"), snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED")),
            participant_inn=INN, mixed_pg=True, leading_pg="lp",
        )
    unknown_formed = (
        snap(C1, pg="lp", status="RUNTIME_FORMED_VALUE"),
        snap(C2, PackageType.GROUP, pg="milk", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER"),
    )
    with pytest.raises(AggregationManualReview, match="STATUS_NOT_CONFIRMED"):
        validate_box_preconditions(parent=None, children=unknown_formed, participant_inn=INN, mixed_pg=True, leading_pg="lp")
    validate_box_preconditions(
        parent=None, children=unknown_formed, participant_inn=INN, mixed_pg=True, leading_pg="lp",
        runtime_formed_status_values=frozenset({"RUNTIME_FORMED_VALUE"}),
    )
    import wbcz.aggregation as a
    assert not hasattr(a, "FORMED")


def test_multiproduct_kitu_transformation_removes_old_status_equality_and_runtime_gates_parent() -> None:
    parent = snap(PARENT, PackageType.BOX, pg="lp", status="RUNTIME_FORMED_VALUE", status_ex=None)
    introduced = snap(C1, PackageType.UNIT, pg="lp", status="INTRODUCED", status_ex=None, parent=PARENT)
    formed = snap(C2, PackageType.GROUP, pg="milk", status="RUNTIME_FORMED_VALUE", status_ex="WAIT_TRANSFER_TO_OWNER", parent=PARENT)
    remaining = (snap(C3, PackageType.UNIT, pg="lp", status="INTRODUCED", status_ex="WAIT_TRANSFER_TO_OWNER", parent=PARENT),)
    with pytest.raises(AggregationManualReview, match="PARENT_STATUS_RUNTIME_CONFIRMATION_REQUIRED"):
        validate_reaggregation_preconditions(
            parent=parent, children=(introduced,), reaggregation_type="REMOVING", participant_inn=INN,
            mixed_pg=True, leading_pg="lp", remaining_children=remaining,
        )
    runtime = frozenset({"RUNTIME_FORMED_VALUE"})
    validate_reaggregation_preconditions(
        parent=parent, children=(introduced,), reaggregation_type="REMOVING", participant_inn=INN,
        mixed_pg=True, leading_pg="lp", remaining_children=remaining, runtime_formed_status_values=runtime,
    )
    validate_reaggregation_preconditions(
        parent=parent, children=(formed,), reaggregation_type="REMOVING", participant_inn=INN,
        mixed_pg=True, leading_pg="lp", remaining_children=remaining, runtime_formed_status_values=runtime,
    )
    with pytest.raises(AggregationManualReview, match="STATUS_NOT_CONFIRMED"):
        validate_reaggregation_preconditions(
            parent=parent,
            children=(snap(C2, PackageType.GROUP, pg="milk", status="UNKNOWN_FORMED_RAW", parent=PARENT),),
            reaggregation_type="REMOVING", participant_inn=INN, mixed_pg=True, leading_pg="lp",
            remaining_children=remaining, runtime_formed_status_values=runtime,
        )


def test_ordinary_kitu_retains_identical_applied_or_introduced_rules() -> None:
    validate_box_preconditions(parent=None, children=(snap(C1), snap(C2)), participant_inn=INN)
    with pytest.raises(AggregationManualReview, match="STATUSES_MUST_MATCH"):
        validate_box_preconditions(
            parent=None, children=(snap(C1, status="APPLIED"), snap(C2, status="INTRODUCED")), participant_inn=INN
        )

def test_disaggregation_preconditions_no_formed_enum_and_runtime_formed_value_is_explicit() -> None:
    validate_disaggregation_preconditions(parents=(snap(PARENT, PackageType.BOX, status="INTRODUCED"),), participant_inn=INN)
    formed=snap(PARENT, PackageType.BOX, status="RUNTIME_FORMED_VALUE")
    with pytest.raises(AggregationManualReview):
        validate_disaggregation_preconditions(parents=(formed,), participant_inn=INN)
    validate_disaggregation_preconditions(parents=(formed,), participant_inn=INN, runtime_formed_status_values=frozenset({"RUNTIME_FORMED_VALUE"}))
    with pytest.raises(AggregationManualReview, match="GROUP"):
        validate_disaggregation_preconditions(parents=(snap(PARENT, PackageType.GROUP, status="INTRODUCED"),), participant_inn=INN)


def test_atk_transformation_and_disaggregation_status_ex_are_operation_specific() -> None:
    atk_parent=snap(PARENT, PackageType.ATK, status="APPLIED", emission="FOREIGN", status_ex="FTS_RESPOND_NOT_OK", children=(C1,))
    child=snap(C1, PackageType.UNIT, status="APPLIED", emission="FOREIGN", parent=PARENT)
    validate_atk_transformation_preconditions(role="IMPORTER", participant_inn=INN, parent=atk_parent, children=(child,), transformation_type="REMOVING")
    with pytest.raises(AggregationManualReview, match="STATUS_EX"):
        validate_atk_transformation_preconditions(role="IMPORTER", participant_inn=INN, parent=snap(PARENT, PackageType.ATK, status="APPLIED", emission="FOREIGN", status_ex="FTS_CONTROL"), children=(child,), transformation_type="REMOVING")
    validate_atk_disaggregation_preconditions(role="IMPORTER", participant_inn=INN, parents=(snap(PARENT, PackageType.ATK, status="APPLIED", emission="FOREIGN", status_ex="FTS_CONTROL"),))


def test_reconciliation_requires_exact_add_parents_and_disaggregation_state_readback() -> None:
    svc=AggregationReconciliationService()
    bad_add=svc.reconcile_relation(operation=AggregationOperationKind.TRANSFORM_PACKAGE_ADD, document_status_raw="CHECKED_OK", expected_parent=PARENT, expected_children=(C1,C2), actual_children=(C1,C2,C3), child_parents={C1:PARENT,C2:PARENT,C3:PARENT})
    assert bad_add.state is AggregationReconciliationState.MANUAL_REVIEW
    event=normalize_aggregation_history_event({"operationType":"DISAGGREGATION","operationDate":"2021-08-10 10:11:01"})
    pending=svc.reconcile_relation(operation=AggregationOperationKind.DISAGGREGATE_PACKAGE, document_status_raw="CHECKED_OK", expected_parent=PARENT, expected_children=(C1,), actual_children=(), child_parents={C1:None}, history_events=(event,))
    assert pending.state is AggregationReconciliationState.MANUAL_REVIEW
    ok=svc.reconcile_relation(operation=AggregationOperationKind.DISAGGREGATE_PACKAGE, document_status_raw="CHECKED_OK", expected_parent=PARENT, expected_children=(C1,), actual_children=(), child_parents={C1:None}, history_events=(event,), parent_status_raw_observed="SOME_RUNTIME_STATUS")
    assert ok.state is AggregationReconciliationState.RECONCILED


def test_atk_transform_and_disaggregation_reconciliation() -> None:
    svc=AggregationReconciliationService()
    add=svc.reconcile_atk_transformation(document_status_raw="CHECKED_OK", parent=PARENT, expected_children=(C1,C2), actual_children=(C1,C2), changed_children=(C2,), transformation_type="ADDING", child_parents={C1:PARENT,C2:PARENT})
    assert add.state is AggregationReconciliationState.RECONCILED
    event=normalize_aggregation_history_event({"operationType":"DISAGGREGATION","operationDate":"2021-08-10T10:11:01Z"})
    dis=svc.reconcile_atk_disaggregation(document_status_raw="CHECKED_OK", parent=PARENT, actual_children=(), former_children=(C1,), child_parents={C1:None}, history_events=(event,))
    assert dis.state is AggregationReconciliationState.RECONCILED


def test_m5_aggregation_hardening_requires_relation_readback_and_models_known_effects() -> None:
    obs=M5AggregationObservation(C1,PARENT,PackageType.BOX,None,relation_read_complete=True,history_semantics=(AggregationHistorySemantic.AUTO_DISAGGREGATION,))
    result=reconcile_m5_aggregation_side_effect(operation_kind="WITHDRAW_DISTANCE", observations=(obs,))
    assert result.state is AggregationReconciliationState.RECONCILED
    missing=M5AggregationObservation(C1,PARENT,PackageType.BOX,PARENT,relation_read_complete=False)
    assert reconcile_m5_aggregation_side_effect(operation_kind="WITHDRAW_DISTANCE", observations=(missing,)).state is AggregationReconciliationState.RECONCILIATION_PENDING
    kin=M5AggregationObservation(C1,PARENT,PackageType.SET,PARENT,relation_read_complete=True)
    assert reconcile_m5_aggregation_side_effect(operation_kind="WRITE_OFF", observations=(kin,)).state is AggregationReconciliationState.MANUAL_REVIEW


def test_m5_reconciliation_does_not_accept_checked_ok_when_parent_effect_unreconciled() -> None:
    svc=OperationReconciliationService()
    post=TurnoverCisSnapshot(C1,"RETIRED",None,INN,"DISTANCE",fetched_at=NOW,parent=None,package_type="UNIT")
    pending=svc.reconcile(operation_kind=TurnoverOperationKind.WITHDRAW_DISTANCE, document_status_raw="CHECKED_OK", snapshots=(post,), pre_parent_map={C1:PARENT})
    assert pending.state is ReconciliationState.PENDING and pending.reason == "AGGREGATION_RECONCILIATION_REQUIRED"
    obs=M5AggregationObservation(C1,PARENT,PackageType.BOX,None,relation_read_complete=True,history_semantics=(AggregationHistorySemantic.AUTO_DISAGGREGATION,))
    ok=svc.reconcile(operation_kind=TurnoverOperationKind.WITHDRAW_DISTANCE, document_status_raw="CHECKED_OK", snapshots=(post,), pre_parent_map={C1:PARENT}, aggregation_observations=(obs,))
    assert ok.state is ReconciliationState.RECONCILED


def test_cancel_withdrawal_requires_relation_reread_when_pre_parent_exists() -> None:
    svc=OperationReconciliationService()
    restored=TurnoverCisSnapshot(C1,"INTRODUCED",None,INN,None,fetched_at=NOW,parent=PARENT,package_type="UNIT")
    pending=svc.reconcile(operation_kind=TurnoverOperationKind.CANCEL_WITHDRAWAL, document_status_raw="CHECKED_OK", snapshots=(restored,), expected_restore={C1:("INTRODUCED",None)}, pre_parent_map={C1:PARENT})
    assert pending.state is ReconciliationState.PENDING
    obs=M5AggregationObservation(C1,PARENT,PackageType.BOX,PARENT,relation_read_complete=True)
    ok=svc.reconcile(operation_kind=TurnoverOperationKind.CANCEL_WITHDRAWAL, document_status_raw="CHECKED_OK", snapshots=(restored,), expected_restore={C1:("INTRODUCED",None)}, pre_parent_map={C1:PARENT}, aggregation_observations=(obs,))
    assert ok.state is ReconciliationState.RECONCILED


def test_aggregation_document_rejects_same_child_under_two_parents() -> None:
    parent2 = "010123456789012321PARENT2"
    doc=AggregationDocument(INN,(AggregationUnit(PARENT,UnitSerialNumberType.BOX,(C1,)),AggregationUnit(parent2,UnitSerialNumberType.BOX,(C1,))))
    with pytest.raises(AggregationContractError, match="only once"):
        doc.to_wire()


def test_set_owner_parent_relation_and_product_group_fail_closed() -> None:
    composition=SetCompositionRequirement(marked_products_quantity_in_set=1)
    parent=snap(PARENT,PackageType.SET,status="APPLIED",emission="LOCAL")
    with pytest.raises(AggregationManualReview, match="NON_OWNER"):
        validate_set_preconditions(parent=parent,children=(snap(C1,owner="9999999999"),),composition=composition,participant_inn=INN)
    with pytest.raises(AggregationManualReview, match="ALREADY_AGGREGATED"):
        validate_set_preconditions(parent=parent,children=(snap(C1,parent=C2),),composition=composition,participant_inn=INN)
    with pytest.raises(AggregationManualReview, match="PRODUCT_GROUP"):
        validate_set_preconditions(parent=parent,children=(snap(C1,pg="milk"),),composition=composition,participant_inn=INN)


def test_kitu_parent_uniqueness_and_mixed_pg_requires_actual_pg() -> None:
    with pytest.raises(AggregationManualReview, match="ALREADY_PRESENT"):
        validate_box_preconditions(parent=snap(PARENT,PackageType.BOX),children=(snap(C1),),participant_inn=INN)
    missing_pg=snap(C1,pg=None,status="INTRODUCED")
    with pytest.raises(AggregationManualReview, match="PRODUCT_GROUP_REQUIRED"):
        validate_box_preconditions(parent=None,children=(missing_pg,),participant_inn=INN,mixed_pg=True,leading_pg="lp")


def test_atk_transformation_matches_parent_pg_tnved_and_foreign() -> None:
    parent=snap(PARENT,PackageType.ATK,status="APPLIED",emission="FOREIGN",tnved="6204430000")
    child=snap(C1,PackageType.UNIT,status="APPLIED",emission="FOREIGN",parent=PARENT,tnved="6204990000")
    validate_atk_transformation_preconditions(role="IMPORTER",participant_inn=INN,parent=parent,children=(child,),transformation_type="REMOVING")
    with pytest.raises(AggregationManualReview, match="MATCH_PARENT"):
        validate_atk_transformation_preconditions(role="IMPORTER",participant_inn=INN,parent=parent,children=(snap(C1,PackageType.UNIT,status="APPLIED",emission="FOREIGN",parent=PARENT,pg="milk",tnved="0401000000"),),transformation_type="REMOVING")
    with pytest.raises(AggregationManualReview, match="FOREIGN_PG_TNVED"):
        validate_atk_transformation_preconditions(role="IMPORTER",participant_inn=INN,parent=snap(PARENT,PackageType.ATK,status="APPLIED",emission="LOCAL"),children=(child,),transformation_type="REMOVING")


def test_remove_all_requires_auto_disaggregation_history_and_parent_state_readback() -> None:
    svc=AggregationReconciliationService()
    no_history=svc.reconcile_relation(operation=AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE,document_status_raw="CHECKED_OK",expected_parent=PARENT,expected_children=(),actual_children=(),removed_children=(C1,),child_parents={C1:None},parent_status_raw_observed="RUNTIME_STATE")
    assert no_history.state is AggregationReconciliationState.MANUAL_REVIEW
    event=normalize_aggregation_history_event({"operationType":"AUTODISAGGREGATED","operationDate":"2021-08-10T10:11:01Z"})
    no_state=svc.reconcile_relation(operation=AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE,document_status_raw="CHECKED_OK",expected_parent=PARENT,expected_children=(),actual_children=(),removed_children=(C1,),child_parents={C1:None},history_events=(event,))
    assert no_state.state is AggregationReconciliationState.MANUAL_REVIEW
    ok=svc.reconcile_relation(operation=AggregationOperationKind.TRANSFORM_PACKAGE_REMOVE,document_status_raw="CHECKED_OK",expected_parent=PARENT,expected_children=(),actual_children=(),removed_children=(C1,),child_parents={C1:None},history_events=(event,),parent_status_raw_observed="RUNTIME_STATE")
    assert ok.state is AggregationReconciliationState.RECONCILED


def test_auto_disaggregation_event_reconciliation_never_synthesizes_success() -> None:
    svc=AggregationReconciliationService()
    pending=svc.reconcile_auto_disaggregation(parent=PARENT,former_children=(C1,),actual_children=(),child_parents={C1:None},history_events=())
    assert pending.state is AggregationReconciliationState.RECONCILIATION_PENDING
    event=normalize_aggregation_history_event({"operationType":"AUTODISAGGREGATION","operationDate":"2021-08-10 10:11:01"})
    ok=svc.reconcile_auto_disaggregation(parent=PARENT,former_children=(C1,),actual_children=(),child_parents={C1:None},history_events=(event,))
    assert ok.state is AggregationReconciliationState.RECONCILED
