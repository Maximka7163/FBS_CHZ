from __future__ import annotations

import base64
import hashlib
import json
from datetime import date, datetime, timedelta, timezone

import pytest

from wbcz.turnover import (
    EAEU_DIRECT_SUBFLOW_DEFER_REASON,
    EAEU_DIRECT_SUBFLOW_IMPLEMENTED,
    KNOWN_FAIL_CLOSED_DOCUMENT_TYPES,
    M5_DOCUMENT_TYPES,
    M5_PG,
    TURNOVER_OPERATION_REGISTRY,
    CisSnapshot,
    LkReceiptCancelDocument,
    LkReceiptDistanceDocument,
    LkRemarkDocument,
    LpReturnDocument,
    ModLocation,
    OperationPreconditionService,
    OperationReconciliationService,
    PermitDocument,
    PrimaryDocument,
    ReconciliationState,
    RemarkProduct,
    ReturnProduct,
    TurnoverContractError,
    TurnoverManualReview,
    TurnoverOperationKind,
    WithdrawalProduct,
    WriteOffDocument,
    document_type_for_operation,
    prepare_turnover_document,
    remark_reason_readback_matches,
    validate_return_reason_matrix,
)
from wbcz.windows_agent import AgentJob, AgentJobType, AgentSecurityError, ProductionAgentTrueApiTransport


INN = "1234567890"
KPP = "123456789"
FIAS = "550e8400-e29b-41d4-a716-446655440000"
CIS = "010460123456789021ABC"
CIS2 = "010460123456789021DEF"
NOW = datetime(2026, 9, 17, 8, 0, tzinfo=timezone.utc)
TODAY = date(2026, 9, 17)


def _snapshot(
    cis: str = CIS,
    *,
    status: str = "INTRODUCED",
    status_ex: str | None = None,
    owner: str | None = INN,
    withdraw_reason: str | None = None,
    emission_type: str | None = None,
) -> CisSnapshot:
    return CisSnapshot(
        cis=cis,
        status=status,
        status_ex=status_ex,
        owner_inn=owner,
        withdraw_reason=withdraw_reason,
        emission_type=emission_type,
        fetched_at=NOW,
    )


def _distance() -> LkReceiptDistanceDocument:
    return LkReceiptDistanceDocument(
        inn=INN,
        action_date=TODAY,
        products=(WithdrawalProduct(CIS, 12345),),
        mod=ModLocation(fias_id=FIAS, legal_entity=True, kpp=KPP),
    )


def test_registry_exact_operation_document_mapping_and_lp_scope() -> None:
    expected = {
        TurnoverOperationKind.INTRODUCE_DOMESTIC: "LP_INTRODUCE_GOODS",
        TurnoverOperationKind.INTRODUCE_FROM_INDIVIDUAL: "LK_INDI_COMMISSIONING",
        TurnoverOperationKind.INTRODUCE_IMPORT_PRE_MANDATORY: "LP_GOODS_IMPORT",
        TurnoverOperationKind.INTRODUCE_EAEU: "CROSSBORDER",
        TurnoverOperationKind.INTRODUCE_REMAINS: "LP_INTRODUCE_OST",
        TurnoverOperationKind.INTRODUCE_CONTRACT: "LK_CONTRACT_COMMISSIONING",
        TurnoverOperationKind.INTRODUCE_FTS: "LP_FTS_INTRODUCE",
        TurnoverOperationKind.WITHDRAW: "LK_RECEIPT",
        TurnoverOperationKind.WITHDRAW_DISTANCE: "LK_RECEIPT",
        TurnoverOperationKind.RETURN_TO_CIRCULATION: "LP_RETURN",
        TurnoverOperationKind.RETURN_REMOTE_SALE: "LP_RETURN",
        TurnoverOperationKind.REMARK: "LK_REMARK",
        TurnoverOperationKind.WRITE_OFF: "WRITE_OFF",
        TurnoverOperationKind.CANCEL_WITHDRAWAL: "LK_RECEIPT_CANCEL",
    }
    assert {kind: item.document_type for kind, item in TURNOVER_OPERATION_REGISTRY.items()} == expected
    assert all(item.pg == (M5_PG,) for item in TURNOVER_OPERATION_REGISTRY.values())
    assert all(item.formats == ("MANUAL",) for item in TURNOVER_OPERATION_REGISTRY.values())
    assert "LK_UNIVERSAL_INTRODUCE" not in M5_DOCUMENT_TYPES
    assert "LP_SHIP_GOODS" not in M5_DOCUMENT_TYPES
    assert KNOWN_FAIL_CLOSED_DOCUMENT_TYPES["LP_CANCEL_SHIPMENT"] == "SOURCE_DOCUMENT_REQUIRED"
    assert TURNOVER_OPERATION_REGISTRY[TurnoverOperationKind.WITHDRAW].capability == (
        "NOT_EXECUTABLE_EXACT_REASON_CONTRACTS_UNAVAILABLE"
    )
    assert TURNOVER_OPERATION_REGISTRY[TurnoverOperationKind.WITHDRAW].supported_reasons == ()
    with pytest.raises(TurnoverContractError):
        document_type_for_operation("ARBITRARY")
    with pytest.raises(TurnoverManualReview, match="OPERATION_NOT_EXECUTABLE"):
        prepare_turnover_document(TurnoverOperationKind.WITHDRAW, _distance())


def test_eaeu_direct_subflow_is_explicitly_deferred() -> None:
    assert EAEU_DIRECT_SUBFLOW_IMPLEMENTED is False
    assert EAEU_DIRECT_SUBFLOW_DEFER_REASON == "EXACT_WIRE_CONTRACT_NOT_PRESENT"


def test_distance_wire_requires_cost_mod_and_has_no_synthetic_fields() -> None:
    wire = _distance().to_wire()
    assert wire == {
        "inn": INN,
        "action": "DISTANCE",
        "action_date": TODAY.isoformat(),
        "fias_id": FIAS,
        "kpp": KPP,
        "products": [{"cis": CIS, "product_cost": 12345}],
    }
    forbidden = {
        "buyer_inn", "withdrawal_type_other", "state_contract_id", "currency",
        "paid", "vat_amount", "fiscal_drive", "wb_sticker", "job_id",
    }
    assert forbidden.isdisjoint(wire)

    with pytest.raises(TypeError):
        WithdrawalProduct(CIS)  # type: ignore[call-arg]
    with pytest.raises(TurnoverContractError):
        LkReceiptDistanceDocument(
            inn=INN,
            action_date=TODAY,
            products=(WithdrawalProduct(CIS, 100),),
            mod=ModLocation(fias_id=FIAS, legal_entity=True, kpp=None),
        ).to_wire()


def test_distance_primary_document_is_optional_but_conditional_when_present() -> None:
    doc = LkReceiptDistanceDocument(
        inn=INN,
        action_date=TODAY,
        products=(WithdrawalProduct(CIS, 100),),
        mod=ModLocation(fias_id=FIAS, legal_entity=True, kpp=KPP),
        primary_document=PrimaryDocument("UTD", "42", TODAY),
    )
    wire = doc.to_wire()
    assert wire["document_type"] == "UTD"
    assert wire["document_number"] == "42"
    assert wire["document_date"] == TODAY.isoformat()
    with pytest.raises(TurnoverContractError):
        LkReceiptDistanceDocument(
            inn=INN,
            action_date=TODAY,
            products=(WithdrawalProduct(CIS, 100),),
            mod=ModLocation(fias_id=FIAS, legal_entity=True, kpp=KPP),
            primary_document=PrimaryDocument("UNKNOWN", "42", TODAY),
        ).to_wire()


def test_distance_date_rules_fail_closed() -> None:
    with pytest.raises(TurnoverContractError):
        LkReceiptDistanceDocument(
            inn=INN,
            action_date=date(2020, 1, 1),
            products=(WithdrawalProduct(CIS, 100),),
            mod=ModLocation(fias_id=FIAS, legal_entity=True, kpp=KPP),
        ).to_wire()


def test_remote_sale_return_paid_root_item_precedence_and_missing_effective_paid() -> None:
    with pytest.raises(TurnoverManualReview, match="PAID_REQUIRED"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
        ).to_wire()

    root_paid_false = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS),),
        paid=False,
    ).to_wire()
    assert root_paid_false["paid"] is False
    assert "paid" not in root_paid_false["products_list"][0]

    item_override = LpReturnDocument(
        trade_participant_inn=INN,
        paid=False,
        products_list=(
            ReturnProduct(
                CIS,
                paid=True,
                primary_document=PrimaryDocument("RECEIPT", "I-1", TODAY),
            ),
        ),
    ).to_wire()
    assert item_override["paid"] is False
    assert item_override["products_list"][0]["paid"] is True
    assert item_override["products_list"][0]["primary_document_number"] == "I-1"


def test_remote_sale_return_primary_document_exact_paid_semantics_and_item_override() -> None:
    with pytest.raises(TurnoverManualReview, match="PRIMARY_DOCUMENT_REQUIRED"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            paid=True,
        ).to_wire()

    with pytest.raises(TurnoverContractError, match="paid=false"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            paid=False,
            primary_document=PrimaryDocument("RECEIPT", "R-0", TODAY),
        ).to_wire()

    with pytest.raises(TurnoverContractError, match="paid=false"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS, paid=False, primary_document=PrimaryDocument("RECEIPT", "I-0", TODAY)),),
            paid=True,
            primary_document=PrimaryDocument("RECEIPT", "ROOT", TODAY),
        ).to_wire()

    wire = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(
            ReturnProduct(CIS, primary_document=PrimaryDocument("SALES_RECEIPT", "ITEM", TODAY)),
        ),
        paid=True,
        primary_document=PrimaryDocument("RECEIPT", "ROOT", TODAY),
    ).to_wire()
    assert wire["primary_document_number"] == "ROOT"
    assert wire["products_list"][0]["primary_document_number"] == "ITEM"


def test_non_remote_returns_reject_paid_at_root_and_item_levels() -> None:
    for return_type, primary, state_contract_id in (
        ("RETAIL_RETURN", PrimaryDocument("RECEIPT", "R", TODAY), None),
        ("NOT_FOR_SALE_RETURN", PrimaryDocument("OTHER", "N", TODAY, custom_name="Other document"), None),
        ("OWN_USE_RETURN", None, None),
        ("STATE_CONTRACT_RETURN", None, "1234567890121123456789012"),
    ):
        with pytest.raises(TurnoverContractError, match="paid must be absent"):
            LpReturnDocument(
                trade_participant_inn=INN,
                products_list=(ReturnProduct(CIS),),
                paid=False,
                primary_document=primary,
                state_contract_id=state_contract_id,
                return_type=return_type,
            ).to_wire()
        with pytest.raises(TurnoverContractError, match="paid must be absent"):
            LpReturnDocument(
                trade_participant_inn=INN,
                products_list=(ReturnProduct(CIS, paid=False),),
                primary_document=primary,
                state_contract_id=state_contract_id,
                return_type=return_type,
            ).to_wire()


def test_retail_return_requires_primary_and_accepts_only_source_allowed_types() -> None:
    with pytest.raises(TurnoverManualReview, match="PRIMARY_DOCUMENT_REQUIRED"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            return_type="RETAIL_RETURN",
        ).to_wire()

    for primary in (
        PrimaryDocument("RECEIPT", "R-1", TODAY),
        PrimaryDocument("SALES_RECEIPT", "S-1", TODAY),
        PrimaryDocument("OTHER", "O-1", TODAY, custom_name="Other retail document"),
    ):
        wire = LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            primary_document=primary,
            return_type="RETAIL_RETURN",
        ).to_wire()
        assert "paid" not in wire
        assert wire["primary_document_type"] == primary.document_type

    with pytest.raises(TurnoverContractError, match="primary_document_custom_name"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            primary_document=PrimaryDocument("RECEIPT", "R-2", TODAY, custom_name="forbidden"),
            return_type="RETAIL_RETURN",
        ).to_wire()


def test_not_for_sale_return_requires_primary_and_restricts_primary_type() -> None:
    with pytest.raises(TurnoverManualReview, match="PRIMARY_DOCUMENT_REQUIRED"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            return_type="NOT_FOR_SALE_RETURN",
        ).to_wire()

    for forbidden in ("RECEIPT", "SALES_RECEIPT"):
        with pytest.raises(TurnoverContractError, match="unsupported primary_document_type"):
            LpReturnDocument(
                trade_participant_inn=INN,
                products_list=(ReturnProduct(CIS),),
                primary_document=PrimaryDocument(forbidden, "N-1", TODAY),
                return_type="NOT_FOR_SALE_RETURN",
            ).to_wire()

    wire = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS),),
        primary_document=PrimaryDocument("OTHER", "N-2", TODAY, custom_name="Donation act"),
        return_type="NOT_FOR_SALE_RETURN",
    ).to_wire()
    assert wire["primary_document_type"] == "OTHER"
    assert wire["primary_document_custom_name"] == "Donation act"


def test_own_use_return_forbids_primary_and_certificate_data() -> None:
    clean = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS),),
        return_type="OWN_USE_RETURN",
    ).to_wire()
    assert clean["return_type"] == "OWN_USE_RETURN"
    assert "paid" not in clean

    with pytest.raises(TurnoverContractError, match="primary document must be absent"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            primary_document=PrimaryDocument("OTHER", "O", TODAY, custom_name="Other"),
            return_type="OWN_USE_RETURN",
        ).to_wire()
    with pytest.raises(TurnoverContractError, match="certificate data must be absent"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS, permit=PermitDocument("DECLARATION", "C-1", TODAY)),),
            return_type="OWN_USE_RETURN",
        ).to_wire()


def test_state_contract_return_exact_id_and_absence_rules() -> None:
    valid_id = "1234567890121123456789012"
    wire = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS),),
        state_contract_id=valid_id,
        return_type="STATE_CONTRACT_RETURN",
    ).to_wire()
    assert wire["state_contract_id"] == valid_id

    with pytest.raises(TurnoverManualReview, match="STATE_CONTRACT_ID_REQUIRED"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            return_type="STATE_CONTRACT_RETURN",
        ).to_wire()
    with pytest.raises(TurnoverContractError, match="25 digits"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            state_contract_id="123",
            return_type="STATE_CONTRACT_RETURN",
        ).to_wire()
    with pytest.raises(TurnoverContractError, match="13th character"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            state_contract_id="1234567890124123456789012",
            return_type="STATE_CONTRACT_RETURN",
        ).to_wire()
    with pytest.raises(TurnoverContractError, match="state_contract_id must be absent"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            paid=False,
            state_contract_id=valid_id,
            return_type="REMOTE_SALE_RETURN",
        ).to_wire()
    with pytest.raises(TurnoverContractError, match="primary document must be absent"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            state_contract_id=valid_id,
            primary_document=PrimaryDocument("OTHER", "S", TODAY, custom_name="Other"),
            return_type="STATE_CONTRACT_RETURN",
        ).to_wire()
    with pytest.raises(TurnoverContractError, match="certificate data must be absent"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            state_contract_id=valid_id,
            permit=PermitDocument("DECLARATION", "C-1", TODAY),
            return_type="STATE_CONTRACT_RETURN",
        ).to_wire()


def test_return_certificate_root_item_mutual_exclusion_and_tuple_validation() -> None:
    with pytest.raises(TurnoverContractError, match="root-level or item-level"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(
                ReturnProduct(CIS, permit=PermitDocument("DECLARATION", "ITEM-CERT", TODAY)),
            ),
            primary_document=PrimaryDocument("RECEIPT", "R", TODAY),
            permit=PermitDocument("DECLARATION", "ROOT-CERT", TODAY),
            return_type="RETAIL_RETURN",
        ).to_wire()

    with pytest.raises(TurnoverContractError, match="certificate_number"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            primary_document=PrimaryDocument("RECEIPT", "R", TODAY),
            permit=PermitDocument("DECLARATION", "", TODAY),
            return_type="RETAIL_RETURN",
        ).to_wire()

    root_wire = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS),),
        primary_document=PrimaryDocument("RECEIPT", "R", TODAY),
        permit=PermitDocument("DECLARATION", "ROOT-CERT", TODAY),
        return_type="RETAIL_RETURN",
    ).to_wire()
    assert root_wire["certificate_number"] == "ROOT-CERT"

    item_wire = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS, permit=PermitDocument("DECLARATION", "ITEM-CERT", TODAY)),),
        primary_document=PrimaryDocument("RECEIPT", "R", TODAY),
        return_type="RETAIL_RETURN",
    ).to_wire()
    assert item_wire["products_list"][0]["certificate_number"] == "ITEM-CERT"

def test_return_reason_matrix_contains_all_confirmed_lp_cells_and_no_inference() -> None:
    confirmed = {
        ("DISTANCE", "REMOTE_SALE_RETURN"),
        ("BY_SAMPLES", "REMOTE_SALE_RETURN"),
        ("RETAIL", "RETAIL_RETURN"),
        ("BY_SAMPLES", "RETAIL_RETURN"),
        ("DISTANCE", "RETAIL_RETURN"),
        ("OWN_USE", "OWN_USE_RETURN"),
        ("PRODUCTION_USE", "OWN_USE_RETURN"),
        ("MEDICAL_USE", "OWN_USE_RETURN"),
        ("VETERINARY_USE", "OWN_USE_RETURN"),
        ("STATE_SECRET", "STATE_CONTRACT_RETURN"),
        ("DONATION", "NOT_FOR_SALE_RETURN"),
        ("OWN_USE", "NOT_FOR_SALE_RETURN"),
        ("PRODUCTION_USE", "NOT_FOR_SALE_RETURN"),
        ("STATE_CONTRACT", "NOT_FOR_SALE_RETURN"),
    }
    for prior_reason, return_type in confirmed:
        validate_return_reason_matrix(
            pg="lp", current_status="RETIRED", current_withdraw_reason=prior_reason, return_type=return_type
        )

    for prior_reason, return_type in (
        ("STATE_SECRET", "REMOTE_SALE_RETURN"),
        ("RETAIL", "OWN_USE_RETURN"),
        ("DISTANCE", "STATE_CONTRACT_RETURN"),
        (None, "NOT_FOR_SALE_RETURN"),
    ):
        with pytest.raises(TurnoverManualReview):
            validate_return_reason_matrix(
                pg="lp", current_status="RETIRED", current_withdraw_reason=prior_reason, return_type=return_type
            )
    with pytest.raises(TurnoverManualReview):
        validate_return_reason_matrix(
            pg="lp", current_status="RETIRED", current_withdraw_reason="DISTANCE", return_type="VENDING_RETURN"
        )


def test_general_lp_return_uses_exact_matrix_and_remote_alias_stays_exact() -> None:
    service = OperationPreconditionService(participant_inn=INN, now=lambda: NOW)
    evidence = service.validate_return(
        (_snapshot(status="RETIRED", withdraw_reason="OWN_USE"),),
        return_type="OWN_USE_RETURN",
    )
    assert evidence.operation_kind is TurnoverOperationKind.RETURN_TO_CIRCULATION

    prepared = prepare_turnover_document(
        TurnoverOperationKind.RETURN_TO_CIRCULATION,
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            return_type="OWN_USE_RETURN",
        ),
    )
    assert prepared.raw_business_reason == "OWN_USE_RETURN"

    with pytest.raises(TurnoverContractError, match="RETURN_REMOTE_SALE"):
        prepare_turnover_document(
            TurnoverOperationKind.RETURN_REMOTE_SALE,
            LpReturnDocument(
                trade_participant_inn=INN,
                products_list=(ReturnProduct(CIS, paid=False),),
                return_type="RETAIL_RETURN",
            ),
        )

def test_preconditions_require_fresh_owner_plain_state_and_raw_reason() -> None:
    service = OperationPreconditionService(participant_inn=INN, now=lambda: NOW)
    evidence = service.validate_distance((_snapshot(),))
    assert evidence.to_ledger()["verified_fresh"] is True

    service.validate_remote_sale_return((
        _snapshot(status="RETIRED", withdraw_reason="DISTANCE"),
    ))
    with pytest.raises(TurnoverManualReview):
        service.validate_remote_sale_return((_snapshot(status="RETIRED", withdraw_reason="UNKNOWN_RAW"),))
    with pytest.raises(TurnoverManualReview):
        service.validate_distance((_snapshot(owner="9999999999"),))
    with pytest.raises(TurnoverManualReview):
        service.validate_distance((_snapshot(status_ex="SPECIAL"),))
    stale = _snapshot()
    stale = CisSnapshot(
        cis=stale.cis, status=stale.status, status_ex=stale.status_ex,
        owner_inn=stale.owner_inn, withdraw_reason=stale.withdraw_reason,
        emission_type=stale.emission_type, fetched_at=NOW - timedelta(minutes=6),
    )
    with pytest.raises(TurnoverManualReview, match="STALE"):
        service.validate_distance((stale,))


def test_remarking_preconditions_and_readback_ambiguity_are_safe() -> None:
    service = OperationPreconditionService(participant_inn=INN, now=lambda: NOW)
    new = _snapshot(status="APPLIED", emission_type="REMARK", owner=None)
    old = _snapshot(status="INTRODUCED")
    service.validate_remark(new_codes=(new,), old_codes=(old,), cause="DESCRIPTION_ERRORS")
    with pytest.raises(TurnoverManualReview):
        service.validate_remark(new_codes=(new,), old_codes=(), cause="DESCRIPTION_ERRORS")
    with pytest.raises(TurnoverManualReview):
        service.validate_remark(
            new_codes=(_snapshot(status="APPLIED", emission_type="LOCAL", owner=None),),
            cause="KM_SPOILED",
        )
    assert remark_reason_readback_matches("KM_SPOILED", "KM_SPOILED_OR_LOST") is True
    assert remark_reason_readback_matches("KM_SPOILED", "DIFFERENT") is False


def test_remark_wire_description_errors_requires_last_uin() -> None:
    with pytest.raises(TurnoverContractError):
        LkRemarkDocument(
            participant_inn=INN,
            remarking_date=TODAY,
            remarking_cause="DESCRIPTION_ERRORS",
            products=(RemarkProduct(new_uin=CIS, tnved_10="6109100000"),),
        ).to_wire()


def test_write_off_is_separate_typed_document_with_official_names() -> None:
    wire = WriteOffDocument(
        participant_id=INN,
        dropout_reason="DESTRUCTION",
        source_doc_type="DESTRUCTION_ACT",
        source_doc_num="A-1",
        source_doc_date=TODAY,
        sntins=(CIS,),
    ).to_wire()
    assert wire == {
        "participantId": INN,
        "dropoutReason": "DESTRUCTION",
        "sourceDocType": "DESTRUCTION_ACT",
        "sourceDocNum": "A-1",
        "sourceDocDate": TODAY.isoformat(),
        "sntins": [CIS],
    }
    assert "action" not in wire


def test_cancel_is_typed_lk_receipt_cancel_and_generic_inverse_is_not_invented() -> None:
    wire = LkReceiptCancelDocument(INN, "document-123").to_wire()
    assert wire == {"inn": INN, "lk_receipt_id": "document-123"}
    assert "LP_RETURN_CANCEL" not in M5_DOCUMENT_TYPES
    assert "WRITE_OFF_CANCEL" not in M5_DOCUMENT_TYPES


def test_reconciliation_needs_document_and_cis_postcondition() -> None:
    reconcile = OperationReconciliationService()
    result = reconcile.reconcile(
        operation_kind=TurnoverOperationKind.WITHDRAW_DISTANCE,
        document_status_raw="CHECKED_OK",
        snapshots=(_snapshot(status="INTRODUCED"),),
    )
    assert result.state is ReconciliationState.PENDING
    assert result.reason == "POSTCONDITION_MISMATCH"

    ok = reconcile.reconcile(
        operation_kind=TurnoverOperationKind.WITHDRAW_DISTANCE,
        document_status_raw="CHECKED_OK",
        snapshots=(_snapshot(status="RETIRED", withdraw_reason="DISTANCE"),),
    )
    assert ok.state is ReconciliationState.RECONCILED

    unknown = reconcile.reconcile(
        operation_kind=TurnoverOperationKind.WITHDRAW_DISTANCE,
        document_status_raw="NEW_UNKNOWN_STATUS",
        snapshots=(_snapshot(status="RETIRED", withdraw_reason="DISTANCE"),),
    )
    assert unknown.state is ReconciliationState.PENDING
    assert unknown.document_status_raw == "NEW_UNKNOWN_STATUS"

    generic = reconcile.reconcile(
        operation_kind=TurnoverOperationKind.WITHDRAW,
        document_status_raw="CHECKED_OK",
        snapshots=(_snapshot(status="RETIRED", withdraw_reason="DISTANCE"),),
    )
    assert generic.state is ReconciliationState.MANUAL_REVIEW
    assert generic.reason == "OPERATION_NOT_EXECUTABLE"


def test_prepare_freezes_exact_bytes_and_operation_type_is_not_caller_arbitrary() -> None:
    prepared = prepare_turnover_document(TurnoverOperationKind.WITHDRAW_DISTANCE, _distance())
    assert prepared.document_type == "LK_RECEIPT"
    raw = base64.b64decode(prepared.exact_document.product_document_base64, validate=True)
    assert raw == prepared.exact_document.bytes_for_signature
    assert hashlib.sha256(raw).hexdigest() == prepared.exact_document.sha256
    assert json.loads(raw.decode("utf-8"))["action"] == "DISTANCE"
    with pytest.raises(TurnoverContractError):
        prepare_turnover_document(TurnoverOperationKind.WRITE_OFF, _distance())  # type: ignore[arg-type]


def test_windows_agent_accepts_only_typed_m5_write_jobs() -> None:
    prepared = prepare_turnover_document(TurnoverOperationKind.WITHDRAW_DISTANCE, _distance())
    job = AgentJob(
        job_id="job-m5-1",
        job_type=AgentJobType.LK_RECEIPT,
        operation_id="op-m5-1",
        pg="lp",
        expected_inn=INN,
        document_type="LK_RECEIPT",
        document_sha256=prepared.exact_document.sha256,
        product_document_base64=prepared.exact_document.product_document_base64,
    )
    job.validate()
    with pytest.raises(ValueError):
        AgentJobType("GENERIC_TRUE_API_WRITE")

    wrong = AgentJob(
        job_id="job-m5-2",
        job_type=AgentJobType.WRITE_OFF,
        operation_id="op-m5-2",
        pg="lp",
        expected_inn=INN,
        document_type="LK_RECEIPT",
        document_sha256=prepared.exact_document.sha256,
        product_document_base64=prepared.exact_document.product_document_base64,
    )
    with pytest.raises(AgentSecurityError):
        wrong.validate()


def test_transport_rejects_unknown_document_type_before_network() -> None:
    transport = ProductionAgentTrueApiTransport()
    with pytest.raises(AgentSecurityError, match="unsupported document type"):
        transport.create_document(
            document_type="ARBITRARY_DOCUMENT",
            product_document_base64=base64.b64encode(b"{}").decode("ascii"),
            signature_base64=base64.b64encode(b"sig").decode("ascii"),
            bearer_token="runtime-token",
        )
