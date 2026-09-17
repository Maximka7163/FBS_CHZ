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
    with pytest.raises(TurnoverContractError):
        document_type_for_operation("ARBITRARY")


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


def test_remote_return_paid_is_never_guessed_or_defaulted() -> None:
    with pytest.raises(TurnoverManualReview, match="PAID_REQUIRED"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            paid=None,
        ).to_wire()

    with pytest.raises(TurnoverManualReview, match="PRIMARY_DOCUMENT_REQUIRED"):
        LpReturnDocument(
            trade_participant_inn=INN,
            products_list=(ReturnProduct(CIS),),
            paid=True,
        ).to_wire()

    wire = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS),),
        paid=False,
    ).to_wire()
    assert wire == {
        "trade_participant_inn": INN,
        "return_type": "REMOTE_SALE_RETURN",
        "paid": False,
        "products_list": [{"ki": CIS}],
    }
    assert {"kpp", "fias_id", "product_cost", "state_contract_id"}.isdisjoint(wire)


def test_remote_return_paid_true_accepts_explicit_primary_document() -> None:
    wire = LpReturnDocument(
        trade_participant_inn=INN,
        products_list=(ReturnProduct(CIS),),
        paid=True,
        primary_document=PrimaryDocument("RECEIPT", "R-1", TODAY),
    ).to_wire()
    assert wire["paid"] is True
    assert wire["primary_document_type"] == "RECEIPT"
    assert wire["primary_document_number"] == "R-1"


def test_return_reason_matrix_only_confirms_researched_remote_sale_cells() -> None:
    validate_return_reason_matrix(
        pg="lp", current_status="RETIRED", current_withdraw_reason="DISTANCE", return_type="REMOTE_SALE_RETURN"
    )
    validate_return_reason_matrix(
        pg="lp", current_status="RETIRED", current_withdraw_reason="BY_SAMPLES", return_type="REMOTE_SALE_RETURN"
    )
    for reason in ("OWN_USE", "STATE_CONTRACT", None):
        with pytest.raises(TurnoverManualReview):
            validate_return_reason_matrix(
                pg="lp", current_status="RETIRED", current_withdraw_reason=reason, return_type="REMOTE_SALE_RETURN"
            )
    with pytest.raises(TurnoverManualReview):
        validate_return_reason_matrix(
            pg="lp", current_status="RETIRED", current_withdraw_reason="DISTANCE", return_type="VENDING_RETURN"
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
