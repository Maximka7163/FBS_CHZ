from __future__ import annotations

from .models import Decision, Event, KiState, Operation, Outcome


def validate_owner_inn(value: str) -> None:
    # Format validation only; no claim to implement fiscal INN verification.
    if not value.isascii() or not value.isdigit() or len(value) not in (10, 12):
        raise ValueError("ИНН владельца должен содержать 10 или 12 ASCII-цифр")


def _has_receipt_evidence(event: Event) -> bool:
    """Evidence required by the standard WB FBS archive flow.

    MarkZnak-style archive control requires receipt data. For this core the
    stable evidence boundary is a receipt number plus the WB event/check date.
    Fiscal-drive number may be absent and is not used as an eligibility signal.
    """
    return bool(event.receipt_number) and event.occurred_at is not None


def decide(event: Event, state: KiState, own_inn: str) -> Outcome:
    """Pure conservative WB FBS state/evidence decision.

    READY means only that the current KI state and WB archive evidence are
    sufficient for a future operation. It never authorizes document creation,
    signing or submission. ALREADY_DONE is determined from current KI state
    before receipt evidence because no new document is required in that case.
    """
    validate_owner_inn(own_inn)

    if state.productGroup is not None and state.productGroup.casefold() != "lp":
        return Outcome(Decision.MANUAL_REVIEW, "WRONG_PRODUCT_GROUP")

    if not state.ownerInn:
        return Outcome(Decision.MANUAL_REVIEW, "OWNER_UNKNOWN")
    if state.ownerInn != own_inn:
        return Outcome(Decision.MANUAL_REVIEW, "OWNER_MISMATCH")

    if state.status not in {"IN_CIRCULATION", "WITHDRAWN"}:
        return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_CHZ_STATUS")

    # Production adapters normalize known empty special statuses to None.
    # Any non-empty unexpected refinement remains a conservative stop.
    if state.statusEx not in (None, "", state.status):
        return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_CHZ_STATUS")

    if state.status == "IN_CIRCULATION":
        if state.withdrawReason not in (None, ""):
            return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_CHZ_STATUS")

        # A returned item which is already in circulation needs no new return.
        if event.operation is Operation.RETURN:
            return Outcome(Decision.ALREADY_DONE, "RETURN_ALREADY_IN_CIRCULATION")

        if event.legal_entity_sale is not False:
            return Outcome(Decision.MANUAL_REVIEW, "LEGAL_ENTITY_RULES_UNDEFINED")
        if not _has_receipt_evidence(event):
            return Outcome(Decision.MANUAL_REVIEW, "SALE_RECEIPT_MISSING")
        return Outcome(Decision.READY_TO_WITHDRAW, "SALE_IN_CIRCULATION")

    # WITHDRAWN
    if state.withdrawReason != "DISTANCE":
        return Outcome(Decision.MANUAL_REVIEW, "NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL")

    # A sale already withdrawn specifically for distance sale needs no new doc,
    # even if the archived receipt fields are absent.
    if event.operation is Operation.SALE:
        return Outcome(Decision.ALREADY_DONE, "SALE_ALREADY_WITHDRAWN_DISTANCE")

    if not _has_receipt_evidence(event):
        return Outcome(Decision.MANUAL_REVIEW, "RETURN_RECEIPT_MISSING")
    return Outcome(Decision.READY_TO_RETURN, "RETURN_WITHDRAWN_DISTANCE")
