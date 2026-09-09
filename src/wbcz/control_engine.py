from __future__ import annotations

from .models import Decision, Event, KiState, Operation, Outcome


def validate_owner_inn(value: str) -> None:
    # Format validation only; no claim to implement fiscal INN verification.
    if not value.isascii() or not value.isdigit() or len(value) not in (10, 12):
        raise ValueError("ИНН владельца должен содержать 10 или 12 ASCII-цифр")


def decide(event: Event, state: KiState, own_inn: str) -> Outcome:
    """Pure state decision, not document readiness or historical reconciliation.

    No database history or external I/O is available. Missing WB date/receipt/FN
    does not block a state decision. READY does not authorize document creation.
    """
    validate_owner_inn(own_inn)
    if not state.ownerInn:
        return Outcome(Decision.MANUAL_REVIEW, "OWNER_UNKNOWN")
    if state.ownerInn != own_inn:
        return Outcome(Decision.MANUAL_REVIEW, "OTHER_OWNER")
    if state.status not in {"IN_CIRCULATION", "WITHDRAWN"}:
        return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_STATUS")
    # statusEx is an internal normalized refinement, not a True API raw code.
    if state.statusEx not in (None, "", state.status):
        return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_OR_CONFLICTING_STATUS_EX")
    if state.status == "IN_CIRCULATION":
        if state.withdrawReason not in (None, ""):
            return Outcome(Decision.MANUAL_REVIEW, "INCONSISTENT_WITHDRAW_REASON")
        if event.operation is Operation.RETURN:
            return Outcome(Decision.ALREADY_DONE, "RETURN_ALREADY_IN_CIRCULATION")
        if event.legal_entity_sale is not False:
            return Outcome(Decision.MANUAL_REVIEW, "LEGAL_ENTITY_RULES_UNDEFINED")
        return Outcome(Decision.READY_TO_WITHDRAW, "SALE_IN_CIRCULATION")
    if state.withdrawReason != "DISTANCE":
        return Outcome(Decision.MANUAL_REVIEW, "NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL")
    if event.operation is Operation.SALE:
        return Outcome(Decision.ALREADY_DONE, "SALE_ALREADY_WITHDRAWN_DISTANCE")
    return Outcome(Decision.READY_TO_RETURN, "RETURN_WITHDRAWN_DISTANCE")
