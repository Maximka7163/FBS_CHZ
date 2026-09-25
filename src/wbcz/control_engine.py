from __future__ import annotations

from .models import Decision, Event, KiState, Operation, Outcome


def validate_owner_inn(value: str) -> None:
    # Format validation only; no claim to implement fiscal INN verification.
    if not value.isascii() or not value.isdigit() or len(value) not in (10, 12):
        raise ValueError("ИНН владельца должен содержать 10 или 12 ASCII-цифр")


def _has_sale_receipt_evidence(event: Event) -> bool:
    """Sale evidence required before a new distance-sale withdrawal."""
    return bool(event.receipt_number) and event.occurred_at is not None


def decide(event: Event, state: KiState, own_inn: str) -> Outcome:
    """Pure conservative WB FBS state/evidence decision.

    v0.4 production/live adapters always provide an explicit productGroup. The
    legacy API-independent test/mock boundary may still omit it; that path keeps
    v0.2 state-only semantics for backwards compatibility and is never used by
    the live True API client. An explicit non-lp or UNKNOWN group is blocked.
    """
    validate_owner_inn(own_inn)

    verified_lp = state.productGroup is not None
    if verified_lp and state.productGroup.casefold() != "lp":
        return Outcome(Decision.MANUAL_REVIEW, "WRONG_PRODUCT_GROUP")

    if not state.ownerInn:
        return Outcome(Decision.MANUAL_REVIEW, "OWNER_UNKNOWN")
    if state.ownerInn != own_inn:
        return Outcome(Decision.MANUAL_REVIEW, "OWNER_MISMATCH")

    if state.status not in {"IN_CIRCULATION", "WITHDRAWN"}:
        return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_CHZ_STATUS")
    if state.statusEx not in (None, "", state.status):
        return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_CHZ_STATUS")

    if state.status == "IN_CIRCULATION":
        if state.withdrawReason not in (None, ""):
            return Outcome(Decision.MANUAL_REVIEW, "UNKNOWN_CHZ_STATUS")
        if event.operation is Operation.RETURN:
            return Outcome(Decision.ALREADY_DONE, "RETURN_ALREADY_IN_CIRCULATION")
        if event.legal_entity_sale is not False:
            return Outcome(Decision.MANUAL_REVIEW, "LEGAL_ENTITY_RULES_UNDEFINED")
        if verified_lp and not _has_sale_receipt_evidence(event):
            return Outcome(Decision.MANUAL_REVIEW, "SALE_RECEIPT_MISSING")
        return Outcome(Decision.READY_TO_WITHDRAW, "SALE_IN_CIRCULATION")

    if state.withdrawReason != "DISTANCE":
        return Outcome(Decision.MANUAL_REVIEW, "NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL")
    if event.operation is Operation.SALE:
        return Outcome(Decision.ALREADY_DONE, "SALE_ALREADY_WITHDRAWN_DISTANCE")
    # A WB return row does not need a new sale receipt/date. Fresh CHZ state is
    # authoritative: a KI withdrawn specifically for distance sale needs return.
    return Outcome(Decision.READY_TO_RETURN, "RETURN_WITHDRAWN_DISTANCE")
