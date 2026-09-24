from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from wbcz.control_engine import decide
from wbcz.models import Decision, Event, KiState, Operation


OWN_INN = "1234567890"


def _event(
    operation: Operation,
    *,
    receipt_number: str | None = "receipt-1",
    occurred_at: datetime | None = datetime(2026, 9, 14, 12, 54, tzinfo=timezone.utc),
) -> Event:
    return Event(
        kiz="010290089707781021POLICY",
        task_number="task-policy",
        sticker="sticker-policy",
        operation=operation,
        occurred_at=occurred_at,
        receipt_number=receipt_number,
        fiscal_drive_number=None,
        amount=Decimal("100.00"),
        currency="RUB",
        legal_entity_sale=False,
    )


def test_return_withdrawn_distance_needs_no_return_row_receipt_or_date() -> None:
    outcome = decide(
        _event(Operation.RETURN, receipt_number=None, occurred_at=None),
        KiState(
            "WITHDRAWN",
            withdrawReason="DISTANCE",
            ownerInn=OWN_INN,
            productGroup="lp",
        ),
        OWN_INN,
    )

    assert outcome.decision is Decision.READY_TO_RETURN
    assert outcome.reason == "RETURN_WITHDRAWN_DISTANCE"


def test_sale_in_circulation_still_requires_sale_receipt_and_date() -> None:
    outcome = decide(
        _event(Operation.SALE, receipt_number=None, occurred_at=None),
        KiState("IN_CIRCULATION", ownerInn=OWN_INN, productGroup="lp"),
        OWN_INN,
    )

    assert outcome.decision is Decision.MANUAL_REVIEW
    assert outcome.reason == "SALE_RECEIPT_MISSING"


def test_return_already_in_circulation_is_already_done() -> None:
    outcome = decide(
        _event(Operation.RETURN, receipt_number=None, occurred_at=None),
        KiState("IN_CIRCULATION", ownerInn=OWN_INN, productGroup="lp"),
        OWN_INN,
    )

    assert outcome.decision is Decision.ALREADY_DONE
    assert outcome.reason == "RETURN_ALREADY_IN_CIRCULATION"


def test_return_non_distance_withdrawal_is_manual_review() -> None:
    outcome = decide(
        _event(Operation.RETURN, receipt_number=None, occurred_at=None),
        KiState(
            "WITHDRAWN",
            withdrawReason="OTHER",
            ownerInn=OWN_INN,
            productGroup="lp",
        ),
        OWN_INN,
    )

    assert outcome.decision is Decision.MANUAL_REVIEW
    assert outcome.reason == "NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL"


def test_owner_mismatch_is_manual_review_before_operation() -> None:
    outcome = decide(
        _event(Operation.RETURN, receipt_number=None, occurred_at=None),
        KiState(
            "WITHDRAWN",
            withdrawReason="DISTANCE",
            ownerInn="0987654321",
            productGroup="lp",
        ),
        OWN_INN,
    )

    assert outcome.decision is Decision.MANUAL_REVIEW
    assert outcome.reason == "OWNER_MISMATCH"
