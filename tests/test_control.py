from dataclasses import replace

import pytest

from wbcz.control_engine import decide
from wbcz.models import Decision, Event, KiState, Operation


OWN = "1234567890"


@pytest.mark.parametrize(
    ("operation", "status", "reason", "expected"),
    [
        pytest.param(
            Operation.SALE, "IN_CIRCULATION", None,
            Decision.READY_TO_WITHDRAW, id="T01",
        ),
        pytest.param(
            Operation.SALE, "WITHDRAWN", "DISTANCE",
            Decision.ALREADY_DONE, id="T02",
        ),
        pytest.param(
            Operation.RETURN, "WITHDRAWN", "DISTANCE",
            Decision.READY_TO_RETURN, id="T03",
        ),
        pytest.param(
            Operation.RETURN, "IN_CIRCULATION", None,
            Decision.ALREADY_DONE, id="T04",
        ),
        pytest.param(
            Operation.RETURN, "WITHDRAWN", "OTHER",
            Decision.MANUAL_REVIEW, id="T05",
        ),
    ],
)
def test_base_machine(event, operation, status, reason, expected):
    result = decide(
        replace(event, operation=operation),
        KiState(status=status, withdrawReason=reason, ownerInn=OWN),
        OWN,
    )
    assert result.decision is expected


def test_T06_other_owner(event: Event):
    result = decide(
        event, KiState("IN_CIRCULATION", ownerInn="9876543210"), OWN,
    )
    assert result.decision is Decision.MANUAL_REVIEW
    assert result.reason == "OTHER_OWNER"


@pytest.mark.parametrize(
    "state",
    [
        KiState("UNKNOWN", ownerInn=OWN),
        KiState("IN_CIRCULATION", ownerInn=None),
        KiState("WITHDRAWN", withdrawReason=None, ownerInn=OWN),
        KiState("IN_CIRCULATION", statusEx="UNKNOWN", ownerInn=OWN),
        KiState("IN_CIRCULATION", statusEx="WITHDRAWN", ownerInn=OWN),
        KiState("IN_CIRCULATION", withdrawReason="DISTANCE", ownerInn=OWN),
    ],
)
def test_uncertainty_is_manual(event, state):
    assert decide(event, state, OWN).decision is Decision.MANUAL_REVIEW


@pytest.mark.parametrize("legal", [True, None])
def test_undefined_legal_entity_rules(event, legal):
    result = decide(
        replace(event, legal_entity_sale=legal),
        KiState("IN_CIRCULATION", ownerInn=OWN),
        OWN,
    )
    assert result.decision is Decision.MANUAL_REVIEW


def test_already_done_is_not_blocked_by_legal_flag(event):
    result = decide(
        replace(event, legal_entity_sale=None),
        KiState("WITHDRAWN", withdrawReason="DISTANCE", ownerInn=OWN),
        OWN,
    )
    assert result.decision is Decision.ALREADY_DONE


def test_normalized_status_ex(event):
    state = KiState(
        "IN_CIRCULATION", statusEx="IN_CIRCULATION", ownerInn=OWN,
    )
    assert decide(event, state, OWN).decision is Decision.READY_TO_WITHDRAW
