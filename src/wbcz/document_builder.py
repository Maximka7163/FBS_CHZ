from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import Decision, Event, canonical_json


@dataclass(frozen=True, slots=True)
class BuiltDocument:
    content_type: str
    payload: bytes


class DocumentBuilder(Protocol):
    def build(self, event: Event, decision: Decision) -> BuiltDocument:
        ...


class FakeDocumentBuilder:
    """TEST-ONLY payload. Deliberately not a marking document/API schema.

    Does not implement production document readiness. READY is a state decision.
    """

    def __init__(self) -> None:
        self.calls = 0

    def build(self, event: Event, decision: Decision) -> BuiltDocument:
        self.calls += 1
        if decision not in {Decision.READY_TO_WITHDRAW, Decision.READY_TO_RETURN}:
            raise ValueError("Документ допустим только для READY-решения")
        return BuiltDocument(
            "application/x-wbcz-test-only",
            canonical_json({
                "TEST_ONLY": True,
                "event_id": event.event_id,
                "decision": decision.value,
            }).encode("utf-8"),
        )
