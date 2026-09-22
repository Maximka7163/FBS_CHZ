from __future__ import annotations

from dataclasses import dataclass

from wbcz.models import Decision, Outcome
from wbcz_web.repositories import ImportRepository


SUPERSEDED_REASON_CODE = "SUPERSEDED_BY_LATER_WB_EVENT"
AMBIGUOUS_REASON_CODE = "HISTORY_ORDER_AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class WbSequenceResolution:
    state: str
    effective_event_id: str | None


def resolve_wb_sequence(imports: ImportRepository, kiz: str) -> WbSequenceResolution:
    rows = imports.history_for_kiz(kiz)
    if not rows:
        return WbSequenceResolution("ABSENT", None)
    if len(rows) == 1:
        return WbSequenceResolution("EFFECTIVE", rows[0].event_id)

    timestamps = [row.occurred_at for row in rows]
    if any(value is None for value in timestamps):
        return WbSequenceResolution("AMBIGUOUS", None)
    if len(set(timestamps)) != len(timestamps):
        return WbSequenceResolution("AMBIGUOUS", None)

    latest = max(rows, key=lambda row: row.occurred_at)
    return WbSequenceResolution("EFFECTIVE", latest.event_id)


def sequence_outcome_for_event(
    imports: ImportRepository,
    event_id: str,
) -> Outcome | None:
    row = imports.event(event_id)
    if row is None:
        raise KeyError(event_id)
    resolution = resolve_wb_sequence(imports, row.kiz)
    if resolution.state == "AMBIGUOUS":
        return Outcome(Decision.MANUAL_REVIEW, AMBIGUOUS_REASON_CODE)
    if resolution.effective_event_id is not None and resolution.effective_event_id != event_id:
        return Outcome(Decision.NO_ACTION, SUPERSEDED_REASON_CODE)
    return None
