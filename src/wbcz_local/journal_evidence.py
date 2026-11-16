"""Read-only evidence queries backing conservative local FBS decisions.

This module never creates, updates, or deletes any row. It only reads the
tenant's own accepted production write journal so the control engine can prove
that a distance-sale withdrawal was genuinely accepted by ЧЗ before treating a
RETIRED КИ as return-ready. All mutation stays in the gated write pipeline.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from wbcz_web.models import EventRecord, WriteOperationRecord
from wbcz_web.services.tenant import TenantContext


def distance_withdraw_journal_reasons(
    db: Session, scope: TenantContext, kizes: list[str]
) -> dict[str, str]:
    """КИЗ whose distance-sale withdrawal document was accepted by ЧЗ.

    /cises/info does not return a withdrawal reason for the lp group, so a
    RETIRED КИ would otherwise be blocked as NON_DISTANCE_OR_UNKNOWN. The only
    acceptable evidence is this tenant's own journal: a READY_TO_WITHDRAW /
    DISTANCE operation that reached SUCCEEDED with a real document_id (poll
    CHECKED_OK terminal success). Anything else stays fail-closed.
    """
    if not kizes:
        return {}
    rows = db.execute(
        select(EventRecord.kiz, WriteOperationRecord.operation_reason)
        .join(
            WriteOperationRecord,
            WriteOperationRecord.event_id == EventRecord.event_id,
        )
        .where(
            EventRecord.kiz.in_(kizes),
            EventRecord.organisation_id == scope.organisation_id,
            EventRecord.participant_id == scope.participant_id,
            WriteOperationRecord.organisation_id == scope.organisation_id,
            WriteOperationRecord.participant_id == scope.participant_id,
            WriteOperationRecord.decision == "READY_TO_WITHDRAW",
            WriteOperationRecord.operation_reason == "DISTANCE",
            WriteOperationRecord.state == "SUCCEEDED",
            WriteOperationRecord.document_id.is_not(None),
        )
    ).all()
    return {kiz: reason for kiz, reason in rows if isinstance(kiz, str)}
