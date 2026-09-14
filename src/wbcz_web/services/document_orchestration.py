from __future__ import annotations

from dataclasses import asdict

from wbcz.control_engine import decide
from wbcz.document_assembler import (
    DocumentAssemblyManualReview,
    OfficialP0DocumentAssembler,
    PrimaryDocumentProvider,
)
from wbcz.models import Decision, KiState, Outcome
from wbcz_web.config import WebConfig
from wbcz_web.models import CheckRecord
from wbcz_web.services.agent_orchestration import (
    AgentOrchestrationBroker as _BaseAgentOrchestrationBroker,
    ExactDocumentAssembler,
)
from wbcz_web.services.imports import record_to_event


class AgentOrchestrationBroker(_BaseAgentOrchestrationBroker):
    """P0 broker with exact VPS-side assembly and fail-closed manual review."""

    def __init__(
        self,
        db,
        config: WebConfig,
        *,
        document_assembler: ExactDocumentAssembler | None = None,
        primary_document_provider: PrimaryDocumentProvider | None = None,
    ) -> None:
        assembler = document_assembler or OfficialP0DocumentAssembler(
            config.organisation_document_config(),
            primary_document_provider=primary_document_provider,
        )
        super().__init__(db, config, document_assembler=assembler)

    def _apply_control_cis(self, event_id, run_id, result) -> None:
        if not event_id or not run_id:
            from wbcz.windows_agent import AgentReplayConflict
            raise AgentReplayConflict("control CIS job misses orchestration metadata")
        row = self.imports.event(event_id)
        if row is None:
            raise KeyError(event_id)
        event = record_to_event(row)
        snapshot: KiState | None = None
        try:
            snapshot = self._single_state(event, result)
            outcome = decide(event, snapshot, self.config.own_inn)
        except Exception as exc:
            outcome = Outcome(Decision.ERROR, "STATE_LOOKUP_OR_NORMALIZATION_FAILED", type(exc).__name__)
        if self.imports.history_order_ambiguous(event.kiz):
            snapshot = None
            outcome = Outcome(Decision.MANUAL_REVIEW, "HISTORY_ORDER_AMBIGUOUS")

        check = CheckRecord(
            run_id=run_id,
            event_id=event_id,
            source="windows-agent-true-api",
            snapshot=asdict(snapshot) if snapshot else None,
            decision=outcome.decision.value,
            reason=outcome.reason,
            error=outcome.error,
        )
        self.db.add(check)
        self.db.flush()

        if outcome.decision not in {Decision.READY_TO_WITHDRAW, Decision.READY_TO_RETURN}:
            return
        try:
            document = self.document_assembler.build_exact(event, outcome.decision)
        except DocumentAssemblyManualReview as exc:
            check.decision = Decision.MANUAL_REVIEW.value
            check.reason = exc.reason
            check.error = "DOCUMENT_ASSEMBLY_BLOCKED"
            self.db.flush()
            return
        self.prepare_approved_write(event_id, document, decision=outcome.decision)
