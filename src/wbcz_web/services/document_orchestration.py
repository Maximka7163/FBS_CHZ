from __future__ import annotations

from dataclasses import asdict

from wbcz.control_engine import decide
from wbcz.document_assembler import OfficialP0DocumentAssembler, PrimaryDocumentProvider, P0OrganisationConfig
from wbcz.models import Decision, KiState, Outcome
from wbcz_web.config import WebConfig
from wbcz_web.models import BootstrapRecord, CheckRecord
from wbcz_web.services.agent_orchestration import (
    AgentOrchestrationBroker as _BaseAgentOrchestrationBroker,
    ExactDocumentAssembler,
    _tenant_or_legacy_inn,
)
from wbcz_web.services.imports import record_to_event
from wbcz_web.services.wb_sequence import sequence_outcome_for_event
from wbcz_web.services.tenant import optional_tenant


class AgentOrchestrationBroker(_BaseAgentOrchestrationBroker):
    """P0 broker with exact VPS-side assembly and fail-closed operator approval gate."""

    def __init__(
        self,
        db,
        config: WebConfig,
        *,
        document_assembler: ExactDocumentAssembler | None = None,
        primary_document_provider: PrimaryDocumentProvider | None = None,
    ) -> None:
        organisation_config = config.organisation_document_config()
        if organisation_config is not None:
            scope = optional_tenant(db)
            if scope is None and db.get(BootstrapRecord, 1) is not None:
                raise PermissionError("active tenant scope required")
            organisation_config = P0OrganisationConfig(
                participant_inn=scope.participant_inn if scope else config.own_inn,
                organisation_type=organisation_config.organisation_type,
                fias_id=organisation_config.fias_id,
                kpp=organisation_config.kpp,
                remote_sale_return_paid=organisation_config.remote_sale_return_paid,
            )
        assembler = document_assembler or OfficialP0DocumentAssembler(
            organisation_config,
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
        outcome = sequence_outcome_for_event(self.imports, event_id)
        if outcome is None:
            try:
                snapshot = self._single_state(event, result)
                outcome = decide(event, snapshot, _tenant_or_legacy_inn(self.db, self.config))
            except Exception as exc:
                outcome = Outcome(Decision.ERROR, "STATE_LOOKUP_OR_NORMALIZATION_FAILED", type(exc).__name__)

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

        # Control is intentionally decision-only. Exact document assembly and
        # WRITE job creation require the separate authenticated bulk endpoint,
        # which re-reads the latest backend decisions after operator confirmation.
        return
