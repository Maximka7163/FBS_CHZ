from __future__ import annotations

from collections import Counter
from dataclasses import asdict

from sqlalchemy.orm import Session

from wbcz.control_engine import decide
from wbcz.models import Decision, Event, Outcome
from wbcz_web.models import CheckRecord, ControlRun
from wbcz_web.repositories import AuditRepository, ImportRepository
from wbcz_web.services.control import OperationMode
from wbcz_web.services.imports import record_to_event
from wbcz_web.services.kiz_transaction_lock import acquire_tenant_kiz_locks
from wbcz_web.services.tenant import active_tenant
from wbcz_web.services.wb_sequence import sequence_outcome_for_event

from .bridge import LocalTrueApiReadBridge


def _select_event_ids(
    imports: ImportRepository,
    import_id: str,
    event_ids: list[str] | None,
) -> list[str]:
    if imports.get(import_id) is None:
        raise KeyError("Импорт не найден")
    allowed = imports.import_event_ids(import_id)
    allowed_set = set(allowed)
    if event_ids is None:
        return list(dict.fromkeys(allowed))
    requested = list(dict.fromkeys(event_ids))
    if not requested:
        raise ValueError("Не выбран ни один КИЗ")
    if any(event_id not in allowed_set for event_id in requested):
        raise ValueError("КИЗ не относится к выбранному импорту")
    wanted = set(requested)
    return list(dict.fromkeys(event_id for event_id in allowed if event_id in wanted))


class LocalTrueApiControlService:
    """Synchronous local FBS control using fresh read-only /cises/info state."""

    def __init__(self, db: Session, bridge: LocalTrueApiReadBridge) -> None:
        self.db = db
        self.bridge = bridge
        self.imports = ImportRepository(db)
        self.audit = AuditRepository(db)
        self.scope = active_tenant(db)

    def run(
        self,
        import_id: str,
        user_id: int,
        mode: OperationMode,
        event_ids: list[str] | None = None,
    ) -> dict:
        selected = _select_event_ids(self.imports, import_id, event_ids)

        immediate: dict[str, Outcome] = {}
        effective: list[tuple[str, Event]] = []
        for event_id in selected:
            row = self.imports.event(event_id)
            if row is None:
                raise KeyError(event_id)
            event = record_to_event(row)
            policy = sequence_outcome_for_event(self.imports, event_id)
            if policy is not None:
                immediate[event_id] = policy
            else:
                effective.append((event_id, event))

        # Authenticate/read before creating a ControlRun. If local CryptoPro,
        # certificate, GOST TLS or True API auth is unavailable, the request
        # fails closed with no fresh decision persisted.
        states = self.bridge.read_states(
            self.scope.participant_inn,
            list(dict.fromkeys(event.kiz for _, event in effective)),
        ) if effective else {}

        # A rolling WB import can commit a later event while /cises/info is in
        # flight. Serialize final history resolution with the same tenant+KIZ
        # transaction locks used by imports, in deterministic KIZ order. Once
        # acquired, re-resolve sequence policy under the lock and keep it until
        # the CheckRecords are persisted/transaction commits.
        selected_kizes: list[str] = []
        for event_id in selected:
            row = self.imports.event(event_id)
            if row is None:
                raise KeyError(event_id)
            selected_kizes.append(record_to_event(row).kiz)
        acquire_tenant_kiz_locks(
            self.db,
            self.scope.organisation_id,
            self.scope.participant_id,
            selected_kizes,
        )

        run = ControlRun(
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            import_id=import_id,
            user_id=user_id,
            mode=mode.value,
            provider="local-cryptopro-true-api",
        )
        self.db.add(run)
        self.db.flush()

        outcomes: list[Outcome] = []
        for event_id in selected:
            row = self.imports.event(event_id)
            if row is None:
                raise KeyError(event_id)
            event = record_to_event(row)
            snapshot = None
            # Never persist a pre-network history decision. Re-evaluate the
            # current tenant WB history while holding its KIZ transaction lock;
            # any newly imported later/ambiguous event wins over fetched CHZ.
            outcome = sequence_outcome_for_event(self.imports, event_id)
            source = "wb-sequence-policy"
            if outcome is None:
                source = "local-cryptopro-true-api"
                value = states.get(event.kiz)
                if isinstance(value, Exception) or value is None:
                    outcome = Outcome(
                        Decision.ERROR,
                        "STATE_LOOKUP_OR_NORMALIZATION_FAILED",
                        type(value).__name__ if isinstance(value, Exception) else "MISSING_CIS_INFO",
                    )
                else:
                    snapshot = value
                    outcome = decide(event, snapshot, self.scope.participant_inn)

            self.db.add(
                CheckRecord(
                    run_id=run.id,
                    event_id=event_id,
                    source=source,
                    snapshot=asdict(snapshot) if snapshot is not None else None,
                    decision=outcome.decision.value,
                    reason=outcome.reason,
                    error=outcome.error,
                )
            )
            outcomes.append(outcome)

        self.db.flush()
        counts = Counter(item.decision.value for item in outcomes)
        reasons = Counter(item.reason for item in outcomes)
        self.audit.append(
            "CONTROL_RUN",
            user_id=user_id,
            entity_type="control_run",
            entity_id=run.id,
            metadata={
                "import_id": import_id,
                "mode": mode.value,
                "checked": len(outcomes),
                "provider": "local-cryptopro-true-api",
                "business_write_enabled": False,
            },
        )
        return {
            "run_id": run.id,
            "provider": "local-cryptopro-true-api",
            "mode": mode.value,
            "checked": len(outcomes),
            "pending": 0,
            "counts": dict(counts),
            "reasons": dict(reasons),
            "production_submission_available": False,
        }
