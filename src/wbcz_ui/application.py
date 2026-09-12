from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from pathlib import Path
import sqlite3
import tempfile
from enum import StrEnum
from typing import Any, Iterable

from wbcz.event_store import EventStore
from wbcz.models import Decision, Event, KiState, Operation, Outcome
from wbcz.service import DryRunService, ImportService
from wbcz.true_api import FakeTrueApiClient, TrueApiError

OWN_INN = "1234567890"


class OperationMode(StrEnum):
    AUTO = "AUTO"
    CONTROL = "CONTROL"
    WITHDRAW_ONLY = "WITHDRAW_ONLY"
    RETURN_ONLY = "RETURN_ONLY"


_PREVIEW_REASON_TEXT = {
    "NOT_CHECKED": "Событие ещё не проверено",
    "OTHER_OWNER": "Другой владелец КИЗ",
    "OWNER_UNKNOWN": "Владелец КИЗ не определён",
    "NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL": "Причина выбытия требует ручной проверки",
    "UNKNOWN_STATUS": "Неизвестное состояние КИЗ",
    "UNKNOWN_OR_CONFLICTING_STATUS_EX": "Состояние КИЗ требует ручной проверки",
    "INCONSISTENT_WITHDRAW_REASON": "Противоречивое состояние выбытия",
    "LEGAL_ENTITY_RULES_UNDEFINED": "Требуется ручная проверка правила продажи",
    "STATE_LOOKUP_OR_NORMALIZATION_FAILED": "Не удалось получить состояние КИЗ",
    "SALE_ALREADY_WITHDRAWN_DISTANCE": "Операция уже не требуется",
    "RETURN_ALREADY_IN_CIRCULATION": "Операция уже не требуется",
    "HISTORY_ORDER_AMBIGUOUS": "История событий КИЗ неоднозначна",
    "MODE_REQUIRES_RETURN": "По текущему состоянию требуется возврат в оборот",
    "MODE_REQUIRES_WITHDRAW": "По текущему состоянию требуется вывод из оборота",
}


def _event_dict(event: Event) -> dict[str, Any]:
    payload = event.to_dict()
    return {"event_id": event.event_id, **payload}


class UiApplication:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def import_bytes(self, filename: str, data: bytes) -> dict[str, Any]:
        safe_name = Path(filename).name or "upload.xlsx"
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory) / safe_name
            temp.write_bytes(data)
            with EventStore(self.db_path) as store:
                report = ImportService(store).import_file(temp)
                summary = self._import_summary(store, report.fingerprint)
                summary.update(asdict(report))
                return summary

    def list_imports(self, limit: int = 10) -> list[dict[str, Any]]:
        if not self.db_path.exists():
            return []
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                """
                SELECT a.created_at, a.action, a.entity_id AS fingerprint,
                       i.filename, i.imported_at, i.state, i.new_events,
                       i.duplicate_events, i.rejected_rows,
                       COUNT(ir.row_number) AS row_count,
                       COUNT(DISTINCT e.kiz) AS unique_kiz
                FROM audit_log a
                JOIN imports i ON i.fingerprint = a.entity_id
                LEFT JOIN import_rows ir ON ir.fingerprint = i.fingerprint
                LEFT JOIN events e ON e.event_id = ir.event_id
                WHERE a.action IN ('IMPORT_COMPLETED', 'IMPORT_REPEATED')
                GROUP BY a.id
                ORDER BY a.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                repeated = row["action"] == "IMPORT_REPEATED"
                result.append({
                    "fingerprint": row["fingerprint"],
                    "filename": row["filename"],
                    "uploaded_at": row["created_at"],
                    "status": "error" if row["rejected_rows"] else "processed",
                    "repeated": repeated,
                    "new_events": 0 if repeated else row["new_events"],
                    "duplicate_events": (row["new_events"] + row["duplicate_events"]) if repeated else row["duplicate_events"],
                    "rejected_rows": row["rejected_rows"],
                    "row_count": row["row_count"],
                    "unique_kiz": row["unique_kiz"],
                })
            return result
        finally:
            connection.close()

    def get_import(self, fingerprint: str) -> dict[str, Any]:
        with EventStore(self.db_path) as store:
            return self._import_summary(store, fingerprint)

    def _import_summary(self, store: EventStore, fingerprint: str) -> dict[str, Any]:
        connection = store._connection  # read-model only; core remains unchanged
        row = connection.execute("SELECT * FROM imports WHERE fingerprint = ?", (fingerprint,)).fetchone()
        if row is None:
            raise KeyError(f"Import not found: {fingerprint}")
        stats = connection.execute(
            """
            SELECT COUNT(ir.row_number) AS row_count,
                   COUNT(ir.event_id) AS event_count,
                   COUNT(DISTINCT e.kiz) AS unique_kiz,
                   SUM(CASE WHEN e.operation='Продажа' THEN 1 ELSE 0 END) AS sales,
                   SUM(CASE WHEN e.operation='Возврат' THEN 1 ELSE 0 END) AS returns,
                   SUM(CASE WHEN e.occurred_at IS NOT NULL THEN 1 ELSE 0 END) AS dated,
                   SUM(CASE WHEN e.occurred_at IS NULL AND ir.event_id IS NOT NULL THEN 1 ELSE 0 END) AS undated
            FROM import_rows ir LEFT JOIN events e ON e.event_id=ir.event_id
            WHERE ir.fingerprint=?
            """,
            (fingerprint,),
        ).fetchone()
        return {
            "fingerprint": fingerprint,
            "filename": row["filename"],
            "uploaded_at": row["imported_at"],
            "status": "error" if row["rejected_rows"] else "processed",
            "new_events": row["new_events"],
            "duplicate_events": row["duplicate_events"],
            "rejected_rows": row["rejected_rows"],
            "row_count": stats["row_count"],
            "event_count": stats["event_count"],
            "unique_kiz": stats["unique_kiz"],
            "sales": stats["sales"] or 0,
            "returns": stats["returns"] or 0,
            "dated": stats["dated"] or 0,
            "undated": stats["undated"] or 0,
        }

    def events_for_import(self, fingerprint: str) -> list[dict[str, Any]]:
        with EventStore(self.db_path) as store:
            rows = store._connection.execute(
                """
                SELECT e.payload_json, MIN(ir.row_number) AS first_row FROM import_rows ir
                JOIN events e ON e.event_id = ir.event_id
                WHERE ir.fingerprint = ?
                GROUP BY e.event_id
                ORDER BY first_row
                """,
                (fingerprint,),
            ).fetchall()
            import json
            events = [Event.from_dict(json.loads(row["payload_json"])) for row in rows]
            previews = {row["event_id"]: row for row in store.previews()}
            return [self._event_view(store, event, previews.get(event.event_id)) for event in events]

    def event_detail(self, event_id: str) -> dict[str, Any]:
        with EventStore(self.db_path) as store:
            event = store.get_event(event_id)
            checks = store.checks(event_id)
            latest = checks[-1] if checks else None
            data = self._event_view(store, event, latest)
            data["history"] = [_event_dict(item) for item in store.events(event.kiz)]
            data["history_order_ambiguous"] = store.history_order_ambiguous(event.kiz)
            return data

    def _event_view(self, store: EventStore, event: Event, check: dict[str, Any] | None) -> dict[str, Any]:
        result = _event_dict(event)
        result["decision"] = check["decision"] if check else None
        result["reason"] = check["reason"] if check else None
        result["error"] = check["error"] if check else None
        result["checked_at"] = check["checked_at"] if check else None
        return result

    def _offline_responses(self, events: Iterable[Event]) -> dict[str, KiState | Exception]:
        counters = Counter()
        responses: dict[str, KiState | Exception] = {}
        for event in events:
            counters[event.operation] += 1
            n = counters[event.operation]
            if event.operation is Operation.SALE:
                if n <= 64:
                    response: KiState | Exception = KiState("IN_CIRCULATION", ownerInn=OWN_INN)
                elif n <= 72:
                    response = KiState("WITHDRAWN", withdrawReason="DISTANCE", ownerInn=OWN_INN)
                elif n <= 75:
                    response = KiState("IN_CIRCULATION", ownerInn="9876543210")
                else:
                    response = TrueApiError("OFFLINE_TEST_STATE_UNAVAILABLE")
            else:
                if n <= 140:
                    response = KiState("WITHDRAWN", withdrawReason="DISTANCE", ownerInn=OWN_INN)
                elif n <= 152:
                    response = KiState("IN_CIRCULATION", ownerInn=OWN_INN)
                elif n <= 158:
                    response = KiState("WITHDRAWN", withdrawReason="OTHER", ownerInn=OWN_INN)
                else:
                    response = TrueApiError("OFFLINE_TEST_STATE_UNAVAILABLE")
            responses[event.kiz] = response
        return responses

    def check_import(self, fingerprint: str) -> dict[str, Any]:
        with EventStore(self.db_path) as store:
            event_ids = [row["event_id"] for row in store._connection.execute(
                "SELECT event_id FROM import_rows WHERE fingerprint=? AND event_id IS NOT NULL ORDER BY row_number",
                (fingerprint,),
            ).fetchall()]
            events = [store.get_event(event_id) for event_id in event_ids]
            client = FakeTrueApiClient(self._offline_responses(events))
            runner = DryRunService(store, client, OWN_INN, source="offline-ui")
            results = []
            for event in events:
                result = runner.check_event(event.event_id)
                # The core decision remains authoritative. The application layer only
                # adds a conservative safety guard when EventStore explicitly says
                # that multiple WB events for one KIZ cannot be ordered reliably.
                if store.history_order_ambiguous(event.kiz):
                    outcome = Outcome(Decision.MANUAL_REVIEW, "HISTORY_ORDER_AMBIGUOUS")
                    result = store.save_check(
                        event.event_id, None, outcome, source="offline-ui-history-guard"
                    )
                results.append(result)
            counts = Counter(result.outcome.decision.value for result in results)
            return {"checked": len(results), "counts": dict(counts)}

    def operation_preview(
        self,
        event_ids: list[str],
        mode: OperationMode | str = OperationMode.AUTO,
        import_id: str | None = None,
    ) -> dict[str, Any]:
        mode = OperationMode(mode)
        if mode is OperationMode.CONTROL:
            raise ValueError("CONTROL is read-only and has no operation preview")

        with EventStore(self.db_path) as store:
            if import_id is not None:
                allowed = {
                    row["event_id"]
                    for row in store._connection.execute(
                        "SELECT event_id FROM import_rows WHERE fingerprint=? AND event_id IS NOT NULL",
                        (import_id,),
                    ).fetchall()
                }
                missing = [event_id for event_id in event_ids if event_id not in allowed]
                if missing:
                    raise ValueError("Selected event does not belong to the requested import")

            previews = {row["event_id"]: row for row in store.previews()}
            included: list[dict[str, Any]] = []
            excluded: list[dict[str, Any]] = []
            for event_id in event_ids:
                event = store.get_event(event_id)
                preview = previews.get(event_id)
                decision = preview["decision"] if preview else None
                item = {
                    "event_id": event_id,
                    "kiz": event.kiz,
                    "operation": event.operation.value,
                    "decision": decision,
                }

                eligible = False
                exclusion_reason: str | None = None
                if mode is OperationMode.AUTO:
                    eligible = decision in {
                        Decision.READY_TO_WITHDRAW.value,
                        Decision.READY_TO_RETURN.value,
                    }
                elif mode is OperationMode.WITHDRAW_ONLY:
                    eligible = decision == Decision.READY_TO_WITHDRAW.value
                    if decision == Decision.READY_TO_RETURN.value:
                        exclusion_reason = "MODE_REQUIRES_RETURN"
                elif mode is OperationMode.RETURN_ONLY:
                    eligible = decision == Decision.READY_TO_RETURN.value
                    if decision == Decision.READY_TO_WITHDRAW.value:
                        exclusion_reason = "MODE_REQUIRES_WITHDRAW"

                if eligible:
                    included.append(item)
                    continue

                if exclusion_reason is None:
                    exclusion_reason = preview["reason"] if preview else "NOT_CHECKED"
                item["reason"] = exclusion_reason
                item["reason_text"] = _PREVIEW_REASON_TEXT.get(exclusion_reason, exclusion_reason)
                excluded.append(item)

            withdraw_count = sum(
                x["decision"] == Decision.READY_TO_WITHDRAW.value for x in included
            )
            return_count = sum(
                x["decision"] == Decision.READY_TO_RETURN.value for x in included
            )
            response = {
                "mode": mode.value,
                "selected_count": len(event_ids),
                "eligible_count": len(included),
                "withdraw_count": withdraw_count,
                "return_count": return_count,
                "excluded_count": len(excluded),
                "included": included,
                "excluded": excluded,
                "production_submission_available": False,
            }
            # Backward-compatible aliases keep the existing 88-test contract intact.
            response.update({
                "selected": response["selected_count"],
                "withdraw": response["withdraw_count"],
                "returns": response["return_count"],
            })
            return response
