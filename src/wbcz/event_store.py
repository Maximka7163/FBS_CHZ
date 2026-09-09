from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator

from .audit import append_audit
from .models import (
    CheckResult, Decision, DocumentReport, DocumentStatus, Event,
    ImportReport, KiState, Outcome, ParsedWorkbook, canonical_json, utc_now,
)
from .wb_parser import PARSER_VERSION


SCHEMA_VERSION = 2
SCHEMA = """
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS imports (
    fingerprint TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    parser_version INTEGER NOT NULL,
    imported_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('IMPORTED', 'PARTIAL')),
    new_events INTEGER NOT NULL,
    duplicate_events INTEGER NOT NULL,
    rejected_rows INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    kiz TEXT NOT NULL,
    task_number TEXT NOT NULL,
    sticker TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('Продажа', 'Возврат')),
    occurred_at TEXT,
    receipt_number TEXT,
    fiscal_drive_number TEXT,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    legal_entity_sale INTEGER CHECK (legal_entity_sale IN (0, 1)),
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_history
    ON events(kiz, occurred_at, event_id);
CREATE TABLE IF NOT EXISTS import_rows (
    fingerprint TEXT NOT NULL REFERENCES imports(fingerprint),
    row_number INTEGER NOT NULL,
    event_id TEXT REFERENCES events(event_id),
    error TEXT,
    PRIMARY KEY (fingerprint, row_number),
    CHECK (
        (event_id IS NOT NULL AND error IS NULL)
        OR (event_id IS NULL AND error IS NOT NULL)
    )
);
CREATE TABLE IF NOT EXISTS checks (
    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    source TEXT NOT NULL,
    snapshot_json TEXT,
    decision TEXT NOT NULL CHECK (decision IN (
        'READY_TO_WITHDRAW', 'READY_TO_RETURN', 'ALREADY_DONE',
        'NO_ACTION', 'MANUAL_REVIEW', 'ERROR'
    )),
    reason TEXT NOT NULL,
    error TEXT,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS checks_history ON checks(event_id, check_id);
-- A replaceable DRY-RUN projection, not a submission/outbox queue.
CREATE TABLE IF NOT EXISTS previews (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id),
    check_id INTEGER NOT NULL UNIQUE REFERENCES checks(check_id),
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    status TEXT NOT NULL CHECK (status IN (
        'ACCEPTED', 'PROCESSING', 'SUCCEEDED', 'REJECTED', 'VERIFICATION_ERROR'
    )),
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS document_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id TEXT NOT NULL REFERENCES documents(document_id),
    status TEXT NOT NULL,
    error TEXT,
    observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
PRAGMA user_version = 2;
COMMIT;
"""


class EventStore:
    """One connection per thread; writes are atomic and serialized by SQLite."""

    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(
            str(path), timeout=10, isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 10000")
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            if version == 1:
                # Explicit minimal migration policy: never relabel a v1 schema,
                # discard old audit, or reuse cached rejected imports silently.
                raise RuntimeError(
                    "БД версии 1 несовместима со схемой 2 (nullable occurred_at). "
                    "Автоматическая миграция не реализована. Сохраните старую БД "
                    "с историей и аудитом; укажите новый путь --db и повторно "
                    "импортируйте исходные WB-файлы. Старую БД не удаляйте."
                )
            if version not in (0, SCHEMA_VERSION):
                raise RuntimeError(f"Неподдерживаемая версия БД: {version}")
            if version == 0:
                objects = self._connection.execute(
                    """SELECT name FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'"""
                ).fetchall()
                if objects:
                    raise RuntimeError(
                        "Непустая БД без версии схемы: автоматическая "
                        "инициализация запрещена. Укажите новую чистую БД."
                    )

            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            if version == 0:
                self._connection.executescript(SCHEMA)

            columns = {
                row["name"]: row
                for row in self._connection.execute("PRAGMA table_info(events)")
            }
            if (
                "occurred_at" not in columns
                or columns["occurred_at"]["notnull"] != 0
            ):
                raise RuntimeError(
                    "Схема БД не соответствует версии 2: "
                    "events.occurred_at должен допускать NULL"
                )
        except BaseException:
            self._connection.close()
            raise

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def existing_import(self, fingerprint: str) -> ImportReport | None:
        row = self._connection.execute(
            "SELECT * FROM imports WHERE fingerprint = ?", (fingerprint,),
        ).fetchone()
        if row is None:
            return None
        return ImportReport(
            fingerprint=fingerprint,
            new_events=0,
            duplicate_events=row["new_events"] + row["duplicate_events"],
            rejected_rows=row["rejected_rows"],
            repeated_file=True,
        )

    def audit(
        self, action: str, entity_type: str, entity_id: str, details: dict[str, Any],
    ) -> None:
        with self._transaction() as connection:
            append_audit(connection, action, entity_type, entity_id, details)

    def import_workbook(
        self, fingerprint: str, filename: str, parsed: ParsedWorkbook,
    ) -> ImportReport:
        with self._transaction() as connection:
            # Recheck under the write lock: the earlier lookup is only a fast path.
            existing = self.existing_import(fingerprint)
            if existing is not None:
                append_audit(
                    connection, "IMPORT_REPEATED", "file", fingerprint, {},
                )
                return existing
            connection.execute(
                """INSERT INTO imports VALUES (?, ?, ?, ?, ?, 0, 0, ?)""",
                (
                    fingerprint, filename, PARSER_VERSION, utc_now(),
                    "PARTIAL" if parsed.issues else "IMPORTED",
                    len(parsed.issues),
                ),
            )
            inserted = 0
            duplicates = 0
            for item in parsed.rows:
                event = item.event
                payload = event.to_dict()
                cursor = connection.execute(
                    """INSERT INTO events (
                        event_id, kiz, task_number, sticker, operation,
                        occurred_at, receipt_number, fiscal_drive_number,
                        amount, currency, legal_entity_sale, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(event_id) DO NOTHING""",
                    (
                        event.event_id, event.kiz, event.task_number, event.sticker,
                        event.operation.value, payload["occurred_at"],
                        event.receipt_number, event.fiscal_drive_number,
                        payload["amount"], event.currency, event.legal_entity_sale,
                        canonical_json(payload), utc_now(),
                    ),
                )
                if cursor.rowcount == 1:
                    inserted += 1
                    # Old previews are snapshots. A changed WB history requires
                    # an explicit fresh preview, never an implicit action.
                    connection.execute(
                        """DELETE FROM previews WHERE event_id IN
                        (SELECT event_id FROM events WHERE kiz = ?)""",
                        (event.kiz,),
                    )
                    append_audit(
                        connection, "EVENT_IMPORTED", "event", event.event_id,
                        {"fingerprint": fingerprint, "row": item.row_number},
                    )
                else:
                    duplicates += 1
                connection.execute(
                    """INSERT INTO import_rows
                    (fingerprint, row_number, event_id, error)
                    VALUES (?, ?, ?, NULL)""",
                    (fingerprint, item.row_number, event.event_id),
                )
            for issue in parsed.issues:
                connection.execute(
                    """INSERT INTO import_rows
                    (fingerprint, row_number, event_id, error)
                    VALUES (?, ?, NULL, ?)""",
                    (fingerprint, issue.row_number, issue.message),
                )
                append_audit(
                    connection, "ROW_REJECTED", "file", fingerprint,
                    {"row": issue.row_number, "error": issue.message},
                )
            connection.execute(
                """UPDATE imports SET new_events = ?, duplicate_events = ?
                WHERE fingerprint = ?""",
                (inserted, duplicates, fingerprint),
            )
            report = ImportReport(
                fingerprint, inserted, duplicates, len(parsed.issues), False,
            )
            append_audit(
                connection, "IMPORT_COMPLETED", "file", fingerprint, asdict(report),
            )
            return report

    def events(self, kiz: str | None = None) -> list[Event]:
        """Deterministic DISPLAY order, not a total real-world chronology.

        Within a KI: known dates chronologically, then undated events by ID.
        Placement of the undated group is presentation only: it does NOT mean
        those events occurred later. ID tie-breaks carry no chronological fact.
        Never choose a 'latest event' by taking the last element of this list.
        """
        if kiz is None:
            rows = self._connection.execute(
                """SELECT payload_json FROM events
                ORDER BY kiz, occurred_at IS NULL, occurred_at, event_id"""
            )
        else:
            rows = self._connection.execute(
                """SELECT payload_json FROM events WHERE kiz = ?
                ORDER BY occurred_at IS NULL, occurred_at, event_id""",
                (kiz,),
            )
        return [Event.from_dict(json.loads(row["payload_json"])) for row in rows]

    def history_order_ambiguous(self, kiz: str) -> bool:
        """Detect missing/tied timestamp evidence in a multi-event KI history.

        A False result is NOT reconciliation approval or document readiness:
        corrected rows and source timestamp precision still require review.
        A lone undated event has unknown date but no pair to order.
        """
        rows = self._connection.execute(
            "SELECT occurred_at FROM events WHERE kiz = ?", (kiz,),
        ).fetchall()
        if len(rows) < 2:
            return False
        dates = [row["occurred_at"] for row in rows]
        return any(value is None for value in dates) or len(set(dates)) != len(dates)

    def get_event(self, event_id: str) -> Event:
        row = self._connection.execute(
            "SELECT payload_json FROM events WHERE event_id = ?", (event_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Событие не найдено: {event_id}")
        return Event.from_dict(json.loads(row["payload_json"]))

    def save_check(
        self, event_id: str, snapshot: KiState | None,
        outcome: Outcome, *, source: str,
    ) -> CheckResult:
        with self._transaction() as connection:
            timestamp = utc_now()
            cursor = connection.execute(
                """INSERT INTO checks (
                    event_id, source, snapshot_json, decision, reason, error, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_id, source,
                    canonical_json(asdict(snapshot)) if snapshot is not None else None,
                    outcome.decision.value, outcome.reason, outcome.error, timestamp,
                ),
            )
            assert cursor.lastrowid is not None
            check_id = cursor.lastrowid
            connection.execute(
                """INSERT INTO previews (event_id, check_id, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    check_id = excluded.check_id,
                    updated_at = excluded.updated_at""",
                (event_id, check_id, timestamp),
            )
            append_audit(
                connection, "DRY_RUN_CHECKED", "event", event_id,
                {
                    "check_id": check_id,
                    "decision": outcome.decision.value,
                    "reason": outcome.reason,
                    "error": outcome.error,
                    "source": source,
                },
            )
            return CheckResult(check_id, event_id, outcome)

    def checks(self, event_id: str) -> list[dict[str, Any]]:
        return [
            dict(row) for row in self._connection.execute(
                "SELECT * FROM checks WHERE event_id = ? ORDER BY check_id",
                (event_id,),
            )
        ]

    def previews(self) -> list[dict[str, Any]]:
        # Same presentation convention as events(), not an execution sequence.
        return [
            dict(row) for row in self._connection.execute(
                """SELECT c.* FROM previews p
                JOIN checks c ON c.check_id = p.check_id
                JOIN events e ON e.event_id = p.event_id
                ORDER BY e.kiz, e.occurred_at IS NULL, e.occurred_at, e.event_id"""
            )
        ]

    def import_issues(self, fingerprint: str) -> list[dict[str, Any]]:
        return [
            dict(row) for row in self._connection.execute(
                """SELECT row_number, error FROM import_rows
                WHERE fingerprint = ? AND error IS NOT NULL
                ORDER BY row_number""",
                (fingerprint,),
            )
        ]

    def audit_entries(self) -> list[dict[str, Any]]:
        return [
            dict(row) for row in self._connection.execute(
                "SELECT * FROM audit_log ORDER BY id"
            )
        ]

    def register_document(self, event_id: str, document_id: str) -> None:
        """Record a known ID. Does not build, sign or submit anything."""
        if not document_id:
            raise ValueError("Пустой document_id")
        with self._transaction() as connection:
            timestamp = utc_now()
            existing = connection.execute(
                "SELECT event_id FROM documents WHERE document_id = ?",
                (document_id,),
            ).fetchone()
            if existing is not None:
                if existing["event_id"] != event_id:
                    raise ValueError("document_id уже связан с другим событием")
                return
            connection.execute(
                "INSERT INTO documents VALUES (?, ?, ?, NULL, ?, ?)",
                (
                    document_id, event_id, DocumentStatus.ACCEPTED.value,
                    timestamp, timestamp,
                ),
            )
            connection.execute(
                """INSERT INTO document_status_history
                (document_id, status, error, observed_at)
                VALUES (?, ?, NULL, ?)""",
                (document_id, DocumentStatus.ACCEPTED.value, timestamp),
            )
            append_audit(
                connection, "DOCUMENT_REGISTERED", "document", document_id,
                {"event_id": event_id, "status": DocumentStatus.ACCEPTED.value},
            )

    def document_report(self, document_id: str) -> DocumentReport:
        row = self._connection.execute(
            "SELECT status, error FROM documents WHERE document_id = ?",
            (document_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Документ не найден: {document_id}")
        return DocumentReport(DocumentStatus(row["status"]), row["error"])

    def update_document(
        self, document_id: str, report: DocumentReport,
    ) -> DocumentReport:
        with self._transaction() as connection:
            current = self.document_report(document_id)
            if current.status in {DocumentStatus.SUCCEEDED, DocumentStatus.REJECTED}:
                if report != current:
                    raise ValueError("Нельзя изменить терминальный статус документа")
                return current
            timestamp = utc_now()
            connection.execute(
                """UPDATE documents SET status = ?, error = ?, updated_at = ?
                WHERE document_id = ?""",
                (report.status.value, report.error, timestamp, document_id),
            )
            connection.execute(
                """INSERT INTO document_status_history
                (document_id, status, error, observed_at) VALUES (?, ?, ?, ?)""",
                (document_id, report.status.value, report.error, timestamp),
            )
            append_audit(
                connection, "DOCUMENT_STATUS_OBSERVED", "document", document_id,
                {"status": report.status.value, "error": report.error},
            )
            return report

    def document_history(self, document_id: str) -> list[dict[str, Any]]:
        return [
            dict(row) for row in self._connection.execute(
                """SELECT * FROM document_status_history
                WHERE document_id = ? ORDER BY id""",
                (document_id,),
            )
        ]

    def count(self, table: str) -> int:
        allowed = {
            "imports", "events", "import_rows", "checks", "previews",
            "documents", "document_status_history", "audit_log",
        }
        if table not in allowed:
            raise ValueError("Недопустимая таблица")
        return int(self._connection.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0])
