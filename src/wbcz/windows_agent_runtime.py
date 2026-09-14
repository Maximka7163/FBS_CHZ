from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3

from .models import canonical_json, utc_now
from .windows_agent import (
    AgentJob,
    AgentProductionWriteDisabled,
    AgentReplayConflict,
    AgentResult,
    WindowsAgentExecutor,
)


class AgentCreateOutcomeUnresolved(AgentReplayConflict):
    """Previous local create reservation has no durable final result."""


_REPLAY_SCHEMA = """
CREATE TABLE IF NOT EXISTS windows_agent_write_replay (
    operation_id TEXT PRIMARY KEY,
    document_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('RESERVED','COMPLETED')),
    result_sha256 TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class WindowsAgentReplayStore:
    """Local durable guard preventing a second create after process restart."""

    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout=10000")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript(_REPLAY_SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "WindowsAgentReplayStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _decode_result(raw: str) -> AgentResult:
        data = json.loads(raw)
        data["cises"] = tuple(data.get("cises") or ())
        return AgentResult(**data)

    def claim(self, operation_id: str, document_sha256: str) -> AgentResult | None:
        if not operation_id or not document_sha256:
            raise ValueError("operation_id and document_sha256 are required")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT * FROM windows_agent_write_replay WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                now = utc_now()
                self._connection.execute(
                    """INSERT INTO windows_agent_write_replay
                    (operation_id, document_sha256, state, result_sha256,
                     result_json, created_at, updated_at)
                    VALUES (?, ?, 'RESERVED', NULL, NULL, ?, ?)""",
                    (operation_id, document_sha256, now, now),
                )
                self._connection.commit()
                return None
            if row["document_sha256"] != document_sha256:
                raise AgentReplayConflict(
                    "operation replay with different immutable document hash"
                )
            if row["state"] == "COMPLETED":
                if not row["result_json"]:
                    raise AgentReplayConflict("completed replay entry misses result")
                result = self._decode_result(row["result_json"])
                self._connection.commit()
                return result
            raise AgentCreateOutcomeUnresolved(
                "previous create attempt outcome is unresolved; duplicate create blocked"
            )
        except BaseException:
            self._connection.rollback()
            raise

    def complete(
        self,
        operation_id: str,
        document_sha256: str,
        result: AgentResult,
    ) -> None:
        serialized = canonical_json(asdict(result))
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT * FROM windows_agent_write_replay WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise AgentReplayConflict("write operation was not reserved")
            if row["document_sha256"] != document_sha256:
                raise AgentReplayConflict("write result hash mismatch")
            if row["state"] == "COMPLETED":
                if row["result_sha256"] != digest:
                    raise AgentReplayConflict("incompatible duplicate local result")
                self._connection.commit()
                return
            self._connection.execute(
                """UPDATE windows_agent_write_replay
                SET state='COMPLETED', result_sha256=?, result_json=?, updated_at=?
                WHERE operation_id=?""",
                (digest, serialized, utc_now(), operation_id),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def state(self, operation_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT state FROM windows_agent_write_replay WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        return str(row["state"]) if row else None


class DurableWindowsAgentExecutor(WindowsAgentExecutor):
    """Production wiring executor with crash-safe duplicate-create prevention."""

    def __init__(self, *args, replay_store: WindowsAgentReplayStore, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.replay_store = replay_store

    def _write(self, job: AgentJob) -> AgentResult:
        if not self.production_write:
            raise AgentProductionWriteDisabled("production_write=false")
        assert job.document_sha256 is not None
        previous = self.replay_store.claim(job.operation_id, job.document_sha256)
        if previous is not None:
            return previous
        # Reservation is durable before signing/create. Any crash or ambiguous
        # exception leaves RESERVED, so a restarted agent fails closed instead
        # of issuing a second True API create.
        result = super()._write(job)
        self.replay_store.complete(
            job.operation_id, job.document_sha256, result
        )
        return result
