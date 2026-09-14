from __future__ import annotations

import base64
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
from .write_pipeline import CreateCategory


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

    def inspect(self, operation_id: str, document_sha256: str) -> AgentResult | None:
        row = self._connection.execute(
            "SELECT * FROM windows_agent_write_replay WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            return None
        if row["document_sha256"] != document_sha256:
            raise AgentReplayConflict("operation replay with different immutable document hash")
        if row["state"] == "COMPLETED":
            if not row["result_json"]:
                raise AgentReplayConflict("completed replay entry misses result")
            return self._decode_result(row["result_json"])
        raise AgentCreateOutcomeUnresolved(
            "previous create attempt outcome is unresolved; duplicate create blocked"
        )

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
                raise AgentReplayConflict("operation replay with different immutable document hash")
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

    def complete(self, operation_id: str, document_sha256: str, result: AgentResult) -> None:
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
        assert job.document_sha256 and job.product_document_base64 and job.document_type

        previous = self.replay_store.inspect(job.operation_id, job.document_sha256)
        if previous is not None:
            return previous

        # Local signing happens before the ambiguity reservation. A pure local
        # signing/certificate error therefore remains safely retryable because
        # no HTTP create can have been sent yet.
        raw = base64.b64decode(job.product_document_base64, validate=True)
        signature, metadata = self.document_signer.sign_document_bytes(
            operation_id=job.operation_id,
            document_type=job.document_type,
            pg=job.pg,
            expected_inn=job.expected_inn,
            document_sha256=job.document_sha256,
            payload=raw,
        )

        # From this point onward a crash/transport exception is ambiguous with
        # respect to create delivery. The durable RESERVED marker is written
        # before the first possible create I/O and can never auto-retry.
        previous = self.replay_store.claim(job.operation_id, job.document_sha256)
        if previous is not None:
            return previous

        response = self.transport.create_document(
            document_type=job.document_type,
            product_document_base64=job.product_document_base64,
            signature_base64=signature,
            bearer_token=self.session_manager.bearer_token(),
        )
        body_sha = hashlib.sha256(response.body).hexdigest()
        if response.status in (200, 201):
            document_id = self.create_id_parser.parse_document_id(response)
            if document_id:
                category = CreateCategory.SUCCESS_WITH_ID.value
                outcome = "SUBMITTED"
            else:
                category = CreateCategory.SUCCESS_CONTRACT_UNCONFIRMED.value
                outcome = "MANUAL_REVIEW"
        else:
            document_id = None
            category = {
                400: CreateCategory.BAD_REQUEST.value,
                401: CreateCategory.UNAUTHORIZED.value,
                403: CreateCategory.FORBIDDEN.value,
                422: CreateCategory.UNPROCESSABLE.value,
            }.get(response.status)
            if category is None:
                category = (
                    CreateCategory.SERVER_ERROR.value
                    if response.status >= 500
                    else CreateCategory.HTTP_ERROR.value
                )
            outcome = "MANUAL_REVIEW" if response.status >= 500 else "FAILED"
        result = AgentResult(
            job.job_id,
            job.operation_id,
            outcome,
            document_sha256=job.document_sha256,
            signature_base64=signature,
            http_status=response.status,
            create_category=category,
            document_id=document_id,
            body_sha256=body_sha,
            **metadata,
        )
        self.replay_store.complete(job.operation_id, job.document_sha256, result)
        return result
