from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from .models import canonical_json, utc_now
from .m11_reports import DispenserCapability, DispenserRateDecision
from .windows_agent import (
    AgentJob,
    AgentJobType,
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

CREATE TABLE IF NOT EXISTS windows_agent_m11_rate_windows (
    scope_key TEXT NOT NULL,
    rate_family TEXT NOT NULL,
    history_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scope_key, rate_family)
);

CREATE TABLE IF NOT EXISTS windows_agent_runtime_metadata (
    metadata_key TEXT PRIMARY KEY,
    metadata_json TEXT NOT NULL,
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

    def consume_m11_rate(
        self,
        capability: DispenserCapability,
        *,
        scope_key: str,
        now_epoch: float,
    ) -> DispenserRateDecision:
        if not capability.enabled:
            from .m11_reports import ReportSecurityError
            raise ReportSecurityError(capability.disabled_reason or "capability disabled")
        if not scope_key:
            from .m11_reports import ReportContractError
            raise ReportContractError("rate scope key required")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT history_json FROM windows_agent_m11_rate_windows WHERE scope_key=? AND rate_family=?",
                (scope_key, capability.rate_family),
            ).fetchone()
            history = json.loads(row["history_json"]) if row is not None else []
            if not isinstance(history, list):
                history = []
            threshold = float(now_epoch) - 60.0
            kept = [float(item) for item in history if isinstance(item, (int, float)) and float(item) > threshold]
            if len(kept) >= capability.requests_per_minute:
                retry = max(0.0, 60.0 - (float(now_epoch) - kept[0]))
                self._connection.commit()
                return DispenserRateDecision(False, retry)
            kept.append(float(now_epoch))
            payload = json.dumps(kept, separators=(",", ":"))
            self._connection.execute(
                """INSERT INTO windows_agent_m11_rate_windows(scope_key, rate_family, history_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(scope_key, rate_family)
                DO UPDATE SET history_json=excluded.history_json, updated_at=excluded.updated_at""",
                (scope_key, capability.rate_family, payload, utc_now()),
            )
            self._connection.commit()
            return DispenserRateDecision(True, 0.0)
        except BaseException:
            self._connection.rollback()
            raise

    def set_runtime_metadata(self, key: str, value: dict) -> None:
        if not key or len(key) > 128:
            raise ValueError("invalid runtime metadata key")
        payload = canonical_json(value)
        self._connection.execute(
            """INSERT INTO windows_agent_runtime_metadata(metadata_key, metadata_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(metadata_key)
            DO UPDATE SET metadata_json=excluded.metadata_json, updated_at=excluded.updated_at""",
            (key, payload, utc_now()),
        )

    def get_runtime_metadata(self, key: str) -> dict | None:
        row = self._connection.execute(
            "SELECT metadata_json FROM windows_agent_runtime_metadata WHERE metadata_key=?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        value = json.loads(row["metadata_json"])
        return value if isinstance(value, dict) else None


class DurableDispenserRateLimiter:
    """M11 limiter whose consumed 60-second windows survive Windows agent restart."""

    def __init__(self, replay_store: WindowsAgentReplayStore, *, wall_clock=time.time) -> None:
        self.replay_store = replay_store
        self.wall_clock = wall_clock

    def consume(
        self,
        capability: DispenserCapability,
        *,
        scope_key: str,
        now_monotonic: float,
    ) -> DispenserRateDecision:
        del now_monotonic
        return self.replay_store.consume_m11_rate(
            capability,
            scope_key=scope_key,
            now_epoch=float(self.wall_clock()),
        )


class DurableWindowsAgentExecutor(WindowsAgentExecutor):
    """Production wiring executor with crash-safe duplicate-create prevention."""

    def __init__(self, *args, replay_store: WindowsAgentReplayStore, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.replay_store = replay_store

    @staticmethod
    def _report_create_payload_sha(job: AgentJob) -> str:
        payload = asdict(job)
        payload["job_type"] = job.job_type.value
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def execute(self, job: AgentJob) -> AgentResult:
        if job.job_type is AgentJobType.REPORT_CREATE:
            job.validate()
            if job.expected_inn != self.participant_inn:
                from .windows_agent import AgentSecurityError
                raise AgentSecurityError("expected_inn mismatch")
            payload_sha = self._report_create_payload_sha(job)
            replay_operation = "m11-report-create:" + job.operation_id
            previous = self.replay_store.claim(replay_operation, payload_sha)
            if previous is not None:
                return previous
            result = super().execute(job)
            self.replay_store.complete(replay_operation, payload_sha, result)
            return result
        return super().execute(job)

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
