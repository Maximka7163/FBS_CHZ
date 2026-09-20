from __future__ import annotations

from dataclasses import asdict
from datetime import timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from wbcz.cis_inventory import validate_m1_job_payload
from wbcz.windows_agent import AgentJob, AgentJobState, AgentJobType, P0_PG
from wbcz_web.config import WebConfig
from wbcz_web.models import AgentJobRecord
from wbcz_web.repositories import SqlAlchemyAgentJobStore
from wbcz_web.services.tenant import participant_inn_for_runtime, scoped_agent_job
from wbcz_web.services.printing import LocalPrintingService


CIS_INVENTORY_PURPOSE = "CIS_INVENTORY"


class CisInventoryUnavailable(RuntimeError):
    pass


class CisInventoryService:
    """Backend-only M1 request queue. No True API transport exists here."""

    def __init__(self, db: Session, config: WebConfig) -> None:
        if not config.agent_enabled:
            raise CisInventoryUnavailable("Windows agent is disabled")
        self.db = db
        self.config = config
        self.jobs = SqlAlchemyAgentJobStore(db, lease_seconds=config.agent_job_lease_seconds)

    def queue(self, job_type: AgentJobType, payload: dict[str, Any]) -> dict[str, Any]:
        if job_type.value not in {
            "CIS_INFO",
            "CIS_SEARCH",
            "CIS_HISTORY",
            "CIS_AGGREGATED_LIST",
            "CIS_AGGREGATION_HISTORY",
            "PRODUCT_INFO",
            "CIS_TO_PRODUCT",
        }:
            raise ValueError("unsupported cis_inventory job type")
        canonical = validate_m1_job_payload(job_type.value, payload)
        request_uuid = uuid4().hex
        operation_id = f"m1read:{request_uuid}"
        job_id = f"job_m1_{request_uuid}"
        job = AgentJob(
            job_id=job_id,
            job_type=job_type,
            operation_id=operation_id,
            pg=P0_PG,
            expected_inn=participant_inn_for_runtime(self.db,self.config.own_inn),
            read_payload=canonical,
        )
        self.jobs.enqueue(job, purpose=CIS_INVENTORY_PURPOSE)
        self.db.flush()
        return {
            "request_id": job_id,
            "status": "pending",
            "job_type": job_type.value,
            "source": "windows-agent-true-api",
        }

    def status(self, request_id: str) -> dict[str, Any]:
        row = scoped_agent_job(self.db, request_id)
        if row is None or row.purpose != CIS_INVENTORY_PURPOSE:
            raise KeyError(request_id)
        state = AgentJobState(row.state)
        result = dict(row.result_json) if isinstance(row.result_json, dict) else None
        if state is AgentJobState.PENDING:
            public_state = "pending"
        elif state is AgentJobState.LEASED:
            public_state = "running"
        elif result and result.get("outcome") == "READ_COMPLETED":
            public_state = "completed"
        else:
            public_state = "failed"
        read_result = result.get("read_result") if result else None
        if public_state == "completed" and read_result is not None:
            read_result = LocalPrintingService(self.db, self.config).enrich_m1_result(read_result)
        return {
            "request_id": row.job_id,
            "job_type": row.job_type,
            "status": public_state,
            "source": "windows-agent-true-api",
            "request": dict(row.payload_json.get("read_payload") or {}),
            "result": read_result,
            "transport": (
                {
                    "http_status": result.get("http_status"),
                    "content_type": result.get("content_type"),
                    "safe_error_code": result.get("error_code"),
                    "safe_error_message": result.get("error_message"),
                    "body_sha256": result.get("body_sha256"),
                }
                if result else None
            ),
            "fetched_at": (
                row.updated_at.astimezone(timezone.utc).isoformat()
                if state is AgentJobState.COMPLETED and row.updated_at is not None
                else None
            ),
        }
