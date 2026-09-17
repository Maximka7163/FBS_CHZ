from __future__ import annotations

from datetime import timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from wbcz.cis_inventory import validate_m1_job_payload
from wbcz.reference_products import M2_READ_JOB_TYPES, validate_m2_job_payload
from wbcz.windows_agent import AgentJob, AgentJobState, AgentJobType, P0_PG
from wbcz_web.config import WebConfig
from wbcz_web.models import AgentJobRecord
from wbcz_web.repositories import SqlAlchemyAgentJobStore


REFERENCE_PRODUCTS_PURPOSE = "REFERENCE_PRODUCTS"


class ReferenceProductsUnavailable(RuntimeError):
    pass


class ReferenceProductsService:
    """M2 backend queue. Dynamic True API reads run only through the Windows agent."""

    def __init__(self, db: Session, config: WebConfig) -> None:
        if not config.agent_enabled:
            raise ReferenceProductsUnavailable("Windows agent is disabled")
        self.db = db
        self.config = config
        self.jobs = SqlAlchemyAgentJobStore(db, lease_seconds=config.agent_job_lease_seconds)

    def queue(self, job_type: AgentJobType, payload: dict[str, Any]) -> dict[str, Any]:
        if job_type is AgentJobType.PRODUCT_INFO:
            canonical = validate_m1_job_payload(job_type.value, payload)
        elif job_type.value in M2_READ_JOB_TYPES:
            canonical = validate_m2_job_payload(job_type.value, payload)
        else:
            raise ValueError("unsupported reference_products job type")
        request_uuid = uuid4().hex
        job = AgentJob(
            job_id=f"job_m2_{request_uuid}",
            job_type=job_type,
            operation_id=f"m2read:{request_uuid}",
            pg=P0_PG,
            expected_inn=self.config.own_inn,
            read_payload=canonical,
        )
        self.jobs.enqueue(job, purpose=REFERENCE_PRODUCTS_PURPOSE)
        self.db.flush()
        return {
            "request_id": job.job_id,
            "status": "pending",
            "job_type": job_type.value,
            "source": "windows-agent-true-api",
        }

    def self_participant(self) -> dict[str, Any]:
        return self.queue(AgentJobType.PARTICIPANTS, {"inns": [self.config.own_inn]})

    def status(self, request_id: str) -> dict[str, Any]:
        row = self.db.get(AgentJobRecord, request_id)
        if row is None or row.purpose != REFERENCE_PRODUCTS_PURPOSE:
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
        return {
            "request_id": row.job_id,
            "job_type": row.job_type,
            "status": public_state,
            "source": "windows-agent-true-api",
            "request": dict(row.payload_json.get("read_payload") or {}),
            "result": result.get("read_result") if result else None,
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
