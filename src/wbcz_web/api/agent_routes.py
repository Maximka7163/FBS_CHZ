from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
import os
from pathlib import Path
import tempfile
from sqlalchemy.orm import Session

from wbcz.agent_http import VpsAgentHttpBoundary
from wbcz.windows_agent import AgentAuthError, AgentSecurityError
from wbcz.write_pipeline import InvalidWriteOperation
from wbcz_web.services.document_orchestration import AgentOrchestrationBroker

from .dependencies import get_db


agent_router = APIRouter(prefix="/api/agent/v1", tags=["agent"])


def _boundary(request: Request, db: Session) -> VpsAgentHttpBoundary | None:
    config = request.app.state.config
    if not config.agent_enabled:
        return None
    return VpsAgentHttpBoundary(AgentOrchestrationBroker(db, config))


def _response(value) -> Response:
    return Response(
        content=value.body,
        status_code=value.status,
        headers=dict(value.headers or {}),
        media_type=None,
    )


@agent_router.head("/jobs/next")
def agent_preflight_auth(request: Request, db: Session = Depends(get_db)) -> Response:
    boundary = _boundary(request, db)
    if boundary is None:
        return Response(status_code=503, headers={"Cache-Control": "no-store"})
    return _response(
        boundary.handle(
            "HEAD",
            "/api/agent/v1/jobs/next",
            headers=request.headers,
        )
    )


@agent_router.get("/jobs/next")
def agent_next_job(request: Request, db: Session = Depends(get_db)) -> Response:
    boundary = _boundary(request, db)
    if boundary is None:
        return Response(status_code=503, headers={"Cache-Control": "no-store"})
    return _response(
        boundary.handle(
            "GET",
            "/api/agent/v1/jobs/next",
            headers=request.headers,
        )
    )


@agent_router.post("/jobs/{job_id}/result")
async def agent_job_result(job_id: str, request: Request, db: Session = Depends(get_db)) -> Response:
    boundary = _boundary(request, db)
    if boundary is None:
        return Response(status_code=503, headers={"Cache-Control": "no-store"})
    body = await request.body()
    return _response(
        boundary.handle(
            "POST",
            f"/api/agent/v1/jobs/{job_id}/result",
            headers=request.headers,
            body=body,
        )
    )


@agent_router.put("/report-artifacts/{artifact_upload_id}")
async def agent_report_artifact_ingress(
    artifact_upload_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    boundary = _boundary(request, db)
    if boundary is None:
        return Response(status_code=503, headers={"Cache-Control": "no-store"})
    config = request.app.state.config
    if not config.report_temp_root:
        return Response(status_code=503, headers={"Cache-Control": "no-store"})
    try:
        token = boundary._bearer(request.headers)
        boundary.broker.check_auth(token)
        report_job_id = request.headers.get("X-Report-Job-Id")
        result_id = request.headers.get("X-Remote-Result-Id")
        result_part_id = request.headers.get("X-Remote-Result-Part-Id")
        if not report_job_id or not result_id:
            raise AgentSecurityError("report artifact binding headers are required")
        if not artifact_upload_id.startswith("upl_") or len(artifact_upload_id) != 36:
            raise AgentSecurityError("invalid artifact upload id")

        temp_root = Path(config.report_temp_root)
        temp_root.mkdir(parents=True, exist_ok=True)
        fd, raw_path = tempfile.mkstemp(prefix="m11-agent-ingress-", suffix=".upload", dir=temp_root)
        os.close(fd)
        path = Path(raw_path)
        try:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            total = 0
            with path.open("wb") as out:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > 2 * 1024 * 1024 * 1024:
                        raise AgentSecurityError("agent artifact upload byte ceiling exceeded")
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())

            def chunks():
                with path.open("rb") as source:
                    while True:
                        part = source.read(1024 * 1024)
                        if not part:
                            break
                        yield part

            boundary.broker.upload_report_artifact(
                token,
                artifact_upload_id=artifact_upload_id,
                report_job_id=report_job_id,
                remote_result_id=result_id,
                remote_result_part_id=result_part_id,
                chunks=chunks(),
                observed_mime=request.headers.get("Content-Type"),
            )
            return Response(status_code=202, headers={"Cache-Control": "no-store"})
        finally:
            path.unlink(missing_ok=True)
    except AgentAuthError:
        return Response(status_code=401, headers={"Cache-Control": "no-store"})
    except (AgentSecurityError, InvalidWriteOperation, ValueError, KeyError):
        return Response(status_code=400, headers={"Cache-Control": "no-store"})
