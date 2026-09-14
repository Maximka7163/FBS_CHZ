from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from wbcz.agent_http import VpsAgentHttpBoundary
from wbcz_web.services.agent_orchestration import AgentOrchestrationBroker

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
