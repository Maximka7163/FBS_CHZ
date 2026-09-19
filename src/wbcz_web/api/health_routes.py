from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from wbcz_web.api.dependencies import AuthenticatedIdentity, get_db, require_permission
from wbcz_web.services.authorization import Permission
from wbcz_web.services.runtime_health import DeepHealthService, ReadinessService


health_router = APIRouter(prefix="/api", tags=["health"])


@health_router.get("/live")
def live(request: Request) -> dict:
    # Pure liveness: deliberately no DB, filesystem, agent or remote integration I/O.
    return {
        "status": "live",
        "service": "wbcz-web",
        "build_sha": request.app.state.config.build_sha,
    }


@health_router.get("/ready")
def ready(request: Request):
    service = ReadinessService(
        session_factory=request.app.state.session_factory,
        config=request.app.state.config,
        secret_provider=request.app.state.integration_secret_provider,
        draining=bool(getattr(request.app.state, "draining", False)),
    )
    ok, payload = service.evaluate()
    if ok:
        return payload
    return JSONResponse(status_code=503, content=payload)


@health_router.get("/health/deep")
def deep_health(
    request: Request,
    _: AuthenticatedIdentity = Depends(require_permission(Permission.AUDIT_READ, participant_required=False)),
    db: Session = Depends(get_db),
) -> dict:
    return DeepHealthService(
        db,
        config=request.app.state.config,
        secret_provider=request.app.state.integration_secret_provider,
    ).snapshot()
