from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import WebConfig
from .db import build_session_factory


def create_app(config: WebConfig | None = None, *, session_factory=None) -> FastAPI:
    # Import routers only after create_app is called, avoiding partially initialized
    # router modules during auth/repository dependency cycles.
    from .api.routes import router
    from .api.agent_routes import agent_router
    from .api.security_routes import security_router
    from .api.report_routes import reports_router\n    from .api.audit_routes import audit_router
    config = (config or WebConfig.from_env()).validate_for_startup()
    production = config.environment == "production"
    child_routes = [
        *router.routes,
        *security_router.routes,
        *reports_router.routes,
        *agent_router.routes,
    ]
    app = FastAPI(
        title="Маркировка — WB FBS",
        version=config.app_version,
        debug=config.debug,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
        routes=child_routes,
    )
    app.state.config = config
    app.state.session_factory = session_factory or build_session_factory(config)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.trusted_hosts))
    paths = {route.path for route in app.routes if hasattr(route, "path")}
    required = {
        "/api/health",
        "/api/security/scopes",
        "/api/security/scope",
        "/api/reports/{job_id}/artifacts/{artifact_id}/download",\n        "/api/audit/events",
        "/api/agent/v1/jobs/next",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(f"API router assembly incomplete: {sorted(missing)}")
    return app


app = create_app()
