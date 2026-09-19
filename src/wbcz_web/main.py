from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import WebConfig
from .db import build_session_factory


def create_app(
    config: WebConfig | None = None,
    *,
    session_factory=None,
    integration_secret_provider=None,
    wb_http_adapter=None,
    wb_rate_limiter=None,
) -> FastAPI:
    # Import routers only after create_app is called, avoiding partially initialized
    # router modules during auth/repository dependency cycles.
    from .api.routes import router
    from .api.agent_routes import agent_router
    from .api.security_routes import security_router
    from .api.report_routes import reports_router
    from .api.audit_routes import audit_router
    from .api.integration_routes import integrations_router
    from .api.health_routes import health_router
    from .api.enrollment_routes import enrollment_router
    from .services.integration_secrets import ReadOnlySecretProvider
    from .services.production_secrets import build_production_secret_provider
    from .middleware import RequestContextMiddleware
    from wbcz.wb_fbs import StatefulWbRateLimiter
    config = (config or WebConfig.from_env()).validate_for_startup()
    production = config.environment == "production"
    child_routes = [
        *router.routes,
        *security_router.routes,
        *reports_router.routes,
        *audit_router.routes,
        *integrations_router.routes,
        *health_router.routes,
        *enrollment_router.routes,
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
    if integration_secret_provider is not None:
        app.state.integration_secret_provider = integration_secret_provider
    elif production and config.m15_strict_production:
        app.state.integration_secret_provider = build_production_secret_provider(config)
    else:
        app.state.integration_secret_provider = ReadOnlySecretProvider()
    app.state.wb_http_adapter = wb_http_adapter
    app.state.wb_rate_limiter = wb_rate_limiter or StatefulWbRateLimiter()
    app.state.draining = False
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.trusted_hosts))
    app.add_middleware(RequestContextMiddleware)
    paths = {route.path for route in app.routes if hasattr(route, "path")}
    required = {
        "/api/health",
        "/api/live",
        "/api/ready",
        "/api/health/deep",
        "/api/security/scopes",
        "/api/security/scope",
        "/api/reports/{job_id}/artifacts/{artifact_id}/download",
        "/api/audit/events",
        "/api/integrations",
        "/api/environment-capabilities",
        "/api/agent/status",
        "/api/certificate/status",
        "/api/agent/v1/jobs/next",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(f"API router assembly incomplete: {sorted(missing)}")
    return app


app = create_app()
