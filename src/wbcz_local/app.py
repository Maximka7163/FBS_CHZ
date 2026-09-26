from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from wbcz.wb_fbs import StatefulWbRateLimiter
from wbcz_web.api.health_routes import health_router
from wbcz_web.api.routes import router as fbs_router
from wbcz_web.config import WebConfig
from wbcz_web.db import build_session_factory
from wbcz_web.middleware import RequestContextMiddleware
from wbcz_web.services.integration_secrets import ReadOnlySecretProvider

from .bridge import LocalTrueApiReadBridge
from .routes import local_router


LOCAL_BIND_HOST = "127.0.0.1"
LOCAL_DEFAULT_PORT = 8765
_LOCAL_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "testserver"}


def assert_local_foundation_safety(config: WebConfig) -> None:
    """Fail closed while the local True API read bridge is not yet accepted."""
    if config.environment == "production":
        raise ValueError("local Sellari runtime must not use production server mode")
    if not config.fbs_dry_run_only:
        raise ValueError("local foundation requires WBCZ_FBS_DRY_RUN_ONLY=true")
    if config.true_api_write_enabled:
        raise ValueError("local foundation forbids True API business writes")
    if not config.true_api_real_read_enabled:
        raise ValueError("local True API real read must be enabled for the accepted read-only runtime")
    if config.agent_enabled:
        raise ValueError("VPS/agent transport is not used by the local foundation runtime")
    if config.printing_enabled or config.print_execution_enabled:
        raise ValueError("printing is outside the local FBS foundation scope")
    if config.suz_full_km_remote_acquisition_enabled:
        raise ValueError("SUZ remote acquisition is outside the local FBS foundation scope")
    if not config.trusted_hosts or any(host not in _LOCAL_ALLOWED_HOSTS for host in config.trusted_hosts):
        raise ValueError("local Sellari trusted hosts must be loopback-only")


def frontend_dist_from_env() -> Path:
    configured = os.getenv("SELLARI_LOCAL_FRONTEND_DIST", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path(__file__).resolve().parents[2] / "frontend" / "dist").resolve()


def create_local_app(
    config: WebConfig | None = None,
    *,
    session_factory=None,
    frontend_dist: Path | None = None,
    true_api_bridge: LocalTrueApiReadBridge | None = None,
) -> FastAPI:
    config = (config or WebConfig.from_env()).validate_for_startup()
    assert_local_foundation_safety(config)

    dist = (frontend_dist or frontend_dist_from_env()).resolve()
    if not (dist / "index.html").is_file():
        raise RuntimeError(
            f"local frontend build is missing: {dist / 'index.html'}; run Setup-Local.ps1"
        )

    local_fbs_paths = {
        "/api/health",
        "/api/version",
        "/api/auth/csrf",
        "/api/auth/login",
        "/api/auth/logout",
        "/api/me",
        "/api/capabilities",
        "/api/workspace",
        "/api/files",
        "/api/files/{import_id}",
        "/api/files/{import_id}/events",
        "/api/files/{import_id}/workspace",
        "/api/files/{import_id}/bulk-preview",
        "/api/files/{import_id}/bulk-actions",
        "/api/events/{event_id}",
        "/api/operation-preview",
    }
    local_base_routes = [
        route
        for route in fbs_router.routes
        if getattr(route, "path", None) in local_fbs_paths
    ]
    app = FastAPI(
        title="Sellari Marking — Local WB FBS",
        version=config.app_version,
        debug=config.debug,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        routes=[
            *local_router.routes,
            *local_base_routes,
            *health_router.routes,
        ],
    )
    app.state.config = config
    app.state.session_factory = session_factory or build_session_factory(config)
    app.state.integration_secret_provider = ReadOnlySecretProvider()
    app.state.wb_http_adapter = None
    app.state.wb_rate_limiter = StatefulWbRateLimiter()
    app.state.draining = False
    app.state.local_true_api_bridge = true_api_bridge or LocalTrueApiReadBridge.from_env()

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.trusted_hosts))
    app.add_middleware(RequestContextMiddleware)

    # StaticFiles is mounted last so every /api route remains backend-authoritative.
    app.mount("/", StaticFiles(directory=str(dist), html=True), name="sellari-local-ui")
    return app
