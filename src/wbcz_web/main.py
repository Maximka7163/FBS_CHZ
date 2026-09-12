from __future__ import annotations

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .api import router
from .config import WebConfig
from .db import build_session_factory


def create_app(config: WebConfig | None = None, *, session_factory=None) -> FastAPI:
    config = (config or WebConfig.from_env()).validate_for_startup()
    production = config.environment == "production"
    app = FastAPI(
        title="Маркировка — WB FBS",
        version=config.app_version,
        debug=config.debug,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )
    app.state.config = config
    app.state.session_factory = session_factory or build_session_factory(config)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.trusted_hosts))
    app.include_router(router)
    return app


app = create_app()
