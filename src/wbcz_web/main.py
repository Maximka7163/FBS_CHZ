from __future__ import annotations
from fastapi import FastAPI
from .api import router
from .config import WebConfig
from .db import build_session_factory

def create_app(config:WebConfig|None=None,*,session_factory=None)->FastAPI:
 config=config or WebConfig.from_env();app=FastAPI(title="Маркировка — WB FBS",version="0.5.0",docs_url=None if config.environment=="production" else "/docs",redoc_url=None);app.state.config=config;app.state.session_factory=session_factory or build_session_factory(config);app.include_router(router);return app
app=create_app()
