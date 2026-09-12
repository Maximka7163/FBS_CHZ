from __future__ import annotations

from pathlib import Path
from typing import Callable

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from wbcz.true_api import TrueApiError
from .application import OperationMode, UiApplication
from .live_true_api import (
    LiveAuthorizationRequired,
    LiveReadOnlyConfig,
    LiveTrueApiClient,
)


class PreviewRequest(BaseModel):
    import_id: str | None = None
    mode: OperationMode = OperationMode.AUTO
    selected_event_ids: list[str] | None = None
    event_ids: list[str] | None = None

    def selected(self) -> list[str]:
        return (
            self.selected_event_ids
            if self.selected_event_ids is not None
            else self.event_ids or []
        )


class CheckRequest(BaseModel):
    event_ids: list[str] | None = None


def create_app(
    db_path: str | Path = "wbcz-ui.sqlite",
    live_config: LiveReadOnlyConfig | None = None,
    live_client_factory: Callable[[LiveReadOnlyConfig], LiveTrueApiClient] | None = None,
) -> FastAPI:
    app = FastAPI(title="WB FBS UI", version="0.4.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:8000",
        ],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    service = UiApplication(db_path, live_config, live_client_factory)

    @app.get("/api/status")
    def status():
        return service.runtime_status()

    @app.post("/api/live/preflight")
    def live_preflight():
        try:
            return service.live_preflight()
        except (ValueError, TrueApiError) as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/api/live/authenticate")
    def live_authenticate():
        try:
            return service.live_authenticate()
        except LiveAuthorizationRequired as exc:
            raise HTTPException(409, str(exc)) from exc
        except (ValueError, TrueApiError) as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.get("/api/imports")
    def imports(limit: int = 10):
        return service.list_imports(min(max(limit, 1), 50))

    @app.post("/api/imports")
    async def upload(file: UploadFile = File(...)):
        if not file.filename or not file.filename.lower().endswith(".xlsx"):
            raise HTTPException(400, "Поддерживается только XLSX")
        return service.import_bytes(file.filename, await file.read())

    @app.get("/api/imports/{fingerprint}")
    def info(fingerprint: str):
        try:
            return service.get_import(fingerprint)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/imports/{fingerprint}/events")
    def events(fingerprint: str):
        return service.events_for_import(fingerprint)

    @app.post("/api/imports/{fingerprint}/check")
    def check(fingerprint: str, request: CheckRequest | None = None):
        try:
            return service.check_import(
                fingerprint, request.event_ids if request else None
            )
        except LiveAuthorizationRequired as exc:
            raise HTTPException(409, str(exc)) from exc
        except TrueApiError as exc:
            raise HTTPException(503, str(exc)) from exc
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/events/{event_id}")
    def event(event_id: str):
        try:
            return service.event_detail(event_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/operation-preview")
    def preview(request: PreviewRequest):
        try:
            return service.operation_preview(
                request.selected(), request.mode, request.import_id
            )
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc

    return app
