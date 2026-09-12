from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .application import UiApplication


class PreviewRequest(BaseModel):
    event_ids: list[str]


def create_app(db_path: str | Path = "wbcz-ui.sqlite") -> FastAPI:
    app = FastAPI(title="WB FBS UI", version="0.3.0")
    app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:8000"], allow_methods=["*"], allow_headers=["*"])
    service = UiApplication(db_path)

    @app.get("/api/status")
    def status():
        return {"mode": "offline-dry-run", "true_api": False, "signing": False, "submission": False}

    @app.get("/api/imports")
    def imports(limit: int = 10):
        return service.list_imports(min(max(limit, 1), 50))

    @app.post("/api/imports")
    async def upload(file: UploadFile = File(...)):
        if not file.filename or not file.filename.lower().endswith(".xlsx"):
            raise HTTPException(400, "Поддерживается только XLSX")
        return service.import_bytes(file.filename, await file.read())

    @app.get("/api/imports/{fingerprint}")
    def import_info(fingerprint: str):
        try:
            return service.get_import(fingerprint)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/imports/{fingerprint}/events")
    def import_events(fingerprint: str):
        return service.events_for_import(fingerprint)

    @app.post("/api/imports/{fingerprint}/check")
    def check(fingerprint: str):
        return service.check_import(fingerprint)

    @app.get("/api/events/{event_id}")
    def event(event_id: str):
        try:
            return service.event_detail(event_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/operation-preview")
    def preview(request: PreviewRequest):
        return service.operation_preview(request.event_ids)

    return app
