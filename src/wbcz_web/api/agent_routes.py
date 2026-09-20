from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
import os
import shutil
from pathlib import Path
import tempfile
from sqlalchemy.orm import Session

from wbcz.agent_http import VpsAgentHttpBoundary
from wbcz.printing_sensitive import b64d
from wbcz.windows_agent import AgentAuthError, AgentSecurityError
from wbcz.write_pipeline import InvalidWriteOperation
from wbcz_web.services.document_orchestration import AgentOrchestrationBroker
from wbcz_web.services.agent_bindings import AgentBindingService
from wbcz_web.services.printing_sensitive_delivery import (
    SensitiveDeliveryRejected,
    SensitivePrintingDeliveryService,
)
from wbcz_web.services.printer_profiles import PrinterProfileRejected, PrinterProfileService

from .dependencies import get_db


agent_router = APIRouter(prefix="/api/agent/v1", tags=["agent"])
agent_v2_printing_router = APIRouter(prefix="/api/agent/v2/printing", tags=["agent-printing-v2"])


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrintKeyRegistrationRequest(_ClosedModel):
    intent_token: str = Field(min_length=43, max_length=256)
    public_key: str = Field(min_length=40, max_length=128)


class PrintPayloadAckRequest(_ClosedModel):
    delivery_reservation_id: str = Field(min_length=1, max_length=64)
    payload_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    context_sha256: str = Field(pattern="^[0-9a-f]{64}$")


class PrinterObservationPayload(_ClosedModel):
    agent_printer_id: str = Field(min_length=1, max_length=160)
    local_printer_fingerprint: str = Field(pattern="^[0-9a-f]{64}$")
    display_name_sanitized: str = Field(min_length=1, max_length=160)
    driver_name_sanitized: str | None = Field(default=None, max_length=160)
    dpi_x: int = Field(ge=0, le=100000)
    dpi_y: int = Field(ge=0, le=100000)
    media_width_mm: float = Field(ge=0, le=5000)
    media_height_mm: float = Field(ge=0, le=5000)
    orientation: str = Field(pattern="^(PORTRAIT|LANDSCAPE)$")
    physical_width_px: int = Field(ge=0, le=1000000)
    physical_height_px: int = Field(ge=0, le=1000000)
    printable_width_px: int = Field(ge=0, le=1000000)
    printable_height_px: int = Field(ge=0, le=1000000)
    offset_x_px: int = Field(ge=0, le=1000000)
    offset_y_px: int = Field(ge=0, le=1000000)
    capability_hash: str = Field(pattern="^[0-9a-f]{64}$")
    observed_at: str = Field(min_length=20, max_length=64)
    availability_state: str = Field(pattern="^(AVAILABLE|UNAVAILABLE|ERROR)$")
    safe_error_code: str | None = Field(default=None, max_length=80)


class PrinterDiscoveryResult(_ClosedModel):
    status: str = Field(pattern="^(COMPLETED|FAILED)$")
    observations: list[PrinterObservationPayload] = Field(default_factory=list, max_length=64)
    safe_error_code: str | None = Field(default=None, max_length=80)


def _machine_principal(request: Request, db: Session):
    if not request.app.state.config.agent_enabled:
        raise AgentAuthError("agent disabled")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise AgentAuthError("machine bearer required")
    raw = auth[7:].strip()
    if not raw:
        raise AgentAuthError("machine bearer required")
    principal = AgentBindingService(db).authenticate(raw, mark_poll=True)
    if principal.legacy or not principal.binding_id:
        raise AgentAuthError("participant-bound machine credential required")
    return principal


def _v2_json(value: dict, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        value,
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


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
        if shutil.disk_usage(temp_root).free < config.report_min_free_disk_bytes:
            raise AgentSecurityError("minimum free disk requirement not met")
        ingress_limit = min(
            config.report_remote_download_byte_ceiling,
            config.report_temp_storage_ceiling_bytes,
            config.report_max_artifact_bytes,
        )
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
                    if total > ingress_limit:
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



@agent_v2_printing_router.post("/encryption-keys/register")
def register_print_encryption_key(
    payload: PrintKeyRegistrationRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    try:
        principal = _machine_principal(request, db)
        row = SensitivePrintingDeliveryService(db, request.app.state.config).register_public_key(
            agent_binding_id=principal.binding_id or "",
            intent_token=payload.intent_token,
            public_key_raw=b64d(payload.public_key),
        )
        return _v2_json({
            "agent_binding_id": row.agent_binding_id,
            "key_version": row.key_version,
            "public_key_fingerprint": row.public_key_fingerprint,
            "algorithm": row.algorithm,
            "state": row.state,
        }, status_code=201)
    except AgentAuthError:
        return _v2_json({"code": "MACHINE_AUTH_REQUIRED"}, status_code=401)
    except SensitiveDeliveryRejected as exc:
        db.commit()
        return _v2_json({"code": exc.code}, status_code=409)
    except ValueError:
        return _v2_json({"code": "PRINT_KEY_REGISTRATION_REJECTED"}, status_code=400)


@agent_v2_printing_router.get("/executions/next")
def next_printing_v2_control(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    try:
        principal = _machine_principal(request, db)
        value = SensitivePrintingDeliveryService(db, request.app.state.config).next_control(
            machine_binding_id=principal.binding_id or "",
        )
        if value is None:
            return Response(status_code=204, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        return _v2_json(value)
    except AgentAuthError:
        return _v2_json({"code": "MACHINE_AUTH_REQUIRED"}, status_code=401)
    except SensitiveDeliveryRejected as exc:
        db.commit()
        return _v2_json({"code": exc.code}, status_code=409)


@agent_v2_printing_router.post("/payload-deliveries/{reservation_id}/issue")
def issue_print_payload(
    reservation_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    try:
        principal = _machine_principal(request, db)
        envelope = SensitivePrintingDeliveryService(db, request.app.state.config).issue(
            reservation_id,
            machine_binding_id=principal.binding_id or "",
        )
        return _v2_json(envelope)
    except AgentAuthError:
        return _v2_json({"code": "MACHINE_AUTH_REQUIRED"}, status_code=401)
    except SensitiveDeliveryRejected as exc:
        db.commit()
        return _v2_json({"code": exc.code}, status_code=409)


@agent_v2_printing_router.post("/payload-deliveries/{reservation_id}/ack")
def acknowledge_print_payload(
    reservation_id: str,
    payload: PrintPayloadAckRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    if payload.delivery_reservation_id != reservation_id:
        return _v2_json({"code": "DELIVERY_ACK_RESERVATION_MISMATCH"}, status_code=400)
    try:
        principal = _machine_principal(request, db)
        value = SensitivePrintingDeliveryService(db, request.app.state.config).acknowledge(
            reservation_id,
            machine_binding_id=principal.binding_id or "",
            payload_sha256=payload.payload_sha256,
            context_sha256=payload.context_sha256,
        )
        return _v2_json(value)
    except AgentAuthError:
        return _v2_json({"code": "MACHINE_AUTH_REQUIRED"}, status_code=401)
    except SensitiveDeliveryRejected as exc:
        db.commit()
        return _v2_json({"code": exc.code}, status_code=409)


@agent_v2_printing_router.get("/printer-discovery/jobs/next")
def next_printer_discovery_job(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    try:
        principal = _machine_principal(request, db)
        value = PrinterProfileService(db, request.app.state.config).fetch_agent_job(
            machine_binding_id=principal.binding_id or "",
        )
        if value is None:
            return Response(status_code=204, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        return _v2_json(value)
    except AgentAuthError:
        return _v2_json({"code": "MACHINE_AUTH_REQUIRED"}, status_code=401)
    except PrinterProfileRejected as exc:
        db.commit()
        return _v2_json({"code": exc.code}, status_code=409)


@agent_v2_printing_router.post("/printer-discovery/jobs/{job_id}/result")
def complete_printer_discovery_job(
    job_id: str,
    payload: PrinterDiscoveryResult,
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    try:
        principal = _machine_principal(request, db)
        service = PrinterProfileService(db, request.app.state.config)
        if payload.status == "FAILED":
            value = service.fail_agent_job(
                job_id=job_id,
                machine_binding_id=principal.binding_id or "",
                safe_error_code=payload.safe_error_code or "PRINTER_DISCOVERY_FAILED",
            )
        else:
            if payload.safe_error_code is not None:
                return _v2_json({"code": "DISCOVERY_COMPLETED_WITH_ERROR_CODE"}, status_code=400)
            value = service.complete_agent_job(
                job_id=job_id,
                machine_binding_id=principal.binding_id or "",
                observations=[item.model_dump() for item in payload.observations],
            )
        return _v2_json(value)
    except AgentAuthError:
        return _v2_json({"code": "MACHINE_AUTH_REQUIRED"}, status_code=401)
    except PrinterProfileRejected as exc:
        db.commit()
        return _v2_json({"code": exc.code}, status_code=409)
    except ValueError:
        return _v2_json({"code": "PRINTER_DISCOVERY_RESULT_REJECTED"}, status_code=400)
