from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from wbcz.printing import PrintingContractError, PrintingSecurityError
from wbcz.printing_agent import FakePrintExecutor, PrintAgentContractError
from wbcz_web.api.dependencies import AuthenticatedIdentity, get_db, require_csrf, require_permission
from wbcz_web.services.authorization import Permission
from wbcz_web.services.printing import LocalPrintingService, PrintingIntegrityError, PrintingUnavailable


printing_router = APIRouter(prefix="/api/printing", tags=["printing"])


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrintabilityRequest(ClosedModel):
    cis: str = Field(min_length=1, max_length=512)


class TemplateCreateRequest(ClosedModel):
    name: str = Field(min_length=1, max_length=160)
    label_width_mm: float
    label_height_mm: float
    layout: dict[str, Any]
    participant_scope: str = "PARTICIPANT"


class TemplateVersionRequest(ClosedModel):
    label_width_mm: float
    label_height_mm: float
    layout: dict[str, Any]


class TemplatePreviewRequest(ClosedModel):
    dpi: int = Field(default=300, ge=150, le=1200)


class PrintJobCreateRequest(ClosedModel):
    stored_item_ids: list[str] = Field(min_length=1, max_length=1000)
    template_version_id: str
    mode: str = "INITIAL_PRINT"
    printer_profile_id: str | None = Field(default=None, max_length=128)


class ReprintRequest(ClosedModel):
    original_print_event_id: str
    use_current_template: bool = False


def _service(request: Request, db: Session) -> LocalPrintingService:
    return LocalPrintingService(db, request.app.state.config)


def _safe_error(exc: Exception, *, not_found: bool = False) -> HTTPException:
    if not_found:
        return HTTPException(status_code=404, detail="printing object not found")
    if isinstance(exc, (PrintingUnavailable, PrintingIntegrityError)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (PrintingContractError, PrintingSecurityError, ValueError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=400, detail="printing request rejected")


@printing_router.post("/printability/resolve")
def resolve_printability(
    payload: PrintabilityRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _service(request, db).resolve_printability_public(payload.cis)


@printing_router.get("/templates")
def list_templates(
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return _service(request, db).list_templates()


@printing_router.post("/templates")
def create_template(
    payload: TemplateCreateRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_TEMPLATES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    organisation_wide = payload.participant_scope == "ORGANISATION"
    if payload.participant_scope not in {"PARTICIPANT", "ORGANISATION"}:
        raise HTTPException(status_code=400, detail="participant_scope must be PARTICIPANT or ORGANISATION")
    if organisation_wide and identity.role not in {"ADMIN", "OWNER"}:
        raise HTTPException(status_code=403, detail="Permission denied")
    try:
        row = _service(request, db).create_template(
            name=payload.name,
            label_width_mm=payload.label_width_mm,
            label_height_mm=payload.label_height_mm,
            layout=payload.layout,
            user_id=identity.user_id,
            organisation_wide=organisation_wide,
        )
        return {"id": row.id, "state": row.state, "current_version_id": row.current_version_id}
    except Exception as exc:
        if isinstance(exc, (PrintingUnavailable, PrintingIntegrityError, PrintingContractError, PrintingSecurityError, ValueError)):
            raise _safe_error(exc) from exc
        raise


@printing_router.get("/templates/{template_id}")
def template_detail(
    template_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).template_detail(template_id)
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc


@printing_router.post("/templates/{template_id}/versions")
def create_template_version(
    template_id: str,
    payload: TemplateVersionRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_TEMPLATES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = _service(request, db).create_template_version(
            template_id,
            label_width_mm=payload.label_width_mm,
            label_height_mm=payload.label_height_mm,
            layout=payload.layout,
            user_id=identity.user_id,
        )
        return {
            "id": row.id,
            "template_id": row.template_id,
            "version_number": row.version_number,
            "layout_sha256": row.layout_sha256,
        }
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrintingUnavailable, PrintingContractError, PrintingSecurityError, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.post("/templates/{template_id}/archive")
def archive_template(
    template_id: str,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_TEMPLATES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = _service(request, db).archive_template(template_id, user_id=identity.user_id)
        return {"id": row.id, "state": row.state, "archived_at": row.archived_at.isoformat() if row.archived_at else None}
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc


@printing_router.post("/template-versions/{version_id}/preview")
def preview_template(
    version_id: str,
    payload: TemplatePreviewRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).preview(version_id, dpi=payload.dpi)
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrintingContractError, PrintingSecurityError, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.get("/jobs")
def list_jobs(
    request: Request,
    limit: int = 100,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    try:
        return _service(request, db).list_jobs(limit=limit)
    except ValueError as exc:
        raise _safe_error(exc) from exc


@printing_router.post("/jobs")
def create_print_job(
    payload: PrintJobCreateRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_EXECUTE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = _service(request, db).create_print_job(
            stored_item_ids=payload.stored_item_ids,
            template_version_id=payload.template_version_id,
            user_id=identity.user_id,
            mode=payload.mode,
            printer_profile_id=payload.printer_profile_id,
        )
        return {"id": row.id, "state": row.state, "mode": row.mode, "item_count": row.item_count}
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrintingUnavailable, PrintingIntegrityError, PrintingContractError, PrintingSecurityError, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.get("/jobs/{job_id}")
def print_job_detail(
    job_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).job_detail(job_id)
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc


@printing_router.post("/jobs/reprint")
def reprint(
    payload: ReprintRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_EXECUTE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = _service(request, db).reprint(
            payload.original_print_event_id,
            user_id=identity.user_id,
            use_current_template=payload.use_current_template,
        )
        return {"id": row.id, "state": row.state, "mode": row.mode, "template_version_id": row.template_version_id}
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrintingUnavailable, PrintingIntegrityError, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.get("/jobs/{job_id}/agent-contract")
def print_agent_contract(
    job_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_EXECUTE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        contract = _service(request, db).agent_contract(job_id)
        # Validate the exact browser-visible/control DTO through the same closed
        # parser used by the fake Windows executor. It contains IDs/hashes only.
        FakePrintExecutor().execute(contract)
        return contract
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrintAgentContractError, PrintingUnavailable) as exc:
        raise _safe_error(exc) from exc
