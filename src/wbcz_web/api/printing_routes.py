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
from wbcz_web.services.printing_sensitive_delivery import (
    SensitiveDeliveryRejected,
    SensitivePrintingDeliveryService,
)
from wbcz_web.services.printer_profiles import PrinterProfileRejected, PrinterProfileService


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
    cis_values: list[str] = Field(min_length=1, max_length=1000)
    template_version_id: str
    mode: str = "INITIAL_PRINT"
    printer_profile_id: str | None = Field(default=None, max_length=128)


class ReprintRequest(ClosedModel):
    original_print_event_id: str
    use_current_template: bool = False


class PrintKeyIntentRequest(ClosedModel):
    purpose: str = Field(pattern="^(FIRST_REGISTRATION|ROTATE|REPLACE_LOST)$")


class SensitiveDeliveryAuthorizationRequest(ClosedModel):
    print_job_item_id: str = Field(min_length=1, max_length=64)
    agent_binding_id: str | None = Field(default=None, max_length=64)


class PrinterDiscoveryRequest(ClosedModel):
    agent_binding_id: str = Field(min_length=1, max_length=64)


class PrinterCompatibilityRequest(ClosedModel):
    template_version_id: str = Field(min_length=1, max_length=64)


def _service(request: Request, db: Session) -> LocalPrintingService:
    return LocalPrintingService(db, request.app.state.config)


def _safe_error(exc: Exception, *, not_found: bool = False) -> HTTPException:
    if not_found:
        return HTTPException(status_code=404, detail="printing object not found")
    if isinstance(exc, (PrintingUnavailable, PrintingIntegrityError, SensitiveDeliveryRejected, PrinterProfileRejected)):
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
        row = _service(request, db).create_print_job_for_cis(
            cis_values=payload.cis_values,
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



@printing_router.post("/agent-bindings/{binding_id}/encryption-key-intents")
def create_print_encryption_key_intent(
    binding_id: str,
    payload: PrintKeyIntentRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.INTEGRATIONS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row, raw = SensitivePrintingDeliveryService(db, request.app.state.config).create_key_intent(
            binding_id,
            purpose=payload.purpose,
            user_id=identity.user_id,
        )
        return {
            "intent_id": row.id,
            "intent_token": raw,
            "purpose": row.purpose,
            "expires_at": row.expires_at.isoformat(),
            "agent_binding_id": row.agent_binding_id,
        }
    except (SensitiveDeliveryRejected, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.post("/jobs/{job_id}/payload-delivery-authorizations")
def authorize_sensitive_payload_delivery(
    job_id: str,
    payload: SensitiveDeliveryAuthorizationRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_EXECUTE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        execution, reservation = SensitivePrintingDeliveryService(
            db, request.app.state.config
        ).authorize_delivery(
            print_job_id=job_id,
            print_job_item_id=payload.print_job_item_id,
            agent_binding_id=payload.agent_binding_id,
            user_id=identity.user_id,
        )
        return {
            "print_execution_id": execution.id,
            "delivery_reservation_id": reservation.id,
            "state": execution.state,
            "payload_sha256": execution.payload_sha256,
            "layout_sha256": execution.layout_sha256,
            "agent_binding_id": execution.agent_binding_id,
            "expires_at": reservation.expires_at.isoformat(),
            "max_issue_count": reservation.max_issue_count,
            "print_protocol_version": execution.print_protocol_version,
        }
    except (SensitiveDeliveryRejected, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.get("/printer-profiles")
def list_printer_profiles(
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    del identity
    return PrinterProfileService(db, request.app.state.config).list_profiles()


@printing_router.get("/printer-profiles/{profile_id}")
def printer_profile_detail(
    profile_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    try:
        return PrinterProfileService(db, request.app.state.config).profile_detail(profile_id)
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc


@printing_router.post("/printer-discoveries")
def request_printer_discovery(
    payload: PrinterDiscoveryRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_TEMPLATES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = PrinterProfileService(db, request.app.state.config).request_discovery(
            agent_binding_id=payload.agent_binding_id,
            user_id=identity.user_id,
        )
        return {
            "id": row.id,
            "agent_binding_id": row.agent_binding_id,
            "state": row.state,
            "requested_at": row.requested_at.isoformat(),
        }
    except (PrinterProfileRejected, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.get("/printer-discoveries/{run_id}")
def printer_discovery_status(
    run_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    try:
        return PrinterProfileService(db, request.app.state.config).discovery_status(run_id)
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc


@printing_router.post("/printer-discoveries/{run_id}/observations/{observation_id}/approve")
def approve_printer_observation(
    run_id: str,
    observation_id: str,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_TEMPLATES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        service = PrinterProfileService(db, request.app.state.config)
        status = service.discovery_status(run_id)
        if not any(item["id"] == observation_id for item in status["observations"]):
            raise KeyError(observation_id)
        row = service.approve_observation(observation_id, user_id=identity.user_id)
        return service.profile_detail(row.id)
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrinterProfileRejected, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.post("/printer-profiles/{profile_id}/disable")
def disable_printer_profile(
    profile_id: str,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_TEMPLATES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        service = PrinterProfileService(db, request.app.state.config)
        row = service.disable_profile(profile_id, user_id=identity.user_id)
        return service.profile_detail(row.id)
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrinterProfileRejected, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.post("/printer-profiles/{profile_id}/refresh")
def refresh_printer_profile(
    profile_id: str,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_TEMPLATES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = PrinterProfileService(db, request.app.state.config).refresh_profile(
            profile_id, user_id=identity.user_id
        )
        return {"id": row.id, "agent_binding_id": row.agent_binding_id, "state": row.state}
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrinterProfileRejected, ValueError) as exc:
        raise _safe_error(exc) from exc


@printing_router.post("/printer-profiles/{profile_id}/compatibility")
def printer_profile_compatibility(
    profile_id: str,
    payload: PrinterCompatibilityRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.PRINT_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    try:
        return PrinterProfileService(db, request.app.state.config).compatibility(
            profile_id, payload.template_version_id
        )
    except KeyError as exc:
        raise _safe_error(exc, not_found=True) from exc
    except (PrinterProfileRejected, PrintingContractError, PrintingSecurityError, ValueError) as exc:
        raise _safe_error(exc) from exc
