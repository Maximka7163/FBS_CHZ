from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from wbcz_web.api.dependencies import AuthenticatedIdentity, get_db, require_csrf, require_permission
from wbcz_web.services.agent_enrollment import AgentEnrollmentService
from wbcz_web.services.authorization import Permission


enrollment_router = APIRouter(prefix="/api", tags=["agent-enrollment"])
manage_integrations = require_permission(Permission.INTEGRATIONS_MANAGE)


class EnrollmentIntentRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    requested_protocol_version: str | None = Field(default=None, max_length=32)


class EnrollmentExchangeRequest(BaseModel):
    enrollment_token: str = Field(min_length=43, max_length=256)
    installation_id: str = Field(min_length=8, max_length=128)
    participant_inn: str = Field(min_length=10, max_length=12)
    protocol_version: str = Field(min_length=3, max_length=32)
    agent_version: str = Field(min_length=1, max_length=64)
    supported_job_types: list[str] = Field(default_factory=list, max_length=100)
    supported_capabilities: list[str] = Field(default_factory=list, max_length=100)


@enrollment_router.post("/agent-enrollment")
def create_enrollment_intent(
    payload: EnrollmentIntentRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    db: Session = Depends(get_db),
) -> dict:
    row, raw = AgentEnrollmentService(db, config=request.app.state.config).create_intent(
        display_name=payload.display_name,
        user_id=identity.user_id,
        requested_protocol_version=payload.requested_protocol_version,
    )
    # Enrollment token is intentionally one-time and shown only here. Permanent
    # machine credentials are never returned by this browser-authorised route.
    return {
        "enrollment_id": row.id,
        "enrollment_token": raw,
        "expires_at": row.expires_at.isoformat(),
        "requested_protocol_version": row.requested_protocol_version,
    }


@enrollment_router.post("/agent/v2/enroll")
def exchange_enrollment_token(
    payload: EnrollmentExchangeRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    if request.app.state.config.environment == "production" and getattr(request.state, "external_scheme", request.url.scheme) != "https":
        raise HTTPException(status_code=400, detail={"code": "HTTPS_REQUIRED", "message": "HTTPS required", "correlation_id": request.state.correlation_id})
    try:
        binding, credential, compatibility = AgentEnrollmentService(
            db, config=request.app.state.config
        ).exchange(
            payload.enrollment_token,
            installation_id=payload.installation_id,
            participant_inn=payload.participant_inn,
            protocol_version=payload.protocol_version,
            agent_version=payload.agent_version,
            supported_job_types=payload.supported_job_types,
            supported_capabilities=payload.supported_capabilities,
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=401,
            detail={"code": "ENROLLMENT_REJECTED", "message": "Enrollment rejected", "correlation_id": request.state.correlation_id},
        ) from exc
    if binding is None or credential is None:
        return {
            "compatibility": compatibility,
            "permanent_credential": None,
            "binding_id": None,
            "protocol_current": request.app.state.config.agent_protocol_current,
            "minimum_agent_version": request.app.state.config.agent_minimum_version,
        }
    # This is the sole permanent-credential delivery response. It is an outbound
    # agent-only exchange and is marked no-store by middleware.
    return {
        "compatibility": compatibility,
        "binding_id": binding.id,
        "permanent_credential": credential,
        "credential_version": binding.credential_version,
        "protocol_current": request.app.state.config.agent_protocol_current,
    }
