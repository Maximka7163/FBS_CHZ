from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from wbcz.models import KiState
from wbcz_web.api.dependencies import (
    AuthenticatedIdentity,
    get_db,
    require_csrf,
    require_permission,
)
from wbcz_web.api.schemas import CisInventoryCisesRequest, ControlRequest
from wbcz_web.services.authorization import Permission

from .bridge import LocalTrueApiReadBridge, LocalTrueApiUnavailable
from .control import LocalTrueApiControlService


local_router = APIRouter(prefix="/api")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BrowserAuthCompleteRequest(_Strict):
    attempt_id: str = Field(min_length=16, max_length=256)
    signature_base64: str = Field(min_length=16, max_length=262144)
    selected_certificate_thumbprint: str = Field(min_length=16, max_length=160)


def _bridge(request: Request) -> LocalTrueApiReadBridge:
    bridge = getattr(request.app.state, "local_true_api_bridge", None)
    if not isinstance(bridge, LocalTrueApiReadBridge):
        raise HTTPException(
            status_code=503,
            detail={"code": "LOCAL_TRUE_API_BRIDGE_UNAVAILABLE"},
        )
    return bridge


def _handle(exc: LocalTrueApiUnavailable) -> HTTPException:
    status = 409 if exc.code in {
        "CERTIFICATE_SELECTION_REQUIRED",
        "TRUE_API_AUTH_REQUIRED",
        "CERTIFICATE_NOT_ELIGIBLE",
        "CERTIFICATE_NOT_FOUND",
        "AUTH_ATTEMPT_INVALID",
        "AUTH_ATTEMPT_MISMATCH",
    } else 503
    return HTTPException(
        status_code=status,
        detail={"code": exc.code, "message": str(exc)},
    )


@local_router.get("/local/true-api/status")
def true_api_status(
    request: Request,
    identity: AuthenticatedIdentity = Depends(
        require_permission(Permission.CIS_READ)
    ),
) -> dict[str, Any]:
    return _bridge(request).status(identity.participant_inn or "")


@local_router.post("/local/auth/prepare")
def prepare_browser_auth(
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(
        require_permission(Permission.CIS_READ)
    ),
) -> dict[str, Any]:
    try:
        return _bridge(request).prepare_auth(
            identity.participant_inn or "",
            identity.session_id,
        )
    except LocalTrueApiUnavailable as exc:
        raise _handle(exc) from exc


@local_router.post("/local/auth/complete")
def complete_browser_auth(
    payload: BrowserAuthCompleteRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(
        require_permission(Permission.CIS_READ)
    ),
) -> dict[str, Any]:
    try:
        return _bridge(request).complete_auth(
            identity.participant_inn or "",
            identity.session_id,
            attempt_id=payload.attempt_id,
            signature_base64=payload.signature_base64,
            selected_certificate_thumbprint=payload.selected_certificate_thumbprint,
        )
    except LocalTrueApiUnavailable as exc:
        raise _handle(exc) from exc


def _state_payload(requested_cis: str, value: KiState | Exception | None) -> dict:
    if isinstance(value, KiState):
        return {
            "requested_cis": requested_cis,
            "normalized": {
                "requested_cis": requested_cis,
                "cis": requested_cis,
                "gtin": None,
                "product_name": None,
                "product_group": value.productGroup,
                "owner_inn": value.ownerInn,
                "owner_name": None,
                "status": value.status,
                "status_ex": value.statusEx,
                "withdraw_reason": value.withdrawReason,
            },
            "item_error": None,
        }
    return {
        "requested_cis": requested_cis,
        "normalized": None,
        "item_error": {
            "code": "CIS_INFO_ITEM_FAILED",
            "message": type(value).__name__ if isinstance(value, Exception) else "Missing result",
        },
    }


@local_router.post("/local/true-api/cises-info")
def cises_info(
    payload: CisInventoryCisesRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(
        require_permission(Permission.CIS_READ)
    ),
) -> dict[str, Any]:
    try:
        values = _bridge(request).read_states(
            identity.participant_inn or "", payload.cises
        )
    except LocalTrueApiUnavailable as exc:
        raise _handle(exc) from exc
    return {
        "status": "completed",
        "source": "local-cryptopro-true-api",
        "items": [
            _state_payload(cis, values.get(cis))
            for cis in payload.cises
        ],
    }


@local_router.post("/files/{import_id}/control")
def control(
    import_id: str,
    payload: ControlRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(
        require_permission(Permission.CONTROL_RUN)
    ),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return LocalTrueApiControlService(db, _bridge(request)).run(
            import_id,
            identity.user_id,
            payload.mode,
            payload.event_ids,
        )
    except LocalTrueApiUnavailable as exc:
        raise _handle(exc) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
