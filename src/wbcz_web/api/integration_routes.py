from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from wbcz.windows_agent import AgentAuthError
from wbcz_web.models import IntegrationHealthCheckRecord
from wbcz_web.services.agent_bindings import AgentBindingService
from wbcz_web.services.authorization import Permission
from wbcz_web.services.integration_secrets import (
    SecretProviderAtomicRotationUnsupported, SecretProviderError,
    SecretProviderWriteUnavailable,
)
from wbcz_web.services.integration_settings import (
    IntegrationCheckBlocked, IntegrationNotFound, IntegrationSettingsError,
    IntegrationSettingsService,
)
from .dependencies import (
    AuthenticatedIdentity, get_db, require_csrf, require_permission,
)


integrations_router = APIRouter(prefix="/api")

read_integrations = require_permission(Permission.INTEGRATIONS_READ)
manage_integrations = require_permission(Permission.INTEGRATIONS_MANAGE)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TrueApiCreate(Strict):
    environment: Literal["PRODUCTION"] = "PRODUCTION"
    primary_agent_binding_id: str | None = Field(default=None, min_length=1, max_length=36)


class WbCreate(Strict):
    display_name: str = Field(default="Wildberries", min_length=1, max_length=200)
    environment: Literal["PRODUCTION","SANDBOX"] = "PRODUCTION"
    token_type: str = Field(default="PERSONAL", min_length=1, max_length=32)
    token_categories: list[str] = Field(default_factory=lambda:["ANY"], max_length=16)
    token_scopes: list[str] = Field(default_factory=list, max_length=64)
    rate_profile: str | None = Field(default=None, max_length=64)


class OzonCreate(Strict):
    display_name: str = Field(default="Ozon", min_length=1, max_length=200)
    environment: Literal["PRODUCTION"] = "PRODUCTION"
    client_id: str = Field(min_length=1, max_length=256)


class SuzCreate(Strict):
    display_name: str = Field(default="SUZ", min_length=1, max_length=200)
    environment: Literal["PRODUCTION"] = "PRODUCTION"
    oms_id: str = Field(min_length=1, max_length=512)
    oms_connection: str = Field(min_length=1, max_length=512)
    installation_name: str = Field(default="Windows Agent", min_length=1, max_length=200)


class ConnectionPatch(Strict):
    display_name: str | None = Field(default=None, max_length=200)
    rate_profile: str | None = Field(default=None, max_length=64)


class SecretInput(Strict):
    value: str = Field(min_length=1, max_length=16384)


class AgentBindingCreate(Strict):
    installation_id: str | None = Field(default=None, min_length=36, max_length=36)
    display_name: str = Field(default="Windows Agent", min_length=1, max_length=200)
    protocol_version: str = Field(default="m14-v1", min_length=1, max_length=32)
    agent_version: str | None = Field(default=None, max_length=64)
    activate: bool = True
    primary: bool = True


class CertificateSelection(Strict):
    thumbprint: str = Field(min_length=32, max_length=200)


def _service(request: Request, db: Session) -> IntegrationSettingsService:
    return IntegrationSettingsService(
        db,
        request.app.state.config,
        secret_provider=request.app.state.integration_secret_provider,
        wb_http_adapter=getattr(request.app.state, "wb_http_adapter", None),
    )


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail="Integration object not found")


def _handle_error(exc: Exception) -> HTTPException:
    if isinstance(exc, (IntegrationNotFound, KeyError)):
        return _not_found()
    if isinstance(exc, IntegrationCheckBlocked):
        code = str(exc)
        status = 409 if code == "CHECK_IN_PROGRESS" else 429 if code == "RATE_LIMITED" else 400
        return HTTPException(status_code=status, detail=code)
    if isinstance(exc, SecretProviderWriteUnavailable):
        return HTTPException(status_code=503, detail="SECRET_PROVIDER_WRITE_UNAVAILABLE")
    if isinstance(exc, SecretProviderAtomicRotationUnsupported):
        return HTTPException(status_code=409, detail="SECRET_PROVIDER_ATOMIC_ROTATION_UNSUPPORTED")
    if isinstance(exc, SecretProviderError):
        return HTTPException(status_code=503, detail="SECRET_PROVIDER_UNAVAILABLE")
    return HTTPException(status_code=400, detail="Integration request rejected")


def _https_secret_boundary(request: Request) -> None:
    config = request.app.state.config
    if config.environment == "production" and request.url.scheme != "https":
        raise HTTPException(status_code=400, detail="HTTPS required for credential management")


@integrations_router.get("/integrations")
def list_integrations(
    request: Request,
    identity: AuthenticatedIdentity = Depends(read_integrations),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    return {
        "items": _service(request, db).list_connections(),
        "derived": {
            "edo": {
                "type":"edo",
                "secret_root":False,
                "EDO_READ":"DERIVED_FROM_TRUE_API_AGENT_CERTIFICATE",
                "EDO_XML_WRITE":"BLOCKED_CONTRACT",
                "blocker_code":"M7_OFFICIAL_XSD_NOT_PINNED",
            }
        },
    }


@integrations_router.get("/integrations/{integration_type}/{connection_id}")
def get_integration(
    integration_type: str,
    connection_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(read_integrations),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    try:
        service = _service(request, db)
        row = service._get(integration_type, connection_id)
        return service.dto(integration_type, row)
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.post("/integrations/true-api")
def create_true_api(
    payload: TrueApiCreate,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).create_true_api(
            environment=payload.environment,
            primary_agent_binding_id=payload.primary_agent_binding_id,
            user_id=identity.user_id,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.post("/integrations/wb")
def create_wb(
    payload: WbCreate,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).create_wb(payload.model_dump(), user_id=identity.user_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.post("/integrations/ozon")
def create_ozon(
    payload: OzonCreate,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).create_ozon(payload.model_dump(), user_id=identity.user_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.post("/integrations/suz")
def create_suz(
    payload: SuzCreate,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).create_suz(payload.model_dump(), user_id=identity.user_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.patch("/integrations/{integration_type}/{connection_id}")
def patch_integration(
    integration_type: str,
    connection_id: str,
    payload: ConnectionPatch,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    changes = {k:v for k,v in payload.model_dump().items() if v is not None}
    try:
        return _service(request, db).update_connection(
            integration_type, connection_id, changes, user_id=identity.user_id
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.post("/integrations/{integration_type}/{connection_id}/secret")
def set_secret(
    integration_type: str,
    connection_id: str,
    payload: SecretInput,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _https_secret_boundary(request)
    if integration_type not in {"wb","ozon"}:
        raise HTTPException(status_code=400, detail="Credential input is allowed only for WB/Ozon")
    try:
        return _service(request, db).set_secret(
            integration_type, connection_id, payload.value, user_id=identity.user_id
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.post("/integrations/{integration_type}/{connection_id}/check")
def check_integration(
    integration_type: str,
    connection_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).check(
            integration_type, connection_id, user_id=identity.user_id
        )
    except Exception as exc:
        raise _handle_error(exc) from None


def _lifecycle(
    action: str,
    integration_type: str,
    connection_id: str,
    request: Request,
    identity: AuthenticatedIdentity,
    db: Session,
) -> dict[str, Any]:
    try:
        return _service(request, db).lifecycle(
            integration_type, connection_id, action, user_id=identity.user_id
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.post("/integrations/{integration_type}/{connection_id}/enable")
def enable_integration(
    integration_type: str, connection_id: str, request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf), db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _lifecycle("enable", integration_type, connection_id, request, identity, db)


@integrations_router.post("/integrations/{integration_type}/{connection_id}/disable")
def disable_integration(
    integration_type: str, connection_id: str, request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf), db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _lifecycle("disable", integration_type, connection_id, request, identity, db)


@integrations_router.post("/integrations/{integration_type}/{connection_id}/archive")
def archive_integration(
    integration_type: str, connection_id: str, request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf), db: Session = Depends(get_db),
) -> dict[str, Any]:
    return _lifecycle("archive", integration_type, connection_id, request, identity, db)


@integrations_router.get("/integrations/{integration_type}/{connection_id}/health")
def integration_health(
    integration_type: str, connection_id: str, request: Request,
    identity: AuthenticatedIdentity = Depends(read_integrations),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    try:
        return _service(request, db).health(integration_type, connection_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.get("/integration-health/{check_id}")
def health_by_id(
    check_id: str, request: Request,
    identity: AuthenticatedIdentity = Depends(read_integrations),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    try:
        return _service(request, db).health_by_id(check_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@integrations_router.get("/environment-capabilities")
def environment_capabilities(
    request: Request,
    identity: AuthenticatedIdentity = Depends(read_integrations),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    return _service(request, db).environment_capabilities()


@integrations_router.get("/agent/status")
def agent_status(
    request: Request,
    identity: AuthenticatedIdentity = Depends(read_integrations),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    return _service(request, db).agent_status()


@integrations_router.post("/agent/bindings")
def create_agent_binding(
    payload: AgentBindingCreate,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if payload.installation_id is not None:
        try:
            UUID(payload.installation_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="installation_id must be UUID") from None
    try:
        row, raw = AgentBindingService(db).create(
            installation_id=payload.installation_id,
            display_name=payload.display_name,
            protocol_version=payload.protocol_version,
            agent_version=payload.agent_version,
            activate=payload.activate,
            primary=payload.primary,
            user_id=identity.user_id,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Agent binding request rejected") from None
    # The raw credential is provisioned exactly once and is never persisted.
    return {
        "binding": AgentBindingService(db).status(row),
        "credential": raw,
        "credential_returned_once": True,
    }


@integrations_router.post("/agent/bindings/{binding_id}/rotate-credential")
def rotate_agent_credential(
    binding_id: str,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row, raw = AgentBindingService(db).rotate_credential(binding_id, user_id=identity.user_id)
    except KeyError:
        raise _not_found() from None
    except Exception:
        raise HTTPException(status_code=400, detail="Agent credential rotation rejected") from None
    return {
        "binding": AgentBindingService(db).status(row),
        "credential": raw,
        "credential_returned_once": True,
    }


@integrations_router.post("/agent/bindings/{binding_id}/disable")
def disable_agent_binding(
    binding_id: str,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = AgentBindingService(db).disable(binding_id, user_id=identity.user_id)
        return {"binding": AgentBindingService(db).status(row)}
    except KeyError:
        raise _not_found() from None
    except Exception:
        raise HTTPException(status_code=400, detail="Agent binding disable rejected") from None


@integrations_router.get("/certificate/status")
def certificate_status(
    request: Request,
    identity: AuthenticatedIdentity = Depends(read_integrations),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del identity
    return _service(request, db).certificate_status()


@integrations_router.post("/integrations/true-api/{connection_id}/certificate-selection")
def certificate_selection(
    connection_id: str,
    payload: CertificateSelection,
    request: Request,
    identity: AuthenticatedIdentity = Depends(manage_integrations),
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return _service(request, db).select_certificate(
            connection_id, payload.thumbprint, user_id=identity.user_id
        )
    except Exception as exc:
        raise _handle_error(exc) from None
