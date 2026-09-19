from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from wbcz.reference_products import lookup_reference_value, reference_categories, reference_entries
from wbcz.windows_agent import AgentJobType, AgentReplayConflict
from wbcz.write_pipeline import InvalidWriteOperation
from wbcz_web.auth import new_csrf_token
from wbcz_web.repositories import ImportRepository
from wbcz_web.services import (
    AuthService,
    AuthenticationError,
    ControlService,
    FileImportService,
    UploadError,
    event_view,
    import_view,
)
from wbcz_web.services.agent_orchestration import AgentControlService
from wbcz_web.services.cis_inventory import CisInventoryService, CisInventoryUnavailable
from wbcz_web.services.reference_products import ReferenceProductsService, ReferenceProductsUnavailable
from wbcz_web.services.document_lifecycle import DocumentLifecycleService, DocumentLifecycleUnavailable
from wbcz_web.services.authorization import Permission
from wbcz_web.services.workspace import (
    BulkActionUnavailable,
    bulk_preview,
    execute_bulk_actions,
    workspace_history,
    workspace_overview,
)

from .dependencies import AuthenticatedIdentity, get_db, require_csrf, require_permission, require_user
from .schemas import (
    BulkActionRequest,
    CisInventoryCisesRequest,
    CisInventoryProductRequest,
    CisInventorySearchRequest,
    CisInventorySingleRequest,
    ControlRequest,
    LoginRequest,
    PreviewRequest,
    ReferenceModValidateRequest,
    ReferenceModsRequest,
    ReferenceParticipantsRequest,
    ReferenceProductGtinRequest,
    ReferenceRdListRequest,
    ReferenceTnVedRequest,
    DocumentListRequest,
    DocumentInfoRequest,
    DocumentCisesRequest,
)

router = APIRouter(prefix="/api")


@router.get("/health")
def health(request: Request) -> dict:
    try:
        with request.app.state.session_factory() as db:
            db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="service unavailable") from exc
    return {"status": "ok", "service": "wbcz-web"}


@router.get("/version")
def version(request: Request) -> dict:
    config = request.app.state.config
    return {"application_version": config.app_version, "build_sha": config.build_sha}


@router.get("/auth/csrf")
def csrf(request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    token = new_csrf_token()
    config = request.app.state.config
    session_token = request.cookies.get(config.session_cookie_name)
    if session_token:
        try:
            _, session = AuthService(db, config).authenticate_token(session_token)
            session.csrf_token_hash = __import__("wbcz_web.auth", fromlist=["token_hash"]).token_hash(token)
            db.flush()
        except AuthenticationError:
            pass
    response.set_cookie(
        config.csrf_cookie_name,
        token,
        httponly=False,
        secure=config.cookie_secure,
        samesite="lax",
        path="/",
        max_age=config.session_ttl_seconds,
    )
    return {"csrf_token": token}


@router.post("/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    _: None = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> dict:
    try:
        config = request.app.state.config
        csrf_token = request.cookies.get(config.csrf_cookie_name)
        auth = AuthService(db, config)
        user, token = auth.login(
            payload.username,
            payload.password,
            csrf_token=csrf_token,
            remote_address=getattr(request.state, "client_ip", None) or (request.client.host if request.client else None),
            user_agent=request.headers.get("user-agent"),
        )
        auth.revoke_presented_session(
            request.cookies.get(config.session_cookie_name),
            reason="login_rotation",
        )
    except AuthenticationError as exc:
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    config = request.app.state.config
    response.set_cookie(
        config.session_cookie_name,
        token,
        httponly=True,
        secure=config.cookie_secure,
        samesite="lax",
        path="/",
        max_age=config.session_ttl_seconds,
    )
    return {"id": user.id, "username": user.username, "is_admin": False}


@router.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    AuthService(db, request.app.state.config).logout(identity.session_id, identity.user_id)
    response.delete_cookie(request.app.state.config.session_cookie_name, path="/")
    return {"ok": True}


@router.get("/me")
def me(identity: AuthenticatedIdentity = Depends(require_user)) -> dict:
    return {
        "id": identity.user_id, "username": identity.username, "is_admin": False, "is_active": True,
        "organisation_id": identity.organisation_id, "participant_id": identity.participant_id,
        "participant_inn": identity.participant_inn, "role": identity.role,
        "permissions": sorted(identity.permissions),
    }


@router.get("/capabilities")
def capabilities(request: Request, _: AuthenticatedIdentity = Depends(require_user)) -> dict:
    config = request.app.state.config
    return {
        "true_api": "windows-agent" if config.agent_enabled else "offline-dry-run",
        "true_api_write": config.true_api_write_enabled,
        "document_signing": False,
        "submission": False,
        "windows_bridge": config.agent_enabled,
        "registration": False,
    }


@router.get("/workspace")
def workspace(_: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_READ)), db: Session = Depends(get_db)) -> dict:
    history = workspace_history(db, limit=10)
    return {
        "active_import_id": history[0]["id"] if history else None,
        "history": history,
    }


@router.post("/files")
async def upload_file(
    request: Request,
    upload: UploadFile = File(..., alias="file"),
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_CREATE)),
    db: Session = Depends(get_db),
) -> dict:
    filename = upload.filename or "upload.xlsx"
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=400, detail="Поддерживаются только файлы .xlsx")
    data = await upload.read(50 * 1024 * 1024 + 1)
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Файл превышает допустимый размер 50 MiB")
    try:
        record = FileImportService(db).import_xlsx(filename, data, identity.user_id)
    except UploadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return import_view(record)


@router.get("/files")
def list_files(identity: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_READ)), db: Session = Depends(get_db)) -> list[dict]:
    return [import_view(row) for row in ImportRepository(db).list_recent()]


@router.get("/files/{import_id}")
def get_file(import_id: str, identity: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_READ)), db: Session = Depends(get_db)) -> dict:
    row = ImportRepository(db).get(import_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Импорт не найден")
    return import_view(row)


@router.get("/files/{import_id}/events")
def file_events(import_id: str, identity: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_READ)), db: Session = Depends(get_db)) -> list[dict]:
    repo = ImportRepository(db)
    if repo.get(import_id) is None:
        raise HTTPException(status_code=404, detail="Импорт не найден")
    return [event_view(db, row, repo.latest_check(row.event_id)) for row in repo.ordered_event_records(import_id)]


@router.get("/files/{import_id}/workspace")
def file_workspace(
    import_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return workspace_overview(db, request.app.state.config, import_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/files/{import_id}/bulk-preview")
def file_bulk_preview(
    import_id: str,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return bulk_preview(db, import_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/files/{import_id}/bulk-actions")
def file_bulk_actions(
    import_id: str,
    payload: BulkActionRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.DOCUMENTS_WRITE)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return execute_bulk_actions(db, request.app.state.config, import_id, identity.user_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except BulkActionUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except InvalidWriteOperation as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/events/{event_id}")
def event_detail(event_id: str, identity: AuthenticatedIdentity = Depends(require_permission(Permission.IMPORTS_READ)), db: Session = Depends(get_db)) -> dict:
    repo = ImportRepository(db)
    row = repo.event(event_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Событие не найдено")
    result = event_view(db, row, repo.latest_check(event_id))
    result["history"] = [event_view(db, item, repo.latest_check(item.event_id)) for item in repo.history_for_kiz(row.kiz)]
    result["history_order_ambiguous"] = repo.history_order_ambiguous(row.kiz)
    return result


@router.post("/files/{import_id}/control")
def control(
    import_id: str,
    payload: ControlRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CONTROL_RUN)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        config = request.app.state.config
        if config.agent_enabled:
            return AgentControlService(db, config).run(import_id, identity.user_id, payload.mode, payload.event_ids)
        return ControlService(db, identity.participant_inn or "").run(import_id, identity.user_id, payload.mode, payload.event_ids)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operation-preview")
def operation_preview(
    payload: PreviewRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CONTROL_RUN)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return ControlService(db, identity.participant_inn or "").preview(payload.import_id, identity.user_id, payload.mode, payload.event_ids)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc



def _cis_inventory_service(request: Request, db: Session) -> CisInventoryService:
    try:
        return CisInventoryService(db, request.app.state.config)
    except CisInventoryUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/cis-inventory/info")
def cis_inventory_info(
    payload: CisInventoryCisesRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return _cis_inventory_service(request, db).queue(AgentJobType.CIS_INFO, {"cises": payload.cises})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cis-inventory/search")
def cis_inventory_search(
    payload: CisInventorySearchRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    body = payload.model_dump(exclude_none=True)
    try:
        return _cis_inventory_service(request, db).queue(AgentJobType.CIS_SEARCH, {"request": body})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cis-inventory/history")
def cis_inventory_history(
    payload: CisInventorySingleRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return _cis_inventory_service(request, db).queue(AgentJobType.CIS_HISTORY, {"cis": payload.cis})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cis-inventory/aggregates")
def cis_inventory_aggregates(
    payload: CisInventoryCisesRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return _cis_inventory_service(request, db).queue(AgentJobType.CIS_AGGREGATED_LIST, {"cises": payload.cises})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cis-inventory/aggregation-history")
def cis_inventory_aggregation_history(
    payload: CisInventorySingleRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return _cis_inventory_service(request, db).queue(AgentJobType.CIS_AGGREGATION_HISTORY, {"cis": payload.cis})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cis-inventory/product-info")
def cis_inventory_product_info(
    payload: CisInventoryProductRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return _cis_inventory_service(request, db).queue(
            AgentJobType.PRODUCT_INFO,
            {"gtins": payload.gtins, "rdInfo": payload.rdInfo},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cis-inventory/enrich")
def cis_inventory_enrich(
    payload: CisInventoryCisesRequest,
    request: Request,
    _: None = Depends(require_csrf),
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return _cis_inventory_service(request, db).queue(AgentJobType.CIS_TO_PRODUCT, {"cises": payload.cises})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/cis-inventory/requests/{request_id}")
def cis_inventory_request_status(
    request_id: str,
    request: Request,
    identity: AuthenticatedIdentity = Depends(require_permission(Permission.CIS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    try:
        return _cis_inventory_service(request, db).status(request_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="M1 request not found") from exc


def _reference_products_service(request: Request, db: Session) -> ReferenceProductsService:
    try:
        return ReferenceProductsService(db, request.app.state.config)
    except ReferenceProductsUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/reference-products/participants")
def reference_participants(payload: ReferenceParticipantsRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).queue(AgentJobType.PARTICIPANTS, {"inns": payload.inns})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reference-products/participants/self")
def reference_self_participant(request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).self_participant()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reference-products/mods/list")
def reference_mods(payload: ReferenceModsRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).queue(AgentJobType.MODS_LIST, payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reference-products/mods/validate-lp")
def reference_validate_lp_mod(payload: ReferenceModValidateRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    body = {"productGroups": ["lp"], "inns": [payload.inn], "limit": 1000, "page": 0}
    if payload.kpp is not None: body["kpp"] = payload.kpp
    if payload.fiasId is not None: body["fiasId"] = payload.fiasId
    try:
        return _reference_products_service(request, db).queue(AgentJobType.MODS_LIST, body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reference-products/tn-ved/search")
def reference_tnved(payload: ReferenceTnVedRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).queue(AgentJobType.TN_VED_SEARCH, payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reference-products/product-info")
def reference_product_info(payload: CisInventoryProductRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).queue(AgentJobType.PRODUCT_INFO, {"gtins": payload.gtins, "rdInfo": payload.rdInfo})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reference-products/product-gtins")
def reference_product_gtins(payload: ReferenceProductGtinRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).queue(AgentJobType.PRODUCT_GTIN_LIST, {"pg": "lp", **payload.model_dump()})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reference-products/regulatory-documents")
def reference_regulatory_documents(payload: ReferenceRdListRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).queue(AgentJobType.RD_LIST, payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/reference-products/requests/{request_id}")
def reference_request_status(request_id: str, request: Request, identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _reference_products_service(request, db).status(request_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="M2 request not found") from exc


@router.get("/reference-products/references")
def reference_registry_categories(identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ))) -> list[dict]:
    return reference_categories()


@router.get("/reference-products/references/{category}")
def reference_registry_entries(category: str, identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ))) -> dict:
    try:
        return reference_entries(category)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="reference category not found") from exc


@router.get("/reference-products/references/{category}/{value}")
def reference_registry_lookup(category: str, value: str, identity: AuthenticatedIdentity = Depends(require_permission(Permission.REFERENCE_READ))) -> dict:
    try:
        return lookup_reference_value(category, value)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="reference category not found") from exc



def _document_lifecycle_service(request: Request, db: Session) -> DocumentLifecycleService:
    try:
        return DocumentLifecycleService(db, request.app.state.config)
    except DocumentLifecycleUnavailable as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/documents/list")
def document_list(payload: DocumentListRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.DOCUMENTS_READ)), db: Session = Depends(get_db)) -> dict:
    body = payload.model_dump(exclude_none=True)
    operation_id = body.pop("operation_id", None)
    try:
        return _document_lifecycle_service(request, db).queue(AgentJobType.DOCUMENT_LIST, body, operation_id=operation_id, user_id=identity.user_id)
    except AgentReplayConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/documents/info")
def document_info(payload: DocumentInfoRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.DOCUMENTS_READ)), db: Session = Depends(get_db)) -> dict:
    body = payload.model_dump(exclude_none=True)
    operation_id = body.pop("operation_id", None)
    try:
        return _document_lifecycle_service(request, db).queue(AgentJobType.DOCUMENT_INFO, body, operation_id=operation_id, user_id=identity.user_id)
    except AgentReplayConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/documents/cises")
def document_cises(payload: DocumentCisesRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_permission(Permission.DOCUMENTS_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _document_lifecycle_service(request, db).queue_cises(
            document_id=payload.document_id,
            write_operation_id=payload.write_operation_id,
            operation_id=payload.operation_id,
            user_id=identity.user_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="write operation not found") from exc
    except AgentReplayConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/documents/requests/{request_id}")
def document_request_status(request_id: str, request: Request, identity: AuthenticatedIdentity = Depends(require_permission(Permission.DOCUMENTS_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _document_lifecycle_service(request, db).status(request_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="M4 request not found") from exc


@router.get("/documents/ledger/{operation_id}")
def document_ledger(operation_id: str, request: Request, identity: AuthenticatedIdentity = Depends(require_permission(Permission.DOCUMENTS_READ)), db: Session = Depends(get_db)) -> dict:
    try:
        return _document_lifecycle_service(request, db).ledger(operation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="M4 operation not found") from exc


@router.get("/documents/registries")
def document_registries(identity: AuthenticatedIdentity = Depends(require_permission(Permission.DOCUMENTS_READ))) -> dict:
    return DocumentLifecycleService.registries()
