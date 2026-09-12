from __future__ import annotations
from fastapi import APIRouter,Depends,File,HTTPException,Request,Response,UploadFile,status
from sqlalchemy.orm import Session
from wbcz_web.auth import new_csrf_token
from wbcz_web.repositories import ImportRepository
from wbcz_web.services import AuthService,AuthenticationError,ControlService,FileImportService,UploadError,event_view,import_view
from .dependencies import AuthenticatedIdentity,get_db,require_csrf,require_user
from .schemas import ControlRequest,LoginRequest,PreviewRequest
router=APIRouter(prefix="/api")
@router.get("/health")
def health()->dict:return {"status":"ok","service":"wbcz-web","version":"0.5"}
@router.get("/auth/csrf")
def csrf(request:Request,response:Response)->dict:
 token=new_csrf_token();c=request.app.state.config;response.set_cookie(c.csrf_cookie_name,token,httponly=False,secure=c.cookie_secure,samesite="lax",path="/",max_age=c.session_ttl_seconds);return {"csrf_token":token}
@router.post("/auth/login")
def login(payload:LoginRequest,request:Request,response:Response,_:None=Depends(require_csrf),db:Session=Depends(get_db))->dict:
 try:user,token=AuthService(db,request.app.state.config).login(payload.username,payload.password)
 except AuthenticationError as exc:raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail=str(exc)) from exc
 c=request.app.state.config;response.set_cookie(c.session_cookie_name,token,httponly=True,secure=c.cookie_secure,samesite="lax",path="/",max_age=c.session_ttl_seconds);return {"id":user.id,"username":user.username,"is_admin":user.is_admin}
@router.post("/auth/logout")
def logout(request:Request,response:Response,_:None=Depends(require_csrf),identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->dict:
 AuthService(db,request.app.state.config).logout(identity.session_id,identity.user_id);response.delete_cookie(request.app.state.config.session_cookie_name,path="/");return {"ok":True}
@router.get("/me")
def me(identity:AuthenticatedIdentity=Depends(require_user))->dict:return {"id":identity.user_id,"username":identity.username,"is_admin":identity.is_admin,"is_active":True}
@router.get("/capabilities")
def capabilities(_:AuthenticatedIdentity=Depends(require_user))->dict:return {"true_api":"mock","true_api_write":False,"document_signing":False,"submission":False,"windows_bridge":False,"registration":False}
@router.post("/files")
async def upload_file(request:Request,upload:UploadFile=File(...,alias="file"),_:None=Depends(require_csrf),identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->dict:
 filename=upload.filename or "upload.xlsx"
 if not filename.lower().endswith(".xlsx"):raise HTTPException(status_code=400,detail="Поддерживаются только файлы .xlsx")
 data=await upload.read(50*1024*1024+1)
 if len(data)>50*1024*1024:raise HTTPException(status_code=413,detail="Файл превышает допустимый размер 50 MiB")
 try:record=FileImportService(db).import_xlsx(filename,data,identity.user_id)
 except UploadError as exc:raise HTTPException(status_code=400,detail=str(exc)) from exc
 return import_view(record)
@router.get("/files")
def list_files(identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->list[dict]:return [import_view(x) for x in ImportRepository(db).list_recent()]
@router.get("/files/{import_id}")
def get_file(import_id:str,identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->dict:
 row=ImportRepository(db).get(import_id)
 if row is None:raise HTTPException(status_code=404,detail="Импорт не найден")
 return import_view(row)
@router.get("/files/{import_id}/events")
def file_events(import_id:str,identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->list[dict]:
 repo=ImportRepository(db)
 if repo.get(import_id) is None:raise HTTPException(status_code=404,detail="Импорт не найден")
 return [event_view(db,row,repo.latest_check(row.event_id)) for row in repo.ordered_event_records(import_id)]
@router.get("/events/{event_id}")
def event_detail(event_id:str,identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->dict:
 repo=ImportRepository(db);row=repo.event(event_id)
 if row is None:raise HTTPException(status_code=404,detail="Событие не найдено")
 result=event_view(db,row,repo.latest_check(event_id));result["history"]=[event_view(db,x,repo.latest_check(x.event_id)) for x in repo.history_for_kiz(row.kiz)];result["history_order_ambiguous"]=repo.history_order_ambiguous(row.kiz);return result
@router.post("/files/{import_id}/control")
def control(import_id:str,payload:ControlRequest,request:Request,_:None=Depends(require_csrf),identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->dict:
 try:return ControlService(db,request.app.state.config.own_inn).run(import_id,identity.user_id,payload.mode,payload.event_ids)
 except KeyError as exc:raise HTTPException(status_code=404,detail=str(exc)) from exc
 except ValueError as exc:raise HTTPException(status_code=400,detail=str(exc)) from exc
@router.post("/operation-preview")
def operation_preview(payload:PreviewRequest,request:Request,_:None=Depends(require_csrf),identity:AuthenticatedIdentity=Depends(require_user),db:Session=Depends(get_db))->dict:
 try:return ControlService(db,request.app.state.config.own_inn).preview(payload.import_id,identity.user_id,payload.mode,payload.event_ids)
 except (KeyError,ValueError) as exc:raise HTTPException(status_code=400,detail=str(exc)) from exc
