from __future__ import annotations
import secrets\nfrom uuid import uuid4
from collections.abc import Callable,Iterator
from dataclasses import dataclass
from fastapi import Depends,Header,HTTPException,Request
from sqlalchemy.orm import Session
from wbcz_web.services import AuthService,AuthenticationError
from wbcz_web.services.authorization import ActiveScope,AuthorizationError,AuthorizationService,Permission,ScopeRequired

def get_db(request:Request)->Iterator[Session]:
 db=request.app.state.session_factory()
 request_id=getattr(request.state,"request_id",None)
 if not request_id:
  request_id="req_"+uuid4().hex
  request.state.request_id=request_id
 correlation_id=getattr(request.state,"correlation_id",None) or request_id
 request.state.correlation_id=correlation_id
 db.info["audit_trace"]={"request_id":request_id,"correlation_id":correlation_id,"causation_id":None}
 config=request.app.state.config
 if getattr(config,"audit_pseudonym_key",None):
  db.info["audit_pseudonym_key"]=config.audit_pseudonym_key.encode("utf-8")
  db.info["audit_pseudonym_key_id"]=config.audit_pseudonym_key_id
 try:yield db;db.commit()
 except Exception:db.rollback();raise
 finally:db.close()

def _session_auth(request:Request,db:Session):
 token=request.cookies.get(request.app.state.config.session_cookie_name)
 return AuthService(db,request.app.state.config).authenticate_token(token)

def require_csrf(request:Request,x_csrf_token:str|None=Header(default=None,alias="X-CSRF-Token"),db:Session=Depends(get_db))->None:
 cookie=request.cookies.get(request.app.state.config.csrf_cookie_name)
 if not cookie or not x_csrf_token or not secrets.compare_digest(cookie,x_csrf_token):
  raise HTTPException(status_code=403,detail="CSRF token is missing or invalid")
 session_token=request.cookies.get(request.app.state.config.session_cookie_name)
 if session_token:
  try:_,session=_session_auth(request,db)
  except AuthenticationError as exc:raise HTTPException(status_code=401,detail="Сессия недействительна") from exc
  if not AuthService(db,request.app.state.config).csrf_matches(session,x_csrf_token):
   raise HTTPException(status_code=403,detail="CSRF token is missing or invalid")

@dataclass(frozen=True,slots=True)
class SessionIdentity:user_id:int;username:str;session_id:str

@dataclass(frozen=True,slots=True)
class AuthenticatedIdentity:
 user_id:int;username:str;session_id:str;organisation_id:str|None;participant_id:str|None
 participant_inn:str|None;role:str|None;permissions:frozenset[str];is_admin:bool=False

def require_session_user(request:Request,db:Session=Depends(get_db))->SessionIdentity:
 try:user,session=_session_auth(request,db);return SessionIdentity(user.id,user.username,session.id)
 except AuthenticationError as exc:raise HTTPException(status_code=401,detail="Требуется авторизация") from exc

def require_user(request:Request,db:Session=Depends(get_db))->AuthenticatedIdentity:
 try:user,session=_session_auth(request,db)
 except AuthenticationError as exc:raise HTTPException(status_code=401,detail="Требуется авторизация") from exc
 scope:ActiveScope|None=None
 try:scope=AuthorizationService(db).resolve_session_scope(user,session,require_participant=False)
 except ScopeRequired:scope=None
 except AuthorizationError as exc:raise HTTPException(status_code=403,detail="Permission denied") from exc
 if user.password_must_change and request.url.path not in {"/api/auth/change-password","/api/auth/logout","/api/me"}:
  raise HTTPException(status_code=403,detail="Password change required")
 return AuthenticatedIdentity(
  user.id,user.username,session.id,
  scope.organisation_id if scope else None,scope.participant_id if scope else None,
  scope.participant_inn if scope else None,scope.role.value if scope else None,
  frozenset(p.value for p in scope.permissions) if scope else frozenset(),False,
 )

def require_permission(permission:Permission,*,participant_required:bool=True)->Callable:
 def dependency(identity:AuthenticatedIdentity=Depends(require_user))->AuthenticatedIdentity:
  if permission.value not in identity.permissions:
   raise HTTPException(status_code=403,detail="Permission denied")
  if participant_required and (not identity.organisation_id or not identity.participant_id or not identity.participant_inn):
   raise HTTPException(status_code=403,detail="Active organisation/participant scope required")
  return identity
 return dependency
