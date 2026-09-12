from __future__ import annotations
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from fastapi import Depends,Header,HTTPException,Request,status
from sqlalchemy.orm import Session
from wbcz_web.services import AuthService,AuthenticationError

def get_db(request:Request)->Iterator[Session]:
 db=request.app.state.session_factory()
 try:yield db;db.commit()
 except Exception:db.rollback();raise
 finally:db.close()
def require_csrf(request:Request,x_csrf_token:str|None=Header(default=None,alias="X-CSRF-Token"))->None:
 cookie=request.cookies.get(request.app.state.config.csrf_cookie_name)
 if not cookie or not x_csrf_token or not secrets.compare_digest(cookie,x_csrf_token):raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="CSRF token is missing or invalid")
@dataclass(frozen=True,slots=True)
class AuthenticatedIdentity:user_id:int;username:str;is_admin:bool;session_id:str
def require_user(request:Request,db:Session=Depends(get_db))->AuthenticatedIdentity:
 token=request.cookies.get(request.app.state.config.session_cookie_name)
 try:
  user,session=AuthService(db,request.app.state.config).authenticate_token(token);return AuthenticatedIdentity(user.id,user.username,user.is_admin,session.id)
 except AuthenticationError as exc:raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail=str(exc)) from exc
