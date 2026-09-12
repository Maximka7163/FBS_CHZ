from __future__ import annotations
from datetime import datetime,timedelta,timezone
from sqlalchemy.orm import Session
from wbcz_web.auth import new_session_token,token_hash,verify_password
from wbcz_web.config import WebConfig
from wbcz_web.models import SessionRecord,User
from wbcz_web.repositories import AuditRepository,SessionRepository,UserRepository
class AuthenticationError(ValueError):pass
class AuthService:
 def __init__(self,db:Session,config:WebConfig)->None:self.db=db;self.config=config;self.users=UserRepository(db);self.sessions=SessionRepository(db);self.audit=AuditRepository(db)
 def login(self,username:str,password:str)->tuple[User,str]:
  username=username.strip();user=self.users.by_username(username)
  if user is None or not user.is_active or not verify_password(user.password_hash,password):self.audit.append("LOGIN_FAILED",entity_type="auth",entity_id=username or None);raise AuthenticationError("Неверный логин или пароль")
  token=new_session_token();record=SessionRecord(user_id=user.id,token_hash=token_hash(token),expires_at=datetime.now(timezone.utc)+timedelta(seconds=self.config.session_ttl_seconds));self.db.add(record);self.db.flush();self.audit.append("LOGIN_SUCCESS",user_id=user.id,entity_type="session",entity_id=record.id);return user,token
 def authenticate_token(self,token:str|None)->tuple[User,SessionRecord]:
  if not token:raise AuthenticationError("Требуется авторизация")
  row=self.sessions.active_by_hash(token_hash(token))
  if row is None:raise AuthenticationError("Сессия недействительна")
  user=self.users.by_id(row.user_id)
  if user is None or not user.is_active:raise AuthenticationError("Пользователь отключён")
  return user,row
 def logout(self,session_id:str,user_id:int)->None:
  row=self.db.get(SessionRecord,session_id)
  if row is not None and row.user_id==user_id and row.revoked_at is None:self.sessions.revoke(row)
  self.audit.append("LOGOUT",user_id=user_id,entity_type="session",entity_id=session_id)
