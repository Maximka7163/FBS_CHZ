from __future__ import annotations
from typing import Any
from .base import Repository
from wbcz_web.models import AuditLog

_ALLOWED={"LOGIN_SUCCESS","LOGIN_FAILED","LOGOUT","USER_CREATED","USER_DISABLED","FILE_IMPORTED","FILE_REPEATED","CONTROL_RUN","PREVIEW_CREATED"}
_FORBIDDEN_KEYS={"password","password_hash","session_token","csrf_token","cookie","cookies","token","signature","pin","private_key"}

class AuditRepository(Repository):
    def append(self, action:str, *, user_id:int|None=None, entity_type:str|None=None, entity_id:str|None=None, metadata:dict[str,Any]|None=None)->AuditLog:
        if action not in _ALLOWED: raise ValueError(f"Unsupported audit action: {action}")
        safe=dict(metadata or {})
        if any(str(key).casefold() in _FORBIDDEN_KEYS for key in safe): raise ValueError("Secret-like field is forbidden in audit metadata")
        row=AuditLog(action=action,user_id=user_id,entity_type=entity_type,entity_id=entity_id,metadata_json=safe);self.db.add(row);self.db.flush();return row
