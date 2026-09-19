from __future__ import annotations
from typing import Any
from .base import Repository
from wbcz_web.models import AuditLog

_ALLOWED={
 "LOGIN_SUCCESS","LOGIN_FAILED","LOGIN_THROTTLED","LOGOUT","LOGOUT_ALL","SESSION_REVOKED",
 "PASSWORD_CHANGED","PASSWORD_AUTHENTICATOR_UNLOCKED","USER_CREATED","USER_DISABLED","FILE_IMPORTED","FILE_REPEATED","CONTROL_RUN",
 "PREVIEW_CREATED","BULK_ACTION_STARTED","BOOTSTRAP_COMPLETED","MEMBERSHIP_ADDED","MEMBERSHIP_REMOVED",
 "ROLE_CHANGED","INVITATION_CREATED","INVITATION_ACCEPTED","INVITATION_REVOKED","SCOPE_CHANGED",
 "REPORT_DOWNLOAD_ALLOWED","REPORT_DOWNLOAD_DENIED","REPORT_DOWNLOAD_INTEGRITY_FAILED",
}
_FORBIDDEN_MARKERS=("password","session_token","csrf","cookie","token","signature","pin","private_key","api_key","secret","authorization")

class AuditRepository(Repository):
 def append(self,action:str,*,user_id:int|None=None,entity_type:str|None=None,entity_id:str|None=None,metadata:dict[str,Any]|None=None)->AuditLog:
  if action not in _ALLOWED:raise ValueError(f"Unsupported audit action: {action}")
  safe=dict(metadata or {})
  for key in safe:
   lowered=str(key).casefold()
   if any(marker in lowered for marker in _FORBIDDEN_MARKERS):raise ValueError("Secret-like field is forbidden in audit metadata")
  scope=self.db.info.get("tenant_scope")
  org=scope.get("organisation_id") if isinstance(scope,dict) else None
  part=scope.get("participant_id") if isinstance(scope,dict) else None
  row=AuditLog(action=action,user_id=user_id,organisation_id=org,participant_id=part,entity_type=entity_type,entity_id=entity_id,metadata_json=safe)
  self.db.add(row);self.db.flush();return row
