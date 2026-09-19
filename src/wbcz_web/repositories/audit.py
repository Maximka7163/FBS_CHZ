from __future__ import annotations

from typing import Any
from sqlalchemy import inspect

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

_IMMUTABLE_EVENT_MAP={
 "LOGIN_SUCCESS":"LOGIN_SUCCESS",
 "LOGIN_FAILED":"LOGIN_FAILED",
 "LOGIN_THROTTLED":"LOGIN_THROTTLED",
 "LOGOUT":"LOGOUT",
 "LOGOUT_ALL":"LOGOUT_ALL",
 "SESSION_REVOKED":"SESSION_REVOKED",
 "PASSWORD_CHANGED":"PASSWORD_CHANGED",
 "PASSWORD_AUTHENTICATOR_UNLOCKED":"PASSWORD_AUTHENTICATOR_UNLOCKED",
 "USER_DISABLED":"USER_DISABLED",
 "BOOTSTRAP_COMPLETED":"BOOTSTRAP_COMPLETED",
 "MEMBERSHIP_ADDED":"MEMBERSHIP_ADDED",
 "MEMBERSHIP_REMOVED":"MEMBERSHIP_REMOVED",
 "ROLE_CHANGED":"ROLE_CHANGED",
 "INVITATION_CREATED":"INVITATION_CREATED",
 "INVITATION_ACCEPTED":"INVITATION_ACCEPTED",
 "INVITATION_REVOKED":"INVITATION_REVOKED",
 "SCOPE_CHANGED":"SCOPE_CHANGED",
 "REPORT_DOWNLOAD_ALLOWED":"REPORT_DOWNLOAD_AUTHORIZED",
 "REPORT_DOWNLOAD_DENIED":"REPORT_DOWNLOAD_DENIED",
 "REPORT_DOWNLOAD_INTEGRITY_FAILED":"REPORT_ARTIFACT_INTEGRITY_FAILED",
}
_SYSTEM_EVENTS={
 "LOGIN_SUCCESS","LOGIN_FAILED","LOGIN_THROTTLED","LOGOUT","LOGOUT_ALL","SESSION_REVOKED",
 "PASSWORD_CHANGED","PASSWORD_AUTHENTICATOR_UNLOCKED","USER_DISABLED",
}
_TENANT_ADMIN_EVENTS={
 "BOOTSTRAP_COMPLETED","MEMBERSHIP_ADDED","MEMBERSHIP_REMOVED","ROLE_CHANGED",
 "INVITATION_CREATED","INVITATION_ACCEPTED","INVITATION_REVOKED","SCOPE_CHANGED",
}


class AuditRepository(Repository):
 def _m13_available(self)->bool:
  cached=self.db.info.get("m13_audit_available")
  if cached is not None:return bool(cached)
  try:available=bool(inspect(self.db.bind).has_table("audit_chain_heads"))
  except Exception:available=False
  self.db.info["m13_audit_available"]=available
  return available

 def _service(self):
  from wbcz_web.services.audit_history import AuditService
  key=self.db.info.get("audit_pseudonym_key")
  key_id=self.db.info.get("audit_pseudonym_key_id")
  return AuditService(self.db,pseudonym_key=key if isinstance(key,(bytes,bytearray)) else None,pseudonym_key_id=str(key_id) if key_id else None)

 @staticmethod
 def _subject_for(action:str,entity_type:str|None,entity_id:str|None,service,org:str|None):
  from wbcz_web.services.audit_history import SubjectRef,SubjectType
  raw=str(entity_id or "unknown")
  if action=="SCOPE_CHANGED":
   return SubjectRef(SubjectType.ORGANISATION,str(org or raw))
  mapping={
   "user":SubjectType.USER,
   "session":SubjectType.SESSION,
   "membership":SubjectType.MEMBERSHIP,
   "invitation":SubjectType.INVITATION,
   "organisation":SubjectType.ORGANISATION,
   "participant":SubjectType.PARTICIPANT,
   "report_artifact":SubjectType.REPORT_ARTIFACT,
  }
  subject_type=mapping.get(str(entity_type or "").casefold(),SubjectType.USER if action in {"USER_DISABLED","PASSWORD_CHANGED","PASSWORD_AUTHENTICATOR_UNLOCKED","LOGOUT_ALL"} else SubjectType.SESSION)
  if subject_type is SubjectType.SESSION:
   raw=service.pseudonymizer.session_identifier(raw)
  return SubjectRef(subject_type,raw)

 def _immutable(
  self,
  action:str,
  *,
  user_id:int|None,
  entity_type:str|None,
  entity_id:str|None,
  metadata:dict[str,Any],
  organisation_id:str|None,
  participant_id:str|None,
 )->None:
  from wbcz_web.services.audit_history import (
   AUDIT_EVENT_REGISTRY,ActorContext,ActorKind,AuditOutcome,AuditTenantScope,
   AuthorizationDecision,TraceContext,
  )
  event_type=_IMMUTABLE_EVENT_MAP.get(action)
  if event_type is None or not self._m13_available():return
  service=self._service()
  if action=="LOGIN_FAILED" and user_id is None:
   # Anonymous username spraying remains operational/rate-bound only. Known-account
   # failures are sealed below without persisting the username/email.
   return
  if action in _SYSTEM_EVENTS:
   tenant=AuditTenantScope.system()
  else:
   if not organisation_id:
    # Tenant admin/business immutable facts must never fall back to SYSTEM.
    raise ValueError("M13 tenant audit scope is required")
   tenant=AuditTenantScope(organisation_id,participant_id)
  if action=="BOOTSTRAP_COMPLETED":
   actor=ActorContext(ActorKind.BOOTSTRAP,user_id=user_id)
  elif action=="USER_DISABLED":
   actor=ActorContext(ActorKind.CLI_ADMIN)
  elif user_id is not None:
   actor=ActorContext(ActorKind.USER,user_id=user_id)
  else:
   actor=ActorContext(ActorKind.SYSTEM)
  subject=self._subject_for(action,entity_type,entity_id,service,organisation_id)

  outcome=AuditOutcome.SUCCESS
  authz=AuthorizationDecision.NOT_APPLICABLE
  if action=="LOGIN_FAILED":
   outcome=AuditOutcome.FAILED
  elif action=="LOGIN_THROTTLED":
   outcome=AuditOutcome.DENIED
  elif action=="REPORT_DOWNLOAD_DENIED":
   outcome=AuditOutcome.DENIED;authz=AuthorizationDecision.DENY
  elif action=="REPORT_DOWNLOAD_INTEGRITY_FAILED":
   outcome=AuditOutcome.FAILED
  elif action in _TENANT_ADMIN_EVENTS or action=="REPORT_DOWNLOAD_ALLOWED":
   authz=AuthorizationDecision.ALLOW

  definition=AUDIT_EVENT_REGISTRY[event_type]
  filtered={k:v for k,v in metadata.items() if k in definition.allowed_metadata_keys}
  trace_data=self.db.info.get("audit_trace")
  request_id=correlation_id=causation_id=None
  if isinstance(trace_data,dict):
   request_id=trace_data.get("request_id")
   correlation_id=trace_data.get("correlation_id")
   causation_id=trace_data.get("causation_id")
  event_key=None
  if request_id:
   event_key=f"request:{request_id}:{event_type}:{subject.id}"[:256]
  service.append(
   event_type=event_type,
   actor=actor,
   tenant=tenant,
   subject=subject,
   outcome=outcome,
   authorization_decision=authz,
   trace=TraceContext(
    request_id=request_id,
    correlation_id=correlation_id,
    causation_id=causation_id,
    event_key=event_key,
   ),
   metadata=filtered,
  )

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
  self.db.add(row);self.db.flush()
  self._immutable(
   action,user_id=user_id,entity_type=entity_type,entity_id=entity_id,
   metadata=safe,organisation_id=org,participant_id=part,
  )
  self.db.flush()
  return row
