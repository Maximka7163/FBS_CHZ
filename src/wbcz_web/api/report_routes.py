from __future__ import annotations
from urllib.parse import quote
from fastapi import APIRouter,Depends,HTTPException,Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from wbcz_web.models import ReportArtifactRecord,ReportJobRecord,SessionRecord,User
from wbcz_web.services.authorization import AuthorizationError,AuthorizationService,Permission
from wbcz_web.services.report_downloads import ReportArtifactIntegrityError,ReportDownloadService,ReportDownloadUnavailable
from wbcz_web.services.audit_history import ActorContext,ActorKind,AuditOutcome,AuditService,AuditTenantScope,AuthorizationDecision,SubjectRef,SubjectType,TraceContext
from .dependencies import AuthenticatedIdentity,get_db,require_permission
reports_router=APIRouter(prefix="/api")
def _scope(db:Session,identity:AuthenticatedIdentity):
 user=db.get(User,identity.user_id);session=db.get(SessionRecord,identity.session_id)
 if user is None or session is None:raise HTTPException(401,"Session is invalid")
 try:return AuthorizationService(db).resolve_session_scope(user,session,require_participant=True)
 except AuthorizationError as exc:raise HTTPException(403,"Active participant scope required") from exc
@reports_router.get("/reports/{job_id}")
def report(job_id:str,identity:AuthenticatedIdentity=Depends(require_permission(Permission.REPORTS_READ)),db:Session=Depends(get_db))->dict:
 s=_scope(db,identity);AuthorizationService.require(s,Permission.REPORTS_READ)
 job=db.scalar(select(ReportJobRecord).where(ReportJobRecord.id==job_id,ReportJobRecord.organisation_id==s.organisation_id,ReportJobRecord.participant_id==s.participant_id))
 if job is None:raise HTTPException(404,"Report not found")
 arts=list(db.scalars(select(ReportArtifactRecord).where(ReportArtifactRecord.report_job_id==job.id).order_by(ReportArtifactRecord.created_at,ReportArtifactRecord.artifact_id)))
 return {"id":job.id,"origin":job.origin,"report_type":job.report_type,"output_format":job.output_format,"sensitivity_class":job.sensitivity_class,"state":job.state,"requested_at":job.requested_at.isoformat(),"completed_at":job.completed_at.isoformat() if job.completed_at else None,"artifacts":[{"artifact_id":a.artifact_id,"role":a.artifact_role,"state":a.state,"format":a.format,"mime":a.mime,"filename":a.safe_filename,"byte_size":a.byte_size,"expires_at":a.expires_at.isoformat() if a.expires_at else None} for a in arts]}
def _record_stream_outcome(session_factory,config,scope,artifact_id:str,trace_data:dict|None,*,success:bool)->None:
 db=session_factory()
 try:
  if getattr(config,"audit_pseudonym_key",None):
   db.info["audit_pseudonym_key"]=config.audit_pseudonym_key.encode("utf-8")
   db.info["audit_pseudonym_key_id"]=config.audit_pseudonym_key_id
  request_id=trace_data.get("request_id") if isinstance(trace_data,dict) else None
  correlation_id=trace_data.get("correlation_id") if isinstance(trace_data,dict) else request_id
  causation_id=trace_data.get("causation_id") if isinstance(trace_data,dict) else None
  AuditService(
   db,
   pseudonym_key=db.info.get("audit_pseudonym_key"),
   pseudonym_key_id=db.info.get("audit_pseudonym_key_id"),
  ).append(
   event_type="REPORT_DOWNLOAD_COMPLETED" if success else "REPORT_DOWNLOAD_FAILED",
   actor=ActorContext(ActorKind.USER,user_id=scope.user_id),
   tenant=AuditTenantScope(scope.organisation_id,scope.participant_id),
   subject=SubjectRef(SubjectType.REPORT_ARTIFACT,artifact_id),
   outcome=AuditOutcome.SUCCESS if success else AuditOutcome.FAILED,
   authorization_decision=AuthorizationDecision.ALLOW,
   trace=TraceContext(
    request_id=request_id,correlation_id=correlation_id,causation_id=causation_id,
    event_key=(f"report-download:{request_id}:{artifact_id}:{'completed' if success else 'failed'}"[:256] if request_id else None),
   ),
   metadata={"artifact_id":artifact_id},
  )
  db.commit()
 except Exception:
  db.rollback()
  raise
 finally:
  db.close()

@reports_router.get("/reports/{job_id}/artifacts/{artifact_id}/download")
def download(job_id:str,artifact_id:str,request:Request,identity:AuthenticatedIdentity=Depends(require_permission(Permission.REPORTS_DOWNLOAD)),db:Session=Depends(get_db)):
 s=_scope(db,identity)
 trace_data=dict(db.info.get("audit_trace") or {})
 try:
  h=ReportDownloadService(db,request.app.state.config).open_download(s,job_id=job_id,artifact_id=artifact_id)
  # M13 contract: authorization evidence must be durable before response bytes.
  db.commit()
 except KeyError as exc:
  db.commit()
  raise HTTPException(404,"Report artifact not found") from exc
 except AuthorizationError as exc:
  db.commit()
  raise HTTPException(403,"Permission denied") from exc
 except ReportDownloadUnavailable as exc:
  db.commit()
  raise HTTPException(409,str(exc)) from exc
 except ReportArtifactIntegrityError as exc:
  db.commit()
  raise HTTPException(409,"Report artifact integrity verification failed") from exc

 def chunks():
  try:
   for chunk in h.chunks():
    yield chunk
  except BaseException:
   _record_stream_outcome(
    request.app.state.session_factory,request.app.state.config,s,artifact_id,trace_data,success=False
   )
   raise
  else:
   _record_stream_outcome(
    request.app.state.session_factory,request.app.state.config,s,artifact_id,trace_data,success=True
   )

 headers={"Content-Disposition":"attachment; filename*=UTF-8''"+quote(h.filename,safe=""),"Content-Length":str(h.byte_size),"X-Content-Type-Options":"nosniff","Cache-Control":"no-store, private"}
 return StreamingResponse(chunks(),media_type=h.mime,headers=headers)
