from __future__ import annotations
from urllib.parse import quote
from fastapi import APIRouter,Depends,HTTPException,Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from wbcz_web.models import ReportArtifactRecord,ReportJobRecord,SessionRecord,User
from wbcz_web.services.authorization import AuthorizationError,AuthorizationService,Permission
from wbcz_web.services.report_downloads import ReportArtifactIntegrityError,ReportDownloadService,ReportDownloadUnavailable
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
@reports_router.get("/reports/{job_id}/artifacts/{artifact_id}/download")
def download(job_id:str,artifact_id:str,request:Request,identity:AuthenticatedIdentity=Depends(require_permission(Permission.REPORTS_DOWNLOAD)),db:Session=Depends(get_db)):
 s=_scope(db,identity)
 try:h=ReportDownloadService(db,request.app.state.config).open_download(s,job_id=job_id,artifact_id=artifact_id)
 except KeyError as exc:raise HTTPException(404,"Report artifact not found") from exc
 except AuthorizationError as exc:raise HTTPException(403,"Permission denied") from exc
 except ReportDownloadUnavailable as exc:raise HTTPException(409,str(exc)) from exc
 except ReportArtifactIntegrityError as exc:raise HTTPException(409,"Report artifact integrity verification failed") from exc
 headers={"Content-Disposition":"attachment; filename*=UTF-8''"+quote(h.filename,safe=""),"Content-Length":str(h.byte_size),"X-Content-Type-Options":"nosniff","Cache-Control":"no-store, private"}
 return StreamingResponse(h.chunks(),media_type=h.mime,headers=headers)
