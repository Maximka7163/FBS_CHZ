from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime,timezone
import hashlib
from pathlib import Path
import re,tempfile
from typing import BinaryIO,Iterator
from sqlalchemy import select
from sqlalchemy.orm import Session
from wbcz.m11_reports import ArtifactRole,FilesystemReportArtifactStore,ReportSensitivity,ReportSecurityError
from wbcz_web.config import WebConfig
from wbcz_web.models import ReportArtifactRecord,ReportJobRecord,ReportSnapshotRecord
from wbcz_web.repositories import AuditRepository
from wbcz_web.services.authorization import ActiveScope,AuthorizationError,AuthorizationService,Permission
from wbcz_web.services.reports import EnvironmentArtifactKeyProvider

class ReportDownloadUnavailable(RuntimeError):pass
class ReportArtifactIntegrityError(RuntimeError):pass

@dataclass(slots=True)
class ReportDownloadHandle:
 stream:BinaryIO;filename:str;mime:str;byte_size:int;sha256:str
 def chunks(self,chunk_size:int=1024*1024)->Iterator[bytes]:
  try:
   while True:
    chunk=self.stream.read(chunk_size)
    if not chunk:break
    yield chunk
  finally:self.stream.close()

class ReportDownloadService:
 def __init__(self,db:Session,config:WebConfig):
  self.db=db;self.config=config
  if not config.report_artifact_root:raise ReportDownloadUnavailable("Report artifact storage is not configured")
  self.root=Path(config.report_artifact_root).resolve()
  self.store=FilesystemReportArtifactStore(
   self.root,key_provider=EnvironmentArtifactKeyProvider(),key_version=config.report_artifact_key_version
  )
  self.audit=AuditRepository(db)

 def _event(self,action:str,scope:ActiveScope,*,artifact_id:str|None=None,reason:str|None=None,sensitivity:str|None=None)->None:
  metadata={}
  if reason:metadata["reason"]=reason[:80]
  if sensitivity:metadata["sensitivity_class"]=sensitivity
  self.audit.append(action,user_id=scope.user_id,entity_type="report_artifact",entity_id=artifact_id,metadata=metadata)

 def _path(self,key:str)->Path:
  if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}",key or ""):raise ReportArtifactIntegrityError("Invalid storage key")
  path=(self.root/key).resolve()
  if path.parent!=self.root:raise ReportArtifactIntegrityError("Artifact path escaped root")
  return path

 def _resolve(self,scope:ActiveScope,job_id:str,artifact_id:str):
  AuthorizationService.require(scope,Permission.REPORTS_DOWNLOAD)
  job=self.db.scalar(select(ReportJobRecord).where(
   ReportJobRecord.id==job_id,
   ReportJobRecord.organisation_id==scope.organisation_id,
   ReportJobRecord.participant_id==scope.participant_id,
  ))
  if job is None:raise KeyError("report artifact not found")
  art=self.db.scalar(select(ReportArtifactRecord).where(
   ReportArtifactRecord.artifact_id==artifact_id,
   ReportArtifactRecord.report_job_id==job.id,
  ))
  if art is None or art.artifact_role not in {ArtifactRole.OUTPUT.value,ArtifactRole.REMOTE_TRUE_API_ARCHIVE.value}:
   raise KeyError("report artifact not found")
  return job,art

 def _aad(self,job,art):
  if art.artifact_role==ArtifactRole.OUTPUT.value:
   snap=self.db.get(ReportSnapshotRecord,job.snapshot_id) if job.snapshot_id else None
   if snap is None or snap.report_job_id!=job.id:raise ReportArtifactIntegrityError("snapshot binding invalid")
   return {"artifact_id":art.artifact_id,"report_job_id":job.id,"snapshot_sha256":snap.descriptor_sha256,"role":ArtifactRole.OUTPUT.value}
  if art.artifact_role==ArtifactRole.REMOTE_TRUE_API_ARCHIVE.value and art.remote_result_id:
   return {"artifact_id":art.artifact_id,"report_job_id":job.id,"remote_result_id":art.remote_result_id,"remote_result_part_id":art.remote_result_part_id,"role":ArtifactRole.REMOTE_TRUE_API_ARCHIVE.value}
  raise ReportArtifactIntegrityError("artifact binding invalid")

 def _open_verified(self,job,art)->BinaryIO:
  sensitive=art.sensitivity_class in {
   ReportSensitivity.BUSINESS_SENSITIVE.value,ReportSensitivity.MARKING_SENSITIVE.value
  }
  if sensitive:
   target=tempfile.SpooledTemporaryFile(max_size=8*1024*1024,mode="w+b")
   try:size,digest=self.store.decrypt_sensitive_to(art.storage_key,target,aad_context=self._aad(job,art))
   except (FileNotFoundError,OSError,ReportSecurityError,ValueError) as exc:
    target.close();raise ReportArtifactIntegrityError("integrity failure") from exc
   if size!=art.byte_size or digest!=art.sha256:
    target.close();raise ReportArtifactIntegrityError("integrity failure")
   target.seek(0);return target
  try:stream=self._path(art.storage_key).open("rb")
  except OSError as exc:raise ReportArtifactIntegrityError("artifact unavailable") from exc
  digest=hashlib.sha256();size=0
  try:
   while True:
    chunk=stream.read(1024*1024)
    if not chunk:break
    size+=len(chunk)
    if size>self.config.report_max_artifact_bytes:raise ReportArtifactIntegrityError("artifact too large")
    digest.update(chunk)
   if size!=art.byte_size or digest.hexdigest()!=art.sha256:raise ReportArtifactIntegrityError("integrity failure")
   stream.seek(0);return stream
  except BaseException:
   stream.close();raise

 def open_download(self,scope:ActiveScope,*,job_id:str,artifact_id:str)->ReportDownloadHandle:
  art=None
  try:
   job,art=self._resolve(scope,job_id,artifact_id);now=datetime.now(timezone.utc)
   if job.state!="READY" or art.state!="READY" or art.deleted_at is not None:
    raise ReportDownloadUnavailable("Report artifact is not downloadable")
   if (art.expires_at and art.expires_at<=now) or (art.remote_file_delete_at and art.remote_file_delete_at<=now):
    raise ReportDownloadUnavailable("Report artifact has expired")
   if art.storage_backend!="FILESYSTEM" or art.byte_size<0 or art.byte_size>self.config.report_max_artifact_bytes:
    raise ReportDownloadUnavailable("Report artifact is unavailable")
   if art.sensitivity_class==ReportSensitivity.MARKING_SENSITIVE.value:
    AuthorizationService.require(scope,Permission.REPORTS_DOWNLOAD_SENSITIVE)
   stream=self._open_verified(job,art)
   self._event("REPORT_DOWNLOAD_ALLOWED",scope,artifact_id=art.artifact_id,sensitivity=art.sensitivity_class)
   return ReportDownloadHandle(stream,art.safe_filename,art.mime or "application/octet-stream",art.byte_size,art.sha256)
  except ReportArtifactIntegrityError:
   self._event("REPORT_DOWNLOAD_INTEGRITY_FAILED",scope,artifact_id=art.artifact_id if art else None,reason="integrity")
   raise
  except (AuthorizationError,KeyError,ReportDownloadUnavailable):
   self._event("REPORT_DOWNLOAD_DENIED",scope,artifact_id=art.artifact_id if art else None,reason="not_authorized_or_unavailable")
   raise
