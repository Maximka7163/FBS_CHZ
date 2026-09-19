from __future__ import annotations
from collections import Counter
from hashlib import sha256
from sqlalchemy.orm import Session
from wbcz.models import Event,Operation
from wbcz.wb_parser import MAX_FILE_BYTES,WorkbookError,parse_excel
from wbcz_web.models import EventRecord,ImportRecord,ImportRow
from wbcz_web.repositories import AuditRepository,ImportRepository
class UploadError(ValueError):pass
def _scope(db:Session):
 s=db.info.get("tenant_scope")
 if not isinstance(s,dict) or not s.get("organisation_id") or not s.get("participant_id"):raise PermissionError("active organisation and participant scope is required")
 return str(s["organisation_id"]),str(s["participant_id"])
def tenant_event_id(org:str,participant:str,source:str)->str:return sha256(f"m12-tenant-event:v1:{org}:{participant}:{source}".encode()).hexdigest()
def event_to_record(event:Event,*,organisation_id:str|None=None,participant_id:str|None=None)->EventRecord:
 if bool(organisation_id)!=bool(participant_id):raise ValueError("organisation_id and participant_id must be provided together")
 storage_id=tenant_event_id(organisation_id,participant_id,event.event_id) if organisation_id and participant_id else event.event_id
 return EventRecord(event_id=storage_id,source_event_id=event.event_id,organisation_id=organisation_id,participant_id=participant_id,kiz=event.kiz,task_number=event.task_number,sticker=event.sticker,operation=event.operation.value,occurred_at=event.occurred_at,receipt_number=event.receipt_number,fiscal_drive_number=event.fiscal_drive_number,amount=event.amount,currency=event.currency,legal_entity_sale=event.legal_entity_sale,payload=event.to_dict())
def record_to_event(row:EventRecord)->Event:return Event.from_dict(dict(row.payload))
class FileImportService:
 def __init__(self,db:Session):self.db=db;self.imports=ImportRepository(db);self.audit=AuditRepository(db)
 def import_xlsx(self,filename:str,data:bytes,user_id:int)->ImportRecord:
  org,participant=_scope(self.db);safe=(filename or "upload.xlsx").replace(chr(92),"/").split("/")[-1]
  if not safe.lower().endswith(".xlsx"):raise UploadError("Поддерживаются только файлы .xlsx")
  if len(data)>MAX_FILE_BYTES:raise UploadError("Файл превышает допустимый размер 50 MiB")
  try:parsed=parse_excel(data)
  except WorkbookError as exc:raise UploadError(str(exc)) from exc
  fingerprint=sha256(data).hexdigest();repeated=self.imports.first_by_fingerprint(fingerprint);record=ImportRecord(organisation_id=org,participant_id=participant,fingerprint=fingerprint,filename=safe[:255],imported_by=user_id,repeated_of_id=repeated.id if repeated else None);self.db.add(record);self.db.flush()
  inserted=duplicates=dated=undated=0;unique_kiz=set();ops=Counter();known=set()
  for item in parsed.rows:
   event=item.event;unique_kiz.add(event.kiz);ops[event.operation.value]+=1;dated+=event.occurred_at is not None;undated+=event.occurred_at is None;storage_id=tenant_event_id(org,participant,event.event_id);exists=event.event_id in known or self.imports.event_exists(event.event_id)
   if exists:duplicates+=1
   else:self.db.add(event_to_record(event,organisation_id=org,participant_id=participant));self.db.flush();known.add(event.event_id);inserted+=1
   self.db.add(ImportRow(import_id=record.id,row_number=item.row_number,event_id=storage_id))
  for issue in parsed.issues:self.db.add(ImportRow(import_id=record.id,row_number=issue.row_number,error=issue.message))
  record.new_events=inserted;record.duplicate_events=duplicates;record.rejected_rows=len(parsed.issues);record.row_count=len(parsed.rows)+len(parsed.issues);record.unique_kiz=len(unique_kiz);record.sales=ops[Operation.SALE.value];record.returns=ops[Operation.RETURN.value];record.dated=dated;record.undated=undated;self.db.flush();self.audit.append("FILE_REPEATED" if repeated else "FILE_IMPORTED",user_id=user_id,entity_type="import",entity_id=record.id,metadata={"fingerprint":fingerprint,"new_events":inserted,"duplicate_events":duplicates,"rejected_rows":len(parsed.issues)});return record
def import_view(row:ImportRecord)->dict:return {"id":row.id,"fingerprint":row.fingerprint,"filename":row.filename,"imported_at":row.imported_at.isoformat() if row.imported_at else None,"repeated":row.repeated_of_id is not None,"repeated_of_id":row.repeated_of_id,"new_events":row.new_events,"duplicate_events":row.duplicate_events,"rejected_rows":row.rejected_rows,"row_count":row.row_count,"unique_kiz":row.unique_kiz,"sales":row.sales,"returns":row.returns,"dated":row.dated,"undated":row.undated,"status":"error" if row.rejected_rows else "processed"}
