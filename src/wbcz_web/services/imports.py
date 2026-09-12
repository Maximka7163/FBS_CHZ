from __future__ import annotations
from collections import Counter
from hashlib import sha256
from sqlalchemy.orm import Session
from wbcz.models import Event,Operation
from wbcz.wb_parser import MAX_FILE_BYTES,WorkbookError,parse_excel
from wbcz_web.models import EventRecord,ImportRecord,ImportRow
from wbcz_web.repositories import AuditRepository,ImportRepository
class UploadError(ValueError):pass
def event_to_record(event:Event)->EventRecord:return EventRecord(event_id=event.event_id,kiz=event.kiz,task_number=event.task_number,sticker=event.sticker,operation=event.operation.value,occurred_at=event.occurred_at,receipt_number=event.receipt_number,fiscal_drive_number=event.fiscal_drive_number,amount=event.amount,currency=event.currency,legal_entity_sale=event.legal_entity_sale,payload=event.to_dict())
def record_to_event(row:EventRecord)->Event:return Event.from_dict(dict(row.payload))
class FileImportService:
 def __init__(self,db:Session)->None:self.db=db;self.imports=ImportRepository(db);self.audit=AuditRepository(db)
 def import_xlsx(self,filename:str,data:bytes,user_id:int)->ImportRecord:
  safe_name=(filename or "upload.xlsx").replace("\\","/").split("/")[-1]
  if not safe_name.lower().endswith(".xlsx"):raise UploadError("Поддерживаются только файлы .xlsx")
  if len(data)>MAX_FILE_BYTES:raise UploadError("Файл превышает допустимый размер 50 MiB")
  try:parsed=parse_excel(data)
  except WorkbookError as exc:raise UploadError(str(exc)) from exc
  fingerprint=sha256(data).hexdigest();repeated=self.imports.first_by_fingerprint(fingerprint);record=ImportRecord(fingerprint=fingerprint,filename=safe_name[:255],imported_by=user_id,repeated_of_id=repeated.id if repeated else None);self.db.add(record);self.db.flush();inserted=duplicates=dated=undated=0;unique_kiz=set();ops=Counter();known=set()
  for item in parsed.rows:
   event=item.event;unique_kiz.add(event.kiz);ops[event.operation.value]+=1;dated+=event.occurred_at is not None;undated+=event.occurred_at is None;exists=event.event_id in known or self.imports.event_exists(event.event_id)
   if exists:duplicates+=1
   else:self.db.add(event_to_record(event));self.db.flush();known.add(event.event_id);inserted+=1
   self.db.add(ImportRow(import_id=record.id,row_number=item.row_number,event_id=event.event_id))
  for issue in parsed.issues:self.db.add(ImportRow(import_id=record.id,row_number=issue.row_number,error=issue.message))
  record.new_events=inserted;record.duplicate_events=duplicates;record.rejected_rows=len(parsed.issues);record.row_count=len(parsed.rows)+len(parsed.issues);record.unique_kiz=len(unique_kiz);record.sales=ops[Operation.SALE.value];record.returns=ops[Operation.RETURN.value];record.dated=dated;record.undated=undated;self.db.flush();action="FILE_REPEATED" if repeated else "FILE_IMPORTED";self.audit.append(action,user_id=user_id,entity_type="import",entity_id=record.id,metadata={"fingerprint":fingerprint,"new_events":inserted,"duplicate_events":duplicates,"rejected_rows":len(parsed.issues)});return record
def import_view(row:ImportRecord)->dict:return {"id":row.id,"fingerprint":row.fingerprint,"filename":row.filename,"imported_at":row.imported_at.isoformat() if row.imported_at else None,"repeated":row.repeated_of_id is not None,"repeated_of_id":row.repeated_of_id,"new_events":row.new_events,"duplicate_events":row.duplicate_events,"rejected_rows":row.rejected_rows,"row_count":row.row_count,"unique_kiz":row.unique_kiz,"sales":row.sales,"returns":row.returns,"dated":row.dated,"undated":row.undated,"status":"error" if row.rejected_rows else "processed"}
