from sqlalchemy import func,select
from .base import Repository
from wbcz_web.models import BootstrapRecord,CheckRecord,EventRecord,ImportRecord,ImportRow

class ImportRepository(Repository):
 def _scope(self):
  scope=self.db.info.get("tenant_scope")
  if isinstance(scope,dict) and scope.get("organisation_id") and scope.get("participant_id"):
   return str(scope["organisation_id"]),str(scope["participant_id"])
  if self.db.get(BootstrapRecord,1) is not None:
   raise PermissionError("active tenant scope required")
  return None
 def _imports(self,q):
  s=self._scope();return q.where(ImportRecord.organisation_id==s[0],ImportRecord.participant_id==s[1]) if s else q
 def _events(self,q):
  s=self._scope();return q.where(EventRecord.organisation_id==s[0],EventRecord.participant_id==s[1]) if s else q
 def first_by_fingerprint(self,fingerprint:str):return self.db.scalar(self._imports(select(ImportRecord).where(ImportRecord.fingerprint==fingerprint)).order_by(ImportRecord.imported_at,ImportRecord.id).limit(1))
 def get(self,import_id:str):return self.db.scalar(self._imports(select(ImportRecord).where(ImportRecord.id==import_id)))
 def list_recent(self,limit:int=20):return list(self.db.scalars(self._imports(select(ImportRecord)).order_by(ImportRecord.imported_at.desc()).limit(limit)))
 def ordered_event_records(self,import_id:str):
  if self.get(import_id) is None:return []
  q=select(EventRecord).join(ImportRow,ImportRow.event_id==EventRecord.event_id).where(ImportRow.import_id==import_id,ImportRow.event_id.is_not(None))
  return list(self.db.scalars(self._events(q).order_by(ImportRow.row_number)))
 def event_row_numbers(self,import_id:str):
  if self.get(import_id) is None:return {}
  rows=self.db.execute(select(ImportRow.event_id,ImportRow.row_number).where(ImportRow.import_id==import_id,ImportRow.event_id.is_not(None)).order_by(ImportRow.row_number)).all()
  result={}
  for event_id,row_number in rows:
   if event_id not in result:result[event_id]=row_number
  return result
 def import_event_ids(self,import_id:str):
  if self.get(import_id) is None:return []
  values=list(self.db.scalars(select(ImportRow.event_id).where(ImportRow.import_id==import_id,ImportRow.event_id.is_not(None)).order_by(ImportRow.row_number)))
  return list(dict.fromkeys(values))
 def event(self,event_id:str):return self.db.scalar(self._events(select(EventRecord).where(EventRecord.event_id==event_id)))
 def history_for_kiz(self,kiz:str):return list(self.db.scalars(self._events(select(EventRecord).where(EventRecord.kiz==kiz)).order_by(EventRecord.occurred_at.is_(None),EventRecord.occurred_at,EventRecord.event_id)))
 def history_order_ambiguous(self,kiz:str)->bool:
  rows=self.history_for_kiz(kiz);dates=[x.occurred_at for x in rows]
  return len(rows)>=2 and (any(x is None for x in dates) or len(set(dates))!=len(dates))
 def latest_check(self,event_id:str):
  if self.event(event_id) is None:return None
  return self.db.scalar(select(CheckRecord).where(CheckRecord.event_id==event_id).order_by(CheckRecord.id.desc()).limit(1))
 def event_exists(self,source_event_id:str)->bool:
  s=self._scope();q=select(func.count()).select_from(EventRecord).where(EventRecord.source_event_id==source_event_id)
  if s:q=q.where(EventRecord.organisation_id==s[0],EventRecord.participant_id==s[1])
  return bool(self.db.scalar(q))
