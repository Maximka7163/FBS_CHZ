from sqlalchemy import func,select
from .base import Repository
from wbcz_web.models import CheckRecord,EventRecord,ImportRecord,ImportRow

class ImportRepository(Repository):
    def first_by_fingerprint(self,fingerprint:str)->ImportRecord|None:return self.db.scalar(select(ImportRecord).where(ImportRecord.fingerprint==fingerprint).order_by(ImportRecord.imported_at,ImportRecord.id).limit(1))
    def get(self,import_id:str)->ImportRecord|None:return self.db.get(ImportRecord,import_id)
    def list_recent(self,limit:int=20)->list[ImportRecord]:return list(self.db.scalars(select(ImportRecord).order_by(ImportRecord.imported_at.desc()).limit(limit)))
    def ordered_event_records(self,import_id:str)->list[EventRecord]:return list(self.db.scalars(select(EventRecord).join(ImportRow,ImportRow.event_id==EventRecord.event_id).where(ImportRow.import_id==import_id,ImportRow.event_id.is_not(None)).order_by(ImportRow.row_number)))
    def import_event_ids(self,import_id:str)->list[str]:return list(self.db.scalars(select(ImportRow.event_id).where(ImportRow.import_id==import_id,ImportRow.event_id.is_not(None)).order_by(ImportRow.row_number)))
    def event(self,event_id:str)->EventRecord|None:return self.db.get(EventRecord,event_id)
    def history_for_kiz(self,kiz:str)->list[EventRecord]:return list(self.db.scalars(select(EventRecord).where(EventRecord.kiz==kiz).order_by(EventRecord.occurred_at.is_(None),EventRecord.occurred_at,EventRecord.event_id)))
    def history_order_ambiguous(self,kiz:str)->bool:
        rows=self.history_for_kiz(kiz)
        if len(rows)<2:return False
        dates=[row.occurred_at for row in rows]
        return any(value is None for value in dates) or len(set(dates))!=len(dates)
    def latest_check(self,event_id:str)->CheckRecord|None:return self.db.scalar(select(CheckRecord).where(CheckRecord.event_id==event_id).order_by(CheckRecord.id.desc()).limit(1))
    def event_exists(self,event_id:str)->bool:return bool(self.db.scalar(select(func.count()).select_from(EventRecord).where(EventRecord.event_id==event_id)))
