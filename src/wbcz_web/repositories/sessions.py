from datetime import datetime,timezone
from sqlalchemy import select,update
from .base import Repository
from wbcz_web.models import SessionRecord
class SessionRepository(Repository):
    def active_by_hash(self,value:str)->SessionRecord|None:
        now=datetime.now(timezone.utc)
        return self.db.scalar(select(SessionRecord).where(SessionRecord.token_hash==value,SessionRecord.revoked_at.is_(None),SessionRecord.expires_at>now))
    def revoke(self,row:SessionRecord)->None:row.revoked_at=datetime.now(timezone.utc);self.db.flush()
    def active_for_user(self,user_id:int)->list[SessionRecord]:
        now=datetime.now(timezone.utc)
        return list(self.db.scalars(select(SessionRecord).where(
            SessionRecord.user_id==user_id,
            SessionRecord.revoked_at.is_(None),
            SessionRecord.expires_at>now,
        ).order_by(SessionRecord.created_at,SessionRecord.id)))
    def revoke_all_for_user(self,user_id:int,*,except_session_id:str|None=None)->int:
        now=datetime.now(timezone.utc);q=update(SessionRecord).where(SessionRecord.user_id==user_id,SessionRecord.revoked_at.is_(None))
        if except_session_id:q=q.where(SessionRecord.id!=except_session_id)
        result=self.db.execute(q.values(revoked_at=now));self.db.flush();return int(result.rowcount or 0)
