from datetime import datetime,timezone
from sqlalchemy import select
from .base import Repository
from wbcz_web.models import SessionRecord

class SessionRepository(Repository):
    def active_by_hash(self,value:str)->SessionRecord|None:
        now=datetime.now(timezone.utc)
        return self.db.scalar(select(SessionRecord).where(SessionRecord.token_hash==value,SessionRecord.revoked_at.is_(None),SessionRecord.expires_at>now))
    def revoke(self,row:SessionRecord)->None:row.revoked_at=datetime.now(timezone.utc);self.db.flush()
