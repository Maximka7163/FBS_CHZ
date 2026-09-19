from sqlalchemy import func,select
from .base import Repository
from wbcz_web.models import User
class UserRepository(Repository):
    def by_username(self,username:str)->User|None:return self.db.scalar(select(User).where(func.lower(User.username)==username.strip().casefold()))
    def by_id(self,user_id:int)->User|None:return self.db.get(User,user_id)
    def list_all(self)->list[User]:return list(self.db.scalars(select(User).order_by(User.id)))
