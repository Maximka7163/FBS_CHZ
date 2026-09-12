from __future__ import annotations
import argparse,getpass,sys
from sqlalchemy.exc import IntegrityError
from .auth import hash_password
from .config import WebConfig
from .db import build_session_factory
from .models import User
from .repositories import AuditRepository,UserRepository

def _create_user(args,db)->int:
 username=args.username.strip()
 if not username:print("Username is required",file=sys.stderr);return 2
 password=getpass.getpass("Password: ");confirm=getpass.getpass("Confirm password: ")
 if password!=confirm:print("Passwords do not match",file=sys.stderr);return 2
 try:
  user=User(username=username,password_hash=hash_password(password),is_active=True,is_admin=bool(args.admin));db.add(user);db.flush();AuditRepository(db).append("USER_CREATED",user_id=user.id,entity_type="user",entity_id=str(user.id),metadata={"username":username,"is_admin":user.is_admin});db.commit()
 except (ValueError,IntegrityError) as exc:db.rollback();print(f"Cannot create user: {exc}",file=sys.stderr);return 2
 print(f"Created user {username} (id={user.id}, admin={user.is_admin})");return 0
def _disable_user(args,db)->int:
 user=UserRepository(db).by_username(args.username.strip())
 if user is None:print("User not found",file=sys.stderr);return 2
 if not user.is_active:print("User is already disabled");return 0
 user.is_active=False;AuditRepository(db).append("USER_DISABLED",user_id=user.id,entity_type="user",entity_id=str(user.id),metadata={"username":user.username});db.commit();print(f"Disabled user {user.username}");return 0
def _list_users(args,db)->int:
 for user in UserRepository(db).list_all():print(f"{user.id}\t{user.username}\tactive={user.is_active}\tadmin={user.is_admin}\tcreated={user.created_at.isoformat() if user.created_at else ''}")
 return 0
def main()->None:
 p=argparse.ArgumentParser(description="WBCZ web admin CLI");s=p.add_subparsers(dest="command",required=True);c=s.add_parser("create-user");c.add_argument("username");c.add_argument("--admin",action="store_true");d=s.add_parser("disable-user");d.add_argument("username");s.add_parser("list-users");a=p.parse_args();db=build_session_factory(WebConfig.from_env())()
 try:code=_create_user(a,db) if a.command=="create-user" else _disable_user(a,db) if a.command=="disable-user" else _list_users(a,db)
 finally:db.close()
 raise SystemExit(code)
if __name__=="__main__":main()
