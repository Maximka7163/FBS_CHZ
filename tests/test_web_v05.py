from __future__ import annotations
from io import BytesIO
import os
import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook
from sqlalchemy import create_engine,select
from sqlalchemy.orm import sessionmaker
from wbcz_web.auth import hash_password
from wbcz_web.config import WebConfig
from wbcz_web.main import create_app
from wbcz_web.models import Base,User
from wbcz_web.services.authorization import BootstrapService
DB_URL=os.getenv("WBCZ_TEST_DATABASE_URL")
pytestmark=pytest.mark.skipif(not DB_URL,reason="WBCZ_TEST_DATABASE_URL requires PostgreSQL")
HEADERS=["№ задания","Стикер","КИЗ","Номер чека","Стоимость","Валюта","Номер фискального накопителя","Дата","Тип операции","Признак продажи юрлицу"]
def make_xlsx(rows,sheet="КИЗ"):
 wb=Workbook();ws=wb.active;ws.title=sheet;ws.append(HEADERS)
 for x in rows:ws.append(x)
 b=BytesIO();wb.save(b);return b.getvalue()
def row(n,op="Продажа",dated=True,kiz=None):return [f"T{n}",f"S{n}",kiz or f"KIZ-{n:04d}",f"CHK-{n}" if dated else None,100,"RUB",f"FN-{n}" if dated else None,f"12:00:00 {((n-1)%28)+1:02d}.08.2026" if dated else None,op,"нет"]
def regression_xlsx():
 rows=[];n=0
 for _ in range(13):n+=1;rows.append(row(n,"Продажа",False))
 for _ in range(63):n+=1;rows.append(row(n,"Продажа",True))
 for _ in range(137):n+=1;rows.append(row(n,"Возврат",False))
 for _ in range(3):n+=1;rows.append(row(n,"Возврат",True))
 for _ in range(2):n+=1;rows.append(row(n,"Возврат",True))
 for _ in range(20):n+=1;rows.append(row(n,"Возврат",False))
 assert n==238;return make_xlsx(rows)
@pytest.fixture()
def env():
 engine=create_engine(DB_URL,future=True);Base.metadata.drop_all(engine);Base.metadata.create_all(engine);factory=sessionmaker(bind=engine,expire_on_commit=False);cfg=WebConfig(DB_URL,"1234567890","test",3600,False);app=create_app(cfg,session_factory=factory)
 with factory() as db:BootstrapService(db).bootstrap(username="owner",password="very-secure-password",organisation_name="Regression Org",participant_inn="1234567890");db.commit()
 with TestClient(app) as client:yield client,factory
 Base.metadata.drop_all(engine);engine.dispose()
def csrf(c):return c.get("/api/auth/csrf").json()["csrf_token"]
def auth(c):
 t=csrf(c);r=c.post("/api/auth/login",json={"username":"owner","password":"very-secure-password"},headers={"X-CSRF-Token":t});assert r.status_code==200
 scopes=c.get("/api/security/scopes");assert scopes.status_code==200 and scopes.json()["scopes"]
 target=scopes.json()["scopes"][0]
 sw=c.post("/api/security/scope",json={"organisation_id":target["organisation_id"],"participant_id":target["participants"][0]["id"]},headers={"X-CSRF-Token":t});assert sw.status_code==200
 return t
def upload(c,t,data,name="wb.xlsx"):return c.post("/api/files",files={"file":(name,data,"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},headers={"X-CSRF-Token":t})
def test_login_success(env):
 c,_=env;t=csrf(c);r=c.post("/api/auth/login",json={"username":"owner","password":"very-secure-password"},headers={"X-CSRF-Token":t});assert r.status_code==200 and r.json()["username"]=="owner"
def test_csrf_clears_stale_session_cookie_and_allows_relogin(env):
 c,_=env
 c.cookies.set("wbcz_session","stale-session-token")
 t=csrf(c)
 assert c.cookies.get("wbcz_session") is None
 r=c.post("/api/auth/login",json={"username":"owner","password":"very-secure-password"},headers={"X-CSRF-Token":t})
 assert r.status_code==200 and r.json()["username"]=="owner"
 assert c.get("/api/me").status_code==200
def test_wrong_login_denied(env):
 c,_=env;t=csrf(c);assert c.post("/api/auth/login",json={"username":"owner","password":"wrong"},headers={"X-CSRF-Token":t}).status_code==401
def test_no_registration_endpoint(env):
 c,_=env;assert c.post("/api/auth/register",json={}).status_code==404;assert c.post("/register",json={}).status_code==404;assert c.post("/signup",json={}).status_code==404
def test_disabled_user_denied(env):
 c,f=env;auth(c);assert c.get("/api/me").status_code==200
 with f() as db:u=db.scalar(select(User).where(User.username=="owner"));u.is_active=False;db.commit()
 assert c.get("/api/me").status_code==401
def test_session_required(env):c,_=env;assert c.get("/api/files").status_code==401
def test_logout_invalidates_session(env):
 c,_=env;t=auth(c);assert c.post("/api/auth/logout",headers={"X-CSRF-Token":t}).status_code==200;assert c.get("/api/me").status_code==401
def test_csrf_required(env):
 c,_=env;csrf(c);assert c.post("/api/auth/login",json={"username":"owner","password":"very-secure-password"}).status_code==403
def test_password_hash_not_plaintext(env):
 _,f=env
 with f() as db:u=db.scalar(select(User).where(User.username=="owner"));assert u.password_hash!="very-secure-password" and u.password_hash.startswith("$argon2id$")
def test_upload_valid_wb_file(env):
 c,_=env;t=auth(c);r=upload(c,t,make_xlsx([row(1),row(2,"Возврат",False)]));assert r.status_code==200;assert r.json()["row_count"]==2 and r.json()["unique_kiz"]==2
def test_wrong_sheet_rejected(env):
 c,_=env;t=auth(c);r=upload(c,t,make_xlsx([row(1)],sheet="Sheet1"));assert r.status_code==400 and "КИЗ" in r.json()["detail"]
def test_duplicate_import_preserved(env):
 c,_=env;t=auth(c);data=make_xlsx([row(1),row(2)]);a=upload(c,t,data).json();b=upload(c,t,data).json();assert a["new_events"]==2;assert b["repeated"] is True and b["new_events"]==0 and b["duplicate_events"]==2
def test_238_event_regression_preserved(env):
 c,_=env;t=auth(c);b=upload(c,t,regression_xlsx()).json();assert {k:b[k] for k in ("row_count","unique_kiz","sales","returns","dated","undated","rejected_rows")}=={"row_count":238,"unique_kiz":238,"sales":76,"returns":162,"dated":68,"undated":170,"rejected_rows":0}
def test_decisions_match_backend_core(env):
 c,_=env;t=auth(c);imp=upload(c,t,regression_xlsx()).json();r=c.post(f"/api/files/{imp['id']}/control",json={"mode":"CONTROL","event_ids":None},headers={"X-CSRF-Token":t});assert r.status_code==200;assert r.json()["counts"]=={"MANUAL_REVIEW":159,"READY_TO_WITHDRAW":51,"ALREADY_DONE":20,"ERROR":5,"READY_TO_RETURN":3}
 ev=c.get(f"/api/files/{imp['id']}/events").json();p=c.post("/api/operation-preview",json={"import_id":imp["id"],"mode":"AUTO","event_ids":[x["event_id"] for x in ev]},headers={"X-CSRF-Token":t});assert {k:p.json()[k] for k in ("eligible_count","withdraw_count","return_count","excluded_count")}=={"eligible_count":54,"withdraw_count":51,"return_count":3,"excluded_count":184}
def test_frontend_cannot_override_decision(env):
 c,_=env;t=auth(c);imp=upload(c,t,make_xlsx([row(1)])).json();assert c.post(f"/api/files/{imp['id']}/control",json={"mode":"CONTROL","event_ids":None,"decision":"READY_TO_WITHDRAW"},headers={"X-CSRF-Token":t}).status_code==422
def test_control_cannot_submit(env):
 c,_=env;t=auth(c);imp=upload(c,t,make_xlsx([row(1)])).json();assert c.post("/api/operation-preview",json={"import_id":imp["id"],"mode":"CONTROL","event_ids":[]},headers={"X-CSRF-Token":t}).status_code==400;assert c.post("/api/submit",headers={"X-CSRF-Token":t}).status_code==404
def test_capabilities_writes_disabled(env):
 c,_=env;auth(c);assert c.get("/api/capabilities").json()=={"true_api":"offline-dry-run","true_api_write":False,"document_signing":False,"submission":False,"windows_bridge":False,"registration":False,"printing":False,"print_execution":False,"suz_full_km_remote_acquisition":False}
def test_no_production_true_api_network_route(env):
 c,_=env;t=auth(c);assert c.post("/api/true-api/cises/info",json={},headers={"X-CSRF-Token":t}).status_code==404;assert c.post("/api/lk/documents/create",json={},headers={"X-CSRF-Token":t}).status_code==404
def test_event_history_preserved(env):
 c,_=env;t=auth(c);imp=upload(c,t,make_xlsx([row(1,"Продажа",False,"SAME-KIZ"),row(2,"Возврат",False,"SAME-KIZ")])).json();events=c.get(f"/api/files/{imp['id']}/events").json();d=c.get(f"/api/events/{events[0]['event_id']}").json();assert len(d["history"])==2 and d["history_order_ambiguous"] is True
