from __future__ import annotations
from collections import Counter
from dataclasses import asdict
from pathlib import Path
import sqlite3, tempfile
from enum import StrEnum
from typing import Any, Callable, Iterable
from wbcz.event_store import EventStore
from wbcz.models import Decision, Event, KiState, Operation, Outcome
from wbcz.service import DryRunService, ImportService
from wbcz.true_api import FakeTrueApiClient, TrueApiError
from .live_true_api import LiveAuthorizationRequired, LiveReadOnlyConfig, LiveTrueApiClient

OWN_INN="1234567890"
class OperationMode(StrEnum): AUTO="AUTO"; CONTROL="CONTROL"; WITHDRAW_ONLY="WITHDRAW_ONLY"; RETURN_ONLY="RETURN_ONLY"
_REASON_TEXT={"NOT_CHECKED":"Событие ещё не проверено","OWNER_MISMATCH":"Владелец КИЗ не совпадает с выбранной организацией","OTHER_OWNER":"Владелец КИЗ не совпадает с выбранной организацией","OWNER_UNKNOWN":"Владелец КИЗ не определён","SALE_RECEIPT_MISSING":"Продажа без данных чека — автоматический вывод отключён","RETURN_RECEIPT_MISSING":"Возврат без данных чека — автоматический возврат отключён","WRONG_PRODUCT_GROUP":"КИЗ относится к другой товарной группе","UNKNOWN_CHZ_STATUS":"Неизвестное состояние Честного знака","NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL":"Причина выбытия требует ручной проверки","UNKNOWN_STATUS":"Неизвестное состояние КИЗ","UNKNOWN_OR_CONFLICTING_STATUS_EX":"Состояние КИЗ требует ручной проверки","INCONSISTENT_WITHDRAW_REASON":"Противоречивое состояние выбытия","LEGAL_ENTITY_RULES_UNDEFINED":"Требуется ручная проверка правила продажи","STATE_LOOKUP_OR_NORMALIZATION_FAILED":"Не удалось получить состояние КИЗ","SALE_ALREADY_WITHDRAWN_DISTANCE":"Операция уже не требуется","RETURN_ALREADY_IN_CIRCULATION":"Операция уже не требуется","HISTORY_ORDER_AMBIGUOUS":"История событий КИЗ неоднозначна","MODE_REQUIRES_RETURN":"По текущему состоянию требуется возврат в оборот","MODE_REQUIRES_WITHDRAW":"По текущему состоянию требуется вывод из оборота"}
def _event_dict(e:Event): return {"event_id":e.event_id,**e.to_dict()}

class UiApplication:
    def __init__(self,db_path:str|Path,live_config:LiveReadOnlyConfig|None=None,live_client_factory:Callable[[LiveReadOnlyConfig],LiveTrueApiClient]|None=None):
        self.db_path=Path(db_path); self.live_config=live_config or LiveReadOnlyConfig.from_env(); self._live_client_factory=live_client_factory or LiveTrueApiClient.from_config; self._live_client=None
    def runtime_status(self):
        live=self.live_config.enabled; client=self._live_client
        return {"mode":"live-read-only" if live else "offline-dry-run","true_api":live,"auth_signing":live,"signing":False,"document_signing":False,"submission":False,"product_group":"lp","tls_preflight_ok":bool(client is not None and getattr(client,"preflight_ok",False)),"authenticated":bool(client is not None and getattr(client,"authenticated",False)),"auth_expire_date":client.expire_date.isoformat() if client is not None and getattr(client,"expire_date",None) is not None else None,"activity_location_configured":self.live_config.activity_location is not None,"activity_location_type":self.live_config.activity_location.kind if self.live_config.activity_location else None}
    def _require_live_client(self):
        if not self.live_config.enabled: raise ValueError("LIVE READ-ONLY mode is not enabled")
        if self._live_client is None: self._live_client=self._live_client_factory(self.live_config)
        return self._live_client
    def live_preflight(self):
        result=self._require_live_client().preflight(); return {**result,"mode":"live-read-only","message":"CryptoPro TLS доступен. Production True API доступен. Сертификат УКЭП проверен. Challenge получен."}
    def live_authenticate(self):
        result=self._require_live_client().authenticate(); return {**result,"mode":"live-read-only","message":"Авторизация успешна. Отправка документов отключена."}
    def import_bytes(self,filename:str,data:bytes):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/(Path(filename).name or "upload.xlsx");p.write_bytes(data)
            with EventStore(self.db_path) as store:
                r=ImportService(store).import_file(p); s=self._import_summary(store,r.fingerprint);s.update(asdict(r));return s
    def list_imports(self,limit:int=10):
        if not self.db_path.exists():return []
        c=sqlite3.connect(self.db_path);c.row_factory=sqlite3.Row
        try:
            rows=c.execute("""SELECT a.created_at,a.action,a.entity_id AS fingerprint,i.filename,i.imported_at,i.state,i.new_events,i.duplicate_events,i.rejected_rows,COUNT(ir.row_number) row_count,COUNT(DISTINCT e.kiz) unique_kiz FROM audit_log a JOIN imports i ON i.fingerprint=a.entity_id LEFT JOIN import_rows ir ON ir.fingerprint=i.fingerprint LEFT JOIN events e ON e.event_id=ir.event_id WHERE a.action IN ('IMPORT_COMPLETED','IMPORT_REPEATED') GROUP BY a.id ORDER BY a.id DESC LIMIT ?""",(limit,)).fetchall();out=[]
            for r in rows:
                rep=r["action"]=="IMPORT_REPEATED";out.append({"fingerprint":r["fingerprint"],"filename":r["filename"],"uploaded_at":r["created_at"],"status":"error" if r["rejected_rows"] else "processed","repeated":rep,"new_events":0 if rep else r["new_events"],"duplicate_events":r["new_events"]+r["duplicate_events"] if rep else r["duplicate_events"],"rejected_rows":r["rejected_rows"],"row_count":r["row_count"],"unique_kiz":r["unique_kiz"]})
            return out
        finally:c.close()
    def get_import(self,fp):
        with EventStore(self.db_path) as s:return self._import_summary(s,fp)
    def _import_summary(self,s,fp):
        row=s._connection.execute("SELECT * FROM imports WHERE fingerprint=?",(fp,)).fetchone()
        if row is None:raise KeyError
        st=s._connection.execute("""SELECT COUNT(ir.row_number) row_count,COUNT(ir.event_id) event_count,COUNT(DISTINCT e.kiz) unique_kiz,SUM(CASE WHEN e.operation='Продажа' THEN 1 ELSE 0 END) sales,SUM(CASE WHEN e.operation='Возврат' THEN 1 ELSE 0 END) returns,SUM(CASE WHEN e.occurred_at IS NOT NULL THEN 1 ELSE 0 END) dated,SUM(CASE WHEN e.occurred_at IS NULL AND ir.event_id IS NOT NULL THEN 1 ELSE 0 END) undated FROM import_rows ir LEFT JOIN events e ON e.event_id=ir.event_id WHERE ir.fingerprint=?""",(fp,)).fetchone()
        return {"fingerprint":fp,"filename":row["filename"],"uploaded_at":row["imported_at"],"status":"error" if row["rejected_rows"] else "processed","new_events":row["new_events"],"duplicate_events":row["duplicate_events"],"rejected_rows":row["rejected_rows"],**{k:st[k] or 0 for k in ("row_count","event_count","unique_kiz","sales","returns","dated","undated")}}
    def _event_ids_for_import(self,s,fp): return [r["event_id"] for r in s._connection.execute("SELECT event_id FROM import_rows WHERE fingerprint=? AND event_id IS NOT NULL ORDER BY row_number",(fp,)).fetchall()]
    def events_for_import(self,fp):
        import json
        with EventStore(self.db_path) as s:
            rows=s._connection.execute("SELECT e.payload_json,MIN(ir.row_number) first_row FROM import_rows ir JOIN events e ON e.event_id=ir.event_id WHERE ir.fingerprint=? GROUP BY e.event_id ORDER BY first_row",(fp,)).fetchall();events=[Event.from_dict(json.loads(r["payload_json"])) for r in rows];pre={r["event_id"]:r for r in s.previews()};return [self._event_view(s,e,pre.get(e.event_id)) for e in events]
    def event_detail(self,event_id):
        with EventStore(self.db_path) as s:
            e=s.get_event(event_id);checks=s.checks(event_id);d=self._event_view(s,e,checks[-1] if checks else None);d["history"]=[_event_dict(x) for x in s.events(e.kiz)];d["history_order_ambiguous"]=s.history_order_ambiguous(e.kiz);return d
    def _event_view(self,s,e,check):
        r=_event_dict(e);r["decision"]=check["decision"] if check else None;r["reason"]=check["reason"] if check else None;r["reason_text"]=_REASON_TEXT.get(check["reason"],check["reason"]) if check else None;r["error"]=check["error"] if check else None;r["checked_at"]=check["checked_at"] if check else None;return r
    def _offline_responses(self,events:Iterable[Event]):
        ctr=Counter();out={}
        for e in events:
            ctr[e.operation]+=1;n=ctr[e.operation]
            if e.operation is Operation.SALE:
                out[e.kiz]=KiState("IN_CIRCULATION",ownerInn=OWN_INN,productGroup="lp") if n<=64 else KiState("WITHDRAWN",withdrawReason="DISTANCE",ownerInn=OWN_INN,productGroup="lp") if n<=72 else KiState("IN_CIRCULATION",ownerInn="9876543210",productGroup="lp") if n<=75 else TrueApiError("OFFLINE_TEST_STATE_UNAVAILABLE")
            else:
                out[e.kiz]=KiState("WITHDRAWN",withdrawReason="DISTANCE",ownerInn=OWN_INN,productGroup="lp") if n<=140 else KiState("IN_CIRCULATION",ownerInn=OWN_INN,productGroup="lp") if n<=152 else KiState("WITHDRAWN",withdrawReason="OTHER",ownerInn=OWN_INN,productGroup="lp") if n<=158 else TrueApiError("OFFLINE_TEST_STATE_UNAVAILABLE")
        return out
    def check_import(self,fp,event_ids=None):
        with EventStore(self.db_path) as s:
            all_ids=self._event_ids_for_import(s,fp);allowed=set(all_ids)
            if event_ids is None:ids=all_ids
            else:
                if not event_ids:raise ValueError
                requested=list(dict.fromkeys(event_ids));
                if any(x not in allowed for x in requested):raise ValueError
                rs=set(requested);ids=[x for x in all_ids if x in rs]
            ev=[s.get_event(x) for x in ids]
            if self.live_config.enabled:
                client=self._require_live_client()
                if not getattr(client,"authenticated",False): raise LiveAuthorizationRequired("Complete LIVE READ-ONLY authorization before checking KIZ")
                client.prime(e.kiz for e in ev);inn=self.live_config.participant_inn;source="true-api-v726-live-read-only";provider="live-read-only"
            else:
                client=FakeTrueApiClient(self._offline_responses(ev));inn=OWN_INN;source="offline-ui";provider="offline-dry-run"
            runner=DryRunService(s,client,inn,source=source);results=[]
            for e in ev:
                res=runner.check_event(e.event_id)
                if s.history_order_ambiguous(e.kiz):res=s.save_check(e.event_id,None,Outcome(Decision.MANUAL_REVIEW,"HISTORY_ORDER_AMBIGUOUS"),source=source+"-history-guard")
                results.append(res)
            response={"provider":provider,"checked":len(results),"counts":dict(Counter(x.outcome.decision.value for x in results)),"reasons":dict(Counter(x.outcome.reason for x in results)),"production_submission_available":False}
            if self.live_config.enabled and len(results)==1:
                import json
                e=ev[0]; normalized={}
                for check in reversed(s.checks(e.event_id)):
                    if check.get("snapshot_json"): normalized=json.loads(check["snapshot_json"]); break
                final=results[0].outcome
                response["diagnostics"]={"kiz":e.kiz,"status":normalized.get("status"),"statusEx":normalized.get("statusEx"),"withdrawReason":normalized.get("withdrawReason"),"ownerInn":normalized.get("ownerInn"),"owner_match":normalized.get("ownerInn")==inn if normalized.get("ownerInn") else None,"productGroup":normalized.get("productGroup"),"decision":final.decision.value,"reason":final.reason,"error":final.error}
            return response
    def operation_preview(self,event_ids,mode=OperationMode.AUTO,import_id=None):
        mode=OperationMode(mode)
        if mode is OperationMode.CONTROL:raise ValueError("CONTROL is read-only and has no operation preview")
        with EventStore(self.db_path) as s:
            if import_id is not None:
                allowed={r["event_id"] for r in s._connection.execute("SELECT event_id FROM import_rows WHERE fingerprint=? AND event_id IS NOT NULL",(import_id,)).fetchall()}
                if any(x not in allowed for x in event_ids):raise ValueError
            previews={r["event_id"]:r for r in s.previews()};inc=[];exc=[]
            for eid in event_ids:
                e=s.get_event(eid);p=previews.get(eid);d=p["decision"] if p else None;item={"event_id":eid,"kiz":e.kiz,"operation":e.operation.value,"decision":d};eligible=False;reason=None
                if mode is OperationMode.AUTO:eligible=d in {Decision.READY_TO_WITHDRAW.value,Decision.READY_TO_RETURN.value}
                elif mode is OperationMode.WITHDRAW_ONLY:eligible=d==Decision.READY_TO_WITHDRAW.value;reason="MODE_REQUIRES_RETURN" if d==Decision.READY_TO_RETURN.value else None
                else:eligible=d==Decision.READY_TO_RETURN.value;reason="MODE_REQUIRES_WITHDRAW" if d==Decision.READY_TO_WITHDRAW.value else None
                if eligible:inc.append(item)
                else:
                    reason=reason or (p["reason"] if p else "NOT_CHECKED");item["reason"]=reason;item["reason_text"]=_REASON_TEXT.get(reason,reason);exc.append(item)
            w=sum(x["decision"]==Decision.READY_TO_WITHDRAW.value for x in inc);r=sum(x["decision"]==Decision.READY_TO_RETURN.value for x in inc)
            return {"mode":mode.value,"selected_count":len(event_ids),"eligible_count":len(inc),"withdraw_count":w,"return_count":r,"excluded_count":len(exc),"included":inc,"excluded":exc,"provider":"live-read-only" if self.live_config.enabled else "offline-dry-run","production_submission_available":False,"selected":len(event_ids),"withdraw":w,"returns":r}
