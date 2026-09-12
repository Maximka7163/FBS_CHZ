from __future__ import annotations
from collections import Counter
from dataclasses import asdict
from enum import StrEnum
from sqlalchemy.orm import Session
from wbcz.control_engine import decide
from wbcz.models import Decision,Outcome
from wbcz_web.models import CheckRecord,ControlRun,PreviewItem,PreviewRecord
from wbcz_web.repositories import AuditRepository,ImportRepository
from .imports import record_to_event
from .mock_true_api import DeterministicMockTrueApi
class OperationMode(StrEnum):AUTO="AUTO";CONTROL="CONTROL";WITHDRAW_ONLY="WITHDRAW_ONLY";RETURN_ONLY="RETURN_ONLY"
_REASON_TEXT={"NOT_CHECKED":"Событие ещё не проверено","OWNER_MISMATCH":"Владелец КИЗ не совпадает с выбранной организацией","OWNER_UNKNOWN":"Владелец КИЗ не определён","SALE_RECEIPT_MISSING":"Продажа без данных чека — автоматический вывод отключён","RETURN_RECEIPT_MISSING":"Возврат без данных чека — автоматический возврат отключён","WRONG_PRODUCT_GROUP":"КИЗ относится к другой товарной группе","UNKNOWN_CHZ_STATUS":"Неизвестное состояние Честного знака","NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL":"Причина выбытия требует ручной проверки","LEGAL_ENTITY_RULES_UNDEFINED":"Требуется ручная проверка правила продажи","STATE_LOOKUP_OR_NORMALIZATION_FAILED":"Не удалось получить состояние КИЗ","SALE_ALREADY_WITHDRAWN_DISTANCE":"Операция уже не требуется","RETURN_ALREADY_IN_CIRCULATION":"Операция уже не требуется","HISTORY_ORDER_AMBIGUOUS":"История событий КИЗ неоднозначна","MODE_REQUIRES_RETURN":"По текущему состоянию требуется возврат в оборот","MODE_REQUIRES_WITHDRAW":"По текущему состоянию требуется вывод из оборота"}
class ControlService:
 def __init__(self,db:Session,own_inn:str)->None:self.db=db;self.own_inn=own_inn;self.imports=ImportRepository(db);self.audit=AuditRepository(db)
 def run(self,import_id:str,user_id:int,mode:OperationMode,event_ids:list[str]|None=None)->dict:
  if self.imports.get(import_id) is None:raise KeyError("Импорт не найден")
  ordered=self.imports.ordered_event_records(import_id);allowed=[r.event_id for r in ordered];aset=set(allowed)
  if event_ids is None:selected=allowed
  else:
   requested=list(dict.fromkeys(event_ids))
   if not requested:raise ValueError("Не выбран ни один КИЗ")
   if any(x not in aset for x in requested):raise ValueError("КИЗ не относится к выбранному импорту")
   wanted=set(requested);selected=[x for x in allowed if x in wanted]
  provider=DeterministicMockTrueApi((record_to_event(r) for r in ordered),self.own_inn);run=ControlRun(import_id=import_id,user_id=user_id,mode=mode.value,provider="mock-v04-deterministic");self.db.add(run);self.db.flush();outcomes=[]
  for eid in selected:
   row=self.imports.event(eid);event=record_to_event(row);snapshot=None
   try:snapshot=provider.get_ki_state(event.kiz);outcome=decide(event,snapshot,self.own_inn)
   except Exception as exc:outcome=Outcome(Decision.ERROR,"STATE_LOOKUP_OR_NORMALIZATION_FAILED",f"{type(exc).__name__}: {exc}"[:2000])
   if self.imports.history_order_ambiguous(event.kiz):snapshot=None;outcome=Outcome(Decision.MANUAL_REVIEW,"HISTORY_ORDER_AMBIGUOUS")
   self.db.add(CheckRecord(run_id=run.id,event_id=eid,source="mock-v04-deterministic",snapshot=asdict(snapshot) if snapshot else None,decision=outcome.decision.value,reason=outcome.reason,error=outcome.error));outcomes.append(outcome)
  self.db.flush();counts=Counter(x.decision.value for x in outcomes);reasons=Counter(x.reason for x in outcomes);self.audit.append("CONTROL_RUN",user_id=user_id,entity_type="control_run",entity_id=run.id,metadata={"import_id":import_id,"mode":mode.value,"checked":len(outcomes)});return {"run_id":run.id,"provider":"mock","mode":mode.value,"checked":len(outcomes),"counts":dict(counts),"reasons":dict(reasons),"production_submission_available":False}
 def preview(self,import_id:str,user_id:int,mode:OperationMode,event_ids:list[str])->dict:
  if mode is OperationMode.CONTROL:raise ValueError("CONTROL — только проверка, operation preview недоступен")
  allowed=set(self.imports.import_event_ids(import_id));selected=list(dict.fromkeys(event_ids))
  if not selected:raise ValueError("Не выбран ни один КИЗ")
  if any(x not in allowed for x in selected):raise ValueError("КИЗ не относится к выбранному импорту")
  included=[];excluded=[];snap=[]
  for eid in selected:
   event=self.imports.event(eid);check=self.imports.latest_check(eid);decision=check.decision if check else None;eligible=False;reason=None
   if mode is OperationMode.AUTO:eligible=decision in {Decision.READY_TO_WITHDRAW.value,Decision.READY_TO_RETURN.value}
   elif mode is OperationMode.WITHDRAW_ONLY:eligible=decision==Decision.READY_TO_WITHDRAW.value;reason="MODE_REQUIRES_RETURN" if decision==Decision.READY_TO_RETURN.value else None
   else:eligible=decision==Decision.READY_TO_RETURN.value;reason="MODE_REQUIRES_WITHDRAW" if decision==Decision.READY_TO_WITHDRAW.value else None
   item={"event_id":eid,"kiz":event.kiz,"operation":event.operation,"decision":decision}
   if eligible:included.append(item)
   else:reason=reason or (check.reason if check else "NOT_CHECKED");item.update({"reason":reason,"reason_text":_REASON_TEXT.get(reason,reason)});excluded.append(item)
   snap.append((eid,eligible,decision,reason))
  withdraw=sum(x["decision"]==Decision.READY_TO_WITHDRAW.value for x in included);returns=sum(x["decision"]==Decision.READY_TO_RETURN.value for x in included);p=PreviewRecord(import_id=import_id,user_id=user_id,mode=mode.value,selected_count=len(selected),eligible_count=len(included),withdraw_count=withdraw,return_count=returns,excluded_count=len(excluded));self.db.add(p);self.db.flush()
  for eid,inc,d,r in snap:self.db.add(PreviewItem(preview_id=p.id,event_id=eid,included=inc,decision=d,reason=r))
  self.audit.append("PREVIEW_CREATED",user_id=user_id,entity_type="preview",entity_id=p.id,metadata={"import_id":import_id,"mode":mode.value,"selected":len(selected)});return {"preview_id":p.id,"mode":mode.value,"selected_count":len(selected),"eligible_count":len(included),"withdraw_count":withdraw,"return_count":returns,"excluded_count":len(excluded),"included":included,"excluded":excluded,"provider":"mock","production_submission_available":False}
def event_view(db,row,latest_check=None)->dict:
 event=record_to_event(row);return {"event_id":row.event_id,**event.to_dict(),"decision":latest_check.decision if latest_check else None,"reason":latest_check.reason if latest_check else None,"reason_text":_REASON_TEXT.get(latest_check.reason,latest_check.reason) if latest_check else None,"error":latest_check.error if latest_check else None,"checked_at":latest_check.checked_at.isoformat() if latest_check and latest_check.checked_at else None}
