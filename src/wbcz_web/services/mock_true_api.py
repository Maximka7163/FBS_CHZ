from __future__ import annotations
from collections import Counter
from collections.abc import Iterable
from wbcz.models import Event,KiState,Operation
from wbcz.true_api import TrueApiError
class DeterministicMockTrueApi:
 def __init__(self,ordered_events:Iterable[Event],own_inn:str)->None:
  ctr=Counter();self._states={};self.calls=[]
  for event in ordered_events:
   ctr[event.operation]+=1;n=ctr[event.operation]
   if event.operation is Operation.SALE:
    state=KiState("IN_CIRCULATION",ownerInn=own_inn,productGroup="lp") if n<=64 else KiState("WITHDRAWN",withdrawReason="DISTANCE",ownerInn=own_inn,productGroup="lp") if n<=72 else KiState("IN_CIRCULATION",ownerInn="9876543210",productGroup="lp") if n<=75 else TrueApiError("OFFLINE_TEST_STATE_UNAVAILABLE")
   else:
    state=KiState("WITHDRAWN",withdrawReason="DISTANCE",ownerInn=own_inn,productGroup="lp") if n<=140 else KiState("IN_CIRCULATION",ownerInn=own_inn,productGroup="lp") if n<=152 else KiState("WITHDRAWN",withdrawReason="OTHER",ownerInn=own_inn,productGroup="lp") if n<=158 else TrueApiError("OFFLINE_TEST_STATE_UNAVAILABLE")
   self._states[event.kiz]=state
 def get_ki_state(self,kiz:str)->KiState:
  self.calls.append(kiz);state=self._states.get(kiz)
  if state is None:raise TrueApiError("Для КИЗ отсутствует mock-состояние")
  if isinstance(state,Exception):raise state
  return state
