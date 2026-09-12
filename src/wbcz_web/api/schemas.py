from __future__ import annotations
from pydantic import BaseModel,ConfigDict,Field
from wbcz_web.services.control import OperationMode
class StrictModel(BaseModel):model_config=ConfigDict(extra="forbid")
class LoginRequest(StrictModel):
 username:str=Field(min_length=1,max_length=128)
 password:str=Field(min_length=1,max_length=1024)
class ControlRequest(StrictModel):
 mode:OperationMode=OperationMode.CONTROL
 event_ids:list[str]|None=None
class PreviewRequest(StrictModel):
 import_id:str
 mode:OperationMode
 event_ids:list[str]
