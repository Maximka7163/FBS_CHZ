from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from wbcz_web.services.control import OperationMode


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class ControlRequest(StrictModel):
    mode: OperationMode = OperationMode.CONTROL
    event_ids: list[str] | None = None


class PreviewRequest(StrictModel):
    import_id: str
    mode: OperationMode
    event_ids: list[str]


class BulkActionRequest(StrictModel):
    confirm: Literal[True]


class CisInventoryCisesRequest(StrictModel):
    cises: list[str] = Field(min_length=1, max_length=1000)


class CisInventorySingleRequest(StrictModel):
    cis: str = Field(min_length=18, max_length=74)


class CisInventorySearchRequest(StrictModel):
    filter: dict[str, Any]
    pagination: dict[str, Any] | None = None


class CisInventoryProductRequest(StrictModel):
    gtins: list[str] = Field(min_length=1, max_length=1000)
    rdInfo: bool = False
