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


class ReferenceParticipantsRequest(StrictModel):
    inns: list[str] = Field(min_length=1, max_length=100)


class ReferenceModsRequest(StrictModel):
    productGroups: list[str] = Field(default_factory=lambda: ["lp"], min_length=1)
    kpp: str | None = None
    fiasId: str | None = None
    inns: list[str] | None = Field(default=None, max_length=10)
    limit: int = Field(default=100, ge=1, le=1000)
    page: int = Field(default=0, ge=0)


class ReferenceModValidateRequest(StrictModel):
    inn: str
    kpp: str | None = None
    fiasId: str | None = None


class ReferenceTnVedRequest(StrictModel):
    pg: str | None = None
    tnveds: list[str] | None = None
    page: int | None = Field(default=None, ge=0)
    limit: int | None = Field(default=None, ge=1, le=1000)
    sort: str | None = None
    direction: str | None = None


class ReferenceProductGtinRequest(StrictModel):
    includeSubaccount: bool = False
    limit: int = Field(default=10, ge=1, le=10000)
    page: int = Field(default=0, ge=0)


class ReferenceRdDocument(StrictModel):
    type: str
    number: str
    dateFrom: str | None = None


class ReferenceRdListRequest(StrictModel):
    documents: list[ReferenceRdDocument] = Field(min_length=1, max_length=25)
