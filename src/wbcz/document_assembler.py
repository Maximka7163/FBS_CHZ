from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
import hashlib
import re
from typing import Any, Callable, Mapping

from wbcz.control_engine import validate_owner_inn
from wbcz.models import Decision, Event, Operation
from wbcz.write_pipeline import ExactDocument, ExactDocumentBuilder, InvalidWriteOperation


class DocumentAssemblyManualReview(InvalidWriteOperation):
    """A business document cannot be assembled without inventing required data."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class OrganisationType(StrEnum):
    LEGAL_ENTITY = "LEGAL_ENTITY"
    INDIVIDUAL_ENTREPRENEUR = "INDIVIDUAL_ENTREPRENEUR"


_FIAS_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_KPP_RE = re.compile(r"^[0-9]{9}$")
_ALLOWED_PRIMARY_TYPES = frozenset({"RECEIPT", "SALES_RECEIPT", "OTHER"})


@dataclass(frozen=True, slots=True)
class P0OrganisationConfig:
    participant_inn: str
    organisation_type: OrganisationType
    fias_id: str
    kpp: str | None = None
    remote_sale_return_paid: bool | None = None

    def __post_init__(self) -> None:
        validate_owner_inn(self.participant_inn)
        if not isinstance(self.organisation_type, OrganisationType):
            raise ValueError("organisation_type must be explicit")
        if not isinstance(self.fias_id, str) or not _FIAS_RE.fullmatch(self.fias_id):
            raise ValueError("fias_id must be a UUID")
        if self.organisation_type is OrganisationType.LEGAL_ENTITY:
            if not isinstance(self.kpp, str) or not _KPP_RE.fullmatch(self.kpp):
                raise ValueError("LEGAL_ENTITY requires a 9-digit kpp")
        elif self.kpp is not None:
            raise ValueError("INDIVIDUAL_ENTREPRENEUR must not configure kpp")
        if self.remote_sale_return_paid is not None and type(self.remote_sale_return_paid) is not bool:
            raise ValueError("remote_sale_return_paid must be boolean or unset")


@dataclass(frozen=True, slots=True)
class ReturnPrimaryDocument:
    document_type: str
    number: str
    document_date: date | datetime
    custom_name: str | None = None

    def fields(self) -> dict[str, Any]:
        document_type = self.document_type.strip().upper() if isinstance(self.document_type, str) else ""
        if document_type not in _ALLOWED_PRIMARY_TYPES:
            raise DocumentAssemblyManualReview("RETURN_PRIMARY_DOCUMENT_TYPE_INVALID")
        number = self.number.strip() if isinstance(self.number, str) else ""
        if not 1 <= len(number) <= 255:
            raise DocumentAssemblyManualReview("RETURN_PRIMARY_DOCUMENT_NUMBER_INVALID")
        value = self.document_date
        if isinstance(value, datetime):
            day = value.date()
        elif isinstance(value, date):
            day = value
        else:
            raise DocumentAssemblyManualReview("RETURN_PRIMARY_DOCUMENT_DATE_INVALID")
        result: dict[str, Any] = {
            "primary_document_type": document_type,
            "primary_document_number": number,
            "primary_document_date": day.isoformat(),
        }
        if document_type == "OTHER":
            custom = self.custom_name.strip() if isinstance(self.custom_name, str) else ""
            if not 1 <= len(custom) <= 255:
                raise DocumentAssemblyManualReview("RETURN_PRIMARY_DOCUMENT_CUSTOM_NAME_REQUIRED")
            result["primary_document_custom_name"] = custom
        elif self.custom_name not in (None, ""):
            raise DocumentAssemblyManualReview("RETURN_PRIMARY_DOCUMENT_CUSTOM_NAME_FORBIDDEN")
        return result


PrimaryDocumentProvider = Callable[[Event], ReturnPrimaryDocument | None]


class _Absent:
    pass


ABSENT = _Absent()


def schema_object(fields: Mapping[str, Any | _Absent]) -> dict[str, Any]:
    """Make ABSENT distinct from an explicit JSON null (None)."""
    return {name: value for name, value in fields.items() if value is not ABSENT}


def rubles_to_kopecks(value: Decimal) -> int:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise DocumentAssemblyManualReview("PRODUCT_COST_INVALID")
    if value < 0:
        raise DocumentAssemblyManualReview("PRODUCT_COST_NEGATIVE")
    kopecks = value * Decimal(100)
    integral = kopecks.to_integral_value()
    if kopecks != integral:
        raise DocumentAssemblyManualReview("PRODUCT_COST_SUBKOPECK")
    result = int(integral)
    if len(str(result)) > 17:
        raise DocumentAssemblyManualReview("PRODUCT_COST_TOO_LARGE")
    return result


def _event_date(event: Event) -> str:
    if event.occurred_at is None:
        raise DocumentAssemblyManualReview("WB_EVENT_DATE_REQUIRED")
    # Preserve the validated WB calendar date. yyyy-MM-dd is an official format.
    return event.occurred_at.date().isoformat()


def _normalized_event_cis(event: Event) -> str:
    value = event.kiz.strip()
    if value != event.kiz or not 18 <= len(value) <= 74:
        raise DocumentAssemblyManualReview("WB_CIS_INVALID")
    return value


def _assert_exact_document(document: ExactDocument) -> None:
    decoded = base64.b64decode(document.product_document_base64, validate=True)
    if decoded != document.bytes_for_signature:
        raise AssertionError("frozen bytes differ from product_document")
    if hashlib.sha256(decoded).hexdigest() != document.sha256:
        raise AssertionError("frozen document hash invariant failed")


class OfficialP0DocumentAssembler:
    """Pure VPS-side business JSON assembler; contains no True API transport."""

    def __init__(
        self,
        organisation: P0OrganisationConfig | None,
        *,
        primary_document_provider: PrimaryDocumentProvider | None = None,
    ) -> None:
        self.organisation = organisation
        self.primary_document_provider = primary_document_provider

    def build_exact(self, event: Event, decision: Decision) -> ExactDocument:
        if decision is Decision.READY_TO_WITHDRAW:
            if event.operation is not Operation.SALE:
                raise DocumentAssemblyManualReview("WITHDRAW_DECISION_EVENT_MISMATCH")
            document = self._lk_receipt_distance(event)
        elif decision is Decision.READY_TO_RETURN:
            if event.operation is not Operation.RETURN:
                raise DocumentAssemblyManualReview("RETURN_DECISION_EVENT_MISMATCH")
            document = self._lp_return_remote_sale(event)
        else:
            raise DocumentAssemblyManualReview("CONTROL_DECISION_NOT_WRITABLE")
        _assert_exact_document(document)
        return document

    def _organisation(self) -> P0OrganisationConfig:
        if self.organisation is None:
            raise DocumentAssemblyManualReview("ORGANISATION_CONFIG_MISSING")
        return self.organisation

    def _lk_receipt_distance(self, event: Event) -> ExactDocument:
        organisation = self._organisation()
        if event.currency != "RUB":
            raise DocumentAssemblyManualReview("LK_RECEIPT_UNSUPPORTED_CURRENCY")
        payload: dict[str, Any] = {
            "inn": organisation.participant_inn,
            "action": "DISTANCE",
            "action_date": _event_date(event),
            "fias_id": organisation.fias_id,
            "products": [
                {
                    "cis": _normalized_event_cis(event),
                    "product_cost": rubles_to_kopecks(event.amount),
                }
            ],
        }
        if organisation.organisation_type is OrganisationType.LEGAL_ENTITY:
            assert organisation.kpp is not None
            payload["kpp"] = organisation.kpp
        # buyer_inn and optional primary-document/fiscal fields are intentionally absent.
        return ExactDocumentBuilder.from_json_value(payload)

    def _lp_return_remote_sale(self, event: Event) -> ExactDocument:
        organisation = self._organisation()
        paid = organisation.remote_sale_return_paid
        if paid is None:
            raise DocumentAssemblyManualReview("REMOTE_SALE_RETURN_PAID_REQUIRED")
        payload: dict[str, Any] = {
            "trade_participant_inn": organisation.participant_inn,
            "return_type": "REMOTE_SALE_RETURN",
            "paid": paid,
            "products_list": [{"ki": _normalized_event_cis(event)}],
        }
        if paid:
            if self.primary_document_provider is None:
                raise DocumentAssemblyManualReview("RETURN_PRIMARY_DOCUMENT_REQUIRED")
            primary = self.primary_document_provider(event)
            if primary is None:
                raise DocumentAssemblyManualReview("RETURN_PRIMARY_DOCUMENT_REQUIRED")
            payload.update(primary.fields())
        # paid=false does not require primary-document fields in P0. Permit/certificate
        # fields are optional and are not fabricated.
        return ExactDocumentBuilder.from_json_value(payload)
