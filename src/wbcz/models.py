from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
import hashlib
import json
from typing import Any


class Operation(StrEnum):
    SALE = "Продажа"
    RETURN = "Возврат"


class Decision(StrEnum):
    READY_TO_WITHDRAW = "READY_TO_WITHDRAW"
    READY_TO_RETURN = "READY_TO_RETURN"
    ALREADY_DONE = "ALREADY_DONE"
    NO_ACTION = "NO_ACTION"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"


class DocumentStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    PROCESSING = "PROCESSING"
    SUCCEEDED = "SUCCEEDED"
    REJECTED = "REJECTED"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"


def utc_now() -> str:
    """Observation/import timestamp; NEVER a substitute for a WB event date."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    )


@dataclass(frozen=True, slots=True)
class Event:
    kiz: str
    task_number: str
    sticker: str
    operation: Operation
    occurred_at: datetime | None
    receipt_number: str | None
    fiscal_drive_number: str | None
    amount: Decimal
    currency: str
    legal_entity_sale: bool | None

    def __post_init__(self) -> None:
        if not self.kiz or not self.task_number or not self.sticker:
            raise ValueError("КИЗ, № задания и стикер обязательны")
        if not isinstance(self.operation, Operation):
            raise ValueError("Некорректный тип операции")
        if self.occurred_at is not None:
            if not isinstance(self.occurred_at, datetime):
                raise ValueError("Дата события должна быть datetime или None")
            if (
                self.occurred_at.tzinfo is None
                or self.occurred_at.utcoffset() is None
            ):
                raise ValueError("Дата события должна содержать часовой пояс")
        if not self.amount.is_finite():
            raise ValueError("Стоимость должна быть конечным числом")
        if abs(self.amount) > Decimal("999999999999999"):
            raise ValueError("Слишком большая стоимость")
        if self.amount != self.amount.quantize(Decimal("0.01")):
            raise ValueError("Стоимость должна содержать не более двух знаков")
        if self.legal_entity_sale is not None and type(self.legal_entity_sale) is not bool:
            raise ValueError("Признак юрлица должен быть bool или None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kiz": self.kiz,
            "task_number": self.task_number,
            "sticker": self.sticker,
            "operation": self.operation.value,
            "occurred_at": (
                self.occurred_at.astimezone(timezone.utc).isoformat(
                    timespec="microseconds"
                )
                if self.occurred_at is not None else None
            ),
            "receipt_number": self.receipt_number,
            "fiscal_drive_number": self.fiscal_drive_number,
            "amount": format(self.amount.quantize(Decimal("0.01")), ".2f"),
            "currency": self.currency,
            "legal_entity_sale": self.legal_entity_sale,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Event:
        occurred_at = value["occurred_at"]
        return cls(
            kiz=value["kiz"],
            task_number=value["task_number"],
            sticker=value["sticker"],
            operation=Operation(value["operation"]),
            occurred_at=(
                datetime.fromisoformat(occurred_at)
                if occurred_at is not None else None
            ),
            receipt_number=value["receipt_number"],
            fiscal_drive_number=value["fiscal_drive_number"],
            amount=Decimal(value["amount"]),
            currency=value["currency"],
            legal_entity_sale=value["legal_entity_sale"],
        )

    @property
    def event_id(self) -> str:
        # Extend the existing canonical domain with JSON null for unknown dates.
        # Keep v1: events with known dates retain EXACTLY their former IDs.
        # No row number, filename, fingerprint or import timestamp is included.
        payload = "wb-event:v1:" + canonical_json(self.to_dict())
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class KiState:
    """Internal normalized model, NOT a production True API schema.

    Known status/statusEx: IN_CIRCULATION, WITHDRAWN.
    Known distance withdrawal reason: DISTANCE.
    Unknown strings are intentionally retained for conservative decisions.
    """
    status: str
    statusEx: str | None = None
    withdrawReason: str | None = None
    ownerInn: str | None = None


@dataclass(frozen=True, slots=True)
class Outcome:
    decision: Decision
    reason: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedRow:
    row_number: int
    event: Event


@dataclass(frozen=True, slots=True)
class RowIssue:
    row_number: int
    message: str


@dataclass(frozen=True, slots=True)
class ParsedWorkbook:
    rows: tuple[ParsedRow, ...]
    issues: tuple[RowIssue, ...]


@dataclass(frozen=True, slots=True)
class ImportReport:
    fingerprint: str
    new_events: int
    duplicate_events: int
    rejected_rows: int
    repeated_file: bool


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: int
    event_id: str
    outcome: Outcome


@dataclass(frozen=True, slots=True)
class DocumentReport:
    status: DocumentStatus
    error: str | None = None

    @property
    def successful(self) -> bool:
        return self.status is DocumentStatus.SUCCEEDED
