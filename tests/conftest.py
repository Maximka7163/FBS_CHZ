from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Iterator

from openpyxl import Workbook
import pytest

from wbcz.event_store import EventStore
from wbcz.models import Event, Operation
from wbcz.wb_parser import HEADERS


@pytest.fixture
def event() -> Event:
    return Event(
        kiz="DEMO-KI",
        task_number="100",
        sticker="200",
        operation=Operation.SALE,
        occurred_at=datetime(2025, 1, 1, 9, 0, tzinfo=timezone.utc),
        receipt_number="300",
        fiscal_drive_number="9999078900000001",
        amount=Decimal("1500.00"),
        currency="RUB",
        legal_entity_sale=False,
    )


@pytest.fixture
def return_event(event: Event) -> Event:
    return replace(event, operation=Operation.RETURN)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[EventStore]:
    with EventStore(tmp_path / "test.sqlite") as value:
        yield value


@pytest.fixture
def wb_row() -> dict[str, Any]:
    return {
        "№ задания": "100",
        "Стикер": "200",
        "КИЗ": "DEMO-KI",
        "Номер чека": "300",
        "Стоимость": "1500,00",
        "Валюта": "RUB",
        "Номер фискального накопителя": "9999078900000001",
        "Дата": datetime(2025, 1, 1, 12, 0),
        "Тип операции": "Продажа",
        "Признак продажи юрлицу": "нет",
    }


@pytest.fixture
def make_xlsx(tmp_path: Path) -> Callable[..., Path]:
    def write(
        rows: list[dict[str, Any]],
        name: str = "archive.xlsx",
        *,
        headers: tuple[str, ...] = HEADERS,
        sheet: str = "КИЗ",
    ) -> Path:
        workbook = Workbook()
        worksheet = workbook.active
        assert worksheet is not None
        worksheet.title = sheet
        worksheet.append(list(headers))
        for row in rows:
            worksheet.append([row.get(header) for header in headers])
        path = tmp_path / name
        workbook.save(path)
        workbook.close()
        return path
    return write


@pytest.fixture
def wb_regression_rows() -> list[dict[str, Any]]:
    """Fully synthetic 238-row WB regression with the historical decision distribution."""

    rows: list[dict[str, Any]] = [
        {
            "№ задания": "TEST-TASK-000001",
            "Стикер": "TEST-STICKER-000001",
            "КИЗ": "SYNTHETIC-KIZ-00000001",
            "Номер чека": "",
            "Стоимость": 2367,
            "Валюта": "₽",
            "Номер фискального накопителя": "",
            "Дата": "",
            "Тип операции": "Возврат",
            "Признак продажи юрлицу": "Нет",
        },
        {
            "№ задания": "TEST-TASK-000002",
            "Стикер": "TEST-STICKER-000002",
            "КИЗ": "SYNTHETIC-KIZ-00000002",
            "Номер чека": "",
            "Стоимость": 4939,
            "Валюта": "₽",
            "Номер фискального накопителя": "",
            "Дата": "",
            "Тип операции": "Продажа",
            "Признак продажи юрлицу": "Нет",
        },
        {
            "№ задания": "TEST-TASK-000003",
            "Стикер": "TEST-STICKER-000003",
            "КИЗ": "SYNTHETIC-KIZ-00000003",
            "Номер чека": "TEST-RECEIPT-000003",
            "Стоимость": 4542,
            "Валюта": "₽",
            "Номер фискального накопителя": "TEST-FN-000003",
            "Дата": "04:58:00 19.08.2026",
            "Тип операции": "Продажа",
            "Признак продажи юрлицу": "Нет",
        },
        {
            "№ задания": "TEST-TASK-000004",
            "Стикер": "TEST-STICKER-000004",
            "КИЗ": "SYNTHETIC-KIZ-00000004",
            "Номер чека": "TEST-RECEIPT-000004",
            "Стоимость": 4795,
            "Валюта": "₽",
            "Номер фискального накопителя": "TEST-FN-000004",
            "Дата": "22:45:00 15.08.2026",
            "Тип операции": "Возврат",
            "Признак продажи юрлицу": "Нет",
        },
    ]

    def add(operation: str, dated: bool, count: int) -> None:
        for _ in range(count):
            number = len(rows) + 1
            rows.append({
                "№ задания": f"TEST-TASK-{number:06d}",
                "Стикер": f"TEST-STICKER-{number:06d}",
                "КИЗ": f"SYNTHETIC-KIZ-{number:08d}",
                "Номер чека": f"TEST-RECEIPT-{number:06d}" if dated else "",
                "Стоимость": 2000 + number,
                "Валюта": "₽",
                "Номер фискального накопителя": f"TEST-FN-{number:06d}" if dated else "",
                "Дата": "04:58:00 19.08.2026" if dated else "",
                "Тип операции": operation,
                "Признак продажи юрлицу": "Нет",
            })

    add("Продажа", False, 12)
    add("Продажа", True, 62)
    add("Возврат", False, 136)
    add("Возврат", True, 2)
    add("Возврат", False, 12)
    add("Возврат", True, 2)
    add("Возврат", False, 4)
    add("Возврат", False, 4)

    assert len(rows) == 238
    return rows

