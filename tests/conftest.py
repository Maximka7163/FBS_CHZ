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
    """Synthetic regression, NOT the unavailable REF_WB_archive_9.xlsx.

    Four verbatim representative records from the task, followed by synthetic
    records matching only the verified counts. Long fiscal IDs are text.
    """
    rows = [
        {
            "№ задания": "5507586445",
            "Стикер": "56873819376",
            "КИЗ": "0102900897077841215nylqhB241sOO",
            "Номер чека": "",
            "Стоимость": 2367,
            "Валюта": "₽",
            "Номер фискального накопителя": "",
            "Дата": "",
            "Тип операции": "Возврат",
            "Признак продажи юрлицу": "Нет",
        },
        {
            "№ задания": "5494037512",
            "Стикер": "56820039412",
            "КИЗ": "0102900897077902215yT'U257>?uV,",
            "Номер чека": "",
            "Стоимость": 4939,
            "Валюта": "₽",
            "Номер фискального накопителя": "",
            "Дата": "",
            "Тип операции": "Продажа",
            "Признак продажи юрлицу": "Нет",
        },
        {
            "№ задания": "5471369116",
            "Стикер": "56703662970",
            "КИЗ": "0102901413694443215O*(HZaeKcg:T",
            "Номер чека": "211671",
            "Стоимость": 4542,
            "Валюта": "₽",
            "Номер фискального накопителя": "7380440903834317",
            "Дата": "04:58:00 19.08.2026",
            "Тип операции": "Продажа",
            "Признак продажи юрлицу": "Нет",
        },
        {
            "№ задания": "5470378133",
            "Стикер": "56701613743",
            "КИЗ": "0102900897077902215BOKABb=hS;'w",
            "Номер чека": "246721",
            "Стоимость": 4795,
            "Валюта": "₽",
            "Номер фискального накопителя": "7384440901398402",
            "Дата": "22:45:00 15.08.2026",
            "Тип операции": "Возврат",
            "Признак продажи юрлицу": "Нет",
        },
    ]
    # Totals including the representatives:
    # sale: 63 dated + 13 undated; return: 5 dated + 157 undated.
    for operation, dated, count in (
        ("Продажа", True, 62),
        ("Продажа", False, 12),
        ("Возврат", True, 4),
        ("Возврат", False, 156),
    ):
        for _ in range(count):
            number = len(rows) + 1
            rows.append({
                "№ задания": str(5500000000 + number),
                "Стикер": str(56800000000 + number),
                "КИЗ": f"010290089707790221SYNTH{number:07d}",
                "Номер чека": str(210000 + number) if dated else "",
                "Стоимость": 2000 + number,
                "Валюта": "₽",
                "Номер фискального накопителя": (
                    "7380440903834317" if dated else ""
                ),
                "Дата": (
                    "04:58:00 19.08.2026"
                    if dated and operation == "Продажа"
                    else "22:45:00 15.08.2026" if dated else ""
                ),
                "Тип операции": operation,
                "Признак продажи юрлицу": "Нет",
            })
    return rows
