from __future__ import annotations

from pathlib import Path
import sys

from openpyxl import Workbook


HEADERS = [
    "№ задания",
    "Стикер",
    "КИЗ",
    "Номер чека",
    "Стоимость",
    "Валюта",
    "Номер фискального накопителя",
    "Дата",
    "Тип операции",
    "Признак продажи юрлицу",
]


def build(path: Path) -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "КИЗ"
    sheet.append(HEADERS)
    row_number = 0

    def add(operation: str, dated: bool) -> None:
        nonlocal row_number
        row_number += 1
        sheet.append(
            [
                f"T{row_number}",
                f"S{row_number}",
                f"CI-KIZ-{row_number:04d}",
                f"CHK-{row_number}" if dated else None,
                100,
                "RUB",
                f"FN-{row_number}" if dated else None,
                f"12:34:56 {((row_number - 1) % 28) + 1:02d}.08.2026" if dated else None,
                operation,
                "нет",
            ]
        )

    for _ in range(13):
        add("Продажа", False)
    for _ in range(63):
        add("Продажа", True)
    for _ in range(137):
        add("Возврат", False)
    for _ in range(3):
        add("Возврат", True)
    for _ in range(2):
        add("Возврат", True)
    for _ in range(20):
        add("Возврат", False)

    assert row_number == 238
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)


if __name__ == "__main__":
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "/mnt/data/REF_WB_archive_9.xlsx")
    build(destination)
