from datetime import datetime, timezone
from decimal import Decimal

import pytest

from wbcz.service import ImportService
from wbcz.wb_parser import HEADERS, WorkbookError, parse_excel


def test_one_bad_row_does_not_abort_import(store, wb_row, make_xlsx):
    bad = {**wb_row, "КИЗ": 1234567890123456}
    good = {**wb_row, "КИЗ": "GOOD-KI"}
    report = ImportService(store).import_file(make_xlsx([bad, good]))
    assert report.new_events == 1
    assert report.rejected_rows == 1
    assert store.import_issues(report.fingerprint)[0]["row_number"] == 2
    assert store.events()[0].kiz == "GOOD-KI"


def test_missing_required_column(wb_row, make_xlsx):
    file = make_xlsx([wb_row], headers=tuple(h for h in HEADERS if h != "КИЗ"))
    with pytest.raises(WorkbookError, match="КИЗ"):
        parse_excel(file.read_bytes())


def test_missing_sheet(wb_row, make_xlsx):
    file = make_xlsx([wb_row], sheet="Другой лист")
    with pytest.raises(WorkbookError, match="лист"):
        parse_excel(file.read_bytes())


def test_duplicate_header(wb_row, make_xlsx):
    file = make_xlsx([wb_row], headers=HEADERS + ("КИЗ",))
    with pytest.raises(WorkbookError, match="Повторяются"):
        parse_excel(file.read_bytes())


def test_normalization(wb_row, make_xlsx):
    row = {
        **wb_row,
        "№ задания": 100,
        "КИЗ": " 010123456789012321abc ",
        "Стоимость": "1\u00a0500,00",
        "Валюта": " руб. ",
        "Тип операции": " продажа ",
        "Дата": "01.01.2025 12:00:00",
    }
    parsed = parse_excel(make_xlsx([row]).read_bytes())
    assert not parsed.issues
    event = parsed.rows[0].event
    assert event.task_number == "100"
    assert event.kiz == "010123456789012321abc"
    assert event.amount == Decimal("1500.00")
    assert event.currency == "RUB"
    assert event.occurred_at == datetime(2025, 1, 1, 9, tzinfo=timezone.utc)


def test_normalized_rows_have_same_identity(wb_row, make_xlsx):
    first = make_xlsx([wb_row], "first.xlsx")
    second = make_xlsx([{
        **wb_row,
        "Стоимость": 1500,
        "Валюта": "RUR",
        "Тип операции": " продажа ",
        "Дата": "2025-01-01T09:00:00+00:00",
    }], "second.xlsx")
    a = parse_excel(first.read_bytes()).rows[0].event
    b = parse_excel(second.read_bytes()).rows[0].event
    assert a.event_id == b.event_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Дата", "вчера"),
        ("Тип операции", "Отмена"),
        ("Номер фискального накопителя", 9999078900000001),
        ("Стоимость", "nan"),
        ("Стоимость", "10.999"),
        ("Признак продажи юрлицу", "непонятно"),
        ("КИЗ", "=1+1"),
    ],
)
def test_invalid_values_are_row_errors(wb_row, make_xlsx, field, value):
    parsed = parse_excel(make_xlsx([{**wb_row, field: value}]).read_bytes())
    assert not parsed.rows
    assert len(parsed.issues) == 1
    assert parsed.issues[0].row_number == 2


def test_bad_file_is_audited(store, tmp_path):
    file = tmp_path / "bad.xlsx"
    file.write_bytes(b"not an Excel file")
    with pytest.raises(WorkbookError):
        ImportService(store).import_file(file)
    assert store.count("events") == 0
    assert store.audit_entries()[-1]["action"] == "IMPORT_FAILED"


def test_blank_rows_are_ignored(wb_row, make_xlsx):
    parsed = parse_excel(make_xlsx([{}, wb_row, {}]).read_bytes())
    assert len(parsed.rows) == 1
    assert not parsed.issues
