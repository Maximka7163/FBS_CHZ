from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import socket
import sqlite3

import pytest

from wbcz.cli import main
from wbcz.control_engine import decide
from wbcz.document_builder import FakeDocumentBuilder
from wbcz.event_store import EventStore, SCHEMA, SCHEMA_VERSION
from wbcz.models import Decision, Event, KiState, Operation, canonical_json
from wbcz.service import DryRunService, ImportService
from wbcz.signing import FakeSigningAdapter
from wbcz.submission import FakeSubmissionService
from wbcz.true_api import FakeTrueApiClient, TrueApiError
from wbcz.wb_parser import PARSER_VERSION, parse_excel


OWN = "1234567890"
OPTIONAL_FIELDS = ("Дата", "Номер чека", "Номер фискального накопителя")


@pytest.mark.parametrize("blank", [None, "", " \t\r\n"])
def test_blank_date_imported_as_none(store, wb_row, make_xlsx, blank):
    report = ImportService(store).import_file(
        make_xlsx([{**wb_row, "Дата": blank}])
    )
    assert report.new_events == 1
    assert report.rejected_rows == 0
    event = store.events()[0]
    assert event.occurred_at is None
    assert event.to_dict()["occurred_at"] is None
    assert event.receipt_number == "300"
    assert event.fiscal_drive_number == "9999078900000001"


@pytest.mark.parametrize(
    ("field", "attribute"),
    [
        ("Номер чека", "receipt_number"),
        ("Номер фискального накопителя", "fiscal_drive_number"),
    ],
)
@pytest.mark.parametrize("blank", [None, "", " \t\r\n"])
def test_optional_fiscal_field_independently_allowed(
    store, wb_row, make_xlsx, field, attribute, blank,
):
    report = ImportService(store).import_file(
        make_xlsx([{**wb_row, field: blank}])
    )
    assert report.new_events == 1
    assert report.rejected_rows == 0
    event = store.events()[0]
    assert getattr(event, attribute) is None
    assert event.occurred_at is not None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "04:58:00 19.08.2026",
            datetime(2026, 8, 19, 1, 58, tzinfo=timezone.utc),
        ),
        (
            "22:45:00 15.08.2026",
            datetime(2026, 8, 15, 19, 45, tzinfo=timezone.utc),
        ),
        (
            "01:02:03 19.08.2026",
            datetime(2026, 8, 18, 22, 2, 3, tzinfo=timezone.utc),
        ),
    ],
)
def test_real_wb_time_first_format(wb_row, make_xlsx, value, expected):
    parsed = parse_excel(make_xlsx([{**wb_row, "Дата": value}]).read_bytes())
    assert not parsed.issues
    assert parsed.rows[0].event.occurred_at == expected


@pytest.mark.parametrize(
    "bad_date", ["UNKNOWN", "null", "25:00:00 19.08.2026", "04:58:00 31.02.2026", 0],
)
def test_nonblank_invalid_date_is_not_silently_unknown(
    wb_row, make_xlsx, bad_date,
):
    parsed = parse_excel(make_xlsx([{**wb_row, "Дата": bad_date}]).read_bytes())
    assert not parsed.rows
    assert len(parsed.issues) == 1


def test_unknown_date_identity_is_stable_and_distinct(event):
    unknown = replace(
        event, occurred_at=None, receipt_number=None, fiscal_drive_number=None,
    )
    payload = unknown.to_dict()
    assert payload["occurred_at"] is None
    assert '"occurred_at":null' in canonical_json(payload)
    restored = Event.from_dict(json.loads(canonical_json(payload)))
    assert restored == unknown
    assert restored.event_id == unknown.event_id
    assert unknown.event_id == hashlib.sha256(
        ("wb-event:v1:" + canonical_json(payload)).encode("utf-8")
    ).hexdigest()
    assert unknown.event_id != replace(
        unknown, occurred_at=event.occurred_at,
    ).event_id
    assert unknown.event_id != replace(
        unknown, operation=Operation.RETURN,
    ).event_id
    assert unknown.event_id != replace(
        unknown, task_number="another",
    ).event_id


def test_known_date_identity_remains_v1_compatible(event):
    # Explicitly reconstruct the OLD canonical payload, independently of to_dict.
    old_payload = {
        "kiz": event.kiz,
        "task_number": event.task_number,
        "sticker": event.sticker,
        "operation": event.operation.value,
        "occurred_at": event.occurred_at.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ),
        "receipt_number": event.receipt_number,
        "fiscal_drive_number": event.fiscal_drive_number,
        "amount": "1500.00",
        "currency": event.currency,
        "legal_entity_sale": event.legal_entity_sale,
    }
    expected = hashlib.sha256(
        ("wb-event:v1:" + canonical_json(old_payload)).encode("utf-8")
    ).hexdigest()
    assert event.event_id == expected


def test_naive_present_date_is_still_rejected_by_model(event):
    with pytest.raises(ValueError, match="часовой пояс"):
        replace(event, occurred_at=datetime(2026, 8, 19, 4, 58))


def test_unknown_date_sql_null_reopen_audit_and_dedup(
    tmp_path, wb_row, make_xlsx,
):
    path = tmp_path / "unknown.sqlite"
    row = {**wb_row, **dict.fromkeys(OPTIONAL_FIELDS, "")}
    file = make_xlsx([row])
    with EventStore(path) as store:
        report = ImportService(store).import_file(file)
        event = store.events()[0]
        event_id = event.event_id
        assert event.occurred_at is None
        result = DryRunService(
            store,
            FakeTrueApiClient({"DEMO-KI": KiState("IN_CIRCULATION", ownerInn=OWN)}),
            OWN,
        ).check_all()[0]
        assert result.outcome.decision is Decision.READY_TO_WITHDRAW

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        saved = connection.execute(
            """SELECT occurred_at, receipt_number, fiscal_drive_number,
            payload_json FROM events WHERE event_id = ?""",
            (event_id,),
        ).fetchone()
        assert saved[:3] == (None, None, None)
        assert json.loads(saved[3])["occurred_at"] is None
        assert connection.execute(
            "SELECT parser_version FROM imports"
        ).fetchone()[0] == PARSER_VERSION
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()

    with EventStore(path) as reopened:
        assert reopened.get_event(event_id) == event
        assert reopened.events()[0].occurred_at is None
        assert len(reopened.checks(event_id)) == 1
        assert len(reopened.previews()) == 1
        assert reopened.import_issues(report.fingerprint) == []
        actions = [entry["action"] for entry in reopened.audit_entries()]
        assert "EVENT_IMPORTED" in actions
        assert "IMPORT_COMPLETED" in actions
        assert "DRY_RUN_CHECKED" in actions
        repeated = ImportService(reopened).import_file(file)
        assert repeated.repeated_file
        assert repeated.new_events == 0
        assert repeated.duplicate_events == 1


def test_distinguishable_undated_events_and_overlapping_archives(
    tmp_path, wb_row, make_xlsx,
):
    row = {**wb_row, **dict.fromkeys(OPTIONAL_FIELDS, "")}
    rows = [
        row,
        {**row, "Тип операции": "Возврат"},
        {**row, "№ задания": "101", "Стикер": "201"},
    ]
    first = make_xlsx(rows, "undated_first.xlsx")
    # Different row order, row numbers, filename and fingerprint.
    second = make_xlsx(
        [{}, rows[2], rows[0], rows[1], rows[0]],
        "undated_overlap.xlsx",
    )
    assert first.read_bytes() != second.read_bytes()
    path = tmp_path / "undated_history.sqlite"
    with EventStore(path) as store:
        importer = ImportService(store)
        assert importer.import_file(first).new_events == 3
        before = store.events("DEMO-KI")
        assert len(before) == 3
        assert all(event.occurred_at is None for event in before)
        assert len({event.event_id for event in before}) == 3
        assert store.history_order_ambiguous("DEMO-KI")
        report = importer.import_file(second)
        assert report.new_events == 0
        assert report.duplicate_events == 4
        assert report.rejected_rows == 0
        assert store.count("events") == 3
        assert store.count("import_rows") == 7
        # Stable ID order is only a display convention, not inferred chronology.
        assert store.events("DEMO-KI") == before

    with EventStore(path) as reopened:
        assert reopened.events("DEMO-KI") == before
        assert reopened.history_order_ambiguous("DEMO-KI")


def test_mixed_dates_have_display_order_and_expose_ambiguity(
    store, wb_row, make_xlsx,
):
    rows = [
        {**wb_row, "Дата": None, "Номер чека": "unknown"},
        {**wb_row, "Дата": "03.01.2025 12:00:00", "Номер чека": "later"},
        wb_row,
    ]
    ImportService(store).import_file(make_xlsx(rows))
    history = store.events("DEMO-KI")
    assert len(history) == 3
    known = [event for event in history if event.occurred_at is not None]
    assert [event.occurred_at.day for event in known] == [1, 3]
    assert sum(event.occurred_at is None for event in history) == 1
    assert store.history_order_ambiguous("DEMO-KI")
    assert not store.history_order_ambiguous("ABSENT-KI")


def test_equal_known_dates_are_also_ambiguous(store, wb_row, make_xlsx):
    ImportService(store).import_file(make_xlsx([
        wb_row, {**wb_row, "Номер чека": "other"},
    ]))
    assert len(store.events("DEMO-KI")) == 2
    assert store.history_order_ambiguous("DEMO-KI")


def test_distinct_known_dates_not_flagged(store, wb_row, make_xlsx):
    ImportService(store).import_file(make_xlsx([
        wb_row, {**wb_row, "Дата": "02.01.2025 12:00:00"},
    ]))
    assert not store.history_order_ambiguous("DEMO-KI")


@pytest.mark.parametrize(
    ("operation", "state", "expected"),
    [
        (
            Operation.SALE,
            KiState("IN_CIRCULATION", ownerInn=OWN),
            Decision.READY_TO_WITHDRAW,
        ),
        (
            Operation.RETURN,
            KiState("WITHDRAWN", withdrawReason="DISTANCE", ownerInn=OWN),
            Decision.READY_TO_RETURN,
        ),
    ],
)
def test_missing_document_fields_do_not_block_state_decision(
    event, operation, state, expected,
):
    incomplete = replace(
        event, operation=operation, occurred_at=None,
        receipt_number=None, fiscal_drive_number=None,
    )
    assert decide(incomplete, state, OWN).decision is expected


def test_undated_dry_run_fresh_lookup_no_mutation_and_error(
    store, wb_row, make_xlsx, monkeypatch,
):
    row = {**wb_row, **dict.fromkeys(OPTIONAL_FIELDS, "")}
    ImportService(store).import_file(make_xlsx([row]))

    def forbidden(*args, **kwargs):
        raise AssertionError("Forbidden external/mutating path")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(FakeDocumentBuilder, "build", forbidden)
    monkeypatch.setattr(FakeSigningAdapter, "sign", forbidden)
    monkeypatch.setattr(FakeSubmissionService, "submit", forbidden)
    api = FakeTrueApiClient({"DEMO-KI": KiState("IN_CIRCULATION", ownerInn=OWN)})
    runner = DryRunService(store, api, OWN)
    assert runner.check_all()[0].outcome.decision is Decision.READY_TO_WITHDRAW

    api.responses["DEMO-KI"] = KiState(
        "WITHDRAWN", withdrawReason="DISTANCE", ownerInn=OWN,
    )
    assert runner.check_all()[0].outcome.decision is Decision.ALREADY_DONE

    api.responses["DEMO-KI"] = TrueApiError("undated mock failure")
    assert runner.check_all()[0].outcome.decision is Decision.ERROR
    assert api.calls == ["DEMO-KI"] * 3
    assert store.count("checks") == 3
    assert store.previews()[0]["decision"] == "ERROR"
    assert store.count("documents") == 0
    assert store.count("document_status_history") == 0


def test_new_undated_event_invalidates_previews_not_checks(
    store, wb_row, make_xlsx,
):
    importer = ImportService(store)
    importer.import_file(make_xlsx([wb_row], "known.xlsx"))
    runner = DryRunService(
        store,
        FakeTrueApiClient({"DEMO-KI": KiState("IN_CIRCULATION", ownerInn=OWN)}),
        OWN,
    )
    runner.check_all()
    assert store.count("previews") == 1
    importer.import_file(make_xlsx([
        {
            **wb_row, **dict.fromkeys(OPTIONAL_FIELDS, ""),
            "Тип операции": "Возврат",
        },
    ], "new_unknown.xlsx"))
    assert store.count("previews") == 0
    assert store.count("checks") == 1
    assert store.history_order_ambiguous("DEMO-KI")
    assert len(runner.check_all()) == 2
    assert store.count("previews") == 2
    assert store.count("documents") == 0


def test_regression_fixture_matches_verified_counts(
    wb_regression_rows, make_xlsx,
):
    rows = wb_regression_rows
    assert len(rows) == 238
    assert len({row["КИЗ"] for row in rows}) == 238
    assert all(str(row["КИЗ"]).startswith("SYNTHETIC-KIZ-") for row in rows)
    assert all(str(row["№ задания"]).startswith("TEST-TASK-") for row in rows)
    assert all(str(row["Стикер"]).startswith("TEST-STICKER-") for row in rows)
    assert Counter(row["Тип операции"] for row in rows) == {
        "Продажа": 76, "Возврат": 162,
    }
    assert Counter(
        (row["Тип операции"], bool(row["Дата"])) for row in rows
    ) == {
        ("Продажа", True): 63,
        ("Продажа", False): 13,
        ("Возврат", True): 5,
        ("Возврат", False): 157,
    }
    for row in rows:
        assert len({bool(row[field]) for field in OPTIONAL_FIELDS}) == 1
    assert sum(not row["Дата"] for row in rows) == 170
    assert sum(bool(row["Дата"]) for row in rows) == 68

    parsed = parse_excel(make_xlsx(rows, "synthetic_wb_238.xlsx").read_bytes())
    assert not parsed.issues
    assert len(parsed.rows) == 238
    events = [row.event for row in parsed.rows]
    assert len({event.event_id for event in events}) == 238
    assert len({event.kiz for event in events}) == 238
    assert all(event.kiz.startswith("SYNTHETIC-KIZ-") for event in events)
    assert Counter(event.operation for event in events) == {
        Operation.SALE: 76, Operation.RETURN: 162,
    }
    assert Counter(
        (event.operation, event.occurred_at is not None) for event in events
    ) == {
        (Operation.SALE, True): 63,
        (Operation.SALE, False): 13,
        (Operation.RETURN, True): 5,
        (Operation.RETURN, False): 157,
    }
    assert sum(event.receipt_number is None for event in events) == 170
    assert sum(event.fiscal_drive_number is None for event in events) == 170
    assert all(event.currency == "RUB" for event in events)
    assert all(event.legal_entity_sale is False for event in events)
    assert events[0].occurred_at is None
    assert events[1].occurred_at is None
    assert events[2].occurred_at == datetime(2026, 8, 19, 1, 58, tzinfo=timezone.utc)
    assert events[2].fiscal_drive_number == "TEST-FN-000003"
    assert events[3].occurred_at == datetime(2026, 8, 15, 19, 45, tzinfo=timezone.utc)

def test_regression_238_import_reopen_overlap_and_dry_run(
    tmp_path, wb_regression_rows, make_xlsx,
):
    first = make_xlsx(wb_regression_rows, "synthetic_wb_238.xlsx")
    overlap = make_xlsx(
        [{}, *reversed(wb_regression_rows)], "synthetic_wb_238_reordered.xlsx",
    )
    path = tmp_path / "regression.sqlite"
    with EventStore(path) as store:
        report = ImportService(store).import_file(first)
        assert report.new_events == 238
        assert report.duplicate_events == 0
        assert report.rejected_rows == 0
        assert not report.repeated_file
        ids = {event.event_id for event in store.events()}
        assert store.count("import_rows") == 238
        assert store.import_issues(report.fingerprint) == []

    with EventStore(path) as store:
        assert {event.event_id for event in store.events()} == ids
        assert sum(event.occurred_at is None for event in store.events()) == 170
        repeat = ImportService(store).import_file(first)
        assert repeat.repeated_file
        assert repeat.new_events == 0
        assert repeat.duplicate_events == 238
        overlap_report = ImportService(store).import_file(overlap)
        assert not overlap_report.repeated_file
        assert overlap_report.new_events == 0
        assert overlap_report.duplicate_events == 238
        assert overlap_report.rejected_rows == 0
        assert store.count("events") == 238
        assert store.count("import_rows") == 476
        assert len([
            item for item in store.audit_entries()
            if item["action"] == "EVENT_IMPORTED"
        ]) == 238

        # Explicit synthetic states, not claims about the actual KI statuses.
        api = FakeTrueApiClient({
            event.kiz: (
                KiState("IN_CIRCULATION", ownerInn=OWN)
                if event.operation is Operation.SALE
                else KiState("WITHDRAWN", withdrawReason="DISTANCE", ownerInn=OWN)
            )
            for event in store.events()
        })
        results = DryRunService(store, api, OWN).check_all()
        assert Counter(result.outcome.decision for result in results) == {
            Decision.READY_TO_WITHDRAW: 76,
            Decision.READY_TO_RETURN: 162,
        }
        assert len(api.calls) == 238
        assert store.count("previews") == 238
        assert store.count("documents") == 0


def test_v1_database_rejected_without_changing_history(tmp_path):
    path = tmp_path / "legacy.sqlite"
    # Exact old schema differences: NOT NULL date and schema version 1.
    legacy_schema = SCHEMA.replace(
        "occurred_at TEXT,", "occurred_at TEXT NOT NULL,"
    ).replace("PRAGMA user_version = 2;", "PRAGMA user_version = 1;")
    connection = sqlite3.connect(path)
    try:
        connection.executescript(legacy_schema)
        connection.execute(
            """INSERT INTO audit_log
            (action, entity_type, entity_id, details_json, created_at)
            VALUES ('LEGACY', 'test', '1', '{}', 'legacy-observation')"""
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="Автоматическая миграция не реализована"):
        EventStore(path)

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute(
            "SELECT action FROM audit_log"
        ).fetchall() == [("LEGACY",)]
        columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(events)")
        }
        assert columns["occurred_at"][3] == 1
    finally:
        connection.close()


def test_unversioned_nonempty_database_not_silently_initialized(tmp_path):
    path = tmp_path / "unversioned.sqlite"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE foreign_data (value TEXT)")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="Непустая БД без версии"):
        EventStore(path)


def test_mislabeled_not_null_schema_not_accepted(tmp_path):
    path = tmp_path / "mislabeled.sqlite"
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA.replace(
            "occurred_at TEXT,", "occurred_at TEXT NOT NULL,"
        ))
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="должен допускать NULL"):
        EventStore(path)


def test_cli_history_reports_null_and_ambiguity(
    tmp_path, wb_row, make_xlsx, capsys,
):
    path = tmp_path / "cli.sqlite"
    row = {**wb_row, **dict.fromkeys(OPTIONAL_FIELDS, "")}
    with EventStore(path) as store:
        ImportService(store).import_file(make_xlsx([
            row, {**row, "Тип операции": "Возврат"},
        ]))
    assert main(["--db", str(path), "history"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output) == 2
    assert all(item["occurred_at"] is None for item in output)
    assert all(item["history_order_ambiguous"] for item in output)

def test_p0_reference_shape_423_rows_302_events_299_unique_ki(make_xlsx):
    rows = []
    for index in range(108):
        rows.append({
            "№ задания": f"SALE-{index:04d}",
            "Стикер": f"ST-{index:04d}",
            "КИЗ": f"0104600000000{index:04d}SERIALSALE{index:04d}",
            "Номер чека": f"R-{index:04d}",
            "Стоимость": 1500,
            "Валюта": "RUB",
            "Номер фискального накопителя": f"FN-{index:04d}",
            "Дата": "12:00:00 20.08.2026",
            "Тип операции": "Продажа",
            "Признак продажи юрлицу": "Нет",
        })
    for index in range(191):
        rows.append({
            "№ задания": f"RETURN-{index:04d}",
            "Стикер": f"RT-{index:04d}",
            "КИЗ": f"0104700000000{index:04d}SERIALRETURN{index:04d}",
            "Номер чека": f"RR-{index:04d}",
            "Стоимость": 1500,
            "Валюта": "RUB",
            "Номер фискального накопителя": f"RFN-{index:04d}",
            "Дата": "13:00:00 20.08.2026",
            "Тип операции": "Возврат",
            "Признак продажи юрлицу": "Нет",
        })
    for index in range(3):
        duplicate = dict(rows[index])
        duplicate["№ задания"] = f"DUP-{index:04d}"
        duplicate["Стикер"] = f"DUP-ST-{index:04d}"
        duplicate["Тип операции"] = "Возврат"
        rows.append(duplicate)
    for index in range(121):
        rows.append({
            "№ задания": f"IGNORED-{index:04d}",
            "Стикер": f"IGN-{index:04d}",
            "КИЗ": f"0104800000000{index:04d}IGNORED{index:04d}",
            "Номер чека": "",
            "Стоимость": 1500,
            "Валюта": "RUB",
            "Номер фискального накопителя": "",
            "Дата": "",
            "Тип операции": "-",
            "Признак продажи юрлицу": "Нет",
        })
    assert len(rows) == 423
    path = make_xlsx(rows, name="p0-reference-shape.xlsx")
    parsed = parse_excel(path.read_bytes())
    events = [row.event for row in parsed.rows]
    assert len(parsed.rows) == 302
    assert len(parsed.issues) == 0
    assert len(parsed.ignored_rows) == 121
    assert sum(event.operation is Operation.SALE for event in events) == 108
    assert sum(event.operation is Operation.RETURN for event in events) == 194
    assert len({event.kiz for event in events}) == 299
