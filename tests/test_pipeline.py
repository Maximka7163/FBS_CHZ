from dataclasses import replace
from datetime import datetime
import socket
import sqlite3

import pytest

from wbcz.document_builder import FakeDocumentBuilder
from wbcz.event_store import EventStore
from wbcz.models import Decision, KiState
from wbcz.service import DryRunService, ImportService
from wbcz.signing import FakeSigningAdapter
from wbcz.submission import FakeSubmissionService
from wbcz.true_api import FakeTrueApiClient, TrueApiError


OWN = "1234567890"


def test_T07_same_file_no_duplicate_events(store, wb_row, make_xlsx):
    file = make_xlsx([wb_row])
    importer = ImportService(store)
    first = importer.import_file(file)
    second = importer.import_file(file)
    assert first.new_events == 1
    assert second.new_events == 0
    assert second.repeated_file
    assert second.duplicate_events == 1
    assert store.count("imports") == 1
    assert store.count("events") == 1
    assert store.count("import_rows") == 1


def test_T08_overlapping_archives_no_duplicate_previews(
    store, wb_row, make_xlsx,
):
    rows = [
        {**wb_row, "КИЗ": code, "№ задания": str(number)}
        for number, code in enumerate(("KI-A", "KI-B", "KI-C"), start=1)
    ]
    first = make_xlsx(rows[:2], "first.xlsx")
    second = make_xlsx(rows[1:], "second.xlsx")
    importer = ImportService(store)
    importer.import_file(first)
    api = FakeTrueApiClient({
        row["КИЗ"]: KiState("IN_CIRCULATION", ownerInn=OWN) for row in rows
    })
    runner = DryRunService(store, api, OWN)
    runner.check_all()
    report = importer.import_file(second)
    runner.check_all()
    runner.check_all()
    assert report.new_events == 1
    assert report.duplicate_events == 1
    assert store.count("events") == 3
    assert store.count("import_rows") == 4
    assert store.count("previews") == 3
    assert len({row["event_id"] for row in store.previews()}) == 3
    assert store.count("checks") == 8  # Rechecks are audit/history, not actions.
    assert store.count("documents") == 0


def test_T09_multiple_events_one_ki_history_preserved(
    store, wb_row, make_xlsx,
):
    rows = [
        {**wb_row, "Дата": datetime(2025, 1, 3, 12), "Номер чека": "303"},
        {
            **wb_row, "Дата": datetime(2025, 1, 2, 12),
            "Тип операции": "Возврат", "Номер чека": "302",
        },
        wb_row,
    ]
    ImportService(store).import_file(make_xlsx(rows))
    history = store.events("DEMO-KI")
    assert len(history) == 3
    assert len({event.event_id for event in history}) == 3
    assert [event.occurred_at.day for event in history] == [1, 2, 3]
    assert [event.operation.value for event in history] == [
        "Продажа", "Возврат", "Продажа",
    ]


def test_T10_api_error_is_not_success(store, wb_row, make_xlsx):
    ImportService(store).import_file(make_xlsx([wb_row]))
    api = FakeTrueApiClient({"DEMO-KI": TrueApiError("mock timeout")})
    result = DryRunService(store, api, OWN).check_all()[0]
    assert result.outcome.decision is Decision.ERROR
    assert "mock timeout" in result.outcome.error
    assert store.previews()[0]["decision"] == "ERROR"
    assert store.checks(result.event_id)[0]["snapshot_json"] is None
    assert store.count("documents") == 0


def test_api_error_replaces_old_ready_projection(store, wb_row, make_xlsx):
    ImportService(store).import_file(make_xlsx([wb_row]))
    api = FakeTrueApiClient({
        "DEMO-KI": KiState("IN_CIRCULATION", ownerInn=OWN),
    })
    runner = DryRunService(store, api, OWN)
    first = runner.check_all()[0]
    assert first.outcome.decision is Decision.READY_TO_WITHDRAW
    api.responses["DEMO-KI"] = TrueApiError("unavailable")
    second = runner.check_all()[0]
    assert second.outcome.decision is Decision.ERROR
    assert store.count("checks") == 2
    assert store.count("previews") == 1
    assert store.previews()[0]["decision"] == "ERROR"


def test_external_state_is_truth_not_local_decision(store, wb_row, make_xlsx):
    ImportService(store).import_file(make_xlsx([wb_row]))
    api = FakeTrueApiClient({
        "DEMO-KI": KiState(
            "WITHDRAWN", withdrawReason="DISTANCE", ownerInn=OWN,
        ),
    })
    runner = DryRunService(store, api, OWN)
    assert runner.check_all()[0].outcome.decision is Decision.ALREADY_DONE
    api.responses["DEMO-KI"] = KiState("IN_CIRCULATION", ownerInn=OWN)
    assert runner.check_all()[0].outcome.decision is Decision.READY_TO_WITHDRAW
    assert len(api.calls) == 2


def test_T12_dry_run_cannot_build_sign_submit_or_use_network(
    store, wb_row, make_xlsx, monkeypatch,
):
    ImportService(store).import_file(make_xlsx([wb_row]))

    def forbidden(*args, **kwargs):
        raise AssertionError("Forbidden external/mutating path")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(FakeDocumentBuilder, "build", forbidden)
    monkeypatch.setattr(FakeSigningAdapter, "sign", forbidden)
    monkeypatch.setattr(FakeSubmissionService, "submit", forbidden)
    state = KiState("IN_CIRCULATION", ownerInn=OWN)
    api = FakeTrueApiClient({"DEMO-KI": state})
    before = dict(api.responses)
    result = DryRunService(store, api, OWN).check_all()[0]
    assert result.outcome.decision is Decision.READY_TO_WITHDRAW
    assert api.responses == before
    assert api.calls == ["DEMO-KI"]
    assert store.count("documents") == 0
    assert store.count("document_status_history") == 0


def test_persistence_across_reopen(tmp_path, wb_row, make_xlsx):
    path = tmp_path / "persistent.sqlite"
    file = make_xlsx([wb_row])
    with EventStore(path) as first:
        ImportService(first).import_file(file)
        event_id = first.events()[0].event_id
    with EventStore(path) as second:
        assert second.get_event(event_id).kiz == "DEMO-KI"
        assert ImportService(second).import_file(file).repeated_file


def test_identical_rows_within_file_are_deduplicated(
    store, wb_row, make_xlsx,
):
    report = ImportService(store).import_file(make_xlsx([wb_row, wb_row]))
    assert report.new_events == 1
    assert report.duplicate_events == 1
    assert store.count("import_rows") == 2


def test_identity_preserves_distinct_receipts(event):
    assert event.event_id != replace(event, receipt_number="another").event_id


def test_identity_preserves_gs_and_crypto_tail(event):
    code = "010123456789012321abc\x1d91key\x1d92tail"
    changed = replace(event, kiz=code)
    restored = type(event).from_dict(changed.to_dict())
    assert restored.kiz == code
    assert restored.event_id == changed.event_id
    assert changed.event_id != replace(event, kiz=code.replace("\x1d", "")).event_id


def test_audit_is_append_only(tmp_path):
    path = tmp_path / "audit.sqlite"
    with EventStore(path) as store:
        store.audit("TEST", "test", "1", {})
    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM audit_log")
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE audit_log SET action = 'CHANGED'")
        connection.rollback()
    finally:
        connection.close()
