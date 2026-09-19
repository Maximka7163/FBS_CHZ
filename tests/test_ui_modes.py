from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from wbcz.event_store import EventStore
from wbcz.models import Decision, KiState, Outcome
from wbcz_ui.application import OperationMode, UiApplication


def _checked_real(tmp_path, wb_regression_rows, make_xlsx):
    app = UiApplication(tmp_path / "modes.sqlite")
    source=make_xlsx(wb_regression_rows,"REF_WB_archive_9.xlsx")
    imported = app.import_bytes("REF_WB_archive_9.xlsx", source.read_bytes())
    checked = app.check_import(imported["fingerprint"])
    events = app.events_for_import(imported["fingerprint"])
    ids = [event["event_id"] for event in events]
    return app, imported, checked, events, ids


def _single_with_decision(tmp_path, wb_row, make_xlsx, decision: Decision, reason: str):
    source = make_xlsx([wb_row], f"{decision.value}.xlsx")
    db = tmp_path / f"{decision.value}.sqlite"
    app = UiApplication(db)
    imported = app.import_bytes(source.name, source.read_bytes())
    event = app.events_for_import(imported["fingerprint"])[0]
    with EventStore(db) as store:
        store.save_check(
            event["event_id"],
            KiState("IN_CIRCULATION", ownerInn="1234567890"),
            Outcome(decision, reason),
            source="test-persisted-decision",
        )
    return app, imported, event["event_id"]


def test_auto_preview_groups_withdraw_and_return(tmp_path, wb_regression_rows, make_xlsx):
    app, imported, checked, _, ids = _checked_real(tmp_path, wb_regression_rows, make_xlsx)
    assert checked["counts"] == {
        "READY_TO_WITHDRAW": 51,
        "READY_TO_RETURN": 3,
        "ALREADY_DONE": 20,
        "MANUAL_REVIEW": 159,
        "ERROR": 5,
    }
    preview = app.operation_preview(ids, OperationMode.AUTO, imported["fingerprint"])
    assert (preview["selected_count"], preview["eligible_count"]) == (238, 54)
    assert (preview["withdraw_count"], preview["return_count"], preview["excluded_count"]) == (51, 3, 184)


def test_withdraw_only_accepts_only_ready_to_withdraw(tmp_path, wb_regression_rows, make_xlsx):
    app, imported, _, _, ids = _checked_real(tmp_path, wb_regression_rows, make_xlsx)
    preview = app.operation_preview(ids, OperationMode.WITHDRAW_ONLY, imported["fingerprint"])
    assert preview["eligible_count"] == 51
    assert preview["withdraw_count"] == 51
    assert preview["return_count"] == 0
    assert preview["excluded_count"] == 187
    assert Counter(item["decision"] for item in preview["excluded"]) == {
        "READY_TO_RETURN": 3,
        "ALREADY_DONE": 20,
        "MANUAL_REVIEW": 159,
        "ERROR": 5,
    }
    return_exclusion = next(item for item in preview["excluded"] if item["decision"] == "READY_TO_RETURN")
    assert return_exclusion["reason_text"] == "По текущему состоянию требуется возврат в оборот"


def test_return_only_accepts_only_ready_to_return(tmp_path, wb_regression_rows, make_xlsx):
    app, imported, _, _, ids = _checked_real(tmp_path, wb_regression_rows, make_xlsx)
    preview = app.operation_preview(ids, OperationMode.RETURN_ONLY, imported["fingerprint"])
    assert preview["eligible_count"] == 3
    assert preview["withdraw_count"] == 0
    assert preview["return_count"] == 3
    assert preview["excluded_count"] == 235
    assert Counter(item["decision"] for item in preview["excluded"]) == {
        "READY_TO_WITHDRAW": 51,
        "ALREADY_DONE": 20,
        "MANUAL_REVIEW": 159,
        "ERROR": 5,
    }
    withdraw_exclusion = next(item for item in preview["excluded"] if item["decision"] == "READY_TO_WITHDRAW")
    assert withdraw_exclusion["reason_text"] == "По текущему состоянию требуется вывод из оборота"


def test_control_is_read_only_and_has_no_preview_or_documents(tmp_path, wb_regression_rows, make_xlsx):
    app, imported, checked, _, ids = _checked_real(tmp_path, wb_regression_rows, make_xlsx)
    assert checked["checked"] == 238
    with pytest.raises(ValueError, match="read-only"):
        app.operation_preview(ids, OperationMode.CONTROL, imported["fingerprint"])
    with EventStore(app.db_path) as store:
        assert store.count("documents") == 0
        assert store.count("document_status_history") == 0


def test_manual_review_never_becomes_eligible(tmp_path, wb_row, make_xlsx):
    app, imported, event_id = _single_with_decision(
        tmp_path, wb_row, make_xlsx, Decision.MANUAL_REVIEW, "OWNER_MISMATCH"
    )
    for mode in (OperationMode.AUTO, OperationMode.WITHDRAW_ONLY, OperationMode.RETURN_ONLY):
        preview = app.operation_preview([event_id], mode, imported["fingerprint"])
        assert preview["eligible_count"] == 0
        assert preview["excluded_count"] == 1


def test_error_never_becomes_eligible(tmp_path, wb_row, make_xlsx):
    app, imported, event_id = _single_with_decision(
        tmp_path, wb_row, make_xlsx, Decision.ERROR, "STATE_LOOKUP_OR_NORMALIZATION_FAILED"
    )
    for mode in (OperationMode.AUTO, OperationMode.WITHDRAW_ONLY, OperationMode.RETURN_ONLY):
        assert app.operation_preview([event_id], mode, imported["fingerprint"])["eligible_count"] == 0


def test_already_done_never_enters_new_operation(tmp_path, wb_row, make_xlsx):
    app, imported, event_id = _single_with_decision(
        tmp_path, wb_row, make_xlsx, Decision.ALREADY_DONE, "SALE_ALREADY_WITHDRAWN_DISTANCE"
    )
    for mode in (OperationMode.AUTO, OperationMode.WITHDRAW_ONLY, OperationMode.RETURN_ONLY):
        assert app.operation_preview([event_id], mode, imported["fingerprint"])["eligible_count"] == 0


def test_mode_cannot_override_persisted_backend_decision(tmp_path, wb_row, make_xlsx):
    app, imported, event_id = _single_with_decision(
        tmp_path, wb_row, make_xlsx, Decision.READY_TO_RETURN, "RETURN_WITHDRAWN_DISTANCE"
    )
    withdraw = app.operation_preview([event_id], OperationMode.WITHDRAW_ONLY, imported["fingerprint"])
    returned = app.operation_preview([event_id], OperationMode.RETURN_ONLY, imported["fingerprint"])
    assert withdraw["eligible_count"] == 0
    assert withdraw["excluded"][0]["decision"] == "READY_TO_RETURN"
    assert returned["eligible_count"] == 1
    assert returned["included"][0]["decision"] == "READY_TO_RETURN"


def test_frontend_uses_single_backend_authoritative_bulk_flow():
    root = Path(__file__).parents[1] / "frontend" / "src"
    main = (root / "main.ts").read_text(encoding="utf-8")
    api = (root / "api.ts").read_text(encoding="utf-8")
    workflow = (root / "workflow.ts").read_text(encoding="utf-8")
    assert "/bulk-preview" in api
    assert "/bulk-actions" in api
    assert "confirm: true" in api
    assert "api.bulkPreview" in main
    assert "api.executeBulk" in main
    assert "data-mode" not in main
    assert "data-pick" not in main
    assert "READY_TO_WITHDRAW" not in workflow
    assert "READY_TO_RETURN" not in workflow
    assert "item.filter_group === filter" in workflow


def test_event_details_still_return_full_eventstore_history(tmp_path, wb_row, make_xlsx):
    first = make_xlsx([wb_row], "mode-history-1.xlsx")
    second = make_xlsx([{**wb_row, "Тип операции": "Возврат", "Дата": None}], "mode-history-2.xlsx")
    app = UiApplication(tmp_path / "mode-history.sqlite")
    imported = app.import_bytes(first.name, first.read_bytes())
    event_id = app.events_for_import(imported["fingerprint"])[0]["event_id"]
    app.import_bytes(second.name, second.read_bytes())
    detail = app.event_detail(event_id)
    assert len(detail["history"]) == 2
    assert {item["operation"] for item in detail["history"]} == {"Продажа", "Возврат"}
    assert detail["history_order_ambiguous"] is True


def test_ambiguous_history_is_forced_to_manual_review_backend_side(tmp_path, wb_row, make_xlsx):
    rows = [
        {**wb_row, "Дата": None, "Номер чека": None, "Номер фискального накопителя": None},
        {**wb_row, "Тип операции": "Возврат", "Дата": None, "Номер чека": None, "Номер фискального накопителя": None},
    ]
    source = make_xlsx(rows, "ambiguous-history.xlsx")
    app = UiApplication(tmp_path / "ambiguous.sqlite")
    imported = app.import_bytes(source.name, source.read_bytes())
    checked = app.check_import(imported["fingerprint"])
    assert checked["counts"] == {"MANUAL_REVIEW": 2}
    events = app.events_for_import(imported["fingerprint"])
    assert all(event["decision"] == "MANUAL_REVIEW" for event in events)
    assert all(event["reason"] == "HISTORY_ORDER_AMBIGUOUS" for event in events)


def test_all_modes_leave_production_documents_zero(tmp_path, wb_regression_rows, make_xlsx):
    app, imported, _, _, ids = _checked_real(tmp_path, wb_regression_rows, make_xlsx)
    for mode in (OperationMode.AUTO, OperationMode.WITHDRAW_ONLY, OperationMode.RETURN_ONLY):
        app.operation_preview(ids, mode, imported["fingerprint"])
    with EventStore(app.db_path) as store:
        assert store.count("documents") == 0
        assert store.count("document_status_history") == 0
