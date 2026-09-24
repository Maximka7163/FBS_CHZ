from __future__ import annotations

from collections import Counter
from pathlib import Path

from wbcz.models import Decision
from wbcz_ui.application import UiApplication


def test_real_import_history_repeat_and_reopen(tmp_path, wb_regression_rows, make_xlsx):
    db = tmp_path / 'ui.sqlite'
    app = UiApplication(db)
    source=make_xlsx(wb_regression_rows,"REF_WB_archive_9.xlsx")
    first = app.import_bytes('REF_WB_archive_9.xlsx', source.read_bytes())
    assert first['event_count'] == 238
    assert first['unique_kiz'] == 238
    assert first['sales'] == 76
    assert first['returns'] == 162
    assert first['dated'] == 68
    assert first['undated'] == 170
    assert first['rejected_rows'] == 0
    assert first['new_events'] == 238
    assert first['duplicate_events'] == 0

    second = app.import_bytes('REF_WB_archive_9.xlsx', source.read_bytes())
    assert second['new_events'] == 0
    assert second['duplicate_events'] == 238
    assert second['repeated_file'] is True

    history = app.list_imports()
    assert len(history) == 2
    assert history[0]['repeated'] is True
    assert history[0]['new_events'] == 0
    assert history[0]['duplicate_events'] == 238
    assert history[0]['row_count'] == 238
    assert history[0]['unique_kiz'] == 238
    assert history[1]['repeated'] is False

    reopened = UiApplication(db)
    info = reopened.get_import(first['fingerprint'])
    assert info['event_count'] == 238
    assert info['undated'] == 170
    assert reopened.list_imports()[0]['repeated'] is True


def test_real_offline_check_and_preview(tmp_path, wb_regression_rows, make_xlsx):
    app = UiApplication(tmp_path / 'ui.sqlite')
    source=make_xlsx(wb_regression_rows,"REF_WB_archive_9.xlsx")
    item = app.import_bytes('REF_WB_archive_9.xlsx', source.read_bytes())
    result = app.check_import(item['fingerprint'])
    assert result['checked'] == 238
    assert result['counts'] == {
        Decision.READY_TO_WITHDRAW.value: 51,
        Decision.READY_TO_RETURN.value: 140,
        Decision.ALREADY_DONE.value: 20,
        Decision.MANUAL_REVIEW.value: 22,
        Decision.ERROR.value: 5,
    }
    assert result['reasons']['SALE_RECEIPT_MISSING'] == 13
    assert 'RETURN_RECEIPT_MISSING' not in result['reasons']
    events = app.events_for_import(item['fingerprint'])
    assert Counter(e['decision'] for e in events) == Counter(result['counts'])
    preview = app.operation_preview([e['event_id'] for e in events])
    assert preview['selected'] == 238
    assert len(preview['included']) == 191
    assert len(preview['excluded']) == 47
    assert preview['withdraw'] == 51
    assert preview['returns'] == 140
    assert preview['production_submission_available'] is False


def test_operation_preview_uses_persisted_backend_check(tmp_path, wb_row, make_xlsx):
    """Preview must consume persisted Python decisions, never infer from UI state."""
    source = make_xlsx([wb_row], "persisted-preview.xlsx")
    db = tmp_path / "preview.sqlite"
    app = UiApplication(db)
    imported = app.import_bytes(source.name, source.read_bytes())
    events = app.events_for_import(imported["fingerprint"])
    event_id = events[0]["event_id"]

    before = app.operation_preview([event_id])
    assert before["included"] == []
    assert len(before["excluded"]) == 1
    assert before["excluded"][0]["decision"] is None
    assert before["excluded"][0]["reason"] == "NOT_CHECKED"

    app.check_import(imported["fingerprint"])
    reopened = UiApplication(db)
    checked_event = reopened.events_for_import(imported["fingerprint"])[0]
    after = reopened.operation_preview([event_id])
    item = (after["included"] + after["excluded"])[0]
    assert item["decision"] == checked_event["decision"]
    assert item["decision"] is not None


def test_event_detail_reads_full_history_from_event_store(tmp_path, wb_row, make_xlsx):
    """KIZ detail must expose EventStore history without choosing a fake latest event."""
    first = make_xlsx([wb_row], "first-history.xlsx")
    second = make_xlsx([
        {
            **wb_row,
            "Тип операции": "Возврат",
            "Дата": None,
            "Номер чека": None,
            "Номер фискального накопителя": None,
        }
    ], "second-history.xlsx")
    app = UiApplication(tmp_path / "history.sqlite")
    first_import = app.import_bytes(first.name, first.read_bytes())
    first_event = app.events_for_import(first_import["fingerprint"])[0]
    app.import_bytes(second.name, second.read_bytes())

    detail = app.event_detail(first_event["event_id"])
    assert detail["kiz"] == first_event["kiz"]
    assert len(detail["history"]) == 2
    assert {item["operation"] for item in detail["history"]} == {"Продажа", "Возврат"}
    assert detail["history_order_ambiguous"] is True
