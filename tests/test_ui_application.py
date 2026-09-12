from __future__ import annotations

from collections import Counter
from pathlib import Path

from wbcz.models import Decision
from wbcz_ui.application import UiApplication

REF = Path('/mnt/data/REF_WB_archive_9.xlsx')


def test_real_import_history_repeat_and_reopen(tmp_path):
    db = tmp_path / 'ui.sqlite'
    app = UiApplication(db)
    first = app.import_bytes('REF_WB_archive_9.xlsx', REF.read_bytes())
    assert first['event_count'] == 238
    assert first['unique_kiz'] == 238
    assert first['sales'] == 76
    assert first['returns'] == 162
    assert first['dated'] == 68
    assert first['undated'] == 170
    assert first['rejected_rows'] == 0
    assert first['new_events'] == 238
    assert first['duplicate_events'] == 0

    second = app.import_bytes('REF_WB_archive_9.xlsx', REF.read_bytes())
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


def test_real_offline_check_and_preview(tmp_path):
    app = UiApplication(tmp_path / 'ui.sqlite')
    item = app.import_bytes('REF_WB_archive_9.xlsx', REF.read_bytes())
    result = app.check_import(item['fingerprint'])
    assert result['checked'] == 238
    assert result['counts'] == {
        Decision.READY_TO_WITHDRAW.value: 64,
        Decision.READY_TO_RETURN.value: 140,
        Decision.ALREADY_DONE.value: 20,
        Decision.MANUAL_REVIEW.value: 9,
        Decision.ERROR.value: 5,
    }
    events = app.events_for_import(item['fingerprint'])
    assert Counter(e['decision'] for e in events) == Counter(result['counts'])
    preview = app.operation_preview([e['event_id'] for e in events])
    assert preview['selected'] == 238
    assert len(preview['included']) == 204
    assert len(preview['excluded']) == 34
    assert preview['withdraw'] == 64
    assert preview['returns'] == 140
    assert preview['production_submission_available'] is False
