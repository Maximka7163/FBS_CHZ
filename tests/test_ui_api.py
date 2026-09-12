import os
from pathlib import Path
from fastapi.testclient import TestClient
from wbcz_ui.api import create_app

REF = Path(os.environ.get('WBCZ_REF_XLSX', '/mnt/data/REF_WB_archive_9.xlsx'))


def test_status_and_history_api(tmp_path):
    client = TestClient(create_app(tmp_path / 'api.sqlite'))
    status = client.get('/api/status').json()
    assert status['mode'] == 'offline-dry-run'
    assert status['true_api'] is False
    assert status['auth_signing'] is False
    assert status['document_signing'] is False
    assert status['submission'] is False
    assert status['product_group'] == 'lp'
    with REF.open('rb') as f:
        response = client.post('/api/imports', files={'file': ('REF_WB_archive_9.xlsx', f, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')})
    assert response.status_code == 200
    data = response.json()
    assert data['event_count'] == 238
    assert data['rejected_rows'] == 0
    history = client.get('/api/imports').json()
    assert len(history) == 1
    assert history[0]['filename'] == 'REF_WB_archive_9.xlsx'
    assert history[0]['row_count'] == 238
    assert history[0]['unique_kiz'] == 238


def test_events_check_detail_preview_api(tmp_path):
    client = TestClient(create_app(tmp_path / 'api.sqlite'))
    with REF.open('rb') as f:
        imported = client.post('/api/imports', files={'file': ('REF_WB_archive_9.xlsx', f)}).json()
    fp = imported['fingerprint']
    before = client.get(f'/api/imports/{fp}/events').json()
    assert len(before) == 238
    assert all(event['decision'] is None for event in before)
    checked = client.post(f'/api/imports/{fp}/check').json()
    assert checked['checked'] == 238
    after = client.get(f'/api/imports/{fp}/events').json()
    assert len(after) == 238
    detail = client.get(f"/api/events/{after[0]['event_id']}").json()
    assert detail['kiz'] == after[0]['kiz']
    assert detail['history']
    preview = client.post('/api/operation-preview', json={'event_ids': [event['event_id'] for event in after]}).json()
    assert len(preview['included']) == 54
    assert len(preview['excluded']) == 184
