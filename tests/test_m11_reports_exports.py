from __future__ import annotations

import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest
from openpyxl import load_workbook
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from wbcz.m11_reports import (
    ARBITRARY_REMOTE_URL_DOWNLOAD,
    ARTIFACT_ENCRYPTION_FORMAT,
    CALLER_CONTROLLED_FILESYSTEM_PATH,
    CALLER_CONTROLLED_STORAGE_KEY,
    CALLER_CONTROLLED_TRUE_API_HOST,
    CALLER_CONTROLLED_TRUE_API_METHOD,
    CALLER_CONTROLLED_TRUE_API_PATH,
    DISPENSER_CAPABILITIES,
    FRONTEND_FREEZE_ACTIVE,
    GENERIC_TRUE_API_REPORT_PROXY,
    KNOWN_REMOTE_AVAILABILITY,
    KNOWN_REMOTE_DOWNLOAD_STATUSES,
    KNOWN_REMOTE_TASK_STATUSES,
    LOCAL_REPORT_CATALOG,
    LP_PRODUCT_GROUP_CODE,
    FILTERED_CIS_LP_PACKAGE_TYPES,
    FILTERED_CIS_LP_STATUSES,
    SOURCE_AMBIGUITY_PACKAGE_LEVEL_VALUES,
    M11_AGENT_JOB_TYPES,
    M12_DEPENDENCY_FOR_DOWNLOAD_AUTH,
    PATH_TRAVERSAL_ALLOWED,
    PRODUCTION_TRUE_API_REPORTS_ENABLED,
    REMOTE_RESULT_DELETE_ENABLED,
    REPORT_CREATE_RATE_PER_MINUTE,
    REPORT_QUOTA_RATE_PER_MINUTE,
    REPORT_RESULTS_RATE_PER_MINUTE,
    REPORT_TASK_RATE_PER_MINUTE,
    USER_REPORT_DOWNLOAD_ENABLED,
    ArtifactIntegrityConflict,
    ArtifactLimitExceeded,
    ArtifactRole,
    BinaryArtifactIngress,
    ChunkedAeadArtifactCipher,
    DispenserCapabilityName,
    DispenserRateLimiter,
    FilesystemReportArtifactStore,
    FilteredCisFilters,
    InMemoryUploadBindingStore,
    LocalReconciliationResult,
    LocalReportType,
    ReportContractError,
    ReportFormatError,
    ReportOutputFormat,
    ReportRateLimitExceeded,
    ReportSecurityError,
    ReportSensitivity,
    ReportSnapshotDescriptor,
    SnapshotStrategy,
    StreamingReportRenderer,
    artifact_reuse_allowed,
    build_dispenser_spec,
    build_filtered_cis_create_body,
    build_reconciliation_row,
    canonical_request_fingerprint,
    disabled_remote_recipes,
    enabled_remote_recipes,
    format_timestamp_preserving_unknown,
    normalize_remote_availability,
    normalize_remote_download_status,
    normalize_remote_task_status,
    parse_result_evidence,
    parse_unambiguous_zulu_timestamp,
    protect_spreadsheet_text,
    sanitize_report_evidence,
    validate_report_agent_payload,
)
from wbcz.windows_agent import (
    AgentHttpResponse,
    AgentJob,
    AgentJobType,
    AgentResult,
    ProductionAgentTrueApiTransport,
)
from wbcz.windows_agent_runtime import (
    AgentCreateOutcomeUnresolved,
    DurableWindowsAgentExecutor,
    WindowsAgentReplayStore,
)
from wbcz_ui.live_true_api import TrueApiError
from wbcz_web.models import (
    Base,
    AgentJobRecord,
    DocumentLifecycleLedgerRecord,
    TurnoverOperationLedgerRecord,
    AggregationOperationLedgerRecord,
    WbConnectionRecord,
    WbOrderRecord,
    WbEventRecord,
    WbReconciliationRecord,
)
from wbcz_web.models.reports import (
    ReportArtifactRecord,
    ReportArtifactUploadRecord,
    ReportJobEventRecord,
    ReportJobRecord,
    ReportSnapshotRecord,
)
from wbcz_web.repositories.reports import SqlReportRepository
from wbcz_web.config import WebConfig
from wbcz_web.services.reports import (
    LocalReportSourceRegistry,
    ReportJobService,
    SynchronousReportExecutor,
)


NOW = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)


class KeyProvider:
    def __init__(self, key: bytes = b"k" * 32) -> None:
        self.key = key
        self.calls: list[str] = []

    def get_key(self, key_version: str) -> bytes:
        self.calls.append(key_version)
        return self.key


class FakeTunnel:
    local_port = 16666

    def session_marker(self):
        return "marker"

    def assert_gost_session(self, marker):
        assert marker == "marker"


class FakeAudit:
    def __init__(self) -> None:
        self.records = []

    def record(self, **kwargs):
        self.records.append(kwargs)


class FakeResponse:
    def __init__(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.status = status
        self._body = body
        self._offset = 0
        self.headers = {"Content-Type": content_type, "X-Request-ID": "req-1"}

    def read(self, size: int | None = None) -> bytes:
        if size is None:
            part = self._body[self._offset:]
            self._offset = len(self._body)
            return part
        part = self._body[self._offset:self._offset + size]
        self._offset += len(part)
        return part


class FakeConnection:
    def __init__(self, owner) -> None:
        self.owner = owner
        self.method = None
        self.target = None
        self.headers = {}

    def putrequest(self, method, target, skip_host=True):
        self.method = method
        self.target = target

    def putheader(self, name, value):
        self.headers[name] = value

    def endheaders(self, data=None):
        self.owner.calls.append((self.method, self.target, dict(self.headers), data))

    def getresponse(self):
        body = self.owner.response_body(self.method, self.target)
        content_type = "application/zip" if "/file" in (self.target or "") else "application/json"
        return FakeResponse(200, body, content_type)

    def close(self):
        pass


class FakeConnectionFactory:
    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        return FakeConnection(self)

    @staticmethod
    def response_body(method, target):
        if "/file" in (target or ""):
            return b"PK\x03\x04REPORT-ZIP-CONTENT"
        if target and "/tasks/" in target and method == "GET":
            return b'{"id":"task-1","currentStatus":"PREPARATION"}'
        if target and "/results" in target:
            return b'{"list":[]}'
        if target and "/tasks" in target and method == "POST":
            return b'{"id":"task-1","currentStatus":"PREPARATION"}'
        return b'{"productGroups":[{"productGroupCode":1,"remainingCount":2}]}'


def create_payload(job_id: str = "rpt_123") -> dict:
    return validate_report_agent_payload(
        "REPORT_CREATE",
        {
            "local_report_job_id": job_id,
            "recipe": "FILTERED_CIS_REPORT",
            "product_group_code": "1",
            "filters": {
                "participant_inn": "1234567890",
                "package_type": ["UNIT"],
                "status": "INTRODUCED",
                "include_gtin": ["00000000000001"],
            },
        },
    )


def test_hard_security_gates_and_no_user_download() -> None:
    assert not PRODUCTION_TRUE_API_REPORTS_ENABLED
    assert not GENERIC_TRUE_API_REPORT_PROXY
    assert not ARBITRARY_REMOTE_URL_DOWNLOAD
    assert not CALLER_CONTROLLED_TRUE_API_HOST
    assert not CALLER_CONTROLLED_TRUE_API_PATH
    assert not CALLER_CONTROLLED_TRUE_API_METHOD
    assert not CALLER_CONTROLLED_FILESYSTEM_PATH
    assert not CALLER_CONTROLLED_STORAGE_KEY
    assert not PATH_TRAVERSAL_ALLOWED
    assert not REMOTE_RESULT_DELETE_ENABLED
    assert not USER_REPORT_DOWNLOAD_ENABLED
    assert FRONTEND_FREEZE_ACTIVE
    assert M12_DEPENDENCY_FOR_DOWNLOAD_AUTH == "PARTIAL"
    routes = Path("src/wbcz_web/api/routes.py").read_text(encoding="utf-8")
    assert '@router.get("/reports/' not in routes
    assert '@router.get("/report-artifacts/' not in routes


def test_local_report_catalog_has_all_required_types_and_blocker_labels() -> None:
    assert set(LOCAL_REPORT_CATALOG) == set(LocalReportType)
    assert len(LOCAL_REPORT_CATALOG) == 12
    m1 = LOCAL_REPORT_CATALOG[LocalReportType.CIS_INVENTORY_STORED_SNAPSHOT]
    assert m1.fixed_labels["observation_semantics"] == "LATEST_STORED_OBSERVATION"
    m7 = LOCAL_REPORT_CATALOG[LocalReportType.EDO_FOUNDATION_STATUS]
    assert m7.fixed_labels["blocker_reason"] == "M7_FULL_XML_WRITE_BLOCKED"
    m8 = LOCAL_REPORT_CATALOG[LocalReportType.SUZ_FOUNDATION_STATUS]
    assert m8.fixed_labels["blocker_reason"] == "M8_FULL_SUZ_WIRE_BLOCKED"
    assert m8.fixed_labels["km_decrypted"] is False
    m10 = LOCAL_REPORT_CATALOG[LocalReportType.OZON_FOUNDATION_STATUS]
    assert m10.fixed_labels["m10_wire_ready"] is False
    assert m10.fixed_labels["m10_executable_read_capabilities"] == "NONE"


def test_request_fingerprint_is_stable_and_only_accepted_fields_contribute() -> None:
    kwargs = dict(
        report_type="WB_RECONCILIATION_EVIDENCE",
        report_schema_version="1.0",
        participant_scope={"participant_inn": "1234567890"},
        normalized_filters={"state": "X", "nested": {"b": 2, "a": 1}},
        output_format="CSV",
        sensitivity_mode="BUSINESS_SENSITIVE",
        snapshot_policy_version="m11-v1",
    )
    a = canonical_request_fingerprint(**kwargs)
    b = canonical_request_fingerprint(**{
        **kwargs,
        "normalized_filters": {"nested": {"a": 1, "b": 2}, "state": "X"},
    })
    assert a == b and len(a) == 64
    assert canonical_request_fingerprint(**{**kwargs, "output_format": "JSON"}) != a


def test_snapshot_descriptor_hash_is_reproducible_and_source_sensitive() -> None:
    a = ReportSnapshotDescriptor(
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        NOW,
        ("M1",),
        ("agent_jobs",),
        {"max_job": "42"},
        {"state": "X"},
        "1.0",
        row_count=10,
    )
    b = ReportSnapshotDescriptor(
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        NOW,
        ("M1",),
        ("agent_jobs",),
        {"max_job": "42"},
        {"state": "X"},
        "1.0",
        row_count=10,
    )
    c = ReportSnapshotDescriptor(
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        NOW,
        ("M1",),
        ("agent_jobs",),
        {"max_job": "43"},
        {"state": "X"},
        "1.0",
        row_count=10,
    )
    assert a.descriptor_sha256 == b.descriptor_sha256
    assert a.descriptor_sha256 != c.descriptor_sha256


def test_reconciliation_keeps_remote_local_and_final_semantics_separate() -> None:
    row = build_reconciliation_row(
        participant_inn="1234567890",
        domain="WB_FBS",
        source="WB_API",
        source_fingerprint="a" * 64,
        local_operation_id="op-1",
        remote_id="remote-1",
        remote_raw_state="sold",
        local_project_state="DISTANCE_PENDING",
        final_result=LocalReconciliationResult.PENDING_EVIDENCE,
        evidence_missing=True,
        conflict_state=None,
        observed_at="2026-09-18T12:00:00",
    )
    assert row["remote_raw_state"] == "sold"
    assert row["local_project_state"] == "DISTANCE_PENDING"
    assert row["final_reconciliation_result"] == "PENDING_EVIDENCE"
    assert row["observed_at"] == "2026-09-18T12:00:00"


def test_timestamp_unknown_is_not_silently_assigned_timezone() -> None:
    assert format_timestamp_preserving_unknown(datetime(2026, 9, 18, 12, 0)) == "2026-09-18T12:00:00|TIMEZONE_UNKNOWN"
    assert format_timestamp_preserving_unknown("2026-09-18 12:00:00") == "2026-09-18 12:00:00"
    assert parse_unambiguous_zulu_timestamp("2026-09-18T12:00:00Z").utcoffset() == timedelta(0)
    assert parse_unambiguous_zulu_timestamp("2026-09-18T12:00:00") is None


def test_csv_formula_protection_unicode_quotes_newlines_and_no_truncation(tmp_path: Path) -> None:
    renderer = StreamingReportRenderer(temp_root=tmp_path, max_bytes=2_000_000)
    long_value = "Ж" * 40000
    rows = [{
        "id": "00000000000000001234",
        "text": 'Кириллица, "quote"\nnext',
        "formula": "=2+2",
        "at": "@cmd",
        "tab": "\tcmd",
        "cr": "\rcmd",
        "long": long_value,
    }]
    artifact = renderer.render(
        rows,
        columns=("id", "text", "formula", "at", "tab", "cr", "long"),
        output_format=ReportOutputFormat.CSV,
    )
    with artifact.path.open("r", encoding="utf-8", newline="") as handle:
        raw = handle.read()
    assert "00000000000000001234" in raw
    assert "Кириллица" in raw
    assert "'=2+2" in raw and "'@cmd" in raw and "'\tcmd" in raw and "'\rcmd" in raw
    assert long_value in raw
    artifact.path.unlink()


def test_xlsx_identifiers_are_text_and_oversize_cell_fails_not_truncates(tmp_path: Path) -> None:
    renderer = StreamingReportRenderer(temp_root=tmp_path, max_bytes=5_000_000)
    artifact = renderer.render(
        [{"id": "00000000000000001234", "uuid": "00000000-0000-0000-0000-000000000001", "formula": "+1"}],
        columns=("id", "uuid", "formula"),
        output_format=ReportOutputFormat.XLSX,
    )
    wb = load_workbook(artifact.path, read_only=True, data_only=False)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=False))
    assert rows[1][0].value == "00000000000000001234"
    assert rows[1][0].data_type == "s"
    assert rows[1][2].value == "'+1"
    wb.close()
    artifact.path.unlink()
    with pytest.raises(ReportFormatError):
        renderer.render(
            [{"cell": "x" * 32768}],
            columns=("cell",),
            output_format=ReportOutputFormat.XLSX,
        )


def test_chunked_sensitive_artifact_encryption_roundtrip_wrong_key_and_tamper(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes((b"CIS-CONTROL-\x1d-SECRET-" * 100000))
    store = FilesystemReportArtifactStore(
        tmp_path / "store",
        key_provider=KeyProvider(),
        key_version="test-v1",
        chunk_bytes=4096,
    )
    result = store.put_file(
        source,
        sensitive=True,
        aad_context={"artifact_id": "a1", "report_job_id": "r1"},
        safe_suffix=".enc",
    )
    assert result.encryption_version == ARTIFACT_ENCRYPTION_FORMAT
    stored = (tmp_path / "store" / result.storage_key).read_bytes()
    assert b"CIS-CONTROL" not in stored
    output = io.BytesIO()
    size, digest = store.decrypt_sensitive_to(
        result.storage_key, output,
        aad_context={"artifact_id": "a1", "report_job_id": "r1"},
    )
    assert output.getvalue() == source.read_bytes()
    assert size == source.stat().st_size
    assert digest == result.plaintext_sha256

    wrong = FilesystemReportArtifactStore(
        tmp_path / "store",
        key_provider=KeyProvider(b"x" * 32),
        key_version="test-v1",
        chunk_bytes=4096,
    )
    with pytest.raises(ReportSecurityError):
        wrong.decrypt_sensitive_to(
            result.storage_key, io.BytesIO(),
            aad_context={"artifact_id": "a1", "report_job_id": "r1"},
        )

    path = tmp_path / "store" / result.storage_key
    data = bytearray(path.read_bytes())
    data[-10] ^= 1
    path.write_bytes(data)
    with pytest.raises(ReportSecurityError):
        store.decrypt_sensitive_to(
            result.storage_key, io.BytesIO(),
            aad_context={"artifact_id": "a1", "report_job_id": "r1"},
        )


def test_filesystem_artifact_store_generates_key_and_rejects_path_traversal(tmp_path: Path) -> None:
    source = tmp_path / "x.txt"
    source.write_text("safe", encoding="utf-8")
    store = FilesystemReportArtifactStore(tmp_path / "store")
    result = store.put_file(source, sensitive=False, aad_context={}, safe_suffix=".txt")
    assert "/" not in result.storage_key and "\\" not in result.storage_key
    with pytest.raises(ReportSecurityError):
        store.inspect("../escape")


def test_artifact_reuse_requires_exact_snapshot_schema_format_and_ready() -> None:
    base = dict(
        old_request_fingerprint="a",
        new_request_fingerprint="a",
        old_snapshot_hash="s",
        new_snapshot_hash="s",
        old_schema_version="1",
        new_schema_version="1",
        old_format="CSV",
        new_format="CSV",
        ready=True,
        expired_or_deleted=False,
    )
    assert artifact_reuse_allowed(**base)
    assert not artifact_reuse_allowed(**{**base, "new_snapshot_hash": "other"})
    assert not artifact_reuse_allowed(**{**base, "ready": False})
    assert not artifact_reuse_allowed(**{**base, "expired_or_deleted": True})


def test_dispenser_registry_exact_capabilities_and_delete_disabled() -> None:
    expected = {
        DispenserCapabilityName.CREATE_EXPORT: ("POST", "/api/v3/true-api/dispenser/tasks", 15),
        DispenserCapabilityName.GET_TASK: ("GET", "/api/v3/true-api/dispenser/tasks/{taskId}", 5),
        DispenserCapabilityName.LIST_TASKS: ("GET", "/api/v3/true-api/dispenser/tasks", 5),
        DispenserCapabilityName.LIST_RESULTS: ("GET", "/api/v3/true-api/dispenser/results", 12),
        DispenserCapabilityName.DOWNLOAD_RESULT: ("GET", "/api/v3/true-api/dispenser/results/{resultId}/file", 12),
        DispenserCapabilityName.QUOTA_BY_TASK_TYPE: ("GET", "/api/v3/true-api/dispenser/tasktypes/available_count", 10),
        DispenserCapabilityName.QUOTA_BY_REPORT: ("GET", "/api/v3/true-api/dispenser/tasktypes/reports/{report_id}/available_count", 10),
    }
    for name, (method, path, rate) in expected.items():
        cap = DISPENSER_CAPABILITIES[name]
        assert cap.enabled and cap.method == method and cap.path_template == path and cap.requests_per_minute == rate
    delete = DISPENSER_CAPABILITIES[DispenserCapabilityName.REMOTE_RESULT_DELETE]
    assert delete.method == "DELETE" and not delete.enabled
    assert not REMOTE_RESULT_DELETE_ENABLED


def test_filtered_cis_recipe_is_only_enabled_create_recipe_and_has_no_raw_params_input() -> None:
    assert enabled_remote_recipes() == ("FILTERED_CIS_REPORT",)
    assert "DOCUMENTS_ERRORS" in disabled_remote_recipes()
    filters = FilteredCisFilters(
        "1234567890", ("UNIT", "SET"), "INTRODUCED",
        ("00000000000001",),
    )
    body = build_filtered_cis_create_body(product_group_code="1", filters=filters)
    assert body == {
        "format": "CSV",
        "name": "FILTERED_CIS_REPORT",
        "periodicity": "SINGLE",
        "productGroupCode": "1",
        "params": '{"includeGtin":["00000000000001"],"packageType":["UNIT","SET"],"participantInn":"1234567890","status":"INTRODUCED"}',
    }
    with pytest.raises(ReportContractError):
        validate_report_agent_payload(
            "REPORT_CREATE",
            {**create_payload(), "params": '{"raw":"forbidden"}'},
        )
    with pytest.raises(ReportContractError):
        validate_report_agent_payload(
            "REPORT_CREATE",
            {
                "local_report_job_id": "r1",
                "recipe": "DOCUMENTS_ERRORS",
                "product_group_code": "1",
                "filters": {},
            },
        )


def test_include_gtin_max_1000_and_status_required_in_restricted_recipe() -> None:
    FilteredCisFilters("1234567890", ("UNIT",), "INTRODUCED", tuple(str(i) for i in range(1000))).validate()
    with pytest.raises(ReportContractError):
        FilteredCisFilters("1234567890", ("UNIT",), "INTRODUCED", tuple(str(i) for i in range(1001))).validate()
    with pytest.raises(ReportContractError):
        FilteredCisFilters("1234567890", ("UNIT",), None, ()).validate()


def test_dispenser_specs_are_fixed_and_quota_report_is_typed() -> None:
    create = build_dispenser_spec("REPORT_CREATE", create_payload())
    assert create.method == "POST"
    assert create.target == "/api/v3/true-api/dispenser/tasks"
    assert create.json_body["name"] == "FILTERED_CIS_REPORT"

    task = build_dispenser_spec(
        "REPORT_TASK_GET",
        {"local_report_job_id": "r1", "task_id": "task-1", "product_group_code": "1"},
    )
    assert task.target == "/api/v3/true-api/dispenser/tasks/task-1?pg=1"

    results = build_dispenser_spec(
        "REPORT_RESULTS",
        {"local_report_job_id": "r1", "page": 0, "size": 100, "product_group_code": "1", "task_ids": ["task-1"]},
    )
    assert results.target.startswith("/api/v3/true-api/dispenser/results?")
    assert "task_ids=task-1" in results.target

    quota = build_dispenser_spec(
        "REPORT_QUOTA_ID",
        {"local_report_job_id": "r1", "report_id": "ppr-1955-1-gismt-c", "product_group_code": "1"},
    )
    assert quota.target == "/api/v3/true-api/dispenser/tasktypes/reports/ppr-1955-1-gismt-c/available_count?pg=1"

    with pytest.raises(ReportContractError):
        build_dispenser_spec(
            "REPORT_QUOTA_ID",
            {"local_report_job_id": "r1", "report_id": "../escape", "product_group_code": "1"},
        )


def test_remote_raw_statuses_preserve_known_and_unknown_exactly() -> None:
    for status in KNOWN_REMOTE_TASK_STATUSES:
        parsed = normalize_remote_task_status(status)
        assert parsed.raw == status and parsed.known
    future = normalize_remote_task_status("FUTURE_STATUS")
    assert future.raw == "FUTURE_STATUS" and not future.known

    for status in KNOWN_REMOTE_DOWNLOAD_STATUSES:
        assert normalize_remote_download_status(status).known
    assert not normalize_remote_download_status("FUTURE").known

    for status in KNOWN_REMOTE_AVAILABILITY:
        assert normalize_remote_availability(status).known
    assert not normalize_remote_availability("FUTURE").known


def test_result_parser_never_turns_remote_file_path_into_fetch_url() -> None:
    parsed = parse_result_evidence({
        "id": "res-1",
        "taskId": "task-1",
        "archiveSize": 123,
        "available": "AVAILABLE",
        "downloadStatus": "SUCCESS",
        "fileDeleteDate": "2026-09-20T12:00:00.000Z",
        "resultFileParts": [{"id": "part-1", "filePath": "../../secret"}],
    })
    assert parsed.result_id == "res-1"
    assert parsed.result_file_parts[0]["filePath"] == "../../secret"
    assert not hasattr(parsed, "fetch_url")


def transport(factory: FakeConnectionFactory, clock=lambda: 0.0) -> ProductionAgentTrueApiTransport:
    return ProductionAgentTrueApiTransport(
        tunnel=FakeTunnel(),
        audit=FakeAudit(),
        connection_factory=factory,
        report_rate_limiter=DispenserRateLimiter(),
        monotonic_clock=clock,
        production_true_api_reports=True,
    )


def test_actual_transport_enforces_create_15_per_minute_before_network() -> None:
    factory = FakeConnectionFactory()
    tx = transport(factory)
    payload = create_payload()
    for _ in range(REPORT_CREATE_RATE_PER_MINUTE):
        tx.m11_report("REPORT_CREATE", payload, bearer_token="BEARER-CANARY", rate_scope="1234567890")
    with pytest.raises(ReportRateLimitExceeded) as exc:
        tx.m11_report("REPORT_CREATE", payload, bearer_token="BEARER-CANARY", rate_scope="1234567890")
    assert exc.value.retry_after_seconds == pytest.approx(60.0)
    assert len(factory.calls) == 15
    assert all("BEARER-CANARY" in call[2]["Authorization"] for call in factory.calls)


def test_actual_transport_task_family_shared_5_per_minute() -> None:
    factory = FakeConnectionFactory()
    tx = transport(factory)
    get_payload = {"local_report_job_id": "r1", "task_id": "task-1", "product_group_code": "1"}
    list_payload = {"local_report_job_id": "r1", "page": 0, "size": 10, "product_group_code": "1"}
    for _ in range(4):
        tx.m11_report("REPORT_TASK_GET", get_payload, bearer_token="B", rate_scope="inn")
    tx.m11_report("REPORT_TASK_LIST", list_payload, bearer_token="B", rate_scope="inn")
    with pytest.raises(ReportRateLimitExceeded):
        tx.m11_report("REPORT_TASK_GET", get_payload, bearer_token="B", rate_scope="inn")
    assert len(factory.calls) == REPORT_TASK_RATE_PER_MINUTE


def test_actual_transport_results_and_download_share_12_per_minute() -> None:
    factory = FakeConnectionFactory()
    tx = transport(factory)
    payload = {"local_report_job_id": "r1", "page": 0, "size": 10, "product_group_code": "1", "task_ids": ["task-1"]}
    for _ in range(REPORT_RESULTS_RATE_PER_MINUTE):
        tx.m11_report("REPORT_RESULTS", payload, bearer_token="B", rate_scope="inn")
    with pytest.raises(ReportRateLimitExceeded):
        tx.m11_report_download(
            {
                "local_report_job_id": "r1",
                "result_id": "res-1",
                "result_part_id": None,
                "product_group_code": "1",
                "artifact_upload_id": "upl_" + "a" * 32,
                "expected_archive_size": None,
                "download_format": None,
            },
            bearer_token="B",
            rate_scope="inn",
            sink=io.BytesIO(),
        )
    assert len(factory.calls) == REPORT_RESULTS_RATE_PER_MINUTE


def test_actual_transport_quota_family_shared_10_per_minute_and_scopes_independent() -> None:
    factory = FakeConnectionFactory()
    tx = transport(factory)
    type_payload = {"local_report_job_id": "r1", "task_type_short_name": "FILTERED_CIS_REPORT", "product_group_code": "1"}
    report_payload = {"local_report_job_id": "r1", "report_id": "ppr-1955-1-gismt-c", "product_group_code": "1"}
    for _ in range(9):
        tx.m11_report("REPORT_QUOTA_TYPE", type_payload, bearer_token="B", rate_scope="inn-a")
    tx.m11_report("REPORT_QUOTA_ID", report_payload, bearer_token="B", rate_scope="inn-a")
    with pytest.raises(ReportRateLimitExceeded):
        tx.m11_report("REPORT_QUOTA_TYPE", type_payload, bearer_token="B", rate_scope="inn-a")
    tx.m11_report("REPORT_QUOTA_TYPE", type_payload, bearer_token="B", rate_scope="inn-b")
    assert len(factory.calls) == REPORT_QUOTA_RATE_PER_MINUTE + 1


def test_transport_default_production_report_gate_is_closed() -> None:
    factory = FakeConnectionFactory()
    tx = ProductionAgentTrueApiTransport(
        tunnel=FakeTunnel(),
        audit=FakeAudit(),
        connection_factory=factory,
    )
    with pytest.raises(Exception):
        tx.m11_report("REPORT_CREATE", create_payload(), bearer_token="B", rate_scope="inn")
    assert factory.calls == []


def test_recursive_security_sanitizer_removes_secret_and_full_marking_canaries() -> None:
    payload = {
        "Authorization": "Bearer SECRET-BEARER",
        "machine_token": "MACHINE-CANARY",
        "future": [{"key": "cis", "value": "FULL-CIS-CANARY"}],
        "nonSensitive": {"keep": "yes"},
    }
    safe = sanitize_report_evidence(payload)
    rendered = repr(safe)
    assert "SECRET-BEARER" not in rendered
    assert "MACHINE-CANARY" not in rendered
    assert "FULL-CIS-CANARY" not in rendered
    assert safe["nonSensitive"] == {"keep": "yes"}


def test_binary_artifact_ingress_streams_hashes_encrypts_and_replay_converges(tmp_path: Path) -> None:
    bindings = InMemoryUploadBindingStore()
    store = FilesystemReportArtifactStore(tmp_path / "store", key_provider=KeyProvider(), key_version="v1", chunk_bytes=16)
    ingress = BinaryArtifactIngress(binding_store=bindings, artifact_store=store, temp_root=tmp_path / "tmp", remote_download_byte_ceiling=10000)
    binding = ingress.prepare(
        report_job_id="rpt_1",
        remote_result_id="res-1",
        remote_result_part_id=None,
        product_group_code="1",
        expected_archive_size=12,
    )
    payload = b"PK0123456789"
    artifact = ingress.ingest(
        artifact_upload_id=binding.artifact_upload_id,
        report_job_id="rpt_1",
        remote_result_id="res-1",
        remote_result_part_id=None,
        chunks=[payload[:3], payload[3:]],
        observed_mime="application/zip",
    )
    assert artifact.byte_size == len(payload)
    assert artifact.sha256
    stored = (tmp_path / "store" / artifact.storage.storage_key).read_bytes()
    assert payload not in stored
    replay = ingress.ingest(
        artifact_upload_id=binding.artifact_upload_id,
        report_job_id="rpt_1",
        remote_result_id="res-1",
        remote_result_part_id=None,
        chunks=[payload],
        observed_mime="application/zip",
    )
    assert replay.artifact_id == artifact.artifact_id
    with pytest.raises(ArtifactIntegrityConflict):
        ingress.ingest(
            artifact_upload_id=binding.artifact_upload_id,
            report_job_id="rpt_1",
            remote_result_id="res-1",
            remote_result_part_id=None,
            chunks=[b"PKxxxxxxxxxx"],
            observed_mime="application/zip",
        )


def test_binary_artifact_ingress_binding_and_archive_size_fail_closed(tmp_path: Path) -> None:
    bindings = InMemoryUploadBindingStore()
    store = FilesystemReportArtifactStore(tmp_path / "store", key_provider=KeyProvider(), key_version="v1")
    ingress = BinaryArtifactIngress(binding_store=bindings, artifact_store=store, temp_root=tmp_path / "tmp")
    with pytest.raises(ReportSecurityError):
        ingress.ingest(
            artifact_upload_id="upl_" + "f" * 32,
            report_job_id="r",
            remote_result_id="res",
            remote_result_part_id=None,
            chunks=[b"x"],
            observed_mime=None,
        )
    binding = ingress.prepare(
        report_job_id="rpt_1",
        remote_result_id="res-1",
        remote_result_part_id="part-1",
        product_group_code="1",
        expected_archive_size=10,
    )
    with pytest.raises(ReportSecurityError):
        ingress.ingest(
            artifact_upload_id=binding.artifact_upload_id,
            report_job_id="WRONG",
            remote_result_id="res-1",
            remote_result_part_id="part-1",
            chunks=[b"1234567890"],
            observed_mime=None,
        )
    with pytest.raises(ArtifactIntegrityConflict):
        ingress.ingest(
            artifact_upload_id=binding.artifact_upload_id,
            report_job_id="rpt_1",
            remote_result_id="res-1",
            remote_result_part_id="part-1",
            chunks=[b"short"],
            observed_mime=None,
        )


class FakeSession:
    def bearer_token(self):
        return "BEARER-SHOULD-NOT-SERIALIZE"

    def observe_http_status(self, status):
        pass


class AmbiguousReportTransport:
    def __init__(self):
        self.calls = 0

    def m11_report(self, *args, **kwargs):
        self.calls += 1
        raise TrueApiError("network outcome unknown")


def report_create_job() -> AgentJob:
    return AgentJob(
        job_id="job_report_create_1",
        job_type=AgentJobType.REPORT_CREATE,
        operation_id="rpt_remote_1",
        pg="lp",
        expected_inn="1234567890",
        read_payload=create_payload("rpt_remote_1"),
    )


def test_ambiguous_create_is_durable_and_not_blindly_retried(tmp_path: Path) -> None:
    replay = WindowsAgentReplayStore(tmp_path / "replay.sqlite")
    fake = AmbiguousReportTransport()
    executor = DurableWindowsAgentExecutor(
        participant_inn="1234567890",
        transport=fake,
        session_manager=FakeSession(),
        document_signer=object(),
        replay_store=replay,
        production_write=False,
    )
    job = report_create_job()
    first = executor.execute(job)
    assert first.outcome == "REMOTE_CREATE_AMBIGUOUS"
    assert fake.calls == 1
    second = executor.execute(job)
    assert second.outcome == "REMOTE_CREATE_AMBIGUOUS"
    assert fake.calls == 1
    replay.close()


def test_unresolved_create_reservation_blocks_post_after_crash(tmp_path: Path) -> None:
    replay = WindowsAgentReplayStore(tmp_path / "replay.sqlite")
    fake = AmbiguousReportTransport()
    executor = DurableWindowsAgentExecutor(
        participant_inn="1234567890",
        transport=fake,
        session_manager=FakeSession(),
        document_signer=object(),
        replay_store=replay,
        production_write=False,
    )
    job = report_create_job()
    payload_sha = executor._report_create_payload_sha(job)
    replay.claim("m11-report-create:" + job.operation_id, payload_sha)
    with pytest.raises(AgentCreateOutcomeUnresolved):
        executor.execute(job)
    assert fake.calls == 0
    replay.close()


class FakeDownloadTransport:
    def m11_report_download(self, payload, *, bearer_token, rate_scope, sink):
        assert bearer_token == "BEARER-SHOULD-NOT-SERIALIZE"
        sink.write(b"ZIP-BINARY-SECRET")
        return {
            "http_status": 200,
            "byte_size": len(b"ZIP-BINARY-SECRET"),
            "sha256": __import__("hashlib").sha256(b"ZIP-BINARY-SECRET").hexdigest(),
            "content_type": "application/zip",
        }


def test_download_executor_uploads_file_and_result_json_contains_no_binary_base64(tmp_path: Path) -> None:
    from wbcz.windows_agent import WindowsAgentExecutor
    executor = WindowsAgentExecutor(
        participant_inn="1234567890",
        transport=FakeDownloadTransport(),
        session_manager=FakeSession(),
        document_signer=object(),
        production_write=False,
    )
    job = AgentJob(
        job_id="job_download",
        job_type=AgentJobType.REPORT_DOWNLOAD,
        operation_id="rpt_1",
        pg="lp",
        expected_inn="1234567890",
        read_payload=validate_report_agent_payload(
            "REPORT_DOWNLOAD",
            {
                "local_report_job_id": "rpt_1",
                "result_id": "res-1",
                "result_part_id": None,
                "product_group_code": "1",
                "artifact_upload_id": "upl_" + "a" * 32,
                "expected_archive_size": None,
                "download_format": None,
            },
        ),
    )
    uploaded = {}

    def upload(metadata, path):
        uploaded["metadata"] = dict(metadata)
        uploaded["bytes"] = path.read_bytes()

    result = executor.execute_report_download(job, upload=upload)
    assert uploaded["bytes"] == b"ZIP-BINARY-SECRET"
    rendered = json.dumps(result.safe_dict())
    assert "ZIP-BINARY-SECRET" not in rendered
    assert "WklQLUJJTkFSWS1TRUNSRVQ" not in rendered
    assert result.outcome == "REPORT_ARTIFACT_UPLOADED"


def _ensure_m11_report_tables(engine) -> None:
    names = (
        "report_snapshots", "report_jobs", "report_artifacts",
        "report_job_events", "report_artifact_uploads",
    )
    tables = [Base.metadata.tables[name] for name in names]
    Base.metadata.create_all(engine, tables=tables, checkfirst=True)


@pytest.mark.skipif(not os.getenv("WBCZ_TEST_DATABASE_URL"), reason="PostgreSQL integration database not configured")
def test_db_backed_report_claim_lease_recovery_bounded_attempts_and_no_double_worker() -> None:
    engine = create_engine(os.environ["WBCZ_TEST_DATABASE_URL"])
    _ensure_m11_report_tables(engine)
    with Session(engine) as db:
        repo = SqlReportRepository(db)
        row = repo.create_job(
            origin="LOCAL",
            participant_inn="1234567890",
            report_type=LocalReportType.OZON_FOUNDATION_STATUS.value,
            report_schema_version="1.0",
            output_format="CSV",
            sensitivity_class="NORMAL",
            filters_sanitized={},
            sensitive_filter_ref=None,
            request_fingerprint_sha256="a" * 64,
            requested_by_user_id=None,
        )
        repo.queue(row.id)
        base = datetime.now(timezone.utc)
        first = repo.claim_next(worker_id="w1", lease_seconds=30, max_attempts=2, now=base)
        assert first and first.attempt_count == 1
        assert repo.claim_next(worker_id="w2", lease_seconds=30, max_attempts=2, now=base + timedelta(seconds=10)) is None
        second = repo.claim_next(worker_id="w2", lease_seconds=30, max_attempts=2, now=base + timedelta(seconds=31))
        assert second and second.attempt_count == 2 and second.lease_owner == "w2"
        assert repo.claim_next(worker_id="w3", lease_seconds=30, max_attempts=2, now=base + timedelta(seconds=62)) is None
        assert db.get(ReportJobRecord, row.id).state == "FAILED"
        db.rollback()
    engine.dispose()


@pytest.mark.skipif(not os.getenv("WBCZ_TEST_DATABASE_URL"), reason="PostgreSQL integration database not configured")
def test_synchronous_local_worker_generates_ready_artifact_without_business_mutation(tmp_path: Path) -> None:
    engine = create_engine(os.environ["WBCZ_TEST_DATABASE_URL"])
    _ensure_m11_report_tables(engine)
    with Session(engine) as db:
        repo = SqlReportRepository(db)
        row = repo.create_job(
            origin="LOCAL",
            participant_inn="1234567890",
            report_type=LocalReportType.OZON_FOUNDATION_STATUS.value,
            report_schema_version="1.0",
            output_format="CSV",
            sensitivity_class="NORMAL",
            filters_sanitized={},
            sensitive_filter_ref=None,
            request_fingerprint_sha256="b" * 64,
            requested_by_user_id=None,
        )
        repo.queue(row.id)
        claimed = repo.claim_next(worker_id="sync", lease_seconds=60, max_attempts=3)
        assert claimed
        store = FilesystemReportArtifactStore(tmp_path / "store", key_provider=KeyProvider(), key_version="v1")
        executor = SynchronousReportExecutor(
            db,
            artifact_store=store,
            temp_root=tmp_path / "tmp",
            participant_inn="1234567890",
        )
        result = executor.execute_claimed(claimed)
        assert result.row_count == 1
        assert db.get(ReportJobRecord, row.id).state == "READY"
        artifact = db.get(ReportArtifactRecord, result.artifact_id)
        assert artifact and artifact.state == "READY" and artifact.artifact_role == "OUTPUT"
        snapshot = db.get(ReportSnapshotRecord, db.get(ReportJobRecord, row.id).snapshot_id)
        assert snapshot and snapshot.descriptor_sha256 == result.snapshot_hash
        db.rollback()
    engine.dispose()


def test_persistence_models_have_no_bearer_token_pin_private_key_or_plaintext_cis_columns() -> None:
    for model in (ReportJobRecord, ReportSnapshotRecord, ReportArtifactRecord, ReportJobEventRecord, ReportArtifactUploadRecord):
        columns = {x.lower() for x in model.__table__.columns.keys()}
        assert not {
            "bearer", "bearer_token", "uuidtoken", "token", "machine_token", "pin",
            "private_key", "certificate_private_key", "cis", "kiz", "sgtin", "full_cis",
        } & columns
    assert {"storage_key", "sha256", "byte_size", "encryption_metadata"} <= set(ReportArtifactRecord.__table__.columns.keys())


def test_migration_head_contract_and_agent_types_are_bounded() -> None:
    migration = Path("migrations/versions/0012_m11_reports.py").read_text(encoding="utf-8")
    assert 'revision = "0012_m11_reports"' in migration
    assert 'down_revision = "0011_m10_ozon"' in migration
    for job_type in M11_AGENT_JOB_TYPES:
        assert job_type in migration
    for forbidden in ("TRUE_API_HTTP", "REPORT_HTTP", "ARBITRARY_REQUEST"):
        assert forbidden not in migration


def test_no_generic_true_api_proxy_arbitrary_url_or_user_download_surface() -> None:
    source = Path("src/wbcz/m11_reports.py").read_text(encoding="utf-8")
    windows = Path("src/wbcz/windows_agent.py").read_text(encoding="utf-8")
    routes = Path("src/wbcz_web/api/agent_routes.py").read_text(encoding="utf-8")
    for forbidden in (
        "GenericTrueApiReportProxy", "execute(method, url", "remote_url",
        "caller_storage_key", "caller_path",
    ):
        assert forbidden not in source
    assert "report-artifacts/{artifact_upload_id}" in routes
    assert "request.stream()" in routes
    assert "request.body()" not in routes[routes.find("agent_report_artifact_ingress"):]
    assert "base64.b64encode" not in windows[windows.find("def execute_report_download"):windows.find("def _cis_check")]


# M11 acceptance FIX-01: tenant isolation, effective filters, LP recipe and configurable limits.

def test_filtered_cis_lp_contract_is_fail_closed_before_network() -> None:
    assert LP_PRODUCT_GROUP_CODE == "1"
    assert FILTERED_CIS_LP_PACKAGE_TYPES == {"UNIT", "SET", "BUNDLE", "BOX", "ATK"}
    assert FILTERED_CIS_LP_STATUSES == {
        "EMITTED", "APPLIED", "INTRODUCED", "WRITTEN_OFF", "RETIRED", "DISAGGREGATION",
    }
    assert SOURCE_AMBIGUITY_PACKAGE_LEVEL_VALUES == "SOURCE_AMBIGUITY_PACKAGE_LEVEL_VALUES"
    for package_type in FILTERED_CIS_LP_PACKAGE_TYPES:
        FilteredCisFilters("1234567890", (package_type,), "INTRODUCED").validate()
    for package_type in ("GROUP", "LEVEL1", "LEVEL2", "LEVEL3", "LEVEL4", "LEVEL5", "FUTURE"):
        with pytest.raises(ReportContractError):
            FilteredCisFilters("1234567890", (package_type,), "INTRODUCED").validate()
    for status in FILTERED_CIS_LP_STATUSES:
        FilteredCisFilters("1234567890", ("UNIT",), status).validate()
    for status in ("WITHDRAWN", "DISAGGREGATED", "APPLIED_NOT_PAID", "FUTURE"):
        with pytest.raises(ReportContractError):
            FilteredCisFilters("1234567890", ("UNIT",), status).validate()
    for pg in (2, 3, 999, "2", "999"):
        with pytest.raises(ReportContractError):
            build_filtered_cis_create_body(
                product_group_code=pg,
                filters=FilteredCisFilters("1234567890", ("UNIT",), "INTRODUCED"),
            )

    factory = FakeConnectionFactory()
    tx = transport(factory)
    invalids = [
        {**create_payload(), "product_group_code": "2"},
        {**create_payload(), "filters": {**create_payload()["filters"], "package_type": ["LEVEL1"]}},
        {**create_payload(), "filters": {**create_payload()["filters"], "package_type": ["GROUP"]}},
        {**create_payload(), "filters": {**create_payload()["filters"], "package_type": ["FUTURE"]}},
        {**create_payload(), "filters": {**create_payload()["filters"], "status": "WITHDRAWN"}},
        {**create_payload(), "filters": {**create_payload()["filters"], "status": "FUTURE"}},
    ]
    for payload in invalids:
        with pytest.raises(Exception):
            tx.m11_report("REPORT_CREATE", payload, bearer_token="B", rate_scope="1234567890")
    assert factory.calls == []


def test_agent_report_create_participant_must_equal_expected_inn() -> None:
    payload = create_payload()
    payload["filters"]["participant_inn"] = "9999999999"
    payload = validate_report_agent_payload("REPORT_CREATE", payload)
    job = AgentJob(
        job_id="job_report_participant_mismatch",
        job_type=AgentJobType.REPORT_CREATE,
        operation_id="rpt_participant_mismatch",
        pg="lp",
        expected_inn="1234567890",
        read_payload=payload,
    )
    with pytest.raises(Exception):
        job.validate()


def test_p0_report_is_disabled_when_participant_scope_cannot_be_proved() -> None:
    definition = LOCAL_REPORT_CATALOG[LocalReportType.P0_IMPORT_CONTROL_QUALITY]
    assert not definition.enabled
    assert definition.disabled_reason == "SOURCE_PARTICIPANT_SCOPE_NOT_PROVABLE"
    assert definition.allowed_filters == ()


def test_report_config_limits_are_typed_positive_and_route_has_no_hardcoded_2gib() -> None:
    config = WebConfig(
        database_url="postgresql+psycopg://u:p@localhost/db",
        own_inn="1234567890",
        environment="test",
        report_max_local_rows=17,
        report_max_artifact_bytes=1000,
        report_remote_download_byte_ceiling=900,
        report_db_fetch_batch_size=7,
        report_snapshot_timeout_seconds=8,
        report_worker_timeout_seconds=9,
        report_temp_storage_ceiling_bytes=800,
        report_min_free_disk_bytes=1,
    ).validate_for_startup()
    assert config.report_max_local_rows == 17
    assert config.report_db_fetch_batch_size == 7
    for field in (
        "report_max_local_rows", "report_max_artifact_bytes", "report_remote_download_byte_ceiling",
        "report_db_fetch_batch_size", "report_snapshot_timeout_seconds", "report_worker_timeout_seconds",
        "report_temp_storage_ceiling_bytes", "report_min_free_disk_bytes",
    ):
        kwargs = {field: 0}
        with pytest.raises(ValueError):
            WebConfig(
                database_url="postgresql+psycopg://u:p@localhost/db",
                own_inn="1234567890",
                environment="test",
                **kwargs,
            ).validate_for_startup()
    route = Path("src/wbcz_web/api/agent_routes.py").read_text(encoding="utf-8")
    assert "total > 2 * 1024 * 1024 * 1024" not in route
    assert "report_remote_download_byte_ceiling" in route
    assert "report_temp_storage_ceiling_bytes" in route
    assert "report_min_free_disk_bytes" in route


def test_binary_ingress_honors_temp_ceiling_and_min_free_disk(tmp_path: Path) -> None:
    bindings = InMemoryUploadBindingStore()
    store = FilesystemReportArtifactStore(tmp_path / "store", key_provider=KeyProvider(), key_version="v1")
    ingress = BinaryArtifactIngress(
        binding_store=bindings,
        artifact_store=store,
        temp_root=tmp_path / "tmp",
        remote_download_byte_ceiling=100,
        temp_storage_ceiling_bytes=4,
        min_free_disk_bytes=1,
    )
    binding = ingress.prepare(
        report_job_id="rpt_limit",
        remote_result_id="res-limit",
        remote_result_part_id=None,
        product_group_code="1",
        expected_archive_size=None,
    )
    with pytest.raises(ArtifactLimitExceeded):
        ingress.ingest(
            artifact_upload_id=binding.artifact_upload_id,
            report_job_id="rpt_limit",
            remote_result_id="res-limit",
            remote_result_part_id=None,
            chunks=[b"12345"],
            observed_mime="application/zip",
        )
    assert not list((tmp_path / "tmp").glob("m11-agent-upload-*"))

    impossible = BinaryArtifactIngress(
        binding_store=InMemoryUploadBindingStore(),
        artifact_store=store,
        temp_root=tmp_path / "tmp2",
        remote_download_byte_ceiling=100,
        temp_storage_ceiling_bytes=100,
        min_free_disk_bytes=2**63 - 1,
    )
    b2 = impossible.prepare(
        report_job_id="rpt_disk",
        remote_result_id="res-disk",
        remote_result_part_id=None,
        product_group_code="1",
        expected_archive_size=None,
    )
    with pytest.raises(ArtifactLimitExceeded):
        impossible.ingest(
            artifact_upload_id=b2.artifact_upload_id,
            report_job_id="rpt_disk",
            remote_result_id="res-disk",
            remote_result_part_id=None,
            chunks=[b"x"],
            observed_mime=None,
        )


def _seed_agent_job(
    db: Session,
    *,
    job_id: str,
    job_type: str,
    purpose: str,
    inn: str,
    result_json: dict | None = None,
    read_payload: dict | None = None,
    state: str = "COMPLETED",
) -> None:
    payload = {
        "job_id": job_id,
        "job_type": job_type,
        "operation_id": "op_" + job_id,
        "pg": "lp",
        "expected_inn": inn,
        "document_type": None,
        "document_sha256": None,
        "product_document_base64": None,
        "cises": [],
        "document_id": None,
        "read_payload": read_payload,
    }
    db.add(AgentJobRecord(
        job_id=job_id,
        job_type=job_type,
        operation_id="op_" + job_id,
        purpose=purpose,
        event_id=None,
        control_run_id=None,
        poll_attempt=0,
        payload_sha256=hashlib.sha256(job_id.encode()).hexdigest(),
        payload_json=payload,
        state=state,
        delivery_count=0,
        result_json=result_json,
    ))
    db.flush()


@pytest.mark.skipif(not os.getenv("WBCZ_TEST_DATABASE_URL"), reason="PostgreSQL integration database not configured")
def test_mixed_tenant_m1_m2_and_filters_are_effective() -> None:
    engine = create_engine(os.environ["WBCZ_TEST_DATABASE_URL"])
    Base.metadata.create_all(engine, checkfirst=True)
    with Session(engine) as db:
        for table in (AgentJobRecord,):
            db.query(table).delete()
        _seed_agent_job(
            db, job_id="m1-a", job_type="CIS_INFO", purpose="CIS_INVENTORY", inn="1234567890",
            result_json={"read_result": {"cises": [{"cis": "CIS-A", "status": "INTRODUCED"}, {"cis": "CIS-A2", "status": "EMITTED"}]}},
            read_payload={"cises": ["CIS-A"]},
        )
        _seed_agent_job(
            db, job_id="m1-b", job_type="CIS_INFO", purpose="CIS_INVENTORY", inn="9999999999",
            result_json={"read_result": {"cises": [{"cis": "CIS-B-SECRET", "status": "INTRODUCED"}]}},
            read_payload={"cises": ["CIS-B-SECRET"]},
        )
        _seed_agent_job(
            db, job_id="m2-a", job_type="PRODUCT_INFO", purpose="REFERENCE_PRODUCTS", inn="1234567890",
            result_json={"read_result": {}}, read_payload={"gtins": ["0001", "0002"]},
        )
        _seed_agent_job(
            db, job_id="m2-b", job_type="PRODUCT_INFO", purpose="REFERENCE_PRODUCTS", inn="9999999999",
            result_json={"read_result": {}}, read_payload={"gtins": ["9999"]},
        )
        db.commit()
        registry = LocalReportSourceRegistry("1234567890", fetch_batch_size=2)
        with engine.connect() as connection:
            m1 = list(registry.rows(connection, LocalReportType.CIS_INVENTORY_STORED_SNAPSHOT, filters={}))
            rendered = json.dumps(m1)
            assert "CIS-B-SECRET" not in rendered
            assert _fingerprint_for_test("CIS-B-SECRET") not in rendered
            wanted_fp = _fingerprint_for_test("CIS-A")
            assert [r["cis_fingerprint"] for r in registry.rows(
                connection, LocalReportType.CIS_INVENTORY_STORED_SNAPSHOT,
                filters={"participant_inn": "1234567890", "cis_fingerprint": wanted_fp},
            )] == [wanted_fp]
            assert all(r["raw_state"] == "EMITTED" for r in registry.rows(
                connection, LocalReportType.CIS_INVENTORY_STORED_SNAPSHOT,
                filters={"state": "EMITTED"},
            ))
            m2 = list(registry.rows(connection, LocalReportType.PRODUCT_REFERENCE_READINESS, filters={}))
            assert {r["gtin"] for r in m2} == {"0001", "0002"}
            assert [r["gtin"] for r in registry.rows(
                connection, LocalReportType.PRODUCT_REFERENCE_READINESS, filters={"gtin": "0002"},
            )] == ["0002"]
            assert list(registry.rows(
                connection, LocalReportType.PRODUCT_REFERENCE_READINESS, filters={"product_group": "other"},
            )) == []
            with pytest.raises(ReportSecurityError):
                list(registry.rows(
                    connection, LocalReportType.PRODUCT_REFERENCE_READINESS,
                    filters={"participant_inn": "9999999999"},
                ))
    engine.dispose()


def _fingerprint_for_test(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.mark.skipif(not os.getenv("WBCZ_TEST_DATABASE_URL"), reason="PostgreSQL integration database not configured")
def test_m4_m5_m6_are_join_scoped_and_filters_are_effective() -> None:
    engine = create_engine(os.environ["WBCZ_TEST_DATABASE_URL"])
    Base.metadata.create_all(engine, checkfirst=True)
    with Session(engine) as db:
        for table in (DocumentLifecycleLedgerRecord, TurnoverOperationLedgerRecord, AggregationOperationLedgerRecord, AgentJobRecord):
            db.query(table).delete()
        _seed_agent_job(db, job_id="m4-a", job_type="DOCUMENT_INFO", purpose="DOCUMENT_LIFECYCLE", inn="1234567890",
                        read_payload={"document_id": "doc-a", "body": False, "content": False},
                        result_json={"outcome": "READ_COMPLETED", "read_result": {"number": "doc-a", "status": {"raw": "CHECKED_OK"}}})
        _seed_agent_job(db, job_id="m4-b", job_type="DOCUMENT_INFO", purpose="DOCUMENT_LIFECYCLE", inn="9999999999",
                        read_payload={"document_id": "doc-b", "body": False, "content": False},
                        result_json={"outcome": "READ_COMPLETED", "read_result": {"number": "doc-b", "status": {"raw": "CHECKED_OK"}}})
        for suffix in ("a", "b"):
            db.add(DocumentLifecycleLedgerRecord(
                operation_id=f"m4-op-{suffix}", request_id=f"m4-{suffix}", job_type="DOCUMENT_INFO",
                request_sha256=("1" if suffix == "a" else "2") * 64,
                idempotency_key=f"idem-m4-{suffix}",
                request_json={"document_id": f"doc-{suffix}"},
            ))
        for prefix, model, kind1, kind2 in (
            ("m5", TurnoverOperationLedgerRecord, "WITHDRAW_DISTANCE", "REMOTE_SALE_RETURN"),
            ("m6", AggregationOperationLedgerRecord, "FORM_SET", "DISAGGREGATE_PACKAGE"),
        ):
            for suffix, inn, kind, state in (
                ("a1", "1234567890", kind1, "RECONCILED"),
                ("a2", "1234567890", kind2, "MANUAL_REVIEW"),
                ("b", "9999999999", kind1, "RECONCILED"),
            ):
                job_type = "LK_RECEIPT" if prefix == "m5" else "SETS_AGGREGATION"
                _seed_agent_job(db, job_id=f"{prefix}-{suffix}", job_type=job_type, purpose=prefix.upper(), inn=inn,
                                read_payload=None, result_json={})
                common = dict(
                    operation_id=f"{prefix}-op-{suffix}", request_id=f"{prefix}-{suffix}",
                    operation_kind=kind, document_type=job_type, document_sha256=(suffix[0] * 64),
                    request_sha256=(suffix[-1] * 64), idempotency_key=f"idem-{prefix}-{suffix}",
                    reconciliation_state=state, remote_document_id=f"remote-{prefix}-{suffix}",
                )
                if prefix == "m5":
                    db.add(model(
                        **common, raw_business_reason=None, precondition_snapshot={}, expected_postcondition={},
                        reconciliation_json={}, cancellation_reference=None,
                    ))
                else:
                    db.add(model(
                        **common, parent_cis=None, discovered_parent_cis=None, child_set_hash="c" * 64,
                        relation_delta="FORM" if "FORM" in kind else "DISAGGREGATE",
                        precondition_snapshot={}, expected_relation_delta={}, reconciliation_json={},
                        raw_history_evidence=[],
                    ))
        db.commit()
        registry = LocalReportSourceRegistry("1234567890")
        with engine.connect() as connection:
            m4 = list(registry.rows(connection, LocalReportType.DOCUMENT_LIFECYCLE, filters={}))
            assert [r["document_id"] for r in m4] == ["doc-a"]
            assert list(registry.rows(connection, LocalReportType.DOCUMENT_LIFECYCLE, filters={"document_id": "doc-b"})) == []
            assert len(list(registry.rows(connection, LocalReportType.DOCUMENT_LIFECYCLE, filters={"state": "COMPLETED"}))) == 1
            for report_type, prefix, kind in (
                (LocalReportType.TURNOVER_OPERATIONS, "m5", "REMOTE_SALE_RETURN"),
                (LocalReportType.AGGREGATION_OPERATIONS, "m6", "DISAGGREGATE_PACKAGE"),
            ):
                rows = list(registry.rows(connection, report_type, filters={}))
                assert len(rows) == 2
                assert all("-b" not in r["operation_id"] for r in rows)
                filtered = list(registry.rows(connection, report_type, filters={"operation_kind": kind}))
                assert len(filtered) == 1 and filtered[0]["operation_kind"] == kind
                manual = list(registry.rows(connection, report_type, filters={"state": "MANUAL_REVIEW"}))
                assert len(manual) == 1 and manual[0]["reconciliation_state"] == "MANUAL_REVIEW"
    engine.dispose()


@pytest.mark.skipif(not os.getenv("WBCZ_TEST_DATABASE_URL"), reason="PostgreSQL integration database not configured")
def test_wb_mixed_tenant_manual_end_to_end_and_filters() -> None:
    engine = create_engine(os.environ["WBCZ_TEST_DATABASE_URL"])
    Base.metadata.create_all(engine, checkfirst=True)
    with Session(engine) as db:
        db.query(WbReconciliationRecord).delete()
        db.query(WbEventRecord).delete()
        db.query(WbOrderRecord).delete()
        db.query(WbConnectionRecord).delete()
        connections = {}
        for label, inn in (("a", "1234567890"), ("b", "9999999999")):
            conn = WbConnectionRecord(
                environment="PRODUCTION", participant_inn=inn, wb_sid=None, wb_tin=inn,
                token_type="PERSONAL", token_categories=[], token_scopes=[], secret_ref=f"secret-{label}",
                rate_profile=None, connection_state="HEALTHY",
            )
            db.add(conn); db.flush()
            connections[label] = conn
            order = WbOrderRecord(
                connection_id=conn.id, assembly_order_id=1 if label == "a" else 999,
                skus=[], fulfillment_model="FBS", source="WB_API", source_fingerprint=(label * 64),
                raw_evidence_hash=(label.upper() * 64), observed_at=NOW,
            )
            db.add(order); db.flush()
            event = WbEventRecord(
                connection_id=conn.id, source="WB_API", source_family="ORDER_FEED",
                source_fingerprint=(label + "e") * 32, assembly_order_id=order.assembly_order_id,
                raw_status="sold", raw_evidence_sanitized={}, raw_evidence_hash=(label + "h") * 32,
                observed_at=NOW,
            )
            db.add(event)
            db.add(WbReconciliationRecord(
                connection_id=conn.id, order_id=order.id,
                state="MANUAL_REVIEW" if label == "a" else "DISTANCE_RECONCILED",
                decision="MANUAL_REVIEW" if label == "a" else "MATCHED",
                reason="A_REASON" if label == "a" else "B_SECRET_REASON",
                evidence_redacted={"tenant": label}, observed_at=NOW,
            ))
        db.commit()
        registry = LocalReportSourceRegistry("1234567890")
        with engine.connect() as connection:
            wb = list(registry.rows(connection, LocalReportType.WB_RECONCILIATION_EVIDENCE, filters={}))
            assert len(wb) == 1 and wb[0]["assembly_order_id"] == "1"
            assert "999" not in json.dumps(wb)
            assert len(list(registry.rows(connection, LocalReportType.WB_RECONCILIATION_EVIDENCE,
                                          filters={"state": "MANUAL_REVIEW"}))) == 1
            assert len(list(registry.rows(connection, LocalReportType.WB_RECONCILIATION_EVIDENCE,
                                          filters={"conflict_state": "CONFLICT"}))) == 1
            manual = list(registry.rows(connection, LocalReportType.MANUAL_REVIEW_AND_CONFLICTS,
                                        filters={"domain": "WB", "reason": "A_REASON"}))
            assert len(manual) == 1
            end = list(registry.rows(connection, LocalReportType.END_TO_END_RECONCILIATION,
                                     filters={"domain": "WB_FBS", "result": "MANUAL_REVIEW"}))
            assert len(end) == 1
            assert "B_SECRET_REASON" not in json.dumps(manual + end)
    engine.dispose()


@pytest.mark.skipif(not os.getenv("WBCZ_TEST_DATABASE_URL"), reason="PostgreSQL integration database not configured")
def test_every_enabled_local_report_adapter_executes_against_current_postgres_schema() -> None:
    engine = create_engine(os.environ["WBCZ_TEST_DATABASE_URL"])
    Base.metadata.create_all(engine, checkfirst=True)
    registry = LocalReportSourceRegistry("1234567890", fetch_batch_size=3)
    with engine.connect() as connection:
        for report_type, definition in LOCAL_REPORT_CATALOG.items():
            if not definition.enabled:
                continue
            rows = registry.rows(
                connection,
                report_type,
                filters={"participant_inn": "1234567890"} if "participant_inn" in definition.allowed_filters else {},
            )
            list(rows)
    engine.dispose()


def test_declared_filters_are_exactly_the_implemented_enabled_set() -> None:
    enabled_filters = {
        report_type.value: definition.allowed_filters
        for report_type, definition in LOCAL_REPORT_CATALOG.items()
        if definition.enabled
    }
    assert sum(len(filters) for filters in enabled_filters.values()) == 27
    assert LOCAL_REPORT_CATALOG[LocalReportType.P0_IMPORT_CONTROL_QUALITY].allowed_filters == ()
    assert all("participant_inn" in filters for filters in enabled_filters.values())


def test_report_job_service_rejects_participant_mismatch_and_disabled_report(monkeypatch) -> None:
    class DummyRepo:
        def create_job(self, **kwargs):
            raise AssertionError("must reject before persistence")
    service = object.__new__(ReportJobService)
    service.db = None
    service.participant_inn = "1234567890"
    service.repo = DummyRepo()
    with pytest.raises(ReportSecurityError):
        service.request_local(
            report_type=LocalReportType.CIS_INVENTORY_STORED_SNAPSHOT,
            output_format=ReportOutputFormat.CSV,
            filters={"participant_inn": "9999999999"},
        )
    with pytest.raises(ReportSecurityError):
        service.request_local(
            report_type=LocalReportType.P0_IMPORT_CONTROL_QUALITY,
            output_format=ReportOutputFormat.CSV,
            filters={},
        )
