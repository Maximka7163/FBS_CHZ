from __future__ import annotations

import csv
import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
import struct
import tempfile
import time
import uuid
import zipfile
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urlencode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell


M11_CONTRACT_REVISION = "198.0"
PRODUCTION_TRUE_API_REPORTS_ENABLED = False
GENERIC_TRUE_API_REPORT_PROXY = False
ARBITRARY_REMOTE_URL_DOWNLOAD = False
CALLER_CONTROLLED_TRUE_API_HOST = False
CALLER_CONTROLLED_TRUE_API_PATH = False
CALLER_CONTROLLED_TRUE_API_METHOD = False
CALLER_CONTROLLED_FILESYSTEM_PATH = False
CALLER_CONTROLLED_STORAGE_KEY = False
PATH_TRAVERSAL_ALLOWED = False
REMOTE_RESULT_DELETE_ENABLED = False
USER_REPORT_DOWNLOAD_ENABLED = False
FRONTEND_FREEZE_ACTIVE = True
REPORT_ROWS_ARE_READ_ONLY = True
REPORT_GENERATION_MUST_NOT_CHANGE_RECONCILIATION = True
PROJECT_RETENTION_NOT_FINALIZED = True
M12_DEPENDENCY_FOR_DOWNLOAD_AUTH = "PARTIAL"

REPORT_CREATE_RATE_PER_MINUTE = 15
REPORT_TASK_RATE_PER_MINUTE = 5
REPORT_RESULTS_RATE_PER_MINUTE = 12
REPORT_QUOTA_RATE_PER_MINUTE = 10

M11_AGENT_JOB_TYPES = frozenset(
    {
        "REPORT_CREATE",
        "REPORT_TASK_GET",
        "REPORT_TASK_LIST",
        "REPORT_RESULTS",
        "REPORT_DOWNLOAD",
        "REPORT_QUOTA_TYPE",
        "REPORT_QUOTA_ID",
    }
)

KNOWN_REMOTE_TASK_STATUSES = frozenset({"PREPARATION", "COMPLETED", "CANCELED", "ARCHIVE", "FAILED"})
KNOWN_REMOTE_DOWNLOAD_STATUSES = frozenset({"SUCCESS", "PREPARATION", "FAILED"})
KNOWN_REMOTE_AVAILABILITY = frozenset({"AVAILABLE", "NOT_AVAILABLE"})
REMOTE_CREATE_AMBIGUOUS = "REMOTE_CREATE_AMBIGUOUS"

M7_FULL_XML_WRITE_BLOCKED = True
M8_FULL_SUZ_WIRE_BLOCKED = True
M10_WIRE_READY = False
M10_EXECUTABLE_READ_CAPABILITIES = "NONE"

DEFAULT_FETCH_BATCH_SIZE = 500
DEFAULT_MAX_LOCAL_ROWS = 1_000_000
DEFAULT_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_REMOTE_DOWNLOAD_BYTE_CEILING = 2 * 1024 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024


class ReportError(RuntimeError):
    pass


class ReportSecurityError(ReportError):
    pass


class ReportContractError(ReportError):
    pass


class ReportRateLimitExceeded(ReportError):
    def __init__(self, family: str, retry_after_seconds: float) -> None:
        self.family = family
        self.retry_after_seconds = max(0.0, float(retry_after_seconds))
        super().__init__(f"report rate limit exceeded for {family}")


class ArtifactIntegrityConflict(ReportError):
    pass


class ArtifactLimitExceeded(ReportError):
    pass


class ReportFormatError(ReportError):
    pass


class ReportJobState(StrEnum):
    REQUESTED = "REQUESTED"
    QUEUED = "QUEUED"
    GENERATING = "GENERATING"
    READY = "READY"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class ReportOrigin(StrEnum):
    LOCAL = "LOCAL"
    TRUE_API_REMOTE = "TRUE_API_REMOTE"


class ReportOutputFormat(StrEnum):
    CSV = "CSV"
    XLSX = "XLSX"
    JSON = "JSON"
    ZIP = "ZIP"


class ReportSensitivity(StrEnum):
    NORMAL = "NORMAL"
    BUSINESS_SENSITIVE = "BUSINESS_SENSITIVE"
    MARKING_SENSITIVE = "MARKING_SENSITIVE"


class ArtifactRole(StrEnum):
    OUTPUT = "OUTPUT"
    REMOTE_TRUE_API_ARCHIVE = "REMOTE_TRUE_API_ARCHIVE"
    SNAPSHOT_INTERNAL = "SNAPSHOT_INTERNAL"
    MANIFEST = "MANIFEST"


class SnapshotStrategy(StrEnum):
    APPEND_ONLY_HIGH_WATER = "APPEND_ONLY_HIGH_WATER"
    POSTGRES_CONSISTENT_SNAPSHOT = "POSTGRES_CONSISTENT_SNAPSHOT"
    MATERIALIZED_IMMUTABLE = "MATERIALIZED_IMMUTABLE"


class LocalReconciliationResult(StrEnum):
    MATCHED = "MATCHED"
    PENDING_EVIDENCE = "PENDING_EVIDENCE"
    CONFLICT = "CONFLICT"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    FAILED = "FAILED"


class LocalReportType(StrEnum):
    CIS_INVENTORY_STORED_SNAPSHOT = "CIS_INVENTORY_STORED_SNAPSHOT"
    PRODUCT_REFERENCE_READINESS = "PRODUCT_REFERENCE_READINESS"
    DOCUMENT_LIFECYCLE = "DOCUMENT_LIFECYCLE"
    TURNOVER_OPERATIONS = "TURNOVER_OPERATIONS"
    AGGREGATION_OPERATIONS = "AGGREGATION_OPERATIONS"
    EDO_FOUNDATION_STATUS = "EDO_FOUNDATION_STATUS"
    SUZ_FOUNDATION_STATUS = "SUZ_FOUNDATION_STATUS"
    WB_RECONCILIATION_EVIDENCE = "WB_RECONCILIATION_EVIDENCE"
    OZON_FOUNDATION_STATUS = "OZON_FOUNDATION_STATUS"
    MANUAL_REVIEW_AND_CONFLICTS = "MANUAL_REVIEW_AND_CONFLICTS"
    END_TO_END_RECONCILIATION = "END_TO_END_RECONCILIATION"
    P0_IMPORT_CONTROL_QUALITY = "P0_IMPORT_CONTROL_QUALITY"


@dataclass(frozen=True, slots=True)
class ReportTypeDefinition:
    report_type: LocalReportType
    schema_version: str
    source_adapter: str
    scope_required: bool
    allowed_filters: tuple[str, ...]
    columns: tuple[str, ...]
    sensitivity: ReportSensitivity
    output_formats: tuple[ReportOutputFormat, ...]
    snapshot_strategy: SnapshotStrategy
    fixed_labels: Mapping[str, Any] = field(default_factory=dict)
    enabled: bool = True
    disabled_reason: str | None = None


LOCAL_REPORT_CATALOG: Mapping[LocalReportType, ReportTypeDefinition] = {
    LocalReportType.CIS_INVENTORY_STORED_SNAPSHOT: ReportTypeDefinition(
        LocalReportType.CIS_INVENTORY_STORED_SNAPSHOT, "1.0", "M1StoredCisAdapter", True,
        ("participant_inn", "cis_fingerprint", "state"),
        ("participant_inn", "cis_masked", "cis_fingerprint", "raw_state", "observed_at", "observation_semantics"),
        ReportSensitivity.BUSINESS_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        {"observation_semantics": "LATEST_STORED_OBSERVATION"},
    ),
    LocalReportType.PRODUCT_REFERENCE_READINESS: ReportTypeDefinition(
        LocalReportType.PRODUCT_REFERENCE_READINESS, "1.0", "M2ProductReferenceAdapter", True,
        ("participant_inn", "gtin", "product_group"),
        ("participant_inn", "gtin", "product_group", "readiness", "source_fingerprint", "observed_at"),
        ReportSensitivity.NORMAL, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
    ),
    LocalReportType.DOCUMENT_LIFECYCLE: ReportTypeDefinition(
        LocalReportType.DOCUMENT_LIFECYCLE, "1.0", "M4DocumentLifecycleAdapter", True,
        ("participant_inn", "document_id", "state"),
        ("participant_inn", "document_id", "raw_remote_state", "local_project_state", "errors", "observed_at"),
        ReportSensitivity.BUSINESS_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.POSTGRES_CONSISTENT_SNAPSHOT,
    ),
    LocalReportType.TURNOVER_OPERATIONS: ReportTypeDefinition(
        LocalReportType.TURNOVER_OPERATIONS, "1.0", "M5TurnoverAdapter", True,
        ("participant_inn", "operation_kind", "state"),
        ("participant_inn", "operation_id", "operation_kind", "remote_document_id", "reconciliation_state", "observed_at"),
        ReportSensitivity.BUSINESS_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.POSTGRES_CONSISTENT_SNAPSHOT,
    ),
    LocalReportType.AGGREGATION_OPERATIONS: ReportTypeDefinition(
        LocalReportType.AGGREGATION_OPERATIONS, "1.0", "M6AggregationAdapter", True,
        ("participant_inn", "operation_kind", "state"),
        ("participant_inn", "operation_id", "operation_kind", "relation_delta", "reconciliation_state", "observed_at"),
        ReportSensitivity.MARKING_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.POSTGRES_CONSISTENT_SNAPSHOT,
    ),
    LocalReportType.EDO_FOUNDATION_STATUS: ReportTypeDefinition(
        LocalReportType.EDO_FOUNDATION_STATUS, "1.0", "M7EdoFoundationAdapter", True,
        ("participant_inn",),
        ("participant_inn", "foundation_state", "full_xml_write_blocked", "blocker_reason"),
        ReportSensitivity.NORMAL, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        {"full_xml_write_blocked": True, "blocker_reason": "M7_FULL_XML_WRITE_BLOCKED"},
    ),
    LocalReportType.SUZ_FOUNDATION_STATUS: ReportTypeDefinition(
        LocalReportType.SUZ_FOUNDATION_STATUS, "1.0", "M8SuzFoundationAdapter", True,
        ("participant_inn",),
        ("participant_inn", "foundation_state", "full_suz_wire_blocked", "km_decrypted", "blocker_reason"),
        ReportSensitivity.NORMAL, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        {"full_suz_wire_blocked": True, "km_decrypted": False, "blocker_reason": "M8_FULL_SUZ_WIRE_BLOCKED"},
    ),
    LocalReportType.WB_RECONCILIATION_EVIDENCE: ReportTypeDefinition(
        LocalReportType.WB_RECONCILIATION_EVIDENCE, "1.0", "M9WbReconciliationAdapter", True,
        ("participant_inn", "state", "conflict_state"),
        ("participant_inn", "assembly_order_id", "raw_remote_state", "local_project_state", "conflict_state", "source_fingerprint", "observed_at"),
        ReportSensitivity.BUSINESS_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.POSTGRES_CONSISTENT_SNAPSHOT,
    ),
    LocalReportType.OZON_FOUNDATION_STATUS: ReportTypeDefinition(
        LocalReportType.OZON_FOUNDATION_STATUS, "1.0", "M10OzonFoundationAdapter", True,
        ("participant_inn",),
        ("participant_inn", "foundation_state", "m10_wire_ready", "m10_executable_read_capabilities"),
        ReportSensitivity.NORMAL, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        {"m10_wire_ready": False, "m10_executable_read_capabilities": "NONE"},
    ),
    LocalReportType.MANUAL_REVIEW_AND_CONFLICTS: ReportTypeDefinition(
        LocalReportType.MANUAL_REVIEW_AND_CONFLICTS, "1.0", "CrossDomainManualReviewAdapter", True,
        ("participant_inn", "domain", "reason"),
        ("participant_inn", "domain", "remote_raw_state", "local_project_state", "final_reconciliation_result", "reason", "evidence_fingerprint"),
        ReportSensitivity.BUSINESS_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.POSTGRES_CONSISTENT_SNAPSHOT,
    ),
    LocalReportType.END_TO_END_RECONCILIATION: ReportTypeDefinition(
        LocalReportType.END_TO_END_RECONCILIATION, "1.0", "EndToEndReconciliationAdapter", True,
        ("participant_inn", "domain", "result"),
        ("participant_inn", "domain", "source", "source_fingerprint", "local_operation_id", "remote_id", "remote_raw_state", "local_project_state", "final_reconciliation_result", "evidence_missing", "conflict_state", "observed_at"),
        ReportSensitivity.MARKING_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON, ReportOutputFormat.ZIP),
        SnapshotStrategy.MATERIALIZED_IMMUTABLE,
    ),
    LocalReportType.P0_IMPORT_CONTROL_QUALITY: ReportTypeDefinition(
        LocalReportType.P0_IMPORT_CONTROL_QUALITY, "1.0", "P0ImportQualityAdapter", True,
        (),
        ("participant_inn", "import_id", "row_index", "decision", "reason", "source_fingerprint", "observed_at"),
        ReportSensitivity.BUSINESS_SENSITIVE, (ReportOutputFormat.CSV, ReportOutputFormat.XLSX, ReportOutputFormat.JSON),
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        enabled=False,
        disabled_reason="SOURCE_PARTICIPANT_SCOPE_NOT_PROVABLE",
    ),
}


def apply_fixed_report_labels(report_type: LocalReportType, row: Mapping[str, Any]) -> dict[str, Any]:
    definition = LOCAL_REPORT_CATALOG[report_type]
    out = dict(row)
    for key, value in definition.fixed_labels.items():
        out[key] = value
    return out


def build_reconciliation_row(
    *,
    participant_inn: str,
    domain: str,
    source: str,
    source_fingerprint: str | None,
    local_operation_id: str | None,
    remote_id: str | None,
    remote_raw_state: str | None,
    local_project_state: str | None,
    final_result: LocalReconciliationResult,
    evidence_missing: bool,
    conflict_state: str | None,
    observed_at: str | datetime | None,
) -> dict[str, Any]:
    return {
        "participant_inn": participant_inn,
        "domain": domain,
        "source": source,
        "source_fingerprint": source_fingerprint,
        "local_operation_id": local_operation_id,
        "remote_id": remote_id,
        "remote_raw_state": remote_raw_state,
        "local_project_state": local_project_state,
        "final_reconciliation_result": final_result.value,
        "evidence_missing": bool(evidence_missing),
        "conflict_state": conflict_state,
        "observed_at": format_timestamp_preserving_unknown(observed_at),
    }


def format_timestamp_preserving_unknown(value: str | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            return value.isoformat() + "|TIMEZONE_UNKNOWN"
        return value.isoformat()
    return str(value)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_request_fingerprint(
    *,
    report_type: str,
    report_schema_version: str,
    participant_scope: Mapping[str, Any],
    normalized_filters: Mapping[str, Any],
    output_format: str,
    sensitivity_mode: str,
    snapshot_policy_version: str,
) -> str:
    payload = {
        "report_type": report_type,
        "report_schema_version": report_schema_version,
        "participant_scope": participant_scope,
        "normalized_filters": normalized_filters,
        "output_format": output_format,
        "sensitivity_mode": sensitivity_mode,
        "snapshot_policy_version": snapshot_policy_version,
    }
    return _sha256_bytes(_canonical(payload).encode("utf-8"))


@dataclass(frozen=True, slots=True)
class ReportSnapshotDescriptor:
    strategy: SnapshotStrategy
    snapshot_at: datetime
    source_domains: tuple[str, ...]
    source_tables: tuple[str, ...]
    high_water_metadata: Mapping[str, Any]
    source_filter_sanitized: Mapping[str, Any]
    schema_version: str
    internal_snapshot_artifact_id: str | None = None
    row_count: int | None = None

    def canonical_payload(self) -> dict[str, Any]:
        at = self.snapshot_at
        if at.tzinfo is None or at.utcoffset() is None:
            raise ReportContractError("snapshot_at must be timezone-aware")
        return {
            "strategy": self.strategy.value,
            "snapshot_at": at.isoformat(),
            "source_domains": list(self.source_domains),
            "source_tables": list(self.source_tables),
            "high_water_metadata": self.high_water_metadata,
            "source_filter_sanitized": self.source_filter_sanitized,
            "schema_version": self.schema_version,
            "internal_snapshot_artifact_id": self.internal_snapshot_artifact_id,
            "row_count": self.row_count,
        }

    @property
    def descriptor_sha256(self) -> str:
        return _sha256_bytes(_canonical(self.canonical_payload()).encode("utf-8"))


def build_append_only_snapshot(
    *,
    source_domains: Sequence[str],
    source_tables: Sequence[str],
    high_water_metadata: Mapping[str, Any],
    source_filter_sanitized: Mapping[str, Any],
    schema_version: str,
    snapshot_at: datetime | None = None,
) -> ReportSnapshotDescriptor:
    return ReportSnapshotDescriptor(
        SnapshotStrategy.APPEND_ONLY_HIGH_WATER,
        snapshot_at or datetime.now(timezone.utc),
        tuple(source_domains),
        tuple(source_tables),
        dict(high_water_metadata),
        dict(source_filter_sanitized),
        schema_version,
    )


class PostgresConsistentSnapshot:
    """Read-only repeatable-read snapshot wrapper. No row locks and no business writes."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def __enter__(self) -> Any:
        self.connection.exec_driver_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        return self.connection

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


@dataclass(frozen=True, slots=True)
class MaterializedSnapshot:
    path: Path
    row_count: int
    sha256: str
    byte_size: int


def materialize_jsonl_snapshot(
    rows: Iterable[Mapping[str, Any]],
    *,
    temp_root: Path,
    max_rows: int = DEFAULT_MAX_LOCAL_ROWS,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> MaterializedSnapshot:
    temp_root.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(prefix="m11-snapshot-", suffix=".jsonl", dir=temp_root)
    os.close(fd)
    path = Path(raw_path)
    try:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        digest = hashlib.sha256()
        row_count = 0
        byte_size = 0
        with path.open("wb") as out:
            for row in rows:
                row_count += 1
                if row_count > max_rows:
                    raise ArtifactLimitExceeded("snapshot row ceiling exceeded")
                chunk = (_canonical(dict(row)) + "\n").encode("utf-8")
                byte_size += len(chunk)
                if byte_size > max_bytes:
                    raise ArtifactLimitExceeded("snapshot byte ceiling exceeded")
                out.write(chunk)
                digest.update(chunk)
            out.flush()
            os.fsync(out.fileno())
        return MaterializedSnapshot(path, row_count, digest.hexdigest(), byte_size)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def protect_spreadsheet_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        text = _canonical(value)
    elif isinstance(value, datetime):
        text = format_timestamp_preserving_unknown(value) or ""
    else:
        text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


@dataclass(frozen=True, slots=True)
class RenderedArtifact:
    path: Path
    format: ReportOutputFormat
    row_count: int
    byte_size: int
    sha256: str
    mime: str


class StreamingReportRenderer:
    def __init__(
        self,
        *,
        temp_root: Path,
        max_rows: int = DEFAULT_MAX_LOCAL_ROWS,
        max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> None:
        self.temp_root = temp_root
        self.max_rows = max_rows
        self.max_bytes = max_bytes
        self.temp_root.mkdir(parents=True, exist_ok=True)

    def _new_path(self, suffix: str) -> Path:
        fd, raw = tempfile.mkstemp(prefix="m11-report-", suffix=suffix, dir=self.temp_root)
        os.close(fd)
        path = Path(raw)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def render(
        self,
        rows: Iterable[Mapping[str, Any]],
        *,
        columns: Sequence[str],
        output_format: ReportOutputFormat,
    ) -> RenderedArtifact:
        if output_format is ReportOutputFormat.CSV:
            return self._csv(rows, columns)
        if output_format is ReportOutputFormat.XLSX:
            return self._xlsx(rows, columns)
        if output_format is ReportOutputFormat.JSON:
            return self._json(rows, columns)
        raise ReportFormatError("ZIP requires render_zip_manifest over an existing artifact")

    def _enforce_file(self, path: Path) -> tuple[int, str]:
        size = path.stat().st_size
        if size > self.max_bytes:
            raise ArtifactLimitExceeded("artifact byte ceiling exceeded")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(DEFAULT_CHUNK_BYTES), b""):
                digest.update(chunk)
        return size, digest.hexdigest()

    def _csv(self, rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> RenderedArtifact:
        path = self._new_path(".csv")
        count = 0
        try:
            with path.open("w", encoding="utf-8", newline="") as out:
                writer = csv.writer(out, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
                writer.writerow(list(columns))
                for row in rows:
                    count += 1
                    if count > self.max_rows:
                        raise ArtifactLimitExceeded("row ceiling exceeded")
                    writer.writerow([protect_spreadsheet_text(row.get(column)) for column in columns])
            size, digest = self._enforce_file(path)
            return RenderedArtifact(path, ReportOutputFormat.CSV, count, size, digest, "text/csv; charset=utf-8")
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def _xlsx(self, rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> RenderedArtifact:
        path = self._new_path(".xlsx")
        count = 0
        try:
            wb = Workbook(write_only=True)
            ws = wb.create_sheet("report")
            ws.append([str(c) for c in columns])
            for row in rows:
                count += 1
                if count > self.max_rows:
                    raise ArtifactLimitExceeded("row ceiling exceeded")
                output_row: list[WriteOnlyCell] = []
                for column in columns:
                    text = protect_spreadsheet_text(row.get(column))
                    if len(text) > 32767:
                        raise ReportFormatError("XLSX cell exceeds safe format limit; use CSV/JSON companion")
                    cell = WriteOnlyCell(ws, value=text)
                    cell.data_type = "s"
                    output_row.append(cell)
                ws.append(output_row)
            wb.save(path)
            size, digest = self._enforce_file(path)
            return RenderedArtifact(path, ReportOutputFormat.XLSX, count, size, digest, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def _json(self, rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> RenderedArtifact:
        path = self._new_path(".json")
        count = 0
        try:
            with path.open("w", encoding="utf-8", newline="") as out:
                out.write("[")
                first = True
                for row in rows:
                    count += 1
                    if count > self.max_rows:
                        raise ArtifactLimitExceeded("row ceiling exceeded")
                    obj = {column: row.get(column) for column in columns}
                    if not first:
                        out.write(",")
                    out.write(_canonical(obj))
                    first = False
                out.write("]")
            size, digest = self._enforce_file(path)
            return RenderedArtifact(path, ReportOutputFormat.JSON, count, size, digest, "application/json; charset=utf-8")
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def render_zip_manifest(
        self,
        *,
        payload_artifact: RenderedArtifact,
        manifest: Mapping[str, Any],
    ) -> RenderedArtifact:
        path = self._new_path(".zip")
        try:
            safe_payload_name = "report." + payload_artifact.format.value.lower()
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                archive.write(payload_artifact.path, arcname=safe_payload_name)
                archive.writestr("manifest.json", _canonical(dict(manifest)).encode("utf-8"))
            size, digest = self._enforce_file(path)
            return RenderedArtifact(path, ReportOutputFormat.ZIP, payload_artifact.row_count, size, digest, "application/zip")
        except BaseException:
            path.unlink(missing_ok=True)
            raise


class ArtifactKeyProvider(Protocol):
    def get_key(self, key_version: str) -> bytes: ...


ARTIFACT_ENCRYPTION_FORMAT = "M11_CHUNKED_AES256_GCM_V1"
_ARTIFACT_MAGIC = b"M11AEAD1\n"


@dataclass(frozen=True, slots=True)
class ArtifactWriteResult:
    storage_backend: str
    storage_key: str
    plaintext_byte_size: int
    plaintext_sha256: str
    stored_byte_size: int
    encryption_version: str | None
    encryption_metadata: Mapping[str, Any]


class ChunkedAeadArtifactCipher:
    def __init__(self, key_provider: ArtifactKeyProvider, *, key_version: str, chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> None:
        if chunk_bytes <= 0:
            raise ValueError("chunk_bytes must be positive")
        self.key_provider = key_provider
        self.key_version = key_version
        self.chunk_bytes = chunk_bytes

    def encrypt_stream(self, source: BinaryIO, target: BinaryIO, *, aad_context: Mapping[str, Any]) -> tuple[int, str, Mapping[str, Any]]:
        key = self.key_provider.get_key(self.key_version)
        if len(key) != 32:
            raise ReportSecurityError("AES-256 artifact key required")
        base_nonce = os.urandom(8)
        header = {
            "format": ARTIFACT_ENCRYPTION_FORMAT,
            "key_version": self.key_version,
            "chunk_bytes": self.chunk_bytes,
            "base_nonce_hex": base_nonce.hex(),
            "aad_context_sha256": _sha256_bytes(_canonical(dict(aad_context)).encode("utf-8")),
        }
        header_raw = _canonical(header).encode("utf-8") + b"\n"
        target.write(_ARTIFACT_MAGIC)
        target.write(struct.pack(">I", len(header_raw)))
        target.write(header_raw)
        digest = hashlib.sha256()
        total = 0
        index = 0
        aes = AESGCM(key)
        while True:
            plain = source.read(self.chunk_bytes)
            if not plain:
                break
            digest.update(plain)
            total += len(plain)
            nonce = base_nonce + index.to_bytes(4, "big")
            aad = _canonical({"header": header, "chunk_index": index, "context": aad_context}).encode("utf-8")
            sealed = aes.encrypt(nonce, plain, aad)
            target.write(struct.pack(">I", len(sealed)))
            target.write(sealed)
            index += 1
        plaintext_sha256 = digest.hexdigest()
        footer_plain = _canonical({
            "byte_size": total,
            "plaintext_sha256": plaintext_sha256,
            "chunk_count": index,
        }).encode("utf-8")
        footer_nonce = base_nonce + index.to_bytes(4, "big")
        footer_aad = _canonical({"header": header, "footer": True, "context": aad_context}).encode("utf-8")
        footer_sealed = aes.encrypt(footer_nonce, footer_plain, footer_aad)
        target.write(struct.pack(">I", 0))
        target.write(struct.pack(">I", len(footer_sealed)))
        target.write(footer_sealed)
        return total, plaintext_sha256, {**header, "chunk_count": index}

    def decrypt_stream(self, source: BinaryIO, target: BinaryIO, *, aad_context: Mapping[str, Any]) -> tuple[int, str]:
        if source.read(len(_ARTIFACT_MAGIC)) != _ARTIFACT_MAGIC:
            raise ReportSecurityError("artifact encryption magic mismatch")
        raw_header_len = source.read(4)
        if len(raw_header_len) != 4:
            raise ReportSecurityError("artifact header missing")
        header_len = struct.unpack(">I", raw_header_len)[0]
        header = json.loads(source.read(header_len).decode("utf-8"))
        if header.get("format") != ARTIFACT_ENCRYPTION_FORMAT:
            raise ReportSecurityError("artifact encryption format mismatch")
        if header.get("key_version") != self.key_version:
            raise ReportSecurityError("artifact key version mismatch")
        expected_context_hash = _sha256_bytes(_canonical(dict(aad_context)).encode("utf-8"))
        if header.get("aad_context_sha256") != expected_context_hash:
            raise ReportSecurityError("artifact AAD context mismatch")
        base_nonce = bytes.fromhex(header["base_nonce_hex"])
        key = self.key_provider.get_key(self.key_version)
        if len(key) != 32:
            raise ReportSecurityError("AES-256 artifact key required")
        aes = AESGCM(key)
        total = 0
        digest = hashlib.sha256()
        index = 0
        while True:
            raw_len = source.read(4)
            if len(raw_len) != 4:
                raise ReportSecurityError("artifact frame truncated")
            sealed_len = struct.unpack(">I", raw_len)[0]
            if sealed_len == 0:
                raw_footer_len = source.read(4)
                if len(raw_footer_len) != 4:
                    raise ReportSecurityError("artifact footer missing")
                footer_len = struct.unpack(">I", raw_footer_len)[0]
                footer_sealed = source.read(footer_len)
                if len(footer_sealed) != footer_len:
                    raise ReportSecurityError("artifact footer truncated")
                footer_nonce = base_nonce + index.to_bytes(4, "big")
                footer_aad = _canonical({"header": header, "footer": True, "context": aad_context}).encode("utf-8")
                try:
                    footer_plain = aes.decrypt(footer_nonce, footer_sealed, footer_aad)
                except InvalidTag as exc:
                    raise ReportSecurityError("artifact footer authentication failed") from exc
                try:
                    footer = json.loads(footer_plain.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ReportSecurityError("artifact footer invalid") from exc
                if (
                    footer.get("byte_size") != total
                    or footer.get("plaintext_sha256") != digest.hexdigest()
                    or footer.get("chunk_count") != index
                ):
                    raise ReportSecurityError("artifact authenticated summary mismatch")
                break
            sealed = source.read(sealed_len)
            if len(sealed) != sealed_len:
                raise ReportSecurityError("artifact frame truncated")
            nonce = base_nonce + index.to_bytes(4, "big")
            aad = _canonical({"header": header, "chunk_index": index, "context": aad_context}).encode("utf-8")
            try:
                plain = aes.decrypt(nonce, sealed, aad)
            except InvalidTag as exc:
                raise ReportSecurityError("artifact authentication failed") from exc
            target.write(plain)
            digest.update(plain)
            total += len(plain)
            index += 1
        return total, digest.hexdigest()


class ReportArtifactStore(Protocol):
    def put_file(
        self,
        source_path: Path,
        *,
        sensitive: bool,
        aad_context: Mapping[str, Any],
        safe_suffix: str,
    ) -> ArtifactWriteResult: ...

    def inspect(self, storage_key: str) -> tuple[int, str]: ...


class FilesystemReportArtifactStore:
    """Server-controlled persistent filesystem adapter; storage keys are server generated."""

    def __init__(
        self,
        root: Path,
        *,
        key_provider: ArtifactKeyProvider | None = None,
        key_version: str = "m11-test-only",
        chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    ) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.key_provider = key_provider
        self.key_version = key_version
        self.chunk_bytes = chunk_bytes

    def _new_storage_key(self, suffix: str) -> str:
        suffix = re.sub(r"[^A-Za-z0-9._-]", "", suffix)[:20]
        return f"{uuid.uuid4().hex}{suffix}"

    def _resolve_storage_key(self, storage_key: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", storage_key or ""):
            raise ReportSecurityError("invalid server storage key")
        path = (self.root / storage_key).resolve()
        if path.parent != self.root:
            raise ReportSecurityError("path traversal denied")
        return path

    def put_file(
        self,
        source_path: Path,
        *,
        sensitive: bool,
        aad_context: Mapping[str, Any],
        safe_suffix: str,
    ) -> ArtifactWriteResult:
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        storage_key = self._new_storage_key(safe_suffix)
        target_path = self._resolve_storage_key(storage_key)
        tmp_path = self._resolve_storage_key(storage_key + ".tmp")
        try:
            if sensitive:
                if self.key_provider is None:
                    raise ReportSecurityError("sensitive artifact requires injected key provider")
                cipher = ChunkedAeadArtifactCipher(
                    self.key_provider, key_version=self.key_version, chunk_bytes=self.chunk_bytes
                )
                with source_path.open("rb") as source, tmp_path.open("xb") as target:
                    plain_size, plain_sha, metadata = cipher.encrypt_stream(source, target, aad_context=aad_context)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(tmp_path, target_path)
                return ArtifactWriteResult(
                    "FILESYSTEM", storage_key, plain_size, plain_sha, target_path.stat().st_size,
                    ARTIFACT_ENCRYPTION_FORMAT, metadata,
                )
            digest = hashlib.sha256()
            size = 0
            with source_path.open("rb") as source, tmp_path.open("xb") as target:
                for chunk in iter(lambda: source.read(self.chunk_bytes), b""):
                    size += len(chunk)
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            os.replace(tmp_path, target_path)
            return ArtifactWriteResult("FILESYSTEM", storage_key, size, digest.hexdigest(), target_path.stat().st_size, None, {})
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def inspect(self, storage_key: str) -> tuple[int, str]:
        path = self._resolve_storage_key(storage_key)
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(self.chunk_bytes), b""):
                digest.update(chunk)
        return path.stat().st_size, digest.hexdigest()

    def decrypt_sensitive_to(self, storage_key: str, target: BinaryIO, *, aad_context: Mapping[str, Any]) -> tuple[int, str]:
        if self.key_provider is None:
            raise ReportSecurityError("artifact key provider missing")
        path = self._resolve_storage_key(storage_key)
        cipher = ChunkedAeadArtifactCipher(self.key_provider, key_version=self.key_version, chunk_bytes=self.chunk_bytes)
        with path.open("rb") as source:
            return cipher.decrypt_stream(source, target, aad_context=aad_context)


class DispenserCapabilityName(StrEnum):
    CREATE_EXPORT = "CREATE_EXPORT"
    GET_TASK = "GET_TASK"
    LIST_TASKS = "LIST_TASKS"
    LIST_RESULTS = "LIST_RESULTS"
    DOWNLOAD_RESULT = "DOWNLOAD_RESULT"
    QUOTA_BY_TASK_TYPE = "QUOTA_BY_TASK_TYPE"
    QUOTA_BY_REPORT = "QUOTA_BY_REPORT"
    REMOTE_RESULT_DELETE = "REMOTE_RESULT_DELETE"


@dataclass(frozen=True, slots=True)
class DispenserCapability:
    name: DispenserCapabilityName
    method: str
    path_template: str
    requests_per_minute: int
    rate_family: str
    enabled: bool = True
    disabled_reason: str | None = None


DISPENSER_CAPABILITIES: Mapping[DispenserCapabilityName, DispenserCapability] = {
    DispenserCapabilityName.CREATE_EXPORT: DispenserCapability(
        DispenserCapabilityName.CREATE_EXPORT, "POST", "/api/v3/true-api/dispenser/tasks",
        REPORT_CREATE_RATE_PER_MINUTE, "CREATE",
    ),
    DispenserCapabilityName.GET_TASK: DispenserCapability(
        DispenserCapabilityName.GET_TASK, "GET", "/api/v3/true-api/dispenser/tasks/{taskId}",
        REPORT_TASK_RATE_PER_MINUTE, "TASK",
    ),
    DispenserCapabilityName.LIST_TASKS: DispenserCapability(
        DispenserCapabilityName.LIST_TASKS, "GET", "/api/v3/true-api/dispenser/tasks",
        REPORT_TASK_RATE_PER_MINUTE, "TASK",
    ),
    DispenserCapabilityName.LIST_RESULTS: DispenserCapability(
        DispenserCapabilityName.LIST_RESULTS, "GET", "/api/v3/true-api/dispenser/results",
        REPORT_RESULTS_RATE_PER_MINUTE, "RESULTS",
    ),
    DispenserCapabilityName.DOWNLOAD_RESULT: DispenserCapability(
        DispenserCapabilityName.DOWNLOAD_RESULT, "GET", "/api/v3/true-api/dispenser/results/{resultId}/file",
        REPORT_RESULTS_RATE_PER_MINUTE, "RESULTS",
    ),
    DispenserCapabilityName.QUOTA_BY_TASK_TYPE: DispenserCapability(
        DispenserCapabilityName.QUOTA_BY_TASK_TYPE, "GET", "/api/v3/true-api/dispenser/tasktypes/available_count",
        REPORT_QUOTA_RATE_PER_MINUTE, "QUOTA",
    ),
    DispenserCapabilityName.QUOTA_BY_REPORT: DispenserCapability(
        DispenserCapabilityName.QUOTA_BY_REPORT, "GET", "/api/v3/true-api/dispenser/tasktypes/reports/{report_id}/available_count",
        REPORT_QUOTA_RATE_PER_MINUTE, "QUOTA",
    ),
    DispenserCapabilityName.REMOTE_RESULT_DELETE: DispenserCapability(
        DispenserCapabilityName.REMOTE_RESULT_DELETE, "DELETE", "/api/v3/true-api/dispenser/results/{resultId}",
        REPORT_RESULTS_RATE_PER_MINUTE, "RESULTS", False, "M11_REMOTE_DELETE_FORBIDDEN",
    ),
}


@dataclass(frozen=True, slots=True)
class DispenserRateDecision:
    allowed: bool
    retry_after_seconds: float


class DispenserRateLimiter:
    """Sliding-window limiter keyed by participant and documented endpoint family."""

    def __init__(self) -> None:
        self._history: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def consume(
        self,
        capability: DispenserCapability,
        *,
        scope_key: str,
        now_monotonic: float,
    ) -> DispenserRateDecision:
        if not capability.enabled:
            raise ReportSecurityError(capability.disabled_reason or "capability disabled")
        if not scope_key:
            raise ReportContractError("rate scope key required")
        key = (scope_key, capability.rate_family)
        history = self._history[key]
        now = float(now_monotonic)
        threshold = now - 60.0
        while history and history[0] <= threshold:
            history.popleft()
        if len(history) >= capability.requests_per_minute:
            retry = 60.0 - (now - history[0])
            return DispenserRateDecision(False, max(0.0, retry))
        history.append(now)
        return DispenserRateDecision(True, 0.0)


LP_PRODUCT_GROUP_CODE = "1"
FILTERED_CIS_LP_PACKAGE_TYPES = frozenset({"UNIT", "SET", "BUNDLE", "BOX", "ATK"})
FILTERED_CIS_LP_STATUSES = frozenset({
    "EMITTED", "APPLIED", "INTRODUCED", "WRITTEN_OFF", "RETIRED", "DISAGGREGATION",
})
SOURCE_AMBIGUITY_PACKAGE_LEVEL_VALUES = "SOURCE_AMBIGUITY_PACKAGE_LEVEL_VALUES"


@dataclass(frozen=True, slots=True)
class FilteredCisFilters:
    participant_inn: str
    package_type: tuple[str, ...]
    status: str | None = None
    include_gtin: tuple[str, ...] = ()

    def validate(self) -> None:
        if not re.fullmatch(r"\d{10}|\d{12}", self.participant_inn or ""):
            raise ReportContractError("participant_inn must be 10 or 12 digits")
        if not self.package_type:
            raise ReportContractError("packageType is required")
        if any(type(value) is not str or value not in FILTERED_CIS_LP_PACKAGE_TYPES for value in self.package_type):
            raise ReportContractError("packageType is not request-safe for LP")
        if self.status not in FILTERED_CIS_LP_STATUSES:
            raise ReportContractError("status is not allowed for LP FILTERED_CIS_REPORT")
        if len(self.include_gtin) > 1000:
            raise ReportContractError("includeGtin max 1000")
        for gtin in self.include_gtin:
            if not isinstance(gtin, str) or not gtin or not gtin.isdigit():
                raise ReportContractError("includeGtin values must be digit strings")

    def to_params(self) -> dict[str, Any]:
        self.validate()
        result: dict[str, Any] = {
            "participantInn": self.participant_inn,
            "packageType": list(self.package_type),
            "status": self.status,
        }
        if self.include_gtin:
            result["includeGtin"] = list(self.include_gtin)
        return result


@dataclass(frozen=True, slots=True)
class RemoteRecipe:
    key: str
    enabled: bool
    disabled_reason: str | None
    task_type_or_name: str | None
    report_id: str | None
    output_format: str | None
    periodicity: str | None
    official_contract_revision: str


REMOTE_RECIPE_REGISTRY: Mapping[str, RemoteRecipe] = {
    "FILTERED_CIS_REPORT": RemoteRecipe(
        "FILTERED_CIS_REPORT", True, None, "FILTERED_CIS_REPORT", None,
        "CSV", "SINGLE", M11_CONTRACT_REVISION,
    ),
    "DOCUMENTS_ERRORS": RemoteRecipe(
        "DOCUMENTS_ERRORS", False, "RECIPE_SCHEMA_NOT_REGISTERED", "DOCUMENTS_ERRORS", None,
        "CSV", "SINGLE", M11_CONTRACT_REVISION,
    ),
    "CIS_ACS": RemoteRecipe(
        "CIS_ACS", False, "RECIPE_SCHEMA_NOT_REGISTERED", "CIS_ACS", None,
        "CSV", "SINGLE", M11_CONTRACT_REVISION,
    ),
    "ACS_DOCUMENTS": RemoteRecipe(
        "ACS_DOCUMENTS", False, "RECIPE_SCHEMA_NOT_REGISTERED", "ACS_DOCUMENTS", None,
        "CSV", None, M11_CONTRACT_REVISION,
    ),
    "LP_STOCK_REPORT": RemoteRecipe(
        "LP_STOCK_REPORT", False, "RECIPE_SCHEMA_NOT_REGISTERED", None, None,
        None, None, M11_CONTRACT_REVISION,
    ),
    "LP_TURNOVER_SALES": RemoteRecipe(
        "LP_TURNOVER_SALES", False, "RECIPE_SCHEMA_NOT_REGISTERED", None, None,
        None, None, M11_CONTRACT_REVISION,
    ),
    "LP_WITHDRAWN_GOODS": RemoteRecipe(
        "LP_WITHDRAWN_GOODS", False, "RECIPE_SCHEMA_NOT_REGISTERED", None, None,
        None, None, M11_CONTRACT_REVISION,
    ),
    "LP_DIRECT_DOCUMENT_ERROR": RemoteRecipe(
        "LP_DIRECT_DOCUMENT_ERROR", False, "RECIPE_SCHEMA_NOT_REGISTERED", None, "document-error-gismt",
        "CSV", "SINGLE", M11_CONTRACT_REVISION,
    ),
    "LP_OUTGOING_DOCUMENT": RemoteRecipe(
        "LP_OUTGOING_DOCUMENT", False, "RECIPE_SCHEMA_NOT_REGISTERED", None, "outgoing-documents-gismt",
        "CSV", "SINGLE", M11_CONTRACT_REVISION,
    ),
}


def enabled_remote_recipes() -> tuple[str, ...]:
    return tuple(k for k, v in REMOTE_RECIPE_REGISTRY.items() if v.enabled)


def disabled_remote_recipes() -> tuple[str, ...]:
    return tuple(k for k, v in REMOTE_RECIPE_REGISTRY.items() if not v.enabled)


def _opaque_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", value):
        raise ReportContractError(f"invalid {label}")
    return value


def _product_group_code(value: Any) -> str:
    if type(value) is int and value == 1:
        return LP_PRODUCT_GROUP_CODE
    if value == LP_PRODUCT_GROUP_CODE:
        return LP_PRODUCT_GROUP_CODE
    raise ReportContractError("FILTERED_CIS_REPORT is fixed to LP productGroupCode=1")


def build_filtered_cis_create_body(
    *,
    product_group_code: str | int,
    filters: FilteredCisFilters,
) -> dict[str, Any]:
    recipe = REMOTE_RECIPE_REGISTRY["FILTERED_CIS_REPORT"]
    if not recipe.enabled:
        raise ReportSecurityError(recipe.disabled_reason or "recipe disabled")
    params = filters.to_params()
    return {
        "format": "CSV",
        "name": "FILTERED_CIS_REPORT",
        "periodicity": "SINGLE",
        "productGroupCode": LP_PRODUCT_GROUP_CODE,
        "params": _canonical(params),
    }


def sanitize_report_evidence(value: Any, *, sensitive_context: bool = False) -> Any:
    direct = {"cis", "cises", "kiz", "kizes", "sgtin", "sgtins", "mark", "marks", "marking", "markingcode", "apikey", "authorization", "bearer", "token", "machinetoken", "pin", "privatekey", "signature"}
    associated = {"value", "values", "data", "codes", "code"}
    discriminators = {"key", "type", "kind", "name", "field"}
    if isinstance(value, Mapping):
        discriminator_sensitive = sensitive_context
        for key, item in value.items():
            if re.sub(r"[^a-z0-9]", "", str(key).lower()) in discriminators and isinstance(item, str):
                if re.sub(r"[^a-z0-9]", "", item.lower()) in direct:
                    discriminator_sensitive = True
                    break
        out: dict[str, Any] = {}
        for key, item in value.items():
            skey = str(key)
            compact = re.sub(r"[^a-z0-9]", "", skey.lower())
            if compact in direct or compact.startswith(("cis", "kiz", "sgtin", "marking", "apikey", "token")):
                out[skey] = "REDACTED"
            elif discriminator_sensitive and compact in associated:
                out[skey] = "REDACTED"
            else:
                out[skey] = sanitize_report_evidence(item, sensitive_context=discriminator_sensitive)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize_report_evidence(x, sensitive_context=sensitive_context) for x in value]
    return value


@dataclass(frozen=True, slots=True)
class DispenserRequestSpec:
    capability: DispenserCapabilityName
    method: str
    target: str
    json_body: Mapping[str, Any] | None
    audit_endpoint: str
    rate_family: str


def validate_report_agent_payload(job_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if job_type not in M11_AGENT_JOB_TYPES:
        raise ReportContractError("unknown report agent job type")
    if not isinstance(payload, Mapping):
        raise ReportContractError("report payload must be object")
    raw = dict(payload)
    allowed_common = {"local_report_job_id"}
    if not isinstance(raw.get("local_report_job_id"), str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", raw["local_report_job_id"]):
        raise ReportContractError("local_report_job_id invalid")

    if job_type == "REPORT_CREATE":
        allowed = allowed_common | {"recipe", "product_group_code", "filters"}
        if set(raw) - allowed:
            raise ReportContractError("REPORT_CREATE contains unsupported fields")
        if raw.get("recipe") != "FILTERED_CIS_REPORT":
            raise ReportContractError("unsupported or disabled recipe")
        filters_raw = raw.get("filters")
        if not isinstance(filters_raw, Mapping):
            raise ReportContractError("FILTERED_CIS_REPORT filters required")
        if set(filters_raw) - {"participant_inn", "package_type", "status", "include_gtin"}:
            raise ReportContractError("raw/arbitrary recipe params denied")
        filters = FilteredCisFilters(
            participant_inn=str(filters_raw.get("participant_inn") or ""),
            package_type=tuple(filters_raw.get("package_type") or ()),
            status=filters_raw.get("status") if isinstance(filters_raw.get("status"), str) else None,
            include_gtin=tuple(filters_raw.get("include_gtin") or ()),
        )
        filters.validate()
        return {
            "local_report_job_id": raw["local_report_job_id"],
            "recipe": "FILTERED_CIS_REPORT",
            "product_group_code": _product_group_code(raw.get("product_group_code")),
            "filters": {
                "participant_inn": filters.participant_inn,
                "package_type": list(filters.package_type),
                "status": filters.status,
                "include_gtin": list(filters.include_gtin),
            },
        }

    if job_type == "REPORT_TASK_GET":
        allowed = allowed_common | {"task_id", "product_group_code"}
        if set(raw) - allowed:
            raise ReportContractError("REPORT_TASK_GET contains unsupported fields")
        return {
            "local_report_job_id": raw["local_report_job_id"],
            "task_id": _opaque_id(raw.get("task_id"), "task_id"),
            "product_group_code": _product_group_code(raw["product_group_code"]) if raw.get("product_group_code") is not None else None,
        }

    if job_type in {"REPORT_TASK_LIST", "REPORT_RESULTS"}:
        allowed = allowed_common | {"page", "size", "product_group_code", "task_ids"}
        if set(raw) - allowed:
            raise ReportContractError(f"{job_type} contains unsupported fields")
        page = raw.get("page")
        size = raw.get("size")
        if type(page) is not int or page < 0 or type(size) is not int or size <= 0:
            raise ReportContractError("page/size invalid")
        normalized: dict[str, Any] = {
            "local_report_job_id": raw["local_report_job_id"],
            "page": page,
            "size": size,
            "product_group_code": _product_group_code(raw["product_group_code"]) if raw.get("product_group_code") is not None else None,
        }
        if job_type == "REPORT_RESULTS":
            task_ids = tuple(raw.get("task_ids") or ())
            for task_id in task_ids:
                _opaque_id(task_id, "task_id")
            normalized["task_ids"] = list(task_ids)
        elif raw.get("task_ids"):
            raise ReportContractError("task_ids unsupported for task list")
        return normalized

    if job_type == "REPORT_DOWNLOAD":
        allowed = allowed_common | {
            "result_id", "result_part_id", "product_group_code", "artifact_upload_id",
            "expected_archive_size", "download_format",
        }
        if set(raw) - allowed:
            raise ReportContractError("REPORT_DOWNLOAD contains unsupported fields")
        upload_id = raw.get("artifact_upload_id")
        if not isinstance(upload_id, str) or not re.fullmatch(r"upl_[A-Fa-f0-9]{32}", upload_id):
            raise ReportContractError("artifact_upload_id invalid")
        expected_size = raw.get("expected_archive_size")
        if expected_size is not None and (type(expected_size) is not int or expected_size < 0):
            raise ReportContractError("expected_archive_size invalid")
        download_format = raw.get("download_format")
        if download_format not in (None, "XLSX"):
            raise ReportContractError("download_format unsupported")
        return {
            "local_report_job_id": raw["local_report_job_id"],
            "result_id": _opaque_id(raw.get("result_id"), "result_id"),
            "result_part_id": _opaque_id(raw["result_part_id"], "result_part_id") if raw.get("result_part_id") is not None else None,
            "product_group_code": _product_group_code(raw["product_group_code"]) if raw.get("product_group_code") is not None else None,
            "artifact_upload_id": upload_id,
            "expected_archive_size": expected_size,
            "download_format": download_format,
        }

    if job_type == "REPORT_QUOTA_TYPE":
        allowed = allowed_common | {"task_type_short_name", "product_group_code"}
        if set(raw) - allowed:
            raise ReportContractError("REPORT_QUOTA_TYPE contains unsupported fields")
        task_type = raw.get("task_type_short_name")
        if task_type != "FILTERED_CIS_REPORT":
            raise ReportContractError("unsupported task type quota")
        return {
            "local_report_job_id": raw["local_report_job_id"],
            "task_type_short_name": task_type,
            "product_group_code": _product_group_code(raw["product_group_code"]) if raw.get("product_group_code") is not None else None,
        }

    if job_type == "REPORT_QUOTA_ID":
        allowed = allowed_common | {"report_id", "product_group_code"}
        if set(raw) - allowed:
            raise ReportContractError("REPORT_QUOTA_ID contains unsupported fields")
        report_id = _opaque_id(raw.get("report_id"), "report_id")
        return {
            "local_report_job_id": raw["local_report_job_id"],
            "report_id": report_id,
            "product_group_code": _product_group_code(raw["product_group_code"]) if raw.get("product_group_code") is not None else None,
        }

    raise ReportContractError("unsupported report agent job type")


def build_dispenser_spec(job_type: str, payload: Mapping[str, Any]) -> DispenserRequestSpec:
    p = validate_report_agent_payload(job_type, payload)
    if job_type == "REPORT_CREATE":
        filters = p["filters"]
        body = build_filtered_cis_create_body(
            product_group_code=p["product_group_code"],
            filters=FilteredCisFilters(
                participant_inn=filters["participant_inn"],
                package_type=tuple(filters["package_type"]),
                status=filters["status"],
                include_gtin=tuple(filters["include_gtin"]),
            ),
        )
        cap = DISPENSER_CAPABILITIES[DispenserCapabilityName.CREATE_EXPORT]
        return DispenserRequestSpec(cap.name, cap.method, cap.path_template, body, "/dispenser/tasks", cap.rate_family)
    if job_type == "REPORT_TASK_GET":
        cap = DISPENSER_CAPABILITIES[DispenserCapabilityName.GET_TASK]
        target = cap.path_template.replace("{taskId}", p["task_id"])
        if p["product_group_code"] is not None:
            target += "?" + urlencode({"pg": p["product_group_code"]})
        return DispenserRequestSpec(cap.name, cap.method, target, None, "/dispenser/tasks/{taskId}", cap.rate_family)
    if job_type == "REPORT_TASK_LIST":
        cap = DISPENSER_CAPABILITIES[DispenserCapabilityName.LIST_TASKS]
        params: list[tuple[str, str]] = [("page", str(p["page"])), ("size", str(p["size"]))]
        if p["product_group_code"] is not None:
            params.append(("pg", p["product_group_code"]))
        return DispenserRequestSpec(cap.name, cap.method, cap.path_template + "?" + urlencode(params), None, "/dispenser/tasks", cap.rate_family)
    if job_type == "REPORT_RESULTS":
        cap = DISPENSER_CAPABILITIES[DispenserCapabilityName.LIST_RESULTS]
        params: list[tuple[str, str]] = [("page", str(p["page"])), ("size", str(p["size"]))]
        if p["product_group_code"] is not None:
            params.append(("pg", p["product_group_code"]))
        params.extend(("task_ids", task_id) for task_id in p["task_ids"])
        return DispenserRequestSpec(cap.name, cap.method, cap.path_template + "?" + urlencode(params), None, "/dispenser/results", cap.rate_family)
    if job_type == "REPORT_DOWNLOAD":
        cap = DISPENSER_CAPABILITIES[DispenserCapabilityName.DOWNLOAD_RESULT]
        target = cap.path_template.replace("{resultId}", p["result_id"])
        params: list[tuple[str, str]] = []
        if p["product_group_code"] is not None:
            params.append(("pg", p["product_group_code"]))
        if p["download_format"] is not None:
            params.append(("downloadFormat", p["download_format"]))
        if p["result_part_id"] is not None:
            params.append(("resultFilePartId", p["result_part_id"]))
        if params:
            target += "?" + urlencode(params)
        return DispenserRequestSpec(cap.name, cap.method, target, None, "/dispenser/results/{resultId}/file", cap.rate_family)
    if job_type == "REPORT_QUOTA_TYPE":
        cap = DISPENSER_CAPABILITIES[DispenserCapabilityName.QUOTA_BY_TASK_TYPE]
        params = [("taskTypeShortName", p["task_type_short_name"])]
        if p["product_group_code"] is not None:
            params.append(("pg", p["product_group_code"]))
        target = cap.path_template + "?" + urlencode(params)
        return DispenserRequestSpec(cap.name, cap.method, target, None, "/dispenser/tasktypes/available_count", cap.rate_family)
    if job_type == "REPORT_QUOTA_ID":
        cap = DISPENSER_CAPABILITIES[DispenserCapabilityName.QUOTA_BY_REPORT]
        target = cap.path_template.replace("{report_id}", p["report_id"])
        if p["product_group_code"] is not None:
            target += "?" + urlencode({"pg": p["product_group_code"]})
        return DispenserRequestSpec(cap.name, cap.method, target, None, "/dispenser/tasktypes/reports/{report_id}/available_count", cap.rate_family)
    raise ReportContractError("job type has no executable dispenser spec")


@dataclass(frozen=True, slots=True)
class RawRemoteValue:
    raw: str | None
    known: bool


def normalize_remote_task_status(value: Any) -> RawRemoteValue:
    raw = None if value is None else str(value)
    return RawRemoteValue(raw, raw in KNOWN_REMOTE_TASK_STATUSES)


def normalize_remote_download_status(value: Any) -> RawRemoteValue:
    raw = None if value is None else str(value)
    return RawRemoteValue(raw, raw in KNOWN_REMOTE_DOWNLOAD_STATUSES)


def normalize_remote_availability(value: Any) -> RawRemoteValue:
    raw = None if value is None else str(value)
    return RawRemoteValue(raw, raw in KNOWN_REMOTE_AVAILABILITY)


@dataclass(frozen=True, slots=True)
class RemoteTaskEvidence:
    task_id: str | None
    raw_status: RawRemoteValue
    raw_payload_sanitized: Mapping[str, Any]


def parse_task_evidence(payload: Any) -> RemoteTaskEvidence:
    safe = sanitize_report_evidence(payload)
    mapping = safe if isinstance(safe, Mapping) else {}
    task_id = mapping.get("id")
    if task_id is not None:
        task_id = str(task_id)
    return RemoteTaskEvidence(task_id, normalize_remote_task_status(mapping.get("currentStatus")), dict(mapping))


@dataclass(frozen=True, slots=True)
class RemoteResultEvidence:
    result_id: str | None
    task_id: str | None
    raw_availability: RawRemoteValue
    raw_download_status: RawRemoteValue
    archive_size: int | None
    file_delete_date_raw: str | None
    result_file_parts: tuple[Mapping[str, Any], ...]
    raw_payload_sanitized: Mapping[str, Any]


def parse_result_evidence(payload: Mapping[str, Any]) -> RemoteResultEvidence:
    safe = sanitize_report_evidence(payload)
    archive_size = safe.get("archiveSize") if isinstance(safe, Mapping) else None
    if type(archive_size) is not int or archive_size < 0:
        archive_size = None
    parts_raw = safe.get("resultFileParts") if isinstance(safe, Mapping) else None
    parts = tuple(dict(x) for x in parts_raw if isinstance(x, Mapping)) if isinstance(parts_raw, list) else ()
    return RemoteResultEvidence(
        str(safe.get("id")) if safe.get("id") is not None else None,
        str(safe.get("taskId")) if safe.get("taskId") is not None else None,
        normalize_remote_availability(safe.get("available")),
        normalize_remote_download_status(safe.get("downloadStatus")),
        archive_size,
        str(safe.get("fileDeleteDate")) if safe.get("fileDeleteDate") is not None else None,
        parts,
        dict(safe),
    )


def parse_unambiguous_zulu_timestamp(raw: str | None) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    if not raw.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ReportArtifactUploadBinding:
    artifact_upload_id: str
    report_job_id: str
    remote_result_id: str
    remote_result_part_id: str | None
    product_group_code: str | None
    expected_archive_size: int | None
    state: str = "PREPARED"
    finalized_artifact_id: str | None = None
    observed_byte_size: int | None = None
    observed_sha256: str | None = None


class UploadBindingStore(Protocol):
    def get(self, upload_id: str) -> ReportArtifactUploadBinding | None: ...
    def put(self, binding: ReportArtifactUploadBinding) -> None: ...
    def update(self, binding: ReportArtifactUploadBinding) -> None: ...


class InMemoryUploadBindingStore:
    def __init__(self) -> None:
        self._items: dict[str, ReportArtifactUploadBinding] = {}

    def get(self, upload_id: str) -> ReportArtifactUploadBinding | None:
        return self._items.get(upload_id)

    def put(self, binding: ReportArtifactUploadBinding) -> None:
        if binding.artifact_upload_id in self._items:
            raise ArtifactIntegrityConflict("duplicate artifact upload id")
        self._items[binding.artifact_upload_id] = binding

    def update(self, binding: ReportArtifactUploadBinding) -> None:
        if binding.artifact_upload_id not in self._items:
            raise KeyError(binding.artifact_upload_id)
        self._items[binding.artifact_upload_id] = binding


@dataclass(frozen=True, slots=True)
class IngressArtifact:
    artifact_id: str
    storage: ArtifactWriteResult
    byte_size: int
    sha256: str
    mime: str | None


class BinaryArtifactIngress:
    def __init__(
        self,
        *,
        binding_store: UploadBindingStore,
        artifact_store: ReportArtifactStore,
        temp_root: Path,
        remote_download_byte_ceiling: int = DEFAULT_REMOTE_DOWNLOAD_BYTE_CEILING,
        temp_storage_ceiling_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        min_free_disk_bytes: int = 1,
        finalized_lookup: Callable[[str], IngressArtifact | None] | None = None,
    ) -> None:
        self.binding_store = binding_store
        self.artifact_store = artifact_store
        self.temp_root = temp_root
        self.remote_download_byte_ceiling = int(remote_download_byte_ceiling)
        if self.remote_download_byte_ceiling <= 0:
            raise ValueError("remote_download_byte_ceiling must be positive")
        self.temp_storage_ceiling_bytes = int(temp_storage_ceiling_bytes)
        self.min_free_disk_bytes = int(min_free_disk_bytes)
        if self.temp_storage_ceiling_bytes <= 0:
            raise ValueError("temp_storage_ceiling_bytes must be positive")
        if self.min_free_disk_bytes <= 0:
            raise ValueError("min_free_disk_bytes must be positive")
        self.finalized_lookup = finalized_lookup
        self.temp_root.mkdir(parents=True, exist_ok=True)
        self._finalized: dict[str, IngressArtifact] = {}

    def prepare(
        self,
        *,
        report_job_id: str,
        remote_result_id: str,
        remote_result_part_id: str | None,
        product_group_code: str | None,
        expected_archive_size: int | None,
    ) -> ReportArtifactUploadBinding:
        _opaque_id(report_job_id, "report_job_id")
        _opaque_id(remote_result_id, "remote_result_id")
        if remote_result_part_id is not None:
            _opaque_id(remote_result_part_id, "remote_result_part_id")
        upload_id = "upl_" + uuid.uuid4().hex
        binding = ReportArtifactUploadBinding(
            upload_id, report_job_id, remote_result_id, remote_result_part_id,
            product_group_code, expected_archive_size,
        )
        self.binding_store.put(binding)
        return binding

    def ingest(
        self,
        *,
        artifact_upload_id: str,
        report_job_id: str,
        remote_result_id: str,
        remote_result_part_id: str | None,
        chunks: Iterable[bytes],
        observed_mime: str | None,
    ) -> IngressArtifact:
        binding = self.binding_store.get(artifact_upload_id)
        if binding is None:
            raise ReportSecurityError("unknown artifact upload id")
        if binding.report_job_id != report_job_id:
            raise ReportSecurityError("artifact upload report job mismatch")
        if binding.remote_result_id != remote_result_id:
            raise ReportSecurityError("artifact upload result mismatch")
        if binding.remote_result_part_id != remote_result_part_id:
            raise ReportSecurityError("artifact upload result part mismatch")

        if shutil.disk_usage(self.temp_root).free < self.min_free_disk_bytes:
            raise ArtifactLimitExceeded("minimum free disk requirement not met")
        fd, raw_path = tempfile.mkstemp(prefix="m11-agent-upload-", suffix=".zip", dir=self.temp_root)
        os.close(fd)
        path = Path(raw_path)
        try:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            digest = hashlib.sha256()
            size = 0
            with path.open("wb") as out:
                for chunk in chunks:
                    if not isinstance(chunk, (bytes, bytearray)):
                        raise ReportContractError("artifact chunk must be bytes")
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > self.remote_download_byte_ceiling:
                        raise ArtifactLimitExceeded("remote download byte ceiling exceeded")
                    if size > self.temp_storage_ceiling_bytes:
                        raise ArtifactLimitExceeded("temporary storage byte ceiling exceeded")
                    digest.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            plain_sha = digest.hexdigest()

            if binding.state == "COMPLETED":
                existing = self._finalized.get(artifact_upload_id)
                if existing is None and binding.finalized_artifact_id and self.finalized_lookup is not None:
                    existing = self.finalized_lookup(binding.finalized_artifact_id)
                if existing is None:
                    raise ArtifactIntegrityConflict("completed binding lacks finalized artifact")
                if existing.byte_size == size and existing.sha256 == plain_sha:
                    return existing
                raise ArtifactIntegrityConflict("replayed upload bytes differ")

            if binding.expected_archive_size is not None and binding.expected_archive_size != size:
                self.binding_store.update(
                    ReportArtifactUploadBinding(
                        **{**asdict(binding), "state": "CONFLICT", "observed_byte_size": size, "observed_sha256": plain_sha}
                    )
                )
                raise ArtifactIntegrityConflict("CRPT archiveSize differs from observed byte size")

            artifact_id = "art_" + uuid.uuid4().hex
            storage = self.artifact_store.put_file(
                path,
                sensitive=True,
                aad_context={
                    "artifact_id": artifact_id,
                    "report_job_id": report_job_id,
                    "remote_result_id": remote_result_id,
                    "remote_result_part_id": remote_result_part_id,
                    "role": ArtifactRole.REMOTE_TRUE_API_ARCHIVE.value,
                },
                safe_suffix=".bin",
            )
            if storage.plaintext_byte_size != size or storage.plaintext_sha256 != plain_sha:
                raise ArtifactIntegrityConflict("artifact store plaintext verification mismatch")
            artifact = IngressArtifact(artifact_id, storage, size, plain_sha, observed_mime)
            self._finalized[artifact_upload_id] = artifact
            self.binding_store.update(
                ReportArtifactUploadBinding(
                    **{
                        **asdict(binding),
                        "state": "COMPLETED",
                        "finalized_artifact_id": artifact_id,
                        "observed_byte_size": size,
                        "observed_sha256": plain_sha,
                    }
                )
            )
            return artifact
        finally:
            path.unlink(missing_ok=True)


def safe_filename(report_type: str, fmt: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", report_type)[:80] or "report"
    ext = {
        "CSV": ".csv", "XLSX": ".xlsx", "JSON": ".json", "ZIP": ".zip",
    }.get(fmt, ".bin")
    return base + ext


def artifact_reuse_allowed(
    *,
    old_request_fingerprint: str,
    new_request_fingerprint: str,
    old_snapshot_hash: str,
    new_snapshot_hash: str,
    old_schema_version: str,
    new_schema_version: str,
    old_format: str,
    new_format: str,
    ready: bool,
    expired_or_deleted: bool,
) -> bool:
    return (
        ready
        and not expired_or_deleted
        and old_request_fingerprint == new_request_fingerprint
        and old_snapshot_hash == new_snapshot_hash
        and old_schema_version == new_schema_version
        and old_format == new_format
    )
