from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from enum import StrEnum
import hashlib
import json
import random
import re
from typing import Any, Callable, Mapping, MutableMapping

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from wbcz.wb_fbs import (
    RateLimitDecision, WbEnvironment, WbRateLimiter, WbTokenType,
)
from wbcz_web.models import ManualReviewCaseRecord, RemoteRateLimitStateRecord
from wbcz_web.services.tenant import active_tenant


EXPECTED_MIGRATION_REVISION = "0018_printing_sensitive_delivery"


class RetryClassification(StrEnum):
    DETERMINISTIC_FAILURE = "DETERMINISTIC_FAILURE"
    AUTH_FAILURE = "AUTH_FAILURE"
    PERMISSION_FAILURE = "PERMISSION_FAILURE"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    CONTRACT_BLOCKED = "CONTRACT_BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    REMOTE_429 = "REMOTE_429"
    REMOTE_5XX = "REMOTE_5XX"
    NETWORK_TIMEOUT_PRE_SEND = "NETWORK_TIMEOUT_PRE_SEND"
    AMBIGUOUS_AFTER_SEND = "AMBIGUOUS_AFTER_SEND"
    STORAGE_TRANSIENT = "STORAGE_TRANSIENT"
    DATABASE_TRANSIENT = "DATABASE_TRANSIENT"
    AGENT_OFFLINE = "AGENT_OFFLINE"
    AGENT_PROTOCOL_ERROR = "AGENT_PROTOCOL_ERROR"
    UNKNOWN_REMOTE_ERROR = "UNKNOWN_REMOTE_ERROR"


@dataclass(frozen=True, slots=True)
class RetryRule:
    max_semantic_attempts: int
    base_seconds: float
    cap_seconds: float
    automatic: bool
    consumes_semantic_attempt: bool = True


RETRY_POLICY: Mapping[RetryClassification, RetryRule] = {
    RetryClassification.DETERMINISTIC_FAILURE: RetryRule(0, 0, 0, False),
    RetryClassification.AUTH_FAILURE: RetryRule(0, 0, 0, False),
    RetryClassification.PERMISSION_FAILURE: RetryRule(0, 0, 0, False),
    RetryClassification.VALIDATION_FAILURE: RetryRule(0, 0, 0, False),
    RetryClassification.CONTRACT_BLOCKED: RetryRule(0, 0, 0, False),
    RetryClassification.RATE_LIMITED: RetryRule(6, 2, 120, True),
    RetryClassification.REMOTE_429: RetryRule(6, 2, 120, True),
    RetryClassification.REMOTE_5XX: RetryRule(5, 2, 120, True),
    RetryClassification.NETWORK_TIMEOUT_PRE_SEND: RetryRule(5, 2, 120, True),
    RetryClassification.AMBIGUOUS_AFTER_SEND: RetryRule(0, 0, 0, False),
    RetryClassification.STORAGE_TRANSIENT: RetryRule(3, 1, 30, True),
    RetryClassification.DATABASE_TRANSIENT: RetryRule(3, 0.1, 2, True),
    RetryClassification.AGENT_OFFLINE: RetryRule(0, 2, 120, True, False),
    RetryClassification.AGENT_PROTOCOL_ERROR: RetryRule(0, 0, 0, False),
    RetryClassification.UNKNOWN_REMOTE_ERROR: RetryRule(0, 0, 0, False),
}


@dataclass(frozen=True, slots=True)
class RetryDecision:
    retry: bool
    delay_seconds: float
    consumes_semantic_attempt: bool
    classification: RetryClassification
    terminal_reason: str | None = None


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return max(0.0, (when.astimezone(timezone.utc) - current.astimezone(timezone.utc)).total_seconds())


def full_jitter_delay(
    classification: RetryClassification,
    attempt: int,
    *,
    rng: Callable[[float, float], float] = random.uniform,
) -> float:
    rule = RETRY_POLICY[classification]
    if rule.cap_seconds <= 0 or rule.base_seconds <= 0:
        return 0.0
    ceiling = min(rule.cap_seconds, rule.base_seconds * (2 ** max(0, int(attempt))))
    return max(0.0, float(rng(0.0, ceiling)))


def retry_decision(
    classification: RetryClassification,
    *,
    semantic_retry_count: int,
    retry_after: str | None = None,
    now: datetime | None = None,
    operation_deadline: datetime | None = None,
    rng: Callable[[float, float], float] = random.uniform,
) -> RetryDecision:
    rule = RETRY_POLICY[classification]
    if not rule.automatic:
        return RetryDecision(False, 0.0, rule.consumes_semantic_attempt, classification, classification.value)
    if rule.consumes_semantic_attempt and semantic_retry_count >= rule.max_semantic_attempts:
        return RetryDecision(False, 0.0, True, classification, "SEMANTIC_RETRY_LIMIT")
    delay = full_jitter_delay(classification, semantic_retry_count, rng=rng)
    parsed = parse_retry_after(retry_after, now=now)
    if parsed is not None:
        delay = parsed
    current = now or datetime.now(timezone.utc)
    if operation_deadline is not None:
        remaining = max(0.0, (operation_deadline - current).total_seconds())
        if remaining <= 0:
            return RetryDecision(False, 0.0, rule.consumes_semantic_attempt, classification, "OPERATION_MAX_AGE")
        delay = min(delay, remaining)
    return RetryDecision(True, delay, rule.consumes_semantic_attempt, classification)


def classify_failure(
    *,
    status_code: int | None = None,
    error_code: str | None = None,
    pre_send_timeout: bool = False,
    ambiguous_after_send: bool = False,
) -> RetryClassification:
    code = (error_code or "").upper()
    if ambiguous_after_send:
        return RetryClassification.AMBIGUOUS_AFTER_SEND
    if pre_send_timeout:
        return RetryClassification.NETWORK_TIMEOUT_PRE_SEND
    if code in {"AGENT_OFFLINE", "AGENT_UNAVAILABLE"}:
        return RetryClassification.AGENT_OFFLINE
    if "PROTOCOL" in code:
        return RetryClassification.AGENT_PROTOCOL_ERROR
    if code in {"CONTRACT_BLOCKED", "FEATURE_BLOCKED", "M7_OFFICIAL_XSD_NOT_PINNED", "OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED"}:
        return RetryClassification.CONTRACT_BLOCKED
    if status_code == 429:
        return RetryClassification.REMOTE_429
    if status_code is not None and 500 <= status_code <= 599:
        return RetryClassification.REMOTE_5XX
    if status_code in {401}:
        return RetryClassification.AUTH_FAILURE
    if status_code in {403}:
        return RetryClassification.PERMISSION_FAILURE
    if status_code in {400, 404, 409, 422}:
        return RetryClassification.VALIDATION_FAILURE
    if code.startswith("DB_") or code in {"DATABASE_TRANSIENT", "DEADLOCK", "SERIALIZATION_FAILURE"}:
        return RetryClassification.DATABASE_TRANSIENT
    if code.startswith("STORAGE_") or code in {"ENOSPC", "EIO"}:
        return RetryClassification.STORAGE_TRANSIENT
    if code in {"RATE_LIMITED"}:
        return RetryClassification.RATE_LIMITED
    if code in {"INVALID", "DETERMINISTIC_FAILURE"}:
        return RetryClassification.DETERMINISTIC_FAILURE
    return RetryClassification.UNKNOWN_REMOTE_ERROR


_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|_)(?:cis|kiz|sgtin|km|password|passwd|session|csrf|invite|token|secret|api_key|"
    r"authorization|bearer|credential|pin|private_key|database_url|db_url|encryption_key|"
    r"artifact_key|audit_key|master_key|signature)(?:$|_)",
    re.IGNORECASE,
)
_PRIVATE_KEY_MARKER = "-----BEGIN"
_DB_URL_RE = re.compile(r"postgres(?:ql)?(?:\+[^:]+)?://[^\s]+", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}", re.IGNORECASE)


def sanitize_operational_data(value: Any, *, _sensitive: bool = False) -> Any:
    """Fail-closed production sanitizer for logs, health, review metadata and metrics."""
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            sensitive = _sensitive or bool(_SENSITIVE_KEY_RE.search(key))
            out[key] = "<REDACTED>" if sensitive else sanitize_operational_data(item)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize_operational_data(item, _sensitive=_sensitive) for item in value]
    if _sensitive:
        return "<REDACTED>"
    if isinstance(value, str):
        text_value = _DB_URL_RE.sub("<REDACTED_DB_URL>", value)
        text_value = _BEARER_RE.sub("Bearer <REDACTED>", text_value)
        if _PRIVATE_KEY_MARKER in text_value and "PRIVATE KEY" in text_value:
            return "<REDACTED_PRIVATE_KEY>"
        return text_value[:2000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return f"<{type(value).__name__}>"


def safe_exception(exc: BaseException, *, error_code: str | None = None) -> dict[str, str | None]:
    return {"exception_class": type(exc).__name__, "error_code": (error_code or type(exc).__name__)[:80]}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _review_fingerprint(
    organisation_id: str,
    participant_id: str,
    domain: str,
    reason_code: str,
    subject_type: str,
    subject_id: str,
    operation_id: str | None,
) -> str:
    payload = json.dumps(
        [organisation_id, participant_id, domain, reason_code, subject_type, subject_id, operation_id],
        ensure_ascii=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ManualReviewService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def open_or_converge(
        self,
        *,
        domain: str,
        reason_code: str,
        subject_type: str,
        subject_id: str,
        severity: str = "WARNING",
        operation_id: str | None = None,
        source_job_id: str | None = None,
        evidence_hashes: tuple[str, ...] = (),
        metadata: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
        increment_attempt: bool = False,
    ) -> ManualReviewCaseRecord:
        scope = active_tenant(self.db)
        fingerprint = _review_fingerprint(
            scope.organisation_id, scope.participant_id, domain, reason_code,
            subject_type, subject_id, operation_id,
        )
        row = self.db.scalar(
            select(ManualReviewCaseRecord).where(
                ManualReviewCaseRecord.organisation_id == scope.organisation_id,
                ManualReviewCaseRecord.participant_id == scope.participant_id,
                ManualReviewCaseRecord.active_fingerprint == fingerprint,
                ManualReviewCaseRecord.status.in_(("OPEN", "ACKNOWLEDGED")),
            ).with_for_update()
        )
        now = _now()
        safe_hashes = sorted({h.lower() for h in evidence_hashes if re.fullmatch(r"[0-9a-fA-F]{64}", h or "")})
        safe_meta = sanitize_operational_data(dict(metadata or {}))
        if row is None:
            row = ManualReviewCaseRecord(
                organisation_id=scope.organisation_id,
                participant_id=scope.participant_id,
                active_fingerprint=fingerprint,
                domain=domain[:48],
                reason_code=reason_code[:96],
                subject_type=subject_type[:48],
                subject_id=subject_id[:160],
                operation_id=operation_id[:160] if operation_id else None,
                source_job_id=source_job_id[:160] if source_job_id else None,
                severity=severity,
                status="OPEN",
                first_seen_at=now,
                last_seen_at=now,
                occurrence_count=1,
                attempt_count=1 if increment_attempt else 0,
                evidence_hashes_json=safe_hashes,
                metadata_sanitized_json=safe_meta if isinstance(safe_meta, dict) else {},
                correlation_id=correlation_id[:128] if correlation_id else None,
            )
            self.db.add(row)
        else:
            row.last_seen_at = now
            row.occurrence_count += 1
            if increment_attempt:
                row.attempt_count += 1
            row.source_job_id = source_job_id[:160] if source_job_id else row.source_job_id
            row.evidence_hashes_json = sorted(set(row.evidence_hashes_json or ()) | set(safe_hashes))
            row.metadata_sanitized_json = safe_meta if isinstance(safe_meta, dict) else {}
            row.correlation_id = correlation_id[:128] if correlation_id else row.correlation_id
            if severity in {"HIGH", "CRITICAL"}:
                row.severity = severity
        self.db.flush()
        return row

    def resolve(
        self,
        case_id: str,
        *,
        user_id: int,
        resolution_code: str,
        resolution_note: str | None = None,
    ) -> ManualReviewCaseRecord:
        scope = active_tenant(self.db)
        row = self.db.scalar(
            select(ManualReviewCaseRecord).where(
                ManualReviewCaseRecord.id == case_id,
                ManualReviewCaseRecord.organisation_id == scope.organisation_id,
                ManualReviewCaseRecord.participant_id == scope.participant_id,
            ).with_for_update()
        )
        if row is None:
            raise KeyError("manual review case not found")
        if row.status == "RESOLVED":
            return row
        row.status = "RESOLVED"
        row.resolved_by_user_id = user_id
        row.resolved_at = _now()
        row.resolution_code = resolution_code[:80]
        row.resolution_note = (resolution_note or "")[:500] or None
        self.db.flush()
        return row


def _wb_scope(secret_ref: str) -> tuple[str, str]:
    # Production integration wiring uses wb:<connection-id>:<credential-version>.
    parts = (secret_ref or "").split(":", 2)
    if len(parts) == 3 and parts[0] == "wb" and parts[1] and parts[2]:
        return parts[1][:160], parts[2][:128]
    digest = hashlib.sha256((secret_ref or "missing").encode("utf-8")).hexdigest()
    return "legacy-" + digest[:32], "legacy"


class PostgresWbRateLimiter:
    """Cross-process token bucket using PostgreSQL row locks.

    No sleep and no remote call occur while the row is locked. The accepted WB
    rate table remains owned by wbcz.wb_fbs.WbRateLimiter.
    """

    def __init__(self, db: Session, *, clock: Callable[[], datetime] = _now) -> None:
        self.db = db
        self.clock = clock

    @staticmethod
    def _id(connection_id: str, credential_version: str, environment: str, family: str) -> str:
        raw = "|".join(("WB", connection_id, credential_version, environment, family))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _consume(
        self,
        *,
        family: str,
        token_type: WbTokenType,
        environment: WbEnvironment,
        token_secret_ref: str,
        weight: int,
        allow_debt: bool,
    ) -> RateLimitDecision:
        if weight <= 0:
            return RateLimitDecision(True, 0.0)
        rule = WbRateLimiter().rule(family, token_type, environment)
        connection_id, credential_version = _wb_scope(token_secret_ref)
        key = self._id(connection_id, credential_version, environment.value, family)
        now = self.clock().astimezone(timezone.utc)
        capacity = float(rule.burst)
        refill = float(rule.limit) / float(rule.period_seconds)

        self.db.execute(
            pg_insert(RemoteRateLimitStateRecord).values(
                id=key,
                provider="WB",
                connection_id=connection_id,
                credential_version=credential_version,
                environment=environment.value,
                rate_family=family,
                token_type=token_type.value,
                tokens=capacity,
                capacity=capacity,
                refill_per_second=refill,
                updated_at=now,
            ).on_conflict_do_nothing(index_elements=["id"])
        )
        row = self.db.scalar(
            select(RemoteRateLimitStateRecord)
            .where(RemoteRateLimitStateRecord.id == key)
            .with_for_update()
        )
        if row is None:
            raise RuntimeError("rate limiter row unavailable")
        elapsed = max(0.0, (now - row.updated_at).total_seconds())
        row.capacity = capacity
        row.refill_per_second = refill
        row.token_type = token_type.value
        row.tokens = min(capacity, float(row.tokens) + elapsed * refill)
        row.updated_at = now
        if row.tokens >= weight:
            row.tokens -= weight
            self.db.flush()
            return RateLimitDecision(True, 0.0)
        if allow_debt:
            row.tokens -= weight
            retry = max(0.0, -row.tokens / refill)
            self.db.flush()
            return RateLimitDecision(row.tokens >= 0, retry)
        missing = weight - row.tokens
        self.db.flush()
        return RateLimitDecision(False, missing / refill)

    def consume(
        self,
        *,
        family: str,
        token_type: WbTokenType,
        environment: WbEnvironment,
        token_secret_ref: str,
        now_monotonic: float,
        weight: int = 1,
    ) -> RateLimitDecision:
        del now_monotonic
        return self._consume(
            family=family, token_type=token_type, environment=environment,
            token_secret_ref=token_secret_ref, weight=weight, allow_debt=False,
        )

    def charge_response(
        self,
        *,
        family: str,
        token_type: WbTokenType,
        environment: WbEnvironment,
        token_secret_ref: str,
        now_monotonic: float,
        status_code: int,
    ) -> RateLimitDecision:
        del now_monotonic
        total_weight = WbRateLimiter.response_weight(family, status_code, environment)
        return self._consume(
            family=family, token_type=token_type, environment=environment,
            token_secret_ref=token_secret_ref, weight=max(0, total_weight - 1),
            allow_debt=True,
        )


FORBIDDEN_METRIC_LABELS = frozenset({
    "tenant_id", "organisation_id", "participant_id", "username", "email",
    "cis", "kiz", "order_id", "document_id", "operation_id",
})


@dataclass(frozen=True, slots=True)
class MetricDefinition:
    name: str
    kind: str
    description: str


METRIC_CATALOG: tuple[MetricDefinition, ...] = (
    MetricDefinition("http_requests_total", "counter", "HTTP requests by route/status class"),
    MetricDefinition("http_request_latency_seconds", "histogram", "HTTP request latency"),
    MetricDefinition("db_errors_total", "counter", "Database errors"),
    MetricDefinition("job_queue_depth", "gauge", "Eligible durable job backlog"),
    MetricDefinition("job_oldest_eligible_age_seconds", "gauge", "Oldest eligible job age"),
    MetricDefinition("job_lease_reclaims_total", "counter", "Expired lease reclaims"),
    MetricDefinition("job_retries_total", "counter", "Semantic retry count"),
    MetricDefinition("manual_review_open", "gauge", "Open manual-review backlog"),
    MetricDefinition("agent_runtime_state", "gauge", "Agent active/stale/offline aggregate"),
    MetricDefinition("integration_health_state", "gauge", "Integration health aggregate"),
    MetricDefinition("remote_429_total", "counter", "Remote 429 responses"),
    MetricDefinition("remote_5xx_total", "counter", "Remote 5xx responses"),
    MetricDefinition("artifact_integrity_failures_total", "counter", "Artifact integrity failures"),
    MetricDefinition("auth_login_failures_total", "counter", "Login failures"),
    MetricDefinition("csrf_failures_total", "counter", "CSRF failures"),
)


class MetricsRegistry:
    """Small vendor-neutral in-process registry; exporters can adapt this catalog later."""

    def __init__(self) -> None:
        self._values: MutableMapping[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    def record(self, name: str, value: float = 1.0, *, labels: Mapping[str, str] | None = None) -> None:
        if name not in {m.name for m in METRIC_CATALOG}:
            raise KeyError(name)
        raw = dict(labels or {})
        forbidden = FORBIDDEN_METRIC_LABELS.intersection(raw)
        if forbidden:
            raise ValueError(f"forbidden metric labels: {sorted(forbidden)}")
        safe = tuple(sorted((str(k)[:48], str(v)[:80]) for k, v in raw.items()))
        key = (name, safe)
        self._values[key] = self._values.get(key, 0.0) + float(value)

    def snapshot(self) -> dict[str, float]:
        return {name + ("{" + ",".join(f"{k}={v}" for k, v in labels) + "}" if labels else ""): value for (name, labels), value in self._values.items()}


@dataclass(frozen=True, slots=True)
class AlertCondition:
    code: str
    severity: str
    active: bool
    reason: str


class AlertPolicy:
    """Typed health evaluation only; delivery to a monitoring vendor is out of scope."""

    def evaluate(self, snapshot: Mapping[str, Any]) -> tuple[AlertCondition, ...]:
        checks = (
            ("SERVICE_UNAVAILABLE", "CRITICAL", not bool(snapshot.get("service_available", True)), "service unavailable"),
            ("DATABASE_UNAVAILABLE", "CRITICAL", not bool(snapshot.get("database_available", True)), "database unavailable"),
            ("MIGRATION_MISMATCH", "CRITICAL", not bool(snapshot.get("migration_match", True)), "packaged migration mismatch"),
            ("AUDIT_INTEGRITY_FAILURE", "CRITICAL", snapshot.get("audit_integrity") is False, "M13 audit integrity failure"),
            ("BACKUP_STALE", "CRITICAL", snapshot.get("backup_healthy") is False, "backup/PITR health failure"),
            ("SECRET_PROVIDER_UNAVAILABLE", "HIGH", snapshot.get("secret_provider_available") is False, "secret provider unavailable"),
            ("WORKER_STALLED", "HIGH", snapshot.get("worker_stalled") is True, "worker heartbeat stalled"),
            ("SCHEDULER_STALLED", "HIGH", snapshot.get("scheduler_stalled") is True, "scheduler heartbeat stalled"),
            ("AGENT_OFFLINE", "HIGH", snapshot.get("primary_agent_offline_too_long") is True, "primary agent offline"),
            ("CERTIFICATE_EXPIRED", "HIGH", snapshot.get("certificate_expired") is True, "certificate expired"),
            ("MANUAL_REVIEW_GROWTH", "HIGH", snapshot.get("manual_review_growth") is True, "manual review backlog growth"),
            ("CERTIFICATE_WARNING", "WARNING", snapshot.get("certificate_warning") is True, "certificate expiry warning"),
            ("SUSTAINED_429", "WARNING", snapshot.get("sustained_429") is True, "sustained remote rate limiting"),
        )
        return tuple(AlertCondition(code, severity, bool(active), reason) for code, severity, active, reason in checks if active)
