from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
from typing import Any, Mapping

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from wbcz_web.models import (
    AgentBindingRecord, IntegrationHealthCheckRecord, ManualReviewCaseRecord,
    WorkerHeartbeatRecord,
)
from wbcz_web.services.integration_secrets import SecretCapability
from wbcz_web.services.production_hardening import (
    AlertPolicy, EXPECTED_MIGRATION_REVISION, sanitize_operational_data,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def audit_key_material(config: Any) -> tuple[bytes | None, str]:
    path = getattr(config, "audit_key_path", None)
    if path:
        try:
            raw = Path(path).read_bytes().strip()
        except OSError:
            return None, getattr(config, "audit_pseudonym_key_id", "audit-v1")
        if len(raw) >= 32:
            return raw, getattr(config, "audit_pseudonym_key_id", "audit-v1")
        return None, getattr(config, "audit_pseudonym_key_id", "audit-v1")
    value = getattr(config, "audit_pseudonym_key", None)
    if value:
        return value.encode("utf-8"), getattr(config, "audit_pseudonym_key_id", "audit-v1")
    return None, getattr(config, "audit_pseudonym_key_id", "audit-v1")


def actual_migration_revision(db: Session) -> str | None:
    try:
        return db.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
    except Exception:
        return None


def _artifact_status(config: Any) -> dict[str, Any]:
    root = getattr(config, "report_artifact_root", None)
    if not root:
        return {"configured": False, "available": False, "free_bytes": None}
    path = Path(root)
    try:
        path.mkdir(parents=True, exist_ok=True)
        usage = shutil.disk_usage(path)
        available = usage.free >= int(getattr(config, "report_min_free_disk_bytes", 1))
        return {"configured": True, "available": available, "free_bytes": int(usage.free)}
    except OSError:
        return {"configured": True, "available": False, "free_bytes": None}


def _backup_status(config: Any) -> dict[str, Any]:
    raw_path = getattr(config, "backup_status_path", None)
    if not raw_path:
        return {"configured": False, "healthy": None, "last_success_at": None}
    try:
        data = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"configured": True, "healthy": False, "last_success_at": None}
    return {
        "configured": True,
        "healthy": bool(data.get("healthy")) if isinstance(data, dict) and "healthy" in data else False,
        "last_success_at": data.get("last_success_at") if isinstance(data, dict) else None,
    }


class ReadinessService:
    def __init__(self, *, session_factory, config: Any, secret_provider: Any, draining: bool = False) -> None:
        self.session_factory = session_factory
        self.config = config
        self.secret_provider = secret_provider
        self.draining = bool(draining)

    def evaluate(self) -> tuple[bool, dict[str, Any]]:
        result: dict[str, Any] = {
            "service": "wbcz-" + str(getattr(self.config, "process_role", "web")),
            "build_sha": self.config.build_sha,
            "expected_migration_revision": EXPECTED_MIGRATION_REVISION,
            "draining": self.draining,
        }
        if self.draining:
            result["reason_code"] = "INSTANCE_DRAINING"
            return False, result
        try:
            with self.session_factory() as db:
                db.execute(text("SELECT 1"))
                revision = actual_migration_revision(db)
        except Exception:
            result.update({"database": "UNAVAILABLE", "reason_code": "DATABASE_UNAVAILABLE"})
            return False, result
        result["database"] = "READY"
        result["actual_migration_revision"] = revision
        if revision != EXPECTED_MIGRATION_REVISION:
            result["reason_code"] = "MIGRATION_REVISION_MISMATCH"
            return False, result

        audit_key, audit_version = audit_key_material(self.config)
        result["audit_key"] = {"configured": audit_key is not None, "version": audit_version}
        if self.config.environment == "production" and self.config.m15_strict_production and audit_key is None:
            result["reason_code"] = "AUDIT_KEY_UNAVAILABLE"
            return False, result

        caps = getattr(self.secret_provider, "capabilities", SecretCapability(0))
        secret_ok = bool(caps & SecretCapability.READ)
        result["secret_provider"] = {"configured": secret_ok, "capabilities": int(caps.value)}
        if self.config.environment == "production" and self.config.m15_strict_production and not secret_ok:
            result["reason_code"] = "SECRET_PROVIDER_UNAVAILABLE"
            return False, result

        artifact = _artifact_status(self.config)
        result["artifact_store"] = artifact
        if self.config.environment == "production" and self.config.m15_strict_production and not artifact["available"]:
            result["reason_code"] = "ARTIFACT_STORE_UNAVAILABLE"
            return False, result

        result["status"] = "ready"
        return True, sanitize_operational_data(result)


class DeepHealthService:
    def __init__(self, db: Session, *, config: Any, secret_provider: Any) -> None:
        self.db = db
        self.config = config
        self.secret_provider = secret_provider

    def snapshot(self) -> dict[str, Any]:
        now = _now()
        revision = actual_migration_revision(self.db)
        worker_rows = list(self.db.scalars(select(WorkerHeartbeatRecord).order_by(WorkerHeartbeatRecord.worker_id)))
        worker_summary = []
        for row in worker_rows:
            age = max(0.0, (now - row.heartbeat_at).total_seconds())
            worker_summary.append({
                "role": row.role,
                "state": row.state,
                "heartbeat_age_seconds": round(age, 3),
                "scheduler_heartbeat_age_seconds": (
                    round(max(0.0, (now - row.scheduler_heartbeat_at).total_seconds()), 3)
                    if row.scheduler_heartbeat_at else None
                ),
                "build_sha": row.build_sha,
            })
        agent_counts: dict[str, int] = {}
        for row in self.db.scalars(select(AgentBindingRecord)):
            state = row.state
            if state == "ACTIVE":
                age = None if row.last_seen_at is None else (now - row.last_seen_at).total_seconds()
                state = "OFFLINE" if age is None or age > self.config.agent_health_stale_seconds else "STALE" if age > self.config.agent_health_online_seconds else "ACTIVE"
            agent_counts[state] = agent_counts.get(state, 0) + 1
        health_counts = {
            str(status): int(count)
            for status, count in self.db.execute(
                select(IntegrationHealthCheckRecord.overall_status, func.count())
                .group_by(IntegrationHealthCheckRecord.overall_status)
            ).all()
        }
        manual_open = int(self.db.scalar(
            select(func.count()).select_from(ManualReviewCaseRecord).where(
                ManualReviewCaseRecord.status.in_(("OPEN", "ACKNOWLEDGED"))
            )
        ) or 0)
        artifact = _artifact_status(self.config)
        backup = _backup_status(self.config)
        caps = getattr(self.secret_provider, "capabilities", SecretCapability(0))
        snapshot = {
            "status": "diagnostic",
            "build_sha": self.config.build_sha,
            "database": {
                "available": True,
                "migration_revision": revision,
                "expected_revision": EXPECTED_MIGRATION_REVISION,
                "migration_match": revision == EXPECTED_MIGRATION_REVISION,
            },
            "artifact_store": artifact,
            "secret_provider": {"capabilities": int(caps.value), "readable": bool(caps & SecretCapability.READ)},
            "backup": backup,
            "workers": worker_summary,
            "agents": agent_counts,
            "integration_health": health_counts,
            "manual_review": {"open": manual_open},
            "blocked_contracts": {
                "M7": "M7_FULL_XML_WRITE_BLOCKED_ON_OFFICIAL_XSD",
                "M8": "M8_FULL_SUZ_WIRE_BLOCKED_ON_OFFICIAL_CORE_SUZ_ARTIFACTS",
                "M10": "M10_EXECUTABLE_READ_CAPABILITIES_NONE",
            },
            "production_true_api_write_enabled": False,
        }
        alert_input = {
            "service_available": True,
            "database_available": True,
            "migration_match": revision == EXPECTED_MIGRATION_REVISION,
            "backup_healthy": backup["healthy"] if backup["configured"] else None,
            "secret_provider_available": bool(caps & SecretCapability.READ),
            "worker_stalled": any(
                item["state"] == "RUNNING" and item["heartbeat_age_seconds"] > self.config.worker_stale_seconds
                for item in worker_summary
            ),
            "scheduler_stalled": any(
                item["state"] == "RUNNING"
                and item["scheduler_heartbeat_age_seconds"] is not None
                and item["scheduler_heartbeat_age_seconds"] > max(self.config.worker_stale_seconds, self.config.scheduler_interval_seconds * 3)
                for item in worker_summary
            ),
        }
        snapshot["alerts"] = [
            {"code": item.code, "severity": item.severity, "reason": item.reason}
            for item in AlertPolicy().evaluate(alert_input)
        ]
        return sanitize_operational_data(snapshot)


def worker_heartbeat_is_fresh(db: Session, *, config: Any, worker_id: str) -> bool:
    row = db.get(WorkerHeartbeatRecord, worker_id)
    if row is None or row.state not in {"RUNNING", "DRAINING"}:
        return False
    return (_now() - row.heartbeat_at) <= timedelta(seconds=config.worker_stale_seconds)
