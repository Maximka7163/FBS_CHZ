from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class ConfigurationStatus(StrEnum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    INCOMPLETE = "INCOMPLETE"
    CONFIGURED = "CONFIGURED"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class RuntimeStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    CHECKING = "CHECKING"
    READY = "READY"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"
    STALE = "STALE"
    OFFLINE = "OFFLINE"


class ContractStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    BLOCKED = "BLOCKED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class FeatureGateStatus(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class CapabilityStatus(StrEnum):
    READY = "READY"
    DEGRADED = "DEGRADED"
    BLOCKED_CONTRACT = "BLOCKED_CONTRACT"
    BLOCKED_FEATURE_GATE = "BLOCKED_FEATURE_GATE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


CAPABILITY_NAMES = (
    "TRUE_API_AUTH", "CIS_READ", "REFERENCE_READ", "DOCUMENT_WRITE", "REPORT_EXPORT",
    "EDO_READ", "EDO_XML_WRITE", "SUZ_ORDER", "WB_READ", "OZON_READ",
    "TRUE_API_PRODUCTION_WRITE",
)


def agent_runtime_status(
    *,
    state: str,
    last_seen_at: datetime | None,
    now: datetime | None = None,
    online_seconds: int = 120,
    stale_seconds: int = 600,
    last_error_code: str | None = None,
) -> str:
    if state in {"DISABLED", "ARCHIVED"}:
        return "DISABLED"
    if last_seen_at is None:
        return "UNKNOWN"
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    seen = last_seen_at if last_seen_at.tzinfo else last_seen_at.replace(tzinfo=timezone.utc)
    age = max(0.0, (now - seen.astimezone(timezone.utc)).total_seconds())
    if last_error_code and age <= stale_seconds:
        return "DEGRADED"
    if age <= online_seconds:
        return "ONLINE"
    if age <= stale_seconds:
        return "STALE"
    return "OFFLINE"


def certificate_expiry_status(
    valid_to: datetime | None,
    *,
    now: datetime | None = None,
    critical_days: int = 7,
    soon_days: int = 30,
) -> str:
    if valid_to is None:
        return "UNKNOWN"
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    end = valid_to if valid_to.tzinfo else valid_to.replace(tzinfo=timezone.utc)
    seconds = (end.astimezone(timezone.utc) - now).total_seconds()
    if seconds <= 0:
        return "EXPIRED"
    days = seconds / 86400
    if days <= critical_days:
        return "EXPIRING_CRITICAL"
    if days <= soon_days:
        return "EXPIRING_SOON"
    return "VALID"


def capability_projection(
    *,
    true_api_configured: bool,
    true_api_auth_ready: bool,
    agent_ready: bool,
    wb_ready: bool,
    true_api_write_enabled: bool,
    reports_enabled: bool,
) -> list[dict[str, Any]]:
    def row(name: str, status: str, reason_code: str | None = None) -> dict[str, Any]:
        return {"name": name, "status": status, "reason_code": reason_code}

    auth = (
        CapabilityStatus.READY.value
        if true_api_auth_ready and agent_ready
        else CapabilityStatus.NOT_CONFIGURED.value
        if not true_api_configured
        else CapabilityStatus.UNKNOWN.value
    )
    read = CapabilityStatus.READY.value if auth == CapabilityStatus.READY.value else auth
    return [
        row("TRUE_API_AUTH", auth),
        row("CIS_READ", read),
        row("REFERENCE_READ", read),
        row("DOCUMENT_WRITE", CapabilityStatus.BLOCKED_FEATURE_GATE.value, "TRUE_API_PRODUCTION_WRITE_DISABLED"),
        row(
            "REPORT_EXPORT",
            CapabilityStatus.READY.value if reports_enabled and auth == CapabilityStatus.READY.value
            else CapabilityStatus.BLOCKED_FEATURE_GATE.value,
            None if reports_enabled else "TRUE_API_REPORTS_DISABLED",
        ),
        row("EDO_READ", read),
        row("EDO_XML_WRITE", CapabilityStatus.BLOCKED_CONTRACT.value, "M7_OFFICIAL_XSD_NOT_PINNED"),
        row("SUZ_ORDER", CapabilityStatus.BLOCKED_CONTRACT.value, "OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED"),
        row("WB_READ", CapabilityStatus.READY.value if wb_ready else CapabilityStatus.UNKNOWN.value),
        row("OZON_READ", CapabilityStatus.BLOCKED_CONTRACT.value, "M10_EXECUTABLE_READ_CAPABILITIES_NONE"),
        row(
            "TRUE_API_PRODUCTION_WRITE",
            CapabilityStatus.READY.value if true_api_write_enabled else CapabilityStatus.BLOCKED_FEATURE_GATE.value,
            None if true_api_write_enabled else "TRUE_API_PRODUCTION_WRITE_DISABLED",
        ),
    ]
