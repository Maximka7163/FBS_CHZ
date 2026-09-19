from __future__ import annotations

from pathlib import Path

from wbcz.ozon_foundation import M10_EXECUTABLE_READ_CAPABILITIES, M10_WIRE_READY
from wbcz_web.config import WebConfig
from wbcz_web.models import AgentBindingRecord, TrueApiConnectionRecord
from wbcz_web.services.audit_history import AUDIT_EVENT_REGISTRY
from wbcz_web.services.integration_status import capability_projection


BASE = "fda8dcd12d66f4c363e9239e6cc2783982ec4da3"


def main() -> None:
    migration = Path("migrations/versions/0015_m14_integration_settings.py").read_text(encoding="utf-8")
    assert 'down_revision = "0014_m13_audit_history"' in migration
    assert "WBCZ_AGENT_MACHINE_TOKEN" not in migration
    assert "os.getenv" not in migration
    assert "CryptoPro" not in migration

    route_source = Path("src/wbcz_web/api/integration_routes.py").read_text(encoding="utf-8").lower()
    for forbidden in (
        "active_secret_ref", "pending_secret_ref", "api_key_secret_ref",
        "private_key", "container_path", "database_url",
    ):
        assert forbidden not in route_source, forbidden

    service_source = Path("src/wbcz_web/services/integration_settings.py").read_text(encoding="utf-8")
    assert "M7_OFFICIAL_XSD_NOT_PINNED" in service_source
    assert "OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED" in service_source
    assert "M10_EXECUTABLE_READ_CAPABILITIES_NONE" in service_source
    assert "GENERIC_INTEGRATION_PROXY" not in service_source
    assert "GENERIC_TRUE_API_PROXY" not in service_source

    true_columns = set(TrueApiConnectionRecord.__table__.columns.keys())
    assert not true_columns.intersection({"bearer", "uuid_token", "pin", "private_key", "pfx"})
    binding_columns = set(AgentBindingRecord.__table__.columns.keys())
    assert "credential_hash" in binding_columns
    assert "credential" not in binding_columns
    assert "machine_token" not in binding_columns

    required_audit = {
        "CONNECTION_CREATED", "CONNECTION_UPDATED", "CONNECTION_ENABLED",
        "CONNECTION_DISABLED", "CONNECTION_ARCHIVED", "SECRET_SET", "SECRET_ROTATED",
        "SECRET_REVOKED", "CONNECTION_CHECK_STARTED", "CONNECTION_CHECK_COMPLETED",
        "CONNECTION_CHECK_FAILED", "CERTIFICATE_SELECTION_CHANGED",
        "AGENT_BINDING_CREATED", "AGENT_BINDING_CHANGED", "AGENT_BINDING_DISABLED",
    }
    assert required_audit <= set(AUDIT_EVENT_REGISTRY)

    cfg = WebConfig.from_env()
    assert cfg.true_api_write_enabled is False
    assert not M10_WIRE_READY
    assert M10_EXECUTABLE_READ_CAPABILITIES == ()

    caps = {item["name"]: item["status"] for item in capability_projection(
        true_api_configured=True,
        true_api_auth_ready=True,
        agent_ready=True,
        wb_ready=True,
        true_api_write_enabled=False,
        reports_enabled=False,
    )}
    assert caps["EDO_XML_WRITE"] == "BLOCKED_CONTRACT"
    assert caps["SUZ_ORDER"] == "BLOCKED_CONTRACT"
    assert caps["OZON_READ"] == "BLOCKED_CONTRACT"
    assert caps["TRUE_API_PRODUCTION_WRITE"] == "BLOCKED_FEATURE_GATE"

    print("M14 safety contract: OK")


if __name__ == "__main__":
    main()
