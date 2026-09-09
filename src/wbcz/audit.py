from __future__ import annotations

import sqlite3
from typing import Any

from .models import canonical_json, utc_now


def append_audit(
    connection: sqlite3.Connection,
    action: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, Any],
) -> None:
    """Append inside the caller's transaction; never commit independently."""
    connection.execute(
        """INSERT INTO audit_log
        (action, entity_type, entity_id, details_json, created_at)
        VALUES (?, ?, ?, ?, ?)""",
        (action, entity_type, entity_id, canonical_json(details), utc_now()),
    )
