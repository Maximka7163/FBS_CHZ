from __future__ import annotations

import hashlib

from sqlalchemy import text
from sqlalchemy.orm import Session


_LOCK_NAMESPACE = "wbcz:wb-history-write:v1"


def _canonical_kiz(kiz: str) -> str:
    value = str(kiz).strip()
    if not value:
        raise ValueError("KIZ lock key must not be empty")
    return value


def tenant_kiz_lock_key(
    organisation_id: str,
    participant_id: str,
    kiz: str,
) -> int:
    raw = (
        f"{_LOCK_NAMESPACE}:{organisation_id}:{participant_id}:{_canonical_kiz(kiz)}"
    ).encode("utf-8")
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big", signed=True)


def acquire_tenant_kiz_locks(
    db: Session,
    organisation_id: str | None,
    participant_id: str | None,
    kizes: list[str] | tuple[str, ...] | set[str],
) -> tuple[int, ...]:
    if bool(organisation_id) != bool(participant_id):
        raise ValueError("organisation_id and participant_id must be provided together")
    if not organisation_id or not participant_id:
        return ()
    if db.get_bind().dialect.name != "postgresql":
        return ()

    canonical = sorted({_canonical_kiz(kiz) for kiz in kizes})
    keys = tuple(
        tenant_kiz_lock_key(str(organisation_id), str(participant_id), kiz)
        for kiz in canonical
    )
    for key in keys:
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
    return keys


def acquire_tenant_kiz_lock(
    db: Session,
    organisation_id: str | None,
    participant_id: str | None,
    kiz: str,
) -> int | None:
    keys = acquire_tenant_kiz_locks(
        db,
        organisation_id,
        participant_id,
        (kiz,),
    )
    return keys[0] if keys else None
