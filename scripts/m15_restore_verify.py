from __future__ import annotations

import argparse
from io import BytesIO
import json
from pathlib import Path
import sys

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from wbcz.m11_reports import FilesystemReportArtifactStore
from wbcz_web.config import WebConfig
from wbcz_web.models import AuditChainHeadRecord
from wbcz_web.services.audit_history import AuditService
from wbcz_web.services.production_hardening import EXPECTED_MIGRATION_REVISION
from wbcz_web.services.production_secrets import (
    EncryptedVersionedFilesystemSecretProvider, VersionedFilesystemKeyProvider,
)
from wbcz_web.services.runtime_health import actual_migration_revision, audit_key_material


def verify(config: WebConfig, manifest: dict) -> None:
    engine = create_engine(config.database_url, pool_pre_ping=True, future=True)
    key, key_id = audit_key_material(config)
    with Session(engine) as db:
        revision = actual_migration_revision(db)
        if revision != EXPECTED_MIGRATION_REVISION:
            raise RuntimeError("RESTORE_MIGRATION_MISMATCH")
        audit = AuditService(db, pseudonym_key=key, pseudonym_key_id=key_id)
        for head in db.scalars(select(AuditChainHeadRecord)):
            result = (
                audit.verify_chain(system=True)
                if head.scope_kind == "SYSTEM"
                else audit.verify_chain(organisation_id=head.organisation_id)
            )
            if result.status != "VALID":
                raise RuntimeError("RESTORE_AUDIT_CHAIN_INVALID")
    engine.dispose()

    provider = EncryptedVersionedFilesystemSecretProvider(
        config.secret_provider_root,
        master_key_path=config.secret_provider_master_key_path,
    )
    for ref in manifest.get("secret_samples", []):
        value = provider.get(str(ref))
        if not value.value:
            raise RuntimeError("RESTORE_SECRET_DECRYPT_EMPTY")

    store = FilesystemReportArtifactStore(
        Path(config.report_artifact_root),
        key_provider=VersionedFilesystemKeyProvider(config.artifact_keyring_root),
        key_version=config.report_artifact_key_version,
    )
    for item in manifest.get("artifact_samples", []):
        if item.get("sensitive"):
            target = BytesIO()
            size, digest = store.decrypt_sensitive_to(
                str(item["storage_key"]), target, aad_context=dict(item["aad_context"])
            )
            if size != int(item["plaintext_byte_size"]) or digest != str(item["plaintext_sha256"]):
                raise RuntimeError("RESTORE_ARTIFACT_INTEGRITY")
        else:
            size, digest = store.inspect(str(item["storage_key"]))
            if size != int(item["stored_byte_size"]) or digest != str(item["stored_sha256"]):
                raise RuntimeError("RESTORE_ARTIFACT_INTEGRITY")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    config = WebConfig.from_env().validate_for_startup()
    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        verify(config, manifest)
    except BaseException as exc:
        print(f"restore verification failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print("M15 restore verification: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
