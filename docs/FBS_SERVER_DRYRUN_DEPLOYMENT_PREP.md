# FBS server dry-run deployment preparation

This is a packaging and deployment-preparation contract only. It does **not** authorize a VPS deployment, a production migration, a real True API session, certificate/UKЭП use, signing, document submission, marked-code mutation, DISTANCE, REMOTE_SALE_RETURN, or physical printing.

## Exact runtime contract

The first FBS VPS dry-run package is bound to:

- source branch `fbs/server-dryrun-deployment-prep-001`;
- an exact 40-character source Git SHA recorded in `RELEASE.json`;
- exact Alembic head `0020_printing_physical_spool`;
- deterministic per-file `SHA256SUMS`;
- a SHA-256 sidecar for the final archive;
- committed production dependency locks;
- package scanning that rejects private-key markers, credential-like GitHub tokens, local databases, spreadsheets, certificate/key files and runtime `.env` files.

The historical `scripts/build_p0_rc1_runtime_bundle.py` and M15 release metadata remain historical P0-RC1/M15 contracts. They are not the package path for this dry-run line and are intentionally not rewritten.

## Mandatory dry-run gates

The VPS runtime contract hard-codes:

- `WBCZ_FBS_DRY_RUN_ONLY=true`;
- `WBCZ_AGENT_ENABLED=true` with `WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED=false`;
- `WBCZ_TRUE_API_WRITE_ENABLED=false`;
- `WBCZ_PRINTING_ENABLED=false`;
- `WBCZ_PRINT_EXECUTION_ENABLED=false`;
- `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false`.

The participant-bound agent runtime is enabled only so a separately enrolled Windows Agent can service read-only CIS checks. Enrollment and certificate use are not part of this preparation task. The application-level FBS dry-run guard remains authoritative even if a browser attempts to call the bulk endpoint directly. This packaging layer adds another deployment invariant; it does not replace the application guard.

## Migration preparation

`marking-migrate` targets only `0020_printing_physical_spool`.

Acceptance must prove both:

1. a fresh empty PostgreSQL database upgrades to 0020; and
2. a database at `0016_m15_production_hardening` upgrades through 0017 -> 0018 -> 0019 -> 0020 and finishes exactly at 0020.

Alembic reads only the migration PostgreSQL URL from WBCZ_MIGRATION_DATABASE_URL or WBCZ_DATABASE_URL. It does not instantiate application WebConfig, so the one-shot migrator does not receive Agent credentials, certificate material, audit keys, browser host settings, or other web/worker runtime secrets. Web and worker startup validation is unchanged.

The one-shot compose service explicitly has WBCZ_AGENT_ENABLED=false and WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED=false. Backend/worker remain participant-Agent-enabled for future read-only CIS_CHECK.

No migration is executed against a VPS or production database by this task.

## Package build

Build the accepted frontend into a directory outside the Git checkout, then invoke `scripts/build_fbs_dryrun_runtime_bundle.py` with that external frontend directory, the exact source SHA, source branch, UTC build timestamp and builder SHA. The builder requires builder SHA == source SHA, verifies checkout HEAD, rejects staged/unstaged/untracked changes, and copies Git source only from the tracked-file set. Ignored or other untracked checkout files therefore cannot enter the bundle. It writes `RELEASE.json`, validates dry-run compose gates and migration 0020, writes `SHA256SUMS`, and emits a deterministic archive sidecar.

Building or validating this archive performs no deployment and no external business operation.
