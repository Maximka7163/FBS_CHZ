# M15 production hardening runbook

This document is an implementation/release contract. It does **not** authorize deployment, production migration, certificate use, or True API business writes.

## Fixed release identity

A production release is identified by an exact Git commit SHA, application version, image digest, exact Alembic revision `0016_m15_production_hardening`, release manifest checksum, dependency lock checksums, SBOM reference, and agent protocol range. The mutable tag `latest` is never canonical.

Production feature gates remain:

- `WBCZ_TRUE_API_WRITE_ENABLED=false`.
- public registration disabled.
- M7 XML writes blocked on the official XSD gap.
- M8 SUZ production wire blocked on official core SUZ artifacts.
- M10 Ozon wire/read execution remains blocked.
- final production legacy global agent bootstrap disabled.

## Runtime topology

Host nginx/TLS → `marking-backend` web container → PostgreSQL. A separate `marking-worker` container consumes DB-backed report leases, runs scheduler/reconciliation scans, persists heartbeats and performs safe ephemeral cleanup. PostgreSQL is internal-only. Artifacts and encrypted secret-store data use dedicated persistent volumes. Windows agents initiate outbound HTTPS only and authenticate with participant-bound credentials.

Web owns HTTP/auth/RBAC/enqueue. Worker owns local report execution, retries, cleanup, scheduler scans and manual-review convergence. No Redis, RabbitMQ, Celery or Kubernetes is required by M15.

## PostgreSQL roles

- `wbcz_migrator`: schema owner/DDL, deployment only.
- `wbcz_app`: runtime DML/sequence access; no schema CREATE/ALTER/DROP or role administration.
- `wbcz_backup`: minimum read privileges used by the backup process.

The runtime app URL must use `wbcz_app`. The migrator URL is passed only to the one-shot maintenance migration process. Runtime containers must not receive migrator credentials.

## Migration procedure

1. Select the exact accepted release SHA and verify the release manifest and checksums.
2. Verify current production revision is exactly the documented predecessor.
3. Confirm worker drain: worker heartbeat reaches `DRAINING`, no new leases are claimed, in-flight safe work completes or leases are released/allowed to expire.
4. Enter the maintenance/write-freeze window. The production True API write gate remains false regardless.
5. Produce and verify a fresh recovery point: base backup/WAL continuity and portable `pg_dump -Fc`.
6. Acquire an operator-controlled migration advisory lock.
7. Run Alembic **once** as `wbcz_migrator` to exact target `0016_m15_production_hardening`.
8. Verify `alembic current` equals the exact target and run schema/privilege invariants.
9. Start worker, verify heartbeat/scheduler heartbeat, then start web.
10. Require `/api/live` and `/api/ready` to pass. Run non-destructive smoke checks.
11. Verify M13 audit chains.
12. Observe the maintenance window before ending maintenance.

Production rollback does not assume Alembic downgrade is safe.

## Application and database rollback

Application rollback is permitted only when the previous application is explicitly schema-compatible with revision 0016. Database rollback is a forward fix or restore from the verified pre-migration recovery point. Do not perform a blind Alembic downgrade in production.

An application/database rollback never reverses a remote business operation already accepted by an external system. Use official status/read reconciliation, an official corrective operation when supported, or manual review.

## Backup and PITR contract

Project targets (engineering policy, not legal retention requirements):

- PostgreSQL RPO ≤ 15 minutes.
- artifact/secret-store RPO ≤ 1 hour.
- service RTO ≤ 4 hours.

Maintain PostgreSQL base backups plus continuous WAL archiving/PITR and periodic `pg_dump -Fc` portability backups. Back up separately: PostgreSQL, report artifacts, encrypted SecretProvider store, cryptographic recovery material/key versions, release/config manifest. Do **not** copy Windows certificate private keys or PINs into VPS backups.

Backup monitoring must produce a sanitized status manifest consumed by `scripts/m15_backup_contract.py`. File existence alone is not success.

## Restore drill

A scheduled restore drill uses isolated infrastructure and must prove:

1. PostgreSQL restores and reports exact expected migration `0016_m15_production_hardening`.
2. M13 system/organisation chains verify.
3. Encrypted SecretProvider sample refs decrypt with restored historical key material.
4. Sensitive artifact samples decrypt and match persisted plaintext SHA-256/size; non-sensitive samples match stored SHA-256/size.
5. App readiness passes against the restored system.

Use `scripts/m15_restore_verify.py`. No production restore is performed by CI.

## Secret/key recovery

The SecretProvider master key, artifact key ring and audit key material are separate from their encrypted data stores. Backups must retain active and historical versions. Rotation adds a new version; old versions remain available for decrypt/verification until an explicit accepted retirement policy exists.

Provider failures never fall back to plaintext environment credentials. WB/Ozon DB rows keep only opaque refs/versions. A stage failure leaves DB unchanged; activation failure preserves the old active version; a DB failure after provider activation leaves durable pending DB evidence for reconciliation.

## Artifact operations

`/var/lib/wbcz/artifacts` is persistent and server-path-controlled. Sensitive report artifacts are AEAD-encrypted. DB tenant authorization, not filesystem paths, is authoritative. Free-space admission runs before writes. Temporary `.tmp`/ingress files are operationally cleaned; business artifacts are not auto-deleted because retention policy is not finalized.

## Non-destructive production smoke

Smoke only:

1. `GET /api/live`.
2. `GET /api/ready` and confirm build SHA/revision.
3. Login + CSRF flow and tenant isolation check.
4. RBAC denial/allow fixture.
5. Append a synthetic non-business M13 event and verify chain.
6. Confirm worker heartbeat and scheduler heartbeat.
7. Generate one local synthetic report and verify artifact encrypt/decrypt/hash.
8. Stage/activate/read/revoke a synthetic SecretProvider value.
9. Confirm agent heartbeat/protocol metadata and certificate **metadata only**.
10. Optional True API auth/preflight; optional M1 read requires a separately approved test CIS.
11. Optional WB seller-info read-only probe if configured.
12. Confirm M7/M8/M10 blockers and `true_api_write_enabled=false`.

No smoke step creates, withdraws, returns, orders, or mutates a real marked item.

## Retention

M15 cleanup is limited to expired sessions, old login attempts/zero throttle state, expired/revoked invitations, stale worker heartbeats, expired enrollment tokens, old rate-window rows, and temporary/orphan files. It does not auto-delete business ledgers/jobs, manual-review history, M13 audit, report artifacts, or business evidence.
