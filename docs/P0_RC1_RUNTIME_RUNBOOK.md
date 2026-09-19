# P0 RC1 runtime runbook — validation/package only

Task: `P0-RC1-RUNTIME-RECONCILIATION-001`.

This runbook describes the validated RC1 package shape. It **does not authorize** deployment,
production migration, real certificate/PIN operations, or any True API request.

## Release identity

The canonical application base for this reconciliation is M15 accepted commit
`ce71f9e049bc7d65a0221001b2c7e5aa701f2243`.

The actual RC1 source identity is the exact `release/p0-rc1` workflow checkout SHA recorded in
`RELEASE.json` and in the artifact checksum sidecars. Mutable tags are not canonical.

Expected migration head: `0016_m15_production_hardening`.

## Runtime artifacts

RC1 CI produces two independent runtime artifacts:

1. VPS runtime archive:
   `sellari-marking-p0-rc1-0.5.1-<sha12>.tar.gz` plus `.sha256`.
2. Windows outbound-agent archive:
   `sellari-wbcz-agent-p0-rc1-0.5.1-<sha12>.zip` plus `.sha256`.

The VPS archive contains the accepted backend, migrations, M15 production compose,
frontend production build, M15 operational scripts/runbooks and release metadata.
It deliberately excludes `src/wbcz_ui`, real environment files, DB files, spreadsheets,
private-key/certificate containers and Windows credentials.

The Windows archive contains a self-contained `wbcz-agent` executable plus non-secret operator
helpers. It does not contain enrollment tokens, permanent credentials, certificate thumbprints,
participant INN, PINs or private keys.

## Fixed safety boundaries

- `WBCZ_TRUE_API_WRITE_ENABLED=false` remains hard-disabled in production compose.
- `WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED=false`.
- M15 web/worker runtime receives the accepted P0 organisation metadata variables
  (`WBCZ_ORGANISATION_TYPE`, `WBCZ_ACTIVITY_FIAS_ID`, `WBCZ_ACTIVITY_KPP`,
  `WBCZ_REMOTE_SALE_RETURN_PAID`) without enabling document writes.
- Windows agent launch helpers force `WBCZ_AGENT_PRODUCTION_WRITE_ENABLED=false` and
  `WBCZ_TRUE_API_WRITE_ENABLED=false`.
- True API production transport remains Windows outbound agent -> CryptoPro/GOST TLS -> True API.
- Private key/PIN never move to VPS.
- No generic signer/proxy is introduced.
- No RC1 CI step calls True API.
- No RC1 CI step deploys to VPS or applies a production migration.

## VPS deployment prerequisites — external gates only

A later separately authorized deployment requires all of the following before any action:

1. Architect/user acceptance of the exact RC1 SHA and CI run.
2. Verified artifact checksums and `RELEASE.json` exact source SHA.
3. Production secret/key material provisioned outside Git:
   - PostgreSQL bootstrap/app/migrator/backup credentials;
   - SecretProvider master key;
   - report artifact keyring;
   - M13 audit key material.
4. Existing valid HTTPS hostname/reverse proxy for the backend.
5. Verified backup/PITR state and an operator-approved maintenance window.
6. Exact current production migration revision and schema-drift check.
7. Separate approval to run migration `0016_m15_production_hardening`.
8. Production write gate confirmed false before and after deployment.
9. P0 organisation metadata verified for the intended participant; missing/ambiguous business
   fields remain fail-closed/manual-review and are not invented by deployment tooling.

The old `deploy/init-production-env.sh` from the pre-M15 packaging line is **not** an RC1
bootstrap authority. M15 role-separated database and key material must be provisioned according to
`docs/M15_PRODUCTION_HARDENING_RUNBOOK.md`.

## Windows agent prerequisites — external gates only

A later Windows installation requires:

1. Windows host with supported CryptoPro CSP/GOST TLS tooling.
2. Approved certificate already installed in the Windows certificate store.
3. Certificate thumbprint and participant INN configured locally.
4. Backend HTTPS URL reachable outbound from Windows.
5. A short-lived one-use enrollment token generated through the accepted M14/M15 enrollment flow.
6. The permanent participant-bound credential stored through DPAPI by `wbcz-agent enroll`.
7. Safe preflight acceptance before normal polling is enabled.
8. A separate future approval before any production document write can ever be enabled.

RC1 does not generate or inspect a real certificate, does not request a PIN and does not access a
real enrollment token.

## Windows operator flow after future authorization

1. Verify ZIP checksum.
2. Extract the Windows artifact.
3. Run `Install-WbczAgent.ps1`.
4. Run `Set-WbczAgentConfig.ps1` and provide only non-secret runtime metadata.
5. Obtain a one-use enrollment token through the approved server-side flow.
6. Run the packaged `Enroll-WbczAgent.ps1`; the token exists only in process environment for the exchange and
   is cleared by the helper afterward. The returned permanent credential is stored by the agent
   through DPAPI.
7. Run `Preflight-WbczAgent.ps1` without a CIS, or with an explicitly approved read-only test CIS.
8. Do not run `Start-WbczAgent.ps1` until a separate operator authorization.

## Migration/runtime verification for a future deployment

A future deployment must verify, without using the RC1 CI as authorization:

- runtime app DB uses the least-privilege `wbcz_app` role;
- one-shot migration uses `wbcz_migrator` only;
- `alembic current` becomes exactly `0016_m15_production_hardening`;
- web and worker readiness pass;
- Windows agent protocol is compatible with `m15-v1` / minimum `m14-v1`;
- frontend is the build from the exact RC1 SHA;
- M13 audit, report artifact encryption and SecretProvider health checks pass;
- production True API write remains disabled.

Application rollback does not reverse external business operations. Any future ambiguous remote
write outcome must be reconciled through accepted document/CIS reads; blind resubmission remains
forbidden.
