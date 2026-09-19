# P0 RC1 runtime-package reconciliation audit

Task: `P0-RC1-RUNTIME-RECONCILIATION-001`.

Accepted application base: `ce71f9e049bc7d65a0221001b2c7e5aa701f2243` (`m15/production-hardening-001`).

Divergent runtime-package branch reviewed: `p0/runtime-package-001` at
`d007620ea44301de4121fd916e2796b65a199506`, common ancestor
`858a329b56c2cabae62e9814f540072e8a048d3f`.

No commit was blindly cherry-picked. Each divergent change was reviewed against the accepted M15 runtime.

| Commit | Legacy intent | Classification | RC1 disposition |
| --- | --- | --- | --- |
| `734c9139fa141cd49bc765a26afc3f25530acc8b` | expose P0 runtime config fail-closed | **OBSOLETE_SUPERSEDED** | M15 compose hard-codes `WBCZ_TRUE_API_WRITE_ENABLED=false`, disables public registration and disables legacy global agent bootstrap. M14/M15 integration settings and participant-bound enrollment supersede the old global machine-token/env wiring. |
| `bc29f798f214c35b0b0b48f27f85ecd13ad93a50` | bootstrap accepted P0 runtime safely | **OBSOLETE_SUPERSEDED** | The legacy helper targets the pre-M15 single DB-user/global-agent environment. M15 requires separate migrator/app/backup DB roles and separately provisioned secret/key material. RC1 does not port the old bootstrap helper into the runtime bundle. |
| `072fa3d302197727222d2f17c76aa5b0a374ae2d` | safe agent machine-secret provisioning | **OBSOLETE_SUPERSEDED** | M14/M15 replaced the global shared machine secret bootstrap with short-lived enrollment plus participant-bound permanent credentials stored through DPAPI. RC1 packages the current enrollment flow and never resurrects the legacy global secret. |
| `d68505d36b2983c22fc2927a67fcb25b721fcf47` | package backend + Windows agent runtime artifacts | **REQUIRED_PORT** | The accepted M15 branch had release manifest/image validation but did not contain deployable VPS archive + self-contained Windows agent package. RC1 ports this capability against current M15 source, migration `0016_m15_production_hardening`, current frontend and current enrollment model. |
| `161b5dfb17350de91e6f10bbf3c9ae08232f0e20` | distinguish legacy/current pinned bundle SHA | **OBSOLETE_SUPERSEDED** | RC1 artifact metadata is generated from the exact `release/p0-rc1` workflow checkout SHA. The old fixed `858a329...` runtime source distinction is no longer valid. |
| `4f2af430fe83d367aa458e74ea99b4d03c34cd4c` | deterministic WB workbook + full package validation | **ALREADY_EQUIVALENT** | M15 already contains `scripts/generate_regression_workbook.py` and full PostgreSQL/backend/frontend regression. RC1 reuses those current mechanisms rather than copying the old inline workbook generator. |
| `693312bfa6572916db511712451267d155d37dca` | install backend deps before workbook build | **ALREADY_EQUIVALENT** | M15 CI installs locked runtime/test dependencies before regression execution. RC1 keeps that ordering with the current dependency lock. |
| `d007620ea44301de4121fd916e2796b65a199506` | isolate compose validation from host test DB env | **REQUIRED_PORT** | The safety concern remains valid. RC1 package validation builds an isolated synthetic compose environment and does not allow host PostgreSQL test URLs to override container runtime DB settings. |

## RC1 safety interpretation

The port is semantic, not historical. Old hard-coded source SHA, old migration head, legacy global
agent machine-token setup and legacy bootstrap environment are intentionally not restored.

The release candidate keeps:

- production True API writes fail-closed and off by default;
- Windows outbound-only True API transport;
- participant-bound agent enrollment and DPAPI credential storage;
- no certificate private key/PIN on VPS;
- immutable document-byte/signature boundary;
- M15 role-separated PostgreSQL runtime;
- exact migration head `0016_m15_production_hardening`;
- current accepted frontend;
- deterministic VPS runtime archive plus checksum;
- self-contained Windows agent archive plus checksum.

This audit does not authorize deployment, production migration, real certificate use or any True API call.
