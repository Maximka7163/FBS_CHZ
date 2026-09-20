# Printing Local Backend Foundation — implementation contract

Task: `PRINTING-LOCAL-BACKEND-FOUNDATION-001`

This milestone is local-only. It does not implement production SUZ FULL-KM acquisition, physical printer execution, guessed SUZ endpoints, or any new production marking mutation.

## Core safety rule

`SEARCHABLE_KIZ != PRINTABLE_KIZ`.

A CIS/KIZ visible through M1/True API search is not printable by existence alone. A code becomes `PRINTABLE_LOCAL_FULL_KM_AVAILABLE` only when all of the following are proven locally:

1. an exact retained FULL KM mapping exists in `stored_full_km_items`;
2. the mapping is tenant- and participant-bound;
3. `provenance_state=PROVEN`;
4. the mapping points to the accepted M8 encrypted vault/order/block lineage;
5. vault AAD/authentication, block hash/count and per-item offset/length/hash checks all pass.

No mapping yields `NOT_PRINTABLE_FULL_KM_UNAVAILABLE`. Unknown/conflicting provenance or broken/integrity-failing linkage yields `MANUAL_REVIEW`.

`KI_ONLY != FULL_KM`. Sellari must never reconstruct FULL KM from KI/SGTIN/CIS, invent AI 91/92, or convert a searchable CIS into a printable code.

The local CIS lookup index is HMAC-only. No plaintext FULL KM column or plaintext CIS fragment is stored in the printing index.

## M8 vault relationship

`stored_full_km_items` is a per-code locator over the existing encrypted M8 vault. It stores only IDs, HMAC lookup material, deterministic byte locator metadata and SHA-256 evidence. Exact FULL KM bytes remain encrypted inside M8 vault storage.

The production remote acquisition/reacquisition wire remains blocked. `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=true` is rejected by startup validation.

## Templates and immutable versions

A `print_templates` row is the mutable logical template identity. Editing never updates a historical layout. Every edit creates a new `print_template_versions` row with a canonical layout SHA-256 and incremented version.

Historical template versions are immutable at PostgreSQL level: UPDATE/DELETE is rejected by `trg_print_template_versions_immutable`. Templates are archived rather than destructively deleting history.

The layout language is closed. Allowed elements are:

- `DATA_MATRIX_KM` — exactly one, mandatory, payload source fixed to `SYSTEM_FULL_KM`;
- `HUMAN_READABLE_KI`;
- `GTIN`;
- `ARTICLE` / `SKU`;
- `PRODUCT_NAME`;
- `STATIC_TEXT`;
- `LINE`;
- `RECTANGLE`.

Only bounded geometry, allowlisted fonts, bounded font sizes, supported alignment/rotation, bounded static text and bounded DataMatrix settings are accepted. Arbitrary payloads, scripts, HTML/JS, expressions, SQL, URLs, filesystem paths, external fonts, plugins and raw ZPL/EPL/CPCL are rejected.

## DataMatrix renderer invariants

The renderer foundation creates GS1 DataMatrix ECC200 from exact bytes. It does not call `strip()`, Unicode normalization, URL encoding, separator removal, or AI 91/92 recomputation.

ASCII 29 remains ASCII 29. Visible `<GS>` is rejected as a substitute. The DataMatrix payload source is never caller-editable.

The accepted module-size range is enforced by the renderer, including the effective device X-dimension after integer pixel scaling. Quiet zone uses the standards-compatible one-module default/constraint from the accepted research; no proprietary CRPT override is invented.

CI renders a synthetic FULL KM fixture with zxing-cpp and decodes the symbol with independent libdmtx/pylibdmtx. The recovered logical bytes, including ASCII 29 separators, must equal the original synthetic fixture exactly.

Browser preview is synthetic-only. It never decrypts a retained FULL KM into a browser response.

## Print jobs and reprint semantics

`print_jobs`, `print_job_items` and append-only `print_events` persist only IDs, hashes, template-version references, safe state/error codes and printer-profile fingerprints. They do not persist plaintext FULL KM.

A new print job can be created only after every requested CIS resolves to a locally proven printable item.

Default **Repeat print** means:

1. start from a successful original print event;
2. reuse the same retained FULL KM item(s);
3. reuse `original_print_event.template_version_id`;
4. create a new `PrintJob` with mode `REPRINT_ORIGINAL_TEMPLATE`.

It never creates a new KIZ, mutates CIS state, reacquires FULL KM, or silently switches to today's template.

The separate explicit operation `PRINT_USING_CURRENT_TEMPLATE` keeps the exact same retained FULL KM while deliberately selecting the template's current immutable version. Its job/event semantics are distinct.

`print_events` are append-only at PostgreSQL level.

## RBAC and API

Permissions:

- VIEWER: `PRINT_READ`;
- OPERATOR: `PRINT_READ` + `PRINT_EXECUTE`;
- ADMIN: adds `PRINT_TEMPLATES_MANAGE`;
- OWNER: all printing permissions.

`CIS_READ` remains the M1 search/read permission. `SUZ_MANAGE` does not bypass blocked remote FULL-KM acquisition. `PRINT_READ` never grants plaintext FULL KM access.

Tenant-scoped authenticated API families cover:

- template list/detail/create/new immutable version/archive;
- exact CIS printability resolve;
- synthetic template preview;
- print job create/list/detail;
- default original-template reprint and explicit current-template reprint;
- safe typed Windows-agent control contract.

There is no generic FULL-KM export, clipboard/copy endpoint, printer proxy or arbitrary printer-command endpoint.

## Windows-local boundary

The accepted boundary remains browser → backend PrintJob → participant-bound Windows Agent → trusted local renderer/spool adapter.

This milestone implements only a closed `printing-agent-v1` control DTO and fake executor. The DTO contains job/template/item IDs, ordinals, payload SHA-256 and approved logical printer profile metadata. It explicitly says `sensitive_payload_delivery=BLOCKED_NOT_IMPLEMENTED`.

Plaintext FULL KM is not placed in ordinary `agent_jobs.payload_json`. No real spooler/printer call exists. No caller-supplied raw printer program is accepted.

## Audit and redaction

M13 registry additions:

- `PRINT_TEMPLATE_CREATED`
- `PRINT_TEMPLATE_VERSION_CREATED`
- `PRINT_TEMPLATE_ARCHIVED`
- `PRINT_JOB_REQUESTED`
- `PRINT_JOB_COMPLETED`
- `PRINT_JOB_FAILED`
- `REPRINT_REQUESTED`
- `REPRINT_COMPLETED`
- `REPRINT_FAILED`

Audit metadata is restricted to IDs, counts, hashes, modes, safe error codes and printer-profile fingerprints. Plaintext FULL KM and plaintext marking values are not audit metadata.

## Feature gates

Defaults are fail-closed:

- `WBCZ_PRINTING_ENABLED=false`
- `WBCZ_PRINT_EXECUTION_ENABLED=false`
- `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false`

Production physical execution is additionally rejected by startup validation in this milestone even if someone attempts to set its flag true.

Existing `WBCZ_TRUE_API_WRITE_ENABLED=false`, M7, M8 and M10 blockers remain authoritative.

## Explicitly blocked / deferred

- production SUZ order creation;
- production initial FULL KM fetch;
- production repeat FULL KM fetch;
- guessed SUZ paths/methods/DTOs;
- physical printer/spooler execution;
- sensitive FULL KM transport to the Windows agent;
- real certificates/PIN/private-key operations for printing;
- real marking codes in tests;
- production deployment or migration application.

A later milestone requires separate acceptance for remote FULL-KM acquisition and physical execution.
