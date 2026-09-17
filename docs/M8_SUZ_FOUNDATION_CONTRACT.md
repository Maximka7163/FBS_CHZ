# M8 SUZ safe backend foundation contract

Source boundary: accepted `M8-SUZ-RESEARCH-001`. Product-group scope is `lp` only.

## Milestone state

`FULL_M8_WIRE=BLOCKED`.

The exact current core SUZ wire contract is not implemented because the authoritative current artifacts are not pinned in the repository:

- `API_СУЗ_3.0.pdf`;
- current «СУЗ-ОБЛАКО 4.0. Специальное программное обеспечение. Руководство программиста».

Until those artifacts are accepted, the foundation deliberately keeps these values unknown: core endpoint paths, HTTP methods, production core base URL, request DTOs, response DTOs, exact core auth-header name and RPS. No path is inferred from UI names, error headings or historical examples.

`PRODUCTION_SUZ_CORE_TRANSPORT_ENABLED=NO` and `PRODUCTION_SUZ_WRITE_ENABLED=NO`.

## Connection and authentication metadata

A SUZ connection stores `participant_inn`, opaque exact `oms_id`, opaque exact `oms_connection`, environment/installation metadata and local authentication timestamps/state. `oms_id` and `oms_connection` are not UUID-normalized, integer-coerced, case-normalized or reformatted.

True API relation used by this foundation: `POST /auth/simpleSignIn/{omsConnection}` returns a dynamic SUZ authentication token. The token lifetime model is 10 hours. A newly issued token for the same `omsConnection` supersedes the previous local token instance.

Local token lifecycle states are project metadata, not claimed SUZ raw enums:

- `NOT_ACQUIRED`;
- `ACTIVE`;
- `EXPIRED`;
- `SUPERSEDED`;
- `INVALIDATED`.

Plaintext dynamic token is `MEMORY_ONLY`. PostgreSQL may store only issuance/expiry/last-auth timestamps and an optional one-way fingerprint. There is no refresh-token concept and no static-token fallback. Reauthentication is the future refresh mechanism.

The signing boundary remains the accepted M3 architecture: private key/PIN remain outside the server. For the current source ambiguity the foundation policy is `SUZ_AUTH_CHALLENGE_SIGNATURE_MODE=ATTACHED`; detached signing is not introduced from ambiguous nearby wording. No real authentication or signature is executed by foundation tests.

## Core capability registry: fail closed

The foundation contains metadata entries for future conceptual capabilities such as create/get/status order, buffer status, KM fetch/list/repeat, close, cancel, reject, application report, report status and health.

Every core capability is disabled with:

- `enabled=false`;
- `disabled_reason=OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED`;
- `method=NULL`;
- `path=NULL`;
- `base=NULL`;
- `request_contract=NULL`;
- `response_contract=NULL`.

Invoking a disabled capability fails locally with `M8_WIRE_CONTRACT_NOT_ENABLED` and performs no HTTP request. There is no generic SUZ HTTP request/proxy abstraction and no caller-selected URL, base, path, method, headers, content type, raw HTTP body or signature route.

`M8_CORE_SUZ_HTTP_LOCATION=UNRESOLVED`; therefore no core SUZ transport is placed on VPS or Windows. The Windows/M3 boundary is reused only as the already accepted cryptographic architecture concept.

## LP order-domain validation

`SuzOrderDraft` is a business/domain object only. It is not a SUZ HTTP DTO and has no wire-name mapping.

Current source-confirmed limits/policies represented by the foundation:

- `MAX_GTINS_PER_ORDER=10`;
- `API_V3_MAX_CODES_SINGLE_GTIN_ORDER=2_000_000`;
- `MAX_ACTIVE_ORDERS=100` as a remote/business capability limit, not an authoritative local counter;
- `SUZ_RPS_LIMIT=UNKNOWN`;
- positions: 1..10, positive quantity, duplicate GTIN positions rejected;
- the 2,000,000 limit is applied only to a one-GTIN order; no invented 2,000,000 total/per-item limit is imposed on multi-GTIN orders.

Product group remains domain value `lp`. No SUZ core wire code is invented.

Serial modes:

- `OPERATOR`: client serial list must be absent;
- `SELF_MADE`: serial list is required, its count equals quantity, duplicates are rejected;
- for `lp` SELF_MADE the client-provided fragment length is exactly 12; the final system-prefixed serial length is 13 by source contract;
- `EXACT_SERIAL_CHARSET=UNKNOWN`; no guessed GS1 whitelist is enforced.

Ordinary `lp` policy:

- emission payment is allowed;
- payment-by-application is rejected locally;
- `LP_MANUAL_APPLICATION_REPORT_ALLOWED=false`; manual application-report transport remains disabled;
- automatic application information must not be confused with M5 introduction.

Confirmed release-domain identities are `REMAINS`, `REMARK`, `REAPPLY`, `CROSSBORDER`. `REAPPLY` requires `UNIT`. `producer` is permitted only for source-confirmed special scenarios (`REMAINS`, `REMARK`, `REAPPLY`). Missing UI/API mappings are left unknown and are never serialized.

## M2/M5/M6 boundaries

The foundation exposes a read-only M2 product-evidence adapter for GTIN existence, product group and readiness evidence. It has no remote SUZ preflight endpoint and does not claim UI flags to be exact SUZ request fields.

Package boundary preserves accepted M6 semantics:

- `UNIT`: supported core code-issuance concept;
- `KIK/BUNDLE` and `KIN/SET`: business/card support known, exact SUZ cisType wire value unknown;
- `KITU/BOX` and `KIGU/GROUP`: not exposed as ordinary `lp` SUZ order capabilities;
- `ATK`: not ordinary M8 issuance;
- aggregate formation remains M6 and is not rewritten by M8.

M8 may end in local project state `READY_FOR_M5`; it does not automatically execute M5 introduction or M6 aggregation.

## Raw statuses and errors

Only source-confirmed raw values are marked known.

Order values: `CREATED`, `PENDING`, `APPROVED`, `CLOSED`.

Buffer values: `ACTIVE`, `PENDING`, `EXHAUSTED`.

Unknown raw values are preserved exactly. UI Russian labels are not aliased to API enums. No terminal flag is invented, and `APPROVED` does not mean KM are durably stored.

The error registry preserves known exact raw codes by source category and the documented `3160..3220` serial-error family without fabricating per-code meanings. Unknown future codes are preserved. The foundation does not invent HTTP mappings, retryability or terminality.

## Local reconciliation and ambiguous create

Local M8 states are project states, separate from SUZ raw status. They cover local preparation/signing metadata, ambiguous submission, remote confirmation/processing, code availability/fetch, encrypted durable storage, automatic application reconciliation, close/reject/cancel/report error/manual review and `READY_FOR_M5`.

Order create has no confirmed server idempotency key. Local evidence uses `operation_id + immutable normalized-domain request SHA-256`.

After an ambiguous network result:

`SUBMISSION_UNKNOWN -> REMOTE_LOOKUP_REQUIRED`.

Blind create replay is always forbidden. Because the exact official lookup wire is not pinned, automatic remote lookup remains disabled.

## Fetch/repeat recovery

Schema-independent local fetch states include prepared, in-flight, response received, block identified, encrypting, durably stored, ambiguous, repeat-recovery-required and manual review.

After `FETCH_AMBIGUOUS`, requesting a fresh next block automatically is forbidden. The only future safe recovery shape is: list remote blocks, identify the exact historical block, repeat exact-block retrieval, compare immutable hash/count, then commit. Those remote actions stay disabled until their exact wire contract is pinned. If the block cannot be uniquely identified, the local result is `MANUAL_REVIEW`.

Remote identifiers (`remote_order_id`, `remote_block_id`, `remote_package_id`, `remote_report_id`, `oms_id`, `oms_connection`) are treated as opaque exact strings unless future accepted documentation proves a stricter type.

## Immutable KM evidence and encrypted vault

Full KM payload bytes are never normalized before hashing/encryption. No separator stripping, text rewriting, serial reconstruction or KI-only reconstruction is performed.

Block evidence stores order/GTIN linkage, optional opaque remote block ID, code count, exact payload SHA-256, ciphertext SHA-256, receive time and recovery state.

PostgreSQL must not contain plaintext full KM. `suz_km_vault` stores only authenticated-encryption material and metadata:

- AES-256-GCM ciphertext;
- nonce;
- authentication tag;
- external key version;
- vault format version;
- AAD hash;
- plaintext SHA-256;
- ciphertext SHA-256;
- code count and order/GTIN/block linkage.

Key material is supplied through an injectable key-provider interface and is outside PostgreSQL. No production key source is implemented in M8 foundation. Tests use a test-only provider.

AAD binds participant, `oms_connection`, local order ID, GTIN, remote block ID when known and vault format version. Metadata changes, wrong key or ciphertext/tag mutation fail authentication.

Security defaults:

- `NO_FULL_KM_LOGGING=YES`;
- `NO_KM_IN_ERROR_MESSAGES=YES`;
- `NO_KM_IN_TELEMETRY=YES`;
- `MASK_KM_BY_DEFAULT=YES`.

Full KM, dynamic token, registration key, signature bytes, PIN and private-key material are excluded/redacted from reusable log/error metadata. There is no KM export capability in this foundation.

`FULL_KM` and `KI_ONLY` are distinct. A KI-only value is `NOT_PRINTABLE_AS_DATAMATRIX`; the foundation has no KI -> full KM reconstruction.

Remote service-window metadata is preserved as `UNRETRIEVED_KM_WINDOW_DAYS=90` and `REPEAT_FULL_KM_FETCH_WINDOW_DAYS=2`. These do not trigger destructive local deletion. Local vault retention remains `PROJECT_POLICY_NOT_FINALIZED`.

## Persistence

Migration `0009_m8_suz` is additive on `0008_m7_edo_lite_foundation` and creates:

- `suz_connections`;
- `suz_orders`;
- `suz_order_items`;
- `suz_km_vault`;
- `suz_code_blocks`;
- `suz_reconciliation_events`.

No historical migration is modified. Connection persistence contains no plaintext dynamic token, registration key, private key or PIN. Order/item tables contain no full KM. SELF_MADE serial plaintext is not persisted; only count and optional immutable hash are available. Vault has no plaintext KM column.

## What remains to unblock full M8

The architect must pin and accept the authoritative current core SUZ artifacts. Only after that may implementation add exact endpoint/base/method/header/request/response DTOs, core transport placement, confirmed rate limits and executable read/write/recovery operations.

M8 full milestone is not complete after this foundation. M9 is not started.
