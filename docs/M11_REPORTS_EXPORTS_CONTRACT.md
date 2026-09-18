# M11 reports and exports backend contract

Accepted research: `M11-REPORTS-EXPORTS-RESEARCH-001`.

Implementation base: `7ca6681557e3a3c7c6488e2471393baf8f4998fb`.

M11 implements two independent backend layers:

1. local Sellari reporting from already stored project evidence;
2. typed True API dispenser orchestration through the existing Windows/M3 outbound boundary.

No browser/user report download endpoint is part of M11. Participant/organisation authorization for end-user download remains an M12 dependency.

## Hard gates

- `PRODUCTION_TRUE_API_REPORTS_ENABLED=NO_BY_DEFAULT`
- `GENERIC_TRUE_API_REPORT_PROXY=NO`
- `ARBITRARY_REMOTE_URL_DOWNLOAD=NO`
- `CALLER_CONTROLLED_TRUE_API_HOST=NO`
- `CALLER_CONTROLLED_TRUE_API_PATH=NO`
- `CALLER_CONTROLLED_TRUE_API_METHOD=NO`
- `CALLER_CONTROLLED_FILESYSTEM_PATH=NO`
- `CALLER_CONTROLLED_STORAGE_KEY=NO`
- `PATH_TRAVERSAL_ALLOWED=NO`
- `REMOTE_RESULT_DELETE_ENABLED=NO`
- `USER_REPORT_DOWNLOAD_ENABLED=NO`
- `FRONTEND_FREEZE_ACTIVE=YES`
- `REPORT_ROWS_ARE_READ_ONLY=YES`
- `REPORT_GENERATION_MUST_NOT_CHANGE_RECONCILIATION=YES`
- `PROJECT_RETENTION_NOT_FINALIZED=YES`

M7 full XML write remains blocked independently on official XSD.
M8 full SUZ wire remains blocked independently on official core SUZ artifacts.
M9 remains accepted and unchanged.
M10 remains a safe Ozon foundation with `M10_WIRE_READY=NO` and `M10_EXECUTABLE_READ_CAPABILITIES=NONE`.

## Persistence

Additive migration:
- revision: `0012_m11_reports`
- down revision: `0011_m10_ozon`

New tables:
- `report_jobs`
- `report_snapshots`
- `report_artifacts`
- `report_job_events`
- `report_artifact_uploads`

The current `agent_jobs` job-type CHECK is replaced additively to include only these M11 job types:
- REPORT_CREATE
- REPORT_TASK_GET
- REPORT_TASK_LIST
- REPORT_RESULTS
- REPORT_DOWNLOAD
- REPORT_QUOTA_TYPE
- REPORT_QUOTA_ID

Historical migrations are not edited.

No M11 table contains bearer/uuidToken, machine token, PIN, private key, detached signing material, plaintext CIS/KIZ/SGTIN, or a caller-controlled filesystem path.

## Local report jobs and worker

Local business states:
- REQUESTED
- QUEUED
- GENERATING
- READY
- FAILED
- EXPIRED
- CANCELLED

Cancellation is a stored state only; M11 does not expose cancellation control.

Worker lease state is independent:
- lease_owner
- lease_expires_at
- claimed_at
- heartbeat_at
- attempt_count

The SQL repository claims work using PostgreSQL row locking with `SKIP LOCKED`. An expired lease may be reclaimed only when no finalized READY output exists. Attempts are bounded. A READY output prevents regeneration/double publication.

Artifacts use a unique server-generated publication key. A conflicting second authoritative publication fails closed.

## Request fingerprint

`request_fingerprint_sha256` is SHA-256 of canonical JSON containing:
- report_type
- report_schema_version
- participant/organisation scope
- normalized filters
- output format
- sensitivity mode
- snapshot policy/version

It excludes:
- requested_at
- worker identity
- lease identity
- random report job ID
- generated filename

Equal request fingerprints do not imply artifact reuse. Reuse additionally requires the exact snapshot descriptor/hash, schema version, output format, READY state, and non-expired/non-deleted artifact state.

## Snapshot contract

`ReportSnapshotDescriptor` persists:
- strategy
- snapshot_at
- source domains/tables
- high-water/source metadata
- sanitized source filter
- descriptor SHA-256
- schema version
- optional internal snapshot artifact
- row count

Strategies:
- APPEND_ONLY_HIGH_WATER
- POSTGRES_CONSISTENT_SNAPSHOT
- MATERIALIZED_IMMUTABLE

Mutable-source extraction uses a read-only PostgreSQL repeatable-read transaction. Large final generation can continue from a server-controlled immutable JSONL snapshot after the DB snapshot is closed.

M11 never claims that `updated_at <= timestamp` reconstructs historical mutable rows.

## Local report catalog

Implemented local report types:
- CIS_INVENTORY_STORED_SNAPSHOT
- PRODUCT_REFERENCE_READINESS
- DOCUMENT_LIFECYCLE
- TURNOVER_OPERATIONS
- AGGREGATION_OPERATIONS
- EDO_FOUNDATION_STATUS
- SUZ_FOUNDATION_STATUS
- WB_RECONCILIATION_EVIDENCE
- OZON_FOUNDATION_STATUS
- MANUAL_REVIEW_AND_CONFLICTS
- END_TO_END_RECONCILIATION
- P0_IMPORT_CONTROL_QUALITY

Important semantics:
- M1 report explicitly labels its evidence `LATEST_STORED_OBSERVATION`; it is not represented as a live GIS MT refresh.
- M7 report always exposes `M7_FULL_XML_WRITE_BLOCKED`.
- M8 report always exposes `M8_FULL_SUZ_WIRE_BLOCKED`; SUZ KM is not decrypted by default.
- M9 conflicts/manual-review evidence is retained.
- M10 report explicitly says `M10_WIRE_READY=NO` and `M10_EXECUTABLE_READ_CAPABILITIES=NONE`; placeholder foundation rows are never represented as fetched Ozon data.

Reconciliation rows keep separate fields for:
- REMOTE_RAW_STATE
- LOCAL_PROJECT_STATE
- FINAL_RECONCILIATION_RESULT

Local final vocabulary:
- MATCHED
- PENDING_EVIDENCE
- CONFLICT
- MANUAL_REVIEW
- FAILED

Missing evidence is retained as incomplete/manual-review evidence rather than silently omitted.

## Local output formats

Supported:
- CSV UTF-8
- XLSX
- JSON
- ZIP + manifest helper

Generation is iterator/stream based and bounded by configurable row/byte limits.

CSV:
- deterministic schema-version column order
- standards-compliant quoting
- formula-injection protection for `=`, `+`, `-`, `@`, TAB and CR
- Unicode/Cyrillic/newlines preserved
- no silent truncation

XLSX:
- write-only streaming mode
- opaque identifiers and marking-like strings written as TEXT
- leading zeros remain text
- no scientific-notation conversion
- cells exceeding the safe XLSX representation limit fail the format instead of being silently truncated

Timezone:
- offset/Z values stay timezone-aware
- timezone-unknown strings remain raw
- naive datetime representations are explicitly marked `TIMEZONE_UNKNOWN`
- M11 never silently assigns UTC or Moscow time

Normal human reports use masked/fingerprinted marking identifiers. Full marking content is allowed only inside explicitly MARKING_SENSITIVE encrypted artifacts.

## Sensitive artifact storage

Domain interface: `ReportArtifactStore`.

Initial adapter: server-controlled persistent filesystem. The domain does not assume S3, MinIO, AWS, or another object-store vendor.

Sensitive artifacts use `M11_CHUNKED_AES256_GCM_V1`:
- injected key provider
- 256-bit key
- bounded-memory chunk encryption
- unique nonce sequence
- authenticated AAD context
- per-chunk AES-GCM authentication
- authenticated final footer containing total plaintext byte size, plaintext SHA-256 and chunk count
- versioned format

The backend computes authoritative:
- plaintext byte_size
- plaintext SHA-256
- stored metadata
- MIME observation
- storage metadata

Temporary plaintext uses server-generated paths only, restrictive permissions where supported, and deterministic cleanup. An unresolved plaintext temp state can never become READY.

Caller-supplied storage keys/paths and path traversal are rejected.

## True API transport boundary

Production path remains:

backend DB/outbox -> typed durable agent job -> Windows agent -> M3 auth/GOST environment -> CRPT.

There is no direct VPS True API HTTP transport.

Bearer uuidToken remains Windows-process-memory-only. Report jobs themselves do not require a detached document signature.

The Windows transport is guarded by explicit runtime flag `WBCZ_AGENT_TRUE_API_REPORTS_ENABLED`; default is false.

There is no public/generic `execute(method,url,body)`.

## Typed dispenser capabilities

| capability | method | fixed path | limit |
| --- | --- | --- | ---: |
| CREATE_EXPORT | POST | `/api/v3/true-api/dispenser/tasks` | 15/min |
| GET_TASK | GET | `/api/v3/true-api/dispenser/tasks/{taskId}` | 5/min |
| LIST_TASKS | GET | `/api/v3/true-api/dispenser/tasks` | 5/min |
| LIST_RESULTS | GET | `/api/v3/true-api/dispenser/results` | 12/min |
| DOWNLOAD_RESULT | GET | `/api/v3/true-api/dispenser/results/{resultId}/file` | 12/min |
| QUOTA_BY_TASK_TYPE | GET | `/api/v3/true-api/dispenser/tasktypes/available_count` | 10/min |
| QUOTA_BY_REPORT | GET | `/api/v3/true-api/dispenser/tasktypes/reports/{report_id}/available_count` | 10/min |
| REMOTE_RESULT_DELETE | DELETE | `/api/v3/true-api/dispenser/results/{resultId}` | DISABLED |

The rate limiter is executed inside the actual Windows outbound transport immediately before network I/O. Endpoint families share their documented budget. It does not sleep. Local denial carries `retry_after_seconds` to the orchestrator.

## CREATE recipe registry

M11 does not accept arbitrary `params` JSON.

Enabled:
- FILTERED_CIS_REPORT only

Pinned M11 recipe:
- format=CSV
- name=FILTERED_CIS_REPORT
- periodicity=SINGLE
- productGroupCode is an exact positive numeric code represented per current contract
- params is constructed internally as canonical JSON string
- participantInn required
- packageType required
- status required by this deliberately restricted recipe
- includeGtin optional, maximum 1000 values

The official contract permits additional FILTERED_CIS_REPORT filters; M11 does not expose them until a later explicit extension. Requiring `status` is intentionally stricter than the source contract because M11 does not expose the alternative `permitDocIndx` branch.

Disabled with `RECIPE_SCHEMA_NOT_REGISTERED`:
- DOCUMENTS_ERRORS
- CIS_ACS
- ACS_DOCUMENTS
- LP_STOCK_REPORT
- LP_TURNOVER_SALES
- LP_WITHDRAWN_GOODS
- LP_DIRECT_DOCUMENT_ERROR
- LP_OUTGOING_DOCUMENT

REGULAR creation is not exposed.

## Remote task/result lifecycle

Task raw values are preserved exactly:
- PREPARATION
- COMPLETED
- CANCELED
- ARCHIVE
- FAILED

Result availability:
- AVAILABLE
- NOT_AVAILABLE

Download status:
- SUCCESS
- PREPARATION
- FAILED

Unknown future values remain raw and are not mapped to invented business enums.

Flow:
1. durable local remote-report intent is committed before CREATE is queued;
2. REPORT_CREATE executes only from the typed recipe;
3. returned task ID is bound deterministically;
4. PREPARATION schedules a later typed GET_TASK;
5. COMPLETED schedules LIST_RESULTS filtered by task ID;
6. a deterministic AVAILABLE + SUCCESS result prepares a bound binary upload ID;
7. DOWNLOAD_RESULT is allowed only through the typed download job;
8. backend finalizes encrypted artifact metadata;
9. report becomes READY only after a durable READY archive exists.

No task cancellation endpoint is invented.

## Ambiguous CREATE

No CRPT generic idempotency key is assumed.

Windows writes a durable local reservation before the first possible CREATE network I/O. If the process crashes after possible delivery, replay sees an unresolved reservation and blocks another POST.

A network exception is returned as `REMOTE_CREATE_AMBIGUOUS`. The backend records that condition and does not blindly enqueue a second CREATE.

LIST_TASKS may later be used as diagnostic evidence but is not allowed to auto-bind a task without deterministic identity.

## Binary artifact ingress

ZIP bytes are never placed in `agent_jobs.result_json`.

REPORT_DOWNLOAD contains only:
- local_report_job_id
- exact remote result ID
- optional result part ID
- product-group identity
- server-generated opaque artifact_upload_id
- optional expected archive size
- tightly bounded download format metadata

The Windows agent constructs the fixed CRPT download target itself, streams the response to a server-uncontrolled temporary file on Windows, and uploads it only to:
`PUT /api/agent/v1/report-artifacts/{artifact_upload_id}`.

That endpoint:
- is under the existing machine-token agent trust boundary
- uses request streaming, not request.body()
- uses server-generated temporary storage
- accepts no filename or filesystem path
- binds upload ID to exact report job/result/part
- recomputes size/SHA-256 backend-side
- compares CRPT archiveSize when present
- encrypts content before READY publication
- converges an exact same-byte replay
- rejects mismatched or different-byte replay

Normal agent result JSON contains metadata/references only.

## Retention

Remote source retention metadata is persisted per result:
- downloadingStorageDays when observed in control metadata
- fileDeleteDate raw
- parsed fileDeleteDate only when timezone semantics are unambiguous

No universal CRPT retention value is hardcoded.

Local retention policy remains `PROJECT_RETENTION_NOT_FINALIZED`:
- expires_at is nullable
- automatic local deletion is off
- remote expiration never implies local deletion
- remote DELETE remains disabled

## M12/M13/M15 boundaries

M11 does not implement:
- user/browser artifact download
- participant/org roles
- M12 authorization
- M13 security audit platform
- M15 queue/broker/autoscaling/priorities/dead-letter/HA platform

M11 history is operational `report_job_events` only.
