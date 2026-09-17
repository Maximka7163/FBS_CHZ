# M4 document lifecycle contract

Source of truth: official True API v726.0 dated 2026-09-04 and accepted M4-DOCUMENTS-RESEARCH-001.

## Scope

M4 adds a general typed read/lifecycle layer around the accepted P0/M3 create/sign/poll stack. It does not replace or redesign authentication, detached document signing, the Windows outbound agent, CryptoPro/GOST transport, typed create, or P0 polling.

Production True API remains Windows-agent only. The VPS never becomes a generic True API client or signing proxy.

## Official read operations

- `GET /api/v4/true-api/doc/list`
- `GET /api/v4/true-api/doc/{docId}/info`
- `GET /api/v3/true-api/doc/cises`

All are represented as typed agent jobs. The caller cannot supply an arbitrary method, host, path, certificate, signing algorithm, or True API bearer.

### Document list

M4 supports the documented v726.0 filter set used by this product: `pg`, `dateFrom`, `dateTo`, `did`, `documentFormat`, `documentStatus`, repeated `documentType`, `limit`, `number`, `order`, `orderedColumnValue`, `pageDir`, `senderInn`, `receiverInn`.

Local `document_id` is the only document-list identifier alias and maps only to official `did`. `operation` and `page` aliases are rejected. Official `number`, `orderedColumnValue`, and `pageDir` remain distinct documented filters and are never synthesized from those removed aliases.

`pg` is fixed to `lp`. `senderInn` and `receiverInn` are not accepted together. M4 does not invent the officially inconsistent rule that one of them must always be present.

### Document info

M4 can request `body` and `content` and preserves documented metadata, raw status, `errors[]`, and `commonErrors[]`. Generic operations history, attachments, detached-signature download, and generic receipts are not documented by the generic API and are not emitted by the generic document-info parser.

### Document CIS list

`GET /api/v3/true-api/doc/cises` is typed with `documentId` and `productGroup=lp`. A local `write_operation_id` may resolve to an already confirmed remote document id; it is not sent to True API.

## Registries

`DocumentFormatRegistry`: `MANUAL`, `XML`, `CSV` for Unified Create. `/doc/list` additionally accepts the documented filter category `UPD`.

`DocumentTypeRegistry`: the accepted §4.1 v726.0 create/view type list. JSON document types are represented by Unified Create `document_format=MANUAL`. Product-group applicability is not inferred from the type code.

`DocumentStatusRegistry`: preserves raw values. For current direct P0 documents only:

- `IN_PROGRESS`, `WAIT_FOR_CONTINUATION` -> intermediate
- `CHECKED_OK` -> success class
- `CHECKED_NOT_OK`, `PARSE_ERROR`, `PROCESSING_ERROR` -> failure class
- `UNDEFINED` and unknown future values -> unknown/manual-review class

`CANCELLED` and the separately documented `CANCELED` spelling are both preserved raw. Shipment-only statuses are not globally reclassified as direct-document success/failure.

## Processing errors

`errors[]` are preserved as raw strings. `commonErrors[]` preserves `errorCode`, `errorMessage`, and `errorObject`. `commonErrors.errorCode` is an arbitrary raw string because v726.0 is internally inconsistent (`ERROR_<number>` vs `INTRO_ERROR`). M4 introduces no local processing-error normalization enum.

## Local audit and idempotency

The existing PostgreSQL `agent_jobs` durable outbox is the M4 request ledger, with `audit_log` entries for lifecycle queue/replay events. M4 computes an immutable request-body SHA-256 over the canonical typed local request.

Idempotency key: `operation_id + ':' + request_body_sha256`.

A duplicate `operation_id` with the identical request is an idempotent replay and returns the existing request. The same `operation_id` with a different job type or body fails closed with `AgentReplayConflict`. Content hash alone is never treated as universal server-side deduplication.

## Create uncertainty and reconciliation

Unified Create success body schema is still officially undocumented. M4 does not invent `response['docId']`, `documentId`, or `id`. The accepted P0 parser remains isolated. A 200/201 without a safely extracted remote id remains `MANUAL_REVIEW`; ambiguous transport/server outcomes are not blindly resubmitted.

M4 includes a raw success-response capture helper for runtime evidence without redefining the P0 create parser.

## Deferred capabilities

Explicit stubs only:

- EDO `/document/reprocess`
- EDO processing receipts/history
- `/doc/validator/*`
- business-specific FNS register behavior
- operator-specific reconciliation

There is no generic `retry(documentId)`, `cancel(documentId)`, `delete(documentId)`, or arbitrary True API request API in M4.

## Runtime-only acceptance

Static/CI acceptance does not claim real production processing latency, polling cadence, undocumented future status values, exact production `commonErrors.errorCode` variants, duplicate handling by CRPT, participant visibility nuances, or the actual Unified Create success envelope. These remain runtime evidence. Polling cadence and timeout stay backend policy under the shared 50 req/s/UOT limit.
