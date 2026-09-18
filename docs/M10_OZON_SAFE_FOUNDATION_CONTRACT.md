# M10 Ozon safe foundation contract

Accepted research:
- `M10-OZON-FBS-RESEARCH-001`
- `M10-OZON-FBS-RESEARCH-001-FIX-01`

Architect boundary:
- `M10_WIRE_READY=NO`
- `M10_EXECUTABLE_READ_CAPABILITIES=NONE`
- safe backend foundation only
- no executable Ozon HTTP reads or writes
- no guessed request/response DTO, pagination, cursor semantics, status enums, marking wire format, payment semantics, return semantics or seller-INN mapping
- frontend freeze remains active

M9 remains accepted and unchanged at `c0fed29533d4522d12015e15bfa2a15e9ff73002`. M7 full XML and M8 full SUZ wire blockers remain independent.

## Hard runtime/security gates

- `PRODUCTION_OZON_WRITE_ENABLED=NO`
- `OZON_INN_AUTOBIND_ENABLED=NO`
- `OZON_API_CIS_AUTOBIND_ENABLED=NO`
- `MARK_VALUE_EXTRACTION_ENABLED=NO`
- `PAYMENT_CONFIRMATION_CONTRACT_PINNED=NO`
- `PAID_SOURCE_PINNED=NO`
- `PHYSICAL_SELLER_RETURN_CONTRACT_PINNED=NO`
- `AUTO_DISTANCE_READY_ENABLED=NO`
- `AUTO_REMOTE_SALE_RETURN_READY_ENABLED=NO`
- `TRUE_API_WRITE_FROM_M10=NO`
- no production deploy or migration apply
- no real Ozon credentials/calls
- no CryptoPro/Rutoken/PIN action

## Known host and authentication facts

Current accepted production host metadata:
- `api-seller.ozon.ru`

Canonical header names are modeled only as local policy:
- `Client-Id`
- `Api-Key`
- `Content-Type: application/json`

There is no Ozon HTTP adapter or executable transport in M10. Callers cannot supply URL, host, path, HTTP method, Client-Id header, Api-Key header, Authorization header, arbitrary headers or arbitrary remote JSON body.

`Client-Id` may be persisted exactly. Api-Key plaintext is memory-only and loaded by an injected secret provider through `api_key_secret_ref`. Repr/str redact the secret. PostgreSQL contains no Api-Key plaintext/auth header field.

Explicit `api_key_expires_at` metadata may be persisted when supplied by trusted configuration/future accepted evidence. M10 never derives an existing key's expiry as creation time plus three months.

Participant INN is explicit local configuration. M10 does not infer legal identity from Client-Id, offer_id, SKU, barcode, posting_number, CIS or warehouse. `/v1/seller/info` and `/v1/roles` are not executable.

## Disabled typed capability registry

Every current capability is metadata-only and disabled:

| Capability | Method | Path | Enabled | Contract pinned | Rate profile pinned |
| --- | --- | --- | --- | --- | --- |
| FBS_LIST | POST | `/v4/posting/fbs/list` | NO | NO | NO |
| FBS_UNFULFILLED | POST | `/v4/posting/fbs/unfulfilled/list` | NO | NO | NO |
| FBS_GET | POST | `/v3/posting/fbs/get` | NO | NO | NO |
| EXEMPLAR_STATUS | POST | `/v5/fbs/posting/product/exemplar/status` | NO | NO | NO |
| RETURNS_LIST | POST | `/v1/returns/list` | NO | NO | NO |
| SELLER_INFO | POST | `/v1/seller/info` | NO | NO | NO |
| ROLES | POST | `/v1/roles` | NO | NO | NO |
| WAREHOUSE_LIST | POST | `/v2/warehouse/list` | NO | NO | NO |

For all eight:
- `request_contract=None`
- `response_contract=None`
- `pagination_contract=None`
- `endpoint_rate_limit=None`
- disabled reason `OFFICIAL_CONTRACT_NOT_PINNED`

A local `require_enabled()` guard always fails closed. There is no generic proxy and no network adapter to bypass the guard.

Deprecated/forbidden paths are not implemented:
- `/v3/posting/fbs/list`
- `/v3/posting/fbs/unfulfilled/list`
- `/v3/finance/transaction/list`
- `/v3/finance/transaction/totals`
- exemplar creation/set/validate/update mutations
- ship/package/cancel/return/notification mutations

## Rate-limit foundation

Accepted schema-independent global contract:
- `GLOBAL_OZON_LIMIT=50 requests/second per Client ID`

M10 provides only a local rolling one-second admission primitive keyed by exact Client-Id. Different Client IDs have independent state.

It does not invent:
- a separate burst capacity
- endpoint-specific rates
- endpoint rate profiles
- Retry-After guarantees

The limiter is intentionally not connected to any outbound Ozon transport because executable remote capabilities are zero.

## Opaque identity

Remote identifiers are stored independently as opaque strings:
- posting_number
- order-related opaque ID
- product_id
- offer_id
- sku
- barcode
- warehouse_id
- delivery_method_id
- exemplar_id
- return_id
- report_id
- finance identifier

M10 never assumes:
- SKU == product_id
- posting_number == order ID
- exemplar_id == CIS
- CIS from GTIN/barcode/SKU/offer_id

Case and exact source representation are preserved.

## Source provenance

Schema-independent local evidence records carry:
- connection_id
- source capability
- source fingerprint
- observed_at
- opaque remote identities
- sanitized raw hash
- evidence hash
- local evidence type
- conflict state

No newest-wins rule exists. Future unknown raw statuses/enums must be retained as raw evidence rather than coerced into invented enums.

## Recursive Ozon sanitizer

All future arbitrary Ozon evidence must pass the recursive sanitizer before raw/audit/error persistence.

It handles:
- Mapping
- list
- tuple
- arbitrary nested combinations
- direct keys such as sgtin/cis/kiz/mark/marks/marking/markingCode
- discriminator forms such as `{key/type/kind: sgtin, value/values/data/...}`
- nested product -> exemplar -> marks structures
- secret keys including Api-Key/auth/token/private-key style fields

Sensitive marking payloads are replaced with `REDACTED`. Non-sensitive future metadata is preserved recursively.

Full marking/API-key values must never survive in raw_sanitized, errors, events, audit summaries, repr, logs or telemetry.

## Ozon-specific marking vault

M10 has a separate Ozon AES-256-GCM vault. It does not use WB persistence tables and does not directly reuse M8 KM tables.

Key provider is injected. Production key material is not hardcoded.

The envelope persists:
- ciphertext
- nonce
- auth tag
- key version
- vault format
- AAD hash
- plaintext SHA-256 fingerprint
- ciphertext SHA-256 fingerprint
- masked representation
- source capability
- posting/item/exemplar linkage through local persistence

No plaintext CIS/KIZ/SGTIN column exists.

Exact future source marking evidence is immutable:
1. hash exact source representation
2. encrypt exact source representation
3. never strip GS/control separators
4. never strip crypto tail
5. never rebuild from GTIN + serial
6. never normalize control characters
7. never derive from SKU/barcode/offer_id

Because the wire contract is unpinned, M10 performs no CIS extraction.

## Sync checkpoint foundation

`OzonSyncCheckpoint` and `ozon_sync_cursors` store only opaque/local checkpoint slots:
- connection_id
- feed/capability
- cycle_id
- cursor_opaque
- offset_opaque
- raw window boundaries
- snapshot_opaque
- last success/attempt times
- redacted error
- generation

M10 does not encode v4 FBS pagination, returns pagination, warehouse cursor semantics, limits, date windows, sort order or terminal has_next semantics.

## Local reconciliation states

The following are project-local states, not Ozon wire enums:
- OZON_ORDER_DISCOVERED
- OZON_CIS_MISSING
- OZON_CIS_CAPTURED
- OZON_CIS_VERIFIED
- OZON_SALE_PENDING
- OZON_DELIVERY_CONFIRMED
- OZON_PAYMENT_PENDING
- OZON_SALE_CONFIRMED
- DISTANCE_PENDING
- DISTANCE_SUBMITTED
- DISTANCE_RECONCILED
- OZON_RETURN_PENDING
- OZON_ITEM_RETURNED
- REMOTE_RETURN_PENDING
- REMOTE_RETURN_RECONCILED
- CANCELLED_NO_ACTION
- MANUAL_REVIEW

No Ozon raw status mapping is authorized in this foundation.

## Payment and return safety

Payment confirmation and authoritative customer-paid amount contracts are unpinned. Seller payout, accrual, commission-adjusted amount, net proceeds or logistics compensation are never labeled as customer-paid amount.

Payment evidence, delivery-like evidence or a paid-amount candidate can only remain `WAIT_FOR_EVIDENCE` unless a conflict requires `MANUAL_REVIEW`. Automatic `DISTANCE_READY` is impossible.

Physical seller-return semantics are also unpinned. Refund, Ozon warehouse receipt, compensation or a return report row are not treated as seller physical receipt. Return/refund evidence remains `WAIT_FOR_EVIDENCE` or `MANUAL_REVIEW`. Automatic `REMOTE_SALE_RETURN_READY` is impossible.

## M1 / M2 / M4 / M5 / M6 boundaries

M10 defines interfaces only:
- M1 fresh CIS-state evidence adapter
- M2 product/GTIN/product-group/participant evidence adapter
- M4 operation/reconciliation reference adapter
- M5 typed local reference for DISTANCE / REMOTE_SALE_RETURN
- M6 aggregate relation adapter

Aggregate ambiguity is manual review. M10 does not flatten KIK/KIN/KITU.

Automatic M5 handoff from Ozon evidence is explicitly disabled. There is no M5 document assembly, True API call, Windows/CryptoPro action or submission.

## Persistence

Additive migration:
- `0011_m10_ozon`
- down revision `0010_m9_wb`

Schema-independent tables:
- ozon_connections
- ozon_postings
- ozon_items
- ozon_marking_bindings
- ozon_events
- ozon_returns
- ozon_sync_cursors
- ozon_reconciliation
- ozon_paid_evidence

Historical migrations are unchanged.

## What is required to unlock executable reads

A future architect-approved research update must pin official current OpenAPI/contracts for each capability before it may become executable. At minimum, the relevant endpoint needs:
- exact official request schema
- exact official response schema
- exact pagination/cursor/window semantics where applicable
- endpoint-specific rate profile or explicit accepted fallback contract
- status/substatus semantics when used for decisions
- marking field shape/format before extraction/binding
- seller identity contract before INN verification/autobind
- payment semantics before sale/payment confirmation
- physical seller-return semantics before return automation

Until those contracts are pinned, `M10_WIRE_READY=NO` and `M10_EXECUTABLE_READ_CAPABILITIES=NONE`.
