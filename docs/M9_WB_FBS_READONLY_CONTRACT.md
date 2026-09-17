# M9 WB FBS read-only backend contract

Accepted research:
- `M9-WB-FBS-RESEARCH-001-TAKEOVER-02B`
- `M9-WB-FBS-RESEARCH-001-TAKEOVER-02B-FIX-01`

M9 is implemented as **read-only official WB evidence ingestion + source-preserving normalization + FBS reconciliation + fail-closed M1/M2/M5/M6 decision foundation**.

Hard runtime gates:

- `PRODUCTION_WB_WRITE_ENABLED=NO`
- `AUTO_DISTANCE_READY_ENABLED=NO`
- `PAID_SOURCE_CONTRACT_PINNED=NO`
- `WB_API_SGTIN_AUTOBIND_ENABLED=NO`
- no True API submission
- no CryptoPro / certificate / Rutoken / PIN operation
- no production deployment or production migration apply
- frontend freeze remains active
- M10 is not started

## WB transport and authentication

WB uses ordinary backend HTTPS. It is not routed through the Windows/CryptoPro agent.

The typed transport exposes only the accepted read capabilities. Callers cannot select a host, URL, path, HTTP method, Authorization header, arbitrary header set or raw HTTP body.

Production hosts:

- `marketplace-api.wildberries.ru`
- `seller-analytics-api.wildberries.ru`
- `statistics-api.wildberries.ru`
- `common-api.wildberries.ru`

Sandbox hosts are used only where the accepted capability says sandbox is supported:

- `marketplace-api-sandbox.wildberries.ru`
- `statistics-api-sandbox.wildberries.ru`

Authorization is constructed internally as:

`Authorization: <WB API TOKEN>`

There is no Bearer prefix.

Runtime token secret is supplied by an injected secret provider. PostgreSQL stores only `secret_ref`, token type/categories/scopes, expiry metadata and connection metadata. Token repr/str is redacted. Raw WB token is never persisted.

Production self-integration defaults to `PERSONAL`. `TEST` is sandbox-only. `SERVICE`, `BASE` and `BASE_WITH_SECRET` are modeled but not silently substituted for `PERSONAL`.

Seller identity verification uses only:

`GET https://common-api.wildberries.ru/api/v1/seller-info`

Configured participant INN must equal returned WB `tin`. A mismatch sets local `CONNECTION_BLOCKED` and requires manual review. Order/article/barcode/warehouse/CIS values are never used to infer seller identity.

## Exact M9 read allowlist

Marketplace:

- GET `/api/v3/orders/new`
- GET `/api/v3/orders`
- GET `/api/marketplace/v3/fbs/orders/archive`
- POST `/api/v3/orders/status`
- POST `/api/marketplace/v3/orders/meta`
- GET `/api/v3/supplies`
- GET `/api/v3/supplies/{supplyId}`
- GET `/api/marketplace/v3/supplies/{supplyId}/order-ids`

Analytics:

- POST `/api/analytics/v1/order-feed`
- GET `/api/v1/analytics/goods-return`

Common:

- GET `/api/v1/seller-info`

Statistics compatibility:

- GET `/api/v1/supplier/sales`

`/api/v1/supplier/orders` is not a mandatory dependency.

All WB mutation capabilities are disabled with `M9_READ_ONLY_SCOPE`. There is no generic WB proxy.

## Rate limits

Rate limiting is enforced inside the typed outbound transport before every adapter call. It is keyed by endpoint family, token type and credential `secret_ref`; denied admission never reaches the HTTP adapter. There is no single global WB limiter.

Marketplace FBS production:
- 300/minute
- 200 ms interval
- burst 20
- documented Marketplace 4XX accounting uses weight 10

Marketplace sandbox:
- maximum 1 request/second globally across Marketplace methods

Order Feed:
- PERSONAL: 1/minute, burst 1
- SERVICE: 1/minute, burst 1
- BASE_WITH_SECRET: 1/minute, burst 1
- BASE: 1/3 hours, burst 1

Supplier Sales:
- PERSONAL: 1/minute, burst 1
- SERVICE: 1/minute, burst 1
- BASE_WITH_SECRET: 1/minute, burst 1
- BASE: 1/2 hours, burst 1

Goods Return:
- PERSONAL/SERVICE/BASE_WITH_SECRET: 1/minute, burst 10
- BASE: 2/hour, 30-minute interval, burst 1

Seller Info:
- 1/minute, burst 10

BASE never inherits PERSONAL limits. Marketplace 4XX×10 is not generalized to other endpoint families. `Retry-After`, when present, may be honored; it is not assumed to be guaranteed.

## FBS order identity

Canonical local Marketplace FBS identity is:

`(connection_id, assembly_order_id)`

Assembly order ID is stored as BigInteger-compatible integer.

The following are retained independently:

- orderUid
- rid
- srid
- nmId
- chrtId
- article
- SKU/barcode evidence
- warehouseId
- officeId
- supplyId
- stickerId

There is no `rid == srid` assumption. No value is derived from the other. Order Feed may contain `srid` without Marketplace assembly ID/rid; equality alone is not a cross-family join rule.

## Current and archive synchronization

Current FBS uses `GET /api/v3/orders`.

Request contract represented locally:
- `limit` 1..1000
- initial `next=0`
- subsequent cursor from response `next`
- `dateFrom/dateTo` as Unix UTC timestamps
- max request window 30 days

The current-order source is treated as recent-domain evidence, not infinite history.

Archive uses production `GET /api/marketplace/v3/fbs/orders/archive`:
- production support: YES
- sandbox support: NOT_DOCUMENTED / DISABLED
- no archive call is mapped to the Marketplace sandbox host
- year required
- month 1..12
- initial `next=0`
- limit 100..1000
- durable year/month/next cursor

There is deliberately no atomic three-month handoff. Transition overlap/recheck remains required because orders can reach archive later after the containing supply finishes. Current disappearance is not cancellation. Archive absence is not deletion. Current/archive conflict is evidence conflict, never newest-wins overwrite.

Cursor advancement happens only after durable evidence commit.

## Order Feed primary sync

Order Feed is the primary Analytics evidence source:

`POST https://seller-analytics-api.wildberries.ru/api/analytics/v1/order-feed`

Maximum selected period: 31 days.

The foundation models:
- selectedPeriod
- nmIds
- subjectIds
- brandNames
- tagIds
- pagination.snapshotTime
- pagination.offset
- pagination.limit when explicitly configured

No undocumented maximum `limit` is invented.

Cycle recovery:
1. open bounded selectedPeriod
2. first response establishes authoritative `snapshotTime`
3. persist cycle identity
4. continue with same snapshotTime and next offset
5. persist page evidence transactionally
6. commit offset only after durable page commit
7. crash before commit replays the same page and deduplicates by evidence fingerprint
8. invalid snapshot restarts the bounded window with a new cycle and overlap deduplication

There is no createdAt-only watermark.

Only currently source-confirmed raw Order Feed values are marked known:
- status: `cancel`
- cancelType: `app`

All unknown status/cancelType values remain exact raw strings and never crash sync. The foundation does not invent `created`, `buyout`, `return` or `returnDefective` as official wire enums.

## Supplier Sales compatibility role

`GET /api/v1/supplier/sales` remains isolated as:

`TEMPORARY_PAYMENT_CONFIRMATION_COMPATIBILITY_EVIDENCE`

The endpoint is modeled as:
- currently callable
- future shutdown announced

For `flag=0`, the next incremental `dateFrom` is the last row's exact `lastChangeDate`.

A matching Sales row is only payment-confirmation evidence. It is not authoritative final finance amount. Core M9 architecture does not depend on this source and can remove it later without changing order identity/reconciliation.

## Paid amount hard gate

Current accepted research does not pin a sufficiently authoritative automatic M5 DISTANCE paid amount source.

Candidate monetary values from:
- Marketplace FBS
- Order Feed `sellerPrice`
- Supplier Sales

are persisted only as evidence with source, raw amount, currency, scale, observation time and contract status.

`forPay`, seller payout, commission and net proceeds are not treated as customer-paid amount.

While:
- `PAID_SOURCE_CONTRACT_PINNED=false`
- `AUTO_DISTANCE_READY_ENABLED=false`

`DISTANCE_READY` cannot be emitted automatically. Even sold + matching Supplier Sales remains `WAIT_FOR_EVIDENCE`.

## Marketplace status and metadata

Marketplace status keeps:
- `supplierStatus`
- `wbStatus`
- `isCancellable`
- unknown future raw fields

Marketplace status is never converted into Order Feed status. `wbStatus=sold` is sale workflow evidence only and cannot independently produce DISTANCE readiness.

Metadata read is:

`POST /api/marketplace/v3/orders/meta`

The current surface is `metaDetails`. Deprecated legacy `meta` is not required and never controls a business decision.

Because the nested `metaDetails` SGTIN contract is not fully pinned:
- `metaDetails` mappings, lists, tuples and arbitrary nested combinations are recursively sanitized
- direct marking fields such as `sgtin`, `cis`, `kiz`, `markingCode` are redacted
- discriminator-style metadata such as `{key/type: sgtin, value/values/data/...}` redacts the associated marking payload
- non-sensitive unknown metadata remains preserved
- exact marking values are routed only to encrypted marking evidence storage, never `raw_sanitized`
- unknown statuses/decisions are preserved
- `WB_API_SGTIN_AUTOBIND_ENABLED=false`

No deterministic CIS binding is created solely from incompletely understood metadata.

## Marking evidence and CIS cardinality

Exact received SGTIN/CIS evidence is immutable. Control separators, GS and crypto tail are not stripped or reconstructed before evidence hashing/encryption.

M9 has its own AES-256-GCM marking vault. It does not reuse M8 KM persistence automatically.

PostgreSQL stores:
- ciphertext
- nonce/tag
- key version
- AAD hash
- SHA-256 fingerprint
- masked representation
- source
- observation time
- validation state
- conflict state
- order linkage

No plaintext CIS/SGTIN/KIZ column exists. Production key material is not hardcoded. Full marking values never appear in repr, logs, error messages or audit summaries.

There is no invariant `1 WB order = 1 CIS`.

Fail-closed cardinality:
- zero CIS → `WAIT_FOR_EVIDENCE`
- one deterministic M1-validated CIS → `CIS_PREFLIGHT`
- unexplained one CIS → `MANUAL_REVIEW`
- multiple candidates → `MANUAL_REVIEW`
- same CIS on multiple live orders → `MANUAL_REVIEW`

## Goods Return and physical return gate

Goods Return uses:

`GET https://seller-analytics-api.wildberries.ru/api/v1/analytics/goods-return`

Maximum date window: 31 days.

Evidence keeps orderId, srid, barcode, nmId, sticker/shk identifiers, readyToReturnDt, completedDt, raw return status/type and raw timestamps.

`completedDt` is the physical-return gate. Order Feed return-like state alone and `readyToReturnDt` alone remain `WAIT_FOR_EVIDENCE`.

Timezone-less Goods Return timestamps are never silently assigned UTC. Raw strings are persisted and parsed into aware timestamps only when an explicit offset is present.

A local `REMOTE_SALE_RETURN_READY` decision requires all of:
- previous accepted DISTANCE relation exists/reconciled
- `completedDt` exists
- deterministic returned CIS mapping
- fresh M1 read
- M1 status/statusEx/withdrawal reason compatible with accepted M5 return
- M2 lp product evidence passes
- M6 relation does not make the individual operation ambiguous
- no duplicate completed M5 return
- source identities do not conflict

M9 never submits the M5 operation.

## Multi-source provenance and XLSX compatibility

Every normalized evidence object retains source:
- `WB_API`
- `WB_XLSX`

along with fingerprint, observed time, source hash/reference and connection identity.

Conflict rules are fail closed:
- same order + same CIS → merge provenance; M1 still required
- same order + different CIS → `MANUAL_REVIEW`
- API missing CIS + XLSX CIS → XLSX remains compatibility evidence; M1 required
- different nmId/chrtId/barcode/GTIN → `MANUAL_REVIEW` unless a deterministic relation is independently proven
- sale/return evidence conflicts → WAIT/MANUAL

No newest-wins logic exists.

The accepted P0 XLSX parser/control logic is unchanged. M9 adds only a source-neutral compatibility adapter.

## M1 / M2 / M5 / M6 boundaries

M1 remains authoritative for fresh CIS owner/status/statusEx/history/current state.

M2 remains authoritative for product GTIN/product group/participant evidence.

M6 remains authoritative for aggregate parent/child relations. KIK/KIN/KITU are not flattened by M9. Aggregate ambiguity is `MANUAL_REVIEW`.

M9 may only prepare typed local M5 decisions for:
- DISTANCE
- REMOTE_SALE_RETURN

M9 does not duplicate document assembly, call True API directly, invoke Windows/CryptoPro, or submit anything.

## Persistence

Additive migration:
- `0010_m9_wb`
- down revision `0009_m8_suz`

Tables:
- `wb_connections`
- `wb_orders`
- `wb_marking_bindings`
- `wb_events`
- `wb_returns`
- `wb_sync_cursors`
- `wb_reconciliation`
- `wb_paid_evidence`

Historical migrations are not modified.

M7 full XML write remains independently blocked on pinned official XSD artifacts. M8 full SUZ wire remains independently blocked on official core SUZ artifacts.


## First-run backfill policy

First-run history depth is explicit project configuration, not a claim of infinite WB retention.

The foundation models configurable horizons and splits current-FBS history into request windows of at most 30 days. Order Feed first-run horizon is capped at its current 31-day source domain. Supplier Sales compatibility backfill does not assume more than the currently guaranteed ~90-day storage window. Archive backfill is configured by explicit year/month and uses its own pagination/overlap policy.

Goods Return uses independent date windows of at most 31 days. A larger project horizon is represented as multiple bounded windows; this does not upgrade any undocumented remote retention guarantee.

The sync-feed registry is source-specific:
- FBS_CURRENT
- FBS_ARCHIVE
- ORDER_FEED
- METADATA
- GOODS_RETURN
- SUPPLIER_SALES_COMPAT

Each feed keeps independent durable cursor/cycle evidence.

## Local M5 decision handoff

M9 defines a typed local M5 decision request containing only local order identity and evidence fingerprints. It has no URL, HTTP transport, WB/True API token, document serialization or signing operation.

Only M9 decisions already in `DISTANCE_READY` or `REMOTE_SALE_RETURN_READY` can be converted into that local handoff. Since the paid-source gate is currently false, normal automatic DISTANCE cannot reach the former state.
