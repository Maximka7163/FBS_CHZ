# M1 cis_inventory — accepted True API v726.0 read-only contract

Source baseline: application commit `bcb567a8f1e4e9261d68fa800ccc96e76518c596`.
This module is post-P0 and read-only. It does not change the frozen P0 candidate or its write guarantees.

## Transport boundary

Production True API traffic remains Windows-only:

`FastAPI/VPS -> durable typed agent job -> outbound Windows agent -> CryptoPro GOST TLS -> markirovka.crpt.ru`

The VPS has no production True API client, bearer token, private key, PIN, certificate signing capability, arbitrary URL/path/method, or generic HTTP proxy. The Windows agent keeps the True API bearer only in process memory. Existing P0 document signing is unchanged and still restricted to the accepted write types. Production write remains disabled by default.

M1 adds only typed read jobs: `CIS_INFO`, `CIS_SEARCH`, `CIS_HISTORY`, `CIS_AGGREGATED_LIST`, `CIS_AGGREGATION_HISTORY`, `PRODUCT_INFO`, and the typed composite `CIS_TO_PRODUCT`. Each validates its own payload before network I/O.

## Official endpoints

- `POST /api/v3/true-api/cises/info?pg=lp` — root CIS array, 1..1000.
- `POST /api/v4/true-api/cises/search` — filtered discovery. `filter.productGroups` is forced to exactly `["lp"]`.
- `POST /api/v3/true-api/cises/history?cis=<URL-ENCODED-CIS>` — one CIS, no body.
- `POST /api/v3/true-api/cises/aggregated/list?pg=lp` — root CIS array, 1..1000; direct composition layer only.
- `POST /api/v3/true-api/cises/history/list` — body `{ "cis": "..." }`.
- `POST /api/v4/true-api/product/info` — body `{ "gtins": [...], "rdInfo": false }`, 1..1000 GTIN.

Wire DTOs remain source-specific. Normalized domain views are produced only after source parsing, so `cises/info.statusEx/withdrawReason` are not aliased with `cises/search.statusExt/eliminationReason` at the wire boundary.

`cises/info.ownerInn` remains authoritative for workflow owner checks. `cises/search.ownerInn` is discovery metadata only and is explicitly normalized as non-authoritative because the official search contract may return manufacturer INN when actual owner INN is absent.

## Search contract and pagination

Supported v726.0 filter names are preserved exactly. In particular:

- date periods: `emissionDatePeriod`, `applicationDatePeriod`, `productionDatePeriod`, `introducedDatePeriod`, each with only `from`/`to` string keys;
- `states[]`: objects with optional `status`, `statusExt`, `isStatusExtNull`;
- `mods[]`: max 50 objects, keys `kpp`, `fiasId`;
- `tnVed`, `tnVed10`, `prVetDoc`, `partyNumber`, `manufacturerInns`, `importerInns` are strings in the official wire contract;
- `productGroups` must be exactly `["lp"]`.

Pagination accepts explicit `perPage` (1..1000), `lastEmissionDate`, `sgtin`, and `direction` (0/1). The official client-side cursor advancement algorithm is **UNKNOWN**, so M1 does not auto-page or invent a cursor. Search result ceiling is represented as 10,000.

## Known official ambiguities (fail-safe)

1. Search cursor advancement: **UNKNOWN**. No automatic continuation is implemented.
2. Aggregation history documents `AUTODISAGGREGATED` in the table and `AUTODISAGGREGATION` in an official example. Both raw values are accepted and normalized separately to the same semantic value; unknown future values remain raw and unclassified.
3. Aggregation history `operationDate` is documented inconsistently. M1 treats it as optional/nullable.

These are accepted research ambiguities and are not guessed around.

## Product enrichment

`CIS_TO_PRODUCT` performs typed `CIS_INFO` first, deduplicates returned GTINs, then issues typed `PRODUCT_INFO` batches (at most 1000). Current CIS state always comes from `cises/info`; product data is enrichment only.

The official product endpoint returns only cards with `goodTurnFlag=true` and `goodMarkFlag=true`. Therefore an omitted requested GTIN is normalized as `NOT_RETURNED_BY_PRODUCT_INFO`; no nonexistent-product reason is invented.

## Errors and rate limiting

HTTP success plus item-level `cises/info` errors is supported without hiding successful sibling items. Transport failures are represented with HTTP status, content type, safe code/message, and SHA-256 of the body. JSON, XML/text, and empty HTTP 406 are handled; bounded text diagnostics redact bearer/token/PIN-like values.

A single Windows transport rate limiter is shared by P0 and M1 True API calls and caps calls to 50 requests/second. Its clock/sleeper are injectable for deterministic tests.

## Persistence and application API

The existing PostgreSQL agent outbox persists M1 jobs and sanitized results across backend restarts. Local result snapshots contain fetch metadata and are not treated as an alternative registry; official True API remains source of truth.

Authenticated same-origin application endpoints queue asynchronous reads and return request IDs. Result retrieval reports `pending`, `running`, `completed`, or `failed`. Browser routes never expose `/api/agent/*` as business API.
