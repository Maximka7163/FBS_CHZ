# M2 reference products contract

Source: official True API v726.0 dated 2026-09-04. This module is read-only.

## Production boundary

Production True API remains Windows-outbound only: backend/VPS -> typed agent job -> Windows agent -> CryptoPro GOST TLS -> `markirovka.crpt.ru`. The backend never receives the True API bearer. No generic HTTP/URL/path/method proxy or arbitrary signer is added. All M1 and M2 True API reads share the existing participant limiter capped at 50 requests/second.

Implemented dynamic contracts:

- `GET /api/v3/true-api/participants`
- `GET /api/v3/true-api/mods/list`
- `POST /api/v4/true-api/tn-ved/search`
- `POST /api/v4/true-api/product/info` — reused from M1, not duplicated
- `GET /api/v4/true-api/product/gtin`
- `POST /api/v4/true-api/rd/list`

`/api/v3/true-api/mods/info` is not used for light-industry MOD validation. Exact `lp` activity-location validation uses `/mods/list`, INN, `productGroups` containing `lp`, optional KPP, and optional FIAS ID. KPP is not invented or made mandatory for an IP flow.

Participant data preserves the documented response. KPP, FIAS, address, organisation type, permissions, and agreements are not invented when `/participants` does not return them. External participant data is not represented as a self extended profile.

`product/info` keeps the accepted M1 absence rule: a requested GTIN missing from `results` is `NOT_RETURNED_BY_PRODUCT_INFO`, not proof that the GTIN does not exist. M2 extends the source-specific product DTO with optional reference fields and preserves additional official group-specific fields in raw data.

Regulatory documents use two separate source contracts: `/rd/list` and optional `certDocList` embedded in `product/info` when `rdInfo=true`. No universal issuer field is invented.

## Static references

Reference source version is `true-api-v726.0`. The registry exposes categories for product groups, CIS base/special statuses, emission types, package types, permit document types, withdrawal reasons, return-reason mapping, participant roles, and participant statuses.

Only rows explicitly available in the accepted M2 research/task context are source-controlled. Categories without the complete accepted official table are exposed with `source_complete=false`; missing rows are not filled from memory or third-party sources. The light-industry product group is exact: numeric ID `1`, code `lp`, name `Лёгкая промышленность`.

Unknown server/reference values are preserved as raw values with `known=false`; no nearest-value coercion, silent remap, or discard is performed.

No official cache TTL is defined by the accepted source and none is claimed or invented here.

## National Catalog

`M2_NK_ADVANCED_SCOPE=DEFERRED`.

Known official endpoints intentionally not implemented in this task:

- `/api/v3/true-api/nk/categories`
- `/api/v3/true-api/nk/brands`
- `/api/v3/true-api/nk/product`
- `/api/v3/true-api/nk/short-product`
- `/api/v3/true-api/nk/feed-product`
- `/api/v3/true-api/nk/etagslist`
- `/api/v3/true-api/nk/attributes`

Reason: advanced NK requires a separate NK authentication/API-key secret boundary and is not needed for the minimal accepted M2 backend. No NK API-key storage is added.
