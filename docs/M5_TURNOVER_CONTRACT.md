# M5 Turnover Contract

Source: True API v726.0 dated 2026-09-04 and accepted `M5-TURNOVER-RESEARCH-001`.

This milestone hardens the accepted P0 sale/return path and adds typed turnover operations for product group `lp`. It does not replace the accepted M1-M4/P0 architecture.

## Architecture boundaries

- VPS/backend prepares exact approved business-document bytes, performs typed validation, persists ledger/audit state and orchestrates reconciliation.
- Windows outbound agent signs the exact approved bytes and performs production GOST transport.
- UKEP private key, PIN and True API bearer token remain Windows-side.
- Production write is disabled by default and remains controlled by the existing accepted switch.
- No generic True API URL/path/method/body proxy exists.
- No arbitrary signer exists.
- No universal `genericTurnover(arbitraryJson)` exists.
- No generic retry/cancel/delete API exists.

## Operation registry

| Business operation | Official document type | Format | lp | Notes |
|---|---|---|---|---|
| INTRODUCE_DOMESTIC | LP_INTRODUCE_GOODS | MANUAL | yes | own production typed flow |
| INTRODUCE_FROM_INDIVIDUAL | LK_INDI_COMMISSIONING | MANUAL | yes | individual commissioning typed flow |
| INTRODUCE_IMPORT_PRE_MANDATORY | LP_GOODS_IMPORT | MANUAL | yes | only the documented pre-mandatory import scenario |
| INTRODUCE_EAEU | CROSSBORDER | MANUAL | yes | EAEU introduction typed flow |
| INTRODUCE_REMAINS | LP_INTRODUCE_OST | MANUAL | yes | REMAINS only, never fallback |
| INTRODUCE_CONTRACT | LK_CONTRACT_COMMISSIONING | MANUAL | yes | producer/owner distinction retained |
| INTRODUCE_FTS | LP_FTS_INTRODUCE | MANUAL | yes | normal FTS introduction path |
| WITHDRAW | LK_RECEIPT | MANUAL | yes | reference-only; not executable because exact reason-specific wire contracts beyond DISTANCE are unavailable |
| WITHDRAW_DISTANCE | LK_RECEIPT | MANUAL | yes | executable confirmed DISTANCE contract |
| RETURN_TO_CIRCULATION / RETURN_REMOTE_SALE | LP_RETURN | MANUAL | yes | general return remains matrix-gated; remote sale exact flow implemented |
| REMARK | LK_REMARK | MANUAL | yes | no SUZ/code ordering |
| WRITE_OFF | WRITE_OFF | MANUAL | yes | separate typed schema |
| CANCEL_WITHDRAWAL | LK_RECEIPT_CANCEL | MANUAL | yes | typed inverse only for eligible LK_RECEIPT |

The caller chooses a known `operation_kind`; the caller does not choose an arbitrary document type.

## Explicit fail-closed capabilities

`LK_UNIVERSAL_INTRODUCE` is not exposed for `lp` in M5.

`LP_FTS_INTRODUCE_AUTO` is system-generated and is not exposed as a normal client submit operation.

`LP_CANCEL_SHIPMENT` remains known in the official registry but is not a broad generic `lp` cancellation capability. A production assembler is not exposed without a known eligible source shipment subtype. Local capability state is `SOURCE_DOCUMENT_REQUIRED`.

Direct EAEU shipment/acceptance is deferred because the accepted implementation handoff did not include the complete exact wire contract required by the fail-closed rule:

- `EAEU_DIRECT_SUBFLOW_IMPLEMENTED=NO`
- `EAEU_DIRECT_SUBFLOW_DEFER_REASON=EXACT_WIRE_CONTRACT_NOT_PRESENT`

No domestic `LP_SHIP_GOODS` substitute is invented for ordinary clothing.

## P0 DISTANCE hardening

Existing mapping remains `WB FBS Sale -> LK_RECEIPT -> action=DISTANCE`.

M5 rules:

- `inn` required.
- `action` exact `DISTANCE`.
- `action_date` required and validated using the accepted v726 date range.
- products non-empty and CIS unique.
- `products[].cis` required.
- `products[].product_cost` required for DISTANCE; stored on wire as integer kopecks within the official numeric range.
- MOD location required for the `lp` DISTANCE path.
- `fias_id` must be UUID.
- `kpp` is legal-entity-only and required for legal-entity MOD.
- primary document is optional for DISTANCE, but if supplied its type/number/date/custom-name tuple is validated source-specifically.
- forbidden/non-applicable fields are not synthesized: buyer INN, `withdrawal_type_other`, `state_contract_id`, WB sticker/job IDs, fiscal-drive fields, currency, synthetic `paid`, synthetic VAT amount.

The accepted Sellari owner check is retained as `OUR_BACKEND_POLICY`; it is not documented as a universal CRPT `ownerInn == sellerInn` rule for every LK_RECEIPT operation.

DISTANCE business success is two-stage: document `CHECKED_OK` and fresh M1 CIS reconciliation to `RETIRED` with raw `withdrawReason=DISTANCE`.

Generic `WITHDRAW` is deliberately non-executable in M5. The accepted research did not provide implementation-ready reason-specific LK_RECEIPT wire contracts beyond DISTANCE, so generic WITHDRAW cannot silently reuse DISTANCE semantics.

## REMOTE_SALE_RETURN hardening

Existing mapping remains `WB FBS Return -> LP_RETURN -> REMOTE_SALE_RETURN`.

- `trade_participant_inn` required.
- `return_type` exact `REMOTE_SALE_RETURN` for the implemented M5 assembler.
- `paid` must resolve explicitly at root or item level. `products_list[].paid` is an optional item override and has priority over root `paid`. It is never defaulted or inferred.
- `state_contract_id` is absent.
- `products_list` is non-empty and `products_list[].ki` is unique.
- fresh precondition state: `RETIRED`, no special state, participant owns the code, prior raw withdrawal reason is `DISTANCE` or `BY_SAMPLES`.
- effective `paid=true` requires the exact effective primary-document tuple. Item primary-document fields override root fields for that item.
- effective `paid=false` does not require a primary document. v726.0 does not establish an absent-only rule here, so M5 does not invent a prohibition against otherwise source-valid supplied primary-document data.
- root values may coexist with item overrides; item-level values take precedence for that item.
- KPP/FIAS/product cost/WB-only fields are not written into LP_RETURN.

Business success is document `CHECKED_OK` plus fresh M1 CIS reconciliation to `INTRODUCED`.

There is no generic LP_RETURN cancellation.

## Return reason matrix

M5 uses a dedicated return matrix keyed by `(pg, current_status, current_withdraw_reason, return_type)`. It is not the LK_RECEIPT reason registry.

Confirmed cells implemented now:

- `REMOTE_SALE_RETURN`: prior `DISTANCE`, `BY_SAMPLES`.
- `RETAIL_RETURN`: prior `RETAIL`, `BY_SAMPLES`, `DISTANCE`.
- `OWN_USE_RETURN`: prior `OWN_USE`, `PRODUCTION_USE`, `MEDICAL_USE`, `VETERINARY_USE`.
- `STATE_CONTRACT_RETURN`: prior `STATE_SECRET`.
- `NOT_FOR_SALE_RETURN`: prior `DONATION`, `OWN_USE`, `PRODUCTION_USE`, `STATE_CONTRACT`.

Every cell is still keyed with `pg=lp` and current status `RETIRED`. Any combination not explicitly listed above is `MANUAL_REVIEW` / validation failure. `VENDING_RETURN` is not accepted for `lp`.

## Introduction flows

Each document has its own DTO/assembler. M5 deliberately does not define a universal introduction DTO.

- `LP_INTRODUCE_GOODS`: participant/producer/owner kept separate, exact production type, TN VED/product readiness and permit references prechecked via M2, production date optional only where allowed.
- `LK_INDI_COMMISSIONING`: separate item/receipt semantics; parent-child structure remains source-specific.
- `LP_GOODS_IMPORT`: pre-mandatory import only; fresh KI must be APPLIED/FOREIGN/no special state; customs declaration/decision fields are validated.
- `CROSSBORDER`: EAEU introduction only; exporter/tax/country/import metadata retained; no invented domestic shipment substitute.
- `LP_INTRODUCE_OST`: REMAINS only.
- `LK_CONTRACT_COMMISSIONING`: producer and owner remain distinct; contract production semantics are explicit.
- `LP_FTS_INTRODUCE`: normal post-mandatory FTS path, separate from system-generated `LP_FTS_INTRODUCE_AUTO`.

## Remarking

Typed `LK_REMARK` only. New code precondition: fresh `APPLIED`, no special state, emission type `REMARK` or `REAPPLY`. Old KI, where used, must be fresh, owned and `INTRODUCED` or `RETIRED`. Return-driven remarking requires the documented retired prior-code condition. `DESCRIPTION_ERRORS` requires `last_uin`.

M5 does not order new codes; SUZ belongs to M8.

Business reason is kept raw. Readback reason is not required to echo request text: submitted `KM_SPOILED` may be observed as `KM_SPOILED_OR_LOST`.

## Write-off

`WRITE_OFF` is a separate typed document and is not converted into an LK_RECEIPT withdrawal reason. Wire field names are source-specific (`participantId`, `dropoutReason`, `destinationCountryCode`, `buyerId`, `fiasId`, `kpp`, `withChild`, `sourceDocType`, `sourceDocNum`, `sourceDocDate`, `sourceDocName`, `sntins`).

Source document is mandatory for ordinary implemented `lp` write-off paths. Start state is checked against the accepted official matrix. Successful business reconciliation expects `WRITTEN_OFF`; document `CHECKED_OK` alone is insufficient.

## LK_RECEIPT_CANCEL

`CANCEL_WITHDRAWAL` maps only to `LK_RECEIPT_CANCEL`. Wire contract is typed `inn + lk_receipt_id` plus no invented fields.

Eligibility is checked against source document `CHECKED_OK`, same sender, latest eligible operation and other source-state evidence. Reconciliation compares the post-cancellation CIS state to the stored expected restoration state.

There is no generic `cancel(documentId)` and no inferred inverse for LP_RETURN or WRITE_OFF.

## Preconditions

`OperationPreconditionService` consumes fresh accepted M1/M2 evidence. Local snapshots are protective evidence, never a replacement for CRPT source of truth. Snapshots have a bounded age; stale local data cannot authorize a mutation indefinitely. The race between precheck and remote processing remains possible and is handled by reconciliation.

M1 evidence covers current status, statusEx, owner, withdrawal reason, emission information and other accepted CIS history/aggregation evidence when needed. M2 evidence covers product/TN VED/MOD/participant/permit readiness.

## Reconciliation

Mutation completion is always two-stage:

1. remote document reaches confirmed success, normally raw `CHECKED_OK`;
2. affected CIS are read again through M1 and compared to the documented expected postcondition.

Examples:

- DISTANCE: `RETIRED + raw withdrawReason DISTANCE`.
- REMOTE_SALE_RETURN: `INTRODUCED`.
- WRITE_OFF: `WRITTEN_OFF`.

Unknown document status, unknown raw reason, missing fresh CIS evidence or state mismatch never becomes silent success. State remains `RECONCILIATION_PENDING` or moves to `MANUAL_REVIEW` where appropriate. `CANCELED` and `CANCELLED` remain raw values where observed; M5 does not normalize away official ambiguity.

## Idempotency and ambiguous Create

M5 reuses the M4 local approach: `operation_id + immutable document SHA-256`, remote document ID when known, and attempt/audit ledger. Same operation/same immutable payload is replay-safe locally. Same operation/different payload is a conflict.

True API is not assumed to provide a universal server `Idempotency-Key`. Ambiguous Create/network timeout is never blindly resubmitted. Reconciliation uses M4 document list/info and M1 CIS state; unresolved ambiguity becomes `MANUAL_REVIEW`.

## Persistence

Migration `0006_m5_turnover` adds only M5 domain metadata: operation kind, immutable document/request hashes, raw business reason, bounded precondition evidence, expected postcondition, reconciliation state/result, cancellation reference and confirmed remote document ID. It does not copy the complete M1/M2 CIS/product/reference records.

## Deferred milestone boundaries

- M6: aggregation, reaggregation, disaggregation and complex parent-child transformations.
- M7: UPD/UKD/EDO, domestic B2B transfer, EDO titles/receipts/annulment.
- M8: SUZ, ordering/emission of new marking codes.
- M9: marketplace orchestration beyond accepted P0 compatibility, including trusted derivation of `paid` and batch automation.

No M6 work is included in this branch.

## Runtime-only uncertainties

Production behavior still requiring runtime evidence includes processing latency, practical polling cadence, races between precheck and processing, actual unknown/new status or reason strings, ambiguous network failures after Create, and participant/role visibility. These uncertainties are deliberately not encoded as guessed wire-contract behavior.
