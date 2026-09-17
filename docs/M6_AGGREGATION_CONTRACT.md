# M6 aggregation contract

Source: True API v726.0 dated 2026-09-04 and accepted `M6-AGGREGATION-RESEARCH-001`. Product group scope: `lp`.

## Package model

`PackageType` and `UnitSerialNumberType` are separate wire/domain concepts. Package types are `UNIT`, `GROUP`, `BUNDLE`, `SET`, `BOX`, `ATK`. `BUNDLE` is the lp KIK. `SET` is KIN. `BOX` is KITU. The separate `unitSerialNumberType` enum is `BOX`, `GROUP`, `PRODUCT_SET`; `SET` must never be emitted where `PRODUCT_SET` is required.

For `lp`, `GROUP` is not exposed as a formable parent. `SET` accepts only direct `UNIT` or `BUNDLE`. `BOX` accepts `UNIT`, `BUNDLE`, `SET`, and nested `BOX`; `GROUP` can only appear as a legitimate non-lp child in a mixed-PG KITU. Nested `SET` is fail-closed. ATK is a separate customs aggregate domain.

## Typed operations

M6 exposes only typed domain operations mapped to exact document types: `FORM_TRANSPORT_PACKAGE` and `FORM_MULTIPRODUCT_TRANSPORT_PACKAGE` -> `AGGREGATION_DOCUMENT`; normal `FORM_SET` -> `SETS_AGGREGATION`; `FORM_SET_GENERIC_COMPATIBILITY` -> `AGGREGATION_DOCUMENT` only when explicitly selected; package add/remove -> `REAGGREGATION_DOCUMENT`; package disaggregation -> `DISAGGREGATION_DOCUMENT`; ATK form/transform/disaggregate -> `ATK_AGGREGATION`, `ATK_TRANSFORMATION`, `ATK_DISAGGREGATION`.

There is no generic document sender, generic aggregation write, arbitrary document type/body/path/URL, generic move-child, or generic cancellation. Auto-disaggregation is an expected CRPT side-effect and reconciliation concept, never a second submitted write.

## Exact JSON MANUAL DTOs

`AGGREGATION_DOCUMENT` preserves official names: `participantId`, `aggregationUnits[]`, `partNumber`, `unitSerialNumber`, `unitSerialNumberType`, `aggregationType`, `sntins`. `aggregationType` is `AGGREGATION`. `partNumber` is not enabled for lp because the accepted source ties its special semantics to other PG-specific rules.

`SETS_AGGREGATION` preserves `participantId`, `aggregationUnits[]`, `unitSerialNumber`, `sntins`. It is the default KIN path. KIN direct children are only `UNIT`/`BUNDLE`. APPLIED children must satisfy same emission semantics and both `REMARK` and `REAPPLY` are rejected. INTRODUCED children follow the documented LOCAL/REMAINS parent rules. Set composition must be proven by M2/NKMT evidence, including the lp `markedProductsQuantityInSet` path where applicable.

`REAGGREGATION_DOCUMENT` preserves `participant_inn`, `reaggregation_type`, `uitu`, `uit_uitu_list[]`, with item-level `uit_uitu` XOR `kitu`. `kitu` is only the nested-BOX case. `reaggregation_type` is `ADDING` or `REMOVING`; there is no MOVE abstraction.

`DISAGGREGATION_DOCUMENT` preserves `participant_inn`, `products_list[].uitu`. `BOX` and `SET` are executable for lp; `GROUP` is rejected. The project requires owner==sender by default. The historical non-owner flow is known but disabled and returns `LEGACY_NON_OWNER_FLOW_NOT_ENABLED`.

ATK DTOs preserve `trade_participant_inn`, `atk`, `transformation_type`, and `products_list[].ki/atk` exactly. Formation/transformation require IMPORTER role, ownership, FOREIGN emission, APPLIED state, one PG, compatible TN VED, and operation-specific `statusEx`. `FTS_CONTROL` is not carried into formation/transformation merely because it is permitted for ATK disaggregation. No local ATK identifier is synthesized.

## Multiproduct KITU

Mixed-PG KITU is supported as the current v726 contract, not downgraded to an old single-PG model. The leading PG is explicit in precondition evidence; at least one child must match it. Child compatibility is evaluated using each child's real PG/package type. Nested BOX is supported. The implementation does not invent a nesting-depth contract. Official non-owner/legacy traceability exceptions are not silently enabled.

## Reads and reconciliation

CRPT current state remains canonical. Local persistence records only operation evidence and reconciliation metadata; it does not mirror a canonical aggregation graph.

Current relation proof uses M1 `cises/aggregated/list` and `cises/info`; nested BOX is traversed level-by-level. The only depth limit in the local tree helper is an explicitly labelled `INTERNAL_SAFETY_LIMIT`; hitting it marks the result truncated rather than complete. Cycles, duplicate edges, and unknown raw package types are surfaced as warnings/manual review.

Aggregation history recognizes raw `AGGREGATION`, `DISAGGREGATION`, `TRANSFORMATION`, and both official auto spellings `AUTODISAGGREGATED` / `AUTODISAGGREGATION`. Raw values and raw dates are preserved. The date parser tolerates both official table/example formats. Integer VIOLATIONS export operation codes are not mixed with the string history enum.

Every mutation is at least two-stage: document `CHECKED_OK` plus CRPT relation/state proof. Formation requires exact parent/child relation; add/remove requires exact relation delta; explicit disaggregation requires relation removal plus compatible history evidence; ATK formation discovers the actual remote parent through child/current state/history and then verifies package type `ATK`. `CHECKED_OK` alone is never business success.

## Auto-disaggregation and M5 hardening

M6 records source-confirmed aggregate effects for KITU child actions, separate introduction of nested children, KIN child introduction/sale, LP_RETURN aggregate-vs-child behavior, LK_RECEIPT aggregate effects, LK_REMARK KIN special cases, ATK child status/owner change, and WRITE_OFF KITU behavior. Unknown KIN cases remain fail-closed.

Accepted M5 is not rewritten. Aggregate-aware hardening requires capturing the parent graph before relevant M5 writes and reconciling after success. DISTANCE and nested introductions reconcile expected KITU effects; LP_RETURN distinguishes returning the aggregate itself from returning a nested child; WRITE_OFF KITU expects auto-disaggregation while WRITE_OFF KIN remains raw/manual when exact effect is not documented; LK_REMARK KIN uses type-specific rules; LK_RECEIPT_CANCEL re-reads the relation graph and never assumes relationship restoration from restored statuses alone.

## Idempotency and races

The local contract reuses operation-id plus immutable request/document hashes and remote document ID when known. No official server idempotency key is assumed. Ambiguous create results are never blindly resubmitted; M4 document state, M1 current relation/state, and M6 history/tree are used for reconciliation, otherwise MANUAL_REVIEW. No transaction lock, child-level atomicity, duplicate-submit deterministic outcome, or parallel race semantics are invented.

## Runtime/source ambiguities

The textual status «Сформирован» has no confirmed current raw enum; `FORMED` is not invented. Raw runtime status is preserved. Explicit disaggregation resulting parent status is read back and not hardcoded to `DISAGGREGATION`. ATK parent code generation is not implemented; the parent is discovered from CRPT. No universal JSON-null normalizer is used; operation-specific strict-absence rules win.

## Security and boundaries

Production write remains default-off. All M6 writes use the existing exact-byte M3/M4 path: server builds approved JSON bytes, Windows signs those exact bytes and performs GOST transport. Private key, PIN and True API bearer remain Windows-side. No direct VPS True API transport is introduced.

M7 remains deferred: UPD/EDO ownership transfer, seller/buyer EDO titles, aggregate shipment via EDO, EDO correction/cancellation. M8 remains deferred: SUZ ordering, marking-code issuance, application reports, code pools, KIN/KIK code generation/emission. M6 assumes required pre-existing codes where the official contract does.
