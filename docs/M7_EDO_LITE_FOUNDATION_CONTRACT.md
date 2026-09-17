# M7 EDO Lite foundation contract

Source boundary: accepted M7 EDO Lite research (`M7-EDO-LITE-UPD-RESEARCH-001` plus FIX-01/FIX-02) and True API v726.0. Product-group scope remains `lp`.

## Milestone state

M7 full XML write is **BLOCKED**. The repository does not contain a pinned official production XSD package for the current 970@ formats, the True-API-compatible 736@ formats, replacement ЕД-1-26/29@ formats, or the service documents required for EDO Lite. This foundation therefore implements read transport, evidence/ledger, reconciliation, quota, immutable-byte, disabled schema-registry, offline-validator and signing-envelope infrastructure only.

No M7 production capability in this commit generates, serializes, signs or sends UPD, UPDi, UKD, UKDi, DP_UVUTOCH, DP_PRANNUL, DP_UNISOOBSCH or any EDO event/service XML. Calling an XML-dependent mutation before an architect-accepted schema is enabled fails locally with `M7_SCHEMA_NOT_ENABLED` and performs no remote call.

## Typed read endpoint allowlist

Only the following schema-independent GET capabilities are represented. Caller-controlled URL, method, path, headers, body and content type are not accepted.

- participant capability: `/api/v4/true-api/edo/inn/{inn}`;
- outgoing/incoming lists: `/api/v3/true-api/elk/outgoing-documents`, `/api/v3/true-api/elk/incoming-documents`;
- raw content: `/elk/outgoing-documents/{documentId}/content`, `/elk/incoming-documents/{documentId}/content`;
- print PDF: `/api/v3/true-api/edo/outgoing-documents/{doc_id}/print`, `/api/v3/true-api/edo/incoming-documents/{doc_id}/print`;
- legal ZIP: `/elk/outgoing-documents/{documentId}`, `/elk/incoming-documents/{documentId}`;
- unsigned events: `/api/v3/true-api/edo/outgoing-documents/unsigned-events`, `/api/v3/true-api/edo/incoming-documents/unsigned-events`;
- incoming event content: `/api/v3/true-api/edo/incoming-documents/{doc_id}/events/{event_id}/content`;
- outgoing/incoming receipt JSON: `/api/v3/true-api/edo/{direction}-documents/{doc_id}/events/{receiptType}`;
- outgoing/incoming MЧД: `/api/v3/true-api/edo/{direction}-documents/{doc_id}/mchd-list`;
- GIS processing: `/documents/edo/tpr/ud?fileId=<ИдФайл>`;
- GIS document-info reconciliation continues to reuse accepted M4 `/api/v4/true-api/doc/{docId}/info`.

List requests expose only `limit`, `offset`, `created_from`, `created_to`, `partner_inn`, `partner_id`, `status`, `type`, `folder`, `asc`, `product_group`; `sortBy` is fixed to `created_at`. Defaults are `limit=10`, `offset=0`. Remote `has_next_page` is preserved as evidence. No cursor, document-number filter, event-id filter or snapshot guarantee is invented.

## Remote identifiers and downloaded bytes

All EDO/GIS identifiers are opaque strings. GUID-looking values are not UUID-normalized; numeric-looking values are not converted to integers; case and exact textual representation are preserved. This applies to document, event, group, parent, annulment, receipt, GIS source/result and related IDs.

Content/PDF/legal ZIP downloads are kept as opaque exact bytes with remote content type and SHA-256. Legal ZIP is not repackaged. Optional inspection never extracts paths and rejects traversal, absolute paths, symlinks, excessive entry/expansion sizes and suspicious compression ratios.

## EDO and GIS status separation

EDO raw numeric status is preserved separately from local normalized state. Known raw values are `0,1,2,3,4,5,7,8,11,12,13,14,15,16,17,18,19,41,42,43,44,61,62,63,64,65,66`; unknown integers are retained rather than rejected. Any remote human label is retained independently.

Raw EDO `61` and `63` are not GIS success. Raw EDO `62` is not treated as complete GIS failure detail. GIS `/documents/edo/tpr/ud` has its own `SUCCESS`, `FAILED`, `IN_PROGRESS` model and preserves source/result document IDs/dates, raw code/description, operations and product-group processing errors.

Final M7 business success is not HTTP 2xx and not any single EDO status. The foundation predicate requires the applicable counterparty completion, GIS receipt `SUCCESS`, accepted M1 owner/status/statusEx reconciliation and accepted M6 aggregate-relation reconciliation. The local DB is evidence/ledger only; CRPT remains canonical.

## Annual EDO Lite quota

`EDO_LITE_ANNUAL_OUTGOING_LIMIT=1000`. The local year/count observation is advisory. No CRPT endpoint for authoritative remaining quota is documented, so the model deliberately has no authoritative `1000 - local_count` remainder. Future mutation automation must refuse volume when quota safety cannot be proven according to policy; today all M7 mutations are disabled regardless.

## Durable ledger and idempotency foundation

Migration `0008_m7_edo_lite_foundation` adds an EDO Lite evidence ledger, disabled schema registry and advisory annual-quota observation. Remote IDs are text/opaque, and the tables contain no bearer token, private key, PIN or certificate private material.

Future idempotency reuses M4 principles: `operation_id`, immutable payload hash and remote ID when known. Same `IdFile` plus same SHA-256 means reconcile the remote existing document; same `IdFile` plus different SHA-256 is a hard conflict/manual-review condition. No generic server idempotency guarantee is claimed and no blind legally-significant resend is introduced.

## Immutable XML/blob foundation

Remote draft/content bytes may be captured with exact SHA-256, document family, schema identity and source. `LOCAL_BUILT` is intentionally unavailable in this foundation because there is no XML builder. Any future signature must bind to exactly the immutable bytes/hash; reserialization after hashing/signing is forbidden.

## Disabled production schema registry

Registry rows describe family/type/title/function metadata only where known. All production entries have `enabled_for_lp=false`. Missing official order, artifact/XSD filename, checksum, root, target namespace, encoding, filename grammar, parent-link rule and marking capability remain explicit NULL/unknown values; no `latest` alias or fake schema metadata exists.

The UKD conflict is represented explicitly:

- `TRUE_API_ENDPOINT_FORMAT=736`;
- `CURRENT_FNS_736_STATUS=REPEALED`;
- `REPLACEMENT_FNS_ORDER=ЕД-1-26/29@`;
- `COMPATIBILITY=UNRESOLVED`.

UKD/UKDi write remains disabled. The code does not substitute 29@ XML into a `/736` endpoint and does not erase knowledge of the True API `/ukd/736` and `/ukdi/736` contract.

## Offline XML validator security

The validator is infrastructure for future architect-pinned XSD packages, not a production M7 schema. Defaults are fail-closed: network resolution, DTD and external entities are disabled; caller `schemaLocation`, schema path, root and namespace selection are unavailable; imports/includes resolve only from the pinned in-memory dependency manifest; checksum mismatch and unknown schema identity hard-fail.

Tests use a tiny `TEST_ONLY_*` XSD exclusively to verify parser mechanics. It is not inserted into the production registry and cannot enable M7 writes.

## Signing boundary

The M7 signing-envelope type binds operation/reference, participant, opaque remote IDs when known, document family/type, schema identity, exact XML bytes and SHA-256. Envelope creation requires a production schema explicitly enabled in the accepted registry, therefore it currently fails locally for every M7 production schema. There is no arbitrary XML/file signer, no caller-selected algorithm/certificate path and no production M7 signing job.

M3 security remains unchanged: the True API bearer, private key and PIN remain Windows/token-side and no direct VPS True API path is introduced.

## MЧД and errors

MЧД read preserves remote data/status including `ACTIVE`, `CREATED`, `PROCESSING`, `EXPIRED`, `REVOKED`, `REJECTED`, `NONE`; MЧД is not made universally mandatory without runtime/document/account evidence.

EDO HTTP/service errors, GIS processing errors, local schema-disabled failures and local reconciliation failures remain separate classes. Raw response/error evidence is retained; no synthetic retriable flag and no blind mutation retry are introduced.

## Artifacts still required to unblock full M7 XML implementation

The architect must pin and accept the exact official raw artifacts relevant to the supported flows, including as applicable:

- `14414412.zip`;
- `xsd_970_736.zip`, if an official compatible package is actually available;
- `10223010.zip`;
- `pril1_16626884_xsd.zip`;
- `pril2_16626884_xsd.zip`;
- `unmf_proj.zip`;
- the official schema defining `DP_UVUTOCH`;
- the official schema defining `DP_PRANNUL`.

No claim is made that standalone DP files with those names necessarily exist; the requirement is to pin the official schema artifact that actually defines each service document.

M7 remains partially blocked after this foundation. M8 is not started.
