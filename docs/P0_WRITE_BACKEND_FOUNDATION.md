# P0 write backend foundation

Status: backend foundation only. Production True API write remains disabled by default and is not wired into the web application.

## Scope

P0 supports only:

- product group `lp`;
- `LK_RECEIPT` for `READY_TO_WITHDRAW` / `DISTANCE`;
- `LP_RETURN` for `READY_TO_RETURN` / `REMOTE_SALE_RETURN`.

`MANUAL_REVIEW`, `ERROR`, unsupported decisions, other product groups and arbitrary document types cannot enter the signing/submission pipeline.

## Immutable document boundary

`P0ExactDocumentBuilder` is the only JSON serialization point for an approved P0 document body. It produces immutable UTF-8 bytes, SHA-256 and Base64. From that point on, submit uses the stored `product_document_base64` verbatim.

Invariant:

```text
bytes_for_signature == Base64Decode(product_document_base64)
```

The write foundation deliberately does not invent an unconfirmed inner True API document-field schema. The caller must provide an already validated P0 document mapping. This module owns immutability, type/reason whitelisting, signing handoff, idempotency, submission request shape, polling and audit state.

## Windows Bridge contract boundary

No bridge HTTP route is exposed in this task because bridge authentication/pairing is a separate security task. The backend service contract is ready for a future outbound-only Windows Bridge.

Pending signing request fields:

```text
request_id
operation_id
document_type
pg
expected_inn
document_sha256
product_document_base64
```

Allowed `document_type`: `LK_RECEIPT`, `LP_RETURN` only. `pg` must be `lp`.

Signing response fields:

```text
operation_id
document_sha256
signature_base64
certificate_thumbprint
certificate_subject
certificate_inn
certificate_valid_from
certificate_valid_to
```

The backend checks operation existence/state, immutable hash equality, whitelist, participant INN match and replay state before storing a detached signature. Private key and PIN never cross this boundary.

There is no generic `sign(any bytes)` contract.

## Idempotency

A business fingerprint is derived from source event, approved decision, P0 document type, `pg` and expected INN. It intentionally excludes document bytes. Therefore the same business operation prepared with changed bytes is an idempotency conflict rather than a second operation.

State persistence uses compare-and-set updates. Once an operation moves from `SIGNED` to `SUBMITTING`, a second create attempt is blocked. A process crash after that boundary fails closed rather than automatically replaying the create call.

## True API create adapter

The adapter constructs only:

```text
POST /api/v3/true-api/lk/documents/create?pg=lp
Authorization: Bearer <token>
Content-Type: application/json
```

Body:

```json
{
  "document_format": "MANUAL",
  "product_document": "<stored exact-document Base64>",
  "type": "LK_RECEIPT | LP_RETURN",
  "signature": "<detached signature Base64 without CR/LF>"
}
```

`second_product_document` and `second_signature` are never emitted.

The adapter has no concrete production transport in this task. Transport is injected, and `write_enabled=False` is the default. The current web application does not instantiate or route to this adapter.

## Create response boundary

HTTP 200/201 is not business success. The production-safe default create-response parser is intentionally unconfirmed and returns no document identifier. Therefore a 200/201 response without an explicitly injected confirmed parser moves the operation to `MANUAL_REVIEW`.

Only a separately confirmed response parser may extract a unique `doc_id`. Tests use a fixture parser; production code does not guess `response["docId"]` or any other envelope.

Safe response metadata stores only status, body length, response-body SHA-256, content type and parser contract name. Bearer token and response body are not written to the audit trail.

## Polling

Endpoint:

```text
GET /api/v4/true-api/doc/{docId}/info
```

Classification:

- `IN_PROGRESS`, `WAIT_FOR_CONTINUATION` -> intermediate / `PROCESSING`;
- `CHECKED_OK` -> document processing success, then immediately `RECONCILIATION_REQUIRED`;
- `CHECKED_NOT_OK`, `PARSE_ERROR`, `PROCESSING_ERROR` -> `FAILED`;
- `UNDEFINED` or any unknown status -> `MANUAL_REVIEW`.

`CHECKED_OK` is not treated as proof of final KI state. A later cises/info reconciliation step remains mandatory.

## Persisted state

Migration `0002_p0_write_pipeline` adds:

- `write_operations`;
- `signing_requests`;
- `write_operation_audit`.

Pipeline states:

```text
PREPARED
AWAITING_SIGNATURE
SIGNED
SUBMITTING
SUBMITTED
PROCESSING
SUCCEEDED
FAILED
MANUAL_REVIEW
RECONCILIATION_REQUIRED
```

Every state transition is auditable. Full product document, KIZ data, signatures and bearer tokens are not copied into audit metadata.

## Security boundary

- backend Docker runtime user remains `wbcz`;
- runtime Alembic permission hardening is retained;
- private key/PIN are never stored server-side;
- production write default is OFF;
- no arbitrary signing API exists;
- no Windows Bridge HTTP endpoints are exposed before authentication/pairing is designed;
- frontend is unchanged;
- no deployment or production migration is part of this task.
