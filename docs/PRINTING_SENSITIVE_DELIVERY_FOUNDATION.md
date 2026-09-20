# Printing Sensitive Delivery Foundation — Phase A

Task: `PRINTING-SENSITIVE-DELIVERY-FOUNDATION-001`

This milestone extends the accepted local printing foundation only through secure delivery of an already retained, already proven exact FULL KM to the exact participant-bound Windows Agent process. It does **not** discover printers, call GDI/spooler APIs, submit physical print work, acquire FULL KM from production SUZ, or enable production print execution.

## Boundary

Canonical flow:

`encrypted M8 vault -> proven StoredFullKmItem -> PrintExecution -> one-time reservation -> HPKE envelope -> exact AgentBinding -> Windows process memory -> SHA-256 verification -> safe ACK`

`SEARCHABLE != PRINTABLE` remains authoritative. A remote/M1 CIS result never creates a printable payload. Sensitive delivery requires the existing local `PRINTABLE_LOCAL_FULL_KM_AVAILABLE` evidence and revalidates vault linkage immediately before every disclosure.

## Why TLS alone is not the canonical payload protection

TLS remains mandatory transport protection in production, but the sensitive payload is additionally encrypted to a printing-specific X25519 public key belonging to the exact participant AgentBinding. This gives application-level recipient binding and prevents an ordinary bearer-authenticated endpoint or another AgentBinding from obtaining plaintext FULL KM.

No custom ECDH/HKDF/AEAD composition exists. Phase A uses the RFC 9180 HPKE implementation already provided by pinned `cryptography==50.0.1`:

- mode: Base;
- KEM: DHKEM(X25519, HKDF-SHA256);
- KDF: HKDF-SHA256;
- AEAD: AES-128-GCM;
- envelope version: `SELLARI_PRINT_HPKE_V1`.

The complete canonical delivery context is authenticated through the RFC 9180 single-shot `info` parameter. The implementation does not invent a second cryptographic layer when the vetted single-shot API exposes authenticated auxiliary context through `info`.

## Canonical authenticated context

Every envelope binds:

- delivery reservation ID;
- print execution ID;
- print job ID;
- print job item ID;
- stored FULL-KM locator ID;
- organisation ID;
- participant ID;
- AgentBinding ID;
- immutable payload SHA-256;
- immutable template-version ID;
- immutable layout SHA-256;
- recipient key version;
- reservation expiry.

The response contains only version/suite metadata, recipient key version, HPKE `enc`, HPKE ciphertext, hashes, IDs, expiry, and the safe canonical context needed by the recipient. Plaintext FULL KM is never returned by an HTTP endpoint.

## Durable Phase-A state

Migration `0018_printing_sensitive_delivery` is additive over `0017_printing_local_foundation`.

### AgentBinding encryption keys

`agent_binding_encryption_keys` stores only public X25519 material and safe metadata. Private keys are never server-side.

Lifecycle:

`ACTIVE -> RETIRING -> REVOKED`

There is one ACTIVE printing key per AgentBinding. Rotation requires an operator-created one-use intent. The retiring key may service only reservations that were already bound to it before rotation and remain unexpired. After the reservation TTL window it is revoked.

Lost private key has no server recovery/export. The operator creates a `REPLACE_LOST` intent; outstanding reservations bound to the lost key are revoked.

### Key enrollment intents

`print_encryption_key_intents` stores a SHA-256 token hash only. Intent states are `PENDING/USED/EXPIRED/REVOKED`. ADMIN/OWNER permission is required to create the intent. A participant-bound machine bearer alone cannot register or rotate a print encryption key.

### PrintExecution

`print_executions` records one physical-attempt foundation per PrintJobItem, but Phase A stops before spool work.

Implemented states:

- `REQUESTED`
- `AUTHORIZED`
- `PAYLOAD_AVAILABLE`
- `PAYLOAD_ISSUED`
- `PAYLOAD_DELIVERED`
- `FAILED_PRE_SPOOL`
- `BLOCKED`
- `CANCELLED_PRE_SPOOL`

There is no executable spool/printer state in this milestone. `PAYLOAD_DELIVERED` means only that the agent proved it opened the exact envelope and verified the exact payload hash.

### Delivery reservation

`print_payload_delivery_reservations` is pinned to the exact execution, job item, retained KM locator, AgentBinding, recipient key, payload hash, participant and tenant.

Project-policy defaults:

- TTL: 10 minutes;
- maximum issuance count: 3.

These three issuances are bounded redisclosure of the same exact payload before any irreversible spool boundary. They are **not** three print attempts.

Every issuance locks the reservation row and revalidates execution state, recipient binding/key, immutable job/item/template hashes, provenance and M8 vault integrity.

## Printing-agent-v2

Phase A protocol:

`printing-agent-v2`

Required capabilities:

- `PRINTING_SENSITIVE_DELIVERY_V1`
- `HPKE_X25519_AES128GCM_V1`

Agents without both capabilities cannot receive sensitive-delivery work. Existing agent protocols remain valid for their accepted prior capabilities.

The v2 control contract contains IDs, hashes, recipient key version and expiry only. FULL KM is never inserted into `agent_jobs.payload_json`.

Machine-only routes are participant-bound and use permanent AgentBinding credentials. Browser cookies do not authorize these routes.

## Windows private-key boundary

The agent generates X25519 locally.

The raw private key:

- is never uploaded;
- is never an environment variable;
- is never SQLite plaintext;
- is never logged;
- is stored only as a Windows DPAPI-protected local blob.

The DPAPI adapter is intentionally narrow and independent from certificate/PIN/signing infrastructure. Non-Windows tests use an explicit fake protector; CI also exercises real synthetic DPAPI protect/unprotect on a hosted Windows runner.

The agent replay SQLite database stores only execution/job-item/reservation IDs, payload/context hashes, state, key version, timestamps and safe errors. It does not store FULL KM, HPKE ciphertext or private keys.

## Plaintext lifetime and current M8 reality

Backend plaintext is permitted only transiently for:

1. decrypting the existing M8 encrypted vault entry;
2. extracting the exact retained item;
3. verifying SHA-256;
4. immediately sealing it with HPKE.

The current M8 format may require decrypting the entire encrypted code block before slicing one item. Phase A does not hide that fact and introduces `WBCZ_MAX_PRINT_DELIVERY_VAULT_ENTRY_BYTES`. Oversized entries fail with `VAULT_ENTRY_TOO_LARGE_FOR_SAFE_PRINT_DELIVERY`.

There is no cross-request decrypted-block cache, temp file, generic artifact, DB persistence, metric payload, or audit payload. Python does not guarantee deterministic memory zeroization; the implementation only minimizes application references after sealing.

On Windows, opened plaintext exists only in process memory long enough to authenticate/decrypt and verify its SHA-256. Phase A ends there.

## ACK and replay

Agent ACK contains only:

- delivery reservation ID;
- payload SHA-256;
- context SHA-256.

A valid ACK changes reservation to `ACKNOWLEDGED` and execution to `PAYLOAD_DELIVERED`. Wrong hash/context fails closed as `FAILED_PRE_SPOOL`. ACK never means rendered, spooled, or printed.

Redisclosure is allowed only for the same unexpired reservation, execution, AgentBinding, recipient key version and payload hash, and only below the issuance ceiling. Future Phase B/C must forbid redisclosure after the irreversible spool boundary.

## Audit and redaction

Phase A adds:

- `PRINT_AGENT_KEY_REGISTERED`
- `PRINT_AGENT_KEY_ROTATED`
- `PRINT_AGENT_KEY_REVOKED`
- `PRINT_PAYLOAD_AUTHORIZED`
- `PRINT_PAYLOAD_ISSUED`
- `PRINT_PAYLOAD_DELIVERED`

Audit metadata is restricted to IDs, hashes, key fingerprint/version, counts and safe error codes. It never contains FULL KM, HPKE ciphertext, private keys or rendered code data.

## Feature gates

The independent gates remain authoritative:

- `WBCZ_PRINTING_ENABLED=false`
- `WBCZ_PRINT_EXECUTION_ENABLED=false`
- `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED=false`

Production with `WBCZ_PRINT_EXECUTION_ENABLED=true` remains a startup error. Phase A does not relax this invariant. Test/development configurations may explicitly enable the pre-spool flow with synthetic data.

Remote SUZ FULL-KM acquisition remains blocked independently.

## Strict Phase B/C boundary

Not implemented here:

- EnumPrinters or printer discovery;
- printer profiles sourced from Windows;
- GDI/StartDoc;
- Windows spooler submission/status;
- ZPL/EPL/CPCL;
- physical test print;
- physical “printed” result;
- production print execution activation;
- production SUZ order/FULL-KM acquisition or reacquisition;
- guessed SUZ wire;
- real marking codes, certificates, PINs or signing private keys.

Those require separate acceptance.
