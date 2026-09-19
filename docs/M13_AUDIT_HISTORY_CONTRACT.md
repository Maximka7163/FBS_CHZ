# M13 Audit History Contract

## Security claim

M13 provides APPEND_ONLY=YES and TAMPER_EVIDENT=YES immutable audit evidence inside PostgreSQL.

M13 is NOT_EXTERNALLY_ANCHORED. It is not blockchain, not externally immutable, not DBA-proof, and does not provide non-repudiation against the database/schema owner. External anchoring, WORM/SIEM replication, and stronger database-role separation are deferred to M15 or later.

## Data classification

M13 keeps four distinct layers:

1. IMMUTABLE_AUDIT — sanitized registered security, administration and high-value business facts, hash chained.
2. OPERATIONAL_HISTORY — existing domain ledgers, workflow state, report job events, agent state and reconciliation rows.
3. RAW_SENSITIVE_EVIDENCE — existing encrypted vaults/artifacts and protected evidence referenced by safe IDs/hashes only.
4. APPLICATION_LOGS — runtime/debug diagnostics, non-authoritative.

Audit is never an authorization source. M12 authorization, tenant ownership, feature gates and domain safety remain authoritative.

## Chain scope

There is exactly one SYSTEM chain and one ORGANISATION chain per organisation. Participant is a sub-scope inside the organisation chain; there is no participant chain.

SYSTEM requires organisation_id=NULL and participant_id=NULL. Organisation events require organisation_id. Participant business events require both organisation_id and participant_id, with the participant verified to belong to that organisation.

Each chain starts with sequence 1 AUDIT_CHAIN_GENESIS and previous_event_hash equal to 64 zeroes.

## Registries and snapshots

Categories, event types, actor kinds, subject types, outcomes and authorization decisions are fixed in code. Unknown values fail closed.

Categories: SECURITY, AUTHORIZATION, TENANT_ADMIN, INTEGRATION, IMPORT, CONTROL, CIS_READ, REFERENCE_READ, DOCUMENT, TURNOVER, AGGREGATION, EDO, SUZ, WB, OZON, REPORT, AGENT, SYSTEM.

Actor kinds: USER, SYSTEM, WORKER, WINDOWS_AGENT, CLI_ADMIN, BOOTSTRAP, REMOTE_SYSTEM.

Outcomes: SUCCESS, DENIED, FAILED, PENDING, CONFLICT, CANCELLED, AMBIGUOUS.

Authorization decisions: ALLOW, DENY, NOT_APPLICABLE.

Tenant USER events preserve stable user ID, membership ID and role snapshot. High-risk authorization/admin/write/download/audit-access events also preserve a sorted effective permission snapshot. Later role/account changes never rewrite old events.

## Sensitive identifiers and client privacy

Plaintext CIS/KIZ/KM/SGTIN is not stored by default. MARKING_IDENTIFIER uses HMAC-SHA256 with a dedicated injected audit pseudonym key over:

marking:v1:<organisation_id>:<exact_value>

The audit key is not hardcoded, committed or logged and is not reused from session, vault, M11 artifact, True API or signing key material.

Raw IP and full User-Agent are not immutable-audit fields. When required they use versioned HMAC pseudonyms with the same dedicated audit key. Existing M12 proxy trust remains authoritative; untrusted X-Forwarded-For is ignored.

## Recursive sanitizer

The M13 sanitizer recurses mappings, lists, tuples and JSON scalars.

Limits:
- max depth 8
- max keys/object 100
- max array elements 100
- max string 4096 characters
- max canonical metadata 32 KiB

Secret-key/path indicators are recursively redacted. Marking values are pseudonymized or redacted. Unknown Python object types fail closed. repr() is never a persistence fallback.

## Canonicalization and hash chain

Audit format version: SELLARI_AUDIT_V1.

Canonical payloads use UTF-8 RFC 8785/JCS-compatible serialization, explicit nulls, UTF-16 code-unit key ordering, UTC RFC3339 fixed microseconds, lowercase UUID strings and decimal-string sequence values. Unsafe large JSON integers are strings. NaN and Infinity are rejected. JCS does not Unicode-normalize strings.

For event N:

previous_event_hash = event_hash(N-1)

event_hash = SHA256(UTF8(JCS(canonical_payload_v1)))

created_at is database storage metadata and is not part of the event hash.

## Append transaction and idempotency

Append resolves/creates the chain, locks audit_chain_heads with SELECT ... FOR UPDATE, assigns head_sequence+1, validates/sanitizes, inserts audit_events and advances the chain head in one transaction.

Different organisation chains have independent locks. SYSTEM is serialized.

event_key is unique per chain. Same event_key plus same semantic event converges to the existing receipt. Same event_key plus conflicting semantics raises AUDIT_EVENT_KEY_CONFLICT.

## Append-only guards and checkpoints

PostgreSQL triggers reject UPDATE/DELETE on audit_events and audit_checkpoints. Application services expose no mutation/delete API. audit_chain_heads are necessarily advanced by append transactions.

These guards do not protect against the DB/schema owner.

Checkpoint format: SELLARI_AUDIT_CHECKPOINT_V1. A checkpoint is due on the first ordinary append of a new UTC day or every 10,000 events. It chains through previous_checkpoint_hash. CHECKPOINT_CREATED uses an explicit suppression path so checkpoint creation does not recurse.

Checkpoints are local tamper evidence only, not an external anchor.

## Legacy history

Pre-M13 rows are not replayed as if they had been sealed when created.

For SYSTEM and each organisation chain M13 records AUDIT_CHAIN_GENESIS then LEGACY_HISTORY_IMPORTED. The latter stores a deterministic manifest of pre-M13 sources with counts/ranges/timestamps and aggregate SHA256.

Legacy semantics are explicitly PRE_M13_UNSEALED_HISTORY. Original historical rows remain intact.

## Failure semantics

Required local business/security mutation and required immutable append share the same database transaction. Audit append failure rolls back/fails the local mutation.

Successful authentication/session creation and LOGIN_SUCCESS are atomic. If required login-success audit cannot commit, no usable successful session is committed.

An authentication denial remains denial even if denial-audit persistence fails.

Sensitive read/download authorization must be durably audited before bytes are released. Completion/failure is recorded afterward.

Remote mutation pattern is intent/result/reconciliation. Durable domain intent plus immutable *_INTENT commits before remote execution. Uncertain remote result is AMBIGUOUS; success is never invented and remote rollback is never pretended.

## Trace propagation

Trace fields are request_id, correlation_id, causation_id, operation_id and agent_job_id. They complement domain IDs. agent_jobs and report_jobs persist nullable correlation/causation; worker and Windows-agent paths propagate lineage without persisting tokens.

## Query API

Backend browser API:
- GET /api/audit/events
- GET /api/audit/events/{event_id}

It requires authenticated active M12 membership plus audit:read; under current M12 roles this is ADMIN/OWNER only. There is no browser SYSTEM-chain API and no platform superuser.

Organisation scope comes from current AuthorizationContext, not query input. Foreign participant/event IDs do not reveal another tenant. Filters are bounded and typed; sequence keyset pagination limit is 1..200. Arbitrary SQL/metadata filters are not supported.

Every audit query appends AUDIT_QUERY_EXECUTED before response release and fails closed if that audit-of-audit append cannot commit.

## Verifier CLI

Use:

wbcz-web-admin verify-audit-chain --organisation-id <uuid>

or:

wbcz-web-admin verify-audit-chain --system

Optional:
- --from-sequence N
- --expected-previous-hash H

Verifier checks contiguous sequence, genesis, previous hashes, recomputed event hashes, stored head, checkpoints and known format/event registry. Output is bounded to scope, chain ID, checked range/count, stored head, checkpoint status, VALID/INVALID, first invalid sequence and reason. It does not dump event metadata.

## Retention and backup/restore

M13 immutable audit has no automatic deletion. PROJECT_AUDIT_RETENTION_NOT_FINALIZED=YES. No arbitrary 30/90/365-day compliance period is invented.

A consistent backup must include at least audit_events, audit_chain_heads, audit_checkpoints, organisations, users, memberships and required interpretation data.

After restore, chain verification is required before production business writes.

FULL_DATABASE_ROLLBACK_DETECTION=REQUIRES_EXTERNAL_ANCHOR. An older internally consistent full-database backup may validate locally; detecting that rollback needs an external anchor deferred to M15/later.

## Explicitly deferred/prohibited

No frontend redesign, platform superuser, blockchain claim, external SIEM/cloud selection, social/OIDC login, M14 integration-settings implementation, M15 deployment work, arbitrary M3/UKЭП signing of audit records, production enabling of blocked M7/M8/M10, production deployment, production migration application, main merge, or real production API calls.
