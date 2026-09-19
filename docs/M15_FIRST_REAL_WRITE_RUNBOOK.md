# M15 first real True API write runbook — NOT AUTHORIZED

This runbook is documentation only. M15 leaves `WBCZ_TRUE_API_WRITE_ENABLED=false`. Execution requires a separate future user/architect approval and a dedicated known test/business CIS.

1. Select one approved CIS/KIZ and obtain a fresh authoritative CIS state.
2. Produce a read-only preview of the exact intended business operation and explain its semantics.
3. Obtain explicit human approval for that exact CIS and operation.
4. Assemble immutable official document bytes and persist SHA-256.
5. Append the M13 intent/idempotency evidence before submission.
6. Reserve the operation once.
7. Windows agent verifies participant-bound identity/certificate metadata and signs exactly the immutable bytes/hash. Private key and PIN remain Windows-only.
8. Submit exactly once.
9. If transport outcome is ambiguous after send, **never blind resend**. Enter manual review/reconciliation.
10. Poll official document/status read path using bounded typed jobs.
11. Perform a fresh post-operation CIS read.
12. Reconcile expected and observed state.
13. Append final M13 evidence/hashes.
14. Any mismatch, unknown status, identity mismatch, protocol mismatch, or ambiguous evidence goes to manual review.

Application rollback does not undo a remote operation. No generic signing or generic True API proxy is permitted.
