# M15 Windows agent operations

Production agent runs under Windows Task Scheduler with a dedicated least-privilege Windows account, independent of interactive desktop sessions.

Required operating contract:

- trigger at system startup and restart on failure with bounded backoff;
- single-instance execution;
- restricted agent data directory;
- outbound HTTPS only; no listener;
- permanent participant credential stored through DPAPI/equivalent, not plaintext env after enrollment;
- replay SQLite retained on durable local disk;
- replay DB may contain job replay state, M11 rate windows and non-secret runtime/protocol metadata only;
- certificate private key and PIN never enter replay DB, logs or VPS;
- no automatic self-update;
- operator-controlled version rollout and protocol compatibility check.

Enrollment uses `wbcz-agent enroll` with a short-lived one-use token supplied only for enrollment. The command stores the returned permanent credential through DPAPI and does not print it. Remove the enrollment token from the environment immediately after exchange.

Task Scheduler example policy (adapt account/path locally; do not execute in CI): startup trigger, “run whether user is logged on or not”, restart on failure, stop duplicate instance, executable `wbcz-agent run`. Restrict ACLs on the data directory to the dedicated account and Administrators.
