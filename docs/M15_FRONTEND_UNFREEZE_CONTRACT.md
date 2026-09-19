# M15 frontend-unfreeze backend contract

Frontend freeze remains active through M15 acceptance. No final product UI is implemented by M15.

Stable backend surfaces required before unfreeze:

- auth/session/CSRF plus multi-organisation/participant active scope;
- M12 RBAC permission semantics and non-enumerating foreign-object behavior;
- integration CRUD/status for True API, WB, Ozon, SUZ and derived EDO state;
- participant-bound agent status, enrollment, protocol compatibility and certificate metadata;
- environment capability/blocker projection;
- report metadata/create/download contracts;
- tenant-scoped manual-review list/resolve contract (resolve does not mutate remote state);
- M13 audit/history and verification semantics;
- `/api/live`, `/api/ready`, authenticated `/api/health/deep`;
- pagination/filter conventions;
- request/correlation IDs;
- safe normalized error shape for new M15 routes: `detail.code`, safe `detail.message`, `detail.correlation_id`; optional sanitized details and manual-review ID only when backend knows them;
- feature/blocker states remain explicit, including M7/M8/M10 and production write=false.

Raw remote errors, secret refs, DB URLs, credentials, private material and sensitive report bodies are not frontend contracts.
