# Web v0.5 architecture

`web/v0.5-isolated-service` is a standalone marking-control service. **Sellari integration = NONE. Colleague integration = NONE. Public registration = NONE.**

The existing `wbcz` package remains the domain core. `wbcz_web` is a separate infrastructure/application layer and reuses `wbcz.models`, `wbcz.wb_parser`, `wbcz.control_engine` and the read-only `wbcz.true_api` boundary. Business decisions remain backend-only.

## Runtime

Browser → Vite/static frontend → FastAPI `wbcz_web` → dedicated PostgreSQL.

v0.5 True API is a deterministic read-only mock. There is no production True API network client in `wbcz_web`. Windows Bridge is a future separate client; CryptoPro, UKEP, GOST TLS and the private key stay on Windows.

## Modules

- `api/`: REST contracts, authentication/CSRF dependencies.
- `auth/`: Argon2id passwords and opaque token helpers.
- `repositories/`: PostgreSQL access.
- `services/`: auth, WB import, deterministic mock control, preview.
- `models/`: SQLAlchemy persistence models.

PostgreSQL tables are `users`, `sessions`, `imports`, `import_rows`, `events`, `control_runs`, `checks`, `previews`, `preview_items`, `audit_log`. `control_runs` groups checks from one explicit user action. `preview_items` stores an immutable preview composition based on persisted backend decisions.

Each upload creates an import occurrence. Core `event_id` deduplicates events globally. Re-uploading the same file creates a repeated import occurrence with `repeated_of_id`, `0 new_events` and duplicate counts without duplicating `events`.

Public endpoints are only health, CSRF bootstrap and login. Workspace/API data requires a valid server-side session. There is no `/register`, `/signup` or password-reset endpoint.
