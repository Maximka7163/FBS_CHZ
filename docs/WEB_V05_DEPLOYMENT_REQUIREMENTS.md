# Web v0.5 deployment requirements

Requirements only. This document intentionally contains no VPS-changing deployment commands.

- Dedicated service identity/process/container for `wbcz_web`.
- Dedicated PostgreSQL database and credentials; DB port must not be public.
- HTTPS termination and production secure-cookie mode.
- Environment-provided `WBCZ_DATABASE_URL`, `WBCZ_OWN_INN`, `WBCZ_ENV=production`.
- Alembic migrations as an explicit release step.
- PostgreSQL backup/restore procedure.
- No public registration routes and no default account/password.
- Initial users created manually with admin CLI.
- No Windows private keys, CryptoPro containers or PINs on VPS.
- Future Windows Bridge remains an independent client boundary.
- Production True API write capability remains disabled until separately reviewed.

**Sellari integration = NONE. Colleague integration = NONE. Public registration = NONE.**
