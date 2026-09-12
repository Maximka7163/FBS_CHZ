# Web v0.5 security

## Authentication

Users are created only with the admin CLI. Passwords are Argon2id hashes. `create-user` reads the password with `getpass`; no password CLI argument and no default administrator/password exist.

Login creates a cryptographically random opaque token. PostgreSQL stores only its SHA-256 hash. The browser session cookie is HttpOnly, `SameSite=Lax`, `Path=/`, and `Secure=True` in production. Logout revokes the server-side session. Every authenticated request re-checks `users.is_active`, so a disabled user cannot continue using an existing session.

## CSRF

Unsafe HTTP requests require a double-submit CSRF token: a CSRF cookie plus matching `X-CSRF-Token`. CSRF is not globally disabled.

## Upload

Only `.xlsx` is accepted. Workbook bytes are parsed in memory and are never written under a public/static path. The core parser retains the 50 MiB file limit, 250 MiB unpacked limit, 200k-row limit, mandatory `КИЗ` sheet, real WB headers, formula/error rejection, nullable `occurred_at`, and no invented timestamps. Filename is display metadata only and never selects a filesystem path.

## Audit

Append-only actions: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGOUT`, `USER_CREATED`, `USER_DISABLED`, `FILE_IMPORTED`, `FILE_REPEATED`, `CONTROL_RUN`, `PREVIEW_CREATED`.

Do not log passwords, password hashes, session tokens, CSRF tokens, cookies, signatures, PINs or private keys.

## Production marking boundary

`/api/capabilities` reports `true_api=mock`, `true_api_write=false`, `document_signing=false`, `submission=false`, `windows_bridge=false`.

`wbcz_web` has no `LK_RECEIPT`, `LP_RETURN`, `/lk/documents/create`, document-signing, submission or production True API network route.

**Sellari integration = NONE. Colleague integration = NONE. Public registration = NONE.**
