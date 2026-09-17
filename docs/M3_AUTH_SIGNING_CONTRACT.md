# M3 Auth / Signing hardening contract

Official source baseline: **True API v726.0 (04.09.2026)**.

## Authentication

Primary UUID flow remains Windows-local: `GET /api/v3/true-api/auth/key` -> validate `uuid` + `data` -> sign the exact UTF-8 challenge using the locally selected CryptoPro certificate in **attached** mode -> `POST /api/v3/true-api/auth/simpleSignIn` with `uuid`, attached signature in `data`, participant `inn`, and `unitedToken=true`.

The bearer credential is strictly `uuidToken`; an optional/legacy `token` field is not used as the credential. `expireDate` must include timezone information and is normalized to UTC. The UUID token is kept only in Windows process memory.

There is no refresh endpoint. Local expiry/near-expiry clears the cached UUID session and the next request repeats the full `/auth/key` -> sign -> `/auth/simpleSignIn` flow. An HTTP 401 also invalidates the local session; no automatic write replay is introduced.

The backend cannot provide an auth challenge or arbitrary bytes to a signer. Agent jobs have no auth-sign operation, challenge field, arbitrary bytes-to-sign field, or certificate override. Challenge provenance comes directly from `/auth/key` inside the Windows runtime.

## Signing modes

Authentication and business-document signing remain separate contracts:

- `WindowsCryptoProAuthSigner`: attached CMS (`cryptcp -signf -attached ...`).
- `WindowsCryptoProDocumentSigner`: detached signature; `-attached` is intentionally absent.

The document signer accepts only the existing P0 business types (`LK_RECEIPT`, `LP_RETURN`) for `pg=lp`, checks participant binding, validates SHA-256 over the exact immutable bytes, and revalidates that those bytes are UTF-8 JSON with an object root. The certificate thumbprint comes from local trusted runtime configuration and cannot be overridden by an agent job.

## Error and secret handling

Authentication HTTP errors reuse the accepted M1 safe transport-error model for JSON, XML, text, and empty bodies. Diagnostics remain bounded and sanitized. Bearer/UUID token, machine token, PIN, and private-key material are not persisted or logged.

## Boundaries preserved

- Windows outbound-only; no inbound listener.
- CryptoPro CSP + stunnel_msspi/MSSPI GOST TLS architecture unchanged.
- Private-key export: **NO**.
- PIN in backend/DB/job/log/browser: **NO**.
- Direct VPS True API: **NO**.
- Generic HTTP/True API proxy: **NO**.
- Generic signing RPC: **NO**.
- Production write remains default-off/hard-disabled pending runtime contract tests.
- No new document types, product groups, mutation operations, or frontend capability.
- No DB migration and no auth-session persistence.

## Runtime-only acceptance

This task does **not** claim real certificate discovery, real CryptoPro CSP/Rutoken/PIN prompting, real GOST TLS negotiation, or real True API authentication. Those remain runtime-only checks for an explicitly authorized Windows environment and are not faked in CI.
