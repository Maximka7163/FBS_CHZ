# v0.4 LIVE READ-ONLY acceptance boundary

## Production GOST TLS

Production Python code does not use `urllib`, `urlopen`, `ssl.SSLContext` or `HTTPSConnection` to connect to True API.

The only production TLS leg is:

```text
Python HTTPConnection -> 127.0.0.1 -> CryptoPro CSP stunnel_msspi.exe -> GOST TLS -> markirovka.crpt.ru:443
```

`stunnel_msspi.exe` runs in client mode with MSSPI enabled. The generated production configuration fixes the destination to `markirovka.crpt.ru:443`, SNI and host verification to `markirovka.crpt.ru`, requires remote certificate validation (`verify=2`), fixes TLS to 1.2, and offers only:

```text
GOST2012-GOST8912-GOST8912:GOST2001-GOST89-GOST89
```

This removes a non-GOST fallback. After each production request, v0.4 requires an explicit MSSPI negotiated-session diagnostic: `SECPKG_ATTR_CIPHER_INFO: CipherSuite: c100`, `c101`, or `c102`. A configuration line containing `GOST` is explicitly not accepted as handshake proof. If no accepted negotiated marker appears after the per-request log marker, the request fails closed with `GostTlsUnavailable`.

No `verify=0`, no certificate-validation bypass and no ordinary Python/OpenSSL production fallback exists.

## Exact production route allowlist

Only:

1. `GET /api/v3/true-api/auth/key`
2. `POST /api/v3/true-api/auth/simpleSignIn`
3. `POST /api/v3/true-api/cises/info?pg=lp`

All other routes fail with `ProductionMutationDisabled` before tunnel startup or any network call.

## Certificate/UKEP preflight

Before authentication the application validates locally:

- exact certificate thumbprint in `CurrentUser\\My`;
- private key is linked;
- certificate validity period;
- GOST public key OID;
- CryptoPro provider binding from Windows certificate provider metadata;
- availability of CryptoPro `cryptcp.exe`.

The diagnostic does not export or invoke the private key and does not read PIN.

## Authentication signing

The authentication challenge is signed only with CryptoPro `cryptcp.exe` using the selected certificate in CurrentUser/My. The command creates an attached strict DER CMS and includes the certificate. No `-pin` value is passed by the application.

The signer exposes only `sign_auth_challenge(...)`. v0.4 has no callable production `sign_document`, `sign_payload_for_submission`, `submit_signed_document` or equivalent mutation path.

## Explicit LIVE sequence

Production interaction is deliberately split:

```text
TLS preflight:       GET /auth/key only; no signer
Authentication:      GET /auth/key -> cryptcp auth signature -> POST /auth/simpleSignIn
One-KIZ control:     POST /cises/info?pg=lp only after explicit authentication
```

Authentication never auto-runs `cises/info`, operation preview or production-document creation.

## One-KIZ diagnostics

For a one-KIZ LIVE control, the frontend receives only normalized data:

- status;
- statusEx;
- withdrawReason;
- ownerInn and owner match;
- productGroup;
- backend decision;
- reason code/error.

Raw True API payload, token and signature stay outside the frontend boundary.

## Mutation boundary

v0.4 contains no callable production path for:

- `/lk/documents/create`;
- `LK_RECEIPT` submission;
- `LP_RETURN` submission;
- production document signing;
- cancellation;
- submission retry.

Preview is only a calculation from persisted backend decisions.
