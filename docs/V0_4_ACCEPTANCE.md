# v0.4 LIVE READ-ONLY acceptance boundary

This file marks the final v0.4 code boundary for acceptance testing.

## Production transport allowlist

Only these calls may reach production True API:

1. `GET /api/v3/true-api/auth/key`
2. `POST /api/v3/true-api/auth/simpleSignIn`
3. `POST /api/v3/true-api/cises/info?pg=lp`

Every other route is rejected locally with `ProductionMutationDisabled` before HTTP I/O.

## Signing boundary

`WindowsCryptoProAuthSigner` signs only authentication challenges through `sign_auth_challenge(...)`. v0.4 has no production document-signing/submission interface.

## Mutation boundary

v0.4 contains no callable production path for:

- `/lk/documents/create`;
- `LK_RECEIPT` submission;
- `LP_RETURN` submission;
- production document signing;
- cancellation;
- submission retry.

## UI boundary

LIVE mode is labelled `Реальный контроль ЧЗ · отправка отключена`. The user may check one KI, selected KIs, or the full imported WB file and may inspect an operation preview. Preview is calculation only.

## Regression rule

The old synthetic `64 / 140` READY counts are not an acceptance target after the WB FBS evidence guard. Missing receipt evidence must block new READY operations while preserving `ALREADY_DONE` for already-correct current KI states.
