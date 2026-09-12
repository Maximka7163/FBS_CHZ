# Known limitations

## WB FBS archive coverage

Standard WB FBS archive mode does not detect subsequent warehouse resale after an FBS refusal. Future reconciliation with WB financial report is required.

This v0.4 stage does not implement that reconciliation scenario.

## Live True API v0.4

v0.4 is production **read-only**. It can authenticate with UKEP and request current KI information for product group `lp`, but it cannot create, sign, submit, retry, cancel, or poll production documents.

Only these production calls are technically allowed by the transport:

- `GET /auth/key`
- `POST /auth/simpleSignIn`
- `POST /cises/info?pg=lp`

All other production endpoints are rejected locally before an HTTP request is made.

## Activity location

A future production withdraw flow will require an explicitly saved activity location. The application model already distinguishes `FIAS_ID` for IP and `KPP` for a legal entity, but v0.4 does not use that setting because it creates no documents.

## Unknown True API values

Unknown or unsupported status/statusEx/product-group information is never interpreted optimistically. It is converted to a manual-review outcome or a read error.
