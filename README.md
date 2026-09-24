# WB FBS → Честный знак

v0.4 combines the existing offline-first WB FBS core with the first production **LIVE READ-ONLY** True API path.

Core properties remain unchanged: Python 3.12, local SQLite, existing `wb_parser`, `EventStore`, deterministic `event_id`, backend-only `control_engine` decisions, and no business rules in the frontend.

## v0.4 safety boundary

LIVE mode may only:

- authenticate with UKEP through `GET /api/v3/true-api/auth/key` and `POST /api/v3/true-api/auth/simpleSignIn`;
- read KI states through `POST /api/v3/true-api/cises/info?pg=lp`.

Production document creation/signing/submission is not implemented. The production transport uses an exact allowlist and raises `ProductionMutationDisabled` before HTTP I/O for every other route, including `/lk/documents/create`.

Authentication challenge signing is a separate boundary. `WindowsCryptoProAuthSigner` exposes only `sign_auth_challenge(...)`; there is no production document-signing method in v0.4.

## WB FBS evidence guard

For the standard WB archive flow, READY recommendations require both the current normalized KI state and WB evidence:

- sale + in circulation + receipt evidence + our owner → `READY_TO_WITHDRAW`;
- sale + already withdrawn for distance sale → `ALREADY_DONE`;
- sale + in circulation + missing receipt → `MANUAL_REVIEW / SALE_RECEIPT_MISSING`;
- return + already in circulation → `ALREADY_DONE`;
- return + withdrawn for distance sale + our owner → `READY_TO_RETURN` even when the RETURN row has no sale receipt/date.

Owner mismatch, ambiguous WB history, unknown CHZ state/statusEx and wrong product-group context are fail-safe manual-review outcomes. Receipt/date evidence is required only before a new SALE withdrawal; a RETURN decision is based on fresh CHZ state and DISTANCE withdrawal reason.

## Installation: Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[ui,test]"
```

Frontend:

```powershell
cd frontend
npm install
npm run typecheck
npm run build
npm run dev
```

Backend (offline by default):

```powershell
.\.venv\Scripts\python.exe -m wbcz_ui --db .\wbcz-ui.sqlite
```

Open `http://127.0.0.1:5173`.

For the first UKEP/production read-only test follow `docs/LIVE_READ_ONLY_WINDOWS_TEST.md` exactly.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The suite preserves the original v0.2 regression coverage, UI/application safety checks, operation-mode checks, and v0.4 read-only transport/auth/evidence tests.

## Real WB regression

`REF_WB_archive_9.xlsx` is expected to import as:

- 238 events;
- 238 unique KIZ;
- 76 sales;
- 162 returns;
- 68 events with date;
- 170 without date;
- 0 rejected rows;
- sales: 63 with receipt evidence, 13 without;
- returns: 5 with receipt evidence, 157 without.

The old synthetic READY counts are not an acceptance target after the evidence guard.

## Data and identity

Missing WB date is stored as Python `None`, JSON `null`, and SQLite `NULL`. Known WB timestamps are normalized to UTC. `event_id` remains SHA-256 over canonical normalized event content with prefix `wb-event:v1:`; filename, source row number, import timestamp and fingerprint are not part of event identity.

Repeated normalized events deduplicate in `events` while every import occurrence remains in `import_rows`. Multiple events for one KIZ are preserved. If their chronology cannot be established safely, application checks force `MANUAL_REVIEW / HISTORY_ORDER_AMBIGUOUS`.

## SQLite and audit

SQLite remains the working-state source; frontend `localStorage` is not used for business state. Existing schema v2 stores nullable `occurred_at`.

LIVE True API metadata is additionally written to the configured JSONL audit with timestamp, LIVE mode, endpoint, KI count, HTTP status and request/correlation ID when available. Tokens, full auth signatures, private keys and PINs are not logged.

## Limitations

See `docs/KNOWN_LIMITATIONS.md`. In particular, standard WB FBS archive mode does not detect a later warehouse resale after an FBS refusal; future reconciliation with the WB financial report is required.

v0.4 does not implement `LK_RECEIPT`, `LP_RETURN`, production document signing, document creation, cancellation, retry submission, or any other production mutation.
