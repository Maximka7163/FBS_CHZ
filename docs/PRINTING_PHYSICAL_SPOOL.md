# Printing Physical Spool — Phase C

Task: `PRINTING-PHYSICAL-SPOOL-001`

Accepted parent: `PRINTING-PRINTER-PROFILES-001` at
`13acd00460ce8f7dbfc87280ebcdd3e14123a837`.

Phase C implements the **local Windows physical-spool runtime** for an already
authorized `PrintExecution`. It does not activate production printing. The
production startup invariant remains authoritative:

`production + WBCZ_PRINT_EXECUTION_ENABLED=true -> startup rejection`

Remote SUZ FULL-KM acquisition remains independently blocked.

## End-to-end boundary

The accepted runtime is:

`PrintExecution authorization -> Phase-A HPKE delivery -> Agent memory -> exact SHA-256 -> server ACK -> immutable TemplateVersion + ACTIVE PrinterProfile -> final-DPI render -> independent decode/equality -> local durable SPOOL_SUBMITTING -> backend durable SPOOL_SUBMITTING -> Windows GDI raster spool -> safe outcome`

FULL KM arrives only through the accepted Phase-A HPKE reservation. It is never
placed into the ordinary print control DTO, generic Agent job, database, audit,
local replay SQLite, temp file, raster persistence, log or browser response.

The Agent keeps the decrypted payload only in process memory long enough to:
1. verify the exact payload hash;
2. submit the Phase-A ACK;
3. receive an exact server ACK;
4. render/verify/spool in the same process-memory lifetime.

There is no second payload redisclosure for Phase C.

## Execution state machine

Migration `0020_printing_physical_spool`, down revision
`0019_printing_printer_profiles`, extends the accepted `PrintExecution` state
machine to:

- `REQUESTED`
- `AUTHORIZED`
- `PAYLOAD_AVAILABLE`
- `PAYLOAD_ISSUED`
- `PAYLOAD_DELIVERED`
- `RENDERED_VERIFIED`
- `SPOOL_SUBMITTING`
- `SPOOL_JOB_CREATED`
- `SPOOLER_ACCEPTED`
- `FAILED_PRE_SPOOL`
- `BLOCKED`
- `UNKNOWN_AFTER_SPOOL`
- `CANCELLED_PRE_SPOOL`

The migration stores safe spool evidence only:

- approved printer profile ID/fingerprint;
- renderer version;
- Windows spool JobId;
- normalized Windows status;
- rendered/spool transition timestamps.

It does **not** add FULL KM, raster bytes, queue/UNC/port path, raw DEVMODE,
spool-file bytes or printer-language data.

## Irreversible SPOOL_SUBMITTING boundary

Before any Windows API may create a physical side effect, the Agent must have
verified:

- exact FULL KM SHA-256 equals the immutable execution payload hash;
- immutable TemplateVersion layout hash equals the execution layout hash;
- exact approved `PrinterProfile` is ACTIVE;
- same organisation, participant and AgentBinding;
- current local printer fingerprint equals the approved fingerprint;
- actual DPI/media/printable area remain compatible;
- renderer/layout/protocol versions are exact;
- final GS1 DataMatrix independently decodes to the exact input bytes.

Then the Agent:

1. durably stores local replay state `SPOOL_SUBMITTING` with SQLite
   `synchronous=FULL`, transaction commit and filesystem fsync;
2. asks the backend to durably transition the same execution to
   `SPOOL_SUBMITTING`;
3. only after that acknowledgement may invoke GDI.

A restart that observes a local irreversible state must **not** automatically
repeat the physical submission.

## Exact renderer and decode verification

Phase C reuses the accepted Sellari renderer in `wbcz.printing`. There is no
second marking-code generator.

The DataMatrix path remains:

`exact FULL KM bytes -> libdmtx GS1 DataMatrix -> integer device module pixels`

For final printing:

- final label dimensions are calculated at the approved printer DPI;
- DataMatrix is generated directly at final integer module pixels;
- the generated symbol is pasted into the final raster 1:1;
- DataMatrix pixels are never resized afterwards;
- quiet zone is preserved;
- immutable label/media geometry and printable-area clipping rules are checked;
- copies are fixed at 1.

The complete label is an in-memory final-size RGB raster. It is not written to a
temp file.

Before spool submission the final raster is independently decoded by
`zxing-cpp`. Acceptance requires:

- decoded symbology identifier is GS1 DataMatrix (`]d2`);
- decoded bytes are **exactly equal** to input FULL KM;
- ASCII 29 separators remain exact.

A mismatch is a pre-spool block. GDI is not called.

Runtime compatibility evidence includes:

- printing contract version;
- layout schema version;
- renderer version;
- libdmtx version;
- decoder version.

### Windows libdmtx runtime packaging

Sellari continues to use the same `wbcz.printing` ctypes renderer and libdmtx C API;
there is no alternate marking-code renderer. The native runtime is supplied by the
pinned `arbez-dmtx==0.0.2` platform wheel, whose bundled libdmtx is validated at
runtime as version >= 0.7.5.

On Windows the loader accepts only the DLL located inside the installed
`arbez_dmtx._libdmtx` package directory. It does not fall back to CWD, PATH,
a browser/server path or an operator-selected arbitrary DLL. The self-contained
Windows Agent build uses PyInstaller `--collect-all arbez_dmtx` so the DLL is
already present before the Agent starts; no network download occurs during render
or physical printing.

Linux/macOS retain the accepted system-lib fallback for compatibility if the
bundled provider is unavailable. A missing/untrusted renderer runtime is reported
as `PRINT_RENDERER_RUNTIME_UNAVAILABLE / LIBDMTX_RUNTIME_UNAVAILABLE`; it is not
misclassified as a DataMatrix module-size or DPI incompatibility.

`PRINTING_PHYSICAL_V1` is advertised only when the physical runtime reports the
required renderer/decoder capability.

## Windows GDI raster model

The physical adapter is closed and raster-only.

Canonical pipeline:

`opaque agent_printer_id -> local queue resolution -> local fingerprint recheck -> CreateDC(WINSPOOL) -> StartDoc -> StartPage -> SetDIBitsToDevice 1:1 -> EndPage -> EndDoc`

The adapter accepts only an internally generated validated raster. It does not
accept caller printer-language bytes.

Forbidden inputs include:

- arbitrary queue/path from browser or server job;
- RAW datatype;
- `WritePrinter` arbitrary bytes;
- ZPL/EPL/CPCL/PostScript;
- shell/PowerShell;
- filesystem path;
- remotely supplied raw DEVMODE.

The exact local Windows queue remains Agent-only.

A positive `StartDoc` return is captured as the Windows spool JobId and is
persisted/reported immediately as `SPOOL_JOB_CREATED`.

## Copies and batch semantics

P0 copies are fixed to exactly 1.

One `PrintJobItem` maps to one Windows spool job. A multi-item Sellari
`PrintJob` is executed item-by-item. Items are not bundled into one ambiguous
Windows spool document.

A second label requires an explicit reprint operation.

## Local replay

The physical replay SQLite stores only:

- execution ID;
- print-job-item ID;
- delivery reservation ID;
- payload/layout hashes;
- printer profile ID/fingerprint;
- state;
- optional Windows spool JobId;
- normalized Windows status;
- timestamps;
- safe error code.

It never stores:

- FULL KM;
- raster;
- exact queue/path;
- raw DEVMODE;
- spool data.

The local irreversible/no-auto-retry states include:

- `SPOOL_SUBMITTING`;
- `SPOOL_JOB_CREATED`;
- `SPOOLER_ACCEPTED`;
- `UNKNOWN_AFTER_SPOOL`;
- a post-boundary `FAILED_PRE_SPOOL` caused by a provably unsuccessful
  `StartDoc`.

The name `FAILED_PRE_SPOOL` means the implementation could prove no Windows
spool job was created; it does **not** make the same execution automatically
retryable after the local irreversible intent was already durably recorded.

## Ambiguity rules

### Before SPOOL_SUBMITTING

A deterministic payload/hash/layout/profile/render/decode/compatibility failure
has no physical side effect. It may be blocked or failed pre-spool according to
the exact failure.

### StartDoc definite failure

If `StartDoc` returns failure and no job can exist, the backend may record
`FAILED_PRE_SPOOL`.

The execution is still not blindly replayed by the Agent because its local
`SPOOL_SUBMITTING` intent was already durable. Any later retry policy must be
an explicit higher-level action.

### Positive StartDoc then failure

Once a positive Windows job ID exists, any later uncertainty is
`UNKNOWN_AFTER_SPOOL` unless absence of possible output can be proven.

Examples:

- StartPage failure after positive StartDoc;
- raster-output failure;
- EndPage failure;
- EndDoc failure/exception;
- Agent crash after job creation;
- Agent crash after Windows acceptance but before backend reporting.

These do not return to a retryable state.

### EndDoc success

`EndDoc` success becomes `SPOOLER_ACCEPTED`.

This means Windows accepted the document into its printing subsystem. It does
not prove:

- paper physically emerged;
- the label was readable;
- the printer completed the job successfully.

## Honest user-facing semantics

Canonical browser success wording is:

**«Отправлено на принтер»**

The API explicitly exposes:

`physical_output_proven=false`

The implementation does not use “Напечатано” as proof of physical output.

Windows spool flags such as PRINTED/COMPLETE are normalized as
`SPOOLER_REPORTED_COMPLETE`; they are not treated as physical proof.

Printer conditions such as OFFLINE, PAPER_OUT or USER_INTERVENTION after
submission never trigger another automatic print.

## PRINT_STATUS

Typed operation:

`PRINT_STATUS`

The control contains only:

- execution ID;
- approved printer profile ID/fingerprint;
- opaque Agent printer ID;
- already known Windows spool JobId.

The Agent resolves the opaque printer ID locally, rechecks the fingerprint and
queries only that known job. The result contains normalized safe state,
observation time and safe error code. It cannot query an arbitrary browser
queue/path.

## Explicit reprint after ambiguity

`UNKNOWN_AFTER_SPOOL` never resets the original execution and never causes an
automatic second print.

An explicit `PRINT_EXECUTE` reprint requires the user to acknowledge:

**«Предыдущая попытка могла попасть в очередь печати. Повторная печать может создать второй экземпляр этикетки.»**

That action creates:

- a new PrintJob;
- a new PrintJobItem;
- a new PrintExecution;
- a new delivery reservation;
- a new audit sequence.

The ambiguous execution remains immutable historical evidence.

Default explicit reprint continues to use the original immutable TemplateVersion.

## Synthetic physical test

Phase C implements the local typed synthetic physical runtime for:

`TEST_PRINT_SYNTHETIC`

with the only accepted fixture:

`SELLARI_SYNTHETIC_LABEL_V1`

It uses the same final renderer/decode/GDI path but does not access M8 and does
not accept caller marking payloads.

CI uses the fake raster spool adapter. Hosted Windows CI loads the real GDI and
status adapters without calling StartDoc, so CI never manufactures a physical
or persistent print artifact.

A representative hardware test, if later performed manually, must use only the
built-in synthetic fixture.

## Backend/API boundary

Browser APIs expose safe execution status/history and the explicit ambiguous
reprint action. They never return FULL KM or exact Windows queue information.

Machine-only Phase-C APIs provide:

- next physical control;
- immutable render contract;
- render-verified transition;
- durable spool-submitting transition;
- safe physical result;
- typed status control;
- normalized status update.

All machine routes require the accepted participant-bound Agent bearer.

The VPS/backend does not implement GDI or spool submission.

## Audit

Phase C adds:

- `PRINT_RENDER_VERIFIED`
- `PRINT_SPOOL_SUBMITTED`
- `PRINT_SPOOL_ACCEPTED`
- `PRINT_EXECUTION_FAILED`
- `PRINT_EXECUTION_UNKNOWN`

Allowed evidence is limited to IDs, payload/layout hashes, AgentBinding ID,
printer profile ID/fingerprint, Windows spool JobId, normalized status, safe
error, renderer/decoder version and attempt number.

Audit never contains FULL KM, rendered DataMatrix/raster, exact queue/port,
raw DEVMODE or spool bytes.

## Feature gates and production status

The independent gates remain:

- `WBCZ_PRINTING_ENABLED`
- `WBCZ_PRINT_EXECUTION_ENABLED`
- `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED`

Phase C implementation acceptance is **not** production activation.

At the end of this milestone:

- production physical print execution remains OFF;
- production startup with print execution enabled remains rejected;
- production SUZ remote FULL-KM acquisition remains blocked independently.

A later separate decision/task is required before either production boundary can
change.

## Strict exclusions

Phase C does not:

- mutate main;
- rewrite migrations 0017, 0018 or 0019;
- deploy or run production migrations;
- enable production physical execution;
- use a real production FULL KM/KIZ;
- acquire/reacquire production SUZ codes;
- guess SUZ wire contracts;
- allow arbitrary browser printer paths;
- allow arbitrary PDL/RAW commands;
- automatically duplicate an ambiguous label;
- claim physical print certainty;
- change SEARCHABLE != PRINTABLE.
