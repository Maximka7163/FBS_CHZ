# Printing Printer Profiles — Phase B

Task: `PRINTING-PRINTER-PROFILES-001`

Phase B adds read-only Windows printer discovery and an explicit server-side PrinterProfile allowlist. It does **not** submit a print job to Windows, call physical print APIs, print a retained FULL KM, acquire marking codes from production SUZ, or enable production physical execution.

Accepted parent: `PRINTING-SENSITIVE-DELIVERY-FOUNDATION-001` at `0f801adbd97dedd10613835c0d5f338965fdb1cd`.

## Boundary

Canonical Phase-B flow:

`ADMIN/OWNER -> discovery request -> typed printing-agent-v2 job -> bounded Windows observation -> sanitized typed result -> server observation -> explicit profile approval`

A discovered device is not automatically an approved printer. Only an explicitly approved `PrinterProfile` can be considered by future Phase-C physical execution.

Phase A remains unchanged:

`encrypted M8 vault -> participant-bound HPKE delivery -> Windows process memory -> hash ACK`

Phase B discovery never needs a FULL KM and never decrypts the M8 vault.

## Local identity versus server identity

Exact Windows device identity remains local to the Agent process:

- exact queue name;
- server/share identifier;
- port identifier;
- raw DEVMODE/capability bytes.

The Agent derives two opaque values:

- `agent_printer_id`: stable opaque identifier for the local queue identity;
- `local_printer_fingerprint`: SHA-256 evidence over exact local queue/driver/port and capability evidence.

The server never receives an exact queue path, UNC path, port path, raw DEVMODE, driver file path, or arbitrary printer command.

Server-visible printer text is sanitized and bounded:

- `display_name_sanitized`;
- `driver_name_sanitized`.

A connection-style queue name is reduced to its display leaf before it can cross the Agent boundary.

## Windows discovery adapter

The read-only Windows adapter uses:

- `EnumPrinters(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS)`, level 4, for queue enumeration;
- bounded detailed inspection for individual queues;
- `OpenPrinter/GetPrinter` only for read-only metadata;
- a printer DC plus `GetDeviceCaps` for DPI, physical media and printable-area evidence.

There is no physical document lifecycle call in Phase B.

Potentially blocking discovery is isolated from the Agent polling/network loop by bounded worker executors. Enumeration has a timeout, per-printer inspection has a timeout, printer count is bounded, and one unavailable or slow connection cannot block the rest of the result.

Hosted Windows CI only requires the adapter to load and enumeration to handle zero or more queues safely. No physical hardware is required.

## printing-agent-v2 discovery protocol

Capability:

`PRINT_DISCOVER_PRINTERS`

Closed operations:

- `LIST`
- `CAPABILITIES`

Inputs contain only:

- `contract_version=printing-agent-v2`;
- operation;
- discovery request ID;
- optional opaque `agent_printer_id` for `CAPABILITIES`.

The protocol has no browser-supplied queue name, path, URL, shell command, raw DEVMODE, ZPL/EPL/CPCL or other arbitrary printer-language payload.

An Agent without `PRINT_DISCOVER_PRINTERS` cannot receive a discovery job.

## Durable state

Migration:

`0019_printing_printer_profiles`

down revision:

`0018_printing_sensitive_delivery`

Phase B adds:

- `printer_discovery_runs`;
- `printer_discovery_observations`;
- `printer_profiles`.

All durable state is organisation/participant/AgentBinding scoped.

The generic `agent_jobs` closed type set is extended only with `PRINTER_DISCOVERY`. Its payload contains the typed IDs-only discovery contract, never FULL KM or arbitrary device paths.

### PrinterProfile

An approved profile contains only sanitized/typed evidence:

- opaque Agent printer ID;
- safe local fingerprint/hash;
- sanitized display/driver names;
- X/Y DPI;
- media width/height;
- orientation;
- physical pixel dimensions;
- printable-area pixel dimensions;
- physical X/Y offsets;
- capability hash/revision;
- state;
- last-seen timestamp.

No raw queue/UNC/port/DEVMODE/command field exists in the profile schema.

## Explicit allowlist and state transitions

A discovery observation is not automatically usable.

ADMIN/OWNER approval is required to create or reapprove a profile. Phase B reuses the existing `PRINT_TEMPLATES_MANAGE` permission instead of adding another RBAC permission.

States:

- `ACTIVE`: approved evidence is still observed exactly and passes basic Phase-B device checks;
- `STALE`: the same opaque local printer now reports a different local fingerprint/capability hash;
- `MISSING`: an approved printer is unavailable or no longer present in a completed LIST result;
- `INCOMPATIBLE`: observed geometry/DPI cannot satisfy printing-v1 device rules;
- `DISABLED`: explicitly disabled by ADMIN/OWNER.

Changed hardware/driver/capability evidence is never silently copied into the approved profile. The approved fingerprint and geometry remain unchanged while the profile is `STALE`. Explicit reapproval advances `capability_revision` and adopts the newly observed evidence.

If exact approved evidence returns unchanged, the profile may become active again. A disabled profile remains disabled until explicitly handled by future policy.

## Browser-safe DTO

Browser profile APIs expose only:

- profile ID;
- sanitized display name;
- sanitized driver display name;
- state;
- X/Y DPI;
- media dimensions;
- orientation;
- printable-area dimensions and offsets;
- last-seen timestamp;
- capability revision;
- synthetic-test capability state.

They do not expose:

- exact queue/UNC/share name;
- port path;
- raw DEVMODE;
- local fingerprint;
- arbitrary command data.

Foreign tenant/participant profile IDs are returned through the existing non-enumerating not-found boundary.

## DPI, media and printable-area compatibility

Phase-B template compatibility is a pure validation primitive. It does not render or spool a production FULL KM.

Printing-v1 device rule:

`dpi_x == dpi_y`

Supported validation range follows the accepted renderer boundary: 150–1200 DPI. Representative 203, 300 and 600 DPI devices are covered by tests.

For the selected immutable TemplateVersion:

`label_width_px = round(label_width_mm * dpi / 25.4)`

`label_height_px = round(label_height_mm * dpi / 25.4)`

For its DataMatrix element:

`module_pixels = round(module_size_mm * dpi / 25.4)`

`effective_module_mm = module_pixels * 25.4 / dpi`

The effective module size must stay inside the accepted printing foundation range. The built-in synthetic preview fixture is used only to validate that the configured DataMatrix element can contain a standards-compatible rendered symbol plus its accepted quiet zone at that DPI. No M8 or production marking payload is used.

Compatibility also requires:

- selected profile is ACTIVE;
- template media dimensions match the approved profile media within the bounded physical tolerance;
- label pixel dimensions do not exceed the physical media;
- all template elements remain inside the reported printable rectangle;
- no automatic scale-to-fit behavior.

Explicit results include:

- `COMPATIBLE`;
- `PRINTER_DPI_UNSUPPORTED`;
- `PRINTER_MEDIA_TEMPLATE_MISMATCH`;
- `PRINT_LAYOUT_OUTSIDE_PRINTABLE_AREA`;
- `DATAMATRIX_MODULE_SIZE_UNSUPPORTED`;
- `PRINTER_PROFILE_STALE`;
- `PRINTER_PROFILE_MISSING`;
- `PRINTER_PROFILE_INCOMPATIBLE`;
- `PRINTER_PROFILE_DISABLED`.

Phase C must repeat all relevant profile/template checks at the irreversible physical execution boundary and must recheck the exact payload-specific rendered symbol before spool submission.

## APIs

Authenticated tenant-scoped browser APIs provide:

- profile list;
- profile detail;
- discovery request;
- discovery status and sanitized observations;
- explicit observation approval;
- profile disable;
- profile refresh/resync;
- template/profile compatibility validation.

Profile mutation/discovery administration uses CSRF protection and `PRINT_TEMPLATES_MANAGE`. Read/status/compatibility uses `PRINT_READ`.

Machine-only v2 routes provide:

- next typed discovery job;
- sanitized typed discovery result.

They require the participant-bound Agent credential and are not authorized by a browser session cookie.

## Synthetic test-print contract

Phase B defines only the closed contract identity:

`TEST_PRINT_SYNTHETIC`

with:

`synthetic_fixture_version=SELLARI_SYNTHETIC_LABEL_V1`

There is no arbitrary barcode/marking payload input.

The only Phase-B execution result is:

`PHYSICAL_EXECUTION_BLOCKED_PHASE_C`

with `physical_printer_called=false`.

Actual synthetic physical output is Phase C work.

## Print-job integration boundary

Phase B provides `validate_future_execution_profile(...)`, which binds future execution validation to:

- exact tenant/participant;
- exact approved profile ID;
- exact AgentBinding when supplied;
- ACTIVE profile state;
- immutable TemplateVersion compatibility.

The existing pre-spool print-job foundation is **not** rewired to cross into physical execution in this milestone. Phase C must replace the old logical placeholder behavior with the exact approved profile ID/fingerprint before introducing any irreversible spool boundary.

## Audit

Phase B adds:

- `PRINTER_DISCOVERY_REQUESTED`;
- `PRINTER_DISCOVERY_COMPLETED`;
- `PRINTER_PROFILE_CREATED`;
- `PRINTER_PROFILE_UPDATED`;
- `PRINTER_PROFILE_DISABLED`;
- `PRINTER_PROFILE_STALE`.

Allowed metadata is limited to safe IDs, AgentBinding ID, safe hashes, state, DPI/media summaries, counts, revisions and safe reason codes.

Audit never contains exact queue/port/DEVMODE, FULL KM, rendered marking code, or arbitrary printer command.

## Feature gates

The independent gates remain authoritative:

- `WBCZ_PRINTING_ENABLED`;
- `WBCZ_PRINT_EXECUTION_ENABLED`;
- `WBCZ_SUZ_FULL_KM_REMOTE_ACQUISITION_ENABLED`.

The production invariant is unchanged:

`production + WBCZ_PRINT_EXECUTION_ENABLED=true -> startup rejection`

Phase B does not enable production physical execution.

Remote production SUZ FULL-KM acquisition remains blocked independently.

## Strict Phase C boundary

Not implemented in Phase B:

- physical label output;
- StartDoc/StartPage/EndDoc physical lifecycle;
- spool submission or spool-status tracking;
- arbitrary WritePrinter/raw printer-language output;
- production FULL KM/KIZ printing;
- production execution activation;
- automatic physical reprint;
- physical completion claims;
- production SUZ acquisition/reacquisition;
- guessed SUZ wire;
- deployment.

Those require a separate Phase-C acceptance.
