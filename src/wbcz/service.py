from __future__ import annotations

import hashlib
from pathlib import Path

from .control_engine import decide, validate_owner_inn
from .event_store import EventStore
from .models import CheckResult, Decision, ImportReport, KiState, Outcome
from .true_api import TrueApiClient
from .wb_parser import MAX_FILE_BYTES, WorkbookError, parse_excel


class ImportService:
    def __init__(self, store: EventStore) -> None:
        self._store = store

    def import_file(self, path: str | Path) -> ImportReport:
        file = Path(path)
        with file.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            self._store.audit(
                "IMPORT_FAILED", "file", file.name,
                {"error": "Файл превышает 50 MiB"},
            )
            raise WorkbookError("Файл превышает допустимый размер 50 MiB")
        fingerprint = hashlib.sha256(data).hexdigest()
        existing = self._store.existing_import(fingerprint)
        if existing is not None:
            self._store.audit("IMPORT_REPEATED", "file", fingerprint, {})
            return existing
        try:
            parsed = parse_excel(data)
        except WorkbookError as exc:
            self._store.audit(
                "IMPORT_FAILED", "file", fingerprint,
                {"filename": file.name, "error": str(exc)},
            )
            raise
        return self._store.import_workbook(fingerprint, file.name, parsed)


class DryRunService:
    """Read KI state, calculate, persist preview. No mutation dependencies.

    There is intentionally no dry_run=False flag and no live implementation.
    Local READY/ALREADY_DONE or document status NEVER substitutes for a lookup.
    State decisions neither establish historical order nor document readiness.
    """

    def __init__(
        self, store: EventStore, client: TrueApiClient, own_inn: str,
        *, source: str = "mock",
    ) -> None:
        validate_owner_inn(own_inn)
        if not source:
            raise ValueError("Источник проверки обязателен")
        self._store = store
        self._client = client
        self._own_inn = own_inn
        self._source = source

    def check_event(self, event_id: str) -> CheckResult:
        event = self._store.get_event(event_id)
        state: KiState | None = None
        try:
            response = self._client.get_ki_state(event.kiz)
            if not isinstance(response, KiState):
                raise TypeError("TrueApiClient вернул не KiState")
            state = response
            outcome = decide(event, state, self._own_inn)
        except Exception as exc:
            # External adapter boundary; DB persistence errors are not swallowed.
            outcome = Outcome(
                Decision.ERROR,
                "STATE_LOOKUP_OR_NORMALIZATION_FAILED",
                f"{type(exc).__name__}: {exc}"[:2000],
            )
        return self._store.save_check(
            event_id, state, outcome, source=self._source,
        )

    def check_all(self) -> list[CheckResult]:
        # Display order only. Independent current-state checks for ALL events,
        # including undated ones; not historical replay or a submit queue.
        return [self.check_event(event.event_id) for event in self._store.events()]
