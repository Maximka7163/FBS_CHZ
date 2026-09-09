from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import sys
from typing import Sequence

from .event_store import EventStore
from .models import KiState
from .service import DryRunService, ImportService
from .true_api import FakeTrueApiClient


def _load_states(path: str) -> dict[str, KiState]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Mock-файл должен содержать объект КИЗ -> внутреннее состояние")
    result: dict[str, KiState] = {}
    fields = {"status", "statusEx", "withdrawReason", "ownerInn"}
    for kiz, state in value.items():
        if not isinstance(kiz, str) or not isinstance(state, dict):
            raise ValueError("Некорректная запись mock-состояния")
        if "status" not in state or set(state) - fields:
            raise ValueError(f"Некорректные поля mock-состояния для {kiz!r}")
        if not isinstance(state["status"], str):
            raise ValueError("status должен быть строкой")
        if any(item is not None and not isinstance(item, str) for item in state.values()):
            raise ValueError("Поля состояния должны быть строками или null")
        result[kiz] = KiState(**state)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WB / marking core. Offline mock dry-run only.",
    )
    parser.add_argument("--db", default="wbcz.sqlite")
    commands = parser.add_subparsers(dest="command", required=True)
    import_command = commands.add_parser("import", help="Импорт Excel, без проверки ЧЗ")
    import_command.add_argument("file")
    preview_command = commands.add_parser("preview", help="Dry-run по локальным mock-данным")
    preview_command.add_argument("--states", required=True)
    preview_command.add_argument("--owner-inn", required=True)
    commands.add_parser(
        "history", help="История WB; неизвестные даты — null, порядок не угадывается",
    )
    commands.add_parser("audit", help="Локальный журнал аудита")
    args = parser.parse_args(argv)
    try:
        with EventStore(args.db) as store:
            exit_code = 0
            if args.command == "import":
                report = ImportService(store).import_file(args.file)
                output = {
                    **asdict(report),
                    "issues": store.import_issues(report.fingerprint),
                }
                exit_code = 2 if report.rejected_rows else 0
            elif args.command == "preview":
                client = FakeTrueApiClient(_load_states(args.states))
                results = DryRunService(
                    store, client, args.owner_inn, source="offline-fixture",
                ).check_all()
                output = {
                    "dry_run": True,
                    "external_mutations": 0,
                    "document_readiness_checked": False,
                    "historical_reconciliation_performed": False,
                    "results": [asdict(result) for result in results],
                }
                exit_code = 2 if any(
                    result.outcome.error is not None for result in results
                ) else 0
            elif args.command == "history":
                events = store.events()
                ambiguity = {
                    kiz: store.history_order_ambiguous(kiz)
                    for kiz in {event.kiz for event in events}
                }
                output = [
                    {
                        "event_id": event.event_id,
                        **event.to_dict(),
                        "history_order_ambiguous": ambiguity[event.kiz],
                    }
                    for event in events
                ]
            else:
                output = store.audit_entries()
            print(json.dumps(output, ensure_ascii=False, indent=2))
            return exit_code
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
