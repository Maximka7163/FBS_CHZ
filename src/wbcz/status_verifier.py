from __future__ import annotations

from collections import deque
from typing import Iterable, Protocol

from .event_store import EventStore
from .models import DocumentReport, DocumentStatus


class StatusVerifier(Protocol):
    def get_document_status(self, document_id: str) -> DocumentReport:
        ...


class FakeStatusVerifier:
    def __init__(self, responses: Iterable[DocumentReport | Exception]) -> None:
        self._responses = deque(responses)
        self.calls: list[str] = []

    def get_document_status(self, document_id: str) -> DocumentReport:
        self.calls.append(document_id)
        if not self._responses:
            raise RuntimeError("Закончились mock-ответы статуса документа")
        response = self._responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response


class DocumentTracker:
    """Read-only external polling abstraction, separate from DryRunService.

    SUCCEEDED means a normalized final document status, not a cached KI state.
    A transport error is not a remote rejection and is retryable.
    """

    def __init__(self, store: EventStore, verifier: StatusVerifier) -> None:
        self._store = store
        self._verifier = verifier

    def refresh(self, document_id: str) -> DocumentReport:
        current = self._store.document_report(document_id)
        if current.status in {DocumentStatus.SUCCEEDED, DocumentStatus.REJECTED}:
            return current
        try:
            report = self._verifier.get_document_status(document_id)
            if not isinstance(report, DocumentReport):
                raise TypeError("StatusVerifier вернул не DocumentReport")
            if not isinstance(report.status, DocumentStatus):
                raise TypeError("Некорректный нормализованный статус документа")
        except Exception as exc:
            report = DocumentReport(
                DocumentStatus.VERIFICATION_ERROR,
                f"{type(exc).__name__}: {exc}"[:2000],
            )
        return self._store.update_document(document_id, report)
