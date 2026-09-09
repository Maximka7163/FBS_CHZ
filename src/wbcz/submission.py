from __future__ import annotations

from typing import Protocol


class SubmissionService(Protocol):
    def submit(self, signed_payload: bytes, *, idempotency_key: str) -> str:
        ...


class FakeSubmissionService:
    """In-memory fake only. Never used by the dry-run execution path."""

    def __init__(self) -> None:
        self.calls = 0
        self._documents: dict[str, tuple[bytes, str]] = {}

    @property
    def created_count(self) -> int:
        return len(self._documents)

    def submit(self, signed_payload: bytes, *, idempotency_key: str) -> str:
        self.calls += 1
        if not idempotency_key:
            raise ValueError("Нужен idempotency_key")
        previous = self._documents.get(idempotency_key)
        if previous is not None:
            payload, document_id = previous
            if payload != signed_payload:
                raise ValueError("Повтор ключа с другим содержимым")
            return document_id
        document_id = f"fake-document-{len(self._documents) + 1}"
        self._documents[idempotency_key] = (signed_payload, document_id)
        return document_id
