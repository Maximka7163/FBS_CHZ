from __future__ import annotations

from typing import Mapping, Protocol

from .models import KiState


class TrueApiError(RuntimeError):
    pass


class TrueApiClient(Protocol):
    """Read-only boundary. No endpoints, authentication or raw API JSON."""

    def get_ki_state(self, kiz: str) -> KiState:
        ...


class FakeTrueApiClient:
    """Offline test double; responses may be states or simulated exceptions."""

    def __init__(self, responses: Mapping[str, KiState | Exception]) -> None:
        self.responses = dict(responses)
        self.calls: list[str] = []

    def get_ki_state(self, kiz: str) -> KiState:
        self.calls.append(kiz)
        if kiz not in self.responses:
            raise TrueApiError("Для КИЗ отсутствует mock-состояние")
        response = self.responses[kiz]
        if isinstance(response, Exception):
            raise response
        return response
