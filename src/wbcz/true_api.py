from __future__ import annotations

from typing import Iterable, Mapping, Protocol

from .models import KiState


CISES_INFO_MAX_CODES = 1000
CISES_INFO_MIN_LENGTH = 18
CISES_INFO_MAX_LENGTH = 74


class TrueApiError(RuntimeError):
    pass


def normalize_cis(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("CIS must be a string")
    normalized = value.strip()
    if not CISES_INFO_MIN_LENGTH <= len(normalized) <= CISES_INFO_MAX_LENGTH:
        raise ValueError("CIS length must be 18..74 characters")
    return normalized


def normalize_cises(values: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(normalize_cis(value) for value in values)
    if not 1 <= len(normalized) <= CISES_INFO_MAX_CODES:
        raise ValueError("cises/info batch must contain 1..1000 cises")
    return normalized


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
