from __future__ import annotations

import re
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


def normalize_wb_kiz(value: str) -> str:
    """Map a WB sticker КИЗ to the bare queryable ЧЗ КИ part.

    WB archive stickers may carry an aggregated clothing code: AI 01 + GTIN,
    AI 21 + serial, then GS (chr 0x1d) separated AI 91/92 aggregation segments.
    The official True API /cises/info contract accepts bare codes 18..74
    characters WITHOUT brackets around AI 01/21; aggregate tail segments are
    not queryable there. Sep–Oct 2026 real ЛК processing proved the bare
    01+GTIN+21+serial part is accepted by ЧЗ as the document code. Codes that
    already satisfy the strict contract pass unchanged; bracketed AI forms are
    expanded to bare form. Anything that does not decode deterministically is
    rejected — never guessed.
    """
    if not isinstance(value, str):
        raise ValueError("WB КИЗ must be a string")
    raw = value.strip(" \t\r\n")
    if not raw:
        raise ValueError("WB КИЗ is empty")
    if "\x1d" in raw or "\ufffd" in raw:
        first_element = re.split("[\x1d\ufffd]", raw)[0]
        match = (
            re.fullmatch(r"\(01\)(\d{14})\(21\)(.+)", first_element)
            or re.fullmatch(r"01(\d{14})21(.+)", first_element)
        )
        if match is None:
            raise ValueError(
                "WB КИЗ aggregate code must start with GS1 AI 01 + 14-digit GTIN "
                "and AI 21 + serial"
            )
        return normalize_cis(f"01{match.group(1)}21{match.group(2)}")
    bracketed = re.fullmatch(r"\(01\)(\d{14})\(21\)(.+)", raw)
    if bracketed is not None:
        return normalize_cis(f"01{bracketed.group(1)}21{bracketed.group(2)}")
    return normalize_cis(raw)


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
