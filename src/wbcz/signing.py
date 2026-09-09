from __future__ import annotations

from typing import Protocol


class SigningAdapter(Protocol):
    def sign(self, payload: bytes) -> bytes:
        ...


class FakeSigningAdapter:
    """Not cryptography, not a valid signature, no certificate interaction."""

    def __init__(self) -> None:
        self.calls = 0

    def sign(self, payload: bytes) -> bytes:
        self.calls += 1
        return b"TEST-ONLY-NOT-A-SIGNATURE:" + payload
