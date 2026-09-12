"""Public v0.4 LIVE READ-ONLY True API boundary.

The bulk of the implementation lives in ``_live_true_api_base`` so the final
GOST-session proof can stay tiny, explicit and independently auditable.
Only a negotiated MSSPI ``SECPKG_ATTR_CIPHER_INFO: CipherSuite`` marker is
accepted; configuration text containing GOST is never session proof.
"""
from __future__ import annotations

import re
from typing import Any

from . import _live_true_api_base as _base
from ._live_true_api_base import *  # noqa: F401,F403


_NEGOTIATED_GOST_CIPHER_RE = re.compile(
    r"SECPKG_ATTR_CIPHER_INFO\s*:\s*CipherSuite\s*:\s*(?:0x)?(c100|c101|c102)\b",
    re.IGNORECASE,
)


class CryptoProGostTlsTunnel(_base.CryptoProGostTlsTunnel):
    """CryptoPro tunnel with fail-closed proof of the negotiated GOST session."""

    def _negotiated_gost_cipher_id(self, start: int = 0) -> str | None:
        path = self._log_path
        if path is None or not path.exists():
            return None
        with path.open("rb") as stream:
            stream.seek(start)
            text = stream.read().decode("utf-8", errors="replace")
        match = _NEGOTIATED_GOST_CIPHER_RE.search(text)
        return match.group(1).upper() if match else None

    def _gost_session_seen(self, start: int = 0) -> bool:
        # A config line such as ``ciphers = GOST...`` or an offered cipher list
        # is not evidence. Only the negotiated MSSPI CipherSuite diagnostic,
        # emitted after the per-request log marker, is accepted.
        return self._negotiated_gost_cipher_id(start) is not None

    def diagnostics(self) -> dict[str, Any]:
        result = super().diagnostics()
        result["gost_session_verified"] = self._gost_session_seen()
        result["negotiated_gost_cipher_id"] = self._negotiated_gost_cipher_id()
        return result


class ReadOnlyTrueApiTransport(_base.ReadOnlyTrueApiTransport):
    """Public transport using the hardened tunnel.

    ``opener`` is accepted only as a backwards-compatible test keyword and is
    deliberately ignored; it can never replace the CryptoPro/MSSPI production
    path or create an ordinary HTTPS fallback.
    """

    def __init__(self, *args: Any, opener: Any = None, **kwargs: Any) -> None:
        del opener
        super().__init__(*args, **kwargs)


# Classes defined in the base module resolve these globals at runtime. Patch
# them once so LiveTrueApiClient.from_config and every public constructor use
# the hardened tunnel/transport. The broad legacy proof is not callable via the
# active production path or the public wbcz_ui.live_true_api module.
_base.CryptoProGostTlsTunnel = CryptoProGostTlsTunnel
_base.ReadOnlyTrueApiTransport = ReadOnlyTrueApiTransport
