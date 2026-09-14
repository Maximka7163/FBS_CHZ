from __future__ import annotations

"""Public Windows-agent API.

The accepted P0 agent implementation is kept in ``_windows_agent_base`` while
this boundary overrides the official v.726 ``cises/info`` request contract.
Callers importing ``wbcz.windows_agent.ProductionAgentTrueApiTransport`` always
receive the strict root-array implementation.
"""

from typing import Any

from ._windows_agent_base import *  # noqa: F401,F403
from . import _windows_agent_base as _base
from .true_api import normalize_cises


class ProductionAgentTrueApiTransport(_base.ProductionAgentTrueApiTransport):
    """Windows-only True API transport with strict v.726 cises/info encoding."""

    def cises_info(self, cises: tuple[str, ...], *, bearer_token: str) -> Any:
        try:
            normalized = normalize_cises(cises)
        except ValueError as exc:
            raise AgentSecurityError(str(exc)) from exc
        return self.request_json(
            "POST",
            "/cises/info",
            params={"pg": "lp"},
            body=list(normalized),
            bearer_token=bearer_token,
            cis_count=len(normalized),
        )


def __getattr__(name: str):
    # Preserve compatibility for internal/private test helpers without exposing
    # a second public production transport implementation.
    return getattr(_base, name)
