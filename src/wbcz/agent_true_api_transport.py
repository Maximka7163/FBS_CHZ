from __future__ import annotations

from typing import Any

from wbcz.true_api import normalize_cises
from wbcz.windows_agent import AgentSecurityError, ProductionAgentTrueApiTransport as _BaseTransport


class ProductionAgentTrueApiTransport(_BaseTransport):
    """Windows-only production transport with the official v.726 cises/info body."""

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
