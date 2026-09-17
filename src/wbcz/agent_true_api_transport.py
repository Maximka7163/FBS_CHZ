from __future__ import annotations

import http.client
from typing import Any

from wbcz.edo_lite import build_edo_read_spec, is_allowed_edo_read_target
from wbcz.true_api import normalize_cises
from wbcz.windows_agent import (
    AgentHttpResponse,
    AgentSecurityError,
    ProductionAgentTrueApiTransport as _BaseTransport,
)
from wbcz_ui.live_true_api import (
    GostTlsUnavailable,
    PRODUCTION_HOST,
    ReadOnlyTrueApiTransport,
    TrueApiError,
)


class ProductionAgentTrueApiTransport(_BaseTransport):
    """Windows-only transport with typed M7 EDO reads and no generic EDO proxy."""

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

    def edo_read(
        self,
        job_type: str,
        payload: dict[str, Any],
        *,
        bearer_token: str,
    ) -> AgentHttpResponse:
        spec = build_edo_read_spec(job_type, payload)
        if not is_allowed_edo_read_target(spec):
            raise AgentSecurityError("arbitrary M7 EDO target denied")
        if not bearer_token:
            raise AgentSecurityError("True API bearer token is required")
        headers = {
            "Accept": "application/json, application/xml, text/xml, application/pdf, application/zip, application/octet-stream",
            "Host": PRODUCTION_HOST,
            "Connection": "close",
            "Authorization": "Bearer " + bearer_token,
        }
        connection: http.client.HTTPConnection | None = None
        self.rate_limiter.acquire()
        try:
            marker = self.tunnel.session_marker()
            connection = self._connection_factory(
                "127.0.0.1", self.tunnel.local_port, timeout=self.timeout
            )
            connection.putrequest("GET", spec.target, skip_host=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            status = int(response.status)
            raw = response.read()
            self.tunnel.assert_gost_session(marker)
            self.audit.record(
                method="GET",
                endpoint=spec.audit_endpoint,
                cis_count=0,
                http_status=status,
                request_id=ReadOnlyTrueApiTransport._request_id(response.headers),
            )
            return AgentHttpResponse(
                status=status,
                body=raw,
                headers={str(k): str(v) for k, v in response.headers.items()},
            )
        except GostTlsUnavailable:
            raise
        except (OSError, http.client.HTTPException) as exc:
            self.audit.record(
                method="GET",
                endpoint=spec.audit_endpoint,
                cis_count=0,
                http_status=None,
                error=type(exc).__name__,
            )
            raise TrueApiError("CryptoPro GOST TLS agent transport error") from exc
        finally:
            if connection is not None:
                connection.close()
