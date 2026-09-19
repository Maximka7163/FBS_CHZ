from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from wbcz_web.services.production_hardening import safe_exception, sanitize_operational_data


_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_LOG = logging.getLogger("wbcz.production")


def validated_external_id(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    return value if _ID_RE.fullmatch(value) else None


def _networks(values: tuple[str, ...]):
    result = []
    for value in values:
        try:
            result.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(result)


def trusted_client_ip(peer: str | None, forwarded_for: str | None, trusted_proxy_cidrs: tuple[str, ...]) -> str | None:
    if not peer:
        return None
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return None
    networks = _networks(trusted_proxy_cidrs)
    if not any(peer_ip in network for network in networks):
        return str(peer_ip)
    if not forwarded_for:
        return str(peer_ip)
    candidate = forwarded_for.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return str(peer_ip)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Request/correlation IDs, trusted proxy source, size guard, security headers and safe JSON logs."""

    async def dispatch(self, request: Request, call_next):
        config = request.app.state.config
        request_id = validated_external_id(request.headers.get("X-Request-ID")) or ("req_" + uuid4().hex)
        correlation_id = validated_external_id(request.headers.get("X-Correlation-ID")) or request_id
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id
        peer = request.client.host if request.client else None
        request.state.client_ip = trusted_client_ip(
            peer,
            request.headers.get("X-Forwarded-For"),
            tuple(getattr(config, "trusted_proxy_cidrs", ()) or ()),
        )

        content_type = (request.headers.get("content-type") or "").lower()
        content_length = request.headers.get("content-length")
        artifact_ingress = request.url.path.startswith("/api/agent/v1/report-artifacts/")
        if content_length and not artifact_ingress and "application/json" in content_type:
            try:
                too_large = int(content_length) > int(config.normal_json_body_limit_bytes)
            except ValueError:
                too_large = True
            if too_large:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": {"code": "REQUEST_BODY_TOO_LARGE", "message": "Request body exceeds configured JSON limit", "correlation_id": correlation_id}},
                )
                self._headers(request, response)
                return response

        started = time.monotonic()
        outcome = "success"
        error_code = None
        try:
            response = await call_next(request)
            if response.status_code >= 500:
                outcome = "error"
            elif response.status_code >= 400:
                outcome = "rejected"
            self._headers(request, response)
            return response
        except BaseException as exc:
            outcome = "exception"
            error_code = type(exc).__name__
            _LOG.error(json.dumps(sanitize_operational_data({
                "timestamp": time.time(),
                "level": "ERROR",
                "service": "wbcz-web",
                "build_sha": config.build_sha,
                "request_id": request_id,
                "correlation_id": correlation_id,
                "route": getattr(request.scope.get("route"), "path", "<unmatched>"),
                "method": request.method,
                "outcome": outcome,
                **safe_exception(exc, error_code=error_code),
            }), separators=(",", ":"), ensure_ascii=True))
            raise
        finally:
            latency = max(0.0, time.monotonic() - started)
            if outcome != "exception":
                route = getattr(request.scope.get("route"), "path", "<unmatched>")
                record = sanitize_operational_data({
                    "timestamp": time.time(),
                    "level": "INFO",
                    "service": "wbcz-web",
                    "build_sha": config.build_sha,
                    "request_id": request_id,
                    "correlation_id": correlation_id,
                    "route": route,
                    "method": request.method,
                    "latency_ms": round(latency * 1000, 3),
                    "outcome": outcome,
                    "error_code": error_code,
                })
                _LOG.info(json.dumps(record, separators=(",", ":"), ensure_ascii=True))

    @staticmethod
    def _headers(request: Request, response) -> None:
        config = request.app.state.config
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Correlation-ID"] = request.state.correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'"
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if config.environment == "production" and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
