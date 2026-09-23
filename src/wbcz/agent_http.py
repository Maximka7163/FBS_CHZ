from __future__ import annotations

from dataclasses import asdict, dataclass
import http.client
import json
import re
from pathlib import Path
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from .windows_agent import (
    AGENT_FETCH_PATH,
    AGENT_RESULT_PATH,
    AgentAuthError,
    AgentBackendChannel,
    AgentJob,
    AgentJobType,
    AgentResult,
    AgentSecurityError,
    VpsAgentBroker,
)


_RESULT_PATH_RE = re.compile(r"^/api/agent/v1/jobs/([A-Za-z0-9._:-]{1,128})/result$")
_REPORT_ARTIFACT_PATH_RE = re.compile(r"^/api/agent/v1/report-artifacts/(upl_[A-Fa-f0-9]{32})$")
REPORT_ARTIFACT_INGRESS_PATH = "/api/agent/v1/report-artifacts/{artifact_upload_id}"
AGENT_ENROLL_PATH = "/api/agent/v2/enroll"
AGENT_RUNTIME_CONFIG_PATH = "/api/agent/v2/runtime-config"
AGENT_CERTIFICATES_PATH = "/api/agent/v2/certificates"


@dataclass(frozen=True, slots=True)
class AgentProtocolResponse:
    status: int
    body: bytes = b""
    headers: Mapping[str, str] | None = None


class AgentHttpSender(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> AgentProtocolResponse:
        ...

    def upload_file(
        self,
        path: str,
        *,
        headers: Mapping[str, str],
        source_path: Path,
    ) -> AgentProtocolResponse:
        ...


def _job_to_json(job: AgentJob) -> bytes:
    payload = asdict(job)
    payload["job_type"] = job.job_type.value
    payload["cises"] = list(job.cises)
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _job_from_json(raw: bytes) -> AgentJob:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentSecurityError("invalid agent job JSON") from exc
    if not isinstance(data, dict):
        raise AgentSecurityError("agent job must be an object")
    try:
        data["job_type"] = AgentJobType(data["job_type"])
        data["cises"] = tuple(data.get("cises") or ())
        job = AgentJob(**data)
    except (KeyError, TypeError, ValueError) as exc:
        raise AgentSecurityError("invalid agent job contract") from exc
    job.validate()
    return job


def _result_to_json(result: AgentResult) -> bytes:
    payload = result.safe_dict()
    payload["cises"] = list(result.cises)
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _result_from_json(raw: bytes) -> AgentResult:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentSecurityError("invalid agent result JSON") from exc
    if not isinstance(data, dict):
        raise AgentSecurityError("agent result must be an object")
    data["cises"] = tuple(data.get("cises") or ())
    try:
        return AgentResult(**data)
    except TypeError as exc:
        raise AgentSecurityError("invalid agent result contract") from exc


class StdlibHttpsAgentSender:
    """Outbound HTTPS client to Sellari backend, restricted to agent endpoints."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        connection_factory: Any = http.client.HTTPSConnection,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("agent backend URL must be HTTPS")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("agent backend URL must be an origin without path/query")
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.timeout = timeout
        self._connection_factory = connection_factory

    @staticmethod
    def _allowed(method: str, path: str) -> bool:
        if method in {"HEAD", "GET"} and path == AGENT_FETCH_PATH:
            return True
        if method == "GET" and path == AGENT_RUNTIME_CONFIG_PATH:
            return True
        if method == "POST" and (
            _RESULT_PATH_RE.fullmatch(path) is not None
            or path in {AGENT_ENROLL_PATH, AGENT_CERTIFICATES_PATH}
        ):
            return True
        return method == "PUT" and _REPORT_ARTIFACT_PATH_RE.fullmatch(path) is not None

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> AgentProtocolResponse:
        method = method.upper()
        if not self._allowed(method, path):
            raise AgentSecurityError("arbitrary VPS endpoint denied")
        connection = self._connection_factory(
            self.host, self.port, timeout=self.timeout
        )
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            response = connection.getresponse()
            return AgentProtocolResponse(
                int(response.status),
                response.read(),
                {str(k): str(v) for k, v in response.headers.items()},
            )
        finally:
            connection.close()

    def upload_file(
        self,
        path: str,
        *,
        headers: Mapping[str, str],
        source_path: Path,
    ) -> AgentProtocolResponse:
        if not self._allowed("PUT", path):
            raise AgentSecurityError("arbitrary VPS upload endpoint denied")
        if not source_path.is_file():
            raise AgentSecurityError("report artifact source is not a file")
        size = source_path.stat().st_size
        connection = self._connection_factory(self.host, self.port, timeout=self.timeout)
        try:
            connection.putrequest("PUT", path)
            for name, value in {**dict(headers), "Content-Length": str(size)}.items():
                connection.putheader(name, value)
            connection.endheaders()
            with source_path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    connection.send(chunk)
            response = connection.getresponse()
            return AgentProtocolResponse(
                int(response.status),
                response.read(),
                {str(k): str(v) for k, v in response.headers.items()},
            )
        finally:
            connection.close()


class OutboundAgentHttpClient(AgentBackendChannel):
    """Concrete agent protocol. No cookies/browser session and no generic request API."""

    def __init__(self, sender: AgentHttpSender) -> None:
        self.sender = sender

    @staticmethod
    def _headers(machine_token: str, *, json_body: bool = False) -> dict[str, str]:
        if not machine_token:
            raise AgentAuthError("machine token is required")
        headers = {
            "Authorization": "Bearer " + machine_token,
            "Accept": "application/json",
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    @staticmethod
    def _json_object(response: AgentProtocolResponse, label: str) -> dict[str, Any]:
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentSecurityError(f"invalid {label} response") from exc
        if not isinstance(value, dict):
            raise AgentSecurityError(f"invalid {label} response")
        return value

    def runtime_config(self, machine_token: str) -> dict[str, Any]:
        response = self.sender.request(
            "GET", AGENT_RUNTIME_CONFIG_PATH, headers=self._headers(machine_token)
        )
        if response.status != 200:
            raise AgentAuthError(
                "agent backend rejected runtime config"
                if response.status in (401, 403)
                else f"agent backend runtime config HTTP {response.status}"
            )
        return self._json_object(response, "runtime config")

    def report_certificates(
        self,
        machine_token: str,
        *,
        cryptopro_available: bool,
        selected_thumbprint: str | None,
        candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload = {
            "cryptopro_available": bool(cryptopro_available),
            "selected_thumbprint": selected_thumbprint,
            "candidates": candidates,
        }
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        response = self.sender.request(
            "POST",
            AGENT_CERTIFICATES_PATH,
            headers={
                **self._headers(machine_token, json_body=True),
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        if response.status != 200:
            raise AgentAuthError(
                "agent backend rejected certificate inventory"
                if response.status in (401, 403)
                else f"agent backend certificate inventory HTTP {response.status}"
            )
        return self._json_object(response, "certificate inventory")

    def check_auth(self, machine_token: str) -> None:
        response = self.sender.request(
            "HEAD", AGENT_FETCH_PATH, headers=self._headers(machine_token)
        )
        if response.status != 204:
            raise AgentAuthError(
                "agent backend rejected machine auth"
                if response.status in (401, 403)
                else f"agent backend preflight HTTP {response.status}"
            )

    def fetch_one(self, machine_token: str) -> AgentJob | None:
        response = self.sender.request(
            "GET", AGENT_FETCH_PATH, headers=self._headers(machine_token)
        )
        if response.status == 204:
            return None
        if response.status != 200:
            raise AgentAuthError(
                "agent backend rejected job fetch"
                if response.status in (401, 403)
                else f"agent backend fetch HTTP {response.status}"
            )
        return _job_from_json(response.body)

    def submit_result(self, machine_token: str, result: AgentResult) -> None:
        path = AGENT_RESULT_PATH.format(job_id=result.job_id)
        body = _result_to_json(result)
        response = self.sender.request(
            "POST",
            path,
            headers={
                **self._headers(machine_token, json_body=True),
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        if response.status not in (202, 204):
            raise AgentAuthError(
                "agent backend rejected result"
                if response.status in (401, 403)
                else f"agent backend result HTTP {response.status}"
            )

    def upload_report_artifact(
        self,
        machine_token: str,
        metadata: Mapping[str, Any],
        path: Path,
    ) -> None:
        upload_id = metadata.get("artifact_upload_id")
        if not isinstance(upload_id, str) or _REPORT_ARTIFACT_PATH_RE.fullmatch(
            REPORT_ARTIFACT_INGRESS_PATH.format(artifact_upload_id=upload_id)
        ) is None:
            raise AgentSecurityError("invalid artifact upload id")
        report_job_id = metadata.get("local_report_job_id")
        result_id = metadata.get("result_id")
        if not isinstance(report_job_id, str) or not isinstance(result_id, str):
            raise AgentSecurityError("report artifact binding metadata missing")
        headers = {
            **self._headers(machine_token),
            "Content-Type": str(metadata.get("content_type") or "application/zip"),
            "X-Report-Job-Id": report_job_id,
            "X-Remote-Result-Id": result_id,
        }
        part = metadata.get("result_part_id")
        if part is not None:
            headers["X-Remote-Result-Part-Id"] = str(part)
        response = self.sender.upload_file(
            REPORT_ARTIFACT_INGRESS_PATH.format(artifact_upload_id=upload_id),
            headers=headers,
            source_path=path,
        )
        if response.status not in (202, 204):
            raise AgentAuthError(
                "agent backend rejected artifact"
                if response.status in (401, 403)
                else f"agent backend artifact HTTP {response.status}"
            )


class OutboundAgentEnrollmentClient:
    """One exact unauthenticated endpoint used only to exchange a short-lived enrollment token."""

    def __init__(self, sender: AgentHttpSender) -> None:
        self.sender = sender

    def exchange(
        self,
        *,
        enrollment_token: str,
        installation_id: str,
        participant_inn: str,
        protocol_version: str,
        agent_version: str,
        supported_job_types: list[str],
        supported_capabilities: list[str],
    ) -> dict[str, Any]:
        payload = {
            "enrollment_token": enrollment_token,
            "installation_id": installation_id,
            "participant_inn": participant_inn,
            "protocol_version": protocol_version,
            "agent_version": agent_version,
            "supported_job_types": list(supported_job_types),
            "supported_capabilities": list(supported_capabilities),
        }
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        response = self.sender.request(
            "POST",
            AGENT_ENROLL_PATH,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        if response.status not in (200, 201):
            raise AgentAuthError("agent enrollment rejected")
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentSecurityError("invalid enrollment response") from exc
        if not isinstance(value, dict):
            raise AgentSecurityError("invalid enrollment response")
        return value


class VpsAgentHttpBoundary:
    """Isolated server-side protocol adapter; mount only under /api/agent/v1/."""

    def __init__(self, broker: VpsAgentBroker) -> None:
        self.broker = broker

    @staticmethod
    def _bearer(headers: Mapping[str, str]) -> str:
        # Header lookup is case-insensitive; Cookie is intentionally ignored.
        auth = next(
            (value for name, value in headers.items() if name.casefold() == "authorization"),
            "",
        )
        prefix = "Bearer "
        if not auth.startswith(prefix) or not auth[len(prefix):]:
            raise AgentAuthError("machine bearer token required")
        return auth[len(prefix):]

    def handle(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes = b"",
    ) -> AgentProtocolResponse:
        method = method.upper()
        try:
            token = self._bearer(headers)
            if method == "HEAD" and path == AGENT_FETCH_PATH:
                if body:
                    raise AgentSecurityError("agent auth check body is not allowed")
                self.broker.check_auth(token)
                return AgentProtocolResponse(204, b"", {"Cache-Control": "no-store"})
            if method == "GET" and path == AGENT_FETCH_PATH:
                if body:
                    raise AgentSecurityError("job fetch body is not allowed")
                job = self.broker.fetch_one(token)
                if job is None:
                    return AgentProtocolResponse(204, b"", {"Cache-Control": "no-store"})
                payload = _job_to_json(job)
                return AgentProtocolResponse(
                    200,
                    payload,
                    {"Content-Type": "application/json", "Cache-Control": "no-store"},
                )
            match = _RESULT_PATH_RE.fullmatch(path)
            if method == "POST" and match:
                result = _result_from_json(body)
                if result.job_id != match.group(1):
                    raise AgentSecurityError("result path job_id mismatch")
                self.broker.submit_result(token, result)
                return AgentProtocolResponse(202, b"", {"Cache-Control": "no-store"})
            raise AgentSecurityError("arbitrary agent endpoint denied")
        except AgentAuthError:
            return AgentProtocolResponse(401, b"", {"Cache-Control": "no-store"})
        except AgentSecurityError:
            return AgentProtocolResponse(400, b"", {"Cache-Control": "no-store"})
