from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
from typing import Any, Callable, Mapping, Protocol

from wbcz.cis_inventory import (
    M1_READ_JOB_TYPES,
    SharedRateLimiter,
    build_cis_to_product_info_request,
    build_read_spec,
    is_allowed_read_target,
    parse_json_bytes,
    parse_success_payload,
    safe_transport_error,
    validate_m1_job_payload,
)
from wbcz.reference_products import (
    M2_READ_JOB_TYPES,
    build_reference_read_spec,
    is_allowed_reference_target,
    parse_reference_success_payload,
    validate_m2_job_payload,
)
from wbcz.document_lifecycle import (
    M4_READ_JOB_TYPES,
    build_document_read_spec,
    capture_create_response,
    is_allowed_document_target,
    parse_m4_success_payload,
    validate_m4_job_payload,
)
from wbcz.turnover import M5_AGENT_WRITE_JOB_TYPES, M5_DOCUMENT_TYPES
from wbcz.aggregation import M6_DOCUMENT_TYPES
from wbcz.models import Decision, KiState, canonical_json, utc_now
from wbcz.true_api import normalize_cises
from wbcz.write_pipeline import (
    CreateCategory,
    CreateResult,
    DuplicateSubmitBlocked,
    InvalidWriteOperation,
    SigningResponse,
    WriteOperationStore,
    WriteState,
    classify_poll_status,
)
from wbcz_ui.live_true_api import (
    AuthSession,
    CryptoProGostTlsTunnel,
    GostTlsUnavailable,
    JsonlLiveAudit,
    PRODUCTION_BASE_PATH,
    PRODUCTION_HOST,
    ReadOnlyTrueApiTransport,
    TrueApiAuthenticator,
    TrueApiCisesInfoAdapter,
    TrueApiError,
    TrueApiHttpError,
    TrueApiProtocolError,
    WindowsCryptoProCertificateInspector,
    _find_cryptopro_binary,
)


P0_PG = "lp"
P0_CREATE_TARGET = "/api/v3/true-api/lk/documents/create?pg=lp"
_POLL_TARGET_RE = re.compile(r"^/api/v4/true-api/doc/([A-Za-z0-9._:-]{1,256})/info$")
_P0_READ_ONLY = frozenset({
    ("GET", "/auth/key"),
    ("POST", "/auth/simpleSignIn"),
    ("POST", "/cises/info"),
})


class AgentSecurityError(RuntimeError):
    pass


class AgentAuthError(AgentSecurityError):
    pass


class AgentReplayConflict(AgentSecurityError):
    pass


class AgentProductionWriteDisabled(AgentSecurityError):
    pass


class AgentJobType(StrEnum):
    CIS_CHECK = "CIS_CHECK"
    LK_RECEIPT = "LK_RECEIPT"
    LP_RETURN = "LP_RETURN"
    LP_INTRODUCE_GOODS = "LP_INTRODUCE_GOODS"
    LK_INDI_COMMISSIONING = "LK_INDI_COMMISSIONING"
    LP_GOODS_IMPORT = "LP_GOODS_IMPORT"
    CROSSBORDER = "CROSSBORDER"
    LP_INTRODUCE_OST = "LP_INTRODUCE_OST"
    LK_CONTRACT_COMMISSIONING = "LK_CONTRACT_COMMISSIONING"
    LP_FTS_INTRODUCE = "LP_FTS_INTRODUCE"
    LK_REMARK = "LK_REMARK"
    WRITE_OFF = "WRITE_OFF"
    LK_RECEIPT_CANCEL = "LK_RECEIPT_CANCEL"
    AGGREGATION_DOCUMENT = "AGGREGATION_DOCUMENT"
    SETS_AGGREGATION = "SETS_AGGREGATION"
    REAGGREGATION_DOCUMENT = "REAGGREGATION_DOCUMENT"
    DISAGGREGATION_DOCUMENT = "DISAGGREGATION_DOCUMENT"
    ATK_AGGREGATION = "ATK_AGGREGATION"
    ATK_TRANSFORMATION = "ATK_TRANSFORMATION"
    ATK_DISAGGREGATION = "ATK_DISAGGREGATION"
    POLL_DOCUMENT = "POLL_DOCUMENT"
    CIS_INFO = "CIS_INFO"
    CIS_SEARCH = "CIS_SEARCH"
    CIS_HISTORY = "CIS_HISTORY"
    CIS_AGGREGATED_LIST = "CIS_AGGREGATED_LIST"
    CIS_AGGREGATION_HISTORY = "CIS_AGGREGATION_HISTORY"
    PRODUCT_INFO = "PRODUCT_INFO"
    CIS_TO_PRODUCT = "CIS_TO_PRODUCT"
    PARTICIPANTS = "PARTICIPANTS"
    MODS_LIST = "MODS_LIST"
    TN_VED_SEARCH = "TN_VED_SEARCH"
    PRODUCT_GTIN_LIST = "PRODUCT_GTIN_LIST"
    RD_LIST = "RD_LIST"
    DOCUMENT_LIST = "DOCUMENT_LIST"
    DOCUMENT_INFO = "DOCUMENT_INFO"
    DOCUMENT_CISES = "DOCUMENT_CISES"


class AgentJobState(StrEnum):
    PENDING = "PENDING"
    LEASED = "LEASED"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True, slots=True)
class AgentJob:
    job_id: str
    job_type: AgentJobType
    operation_id: str
    pg: str
    expected_inn: str
    document_type: str | None = None
    document_sha256: str | None = None
    product_document_base64: str | None = None
    cises: tuple[str, ...] = ()
    document_id: str | None = None
    read_payload: dict[str, Any] | None = None

    def validate(self) -> None:
        if not self.job_id or not self.operation_id:
            raise AgentSecurityError("job_id and operation_id are required")
        if self.pg != P0_PG:
            raise AgentSecurityError("P0 agent allows only pg=lp")
        if not self.expected_inn:
            raise AgentSecurityError("expected_inn is required")
        if self.job_type.value in (M5_AGENT_WRITE_JOB_TYPES | M6_DOCUMENT_TYPES):
            expected_type = self.job_type.value
            if self.document_type != expected_type:
                raise AgentSecurityError("job/document type mismatch")
            if self.document_type not in (M5_DOCUMENT_TYPES | M6_DOCUMENT_TYPES):
                raise AgentSecurityError("unsupported document type")
            if not self.document_sha256 or not self.product_document_base64:
                raise AgentSecurityError("write job misses immutable document fields")
            try:
                raw = base64.b64decode(self.product_document_base64, validate=True)
            except Exception as exc:
                raise AgentSecurityError("product_document is invalid Base64") from exc
            if hashlib.sha256(raw).hexdigest() != self.document_sha256:
                raise AgentSecurityError("document_sha256 mismatch")
            try:
                json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AgentSecurityError("document bytes are not UTF-8 JSON") from exc
            if self.cises or self.document_id or self.read_payload is not None:
                raise AgentSecurityError("write job contains unrelated fields")
        elif self.job_type is AgentJobType.CIS_CHECK:
            try:
                normalized = normalize_cises(self.cises)
            except ValueError as exc:
                raise AgentSecurityError(str(exc)) from exc
            if normalized != self.cises:
                raise AgentSecurityError("CIS_CHECK cises must already be normalized")
            if any((self.document_type, self.document_sha256, self.product_document_base64, self.document_id)) or self.read_payload is not None:
                raise AgentSecurityError("CIS_CHECK contains write/poll/read fields")
        elif self.job_type is AgentJobType.POLL_DOCUMENT:
            if not self.document_id or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", self.document_id):
                raise AgentSecurityError("invalid document_id")
            if any((self.document_type, self.document_sha256, self.product_document_base64, self.cises)) or self.read_payload is not None:
                raise AgentSecurityError("POLL_DOCUMENT contains unrelated fields")
        elif self.job_type.value in M1_READ_JOB_TYPES:
            if self.read_payload is None:
                raise AgentSecurityError("M1 read job misses read_payload")
            if any((self.document_type, self.document_sha256, self.product_document_base64, self.cises, self.document_id)):
                raise AgentSecurityError("M1 read job contains P0/write fields")
            try:
                normalized = validate_m1_job_payload(self.job_type.value, self.read_payload)
            except ValueError as exc:
                raise AgentSecurityError(str(exc)) from exc
            if normalized != self.read_payload:
                raise AgentSecurityError("M1 read_payload must already be canonical")
        elif self.job_type.value in M2_READ_JOB_TYPES:
            if self.read_payload is None:
                raise AgentSecurityError("M2 read job misses read_payload")
            if any((self.document_type, self.document_sha256, self.product_document_base64, self.cises, self.document_id)):
                raise AgentSecurityError("M2 read job contains P0/write fields")
            try:
                normalized = validate_m2_job_payload(self.job_type.value, self.read_payload)
            except ValueError as exc:
                raise AgentSecurityError(str(exc)) from exc
            if normalized != self.read_payload:
                raise AgentSecurityError("M2 read_payload must already be canonical")
        elif self.job_type.value in M4_READ_JOB_TYPES:
            if self.read_payload is None:
                raise AgentSecurityError("M4 document read job misses read_payload")
            if any((self.document_type, self.document_sha256, self.product_document_base64, self.cises, self.document_id)):
                raise AgentSecurityError("M4 document read job contains P0/write fields")
            try:
                normalized = validate_m4_job_payload(self.job_type.value, self.read_payload)
            except ValueError as exc:
                raise AgentSecurityError(str(exc)) from exc
            if normalized != self.read_payload:
                raise AgentSecurityError("M4 read_payload must already be canonical")
        else:
            raise AgentSecurityError("unsupported agent job type")


@dataclass(frozen=True, slots=True)
class AgentResult:
    job_id: str
    operation_id: str
    outcome: str
    document_sha256: str | None = None
    signature_base64: str | None = None
    certificate_thumbprint: str | None = None
    certificate_subject: str | None = None
    certificate_inn: str | None = None
    certificate_valid_from: str | None = None
    certificate_valid_to: str | None = None
    http_status: int | None = None
    create_category: str | None = None
    document_id: str | None = None
    remote_status: str | None = None
    body_sha256: str | None = None
    cises: tuple[dict[str, Any], ...] = ()
    error_code: str | None = None
    error_message: str | None = None
    content_type: str | None = None
    read_result: Any | None = None
    create_response: dict[str, Any] | None = None

    def safe_dict(self) -> dict[str, Any]:
        return asdict(self)


class MachineTokenVerifier:
    """Machine auth secret is injected at runtime; it is never serialized or logged."""

    def __init__(self, token: str) -> None:
        if not isinstance(token, str) or len(token) < 16:
            raise ValueError("agent machine token must be a runtime secret >=16 chars")
        self._token = token

    def verify(self, supplied: str | None) -> None:
        if not supplied or not hmac.compare_digest(self._token, supplied):
            raise AgentAuthError("invalid agent credentials")


class AgentBackendChannel(Protocol):
    """Outbound-only Windows client boundary; no Windows listener is required."""

    def fetch_one(self, machine_token: str) -> AgentJob | None:
        ...

    def submit_result(self, machine_token: str, result: AgentResult) -> None:
        ...


AGENT_FETCH_PATH = "/api/agent/v1/jobs/next"
AGENT_RESULT_PATH = "/api/agent/v1/jobs/{job_id}/result"


@dataclass(frozen=True, slots=True)
class AgentHttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


class ProductionAgentTrueApiTransport:
    """Strict P0 production transport. It is not an arbitrary URL client/proxy."""

    def __init__(
        self,
        *,
        tunnel: CryptoProGostTlsTunnel | None = None,
        audit: JsonlLiveAudit | None = None,
        timeout: float = 30.0,
        connection_factory: Callable[..., http.client.HTTPConnection] = http.client.HTTPConnection,
        rate_limiter: SharedRateLimiter | None = None,
    ) -> None:
        self.tunnel = tunnel or CryptoProGostTlsTunnel()
        self.audit = audit or JsonlLiveAudit("windows_agent_true_api.jsonl")
        self.timeout = timeout
        self._connection_factory = connection_factory
        self.rate_limiter = rate_limiter or SharedRateLimiter()
        self._read_only = ReadOnlyTrueApiTransport(
            tunnel=self.tunnel,
            audit=self.audit,
            timeout=timeout,
            connection_factory=connection_factory,
        )

    def tls_diagnostics(self) -> dict[str, Any]:
        return self._read_only.tls_diagnostics()

    def request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        body: Any = None,
        bearer_token: str | None = None,
        cis_count: int = 0,
    ) -> Any:
        method = method.upper()
        if (method, path) not in _P0_READ_ONLY:
            raise AgentSecurityError("arbitrary True API endpoint denied")
        self.rate_limiter.acquire()
        return self._read_only.request_json(
            method,
            path,
            params=params,
            body=body,
            bearer_token=bearer_token,
            cis_count=cis_count,
        )

    def cises_info(self, cises: tuple[str, ...], *, bearer_token: str) -> Any:
        try:
            normalized = normalize_cises(cises)
        except ValueError as exc:
            raise AgentSecurityError(str(exc)) from exc
        if normalized != cises:
            raise AgentSecurityError("cises/info cises must already be normalized")
        return self.request_json(
            "POST",
            "/cises/info",
            params={"pg": "lp"},
            body=list(normalized),
            bearer_token=bearer_token,
            cis_count=len(normalized),
        )

    def m1_read(self, job_type: str, payload: dict[str, Any], *, bearer_token: str) -> AgentHttpResponse:
        if job_type == "CIS_TO_PRODUCT":
            raise AgentSecurityError("composite M1 job has no single transport request")
        spec = build_read_spec(job_type, payload)
        if not is_allowed_read_target(spec):
            raise AgentSecurityError("arbitrary True API read target denied")
        if not bearer_token:
            raise AgentSecurityError("True API bearer token is required")
        headers = {
            "Accept": "application/json, application/xml, text/xml",
            "Host": PRODUCTION_HOST,
            "Connection": "close",
            "Authorization": "Bearer " + bearer_token,
        }
        data: bytes | None = None
        if spec.body is not None:
            headers["Content-Type"] = "application/json; charset=UTF-8"
            data = json.dumps(spec.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            headers["Content-Length"] = str(len(data))
        connection: http.client.HTTPConnection | None = None
        self.rate_limiter.acquire()
        try:
            marker = self.tunnel.session_marker()
            connection = self._connection_factory("127.0.0.1", self.tunnel.local_port, timeout=self.timeout)
            connection.putrequest(spec.method, spec.target, skip_host=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders(data)
            response = connection.getresponse()
            status = int(response.status)
            raw = response.read()
            self.tunnel.assert_gost_session(marker)
            self.audit.record(
                method=spec.method,
                endpoint=spec.audit_endpoint,
                cis_count=spec.cis_count,
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
                method=spec.method,
                endpoint=spec.audit_endpoint,
                cis_count=spec.cis_count,
                http_status=None,
                error=type(exc).__name__,
            )
            raise TrueApiError("CryptoPro GOST TLS agent transport error") from exc
        finally:
            if connection is not None:
                connection.close()

    def m2_read(self, job_type: str, payload: dict[str, Any], *, bearer_token: str) -> AgentHttpResponse:
        spec = build_reference_read_spec(job_type, payload)
        if not is_allowed_reference_target(spec):
            raise AgentSecurityError("arbitrary M2 True API read target denied")
        if not bearer_token:
            raise AgentSecurityError("True API bearer token is required")
        headers = {
            "Accept": "application/json, application/xml, text/xml",
            "Host": PRODUCTION_HOST,
            "Connection": "close",
            "Authorization": "Bearer " + bearer_token,
        }
        data: bytes | None = None
        if spec.body is not None:
            headers["Content-Type"] = "application/json; charset=UTF-8"
            data = json.dumps(spec.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            headers["Content-Length"] = str(len(data))
        connection: http.client.HTTPConnection | None = None
        self.rate_limiter.acquire()
        try:
            marker = self.tunnel.session_marker()
            connection = self._connection_factory("127.0.0.1", self.tunnel.local_port, timeout=self.timeout)
            connection.putrequest(spec.method, spec.target, skip_host=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders(data)
            response = connection.getresponse()
            status = int(response.status)
            raw = response.read()
            self.tunnel.assert_gost_session(marker)
            self.audit.record(
                method=spec.method, endpoint=spec.audit_endpoint, cis_count=0,
                http_status=status, request_id=ReadOnlyTrueApiTransport._request_id(response.headers),
            )
            return AgentHttpResponse(status=status, body=raw, headers={str(k): str(v) for k, v in response.headers.items()})
        except GostTlsUnavailable:
            raise
        except (OSError, http.client.HTTPException) as exc:
            self.audit.record(method=spec.method, endpoint=spec.audit_endpoint, cis_count=0, http_status=None, error=type(exc).__name__)
            raise TrueApiError("CryptoPro GOST TLS agent transport error") from exc
        finally:
            if connection is not None:
                connection.close()

    def m4_read(self, job_type: str, payload: dict[str, Any], *, bearer_token: str) -> AgentHttpResponse:
        spec = build_document_read_spec(job_type, payload)
        if not is_allowed_document_target(spec):
            raise AgentSecurityError("arbitrary M4 True API document target denied")
        if not bearer_token:
            raise AgentSecurityError("True API bearer token is required")
        headers = {
            "Accept": "application/json, application/xml, text/xml",
            "Host": PRODUCTION_HOST,
            "Connection": "close",
            "Authorization": "Bearer " + bearer_token,
        }
        connection: http.client.HTTPConnection | None = None
        self.rate_limiter.acquire()
        try:
            marker = self.tunnel.session_marker()
            connection = self._connection_factory("127.0.0.1", self.tunnel.local_port, timeout=self.timeout)
            connection.putrequest(spec.method, spec.target, skip_host=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            status = int(response.status)
            raw = response.read()
            self.tunnel.assert_gost_session(marker)
            self.audit.record(
                method=spec.method,
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
                method=spec.method, endpoint=spec.audit_endpoint, cis_count=0,
                http_status=None, error=type(exc).__name__,
            )
            raise TrueApiError("CryptoPro GOST TLS agent transport error") from exc
        finally:
            if connection is not None:
                connection.close()

    def create_document(
        self,
        *,
        document_type: str,
        product_document_base64: str,
        signature_base64: str,
        bearer_token: str,
    ) -> AgentHttpResponse:
        if document_type not in (M5_DOCUMENT_TYPES | M6_DOCUMENT_TYPES):
            raise AgentSecurityError("unsupported document type")
        if not bearer_token:
            raise AgentSecurityError("True API bearer token is required")
        for label, value in (
            ("product_document", product_document_base64),
            ("signature", signature_base64),
        ):
            if not value or "\r" in value or "\n" in value:
                raise AgentSecurityError(f"{label} must be single-line Base64")
            try:
                base64.b64decode(value, validate=True)
            except Exception as exc:
                raise AgentSecurityError(f"{label} is invalid Base64") from exc
        return self._exact_request(
            "POST",
            P0_CREATE_TARGET,
            body={
                "document_format": "MANUAL",
                "product_document": product_document_base64,
                "type": document_type,
                "signature": signature_base64,
            },
            bearer_token=bearer_token,
            audit_endpoint="/lk/documents/create?pg=lp",
        )

    def poll_document(
        self, document_id: str, *, bearer_token: str
    ) -> AgentHttpResponse:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", document_id or ""):
            raise AgentSecurityError("invalid document_id")
        return self._exact_request(
            "GET",
            f"/api/v4/true-api/doc/{document_id}/info",
            bearer_token=bearer_token,
            audit_endpoint="/doc/{docId}/info",
        )

    def _exact_request(
        self,
        method: str,
        target: str,
        *,
        body: Any = None,
        bearer_token: str | None,
        audit_endpoint: str,
    ) -> AgentHttpResponse:
        # Private primitive. Public callers cannot choose a target.
        if target != P0_CREATE_TARGET and _POLL_TARGET_RE.fullmatch(target) is None:
            raise AgentSecurityError("arbitrary True API target denied")
        headers = {
            "Accept": "application/json",
            "Host": PRODUCTION_HOST,
            "Connection": "close",
        }
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json; charset=UTF-8"
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            headers["Content-Length"] = str(len(data))
        if bearer_token:
            headers["Authorization"] = "Bearer " + bearer_token
        connection: http.client.HTTPConnection | None = None
        self.rate_limiter.acquire()
        try:
            local_port = self.tunnel.local_port
            marker = self.tunnel.session_marker()
            connection = self._connection_factory(
                "127.0.0.1", local_port, timeout=self.timeout
            )
            connection.putrequest(method, target, skip_host=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders(data)
            response = connection.getresponse()
            status = int(response.status)
            raw = response.read()
            self.tunnel.assert_gost_session(marker)
            self.audit.record(
                method=method,
                endpoint=audit_endpoint,
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
                method=method,
                endpoint=audit_endpoint,
                cis_count=0,
                http_status=None,
                error=type(exc).__name__,
            )
            raise TrueApiError("CryptoPro GOST TLS agent transport error") from exc
        finally:
            if connection is not None:
                connection.close()


class WindowsCryptoProDocumentSigner:
    """Detached CMS/CAdES-BES-compatible document signing path; no arbitrary sign()."""

    def __init__(
        self,
        *,
        certificate_thumbprint: str,
        participant_inn: str,
        cryptcp_path: str | Path | None = None,
        inspector: Any | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        normalized = certificate_thumbprint.replace(" ", "").upper()
        if not normalized:
            raise ValueError("certificate thumbprint is required")
        if not participant_inn:
            raise ValueError("participant_inn is required")
        self.thumbprint = normalized
        self.participant_inn = participant_inn
        self._explicit_cryptcp = Path(cryptcp_path) if cryptcp_path else None
        self._runner = runner
        self.inspector = inspector or WindowsCryptoProCertificateInspector(
            normalized, cryptcp_path=cryptcp_path, runner=runner
        )

    @property
    def cryptcp(self) -> Path:
        return _find_cryptopro_binary(self._explicit_cryptcp, "cryptcp.exe")

    def sign_document_bytes(
        self,
        *,
        operation_id: str,
        document_type: str,
        pg: str,
        expected_inn: str,
        document_sha256: str,
        payload: bytes,
    ) -> tuple[str, dict[str, Any]]:
        if not operation_id:
            raise AgentSecurityError("operation_id is required")
        if document_type not in (M5_DOCUMENT_TYPES | M6_DOCUMENT_TYPES):
            raise AgentSecurityError("unsupported document type")
        if pg != P0_PG:
            raise AgentSecurityError("document signing allows only pg=lp")
        if expected_inn != self.participant_inn:
            raise AgentSecurityError("expected_inn mismatch")
        if hashlib.sha256(payload).hexdigest() != document_sha256:
            raise AgentSecurityError("document hash mismatch")
        try:
            parsed_document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentSecurityError("document bytes are not UTF-8 JSON") from exc
        if not isinstance(parsed_document, dict):
            raise AgentSecurityError("document JSON root must be an object")
        cert = self.inspector.inspect()
        with tempfile.TemporaryDirectory(prefix="wbcz-doc-") as directory:
            temp = Path(directory)
            source = temp / "document.json"
            source.write_bytes(payload)
            command = [
                str(self.cryptcp),
                "-signf",
                "-der",
                "-strict",
                "-cert",
                "-uMy",
                "-thumbprint",
                self.thumbprint,
                "-dir",
                str(temp),
                str(source),
                "-fext",
                ".sgn",
            ]
            # Intentionally no -attached: documents require detached signature.
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            completed = self._runner(
                command,
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
                creationflags=creationflags,
            )
            if completed.returncode != 0:
                raise TrueApiError(
                    (completed.stderr.strip() or completed.stdout.strip() or "CryptoPro document signing failed")[:1000]
                )
            expected = source.with_name(source.name + ".sgn")
            if not expected.is_file():
                candidates = list(temp.glob("*.sgn"))
                if len(candidates) != 1:
                    raise TrueApiError("CryptoPro did not produce detached document signature")
                expected = candidates[0]
            signature = expected.read_bytes()
            if not signature:
                raise TrueApiError("empty detached document signature")
            metadata = {
                "certificate_thumbprint": self.thumbprint,
                "certificate_subject": cert.get("subject"),
                "certificate_inn": self.participant_inn,
                "certificate_valid_from": cert.get("not_before"),
                "certificate_valid_to": cert.get("not_after"),
            }
            return base64.b64encode(signature).decode("ascii"), metadata


class AgentSessionManager:
    """Memory-only UUID session; expiry/401 causes full re-auth, never refresh."""

    def __init__(
        self,
        authenticator: TrueApiAuthenticator,
        *,
        refresh_margin: timedelta = timedelta(minutes=2),
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.authenticator = authenticator
        self.refresh_margin = refresh_margin
        self._now = now
        self._session: AuthSession | None = None

    def invalidate(self) -> None:
        self._session = None

    def observe_http_status(self, status: int | None) -> None:
        if status == 401:
            self.invalidate()

    def bearer_token(self) -> str:
        now = self._now().astimezone(timezone.utc)
        if self._session is None or self._session.expire_date <= now + self.refresh_margin:
            self._session = None
            self._session = self.authenticator.authenticate()
        return self._session.uuid_token

    @property
    def expire_date(self) -> datetime | None:
        return self._session.expire_date if self._session else None


class CreateIdParser(Protocol):
    def parse_document_id(self, response: AgentHttpResponse) -> str | None:
        ...


class UnconfirmedAgentCreateIdParser:
    def parse_document_id(self, response: AgentHttpResponse) -> str | None:
        return None


class PollStatusParser(Protocol):
    def parse_status(self, response: AgentHttpResponse) -> str | None:
        ...


class UnconfirmedAgentPollStatusParser:
    def parse_status(self, response: AgentHttpResponse) -> str | None:
        return None


class WindowsAgentExecutor:
    def __init__(
        self,
        *,
        participant_inn: str,
        transport: ProductionAgentTrueApiTransport,
        session_manager: AgentSessionManager,
        document_signer: WindowsCryptoProDocumentSigner,
        cises_adapter: TrueApiCisesInfoAdapter | None = None,
        create_id_parser: CreateIdParser | None = None,
        poll_status_parser: PollStatusParser | None = None,
        production_write: bool = False,
    ) -> None:
        self.participant_inn = participant_inn
        self.transport = transport
        self.session_manager = session_manager
        self.document_signer = document_signer
        self.cises_adapter = cises_adapter or TrueApiCisesInfoAdapter()
        self.create_id_parser = create_id_parser or UnconfirmedAgentCreateIdParser()
        self.poll_status_parser = poll_status_parser or UnconfirmedAgentPollStatusParser()
        self.production_write = bool(production_write)
        self._write_replay: dict[str, tuple[str, AgentResult]] = {}

    def execute(self, job: AgentJob) -> AgentResult:
        job.validate()
        if job.expected_inn != self.participant_inn:
            raise AgentSecurityError("expected_inn mismatch")
        if job.job_type is AgentJobType.CIS_CHECK:
            return self._cis_check(job)
        if job.job_type.value in M1_READ_JOB_TYPES:
            return self._m1_read(job)
        if job.job_type.value in M2_READ_JOB_TYPES:
            return self._m2_read(job)
        if job.job_type.value in M4_READ_JOB_TYPES:
            return self._m4_read(job)
        if job.job_type is AgentJobType.POLL_DOCUMENT:
            return self._poll(job)
        return self._write(job)

    @staticmethod
    def _content_type(headers: Mapping[str, str]) -> str | None:
        return next((str(v) for k, v in headers.items() if str(k).casefold() == "content-type"), None)

    def _read_response(self, job: AgentJob, response: AgentHttpResponse, *, job_type: str, request_payload: dict[str, Any]) -> AgentResult:
        body_sha = hashlib.sha256(response.body).hexdigest()
        content_type = self._content_type(response.headers)
        getattr(self.session_manager, "observe_http_status", lambda _status: None)(response.status)
        if 200 <= response.status < 300:
            payload = parse_json_bytes(response.body)
            if job_type in M4_READ_JOB_TYPES:
                parsed = parse_m4_success_payload(job_type, payload)
            elif job_type in M2_READ_JOB_TYPES:
                parsed = parse_reference_success_payload(job_type, request_payload, payload)
            else:
                parsed = parse_success_payload(job_type, request_payload, payload)
            return AgentResult(
                job.job_id,
                job.operation_id,
                "READ_COMPLETED",
                http_status=response.status,
                body_sha256=body_sha,
                content_type=content_type,
                read_result=parsed,
            )
        safe = safe_transport_error(response.status, response.headers, response.body)
        return AgentResult(
            job.job_id,
            job.operation_id,
            "READ_FAILED",
            http_status=response.status,
            body_sha256=safe.body_sha256,
            content_type=safe.content_type,
            error_code=safe.safe_error_code or f"HTTP_{response.status}",
            error_message=safe.safe_error_message,
            read_result={"transport_error": asdict(safe)},
        )

    def _m1_read(self, job: AgentJob) -> AgentResult:
        assert job.read_payload is not None
        bearer = self.session_manager.bearer_token()
        if job.job_type is AgentJobType.CIS_TO_PRODUCT:
            cises = tuple(job.read_payload["cises"])
            info_payload = {"cises": list(cises)}
            info_response = self.transport.m1_read("CIS_INFO", info_payload, bearer_token=bearer)
            if not 200 <= info_response.status < 300:
                return self._read_response(job, info_response, job_type="CIS_INFO", request_payload=info_payload)
            info_raw = parse_json_bytes(info_response.body)
            info_parsed, gtins = build_cis_to_product_info_request(info_raw, cises)
            product_parsed: dict[str, Any] | None = None
            product_http_status: int | None = None
            product_body_sha256: str | None = None
            if gtins:
                product_payload = {"gtins": gtins, "rdInfo": False}
                product_response = self.transport.m1_read("PRODUCT_INFO", product_payload, bearer_token=bearer)
                product_http_status = product_response.status
                product_body_sha256 = hashlib.sha256(product_response.body).hexdigest()
                getattr(self.session_manager, "observe_http_status", lambda _status: None)(product_response.status)
                if not 200 <= product_response.status < 300:
                    safe = safe_transport_error(product_response.status, product_response.headers, product_response.body)
                    return AgentResult(
                        job.job_id, job.operation_id, "READ_FAILED",
                        http_status=product_response.status,
                        body_sha256=safe.body_sha256,
                        content_type=safe.content_type,
                        error_code=safe.safe_error_code or f"HTTP_{product_response.status}",
                        error_message=safe.safe_error_message,
                        read_result={"type": "CIS_TO_PRODUCT", "cis_info": info_parsed, "product_transport_error": asdict(safe)},
                    )
                product_raw = parse_json_bytes(product_response.body)
                product_parsed = parse_success_payload("PRODUCT_INFO", product_payload, product_raw)
            return AgentResult(
                job.job_id, job.operation_id, "READ_COMPLETED",
                http_status=product_http_status or info_response.status,
                body_sha256=product_body_sha256 or hashlib.sha256(info_response.body).hexdigest(),
                content_type=self._content_type(info_response.headers),
                read_result={
                    "type": "CIS_TO_PRODUCT",
                    "cis_info": info_parsed,
                    "deduplicated_gtins": gtins,
                    "product_info": product_parsed,
                    "product_info_called": bool(gtins),
                },
            )
        response = self.transport.m1_read(job.job_type.value, job.read_payload, bearer_token=bearer)
        return self._read_response(job, response, job_type=job.job_type.value, request_payload=job.read_payload)

    def _m2_read(self, job: AgentJob) -> AgentResult:
        assert job.read_payload is not None
        bearer = self.session_manager.bearer_token()
        response = self.transport.m2_read(job.job_type.value, job.read_payload, bearer_token=bearer)
        return self._read_response(job, response, job_type=job.job_type.value, request_payload=job.read_payload)

    def _m4_read(self, job: AgentJob) -> AgentResult:
        assert job.read_payload is not None
        bearer = self.session_manager.bearer_token()
        response = self.transport.m4_read(job.job_type.value, job.read_payload, bearer_token=bearer)
        return self._read_response(
            job, response, job_type=job.job_type.value, request_payload=job.read_payload
        )

    def _cis_check(self, job: AgentJob) -> AgentResult:
        try:
            payload = self.transport.cises_info(job.cises, bearer_token=self.session_manager.bearer_token())
        except TrueApiHttpError as exc:
            getattr(self.session_manager, "observe_http_status", lambda _status: None)(exc.status)
            raise
        if isinstance(payload, dict) and isinstance(payload.get("results"), list):
            items = payload["results"]
        elif isinstance(payload, list):
            items = payload
        else:
            raise TrueApiProtocolError("cises/info returned unexpected payload")
        if len(items) != len(job.cises):
            raise TrueApiProtocolError("cises/info result count mismatch")
        normalized = []
        for cis, item in zip(job.cises, items, strict=True):
            state = self.cises_adapter.normalize(cis, item)
            normalized.append({"cis": cis, **asdict(state)})
        return AgentResult(job.job_id, job.operation_id, "CIS_CHECKED", cises=tuple(normalized))

    def _write(self, job: AgentJob) -> AgentResult:
        if not self.production_write:
            raise AgentProductionWriteDisabled("production_write=false")
        assert job.document_sha256 and job.product_document_base64 and job.document_type
        cached = self._write_replay.get(job.operation_id)
        if cached is not None:
            old_hash, result = cached
            if old_hash != job.document_sha256:
                raise AgentReplayConflict("operation replay with different payload")
            return result
        raw = base64.b64decode(job.product_document_base64, validate=True)
        signature, metadata = self.document_signer.sign_document_bytes(
            operation_id=job.operation_id,
            document_type=job.document_type,
            pg=job.pg,
            expected_inn=job.expected_inn,
            document_sha256=job.document_sha256,
            payload=raw,
        )
        response = self.transport.create_document(
            document_type=job.document_type,
            product_document_base64=job.product_document_base64,
            signature_base64=signature,
            bearer_token=self.session_manager.bearer_token(),
        )
        getattr(self.session_manager, "observe_http_status", lambda _status: None)(response.status)
        body_sha = hashlib.sha256(response.body).hexdigest()
        create_capture = (
            capture_create_response(response.status, response.headers, response.body)
            if response.status in (200, 201) else None
        )
        if response.status in (200, 201):
            document_id = self.create_id_parser.parse_document_id(response)
            if document_id:
                category = CreateCategory.SUCCESS_WITH_ID.value
                outcome = "SUBMITTED"
            else:
                category = CreateCategory.SUCCESS_CONTRACT_UNCONFIRMED.value
                outcome = "MANUAL_REVIEW"
        else:
            document_id = None
            category = {
                400: CreateCategory.BAD_REQUEST.value,
                401: CreateCategory.UNAUTHORIZED.value,
                403: CreateCategory.FORBIDDEN.value,
                422: CreateCategory.UNPROCESSABLE.value,
            }.get(response.status)
            if category is None:
                category = (
                    CreateCategory.SERVER_ERROR.value
                    if response.status >= 500
                    else CreateCategory.HTTP_ERROR.value
                )
            outcome = "MANUAL_REVIEW" if response.status >= 500 else "FAILED"
        result = AgentResult(
            job.job_id,
            job.operation_id,
            outcome,
            document_sha256=job.document_sha256,
            signature_base64=signature,
            http_status=response.status,
            create_category=category,
            document_id=document_id,
            body_sha256=body_sha,
            create_response=asdict(create_capture) if create_capture is not None else None,
            **metadata,
        )
        self._write_replay[job.operation_id] = (job.document_sha256, result)
        return result

    def _poll(self, job: AgentJob) -> AgentResult:
        assert job.document_id
        response = self.transport.poll_document(
            job.document_id, bearer_token=self.session_manager.bearer_token()
        )
        getattr(self.session_manager, "observe_http_status", lambda _status: None)(response.status)
        body_sha = hashlib.sha256(response.body).hexdigest()
        if response.status != 200:
            return AgentResult(
                job.job_id,
                job.operation_id,
                "MANUAL_REVIEW",
                http_status=response.status,
                body_sha256=body_sha,
                error_code="POLL_HTTP_ERROR",
            )
        status = self.poll_status_parser.parse_status(response)
        classification = classify_poll_status(status)
        outcome = {
            "INTERMEDIATE": "INTERMEDIATE",
            "TERMINAL_SUCCESS": "RECONCILIATION_REQUIRED",
            "TERMINAL_FAILURE": "FAILED",
            "MANUAL_REVIEW": "MANUAL_REVIEW",
        }[classification.value]
        return AgentResult(
            job.job_id,
            job.operation_id,
            outcome,
            http_status=response.status,
            remote_status=status,
            body_sha256=body_sha,
        )


_AGENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_jobs (
    job_id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','LEASED','COMPLETED')),
    result_sha256 TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(job_type, operation_id)
);
"""


class VpsAgentJobStore:
    """Durable VPS job outbox. Contains no UKEP key, PIN or True API token."""

    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout=10000")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.executescript(_AGENT_SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "VpsAgentJobStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _payload(job: AgentJob) -> str:
        value = asdict(job)
        value["job_type"] = job.job_type.value
        return canonical_json(value)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> AgentJob:
        data = json.loads(row["payload_json"])
        data["job_type"] = AgentJobType(data["job_type"])
        data["cises"] = tuple(data.get("cises") or ())
        return AgentJob(**data)

    def enqueue(self, job: AgentJob) -> AgentJob:
        job.validate()
        payload = self._payload(job)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._connection.execute(
                "SELECT * FROM agent_jobs WHERE job_type=? AND operation_id=?",
                (job.job_type.value, job.operation_id),
            ).fetchone()
            if existing is not None:
                if existing["payload_sha256"] != digest:
                    raise AgentReplayConflict("same agent operation has different payload")
                self._connection.commit()
                return self._from_row(existing)
            now = utc_now()
            self._connection.execute(
                "INSERT INTO agent_jobs VALUES (?, ?, ?, ?, ?, 'PENDING', NULL, NULL, ?, ?)",
                (job.job_id, job.job_type.value, job.operation_id, digest, payload, now, now),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        return job

    def fetch_one(self) -> AgentJob | None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT * FROM agent_jobs WHERE state IN ('LEASED','PENDING') ORDER BY created_at, job_id LIMIT 1"
            ).fetchone()
            if row is None:
                self._connection.commit()
                return None
            if row["state"] == "PENDING":
                self._connection.execute(
                    "UPDATE agent_jobs SET state='LEASED', updated_at=? WHERE job_id=?",
                    (utc_now(), row["job_id"]),
                )
            self._connection.commit()
            return self._from_row(row)
        except BaseException:
            self._connection.rollback()
            raise

    def complete(self, result: AgentResult) -> None:
        serialized = canonical_json(result.safe_dict())
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT * FROM agent_jobs WHERE job_id=?", (result.job_id,)
            ).fetchone()
            if row is None:
                raise KeyError("unknown agent job")
            if row["operation_id"] != result.operation_id:
                raise AgentReplayConflict("result operation_id mismatch")
            if row["state"] == "COMPLETED":
                if row["result_sha256"] != digest:
                    raise AgentReplayConflict("incompatible duplicate agent result")
                self._connection.commit()
                return
            self._connection.execute(
                "UPDATE agent_jobs SET state='COMPLETED', result_sha256=?, result_json=?, updated_at=? WHERE job_id=?",
                (digest, serialized, utc_now(), result.job_id),
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def state(self, job_id: str) -> AgentJobState:
        row = self._connection.execute(
            "SELECT state FROM agent_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return AgentJobState(row["state"])


class VpsAgentBroker:
    """Production control-plane boundary: no True API transport exists here."""

    def __init__(
        self,
        *,
        write_store: WriteOperationStore,
        job_store: VpsAgentJobStore,
        machine_auth: MachineTokenVerifier,
        own_inn: str,
    ) -> None:
        self.write_store = write_store
        self.job_store = job_store
        self.machine_auth = machine_auth
        self.own_inn = own_inn

    @staticmethod
    def _job_id(job_type: AgentJobType, operation_id: str, payload_seed: str) -> str:
        digest = hashlib.sha256(
            f"p0-agent:v1:{job_type.value}:{operation_id}:{payload_seed}".encode("utf-8")
        ).hexdigest()
        return "job_" + digest[:32]

    def queue_write(self, operation_id: str) -> AgentJob:
        req = self.write_store.signing_request(operation_id)
        job_type = AgentJobType(req.document_type)
        job = AgentJob(
            job_id=self._job_id(job_type, operation_id, req.document_sha256),
            job_type=job_type,
            operation_id=operation_id,
            pg=req.pg,
            expected_inn=req.expected_inn,
            document_type=req.document_type,
            document_sha256=req.document_sha256,
            product_document_base64=req.product_document_base64,
        )
        return self.job_store.enqueue(job)

    def queue_cis_check(self, request_id: str, cises: tuple[str, ...]) -> AgentJob:
        seed = hashlib.sha256(canonical_json(list(cises)).encode("utf-8")).hexdigest()
        job = AgentJob(
            self._job_id(AgentJobType.CIS_CHECK, request_id, seed),
            AgentJobType.CIS_CHECK,
            request_id,
            P0_PG,
            self.own_inn,
            cises=cises,
        )
        return self.job_store.enqueue(job)

    def queue_poll(self, operation_id: str, document_id: str) -> AgentJob:
        job = AgentJob(
            self._job_id(AgentJobType.POLL_DOCUMENT, operation_id, document_id),
            AgentJobType.POLL_DOCUMENT,
            operation_id,
            P0_PG,
            self.own_inn,
            document_id=document_id,
        )
        return self.job_store.enqueue(job)

    def fetch_one(self, machine_token: str) -> AgentJob | None:
        self.machine_auth.verify(machine_token)
        return self.job_store.fetch_one()

    def submit_result(self, machine_token: str, result: AgentResult) -> None:
        self.machine_auth.verify(machine_token)
        # Apply write operation state before marking job completed. A repeated
        # callback is accepted without ever issuing a second True API request.
        if result.create_category is not None:
            self._apply_write_result(result)
        elif result.remote_status is not None or result.error_code == "POLL_HTTP_ERROR":
            self._apply_poll_result(result)
        self.job_store.complete(result)

    def _apply_write_result(self, result: AgentResult) -> None:
        op = self.write_store.get(result.operation_id)
        if op.state is WriteState.AWAITING_SIGNATURE:
            if not result.document_sha256 or not result.signature_base64:
                raise AgentReplayConflict("write result misses signature/hash")
            self.write_store.accept_signature(
                SigningResponse(
                    operation_id=result.operation_id,
                    document_sha256=result.document_sha256,
                    signature_base64=result.signature_base64,
                    certificate_thumbprint=result.certificate_thumbprint,
                    certificate_subject=result.certificate_subject,
                    certificate_inn=result.certificate_inn,
                    certificate_valid_from=result.certificate_valid_from,
                    certificate_valid_to=result.certificate_valid_to,
                ),
                own_inn=self.own_inn,
            )
            op = self.write_store.get(result.operation_id)
        if op.state is WriteState.SIGNED:
            self.write_store.reserve_submit(result.operation_id)
            op = self.write_store.get(result.operation_id)
        if op.state is WriteState.SUBMITTING:
            try:
                category = CreateCategory(result.create_category or "")
            except ValueError as exc:
                raise AgentReplayConflict("unknown create result category") from exc
            self.write_store.complete_submit(
                result.operation_id,
                CreateResult(
                    category=category,
                    http_status=result.http_status or 0,
                    document_id=result.document_id,
                    body_sha256=result.body_sha256 or hashlib.sha256(b"").hexdigest(),
                    content_type=None,
                ),
            )
            return
        # Idempotent callback after state was already applied: never reserve or
        # create again. Incompatible payloads were already caught by job store.
        if op.state not in {
            WriteState.SUBMITTED,
            WriteState.PROCESSING,
            WriteState.RECONCILIATION_REQUIRED,
            WriteState.SUCCEEDED,
            WriteState.FAILED,
            WriteState.MANUAL_REVIEW,
        }:
            raise AgentReplayConflict(f"unexpected operation state {op.state.value}")

    def _apply_poll_result(self, result: AgentResult) -> None:
        op = self.write_store.get(result.operation_id)
        if op.state in {WriteState.SUBMITTED, WriteState.PROCESSING}:
            self.write_store.apply_poll_status(
                result.operation_id,
                status=result.remote_status,
                http_status=result.http_status,
                body_sha256=result.body_sha256,
            )


class WindowsOutboundAgent:
    """One polling iteration. All connectivity is initiated from Windows."""

    def __init__(
        self,
        *,
        backend: AgentBackendChannel,
        machine_token: str,
        executor: WindowsAgentExecutor,
    ) -> None:
        if not machine_token:
            raise ValueError("machine token is required")
        self.backend = backend
        self._machine_token = machine_token
        self.executor = executor

    def run_once(self) -> bool:
        job = self.backend.fetch_one(self._machine_token)
        if job is None:
            return False
        try:
            result = self.executor.execute(job)
        except AgentProductionWriteDisabled:
            result = AgentResult(
                job.job_id,
                job.operation_id,
                "MANUAL_REVIEW",
                document_sha256=job.document_sha256,
                error_code="PRODUCTION_WRITE_DISABLED",
            )
        except Exception as exc:
            # Never send exception text: it could contain provider/transport data.
            result = AgentResult(
                job.job_id,
                job.operation_id,
                "MANUAL_REVIEW",
                document_sha256=job.document_sha256,
                error_code=type(exc).__name__,
            )
        self.backend.submit_result(self._machine_token, result)
        return True
