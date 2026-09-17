from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# Local aliases are accepted only at the Sellari boundary and translated into
# documented True API wire parameters.
replace_once(
    "src/wbcz/document_lifecycle.py",
    '            "document_id", "did", "document_type_code", "document_status_code",\n',
    '            "document_id", "did", "document_type_code", "document_status_code", "operation",\n',
)
replace_once(
    "src/wbcz/document_lifecycle.py",
    '        if "document_status_code" in root and root["document_status_code"] is not None:\n            normalized["document_status_code"] = _expect_string(root["document_status_code"], "document_status_code")\n        if "document_format" in root and root["document_format"] is not None:\n',
    '        if "document_status_code" in root and root["document_status_code"] is not None:\n            normalized["document_status_code"] = _expect_string(root["document_status_code"], "document_status_code")\n        if "operation" in root and root["operation"] is not None:\n            if "document_status_code" in normalized:\n                raise DocumentLifecycleContractError("operation and document_status_code are aliases; provide only one")\n            normalized["document_status_code"] = _expect_string(root["operation"], "operation")\n        if "document_format" in root and root["document_format"] is not None:\n',
)

# Typed M4 read jobs reuse the existing Windows outbound agent, auth session,
# shared rate limiter and GOST transport. No generic request primitive is added.
replace_once(
    "src/wbcz/windows_agent.py",
    'from wbcz.reference_products import (\n    M2_READ_JOB_TYPES,\n    build_reference_read_spec,\n    is_allowed_reference_target,\n    parse_reference_success_payload,\n    validate_m2_job_payload,\n)\n',
    'from wbcz.reference_products import (\n    M2_READ_JOB_TYPES,\n    build_reference_read_spec,\n    is_allowed_reference_target,\n    parse_reference_success_payload,\n    validate_m2_job_payload,\n)\nfrom wbcz.document_lifecycle import (\n    M4_READ_JOB_TYPES,\n    build_document_read_spec,\n    capture_create_response,\n    is_allowed_document_target,\n    parse_m4_success_payload,\n    validate_m4_job_payload,\n)\n',
)
replace_once(
    "src/wbcz/windows_agent.py",
    '    PRODUCT_GTIN_LIST = "PRODUCT_GTIN_LIST"\n    RD_LIST = "RD_LIST"\n',
    '    PRODUCT_GTIN_LIST = "PRODUCT_GTIN_LIST"\n    RD_LIST = "RD_LIST"\n    DOCUMENT_LIST = "DOCUMENT_LIST"\n    DOCUMENT_INFO = "DOCUMENT_INFO"\n    DOCUMENT_CISES = "DOCUMENT_CISES"\n',
)
replace_once(
    "src/wbcz/windows_agent.py",
    '        elif self.job_type.value in M2_READ_JOB_TYPES:\n            if self.read_payload is None:\n                raise AgentSecurityError("M2 read job misses read_payload")\n            if any((self.document_type, self.document_sha256, self.product_document_base64, self.cises, self.document_id)):\n                raise AgentSecurityError("M2 read job contains P0/write fields")\n            try:\n                normalized = validate_m2_job_payload(self.job_type.value, self.read_payload)\n            except ValueError as exc:\n                raise AgentSecurityError(str(exc)) from exc\n            if normalized != self.read_payload:\n                raise AgentSecurityError("M2 read_payload must already be canonical")\n        else:\n',
    '        elif self.job_type.value in M2_READ_JOB_TYPES:\n            if self.read_payload is None:\n                raise AgentSecurityError("M2 read job misses read_payload")\n            if any((self.document_type, self.document_sha256, self.product_document_base64, self.cises, self.document_id)):\n                raise AgentSecurityError("M2 read job contains P0/write fields")\n            try:\n                normalized = validate_m2_job_payload(self.job_type.value, self.read_payload)\n            except ValueError as exc:\n                raise AgentSecurityError(str(exc)) from exc\n            if normalized != self.read_payload:\n                raise AgentSecurityError("M2 read_payload must already be canonical")\n        elif self.job_type.value in M4_READ_JOB_TYPES:\n            if self.read_payload is None:\n                raise AgentSecurityError("M4 document read job misses read_payload")\n            if any((self.document_type, self.document_sha256, self.product_document_base64, self.cises, self.document_id)):\n                raise AgentSecurityError("M4 document read job contains P0/write fields")\n            try:\n                normalized = validate_m4_job_payload(self.job_type.value, self.read_payload)\n            except ValueError as exc:\n                raise AgentSecurityError(str(exc)) from exc\n            if normalized != self.read_payload:\n                raise AgentSecurityError("M4 read_payload must already be canonical")\n        else:\n',
)
replace_once(
    "src/wbcz/windows_agent.py",
    '    read_result: Any | None = None\n\n    def safe_dict(self) -> dict[str, Any]:\n',
    '    read_result: Any | None = None\n    create_response: dict[str, Any] | None = None\n\n    def safe_dict(self) -> dict[str, Any]:\n',
)

m4_transport = '''    def m4_read(self, job_type: str, payload: dict[str, Any], *, bearer_token: str) -> AgentHttpResponse:\n        spec = build_document_read_spec(job_type, payload)\n        if not is_allowed_document_target(spec):\n            raise AgentSecurityError("arbitrary M4 True API document target denied")\n        if not bearer_token:\n            raise AgentSecurityError("True API bearer token is required")\n        headers = {\n            "Accept": "application/json, application/xml, text/xml",\n            "Host": PRODUCTION_HOST,\n            "Connection": "close",\n            "Authorization": "Bearer " + bearer_token,\n        }\n        connection: http.client.HTTPConnection | None = None\n        self.rate_limiter.acquire()\n        try:\n            marker = self.tunnel.session_marker()\n            connection = self._connection_factory("127.0.0.1", self.tunnel.local_port, timeout=self.timeout)\n            connection.putrequest(spec.method, spec.target, skip_host=True)\n            for name, value in headers.items():\n                connection.putheader(name, value)\n            connection.endheaders()\n            response = connection.getresponse()\n            status = int(response.status)\n            raw = response.read()\n            self.tunnel.assert_gost_session(marker)\n            self.audit.record(\n                method=spec.method,\n                endpoint=spec.audit_endpoint,\n                cis_count=0,\n                http_status=status,\n                request_id=ReadOnlyTrueApiTransport._request_id(response.headers),\n            )\n            return AgentHttpResponse(\n                status=status,\n                body=raw,\n                headers={str(k): str(v) for k, v in response.headers.items()},\n            )\n        except GostTlsUnavailable:\n            raise\n        except (OSError, http.client.HTTPException) as exc:\n            self.audit.record(\n                method=spec.method, endpoint=spec.audit_endpoint, cis_count=0,\n                http_status=None, error=type(exc).__name__,\n            )\n            raise TrueApiError("CryptoPro GOST TLS agent transport error") from exc\n        finally:\n            if connection is not None:\n                connection.close()\n\n'''
replace_once("src/wbcz/windows_agent.py", "    def create_document(\n", m4_transport + "    def create_document(\n")

replace_once(
    "src/wbcz/windows_agent.py",
    '        if job.job_type.value in M2_READ_JOB_TYPES:\n            return self._m2_read(job)\n        if job.job_type is AgentJobType.POLL_DOCUMENT:\n',
    '        if job.job_type.value in M2_READ_JOB_TYPES:\n            return self._m2_read(job)\n        if job.job_type.value in M4_READ_JOB_TYPES:\n            return self._m4_read(job)\n        if job.job_type is AgentJobType.POLL_DOCUMENT:\n',
)
replace_once(
    "src/wbcz/windows_agent.py",
    '            parsed = (\n                parse_reference_success_payload(job_type, request_payload, payload)\n                if job_type in M2_READ_JOB_TYPES\n                else parse_success_payload(job_type, request_payload, payload)\n            )\n',
    '            if job_type in M4_READ_JOB_TYPES:\n                parsed = parse_m4_success_payload(job_type, payload)\n            elif job_type in M2_READ_JOB_TYPES:\n                parsed = parse_reference_success_payload(job_type, request_payload, payload)\n            else:\n                parsed = parse_success_payload(job_type, request_payload, payload)\n',
)
replace_once(
    "src/wbcz/windows_agent.py",
    '    def _cis_check(self, job: AgentJob) -> AgentResult:\n',
    '    def _m4_read(self, job: AgentJob) -> AgentResult:\n        assert job.read_payload is not None\n        bearer = self.session_manager.bearer_token()\n        response = self.transport.m4_read(job.job_type.value, job.read_payload, bearer_token=bearer)\n        return self._read_response(\n            job, response, job_type=job.job_type.value, request_payload=job.read_payload\n        )\n\n    def _cis_check(self, job: AgentJob) -> AgentResult:\n',
)
replace_once(
    "src/wbcz/windows_agent.py",
    '        body_sha = hashlib.sha256(response.body).hexdigest()\n        if response.status in (200, 201):\n',
    '        body_sha = hashlib.sha256(response.body).hexdigest()\n        create_capture = (\n            capture_create_response(response.status, response.headers, response.body)\n            if response.status in (200, 201) else None\n        )\n        if response.status in (200, 201):\n',
)
replace_once(
    "src/wbcz/windows_agent.py",
    '            body_sha256=body_sha,\n            **metadata,\n        )\n',
    '            body_sha256=body_sha,\n            create_response=asdict(create_capture) if create_capture is not None else None,\n            **metadata,\n        )\n',
)

# Backend broker accepts typed M4 read results as durable read-only results only.
replace_once(
    "src/wbcz_web/services/agent_orchestration.py",
    '        elif metadata.purpose == "REFERENCE_PRODUCTS":\n            # M2 is read-only; typed/sanitized results are already durable.\n            pass\n        else:\n',
    '        elif metadata.purpose == "REFERENCE_PRODUCTS":\n            # M2 is read-only; typed/sanitized results are already durable.\n            pass\n        elif metadata.purpose == "DOCUMENT_LIFECYCLE":\n            # M4 is read-only; result/ledger persistence has no business mutation.\n            pass\n        else:\n',
)

# API routes expose local aliases; they do not become True API wire fields.
replace_once(
    "src/wbcz_web/api/routes.py",
    'from wbcz.windows_agent import AgentJobType\n',
    'from wbcz.windows_agent import AgentJobType, AgentReplayConflict\n',
)
replace_once(
    "src/wbcz_web/api/routes.py",
    'from wbcz_web.services.reference_products import ReferenceProductsService, ReferenceProductsUnavailable\n',
    'from wbcz_web.services.reference_products import ReferenceProductsService, ReferenceProductsUnavailable\nfrom wbcz_web.services.document_lifecycle import DocumentLifecycleService, DocumentLifecycleUnavailable\n',
)
replace_once(
    "src/wbcz_web/api/routes.py",
    '    ReferenceTnVedRequest,\n)\n',
    '    ReferenceTnVedRequest,\n    DocumentListRequest,\n    DocumentInfoRequest,\n    DocumentCisesRequest,\n)\n',
)

routes = Path("src/wbcz_web/api/routes.py")
text = routes.read_text(encoding="utf-8")
if '@router.get("/documents/registries")' in text:
    raise SystemExit("M4 routes already present")
text += '''\n\n\ndef _document_lifecycle_service(request: Request, db: Session) -> DocumentLifecycleService:\n    try:\n        return DocumentLifecycleService(db, request.app.state.config)\n    except DocumentLifecycleUnavailable as exc:\n        raise HTTPException(status_code=409, detail=str(exc)) from exc\n\n\n@router.post("/documents/list")\ndef document_list(payload: DocumentListRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_user), db: Session = Depends(get_db)) -> dict:\n    body = payload.model_dump(exclude_none=True)\n    operation_id = body.pop("operation_id", None)\n    try:\n        return _document_lifecycle_service(request, db).queue(AgentJobType.DOCUMENT_LIST, body, operation_id=operation_id, user_id=identity.user_id)\n    except AgentReplayConflict as exc:\n        raise HTTPException(status_code=409, detail=str(exc)) from exc\n    except ValueError as exc:\n        raise HTTPException(status_code=400, detail=str(exc)) from exc\n\n\n@router.post("/documents/info")\ndef document_info(payload: DocumentInfoRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_user), db: Session = Depends(get_db)) -> dict:\n    body = payload.model_dump(exclude_none=True)\n    operation_id = body.pop("operation_id", None)\n    try:\n        return _document_lifecycle_service(request, db).queue(AgentJobType.DOCUMENT_INFO, body, operation_id=operation_id, user_id=identity.user_id)\n    except AgentReplayConflict as exc:\n        raise HTTPException(status_code=409, detail=str(exc)) from exc\n    except ValueError as exc:\n        raise HTTPException(status_code=400, detail=str(exc)) from exc\n\n\n@router.post("/documents/cises")\ndef document_cises(payload: DocumentCisesRequest, request: Request, _: None = Depends(require_csrf), identity: AuthenticatedIdentity = Depends(require_user), db: Session = Depends(get_db)) -> dict:\n    try:\n        return _document_lifecycle_service(request, db).queue_cises(\n            document_id=payload.document_id,\n            write_operation_id=payload.write_operation_id,\n            operation_id=payload.operation_id,\n            user_id=identity.user_id,\n        )\n    except KeyError as exc:\n        raise HTTPException(status_code=404, detail="write operation not found") from exc\n    except AgentReplayConflict as exc:\n        raise HTTPException(status_code=409, detail=str(exc)) from exc\n    except ValueError as exc:\n        raise HTTPException(status_code=400, detail=str(exc)) from exc\n\n\n@router.get("/documents/requests/{request_id}")\ndef document_request_status(request_id: str, request: Request, identity: AuthenticatedIdentity = Depends(require_user), db: Session = Depends(get_db)) -> dict:\n    try:\n        return _document_lifecycle_service(request, db).status(request_id)\n    except KeyError as exc:\n        raise HTTPException(status_code=404, detail="M4 request not found") from exc\n\n\n@router.get("/documents/ledger/{operation_id}")\ndef document_ledger(operation_id: str, request: Request, identity: AuthenticatedIdentity = Depends(require_user), db: Session = Depends(get_db)) -> dict:\n    try:\n        return _document_lifecycle_service(request, db).ledger(operation_id)\n    except KeyError as exc:\n        raise HTTPException(status_code=404, detail="M4 operation not found") from exc\n\n\n@router.get("/documents/registries")\ndef document_registries(identity: AuthenticatedIdentity = Depends(require_user)) -> dict:\n    return DocumentLifecycleService.registries()\n'''
routes.write_text(text, encoding="utf-8")

print("M4 typed wiring applied")
