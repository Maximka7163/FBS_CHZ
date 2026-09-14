from __future__ import annotations

import base64
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess

import pytest

from wbcz.models import Decision
from wbcz.windows_agent import (
    AGENT_FETCH_PATH,
    AGENT_RESULT_PATH,
    AgentAuthError,
    AgentHttpResponse,
    AgentJob,
    AgentJobState,
    AgentJobType,
    AgentProductionWriteDisabled,
    AgentReplayConflict,
    AgentResult,
    AgentSecurityError,
    AgentSessionManager,
    MachineTokenVerifier,
    ProductionAgentTrueApiTransport,
    UnconfirmedAgentCreateIdParser,
    VpsAgentBroker,
    VpsAgentJobStore,
    WindowsCryptoProDocumentSigner,
    WindowsOutboundAgent,
    WindowsAgentExecutor,
)
from wbcz.write_pipeline import (
    CreateCategory,
    ExactDocumentBuilder,
    WriteOperationStore,
    WritePipeline,
    WriteState,
)
from wbcz_ui.live_true_api import (
    AuthSession,
    TrueApiAuthenticator,
    WindowsCryptoProAuthSigner,
)


OWN = "1234567890"
MACHINE_TOKEN = "test-machine-token-0123456789"


class FakeHeaders(dict):
    pass


class FakeHttpResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body
        self.headers = FakeHeaders(headers or {})

    def read(self):
        return self._body


class FakeConnection:
    def __init__(self, response, calls, host, port, timeout=None):
        self.response = response
        self.calls = calls
        self.host = host
        self.port = port
        self.timeout = timeout
        self.target = None
        self.headers = {}
        self.data = None

    def putrequest(self, method, target, skip_host=False):
        self.method = method
        self.target = target

    def putheader(self, name, value):
        self.headers[name] = value

    def endheaders(self, data=None):
        self.data = data
        self.calls.append(self)

    def getresponse(self):
        return self.response

    def close(self):
        pass


class FakeTunnel:
    def __init__(self):
        self.port_reads = 0
        self.assertions = 0

    @property
    def local_port(self):
        self.port_reads += 1
        return 41414

    def session_marker(self):
        return 0

    def assert_gost_session(self, marker=0):
        self.assertions += 1

    def diagnostics(self):
        return {"mechanism": "CryptoPro CSP stunnel-msspi / MSSPI GOST TLS"}


def transport_with_response(tmp_path, *, status=200, payload=None):
    calls = []
    tunnel = FakeTunnel()
    body = json.dumps(payload if payload is not None else {}).encode()
    response = FakeHttpResponse(status, body, {"X-Request-ID": "r1"})

    def factory(host, port, timeout=None):
        return FakeConnection(response, calls, host, port, timeout)

    from wbcz_ui.live_true_api import JsonlLiveAudit

    transport = ProductionAgentTrueApiTransport(
        tunnel=tunnel,
        audit=JsonlLiveAudit(tmp_path / "agent.jsonl"),
        connection_factory=factory,
    )
    return transport, tunnel, calls


def write_job(doc=None):
    doc = doc or ExactDocumentBuilder.from_json_value({"withdrawReason": "DISTANCE"})
    return AgentJob(
        job_id="job-write-1",
        job_type=AgentJobType.LK_RECEIPT,
        operation_id="op-write-1",
        pg="lp",
        expected_inn=OWN,
        document_type="LK_RECEIPT",
        document_sha256=doc.sha256,
        product_document_base64=doc.product_document_base64,
    )


def test_agent_job_whitelist_and_arbitrary_document_type_denied():
    doc = ExactDocumentBuilder.from_json_value({"x": 1})
    with pytest.raises((ValueError, AgentSecurityError)):
        AgentJob(
            "j", AgentJobType("LK_RECEIPT"), "op", "lp", OWN,
            document_type="ARBITRARY", document_sha256=doc.sha256,
            product_document_base64=doc.product_document_base64,
        ).validate()


def test_pg_not_lp_denied():
    job = write_job()
    bad = AgentJob(**{**job.__dict__, "pg": "shoes"}) if hasattr(job, "__dict__") else AgentJob(
        job.job_id, job.job_type, job.operation_id, "shoes", job.expected_inn,
        job.document_type, job.document_sha256, job.product_document_base64,
    )
    with pytest.raises(AgentSecurityError):
        bad.validate()


def test_hash_mismatch_denied():
    job = write_job()
    bad = AgentJob(
        job.job_id, job.job_type, job.operation_id, job.pg, job.expected_inn,
        job.document_type, "0" * 64, job.product_document_base64,
    )
    with pytest.raises(AgentSecurityError, match="sha256"):
        bad.validate()


def test_inn_mismatch_denied_before_execution(tmp_path):
    class Noop:
        pass
    executor = WindowsAgentExecutor(
        participant_inn=OWN,
        transport=Noop(),
        session_manager=Noop(),
        document_signer=Noop(),
    )
    job = write_job()
    bad = AgentJob(
        job.job_id, job.job_type, job.operation_id, job.pg, "9999999999",
        job.document_type, job.document_sha256, job.product_document_base64,
    )
    with pytest.raises(AgentSecurityError, match="expected_inn"):
        executor.execute(bad)


def test_arbitrary_true_api_endpoint_denied_before_tunnel(tmp_path):
    transport, tunnel, calls = transport_with_response(tmp_path)
    with pytest.raises(AgentSecurityError):
        transport.request_json("GET", "/anything")
    assert tunnel.port_reads == 0
    assert calls == []


def test_cises_info_uses_gost_transport_foundation(tmp_path):
    payload = {"results": [{"cisInfo": {"cis": "K1", "status": "INTRODUCED", "ownerInn": OWN, "productGroup": "lp"}}]}
    transport, tunnel, calls = transport_with_response(tmp_path, payload=payload)
    result = transport.cises_info(("K1",), bearer_token="UUID-TOKEN")
    assert result == payload
    assert calls[0].target == "/api/v3/true-api/cises/info?pg=lp"
    assert tunnel.assertions == 1
    assert calls[0].headers["Authorization"] == "Bearer UUID-TOKEN"


def test_create_uses_gost_transport_exact_shape_and_token_not_logged(tmp_path):
    transport, tunnel, calls = transport_with_response(tmp_path, status=201, payload={"opaque": True})
    product = base64.b64encode(b'{"x":1}').decode()
    signature = base64.b64encode(b"sig").decode()
    response = transport.create_document(
        document_type="LK_RECEIPT",
        product_document_base64=product,
        signature_base64=signature,
        bearer_token="UUID-SUPER-SECRET",
    )
    assert response.status == 201
    call = calls[0]
    assert call.target == "/api/v3/true-api/lk/documents/create?pg=lp"
    body = json.loads(call.data)
    assert body == {
        "document_format": "MANUAL",
        "product_document": product,
        "type": "LK_RECEIPT",
        "signature": signature,
    }
    assert "second_product_document" not in body
    assert "second_signature" not in body
    assert tunnel.assertions == 1
    audit = (tmp_path / "agent.jsonl").read_text(encoding="utf-8")
    assert "UUID-SUPER-SECRET" not in audit


def test_polling_uses_gost_transport_v4(tmp_path):
    transport, tunnel, calls = transport_with_response(tmp_path, payload={"status": "IN_PROGRESS"})
    response = transport.poll_document("doc-123", bearer_token="UUID-TOKEN")
    assert response.status == 200
    assert calls[0].target == "/api/v4/true-api/doc/doc-123/info"
    assert tunnel.assertions == 1


def test_transport_public_boundary_cannot_proxy_arbitrary_target(tmp_path):
    transport, tunnel, calls = transport_with_response(tmp_path)
    with pytest.raises(AgentSecurityError):
        transport._exact_request(
            "GET", "/api/v3/true-api/users", bearer_token="x",
            audit_endpoint="bad",
        )
    assert calls == []


def test_auth_signer_attached_document_signer_detached(tmp_path):
    cryptcp = tmp_path / "cryptcp.exe"
    cryptcp.write_bytes(b"x")

    class Inspector:
        def inspect(self):
            return {"subject": "CN=test"}

    auth_calls = []
    doc_calls = []

    def auth_runner(command, **kwargs):
        auth_calls.append(command)
        source = Path(command[command.index("-fext") - 1])
        source.with_name(source.name + ".sgn").write_bytes(b"AUTH")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def doc_runner(command, **kwargs):
        doc_calls.append(command)
        source = Path(command[command.index("-fext") - 1])
        source.with_name(source.name + ".sgn").write_bytes(b"DOC")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    auth = WindowsCryptoProAuthSigner(
        "AA11", cryptcp_path=cryptcp, inspector=Inspector(), runner=auth_runner
    )
    assert base64.b64decode(auth.sign_auth_challenge("challenge")) == b"AUTH"
    assert "-attached" in auth_calls[0]

    signer = WindowsCryptoProDocumentSigner(
        certificate_thumbprint="AA11",
        participant_inn=OWN,
        cryptcp_path=cryptcp,
        inspector=Inspector(),
        runner=doc_runner,
    )
    payload = b'{"x":1}'
    sig, _ = signer.sign_document_bytes(
        operation_id="op1",
        document_type="LK_RECEIPT",
        pg="lp",
        expected_inn=OWN,
        document_sha256=__import__("hashlib").sha256(payload).hexdigest(),
        payload=payload,
    )
    assert base64.b64decode(sig) == b"DOC"
    assert "-attached" not in doc_calls[0]
    assert "-der" in doc_calls[0]
    assert "-strict" in doc_calls[0]
    assert "-pin" not in doc_calls[0]
    assert not hasattr(signer, "sign")


def test_private_key_and_pin_not_serialized_in_protocol():
    names = {f.name for f in fields(AgentJob)} | {f.name for f in fields(AgentResult)}
    assert "private_key" not in names
    assert "pin" not in names
    job = write_job()
    serialized = json.dumps({f.name: getattr(job, f.name) for f in fields(job)}, default=list)
    assert "PRIVATE KEY" not in serialized.upper()
    assert '"pin"' not in serialized.lower()


def test_session_manager_reauthenticates_on_expiry():
    now = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)

    class Auth:
        def __init__(self):
            self.calls = 0
        def authenticate(self):
            self.calls += 1
            return AuthSession(f"token-{self.calls}", now + timedelta(minutes=3 * self.calls))

    auth = Auth()
    clock = [now]
    manager = AgentSessionManager(auth, now=lambda: clock[0])
    assert manager.bearer_token() == "token-1"
    assert manager.bearer_token() == "token-1"
    clock[0] = now + timedelta(minutes=2)
    assert manager.bearer_token() == "token-2"
    assert auth.calls == 2


def test_authenticator_uses_attached_signer_contract_and_keeps_token_in_session_only():
    class Transport:
        def __init__(self): self.calls = []
        def request_json(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            if path == "/auth/key": return {"uuid": "u", "data": "challenge"}
            return {"uuidToken": "secret-token", "expireDate": "2099-01-01T00:00:00Z"}
        def tls_diagnostics(self): return {}
    class Signer:
        def __init__(self): self.calls = []
        def sign_auth_challenge(self, data): self.calls.append(data); return "attached-cms"
    t = Transport(); s = Signer()
    session = TrueApiAuthenticator(t, s, OWN).authenticate()
    assert s.calls == ["challenge"]
    assert session.bearer_token == "secret-token"
    assert t.calls[1][1] == "/auth/simpleSignIn"


class StubSession:
    def bearer_token(self):
        return "LOCAL-WINDOWS-TOKEN"


class StubSigner:
    def __init__(self): self.calls = 0
    def sign_document_bytes(self, **kwargs):
        self.calls += 1
        return base64.b64encode(b"detached").decode(), {
            "certificate_thumbprint": "AA11",
            "certificate_subject": "CN=test",
            "certificate_inn": OWN,
            "certificate_valid_from": None,
            "certificate_valid_to": None,
        }


class StubAgentTransport:
    def __init__(self, create_response=None, poll_response=None, cis_payload=None):
        self.create_response = create_response or AgentHttpResponse(201, b'{}', {})
        self.poll_response = poll_response or AgentHttpResponse(200, b'{}', {})
        self.cis_payload = cis_payload
        self.create_calls = 0
        self.poll_calls = 0
        self.cis_calls = 0
    def create_document(self, **kwargs):
        self.create_calls += 1
        assert kwargs["bearer_token"] == "LOCAL-WINDOWS-TOKEN"
        return self.create_response
    def poll_document(self, document_id, **kwargs):
        self.poll_calls += 1
        return self.poll_response
    def cises_info(self, cises, **kwargs):
        self.cis_calls += 1
        return self.cis_payload


class ConfirmedId:
    def parse_document_id(self, response): return "doc-confirmed"


class FixedPoll:
    def __init__(self, status): self.status = status
    def parse_status(self, response): return self.status


def test_production_write_default_off():
    executor = WindowsAgentExecutor(
        participant_inn=OWN,
        transport=StubAgentTransport(),
        session_manager=StubSession(),
        document_signer=StubSigner(),
    )
    assert executor.production_write is False
    with pytest.raises(AgentProductionWriteDisabled):
        executor.execute(write_job())


def test_unknown_create_success_envelope_fails_closed():
    transport = StubAgentTransport(AgentHttpResponse(201, b'{"unknown":1}', {}))
    executor = WindowsAgentExecutor(
        participant_inn=OWN,
        transport=transport,
        session_manager=StubSession(),
        document_signer=StubSigner(),
        production_write=True,
        create_id_parser=UnconfirmedAgentCreateIdParser(),
    )
    result = executor.execute(write_job())
    assert result.outcome == "MANUAL_REVIEW"
    assert result.create_category == CreateCategory.SUCCESS_CONTRACT_UNCONFIRMED.value
    assert result.document_id is None


def test_duplicate_write_job_safe_and_second_create_blocked():
    transport = StubAgentTransport()
    signer = StubSigner()
    executor = WindowsAgentExecutor(
        participant_inn=OWN,
        transport=transport,
        session_manager=StubSession(),
        document_signer=signer,
        production_write=True,
        create_id_parser=ConfirmedId(),
    )
    job = write_job()
    first = executor.execute(job)
    second = executor.execute(job)
    assert first == second
    assert first.outcome == "SUBMITTED"
    assert transport.create_calls == 1
    assert signer.calls == 1


def test_same_operation_different_payload_replay_blocked():
    transport = StubAgentTransport()
    executor = WindowsAgentExecutor(
        participant_inn=OWN,
        transport=transport,
        session_manager=StubSession(),
        document_signer=StubSigner(),
        production_write=True,
        create_id_parser=ConfirmedId(),
    )
    executor.execute(write_job())
    changed = ExactDocumentBuilder.from_json_value({"withdrawReason": "DISTANCE", "x": 2})
    job = write_job(changed)
    with pytest.raises(AgentReplayConflict):
        executor.execute(job)
    assert transport.create_calls == 1


def test_unknown_poll_status_manual_review():
    executor = WindowsAgentExecutor(
        participant_inn=OWN,
        transport=StubAgentTransport(poll_response=AgentHttpResponse(200, b'{"x":1}', {})),
        session_manager=StubSession(),
        document_signer=StubSigner(),
        poll_status_parser=FixedPoll("BRAND_NEW_STATUS"),
    )
    job = AgentJob(
        "jp", AgentJobType.POLL_DOCUMENT, "op", "lp", OWN,
        document_id="doc-1",
    )
    result = executor.execute(job)
    assert result.outcome == "MANUAL_REVIEW"
    assert result.remote_status == "BRAND_NEW_STATUS"


@pytest.mark.parametrize(
    "status,outcome",
    [
        ("IN_PROGRESS", "INTERMEDIATE"),
        ("WAIT_FOR_CONTINUATION", "INTERMEDIATE"),
        ("CHECKED_OK", "RECONCILIATION_REQUIRED"),
        ("CHECKED_NOT_OK", "FAILED"),
        ("PARSE_ERROR", "FAILED"),
        ("PROCESSING_ERROR", "FAILED"),
        ("UNDEFINED", "MANUAL_REVIEW"),
    ],
)
def test_poll_status_mapping(status, outcome):
    executor = WindowsAgentExecutor(
        participant_inn=OWN,
        transport=StubAgentTransport(),
        session_manager=StubSession(),
        document_signer=StubSigner(),
        poll_status_parser=FixedPoll(status),
    )
    result = executor.execute(AgentJob(
        "jp", AgentJobType.POLL_DOCUMENT, "op", "lp", OWN,
        document_id="doc-1",
    ))
    assert result.outcome == outcome


def prepared_write_store(tmp_path):
    store = WriteOperationStore(tmp_path / "write.sqlite")
    pipeline = WritePipeline(store=store, own_inn=OWN)
    doc = ExactDocumentBuilder.from_json_value({"withdrawReason": "DISTANCE"})
    op = pipeline.prepare(
        event_id="event-1",
        decision=Decision.READY_TO_WITHDRAW,
        document_type="LK_RECEIPT",
        operation_reason="DISTANCE",
        pg="lp",
        expected_inn=OWN,
        document=doc,
    )
    return store, op, doc


def test_vps_agent_machine_auth_and_separate_protocol_paths(tmp_path):
    write_store, op, doc = prepared_write_store(tmp_path)
    jobs = VpsAgentJobStore(tmp_path / "jobs.sqlite")
    broker = VpsAgentBroker(
        write_store=write_store,
        job_store=jobs,
        machine_auth=MachineTokenVerifier(MACHINE_TOKEN),
        own_inn=OWN,
    )
    queued = broker.queue_write(op.operation_id)
    assert AGENT_FETCH_PATH.startswith("/api/agent/")
    assert AGENT_RESULT_PATH.startswith("/api/agent/")
    with pytest.raises(AgentAuthError):
        broker.fetch_one("wrong-token-which-is-long-enough")
    claimed = broker.fetch_one(MACHINE_TOKEN)
    assert claimed == queued
    assert jobs.state(queued.job_id) is AgentJobState.LEASED


def test_vps_job_redelivery_is_same_job_and_payload(tmp_path):
    write_store, op, doc = prepared_write_store(tmp_path)
    jobs = VpsAgentJobStore(tmp_path / "jobs.sqlite")
    broker = VpsAgentBroker(
        write_store=write_store, job_store=jobs,
        machine_auth=MachineTokenVerifier(MACHINE_TOKEN), own_inn=OWN,
    )
    first = broker.queue_write(op.operation_id)
    second = broker.queue_write(op.operation_id)
    assert first == second
    assert broker.fetch_one(MACHINE_TOKEN) == first
    assert broker.fetch_one(MACHINE_TOKEN) == first


def test_vps_accepts_agent_create_result_without_direct_true_api(tmp_path):
    write_store, op, doc = prepared_write_store(tmp_path)
    jobs = VpsAgentJobStore(tmp_path / "jobs.sqlite")
    broker = VpsAgentBroker(
        write_store=write_store, job_store=jobs,
        machine_auth=MachineTokenVerifier(MACHINE_TOKEN), own_inn=OWN,
    )
    job = broker.queue_write(op.operation_id)
    broker.fetch_one(MACHINE_TOKEN)
    result = AgentResult(
        job.job_id,
        op.operation_id,
        "SUBMITTED",
        document_sha256=doc.sha256,
        signature_base64=base64.b64encode(b"sig").decode(),
        certificate_thumbprint="AA11",
        certificate_inn=OWN,
        http_status=201,
        create_category=CreateCategory.SUCCESS_WITH_ID.value,
        document_id="doc-1",
        body_sha256="1" * 64,
    )
    broker.submit_result(MACHINE_TOKEN, result)
    assert write_store.get(op.operation_id).state is WriteState.SUBMITTED
    assert write_store.get(op.operation_id).document_id == "doc-1"
    assert jobs.state(job.job_id) is AgentJobState.COMPLETED
    # Compatible repeat callback is safe and cannot cause another create: VPS
    # has no True API transport at all.
    broker.submit_result(MACHINE_TOKEN, result)
    assert write_store.get(op.operation_id).state is WriteState.SUBMITTED


def test_incompatible_duplicate_completion_rejected(tmp_path):
    write_store, op, doc = prepared_write_store(tmp_path)
    jobs = VpsAgentJobStore(tmp_path / "jobs.sqlite")
    broker = VpsAgentBroker(
        write_store=write_store, job_store=jobs,
        machine_auth=MachineTokenVerifier(MACHINE_TOKEN), own_inn=OWN,
    )
    job = broker.queue_write(op.operation_id)
    broker.fetch_one(MACHINE_TOKEN)
    result = AgentResult(
        job.job_id, op.operation_id, "MANUAL_REVIEW",
        document_sha256=doc.sha256,
        signature_base64=base64.b64encode(b"sig").decode(),
        certificate_inn=OWN,
        http_status=201,
        create_category=CreateCategory.SUCCESS_CONTRACT_UNCONFIRMED.value,
        body_sha256="2" * 64,
    )
    broker.submit_result(MACHINE_TOKEN, result)
    changed = AgentResult(
        job.job_id, op.operation_id, "FAILED",
        document_sha256=doc.sha256,
        signature_base64=base64.b64encode(b"sig").decode(),
        certificate_inn=OWN,
        http_status=400,
        create_category=CreateCategory.BAD_REQUEST.value,
        body_sha256="3" * 64,
    )
    with pytest.raises(AgentReplayConflict):
        broker.submit_result(MACHINE_TOKEN, changed)


def test_outbound_agent_needs_no_windows_inbound_listener():
    class Backend:
        def __init__(self): self.fetch = 0; self.results = []
        def fetch_one(self, token): self.fetch += 1; return None
        def submit_result(self, token, result): self.results.append(result)
    class Executor: pass
    backend = Backend()
    agent = WindowsOutboundAgent(
        backend=backend, machine_token=MACHINE_TOKEN, executor=Executor()
    )
    assert agent.run_once() is False
    assert backend.fetch == 1
    assert not hasattr(agent, "listen")
    assert not hasattr(agent, "serve")
    assert not hasattr(agent, "open_port")


def test_vps_broker_has_no_direct_true_api_adapter_dependency():
    import inspect
    import wbcz.windows_agent as module
    source = inspect.getsource(module.VpsAgentBroker)
    assert "TrueApiWriteAdapter" not in source
    assert "markirovka.crpt.ru" not in source
    assert "request_json" not in source
