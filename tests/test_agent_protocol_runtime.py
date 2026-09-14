from __future__ import annotations

import base64
import json

import pytest

from wbcz.agent_http import (
    AgentProtocolResponse,
    OutboundAgentHttpClient,
    StdlibHttpsAgentSender,
    VpsAgentHttpBoundary,
)
from wbcz.models import Decision
from wbcz.windows_agent import (
    AGENT_FETCH_PATH,
    AGENT_RESULT_PATH,
    AgentHttpResponse,
    AgentJob,
    AgentJobType,
    AgentResult,
    AgentSecurityError,
    MachineTokenVerifier,
    VpsAgentBroker,
    VpsAgentJobStore,
)
from wbcz.windows_agent_runtime import (
    AgentCreateOutcomeUnresolved,
    DurableWindowsAgentExecutor,
    WindowsAgentReplayStore,
)
from wbcz.write_pipeline import ExactDocumentBuilder, WriteOperationStore, WritePipeline


OWN = "1234567890"
TOKEN = "machine-secret-runtime-0123456789"


def sample_job():
    doc = ExactDocumentBuilder.from_json_value({"withdrawReason": "DISTANCE"})
    return AgentJob(
        "job-1",
        AgentJobType.LK_RECEIPT,
        "op-1",
        "lp",
        OWN,
        document_type="LK_RECEIPT",
        document_sha256=doc.sha256,
        product_document_base64=doc.product_document_base64,
    )


class QueueSender:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, path, *, headers, body=None):
        self.calls.append((method, path, dict(headers), body))
        return self.responses.pop(0)


def test_concrete_outbound_http_protocol_has_no_cookie_or_browser_session():
    job = sample_job()
    payload = {
        "job_id": job.job_id,
        "job_type": job.job_type.value,
        "operation_id": job.operation_id,
        "pg": job.pg,
        "expected_inn": job.expected_inn,
        "document_type": job.document_type,
        "document_sha256": job.document_sha256,
        "product_document_base64": job.product_document_base64,
        "cises": [],
        "document_id": None,
    }
    sender = QueueSender([
        AgentProtocolResponse(200, json.dumps(payload).encode()),
        AgentProtocolResponse(202),
    ])
    client = OutboundAgentHttpClient(sender)
    fetched = client.fetch_one(TOKEN)
    assert fetched == job
    result = AgentResult(job.job_id, job.operation_id, "MANUAL_REVIEW")
    client.submit_result(TOKEN, result)

    method, path, headers, body = sender.calls[0]
    assert (method, path) == ("GET", AGENT_FETCH_PATH)
    assert headers["Authorization"] == "Bearer " + TOKEN
    assert "Cookie" not in headers
    method, path, headers, body = sender.calls[1]
    assert method == "POST"
    assert path == AGENT_RESULT_PATH.format(job_id=job.job_id)
    assert headers["Authorization"] == "Bearer " + TOKEN
    assert "Cookie" not in headers
    assert TOKEN.encode() not in (body or b"")


def test_stdlib_sender_restricts_origin_and_endpoints_before_network():
    with pytest.raises(ValueError):
        StdlibHttpsAgentSender("http://sellari.example")
    with pytest.raises(ValueError):
        StdlibHttpsAgentSender("https://sellari.example/api/user")

    class Connection:
        def __init__(self, *args, **kwargs):
            raise AssertionError("network reached")

    sender = StdlibHttpsAgentSender(
        "https://sellari.example", connection_factory=Connection
    )
    with pytest.raises(AgentSecurityError):
        sender.request(
            "GET",
            "/api/users",
            headers={"Authorization": "Bearer " + TOKEN},
        )


def prepared_broker(tmp_path):
    write_store = WriteOperationStore(tmp_path / "write.sqlite")
    pipeline = WritePipeline(store=write_store, own_inn=OWN)
    doc = ExactDocumentBuilder.from_json_value({"withdrawReason": "DISTANCE"})
    op = pipeline.prepare(
        event_id="event-http-1",
        decision=Decision.READY_TO_WITHDRAW,
        document_type="LK_RECEIPT",
        operation_reason="DISTANCE",
        pg="lp",
        expected_inn=OWN,
        document=doc,
    )
    jobs = VpsAgentJobStore(tmp_path / "jobs.sqlite")
    broker = VpsAgentBroker(
        write_store=write_store,
        job_store=jobs,
        machine_auth=MachineTokenVerifier(TOKEN),
        own_inn=OWN,
    )
    return write_store, jobs, broker, op, doc


def test_vps_http_boundary_is_agent_only_and_machine_authenticated(tmp_path):
    write_store, jobs, broker, op, doc = prepared_broker(tmp_path)
    queued = broker.queue_write(op.operation_id)
    boundary = VpsAgentHttpBoundary(broker)

    unauthorized = boundary.handle(
        "GET", AGENT_FETCH_PATH, headers={"Cookie": "browser=session"}
    )
    assert unauthorized.status == 401

    denied = boundary.handle(
        "GET", "/api/user/me", headers={"Authorization": "Bearer " + TOKEN}
    )
    assert denied.status == 400

    response = boundary.handle(
        "GET", AGENT_FETCH_PATH, headers={"Authorization": "Bearer " + TOKEN}
    )
    assert response.status == 200
    decoded = json.loads(response.body)
    assert decoded["job_id"] == queued.job_id
    assert "private_key" not in decoded
    assert "pin" not in decoded


def test_vps_http_boundary_rejects_result_path_job_mismatch(tmp_path):
    write_store, jobs, broker, op, doc = prepared_broker(tmp_path)
    queued = broker.queue_write(op.operation_id)
    broker.fetch_one(TOKEN)
    boundary = VpsAgentHttpBoundary(broker)
    result = AgentResult(queued.job_id, op.operation_id, "MANUAL_REVIEW")
    body = json.dumps(result.safe_dict()).encode()
    response = boundary.handle(
        "POST",
        "/api/agent/v1/jobs/different-job/result",
        headers={"Authorization": "Bearer " + TOKEN},
        body=body,
    )
    assert response.status == 400


class StubSession:
    def bearer_token(self):
        return "LOCAL-TRUE-API-TOKEN"


class StubSigner:
    def __init__(self):
        self.calls = 0

    def sign_document_bytes(self, **kwargs):
        self.calls += 1
        return base64.b64encode(b"detached").decode(), {
            "certificate_thumbprint": "AA11",
            "certificate_subject": "CN=test",
            "certificate_inn": OWN,
            "certificate_valid_from": None,
            "certificate_valid_to": None,
        }


class StubTransport:
    def __init__(self):
        self.create_calls = 0

    def create_document(self, **kwargs):
        self.create_calls += 1
        return AgentHttpResponse(201, b'{"opaque":true}', {})


class ConfirmedIdParser:
    def parse_document_id(self, response):
        return "doc-runtime-confirmed"


def durable_executor(replay_store, transport, signer):
    return DurableWindowsAgentExecutor(
        participant_inn=OWN,
        transport=transport,
        session_manager=StubSession(),
        document_signer=signer,
        create_id_parser=ConfirmedIdParser(),
        production_write=True,
        replay_store=replay_store,
    )


def test_durable_replay_survives_agent_restart_and_blocks_second_create(tmp_path):
    job = sample_job()
    replay_path = tmp_path / "agent-replay.sqlite"
    transport = StubTransport()
    signer = StubSigner()

    with WindowsAgentReplayStore(replay_path) as replay:
        first = durable_executor(replay, transport, signer).execute(job)
        assert first.outcome == "SUBMITTED"
        assert replay.state(job.operation_id) == "COMPLETED"

    with WindowsAgentReplayStore(replay_path) as replay:
        second = durable_executor(replay, transport, signer).execute(job)
        assert second == first

    assert transport.create_calls == 1
    assert signer.calls == 1


def test_unresolved_local_create_reservation_fails_closed_after_restart(tmp_path):
    job = sample_job()
    replay_path = tmp_path / "agent-replay.sqlite"
    transport = StubTransport()
    signer = StubSigner()

    with WindowsAgentReplayStore(replay_path) as replay:
        assert replay.claim(job.operation_id, job.document_sha256) is None
        assert replay.state(job.operation_id) == "RESERVED"

    with WindowsAgentReplayStore(replay_path) as replay:
        executor = durable_executor(replay, transport, signer)
        with pytest.raises(AgentCreateOutcomeUnresolved):
            executor.execute(job)

    assert transport.create_calls == 0
    assert signer.calls == 0


def test_durable_replay_rejects_changed_payload_hash(tmp_path):
    job = sample_job()
    path = tmp_path / "agent-replay.sqlite"
    with WindowsAgentReplayStore(path) as replay:
        replay.claim(job.operation_id, job.document_sha256)
        with pytest.raises(Exception, match="different immutable document hash"):
            replay.claim(job.operation_id, "0" * 64)
