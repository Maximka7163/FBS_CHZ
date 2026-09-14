from __future__ import annotations

import base64
import json

import pytest

from wbcz.models import Decision
from wbcz.p0_write import (
    CertificateMetadata,
    DuplicateSubmitBlocked,
    HttpResponse,
    IdempotencyConflict,
    InMemoryWritePipelineStore,
    OperationNotFound,
    P0DocumentType,
    P0ExactDocumentBuilder,
    P0WritePipeline,
    PipelineOperation,
    ProductionWriteDisabled,
    SignatureRejected,
    SigningResponse,
    TrueApiWriteAdapter,
    UnsupportedP0Operation,
    WriteState,
)


INN = "1234567890"
EVENT_ID = "e" * 64
BODY = {"document_number": "WB-1", "products": [{"cis": "TEST-CIS"}]}
SIGNATURE = base64.b64encode(b"detached-cms-signature").decode("ascii")


class QueueTransport:
    def __init__(self, *responses: HttpResponse):
        self.responses = list(responses)
        self.requests = []

    def request(self, *, method, path, headers, body):
        self.requests.append({"method": method, "path": path, "headers": dict(headers), "body": body})
        if not self.responses:
            raise AssertionError("unexpected transport call")
        return self.responses.pop(0)


class FixtureCreateParser:
    contract_name = "TEST_CONFIRMED_FIXTURE_V1"

    def parse_document_id(self, response: HttpResponse) -> str | None:
        payload = json.loads(response.body.decode("utf-8"))
        value = payload.get("confirmed_document_id")
        return value if isinstance(value, str) and value else None


def make_pipeline(*responses: HttpResponse, parser=None, write_enabled=True):
    transport = QueueTransport(*responses)
    adapter = TrueApiWriteAdapter(
        transport,
        create_response_parser=parser,
        write_enabled=write_enabled,
    )
    store = InMemoryWritePipelineStore()
    return P0WritePipeline(store, true_api=adapter), store, transport


def prepare_and_sign(pipeline: P0WritePipeline):
    op = pipeline.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=BODY,
    )
    request = pipeline.create_signing_request(op.operation_id)
    signed = pipeline.accept_signature(
        SigningResponse(
            operation_id=op.operation_id,
            document_sha256=request.document_sha256,
            signature_base64=SIGNATURE,
            certificate=CertificateMetadata(
                certificate_inn=INN,
                certificate_thumbprint="AA11",
                certificate_subject="CN=TEST",
            ),
        )
    )
    return signed


def test_exact_document_bytes_equal_product_document_decode_and_body_mutation_cannot_change_them():
    body = {"z": 1, "a": ["x"]}
    prepared = P0ExactDocumentBuilder().prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=body,
    )
    before = prepared.product_document_base64
    body["z"] = 999
    assert base64.b64decode(prepared.product_document_base64) == prepared.bytes_for_signature
    assert prepared.product_document_base64 == before


def test_idempotent_prepare_returns_same_operation_and_changed_bytes_conflict():
    pipeline = P0WritePipeline(InMemoryWritePipelineStore())
    first = pipeline.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=BODY,
    )
    second = pipeline.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=BODY,
    )
    assert second.operation_id == first.operation_id
    with pytest.raises(IdempotencyConflict):
        pipeline.prepare(
            source_event_id=EVENT_ID,
            decision=Decision.READY_TO_WITHDRAW,
            operation_reason="DISTANCE",
            expected_inn=INN,
            document_body={"different": True},
        )


@pytest.mark.parametrize("decision", [Decision.MANUAL_REVIEW, Decision.ERROR])
def test_manual_review_and_error_cannot_enter_write_pipeline(decision):
    with pytest.raises(UnsupportedP0Operation):
        P0ExactDocumentBuilder().prepare(
            source_event_id=EVENT_ID,
            decision=decision,
            operation_reason="DISTANCE",
            expected_inn=INN,
            document_body=BODY,
        )


def test_wrong_operation_id_rejected():
    pipeline = P0WritePipeline(InMemoryWritePipelineStore())
    with pytest.raises(OperationNotFound):
        pipeline.accept_signature(
            SigningResponse(
                operation_id="missing",
                document_sha256="0" * 64,
                signature_base64=SIGNATURE,
                certificate=CertificateMetadata(certificate_inn=INN),
            )
        )


def test_hash_mismatch_signature_rejected():
    pipeline = P0WritePipeline(InMemoryWritePipelineStore())
    op = pipeline.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=BODY,
    )
    pipeline.create_signing_request(op.operation_id)
    with pytest.raises(SignatureRejected, match="document_sha256"):
        pipeline.accept_signature(
            SigningResponse(
                operation_id=op.operation_id,
                document_sha256="0" * 64,
                signature_base64=SIGNATURE,
                certificate=CertificateMetadata(certificate_inn=INN),
            )
        )


def test_wrong_certificate_inn_rejected():
    pipeline = P0WritePipeline(InMemoryWritePipelineStore())
    op = pipeline.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=BODY,
    )
    request = pipeline.create_signing_request(op.operation_id)
    with pytest.raises(SignatureRejected, match="certificate INN"):
        pipeline.accept_signature(
            SigningResponse(
                operation_id=op.operation_id,
                document_sha256=request.document_sha256,
                signature_base64=SIGNATURE,
                certificate=CertificateMetadata(certificate_inn="7701234567"),
            )
        )


def test_duplicate_signature_is_safe_and_line_wrapping_is_normalized():
    pipeline = P0WritePipeline(InMemoryWritePipelineStore())
    op = pipeline.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=BODY,
    )
    request = pipeline.create_signing_request(op.operation_id)
    wrapped = SIGNATURE[:6] + "\r\n" + SIGNATURE[6:]
    response = SigningResponse(
        operation_id=op.operation_id,
        document_sha256=request.document_sha256,
        signature_base64=wrapped,
        certificate=CertificateMetadata(certificate_inn=INN),
    )
    first = pipeline.accept_signature(response)
    second = pipeline.accept_signature(response)
    assert first.state is WriteState.SIGNED
    assert second.signature_base64 == SIGNATURE


def test_wrong_pg_and_unsupported_document_type_rejected_before_signing_request():
    builder = P0ExactDocumentBuilder()
    prepared = builder.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_WITHDRAW,
        operation_reason="DISTANCE",
        expected_inn=INN,
        document_body=BODY,
    )
    for field, value in (("pg", "other"), ("document_type", "ANY_DOCUMENT")):
        store = InMemoryWritePipelineStore()
        op = PipelineOperation.from_prepared(prepared)
        op.operation_id += field
        setattr(op, field, value)
        store.create_or_get_operation(op)
        pipeline = P0WritePipeline(store)
        with pytest.raises(UnsupportedP0Operation):
            pipeline.create_signing_request(op.operation_id)


def test_signing_request_is_whitelisted_contract_not_arbitrary_signing():
    pipeline = P0WritePipeline(InMemoryWritePipelineStore())
    op = pipeline.prepare(
        source_event_id=EVENT_ID,
        decision=Decision.READY_TO_RETURN,
        operation_reason="REMOTE_SALE_RETURN",
        expected_inn=INN,
        document_body=BODY,
    )
    request = pipeline.create_signing_request(op.operation_id)
    assert request.document_type == P0DocumentType.LP_RETURN.value
    assert request.pg == "lp"
    assert set(request.__dataclass_fields__) == {
        "request_id", "operation_id", "document_type", "pg", "expected_inn",
        "document_sha256", "product_document_base64",
    }


def test_production_write_is_default_off_and_state_is_not_changed():
    transport = QueueTransport()
    pipeline = P0WritePipeline(
        InMemoryWritePipelineStore(),
        true_api=TrueApiWriteAdapter(transport),
    )
    signed = prepare_and_sign(pipeline)
    with pytest.raises(ProductionWriteDisabled):
        pipeline.submit(signed.operation_id, bearer_token="token")
    assert pipeline.store.get_operation(signed.operation_id).state is WriteState.SIGNED
    assert not transport.requests


def test_create_request_exact_shape_reuses_stored_document_base64_and_has_no_second_document():
    response = HttpResponse(201, b'{"confirmed_document_id":"doc-1"}', {"Content-Type": "application/json"})
    pipeline, _, transport = make_pipeline(response, parser=FixtureCreateParser())
    signed = prepare_and_sign(pipeline)
    submitted = pipeline.submit(signed.operation_id, bearer_token="secret-token")
    assert submitted.state is WriteState.SUBMITTED
    request = transport.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/api/v3/true-api/lk/documents/create?pg=lp"
    assert request["headers"]["Authorization"] == "Bearer secret-token"
    body = json.loads(request["body"])
    assert body == {
        "document_format": "MANUAL",
        "product_document": signed.product_document_base64,
        "type": "LK_RECEIPT",
        "signature": SIGNATURE,
    }
    assert "second_product_document" not in body
    assert "second_signature" not in body


@pytest.mark.parametrize("status", [400, 401, 403, 422])
def test_immediate_create_errors_are_failed(status):
    pipeline, _, _ = make_pipeline(HttpResponse(status, b"{}"))
    signed = prepare_and_sign(pipeline)
    result = pipeline.submit(signed.operation_id, bearer_token="token")
    assert result.state is WriteState.FAILED
    assert result.last_http_status == status


def test_create_5xx_is_fail_closed_manual_review():
    pipeline, _, _ = make_pipeline(HttpResponse(503, b"upstream unavailable"))
    signed = prepare_and_sign(pipeline)
    result = pipeline.submit(signed.operation_id, bearer_token="token")
    assert result.state is WriteState.MANUAL_REVIEW


@pytest.mark.parametrize("status", [200, 201])
def test_unknown_create_success_envelope_is_not_success(status):
    pipeline, _, _ = make_pipeline(HttpResponse(status, b'{"something":"unknown"}'))
    signed = prepare_and_sign(pipeline)
    result = pipeline.submit(signed.operation_id, bearer_token="token")
    assert result.state is WriteState.MANUAL_REVIEW
    assert result.doc_id is None
    assert result.last_response_meta["parser_contract"] == "UNCONFIRMED"


def test_200_201_with_confirmed_parser_is_only_submitted_not_business_success():
    pipeline, _, _ = make_pipeline(
        HttpResponse(200, b'{"confirmed_document_id":"doc-1"}'),
        parser=FixtureCreateParser(),
    )
    signed = prepare_and_sign(pipeline)
    result = pipeline.submit(signed.operation_id, bearer_token="token")
    assert result.state is WriteState.SUBMITTED
    assert result.doc_id == "doc-1"
    assert not result.reconciliation_required


def test_duplicate_submit_is_blocked_before_second_transport_call():
    pipeline, _, transport = make_pipeline(
        HttpResponse(201, b'{"confirmed_document_id":"doc-1"}'),
        parser=FixtureCreateParser(),
    )
    signed = prepare_and_sign(pipeline)
    pipeline.submit(signed.operation_id, bearer_token="token")
    with pytest.raises(DuplicateSubmitBlocked):
        pipeline.submit(signed.operation_id, bearer_token="token")
    assert len(transport.requests) == 1


def submitted_pipeline_with_poll(poll_status: str):
    pipeline, store, transport = make_pipeline(
        HttpResponse(201, b'{"confirmed_document_id":"doc-1"}'),
        HttpResponse(200, json.dumps({"status": poll_status}).encode("utf-8")),
        parser=FixtureCreateParser(),
    )
    signed = prepare_and_sign(pipeline)
    pipeline.submit(signed.operation_id, bearer_token="token")
    return pipeline, store, transport, signed.operation_id


def test_poll_checked_ok_transitions_through_success_to_reconciliation_required():
    pipeline, store, transport, op_id = submitted_pipeline_with_poll("CHECKED_OK")
    result = pipeline.poll(op_id, bearer_token="token")
    assert result.state is WriteState.RECONCILIATION_REQUIRED
    assert result.reconciliation_required is True
    assert transport.requests[-1]["path"] == "/api/v4/true-api/doc/doc-1/info"
    transitions = [(a.from_state, a.to_state) for a in store.audit_for_operation(op_id)]
    assert (WriteState.SUBMITTED.value, WriteState.SUCCEEDED.value) in transitions
    assert (WriteState.SUCCEEDED.value, WriteState.RECONCILIATION_REQUIRED.value) in transitions


@pytest.mark.parametrize("status", ["CHECKED_NOT_OK", "PARSE_ERROR", "PROCESSING_ERROR"])
def test_poll_terminal_failures(status):
    pipeline, _, _, op_id = submitted_pipeline_with_poll(status)
    assert pipeline.poll(op_id, bearer_token="token").state is WriteState.FAILED


@pytest.mark.parametrize("status", ["UNDEFINED", "SOMETHING_NEW"])
def test_poll_unknown_status_is_manual_review(status):
    pipeline, _, _, op_id = submitted_pipeline_with_poll(status)
    assert pipeline.poll(op_id, bearer_token="token").state is WriteState.MANUAL_REVIEW


@pytest.mark.parametrize("status", ["IN_PROGRESS", "WAIT_FOR_CONTINUATION"])
def test_poll_intermediate_statuses_are_processing(status):
    pipeline, _, _, op_id = submitted_pipeline_with_poll(status)
    assert pipeline.poll(op_id, bearer_token="token").state is WriteState.PROCESSING


def test_audit_transition_coverage_has_no_document_or_signature_payloads():
    pipeline, store, _, op_id = submitted_pipeline_with_poll("CHECKED_OK")
    pipeline.poll(op_id, bearer_token="token")
    entries = store.audit_for_operation(op_id)
    assert {entry.to_state for entry in entries} >= {
        "PREPARED", "AWAITING_SIGNATURE", "SIGNED", "SUBMITTING", "SUBMITTED",
        "SUCCEEDED", "RECONCILIATION_REQUIRED",
    }
    serialized = json.dumps([entry.metadata for entry in entries], sort_keys=True)
    assert SIGNATURE not in serialized
    assert "TEST-CIS" not in serialized
    assert "secret-token" not in serialized
