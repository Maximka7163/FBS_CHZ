from __future__ import annotations

import base64
import json

import pytest

from wbcz.models import Decision
from wbcz.write_pipeline import (
    CreateCategory,
    DuplicateSubmitBlocked,
    ExactDocumentBuilder,
    HttpResponse,
    InvalidWriteOperation,
    PollClassification,
    ProductionWriteDisabled,
    ReplayConflict,
    SigningResponse,
    TrueApiPollingAdapter,
    TrueApiWriteAdapter,
    WriteOperationStore,
    WritePipeline,
    WriteState,
)


class FakeTransport:
    def __init__(self, post_response=None, get_response=None):
        self.post_response = post_response or HttpResponse(
            201, b"{}", {"Content-Type": "application/json"}
        )
        self.get_response = get_response or HttpResponse(
            200, b"{}", {"Content-Type": "application/json"}
        )
        self.posts = []
        self.gets = []

    def post_json(self, url, *, headers, body):
        self.posts.append((url, dict(headers), dict(body)))
        if isinstance(self.post_response, Exception):
            raise self.post_response
        return self.post_response

    def get(self, url, *, headers):
        self.gets.append((url, dict(headers)))
        if isinstance(self.get_response, Exception):
            raise self.get_response
        return self.get_response


class ConfirmedIdParser:
    def __init__(self, value="doc-1"):
        self.value = value

    def parse_document_id(self, response):
        return self.value


class FixedStatusParser:
    def __init__(self, status):
        self.status = status

    def parse_status(self, response):
        return self.status


def make_pipeline(
    tmp_path, *, write=False, post_status=201, parser=None, poll_status="IN_PROGRESS"
):
    transport = FakeTransport(
        post_response=HttpResponse(
            post_status,
            b'{"opaque":"response"}',
            {"Content-Type": "application/json"},
        ),
        get_response=HttpResponse(
            200, b'{"opaque":"poll"}', {"Content-Type": "application/json"}
        ),
    )
    writer = TrueApiWriteAdapter(
        base_url="https://markirovka.crpt.ru",
        authorization="SECRET_TOKEN",
        transport=transport,
        success_parser=parser,
    )
    poller = TrueApiPollingAdapter(
        base_url="https://markirovka.crpt.ru",
        authorization="SECRET_TOKEN",
        transport=transport,
        status_parser=FixedStatusParser(poll_status),
    )
    store = WriteOperationStore(tmp_path / "write.sqlite")
    pipeline = WritePipeline(
        store=store,
        own_inn="1234567890",
        writer=writer,
        poller=poller,
        true_api_write=write,
    )
    return pipeline, store, transport


def prepare_sale(pipeline, payload=None):
    doc = ExactDocumentBuilder.from_json_value(
        payload or {"type": "fixture", "withdrawReason": "DISTANCE"}
    )
    op = pipeline.prepare(
        event_id="event-sale-1",
        decision=Decision.READY_TO_WITHDRAW,
        document_type="LK_RECEIPT",
        operation_reason="DISTANCE",
        pg="lp",
        expected_inn="1234567890",
        document=doc,
    )
    return op, doc


def sign(pipeline, op, doc, sig=b"detached-signature"):
    return pipeline.accept_signature(
        SigningResponse(
            operation_id=op.operation_id,
            document_sha256=doc.sha256,
            signature_base64=base64.b64encode(sig).decode("ascii"),
            certificate_thumbprint="AA11",
            certificate_subject="CN=Test",
            certificate_inn="1234567890",
        )
    )


def test_exact_signed_bytes_equal_product_document(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    req = pipeline.pending_signing_request(op.operation_id)
    assert req.document_sha256 == doc.sha256
    assert base64.b64decode(req.product_document_base64) == doc.bytes_for_signature


def test_no_reserialization_after_prepare(tmp_path):
    source = {"a": 1, "nested": {"x": "y"}}
    doc = ExactDocumentBuilder.from_json_value(source)
    source["a"] = 999
    assert json.loads(doc.payload)["a"] == 1
    pipeline, store, transport = make_pipeline(
        tmp_path, write=True, parser=ConfirmedIdParser()
    )
    op = pipeline.prepare(
        event_id="event-sale-1",
        decision=Decision.READY_TO_WITHDRAW,
        document_type="LK_RECEIPT",
        operation_reason="DISTANCE",
        pg="lp",
        expected_inn="1234567890",
        document=doc,
    )
    original = op.product_document_base64
    sign(pipeline, op, doc)
    pipeline.submit(op.operation_id)
    assert transport.posts[0][2]["product_document"] == original


def test_hash_mismatch_rejected(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    with pytest.raises(InvalidWriteOperation):
        pipeline.accept_signature(
            SigningResponse(
                op.operation_id,
                "0" * 64,
                base64.b64encode(b"sig").decode(),
            )
        )


def test_wrong_operation_id_rejected(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    with pytest.raises(KeyError):
        pipeline.accept_signature(
            SigningResponse(
                "op_missing", doc.sha256, base64.b64encode(b"sig").decode()
            )
        )


@pytest.mark.parametrize("pg", ["shoes", "", "LP"])
def test_wrong_pg_rejected(tmp_path, pg):
    pipeline, store, _ = make_pipeline(tmp_path)
    doc = ExactDocumentBuilder.from_json_value({"x": 1})
    with pytest.raises(InvalidWriteOperation):
        pipeline.prepare(
            event_id="e",
            decision=Decision.READY_TO_WITHDRAW,
            document_type="LK_RECEIPT",
            operation_reason="DISTANCE",
            pg=pg,
            expected_inn="1234567890",
            document=doc,
        )


def test_unsupported_document_type_rejected(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    doc = ExactDocumentBuilder.from_json_value({"x": 1})
    with pytest.raises(InvalidWriteOperation):
        pipeline.prepare(
            event_id="e",
            decision=Decision.READY_TO_WITHDRAW,
            document_type="ARBITRARY",
            operation_reason="DISTANCE",
            pg="lp",
            expected_inn="1234567890",
            document=doc,
        )


def test_wrong_expected_inn_rejected(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    doc = ExactDocumentBuilder.from_json_value({"x": 1})
    with pytest.raises(InvalidWriteOperation):
        pipeline.prepare(
            event_id="e",
            decision=Decision.READY_TO_WITHDRAW,
            document_type="LK_RECEIPT",
            operation_reason="DISTANCE",
            pg="lp",
            expected_inn="9999999999",
            document=doc,
        )


def test_duplicate_signature_safe(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    signed = sign(pipeline, op, doc)
    replay = sign(pipeline, op, doc)
    assert signed.state is WriteState.SIGNED
    assert replay.state is WriteState.SIGNED
    assert any(
        x["action"] == "SIGNATURE_REPLAY_IDEMPOTENT"
        for x in store.audit_entries(op.operation_id)
    )


def test_prepare_replay_idempotent_and_changed_bytes_conflict(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    same, _ = prepare_sale(pipeline)
    assert same.operation_id == op.operation_id
    changed = ExactDocumentBuilder.from_json_value({"changed": True})
    with pytest.raises(ReplayConflict):
        pipeline.prepare(
            event_id="event-sale-1",
            decision=Decision.READY_TO_WITHDRAW,
            document_type="LK_RECEIPT",
            operation_reason="DISTANCE",
            pg="lp",
            expected_inn="1234567890",
            document=changed,
        )


def test_duplicate_submit_blocked(tmp_path):
    pipeline, store, transport = make_pipeline(
        tmp_path, write=True, parser=ConfirmedIdParser()
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    submitted = pipeline.submit(op.operation_id)
    assert submitted.state is WriteState.SUBMITTED
    with pytest.raises(DuplicateSubmitBlocked):
        pipeline.submit(op.operation_id)
    assert len(transport.posts) == 1


def test_manual_review_and_error_cannot_submit(tmp_path):
    pipeline, store, transport = make_pipeline(
        tmp_path, write=True, parser=ConfirmedIdParser()
    )
    op, doc = prepare_sale(pipeline)
    store.mark_manual_review(op.operation_id, reason="test")
    with pytest.raises(InvalidWriteOperation):
        pipeline.submit(op.operation_id)

    op2 = pipeline.prepare(
        event_id="event-sale-2",
        decision=Decision.READY_TO_WITHDRAW,
        document_type="LK_RECEIPT",
        operation_reason="DISTANCE",
        pg="lp",
        expected_inn="1234567890",
        document=doc,
    )
    sign(pipeline, op2, doc)
    store.mark_error(op2.operation_id, error_type="test")
    with pytest.raises(InvalidWriteOperation):
        pipeline.submit(op2.operation_id)
    assert len(transport.posts) == 0


def test_production_write_default_off(tmp_path):
    pipeline, store, transport = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    assert pipeline.true_api_write is False
    with pytest.raises(ProductionWriteDisabled):
        pipeline.submit(op.operation_id)
    assert transport.posts == []


def test_exact_create_request_shape_and_no_second_fields(tmp_path):
    pipeline, store, transport = make_pipeline(
        tmp_path, write=True, parser=ConfirmedIdParser()
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    pipeline.submit(op.operation_id)
    url, headers, body = transport.posts[0]
    assert url == (
        "https://markirovka.crpt.ru/api/v3/true-api/lk/documents/create?pg=lp"
    )
    assert headers == {
        "Authorization": "SECRET_TOKEN",
        "Content-Type": "application/json",
    }
    assert set(body) == {
        "document_format",
        "product_document",
        "type",
        "signature",
    }
    assert body["document_format"] == "MANUAL"
    assert body["type"] == "LK_RECEIPT"
    assert body["product_document"] == op.product_document_base64
    assert "\n" not in body["signature"] and "\r" not in body["signature"]
    assert "second_product_document" not in body
    assert "second_signature" not in body


@pytest.mark.parametrize(
    "status,category",
    [
        (400, CreateCategory.BAD_REQUEST),
        (401, CreateCategory.UNAUTHORIZED),
        (403, CreateCategory.FORBIDDEN),
        (422, CreateCategory.UNPROCESSABLE),
        (500, CreateCategory.SERVER_ERROR),
        (503, CreateCategory.SERVER_ERROR),
    ],
)
def test_immediate_errors_classified(tmp_path, status, category):
    pipeline, store, transport = make_pipeline(
        tmp_path, write=True, post_status=status
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    result = pipeline.submit(op.operation_id)
    if status >= 500:
        assert result.state is WriteState.MANUAL_REVIEW
    else:
        assert result.state is WriteState.FAILED
    row = store._connection.execute(
        "select submit_category from write_operations where operation_id=?",
        (op.operation_id,),
    ).fetchone()
    assert row[0] == category.value


@pytest.mark.parametrize("status", [200, 201])
def test_success_http_is_not_business_success_and_unknown_envelope_fails_closed(
    tmp_path, status
):
    pipeline, store, transport = make_pipeline(
        tmp_path, write=True, post_status=status, parser=None
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    result = pipeline.submit(op.operation_id)
    assert result.state is WriteState.MANUAL_REVIEW
    assert result.document_id is None


def test_confirmed_create_id_is_only_submitted_not_succeeded(tmp_path):
    pipeline, store, transport = make_pipeline(
        tmp_path, write=True, parser=ConfirmedIdParser("known-id")
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    result = pipeline.submit(op.operation_id)
    assert result.state is WriteState.SUBMITTED
    assert result.document_id == "known-id"


def test_checked_ok_requires_reconciliation_then_succeeds(tmp_path):
    pipeline, store, transport = make_pipeline(
        tmp_path,
        write=True,
        parser=ConfirmedIdParser(),
        poll_status="CHECKED_OK",
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    pipeline.submit(op.operation_id)
    polled, classification = pipeline.poll_once(op.operation_id)
    assert classification is PollClassification.TERMINAL_SUCCESS
    assert polled.state is WriteState.RECONCILIATION_REQUIRED
    final = store.reconciliation_result(
        op.operation_id, confirmed=True, details={"source": "cises/info"}
    )
    assert final.state is WriteState.SUCCEEDED


@pytest.mark.parametrize(
    "status", ["CHECKED_NOT_OK", "PARSE_ERROR", "PROCESSING_ERROR"]
)
def test_polling_failure_statuses(tmp_path, status):
    pipeline, store, transport = make_pipeline(
        tmp_path,
        write=True,
        parser=ConfirmedIdParser(),
        poll_status=status,
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    pipeline.submit(op.operation_id)
    polled, classification = pipeline.poll_once(op.operation_id)
    assert classification is PollClassification.TERMINAL_FAILURE
    assert polled.state is WriteState.FAILED


@pytest.mark.parametrize("status", ["UNDEFINED", "SOMETHING_NEW", None])
def test_unknown_poll_status_manual_review(tmp_path, status):
    pipeline, store, transport = make_pipeline(
        tmp_path,
        write=True,
        parser=ConfirmedIdParser(),
        poll_status=status,
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    pipeline.submit(op.operation_id)
    polled, classification = pipeline.poll_once(op.operation_id)
    assert classification is PollClassification.MANUAL_REVIEW
    assert polled.state is WriteState.MANUAL_REVIEW


@pytest.mark.parametrize("status", ["IN_PROGRESS", "WAIT_FOR_CONTINUATION"])
def test_intermediate_polling(tmp_path, status):
    pipeline, store, transport = make_pipeline(
        tmp_path,
        write=True,
        parser=ConfirmedIdParser(),
        poll_status=status,
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    pipeline.submit(op.operation_id)
    polled, classification = pipeline.poll_once(op.operation_id)
    assert classification is PollClassification.INTERMEDIATE
    assert polled.state is WriteState.PROCESSING


def test_audit_transition_coverage_and_no_secret(tmp_path):
    pipeline, store, transport = make_pipeline(
        tmp_path,
        write=True,
        parser=ConfirmedIdParser(),
        poll_status="CHECKED_OK",
    )
    op, doc = prepare_sale(pipeline)
    sign(pipeline, op, doc)
    pipeline.submit(op.operation_id)
    pipeline.poll_once(op.operation_id)
    store.reconciliation_result(op.operation_id, confirmed=True)
    entries = store.audit_entries(op.operation_id)
    actions = {e["action"] for e in entries}
    assert {
        "OPERATION_PREPARED",
        "SIGNING_REQUEST_PENDING",
        "SIGNATURE_ACCEPTED",
        "SUBMIT_RESERVED",
        "SUBMIT_RESULT",
        "POLL_TERMINAL",
        "RECONCILIATION_RESULT",
    } <= actions
    serialized = json.dumps(entries)
    assert "SECRET_TOKEN" not in serialized
    assert "PRIVATE_KEY" not in serialized
    assert "PIN" not in serialized


def test_no_arbitrary_signing_contract(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    req = pipeline.pending_signing_request(op.operation_id)
    assert req.document_type in {"LK_RECEIPT", "LP_RETURN"}
    assert req.pg == "lp"
    assert not hasattr(pipeline, "sign")
    assert not hasattr(store, "sign_any")


def test_certificate_inn_mismatch_rejected(tmp_path):
    pipeline, store, _ = make_pipeline(tmp_path)
    op, doc = prepare_sale(pipeline)
    with pytest.raises(InvalidWriteOperation):
        pipeline.accept_signature(
            SigningResponse(
                op.operation_id,
                doc.sha256,
                base64.b64encode(b"sig").decode(),
                certificate_inn="9999999999",
            )
        )
