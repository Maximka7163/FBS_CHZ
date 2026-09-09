import pytest

from wbcz.document_builder import FakeDocumentBuilder
from wbcz.models import Decision, DocumentReport, DocumentStatus
from wbcz.service import ImportService
from wbcz.signing import FakeSigningAdapter
from wbcz.status_verifier import DocumentTracker, FakeStatusVerifier
from wbcz.submission import FakeSubmissionService


def test_T11_accepted_then_rejected_is_not_success(
    store, wb_row, make_xlsx,
):
    ImportService(store).import_file(make_xlsx([wb_row]))
    event = store.events()[0]
    store.register_document(event.event_id, "fake-document")
    assert not store.document_report("fake-document").successful
    verifier = FakeStatusVerifier([
        DocumentReport(DocumentStatus.PROCESSING),
        DocumentReport(DocumentStatus.REJECTED, "mock business rejection"),
    ])
    tracker = DocumentTracker(store, verifier)
    assert not tracker.refresh("fake-document").successful
    final = tracker.refresh("fake-document")
    assert final.status is DocumentStatus.REJECTED
    assert not final.successful
    assert len(store.document_history("fake-document")) == 3


def test_accepted_then_poll_error_is_retryable_not_success(
    store, wb_row, make_xlsx,
):
    ImportService(store).import_file(make_xlsx([wb_row]))
    store.register_document(store.events()[0].event_id, "fake-document")
    verifier = FakeStatusVerifier([
        TimeoutError("mock poll timeout"),
        DocumentReport(DocumentStatus.SUCCEEDED),
    ])
    tracker = DocumentTracker(store, verifier)
    failed_poll = tracker.refresh("fake-document")
    assert failed_poll.status is DocumentStatus.VERIFICATION_ERROR
    assert not failed_poll.successful
    assert tracker.refresh("fake-document").successful


def test_fake_interfaces_are_idempotent_and_not_real_documents(event):
    builder = FakeDocumentBuilder()
    signer = FakeSigningAdapter()
    submission = FakeSubmissionService()
    built = builder.build(event, Decision.READY_TO_WITHDRAW)
    signed = signer.sign(built.payload)
    first = submission.submit(signed, idempotency_key=event.event_id)
    second = submission.submit(signed, idempotency_key=event.event_id)
    assert first == second
    assert submission.created_count == 1
    assert signed.startswith(b"TEST-ONLY-NOT-A-SIGNATURE:")
    with pytest.raises(ValueError, match="другим содержимым"):
        submission.submit(b"different", idempotency_key=event.event_id)


def test_terminal_document_status_is_not_overwritten(
    store, wb_row, make_xlsx,
):
    ImportService(store).import_file(make_xlsx([wb_row]))
    store.register_document(store.events()[0].event_id, "fake-document")
    store.update_document(
        "fake-document", DocumentReport(DocumentStatus.REJECTED, "reason"),
    )
    with pytest.raises(ValueError, match="терминальный"):
        store.update_document(
            "fake-document", DocumentReport(DocumentStatus.SUCCEEDED),
        )
