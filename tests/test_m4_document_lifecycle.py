from __future__ import annotations

import json
from pathlib import Path

import pytest

import wbcz.document_lifecycle as lifecycle_module
from wbcz.document_lifecycle import (
    DOCUMENT_STATUS_REGISTRY,
    DOCUMENT_TYPE_REGISTRY,
    M4_READ_JOB_TYPES,
    DocumentFormat,
    DocumentLifecycleContractError,
    build_document_read_spec,
    capture_create_response,
    classify_direct_status,
    local_idempotency_key,
    parse_document_cises,
    parse_document_info,
    parse_document_list,
    validate_m4_job_payload,
)
from wbcz.windows_agent import AgentHttpResponse, AgentJob, AgentJobType, P0_PG, WindowsAgentExecutor


INN = "1234567890"


def test_document_type_and_format_registry_matches_accepted_v726_contract():
    assert {item.value for item in DocumentFormat} == {"MANUAL", "XML", "CSV"}
    assert DOCUMENT_TYPE_REGISTRY["LK_RECEIPT"].formats == (DocumentFormat.MANUAL,)
    assert DOCUMENT_TYPE_REGISTRY["LP_RETURN"].formats == (DocumentFormat.MANUAL,)
    assert DOCUMENT_TYPE_REGISTRY["UNIVERSAL_TRANSFER_DOCUMENT"].formats == (DocumentFormat.XML,)
    assert DOCUMENT_TYPE_REGISTRY["LK_RECEIPT_CSV"].formats == (DocumentFormat.CSV,)
    assert "ADDOPTION" not in {item.value for item in DocumentFormat}
    assert not hasattr(lifecycle_module, "LocalDocumentCategory")
    assert not hasattr(lifecycle_module, "LocalProcessingErrorCode")
    source = Path("src/wbcz/document_lifecycle.py").read_text(encoding="utf-8")
    assert all(value not in source for value in ("ADDOPTION", "AGENCY", "OTHER", "INVALID_DOCUMENT_ID", "INVALID_DOCUMENT_STATUS", "DOCUMENT_ALREADY_PROCESSED", "CONTRACT_ERROR"))


def test_raw_status_registry_preserves_official_inconsistency_and_unknown_values():
    assert "CANCELLED" in DOCUMENT_STATUS_REGISTRY
    assert "CANCELED" in DOCUMENT_STATUS_REGISTRY
    assert classify_direct_status("CHECKED_OK").value == "SUCCESS"
    assert classify_direct_status("IN_PROGRESS").value == "INTERMEDIATE"
    assert classify_direct_status("PROCESSING_ERROR").value == "FAILURE"
    assert classify_direct_status("ACCEPTED").value == "UNKNOWN"
    assert classify_direct_status("FUTURE_STATUS").value == "UNKNOWN"


def test_document_list_typed_wire_filters_and_only_document_id_alias():
    payload = {
        "document_id": "doc-1",
        "number": "official-number",
        "document_type_code": ["LK_RECEIPT", "LP_RETURN"],
        "document_status_code": "CHECKED_OK",
        "date_from": "2026-09-01T00:00:00+03:00",
        "date_to": "2026-09-17T23:59:59+03:00",
        "ordered_column_value": "2026-09-17T12:00:00Z",
        "page_dir": "NEXT",
        "limit": 1000,
        "order": "DESC",
        "sender_inn": INN,
    }
    canonical = validate_m4_job_payload("DOCUMENT_LIST", payload)
    assert canonical["did"] == "doc-1"
    assert "document_id" not in canonical
    assert canonical["number"] == "official-number"
    spec = build_document_read_spec("DOCUMENT_LIST", payload)
    assert spec.method == "GET"
    assert spec.target.startswith("/api/v4/true-api/doc/list?")
    assert "pg=lp" in spec.target
    assert "did=doc-1" in spec.target
    assert "number=official-number" in spec.target
    assert "documentStatus=CHECKED_OK" in spec.target
    assert spec.target.count("documentType=") == 2
    assert "orderedColumnValue=" in spec.target and "pageDir=NEXT" in spec.target
    assert "senderInn=1234567890" in spec.target
    assert "operation=" not in spec.target and "page=" not in spec.target


def test_document_list_rejects_removed_aliases_and_invented_filters():
    with pytest.raises(DocumentLifecycleContractError):
        validate_m4_job_payload("DOCUMENT_LIST", {"operation": "CHECKED_OK"})
    with pytest.raises(DocumentLifecycleContractError):
        validate_m4_job_payload("DOCUMENT_LIST", {"page": {"ordered_column_value": "x", "direction": "NEXT"}})
    with pytest.raises(DocumentLifecycleContractError):
        validate_m4_job_payload("DOCUMENT_LIST", {"document_id": "doc-1", "did": "doc-1"})
    with pytest.raises(DocumentLifecycleContractError):
        validate_m4_job_payload("DOCUMENT_LIST", {"sender_inn": INN, "receiver_inn": INN})
    with pytest.raises(DocumentLifecycleContractError):
        validate_m4_job_payload("DOCUMENT_LIST", {"cancel": True})


def test_document_info_expanded_metadata_errors_without_edo_placeholders():
    payload = {
        "number": "doc-1",
        "docDate": "2026-09-17T10:00:00Z",
        "receivedAt": "2026-09-17T10:00:01Z",
        "type": "LK_RECEIPT",
        "status": "FUTURE_SERVER_STATUS",
        "senderInn": INN,
        "senderName": "Sender",
        "senderMod": {"kpp": "1"},
        "receiverInn": None,
        "receiverName": None,
        "receiverMod": None,
        "invoiceNumber": None,
        "invoiceDate": None,
        "relatedDocId": None,
        "turnoverType": "SELLING",
        "body": {"inn": INN},
        "content": "server-content",
        "input": False,
        "errors": ["raw operation error"],
        "commonErrors": [
            {"errorCode": "INTRO_ERROR", "errorMessage": "bad", "errorObject": {"field": "x"}},
            {"errorCode": "ERROR_777", "errorMessage": "other", "errorObject": None},
        ],
        "productGroup": ["lp"],
        "productGroupId": [1],
        "eliminationReason": "DISTANCE",
        "futureField": 42,
    }
    parsed = parse_document_info(payload)
    assert parsed["status"]["raw"] == "FUTURE_SERVER_STATUS"
    assert parsed["status"]["known"] is False
    assert parsed["errors"] == [{"raw_message": "raw operation error"}]
    assert parsed["commonErrors"][0]["raw_code"] == "INTRO_ERROR"
    assert "local_code" not in parsed["commonErrors"][0]
    assert parsed["commonErrors"][1]["raw_code"] == "ERROR_777"
    assert all(key not in parsed for key in ("operations", "attachments", "receipts", "generic_capabilities"))
    assert parsed["raw"]["futureField"] == 42


def test_document_cises_preserves_cis_and_product_envelopes_without_invention():
    parsed = parse_document_cises({
        "senderInn": INN,
        "type": "LK_RECEIPT",
        "status": "CHECKED_OK",
        "receivedAt": "2026-09-17T10:00:00Z",
        "documentId": "doc-1",
        "turnoverType": "SELLING",
        "relatedDocId": None,
        "cisList": ["010460123456789021ABC"],
        "products": [{"gtin": "04601234567890", "cis": ["x"]}],
        "future": True,
    })
    assert parsed["documentId"] == "doc-1"
    assert parsed["status"]["direct_class"] == "SUCCESS"
    assert parsed["cisList"] == ["010460123456789021ABC"]
    assert parsed["products"][0]["gtin"] == "04601234567890"
    assert parsed["raw"]["future"] is True


def test_m4_agent_jobs_are_typed_and_cannot_become_arbitrary_proxy():
    assert M4_READ_JOB_TYPES == {"DOCUMENT_LIST", "DOCUMENT_INFO", "DOCUMENT_CISES"}
    assert not any(name in AgentJobType.__members__ for name in {"TRUE_API_GENERIC", "TRUE_API_REQUEST", "RAW_URL", "RAW_PATH", "GENERIC_GET"})
    job = AgentJob(
        "j-m4",
        AgentJobType.DOCUMENT_INFO,
        "m4-op",
        P0_PG,
        INN,
        read_payload={"document_id": "doc-1", "body": True, "content": True},
    )
    job.validate()
    with pytest.raises(Exception):
        AgentJob(
            "j-bad",
            AgentJobType.DOCUMENT_INFO,
            "m4-op-bad",
            P0_PG,
            INN,
            read_payload={"document_id": "doc-1", "url": "https://example.com"},
        ).validate()


def test_local_idempotency_is_operation_plus_request_hash_and_not_hash_only():
    body = b'{"document_id":"doc-1"}'
    one = local_idempotency_key("operation-A", body)
    two = local_idempotency_key("operation-B", body)
    assert one != two
    assert one.startswith("operation-A:")
    assert one.split(":", 1)[1] == two.split(":", 1)[1]


def test_create_success_raw_capture_does_not_guess_document_id():
    raw = b'{"futureServerEnvelope":{"value":"abc"}}'
    captured = capture_create_response(201, {"Content-Type": "application/json"}, raw)
    assert captured.http_status == 201
    assert captured.parsed_json == {"futureServerEnvelope": {"value": "abc"}}
    assert captured.raw_body_base64
    assert not hasattr(captured, "document_id")


class _Session:
    def bearer_token(self): return "secret-token"
    def observe_http_status(self, status): self.status = status


class _Transport:
    def __init__(self): self.calls = []
    def m4_read(self, job_type, payload, *, bearer_token):
        assert bearer_token == "secret-token"
        self.calls.append((job_type, payload))
        if job_type == "DOCUMENT_INFO":
            body = json.dumps({"number": "doc-1", "type": "LK_RECEIPT", "status": "CHECKED_OK", "errors": [], "commonErrors": []}).encode()
        elif job_type == "DOCUMENT_LIST":
            body = json.dumps({"results": [], "nextPage": False}).encode()
        else:
            body = json.dumps({"documentId": "doc-1", "status": "CHECKED_OK", "cisList": []}).encode()
        return AgentHttpResponse(200, body, {"Content-Type": "application/json"})


class _Signer:
    pass


def test_windows_executor_routes_m4_through_typed_read_only_transport():
    transport = _Transport()
    executor = WindowsAgentExecutor(
        participant_inn=INN,
        transport=transport,
        session_manager=_Session(),
        document_signer=_Signer(),
        production_write=False,
    )
    job = AgentJob(
        "j-info",
        AgentJobType.DOCUMENT_INFO,
        "op-info",
        P0_PG,
        INN,
        read_payload={"document_id": "doc-1", "body": False, "content": False},
    )
    result = executor.execute(job)
    assert result.outcome == "READ_COMPLETED"
    assert result.read_result["number"] == "doc-1"
    assert result.read_result["status"]["raw"] == "CHECKED_OK"
    assert transport.calls == [("DOCUMENT_INFO", {"document_id": "doc-1", "body": False, "content": False})]


def test_no_generic_retry_cancel_delete_or_edo_business_implementation():
    source = Path("src/wbcz/document_lifecycle.py").read_text(encoding="utf-8")
    assert "def generic_retry" not in source
    assert "def generic_cancel" not in source
    assert "def generic_delete" not in source
    assert "TODO M4 optional-later" in source
    assert "TODO business-specific" in source
