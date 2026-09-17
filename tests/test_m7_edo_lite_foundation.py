from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import zipfile

import pytest

from wbcz.windows_agent import AgentJob, AgentJobType
from wbcz.edo_lite import (
    BINARY_EDO_READ_JOB_TYPES,
    CURRENT_FNS_736_STATUS,
    EDO_LITE_ANNUAL_OUTGOING_LIMIT,
    KNOWN_EDO_RAW_STATUSES,
    M7_MUTATION_REGISTRY,
    M7_PRODUCT_GROUP_WIRE_VALUE,
    M7_READ_JOB_TYPES,
    MCHD_RAW_STATUSES,
    PRODUCTION_SCHEMA_REGISTRY,
    REPLACEMENT_FNS_ORDER,
    TRUE_API_ENDPOINT_FORMAT_UKD,
    UKD_FORMAT_COMPATIBILITY,
    AnnualQuotaObservation,
    EdoReadSpec,
    BlobSource,
    EdoLiteContractError,
    EdoLiteSecurityError,
    GisProcessingState,
    IdFileConflict,
    ImmutableDocumentBlob,
    LocalEdoState,
    M1ReconciliationAdapter,
    M6ReconciliationAdapter,
    M7SchemaNotEnabled,
    OfflineXmlValidator,
    ReconciliationEvidence,
    build_edo_read_spec,
    capture_edo_read_success,
    classify_id_file_conflict,
    create_m7_signing_envelope,
    final_business_success,
    inspect_legal_zip_safely,
    is_allowed_edo_read_target,
    opaque_remote_id,
    parse_edo_raw_status,
    parse_gis_processing_result,
    reconcile_local_state,
    require_m7_mutation_enabled,
    validate_edo_read_payload,
)


def canonical(job_type: str, payload: dict) -> dict:
    return validate_edo_read_payload(job_type, payload)


def test_endpoint_allowlist_and_payload_security() -> None:
    participant = build_edo_read_spec("EDO_PARTICIPANT", canonical("EDO_PARTICIPANT", {"inn": "1234567890"}))
    assert participant.method == "GET"
    assert participant.target == "/api/v4/true-api/edo/inn/1234567890"
    assert is_allowed_edo_read_target(participant)

    outgoing = build_edo_read_spec("EDO_OUTGOING_LIST", canonical("EDO_OUTGOING_LIST", {}))
    assert outgoing.target.startswith("/api/v3/true-api/elk/outgoing-documents?")
    assert "limit=10" in outgoing.target and "offset=0" in outgoing.target
    assert "sortBy=created_at" in outgoing.target and "asc=false" in outgoing.target
    assert is_allowed_edo_read_target(outgoing)

    with pytest.raises(EdoLiteContractError):
        validate_edo_read_payload("EDO_OUTGOING_LIST", {"url": "https://evil.invalid"})
    with pytest.raises(EdoLiteContractError):
        validate_edo_read_payload("EDO_OUTGOING_LIST", {"method": "POST"})
    with pytest.raises(EdoLiteContractError):
        validate_edo_read_payload("EDO_OUTGOING_LIST", {"headers": {"X": "Y"}})
    with pytest.raises(EdoLiteContractError):
        validate_edo_read_payload("GENERIC_EDO_HTTP", {})




def test_allowlist_rejects_manual_arbitrary_method_url_path_and_query() -> None:
    assert not is_allowed_edo_read_target(EdoReadSpec("EDO_OUTGOING_PRINT", "POST", "/api/v3/true-api/edo/outgoing-documents/x/print", "x"))
    assert not is_allowed_edo_read_target(EdoReadSpec("EDO_OUTGOING_PRINT", "GET", "https://evil.invalid/x", "x"))
    assert not is_allowed_edo_read_target(EdoReadSpec("EDO_OUTGOING_PRINT", "GET", "/api/v3/true-api/edo/outgoing-documents/x/print/evil", "x"))
    assert not is_allowed_edo_read_target(EdoReadSpec("EDO_OUTGOING_LIST", "GET", "/api/v3/true-api/elk/outgoing-documents?limit=10&offset=0&sortBy=created_at&asc=false&cursor=x", "x"))


def test_mchd_known_statuses_are_raw_only_not_universally_required() -> None:
    assert MCHD_RAW_STATUSES == {"ACTIVE", "CREATED", "PROCESSING", "EXPIRED", "REVOKED", "REJECTED", "NONE"}


def test_json_read_capture_preserves_remote_pagination_fields_without_inventing_cursor() -> None:
    raw = b'{"items":[],"has_next_page":true}'
    result = capture_edo_read_success("EDO_OUTGOING_LIST", {"limit": 10, "offset": 0, "asc": False}, raw, "application/json")
    assert result["payload"]["has_next_page"] is True
    assert "cursor" not in result["payload"]


@pytest.mark.parametrize("job_type,payload,fragment", [
    ("EDO_OUTGOING_CONTENT", {"document_id": "Doc/Case A"}, "/elk/outgoing-documents/Doc%2FCase%20A/content"),
    ("EDO_INCOMING_CONTENT", {"document_id": "i-1"}, "/elk/incoming-documents/i-1/content"),
    ("EDO_OUTGOING_PRINT", {"document_id": "o-1"}, "/api/v3/true-api/edo/outgoing-documents/o-1/print"),
    ("EDO_INCOMING_PRINT", {"document_id": "i-1"}, "/api/v3/true-api/edo/incoming-documents/i-1/print"),
    ("EDO_OUTGOING_LEGAL_ZIP", {"document_id": "o-1"}, "/elk/outgoing-documents/o-1"),
    ("EDO_INCOMING_LEGAL_ZIP", {"document_id": "i-1"}, "/elk/incoming-documents/i-1"),
    ("EDO_EVENT_CONTENT", {"document_id": "d", "event_id": "e"}, "/incoming-documents/d/events/e/content"),
    ("EDO_OUTGOING_RECEIPT", {"document_id": "d", "receipt_type": "RECEIPT"}, "/outgoing-documents/d/events/RECEIPT"),
    ("EDO_INCOMING_MCHD", {"document_id": "d"}, "/incoming-documents/d/mchd-list"),
    ("EDO_GIS_PROCESSING", {"file_id": "ID FILE"}, "/documents/edo/tpr/ud?fileId=ID+FILE"),
])
def test_all_read_routes_are_typed(job_type: str, payload: dict, fragment: str) -> None:
    normalized = canonical(job_type, payload)
    spec = build_edo_read_spec(job_type, normalized)
    assert fragment in spec.target
    assert is_allowed_edo_read_target(spec)


def test_unsigned_events_have_no_caller_selected_target_fields() -> None:
    for job_type in ("EDO_OUTGOING_UNSIGNED_EVENTS", "EDO_INCOMING_UNSIGNED_EVENTS"):
        spec = build_edo_read_spec(job_type, canonical(job_type, {}))
        assert spec.target.endswith("/unsigned-events")
        with pytest.raises(EdoLiteContractError):
            validate_edo_read_payload(job_type, {"document_id": "x"})


def test_remote_identifiers_are_opaque_strings() -> None:
    guid = "A6B9270F-11AA-4A57-9E9F-ABCDEF123456"
    nonguid = "000123:Group/Remote Value"
    assert opaque_remote_id(guid) == guid
    assert opaque_remote_id(nonguid) == nonguid
    with pytest.raises(EdoLiteContractError):
        opaque_remote_id(123)
    assert canonical("EDO_EVENT_CONTENT", {"document_id": nonguid, "event_id": "0007"})["event_id"] == "0007"


def test_status_registry_preserves_all_known_and_unknown_raw_values() -> None:
    expected = {0,1,2,3,4,5,7,8,11,12,13,14,15,16,17,18,19,41,42,43,44,61,62,63,64,65,66}
    assert KNOWN_EDO_RAW_STATUSES == expected
    for raw in expected:
        item = parse_edo_raw_status(raw, f"remote-{raw}")
        assert item.raw_numeric == raw and item.known
        assert item.normalized_local_state is None
    unknown = parse_edo_raw_status(999, "future")
    assert unknown.raw_numeric == 999 and not unknown.known
    assert parse_edo_raw_status(61).normalized_local_state is None
    assert parse_edo_raw_status(63).normalized_local_state is None
    assert parse_edo_raw_status(62).normalized_local_state is None


def test_gis_processing_is_separate_and_preserves_raw_operations() -> None:
    for state in ("SUCCESS", "FAILED", "IN_PROGRESS"):
        raw = {
            "state": state,
            "resultDocId": "R/1",
            "resultDocDate": "2026-09-17",
            "sourceDocId": "S:1",
            "sourceDocDate": "2026-09-16",
            "code": "E1" if state == "FAILED" else None,
            "description": "raw detail",
            "operations": [{"pg": "lp", "errors": [{"code": "X"}], "raw": {"keep": True}}],
        }
        parsed = parse_gis_processing_result(raw)
        assert parsed.state.value == state
        assert parsed.result_doc_id == "R/1"
        assert parsed.source_doc_id == "S:1"
        assert parsed.operations[0]["raw"]["keep"] is True
        assert parsed.raw == raw


def test_final_success_requires_counterparty_gis_m1_and_m6() -> None:
    complete = ReconciliationEvidence(True, GisProcessingState.SUCCESS, True, True)
    assert final_business_success(complete)
    assert reconcile_local_state(complete) is LocalEdoState.MARKING_RECONCILED
    for evidence in (
        ReconciliationEvidence(False, GisProcessingState.SUCCESS, True, True),
        ReconciliationEvidence(True, GisProcessingState.IN_PROGRESS, True, True),
        ReconciliationEvidence(True, GisProcessingState.SUCCESS, False, True),
        ReconciliationEvidence(True, GisProcessingState.SUCCESS, True, False),
    ):
        assert not final_business_success(evidence)
    assert reconcile_local_state(ReconciliationEvidence(True, GisProcessingState.SUCCESS, False, True)) is LocalEdoState.GIS_SUCCEEDED
    assert M1ReconciliationAdapter(True, True, True, True).reconciled
    assert M6ReconciliationAdapter(True, True).reconciled


def test_annual_quota_is_advisory_not_authoritative_remaining() -> None:
    q = AnnualQuotaObservation(2026, 999, datetime.now(timezone.utc), "local outgoing list ledger")
    assert EDO_LITE_ANNUAL_OUTGOING_LIMIT == 1000
    assert q.authoritative_remote_remaining is None
    assert not q.safe_for_future_batch(1, independent_evidence_confirmed=False)
    assert q.safe_for_future_batch(1, independent_evidence_confirmed=True)
    assert not q.safe_for_future_batch(2, independent_evidence_confirmed=True)


def test_all_production_schemas_and_mutations_are_disabled() -> None:
    assert PRODUCTION_SCHEMA_REGISTRY
    assert all(item.production and not item.enabled_for_lp for item in PRODUCTION_SCHEMA_REGISTRY.values())
    assert all(item.xsd_sha256 is None and item.xsd_filename is None and item.root is None and item.target_namespace is None for item in PRODUCTION_SCHEMA_REGISTRY.values())
    assert all("latest" not in key.casefold() for key in PRODUCTION_SCHEMA_REGISTRY)
    assert M7_MUTATION_REGISTRY and all(not item.enabled for item in M7_MUTATION_REGISTRY.values())
    for name in M7_MUTATION_REGISTRY:
        with pytest.raises(M7SchemaNotEnabled):
            require_m7_mutation_enabled(name)


def test_ukd_736_29_conflict_is_explicit_and_writer_disabled() -> None:
    assert TRUE_API_ENDPOINT_FORMAT_UKD == "736"
    assert CURRENT_FNS_736_STATUS == "REPEALED"
    assert REPLACEMENT_FNS_ORDER == "ЕД-1-26/29@"
    assert UKD_FORMAT_COMPATIBILITY == "UNRESOLVED"
    assert PRODUCTION_SCHEMA_REGISTRY["UKD_736_600_SELLER"].disabled_reason == "TRUE_API_FNS_FORMAT_CONFLICT"
    assert not M7_MUTATION_REGISTRY["CREATE_UKD_736"].enabled


def test_immutable_remote_blob_and_signing_hard_block() -> None:
    raw = b"<remote>exact bytes</remote>"
    blob = ImmutableDocumentBlob.capture_remote(raw, document_family="UPD", schema_identity="UPD_970_520_SELLER")
    assert blob.source is BlobSource.REMOTE_CONTENT
    assert blob.sha256 == hashlib.sha256(raw).hexdigest()
    blob.verify()
    with pytest.raises(EdoLiteSecurityError):
        ImmutableDocumentBlob.capture_remote(raw, document_family="UPD", schema_identity=None, source=BlobSource.LOCAL_BUILT)
    with pytest.raises(M7SchemaNotEnabled):
        create_m7_signing_envelope(
            operation_id="op-1", blob=blob, schema_identity="UPD_970_520_SELLER",
            participant_inn="1234567890", reference="ledger:op-1",
        )


TEST_XSD = b'''<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
 targetNamespace="urn:test:m7" xmlns:t="urn:test:m7" elementFormDefault="qualified">
 <xs:element name="Envelope"><xs:complexType><xs:sequence>
 <xs:element name="Value" type="xs:string"/>
 </xs:sequence></xs:complexType></xs:element>
</xs:schema>'''


def validator() -> OfflineXmlValidator:
    v = OfflineXmlValidator()
    v.register_test_only_schema(
        schema_identity="TEST_ONLY_M7_SECURITY",
        xsd_bytes=TEST_XSD,
        expected_sha256=hashlib.sha256(TEST_XSD).hexdigest(),
        root="Envelope",
        target_namespace="urn:test:m7",
    )
    return v


def test_xml_security_engine_validates_test_only_pinned_schema() -> None:
    xml = b'<Envelope xmlns="urn:test:m7"><Value>ok</Value></Envelope>'
    validator().validate(xml, schema_identity="TEST_ONLY_M7_SECURITY")


@pytest.mark.parametrize("xml", [
    b'<!DOCTYPE x [<!ENTITY p SYSTEM "file:///etc/passwd">]><Envelope xmlns="urn:test:m7"><Value>&p;</Value></Envelope>',
    b'<Envelope xmlns="urn:test:m7" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:test:m7 https://evil/x.xsd"><Value>x</Value></Envelope>',
])
def test_xml_security_rejects_xxe_dtd_and_schema_location(xml: bytes) -> None:
    with pytest.raises(EdoLiteSecurityError):
        validator().validate(xml, schema_identity="TEST_ONLY_M7_SECURITY")




def test_xml_security_rejects_unpinned_network_schema_dependency() -> None:
    xsd = b"""<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
 targetNamespace="urn:test:network" xmlns:t="urn:test:network" elementFormDefault="qualified">
 <xs:include schemaLocation="https://evil.invalid/external.xsd"/>
 <xs:element name="Envelope" type="xs:string"/>
</xs:schema>"""
    v = OfflineXmlValidator()
    v.register_test_only_schema(
        schema_identity="TEST_ONLY_NETWORK_BLOCK",
        xsd_bytes=xsd,
        expected_sha256=hashlib.sha256(xsd).hexdigest(),
        root="Envelope",
        target_namespace="urn:test:network",
    )
    with pytest.raises(EdoLiteSecurityError):
        v.validate(b'<Envelope xmlns="urn:test:network">x</Envelope>', schema_identity="TEST_ONLY_NETWORK_BLOCK")


def test_xml_security_rejects_unknown_schema_and_fake_hash() -> None:
    xml = b'<Envelope xmlns="urn:test:m7"><Value>ok</Value></Envelope>'
    with pytest.raises(EdoLiteSecurityError):
        OfflineXmlValidator().validate(xml, schema_identity="TEST_ONLY_MISSING")
    with pytest.raises(EdoLiteSecurityError):
        OfflineXmlValidator().register_test_only_schema(
            schema_identity="TEST_ONLY_BAD_HASH", xsd_bytes=TEST_XSD,
            expected_sha256="0" * 64, root="Envelope", target_namespace="urn:test:m7",
        )


def test_id_file_idempotency_foundation() -> None:
    sha = "a" * 64
    assert classify_id_file_conflict(None, sha) is IdFileConflict.NEW
    assert classify_id_file_conflict(sha, sha) is IdFileConflict.RECONCILE_EXISTING
    assert classify_id_file_conflict("b" * 64, sha) is IdFileConflict.HARD_CONFLICT


def _zip(entries: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, value in entries.items():
            zf.writestr(name, value)
    return out.getvalue()


def test_legal_zip_inspection_never_extracts_and_rejects_traversal() -> None:
    result = inspect_legal_zip_safely(_zip({"legal/doc.xml": b"x", "sig/doc.sgn": b"y"}))
    assert result.entries == ("legal/doc.xml", "sig/doc.sgn")
    with pytest.raises(EdoLiteSecurityError):
        inspect_legal_zip_safely(_zip({"../escape.txt": b"x"}))


def test_read_capture_preserves_binary_bytes_content_type_and_hash() -> None:
    raw = b"%PDF-1.7 exact"
    result = capture_edo_read_success("EDO_OUTGOING_PRINT", {"document_id": "DocA"}, raw, "application/pdf")
    assert "EDO_OUTGOING_PRINT" in BINARY_EDO_READ_JOB_TYPES
    assert result["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["content_type"] == "application/pdf"
    assert result["remote_ids"]["document_id"] == "DocA"




def test_windows_agent_accepts_only_canonical_typed_m7_read_job() -> None:
    payload = canonical("EDO_OUTGOING_LIST", {})
    job = AgentJob(
        job_id="m7-read-1",
        job_type=AgentJobType.EDO_OUTGOING_LIST,
        operation_id="m7-read-op-1",
        pg="lp",
        expected_inn="1234567890",
        read_payload=payload,
    )
    job.validate()
    assert AgentJobType.EDO_OUTGOING_LIST.value in M7_READ_JOB_TYPES


def test_read_job_registry_has_no_mutation_or_generic_proxy() -> None:
    forbidden = {"GENERIC_EDO_HTTP", "RAW_URL", "RAW_PATH", "RAW_METHOD", "RAW_HEADERS", "ARBITRARY_BODY", "ARBITRARY_XML_SIGN", "ARBITRARY_FILE_SIGN"}
    assert forbidden.isdisjoint(M7_READ_JOB_TYPES)


def test_list_query_official_numeric_wire_types_and_serialization() -> None:
    payload = canonical("EDO_OUTGOING_LIST", {
        "limit": 101, "offset": 0, "created_from": 1770000000, "created_to": 1770003600,
        "status": 3, "type": 520, "folder": 3, "product_group": 1,
    })
    assert payload["limit"] == 101 and M7_PRODUCT_GROUP_WIRE_VALUE == 1
    spec = build_edo_read_spec("EDO_OUTGOING_LIST", payload)
    for fragment in ("limit=101", "offset=0", "sortBy=created_at", "asc=false", "created_from=1770000000", "created_to=1770003600", "status=3", "type=520", "folder=3", "product_group=1"):
        assert fragment in spec.target
    assert "product_group=lp" not in spec.target
    assert is_allowed_edo_read_target(spec)


@pytest.mark.parametrize("bad", [
    {"created_from": "1770000000"}, {"created_to": "1770003600"}, {"status": "3"}, {"type": "520"},
    {"folder": "3"}, {"folder": 9}, {"product_group": "lp"}, {"product_group": 2},
    {"created_from": True}, {"created_to": True}, {"status": True}, {"type": True}, {"folder": True},
    {"product_group": True}, {"limit": True}, {"offset": True},
])
def test_list_query_rejects_non_contract_integer_values(bad: dict) -> None:
    with pytest.raises(EdoLiteContractError):
        validate_edo_read_payload("EDO_OUTGOING_LIST", bad)


def test_list_query_integer_boundaries_and_no_invented_limit_100() -> None:
    assert canonical("EDO_OUTGOING_LIST", {"folder": 0})["folder"] == 0
    assert canonical("EDO_OUTGOING_LIST", {"folder": 8})["folder"] == 8
    assert canonical("EDO_OUTGOING_LIST", {"limit": 1000})["limit"] == 1000
    assert canonical("EDO_OUTGOING_LIST", {"offset": 0})["offset"] == 0
    for bad in ({"limit": 0}, {"offset": -1}, {"created_from": -1}, {"created_to": -1}):
        with pytest.raises(EdoLiteContractError): validate_edo_read_payload("EDO_OUTGOING_LIST", bad)
    assert not is_allowed_edo_read_target(EdoReadSpec("EDO_OUTGOING_LIST", "GET", "/api/v3/true-api/elk/outgoing-documents?limit=10&offset=0&sortBy=created_at&asc=false&product_group=lp", "x"))


def test_schema_registry_has_one_exact_official_type_per_disabled_row() -> None:
    expected = {
        ("UPD","520","SELLER","ДОП"),("UPD","521","BUYER","ДОП"),("UPD","522","SELLER","СЧФ"),("UPD","524","SELLER","СЧФДОП"),("UPD","525","BUYER","СЧФДОП"),
        ("UPDI","820","SELLER","ДОП"),("UPDI","821","BUYER","ДОП"),("UPDI","822","SELLER","СЧФ"),("UPDI","824","SELLER","СЧФДОП"),("UPDI","825","BUYER","СЧФДОП"),
        ("UKD","600","SELLER","ДИС"),("UKD","601","BUYER","ДИС"),("UKD","602","SELLER","КСЧФ"),("UKD","604","SELLER","КСФДИС"),("UKD","605","BUYER","КСФДИС"),
        ("UKDI","700","SELLER","ДИС"),("UKDI","701","BUYER","ДИС"),("UKDI","702","SELLER","КСЧФ"),("UKDI","704","SELLER","КСФДИС"),("UKDI","705","BUYER","КСФДИС"),
    }
    rows=[x for x in PRODUCTION_SCHEMA_REGISTRY.values() if x.family != "SERVICE"]
    assert {(x.family,x.official_type_code,x.title_role,x.function) for x in rows} == expected
    assert all(x.official_type_code is None or "/" not in x.official_type_code for x in PRODUCTION_SCHEMA_REGISTRY.values())
    by_code={x.official_type_code:x for x in rows}
    for code in {"522","602","702","822"}: assert by_code[code].title_role == "SELLER"
    assert all(not x.enabled_for_lp for x in PRODUCTION_SCHEMA_REGISTRY.values())
    assert all(x.disabled_reason == "TRUE_API_FNS_FORMAT_CONFLICT" for x in rows if x.family in {"UKD","UKDI"})
    assert all(x.disabled_reason == "OFFICIAL_SCHEMA_NOT_PINNED" for x in rows if x.family in {"UPD","UPDI"})
    for x in PRODUCTION_SCHEMA_REGISTRY.values():
        assert x.artifact_filename is None and x.artifact_sha256 is None and x.xsd_filename is None and x.xsd_sha256 is None
        assert x.root is None and x.target_namespace is None
