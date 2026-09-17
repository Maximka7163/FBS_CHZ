from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wbcz.cis_inventory import SharedRateLimiter, parse_success_payload, safe_transport_error
from wbcz.reference_products import (
    M2_READ_JOB_TYPES,
    M2_SOURCE_VERSION,
    PARTICIPANTS_PATH,
    MODS_LIST_PATH,
    PRODUCT_GTIN_PATH,
    RD_LIST_PATH,
    TN_VED_SEARCH_PATH,
    ReferenceProductsContractError,
    build_reference_read_spec,
    is_allowed_reference_target,
    lookup_reference_value,
    parse_reference_success_payload,
    reference_categories,
    reference_entries,
    validate_exact_lp_activity_location,
    validate_m2_job_payload,
)
from wbcz.windows_agent import AgentJob, AgentJobType, P0_PG, ProductionAgentTrueApiTransport


INN = "1234567890"
INN2 = "123456789012"


def test_participants_exact_get_repeated_inns_and_limits():
    spec = build_reference_read_spec("PARTICIPANTS", {"inns": [INN, INN2]})
    assert spec.method == "GET"
    assert spec.target == f"{PARTICIPANTS_PATH}?inns={INN}&inns={INN2}"
    assert spec.body is None
    assert is_allowed_reference_target(spec)
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("PARTICIPANTS", {"inns": [INN] * 101})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("PARTICIPANTS", {"inns": [INN], "kpp": "x"})


def test_participants_optional_fields_and_item_errors_preserved_without_inventions():
    payload = [{
        "inn": INN,
        "name": "ООО Тест",
        "statusInn": "ACTIVE",
        "role": "SOME_SERVER_ROLE",
        "productGroups": ["lp"],
        "productGroupInfo": [{"productGroup": "lp", "farmer": False, "isControllability": True}],
        "errorCode": "ITEM_WARNING",
        "serverFutureField": 7,
    }]
    parsed = parse_reference_success_payload("PARTICIPANTS", {"inns": [INN]}, payload)
    item = parsed["items"][0]
    assert item["wire"]["inn"] == INN
    assert item["wire"]["raw"]["serverFutureField"] == 7
    assert item["wire"]["errorCode"] == "ITEM_WARNING"
    assert item["kpp_invented"] is False
    assert item["fias_invented"] is False
    assert "kpp" not in item["wire"]["raw"]
    assert parsed["partial_item_errors_preserved"] is True


def test_mods_exact_get_lp_validation_limits_and_filters():
    payload = {"productGroups": ["lp"], "inns": [INN], "kpp": "027401001", "fiasId": "fias-1", "limit": 1000, "page": 0}
    spec = build_reference_read_spec("MODS_LIST", payload)
    assert spec.method == "GET"
    assert spec.target.startswith(MODS_LIST_PATH + "?")
    assert "productGroups=lp" in spec.target
    assert f"inns={INN}" in spec.target
    assert "kpp=027401001" in spec.target
    assert "fiasId=fias-1" in spec.target
    assert "limit=1000" in spec.target and "page=0" in spec.target
    assert is_allowed_reference_target(spec)
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("MODS_LIST", {"inns": [INN] * 11})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("MODS_LIST", {"limit": 1001})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("MODS_LIST", {"page": -1})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("MODS_LIST", {"productGroups": ["beer"]})


def test_mod_lp_exact_validation_supports_legal_entity_and_ip_without_kpp():
    rows = [
        {"inn": INN, "kpp": "027401001", "fiasId": "fias-1", "productGroups": ["lp"], "address": "A"},
        {"inn": INN2, "fiasId": "fias-ip", "productGroups": ["lp"], "address": "B"},
        {"inn": INN, "kpp": "other", "fiasId": "fias-1", "productGroups": ["lp"]},
    ]
    legal = validate_exact_lp_activity_location(rows, inn=INN, kpp="027401001", fias_id="fias-1")
    assert legal["valid"] is True and len(legal["matches"]) == 1 and legal["kpp_required"] is True
    ip = validate_exact_lp_activity_location(rows, inn=INN2, fias_id="fias-ip")
    assert ip["valid"] is True and ip["kpp_required"] is False
    parsed = parse_reference_success_payload(
        "MODS_LIST",
        {"productGroups": ["lp"], "inns": [INN2], "fiasId": "fias-ip", "limit": 100, "page": 0},
        {"result": rows, "total": 3, "nextPage": 1},
    )
    assert parsed["lp_activity_location_validation"]["valid"] is True
    assert parsed["mods_info_used"] is False
    assert all(x["general_active_status_invented"] is False for x in parsed["result"])


def test_no_mods_info_for_lp_and_no_generic_active_status_invention():
    text = Path("src/wbcz/reference_products.py").read_text(encoding="utf-8")
    assert "/api/v3/true-api/mods/info" not in text
    assert "isActive" not in text


def test_tnved_exact_post_validation_and_pg_relation():
    spec = build_reference_read_spec("TN_VED_SEARCH", {"pg": "lp", "tnveds": ["6109", "6109100000"], "limit": 1000, "page": 0, "sort": "tnved", "direction": "DESC"})
    assert spec.method == "POST" and spec.target == TN_VED_SEARCH_PATH
    assert spec.body["tnveds"] == ["6109", "6109100000"]
    assert is_allowed_reference_target(spec)
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("TN_VED_SEARCH", {})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("TN_VED_SEARCH", {"tnveds": ["123"]})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("TN_VED_SEARCH", {"pg": "lp", "limit": 1001})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("TN_VED_SEARCH", {"pg": "lp", "direction": "SIDEWAYS"})
    parsed = parse_reference_success_payload("TN_VED_SEARCH", {"pg": "lp"}, {"tnveds": [{"tnved": "6109", "description": "text", "pg": "lp", "extra": 1}], "total": 1, "last": True})
    assert parsed["tnveds"][0]["wire"]["description"] == "text"
    assert parsed["tnveds"][0]["wire"]["pg"] == "lp"
    assert parsed["tnveds"][0]["wire"]["raw"]["extra"] == 1


def test_product_info_reuses_m1_parser_with_extended_optional_fields_and_missing_semantics():
    response = {"results": [{
        "gtin": "04601234567890", "name": "Товар", "brand": "Brand", "productGroup": "lp",
        "goodMarkFlag": True, "goodTurnFlag": True, "subBrand": "Sub", "privateBrand": "Private",
        "packageType": "UNIT", "innerUnitCount": 2, "model": "M", "inn": INN,
        "permittedInns": [INN], "productGroupId": 1, "goodSignedFlag": True, "goodStatus": "ACTIVE",
        "isKit": False, "isTechGtin": False, "isSet": False, "setGtin": None, "setDescription": None,
        "level": 1, "mainGtin": None, "multiplier": 1, "foreignProducer": None, "exporter": None,
        "standardNumber": "STD", "tnVedCode": "6109", "tnVedCode10": "6109100000", "fullName": "Полное",
        "basicUnit": "PCE", "quantityInPack": 1, "quantityInPackType": "UNIT",
        "reasonCertMissing": None, "reasonCertMissingDetails": None,
        "certDocList": [{"type": "CONFORMITY_DECLARATION", "number": "D-1", "active": True}],
        "futureGroupField": {"x": 1},
    }]}
    parsed = parse_success_payload("PRODUCT_INFO", {"gtins": ["04601234567890", "04609999999999"], "rdInfo": True}, response)
    wire = parsed["results"][0]["wire"]
    assert wire["subBrand"] == "Sub" and wire["tnVedCode10"] == "6109100000"
    assert wire["certDocList"][0]["number"] == "D-1"
    assert wire["raw"]["futureGroupField"] == {"x": 1}
    assert parsed["requested"][1]["state"] == "NOT_RETURNED_BY_PRODUCT_INFO"
    assert parsed["absence_does_not_mean_nonexistent"] is True


def test_product_gtin_exact_get_forced_lp_and_own_inventory_semantics():
    canonical = validate_m2_job_payload("PRODUCT_GTIN_LIST", {})
    assert canonical == {"pg": "lp", "includeSubaccount": False, "limit": 10, "page": 0}
    spec = build_reference_read_spec("PRODUCT_GTIN_LIST", canonical)
    assert spec.method == "GET" and spec.target.startswith(PRODUCT_GTIN_PATH + "?pg=lp")
    assert is_allowed_reference_target(spec)
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("PRODUCT_GTIN_LIST", {"pg": "other"})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("PRODUCT_GTIN_LIST", {"limit": 10001})
    parsed = parse_reference_success_payload("PRODUCT_GTIN_LIST", canonical, {"results": [{"gtin": "04601234567890", "goodStatus": "ACTIVE", "future": 1}], "total": 1})
    assert parsed["own_inventory"] is True and parsed["pg"] == "lp"
    assert parsed["results"][0]["wire"]["raw"]["future"] == 1


def test_rd_list_exact_post_conditional_date_and_no_issuer_invention():
    payload = {"documents": [
        {"type": "CONFORMITY_CERTIFICATE", "number": "C-1", "dateFrom": "2026-01-01"},
        {"type": "CONFORMITY_DECLARATION", "number": "D-1", "dateFrom": "2026-02-01"},
        {"type": "STATE_REGISTRATION_CERTIFICATE", "number": "S-1"},
    ]}
    spec = build_reference_read_spec("RD_LIST", payload)
    assert spec.method == "POST" and spec.target == RD_LIST_PATH and is_allowed_reference_target(spec)
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("RD_LIST", {"documents": []})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("RD_LIST", {"documents": payload["documents"] * 9})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("RD_LIST", {"documents": [{"type": "CONFORMITY_CERTIFICATE", "number": "C"}]})
    with pytest.raises(ReferenceProductsContractError):
        validate_m2_job_payload("RD_LIST", {"documents": [{"type": "UNPROVEN_TYPE", "number": "X"}]})
    parsed = parse_reference_success_payload("RD_LIST", payload, [{"type": "CONFORMITY_CERTIFICATE", "number": "C-1", "status": "VALID", "errors": [{"code": "W"}], "future": 1}])
    wire = parsed["documents"][0]
    assert wire["wire"]["errors"] == [{"code": "W"}]
    assert wire["wire"]["raw"]["future"] == 1
    assert wire["issuer_invented"] is False
    assert "issuer" not in wire["wire"]


def test_static_registry_v726_exact_lp_and_accepted_values():
    categories = {row["category"]: row for row in reference_categories()}
    assert set(categories) == {
        "PRODUCT_GROUPS", "CIS_BASE_STATUSES", "CIS_SPECIAL_STATUSES", "EMISSION_TYPES",
        "PACKAGE_TYPES", "PERMIT_DOCUMENT_TYPES", "WITHDRAWAL_REASONS", "RETURN_REASON_MAPPING",
        "PARTICIPANT_ROLES", "PARTICIPANT_STATUSES",
    }
    assert all(row["source_version"] == M2_SOURCE_VERSION for row in categories.values())
    pg = reference_entries("PRODUCT_GROUPS")["entries"]
    assert pg == [{"numeric_id": 1, "code": "lp", "name": "Лёгкая промышленность", "source_version": M2_SOURCE_VERSION}]
    assert {x["code"] for x in reference_entries("CIS_BASE_STATUSES")["entries"]} >= {"EMITTED", "APPLIED", "INTRODUCED", "WRITTEN_OFF", "RETIRED", "WITHDRAWN", "DISAGGREGATION", "DISAGGREGATED", "APPLIED_NOT_PAID"}
    assert {x["code"] for x in reference_entries("CIS_SPECIAL_STATUSES")["entries"]} >= {"EMPTY", "IN_GRAY_ZONE", "MOVING_BY_UD"}
    assert {x["code"] for x in reference_entries("EMISSION_TYPES")["entries"]} == {"LOCAL", "FOREIGN", "REMAINS", "CROSSBORDER", "REMARK", "COMMISSION", "REAPPLY"}
    assert reference_entries("PACKAGE_TYPES")["source_complete"] is False
    assert reference_entries("PARTICIPANT_ROLES")["entries"] == []


def test_unknown_reference_preserves_raw_and_never_coerces():
    unknown = lookup_reference_value("CIS_BASE_STATUSES", "FUTURE_SERVER_STATUS")
    assert unknown == {"raw_value": "FUTURE_SERVER_STATUS", "known": False, "reference": None, "source_version": M2_SOURCE_VERSION, "coerced": False}
    known = lookup_reference_value("CIS_SPECIAL_STATUSES", "EMPTY")
    assert known["known"] is True and known["raw_value"] == "EMPTY"


def test_m2_agent_jobs_are_typed_and_reject_noncanonical_or_arbitrary_payloads():
    assert M2_READ_JOB_TYPES == {"PARTICIPANTS", "MODS_LIST", "TN_VED_SEARCH", "PRODUCT_GTIN_LIST", "RD_LIST"}
    assert not any(name in AgentJobType.__members__ for name in {"TRUE_API_GENERIC", "TRUE_API_REQUEST", "HTTP_REQUEST", "RAW_PATH", "RAW_URL", "GENERIC_GET", "GENERIC_POST"})
    job = AgentJob("j", AgentJobType.PARTICIPANTS, "op", P0_PG, INN, read_payload={"inns": [INN]})
    job.validate()
    with pytest.raises(Exception):
        AgentJob("j2", AgentJobType.PARTICIPANTS, "op2", P0_PG, INN, read_payload={"inns": [INN], "url": "https://example.com"}).validate()


class _Limiter:
    def __init__(self): self.calls = 0
    def acquire(self): self.calls += 1


class _Tunnel:
    local_port = 12345
    def session_marker(self): return "m"
    def assert_gost_session(self, marker): assert marker == "m"


class _Audit:
    def record(self, **kwargs): pass


class _Response:
    status = 200
    headers = {"Content-Type": "application/json", "X-Request-ID": "r"}
    def read(self): return b"{}"


class _Connection:
    def __init__(self, *args, **kwargs): self.method = None; self.target = None
    def putrequest(self, method, target, skip_host=True): self.method, self.target = method, target
    def putheader(self, *args): pass
    def endheaders(self, data=None): self.data = data
    def getresponse(self): return _Response()
    def close(self): pass


def test_m1_and_m2_share_one_rate_limiter_boundary():
    limiter = _Limiter()
    transport = ProductionAgentTrueApiTransport(tunnel=_Tunnel(), audit=_Audit(), connection_factory=_Connection, rate_limiter=limiter)
    transport.m1_read("PRODUCT_INFO", {"gtins": ["04601234567890"], "rdInfo": False}, bearer_token="secret")
    transport.m2_read("PARTICIPANTS", {"inns": [INN]}, bearer_token="secret")
    assert transport.rate_limiter is limiter
    assert limiter.calls == 2


def test_shared_rate_limiter_default_is_50_and_deterministic():
    now = [0.0]
    sleeps = []
    def clock(): return now[0]
    def sleep(value): sleeps.append(value); now[0] += value
    limiter = SharedRateLimiter(clock=clock, sleeper=sleep)
    assert limiter.max_rps == 50
    limiter.acquire(); limiter.acquire(); limiter.acquire()
    assert sleeps == pytest.approx([0.02, 0.02])


def test_existing_safe_error_model_handles_json_xml_text_and_empty_without_secrets():
    j = safe_transport_error(400, {"Content-Type": "application/json"}, json.dumps({"errorCode": "E", "message": "Bearer abc.def"}).encode())
    assert j.safe_error_code == "E" and "abc.def" not in (j.safe_error_message or "")
    x = safe_transport_error(400, {"Content-Type": "application/xml"}, b"<error>bad</error>")
    assert x.raw_body_preview == "<error>bad</error>"
    t = safe_transport_error(500, {"Content-Type": "text/plain"}, b"token=secretvalue")
    assert "secretvalue" not in (t.safe_error_message or "")
    e = safe_transport_error(406, {"Content-Type": "text/plain"}, b"")
    assert e.safe_error_message == "HTTP 406 with empty body"


def test_advanced_nk_and_secret_storage_not_implemented():
    source = (Path("src/wbcz/reference_products.py").read_text(encoding="utf-8") + Path("src/wbcz_web/services/reference_products.py").read_text(encoding="utf-8"))
    assert "/nk/" not in source
    assert "apikey" not in source.casefold()
    assert "NK_API" not in source


def test_product_text_search_and_official_ttl_not_invented():
    source = Path("src/wbcz/reference_products.py").read_text(encoding="utf-8")
    assert "PRODUCT_TEXT_SEARCH" not in source
    assert "cache_ttl" not in source.casefold()


def test_persisted_m2_job_survives_postgres_reopen_and_duplicate_result_is_safe():
    url = os.environ.get("WBCZ_TEST_DATABASE_URL")
    if not url or not url.startswith("postgresql"):
        pytest.skip("WBCZ_TEST_DATABASE_URL requires PostgreSQL")
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from wbcz.windows_agent import AgentResult
    from wbcz_web.models import AgentJobRecord, Base
    from wbcz_web.repositories import SqlAlchemyAgentJobStore

    job = AgentJob("job_m2_persist_test", AgentJobType.PARTICIPANTS, "m2read:persist", P0_PG, INN, read_payload={"inns": [INN]})
    engine = create_engine(url)
    # Other full-suite migration tests intentionally exercise destructive clean-db paths.
    # Recreate the ORM schema here so this persistence/reopen regression is order-independent.
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session.begin() as db:
        old = db.get(AgentJobRecord, job.job_id)
        if old is not None:
            db.delete(old)
    with Session.begin() as db:
        SqlAlchemyAgentJobStore(db).enqueue(job, purpose="REFERENCE_PRODUCTS")
    engine.dispose()

    engine2 = create_engine(url)
    Session2 = sessionmaker(bind=engine2, expire_on_commit=False)
    result = AgentResult(job.job_id, job.operation_id, "READ_COMPLETED", read_result={"type": "PARTICIPANTS", "items": []})
    with Session2.begin() as db:
        store = SqlAlchemyAgentJobStore(db)
        meta = store.metadata(job.job_id)
        assert meta.job.job_type is AgentJobType.PARTICIPANTS
        store.complete(result)
        store.complete(result)
        with pytest.raises(Exception):
            store.complete(AgentResult(job.job_id, job.operation_id, "READ_COMPLETED", read_result={"different": True}))
    engine2.dispose()
