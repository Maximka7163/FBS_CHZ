from __future__ import annotations

from dataclasses import asdict
import json

import pytest

from wbcz.cis_inventory import (
    AGGREGATED_LIST_TARGET,
    AGGREGATION_HISTORY_TARGET,
    CIS_HISTORY_PREFIX,
    CIS_INFO_TARGET,
    CIS_SEARCH_TARGET,
    PRODUCT_INFO_TARGET,
    SEARCH_RESULT_CEILING,
    SharedRateLimiter,
    build_read_spec,
    parse_success_payload,
    safe_transport_error,
    validate_m1_job_payload,
    validate_search_request,
)
from wbcz.windows_agent import (
    AgentHttpResponse,
    AgentJob,
    AgentJobType,
    AgentSecurityError,
    P0_PG,
    ProductionAgentTrueApiTransport,
    WindowsAgentExecutor,
)


CIS = "010460123456789021ABCDEFGHIJKL"
CIS2 = "010460123456789021MNOPQRSTUVWX"


def _job(kind: AgentJobType, payload: dict):
    canonical = validate_m1_job_payload(kind.value, payload)
    return AgentJob(
        job_id="job_m1_test",
        job_type=kind,
        operation_id="m1read:test",
        pg=P0_PG,
        expected_inn="1234567890",
        read_payload=canonical,
    )


def test_cis_info_exact_root_array_bounds_and_pg():
    spec = build_read_spec("CIS_INFO", {"cises": [CIS]})
    assert spec.method == "POST"
    assert spec.target == CIS_INFO_TARGET
    assert spec.body == [CIS]
    assert spec.cis_count == 1
    build_read_spec("CIS_INFO", {"cises": [CIS] * 1000})
    with pytest.raises(ValueError):
        build_read_spec("CIS_INFO", {"cises": []})
    with pytest.raises(ValueError):
        build_read_spec("CIS_INFO", {"cises": [CIS] * 1001})
    with pytest.raises(ValueError):
        build_read_spec("CIS_INFO", {"cises": ["short"]})


def test_cis_info_partial_item_errors_are_not_transport_failure():
    payload = [
        {"cisInfo": {"cis": CIS, "gtin": "04601234567890", "status": "INTRODUCED", "ownerInn": "1234567890", "statusEx": "OK", "withdrawReason": None}},
        {"errorCode": "404", "errorMessage": "not found"},
    ]
    parsed = parse_success_payload("CIS_INFO", {"cises": [CIS, CIS2]}, payload)
    assert parsed["items"][0]["normalized"]["owner_inn"] == "1234567890"
    assert parsed["items"][1]["normalized"] is None
    assert parsed["items"][1]["item_error"] == {"code": "404", "message": "not found"}


def test_search_exact_v4_lp_scope_wire_names_and_no_cursor_guess():
    request = {
        "filter": {
            "productGroups": ["lp"],
            "gtins": ["04601234567890"],
            "manufacturerInns": "1234567890",
            "importerInns": "1234567890",
            "states": [{"status": "INTRODUCED", "statusExt": "ACTIVE", "isStatusExtNull": False}],
            "tnVed": "6108",
            "tnVed10": "6108210000",
            "prVetDoc": "vet-doc",
            "productionDatePeriod": {"from": "2026-01-01T00:00:00Z"},
            "mods": [{"kpp": "123456789", "fiasId": "11111111-2222-3333-4444-555555555555"}],
        },
        "pagination": {
            "perPage": 1000,
            "lastEmissionDate": "2026-09-01T00:00:00Z",
            "sgtin": "04601234567890123456789012",
            "direction": 0,
        },
    }
    spec = build_read_spec("CIS_SEARCH", {"request": request})
    assert spec.target == CIS_SEARCH_TARGET
    assert spec.body["filter"]["manufacturerInns"] == "1234567890"
    assert spec.body["filter"]["importerInns"] == "1234567890"
    assert spec.body["pagination"]["perPage"] == 1000
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"]}, "pagination": {"perPage": 1001, "lastEmissionDate": "x", "sgtin": "y"}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["other"]}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "manufacturerInns": ["123"]}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "states": ["INTRODUCED"]}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "mods": [{"raw": "x"}]}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "mods": [{"kpp": "x"}] * 51}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "tnVed": ["6108"]}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "prVetDoc": True}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "withdrawDatePeriod": {"from": "x"}}})
    with pytest.raises(ValueError):
        validate_search_request({"filter": {"productGroups": ["lp"], "productionDatePeriod": {"from": "x", "after": "y"}}})

    normalized_request = validate_search_request(request)
    assert normalized_request["filter"]["states"][0]["statusExt"] == "ACTIVE"
    assert normalized_request["filter"]["mods"][0]["fiasId"].startswith("11111111")
    assert normalized_request["filter"]["productionDatePeriod"] == {"from": "2026-01-01T00:00:00Z"}
    assert normalized_request["filter"]["tnVed"] == "6108"
    assert normalized_request["filter"]["tnVed10"] == "6108210000"
    assert normalized_request["filter"]["prVetDoc"] == "vet-doc"

    response = {
        "isLastPage": False,
        "result": [{"cis": CIS, "sgtin": "S", "gtin": "G", "ownerInn": "111", "status": "X", "statusExt": "Y", "eliminationReason": "Z"}],
    }
    parsed = parse_success_payload("CIS_SEARCH", {"request": request}, response)
    item = parsed["result"][0]
    assert item["wire"]["statusExt"] == "Y"
    assert item["wire"]["eliminationReason"] == "Z"
    assert item["normalized"]["owner_authoritative"] is False
    assert parsed["auto_pagination"] is False
    assert parsed["cursor_advancement"] == "UNKNOWN"
    assert parsed["result_ceiling"] == SEARCH_RESULT_CEILING == 10000


def test_history_exact_target_escapes_query_and_does_not_invent_status_ex():
    cis = "01 04601234567890/21ABCDEF?XYZ"
    # spaces and reserved query characters must be encoded after normalization.
    spec = build_read_spec("CIS_HISTORY", {"cis": cis})
    assert spec.target.startswith(CIS_HISTORY_PREFIX)
    assert " " not in spec.target and "?XYZ" not in spec.target and "/21" not in spec.target
    assert spec.body is None
    parsed = parse_success_payload("CIS_HISTORY", {"cis": cis}, [{"cis": cis.strip(), "status": "INTRODUCED", "operationDate": None}])
    assert "statusEx" not in parsed["history"][0]["wire"]["raw"]


def test_aggregated_list_exact_target_direct_layer_and_empty_unknown():
    spec = build_read_spec("CIS_AGGREGATED_LIST", {"cises": [CIS, CIS2]})
    assert spec.target == AGGREGATED_LIST_TARGET
    parsed = parse_success_payload("CIS_AGGREGATED_LIST", {"cises": [CIS, CIS2]}, {CIS: {"child": ["a"]}, CIS2: {}})
    assert parsed["items"][0]["direct_layer_only"] is True
    assert parsed["items"][0]["recursive"] is False
    assert parsed["items"][1]["wire"]["raw"] == {}


def test_aggregation_history_accepts_both_official_values_unknown_and_nullable_date():
    spec = build_read_spec("CIS_AGGREGATION_HISTORY", {"cis": CIS})
    assert spec.target == AGGREGATION_HISTORY_TARGET
    payload = {"cisAggregation": [
        {"cis": CIS, "operationType": "AUTODISAGGREGATED", "operationDate": None},
        {"cis": CIS, "operationType": "AUTODISAGGREGATION"},
        {"cis": CIS, "operationType": "FUTURE_ENUM"},
    ]}
    parsed = parse_success_payload("CIS_AGGREGATION_HISTORY", {"cis": CIS}, payload)
    assert parsed["operationDate_nullable"] is True
    assert parsed["cisAggregation"][0]["normalized_operation_type"] == "AUTODISAGGREGATION"
    assert parsed["cisAggregation"][1]["normalized_operation_type"] == "AUTODISAGGREGATION"
    assert parsed["cisAggregation"][2]["wire"]["operationType"] == "FUTURE_ENUM"
    assert parsed["cisAggregation"][2]["operation_type_known"] is False


def test_product_info_exact_v4_limit_rdinfo_default_and_missing_not_nonexistent():
    payload = validate_m1_job_payload("PRODUCT_INFO", {"gtins": ["1", "2"]})
    assert payload == {"gtins": ["1", "2"], "rdInfo": False}
    spec = build_read_spec("PRODUCT_INFO", payload)
    assert spec.target == PRODUCT_INFO_TARGET
    with pytest.raises(ValueError):
        validate_m1_job_payload("PRODUCT_INFO", {"gtins": []})
    with pytest.raises(ValueError):
        validate_m1_job_payload("PRODUCT_INFO", {"gtins": ["1"] * 1001})
    parsed = parse_success_payload(
        "PRODUCT_INFO",
        payload,
        {"results": [{"gtin": "1", "name": "A", "goodTurnFlag": True, "goodMarkFlag": True, "futureGroupField": {"x": 1}}], "total": 1},
    )
    assert parsed["requested"][0]["state"] == "RETURNED"
    assert parsed["requested"][1]["state"] == "NOT_RETURNED_BY_PRODUCT_INFO"
    assert parsed["absence_does_not_mean_nonexistent"] is True
    assert parsed["results"][0]["wire"]["raw"]["futureGroupField"] == {"x": 1}


def test_strict_m1_jobs_have_no_generic_proxy_or_arbitrary_path_method():
    forbidden = {"TRUE_API_REQUEST", "GENERIC_HTTP", "RAW_URL", "RAW_PATH", "ARBITRARY_REQUEST"}
    assert not forbidden.intersection({item.value for item in AgentJobType})
    _job(AgentJobType.CIS_INFO, {"cises": [CIS]}).validate()
    with pytest.raises(AgentSecurityError):
        AgentJob("j", AgentJobType.CIS_SEARCH, "o", P0_PG, "1234567890", read_payload={"request": {"filter": {"productGroups": ["lp"]}, "path": "/evil"}}).validate()


def test_safe_transport_error_handles_json_xml_and_empty_406_without_secrets():
    j = safe_transport_error(400, {"Content-Type": "application/json"}, b'{"errorCode":"E1","message":"bad"}')
    assert j.safe_error_code == "E1" and j.safe_error_message == "bad"
    secret_json = safe_transport_error(401, {"Content-Type": "application/json"}, b'{"message":"Bearer super.secret token=SECRET pin=1234"}')
    serialized = json.dumps(asdict(secret_json))
    assert "super.secret" not in serialized and "SECRET" not in serialized and "1234" not in serialized
    x = safe_transport_error(500, {"Content-Type": "application/xml"}, b'<e>Bearer abc.def token=SECRET pin=1234</e>')
    assert "abc.def" not in (x.raw_body_preview or "")
    assert "SECRET" not in (x.raw_body_preview or "")
    assert "1234" not in (x.raw_body_preview or "")
    e = safe_transport_error(406, {"Content-Type": "application/json"}, b"")
    assert e.safe_error_message == "HTTP 406 with empty body"
    assert len(e.body_sha256) == 64


def test_shared_rate_limit_is_deterministic_and_caps_at_50_rps():
    class FakeTime:
        def __init__(self): self.now = 0.0
        def clock(self): return self.now
        def sleep(self, value): self.now += value
    fake = FakeTime()
    limiter = SharedRateLimiter(50, clock=fake.clock, sleeper=fake.sleep)
    for _ in range(51):
        limiter.acquire()
    assert fake.now >= 1.0
    assert fake.now < 1.01


class _Headers(dict):
    pass


class _Response:
    def __init__(self, status=200, body=b'{}', headers=None):
        self.status=status
        self._body=body
        self.headers=_Headers(headers or {"Content-Type": "application/json"})
    def read(self): return self._body


class _Connection:
    def __init__(self, *args, **kwargs):
        self.method=None; self.target=None; self.headers=[]; self.body=None
    def putrequest(self, method, target, skip_host=False): self.method=method; self.target=target
    def putheader(self, name, value): self.headers.append((name,value))
    def endheaders(self, body=None): self.body=body
    def getresponse(self): return _Response(200, b'{"isLastPage":true,"result":[]}', {"Content-Type":"application/json"})
    def close(self): pass


class _Tunnel:
    local_port=12345
    def session_marker(self): return 0
    def assert_gost_session(self, marker): pass


class _Audit:
    def record(self, **kwargs): pass


def test_transport_uses_only_typed_exact_search_target():
    conn = _Connection()
    transport = ProductionAgentTrueApiTransport(
        tunnel=_Tunnel(), audit=_Audit(), connection_factory=lambda *a, **k: conn,
        rate_limiter=SharedRateLimiter(50, clock=lambda: 0.0, sleeper=lambda _: None),
    )
    request = {"filter": {"productGroups": ["lp"]}}
    response = transport.m1_read("CIS_SEARCH", {"request": request}, bearer_token="SECRET_BEARER")
    assert response.status == 200
    assert conn.method == "POST" and conn.target == CIS_SEARCH_TARGET
    sent = dict(conn.headers)
    assert sent["Authorization"] == "Bearer SECRET_BEARER"
    assert json.loads(conn.body) == request
    with pytest.raises((ValueError, AgentSecurityError)):
        transport.m1_read("RAW_URL", {"url": "https://example.com"}, bearer_token="x")


def test_cis_to_product_deduplicates_gtin_and_never_returns_bearer():
    class Session:
        def bearer_token(self): return "VERY_SECRET_BEARER"
    class Transport:
        def __init__(self): self.calls=[]
        def m1_read(self, job_type, payload, *, bearer_token):
            self.calls.append((job_type, payload, bearer_token))
            if job_type == "CIS_INFO":
                body = json.dumps([
                    {"cisInfo": {"cis": CIS, "gtin": "0460", "status": "INTRODUCED"}},
                    {"cisInfo": {"cis": CIS2, "gtin": "0460", "status": "INTRODUCED"}},
                ]).encode()
            else:
                body = json.dumps({"results": [{"gtin":"0460","name":"Product","goodTurnFlag":True,"goodMarkFlag":True}],"total":1}).encode()
            return AgentHttpResponse(200, body, {"Content-Type":"application/json"})
    class Signer: pass
    transport=Transport()
    executor=WindowsAgentExecutor(
        participant_inn="1234567890", transport=transport, session_manager=Session(), document_signer=Signer(), production_write=False
    )
    result=executor.execute(_job(AgentJobType.CIS_TO_PRODUCT, {"cises":[CIS,CIS2]}))
    assert result.outcome == "READ_COMPLETED"
    assert result.read_result["deduplicated_gtins"] == ["0460"]
    assert [call[0] for call in transport.calls] == ["CIS_INFO","PRODUCT_INFO"]
    assert transport.calls[1][1]["gtins"] == ["0460"]
    assert "VERY_SECRET_BEARER" not in json.dumps(result.safe_dict())


def test_m1_job_persists_across_backend_session_restart_and_duplicate_result_is_safe():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from wbcz.windows_agent import AgentResult
    from wbcz_web.config import WebConfig
    from wbcz_web.models import Base
    from wbcz_web.repositories import SqlAlchemyAgentJobStore
    from wbcz_web.services.cis_inventory import CisInventoryService

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    config = WebConfig(
        "postgresql+psycopg://u:p@localhost/db",
        "1234567890",
        environment="test",
        agent_enabled=True,
        agent_machine_token="0123456789abcdef",
    )
    with factory() as db:
        queued = CisInventoryService(db, config).queue(AgentJobType.CIS_INFO, {"cises": [CIS]})
        request_id = queued["request_id"]
        db.commit()
    with factory() as db:
        assert CisInventoryService(db, config).status(request_id)["status"] == "pending"
        store = SqlAlchemyAgentJobStore(db, legacy_unbound=True)
        job = store.fetch_one()
        assert job is not None and job.job_type is AgentJobType.CIS_INFO
        result = AgentResult(job.job_id, job.operation_id, "READ_COMPLETED", read_result={"type":"CIS_INFO","items":[]})
        store.complete(result)
        store.complete(result)
        with pytest.raises(Exception):
            store.complete(AgentResult(job.job_id, job.operation_id, "READ_COMPLETED", read_result={"different": True}))
        db.commit()
    with factory() as db:
        state = CisInventoryService(db, config).status(request_id)
        assert state["status"] == "completed"
        assert state["result"]["type"] == "CIS_INFO"
    engine.dispose()


def test_m1_application_api_uses_session_csrf_and_never_exposes_agent_endpoint():
    import os
    db_url = os.getenv("WBCZ_TEST_DATABASE_URL")
    if not db_url:
        pytest.skip("WBCZ_TEST_DATABASE_URL requires PostgreSQL")
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from wbcz_web.auth import hash_password
    from wbcz_web.config import WebConfig
    from wbcz_web.main import create_app
    from wbcz_web.models import AgentJobRecord, Base
    from wbcz_web.services.authorization import BootstrapService

    engine = create_engine(db_url, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    config = WebConfig(
        db_url,
        "1234567890",
        environment="test",
        agent_enabled=True,
        agent_machine_token="0123456789abcdef",
    )
    app = create_app(config, session_factory=factory)
    request_id = None
    try:
        with factory() as db:
            BootstrapService(db).bootstrap(
                username="owner",password="pw-strong-enough",organisation_name="M1 Test Org",participant_inn="1234567890"
            )
            db.commit()
        with TestClient(app) as client:
            assert client.post("/api/cis-inventory/info", json={"cises":[CIS]}).status_code in (401, 403)
            csrf = client.get("/api/auth/csrf").json()["csrf_token"]
            login = client.post("/api/auth/login", json={"username":"owner","password":"pw-strong-enough"}, headers={"X-CSRF-Token":csrf})
            assert login.status_code == 200
            scopes=client.get("/api/security/scopes")
            assert scopes.status_code==200 and scopes.json()["scopes"]
            target=scopes.json()["scopes"][0]
            switched=client.post(
                "/api/security/scope",
                json={"organisation_id":target["organisation_id"],"participant_id":target["participants"][0]["id"]},
                headers={"X-CSRF-Token":csrf},
            )
            assert switched.status_code==200
            queued = client.post("/api/cis-inventory/info", json={"cises":[CIS]}, headers={"X-CSRF-Token":csrf})
            assert queued.status_code == 200
            request_id = queued.json()["request_id"]
            state = client.get(f"/api/cis-inventory/requests/{request_id}")
            assert state.status_code == 200 and state.json()["status"] == "pending"
            assert client.get("/api/agent/v1/jobs/next").status_code == 401
        with factory() as db:
            row = db.scalar(select(AgentJobRecord).where(AgentJobRecord.job_id == request_id))
            assert row is not None and row.job_type == "CIS_INFO" and row.purpose == "CIS_INVENTORY"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
