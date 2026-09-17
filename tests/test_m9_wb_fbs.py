from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from wbcz.wb_fbs import (
    ANALYTICS_PROD_HOST,
    AUTO_DISTANCE_READY_ENABLED,
    COMMON_PROD_HOST,
    CURRENT_ARCHIVE_TRANSITION_POLICY,
    FbsArchiveQuery,
    FbsCurrentQuery,
    FbsOrderIdentity,
    FulfillmentModel,
    GoodsReturnQuery,
    MarkingBinding,
    MarkingConflictState,
    MarkingValidationState,
    MarkingVault,
    M9Decision,
    M9ReconciliationState,
    MARKETPLACE_PROD_HOST,
    MARKETPLACE_SANDBOX_HOST,
    OrderFeedCycle,
    OrderFeedQuery,
    PAID_SOURCE_CONTRACT_PINNED,
    PRODUCTION_WB_WRITE_ENABLED,
    RATE_RULES,
    STATISTICS_PROD_HOST,
    SUPPLIER_SALES_DEPRECATION_STATE,
    SUPPLIER_SALES_ROLE,
    SupplierSalesQuery,
    TimestampSemantics,
    WbCapabilityName,
    WbConnection,
    WbConnectionState,
    WbContractError,
    WbEnvironment,
    WbErrorEvidence,
    WbEvidenceSource,
    WbHttpResponse,
    WbReadTransport,
    WbRuntimeToken,
    WbSecurityError,
    WbTokenCategory,
    WbTokenType,
    WB_API_SGTIN_AUTOBIND_ENABLED,
    WB_MUTATION_CAPABILITIES,
    WB_READ_CAPABILITIES,
    adapt_p0_xlsx_row,
    cancellation_decision,
    decide_cis_cardinality,
    evaluate_distance_candidate,
    evaluate_remote_sale_return_candidate,
    parse_goods_return_timestamp,
    parse_meta_details,
    parse_order_feed_cancel_type,
    parse_order_feed_status,
    parse_wb_error,
    reconcile_source_marking,
    require_fbs,
    rid_srid_equality_is_join_rule,
    verify_seller_identity,
    WbRateLimiter,
)
from wbcz_web.models.wb_fbs import (
    WbConnectionRecord,
    WbEventRecord,
    WbMarkingBindingRecord,
    WbOrderRecord,
    WbPaidEvidenceRecord,
    WbReconciliationRecord,
    WbReturnRecord,
    WbSyncCursorRecord,
)


NOW = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)


class FakeAdapter:
    def __init__(self) -> None:
        self.calls = []

    def send(self, *, method, url, headers, params, json_body):
        self.calls.append((method, url, dict(headers), dict(params or {}), json_body))
        return WbHttpResponse(200, "application/json", b"{}", {})


def prod_token(category: WbTokenCategory) -> WbRuntimeToken:
    return WbRuntimeToken(
        "WB-TOKEN-CANARY",
        secret_ref="secret://wb/prod",
        token_type=WbTokenType.PERSONAL,
        categories=(category,),
    )


def test_connection_token_policy_and_repr_redaction() -> None:
    connection = WbConnection(
        WbEnvironment.PRODUCTION,
        "1234567890",
        "secret://wb/personal",
        WbTokenType.PERSONAL,
        (WbTokenCategory.MARKETPLACE,),
    )
    assert connection.secret_ref == "secret://wb/personal"
    token = prod_token(WbTokenCategory.MARKETPLACE)
    assert "WB-TOKEN-CANARY" not in repr(token)
    assert "WB-TOKEN-CANARY" not in str(token)
    with pytest.raises(WbContractError):
        WbConnection(WbEnvironment.PRODUCTION, "1234567890", "x", WbTokenType.TEST, (WbTokenCategory.MARKETPLACE,))
    with pytest.raises(WbContractError):
        WbConnection(WbEnvironment.SANDBOX, "1234567890", "x", WbTokenType.PERSONAL, (WbTokenCategory.MARKETPLACE,))


def test_seller_tin_verification_blocks_mismatch() -> None:
    connection = WbConnection(WbEnvironment.PRODUCTION, "1234567890", "secret://x", WbTokenType.PERSONAL, (WbTokenCategory.MARKETPLACE,))
    ok, identity = verify_seller_identity(connection, {"sid": "SID-X", "tin": "1234567890", "name": "seller"})
    assert ok.connection_state is WbConnectionState.HEALTHY and identity.sid == "SID-X"
    bad, _ = verify_seller_identity(connection, {"sid": "SID-Y", "tin": "9999999999"})
    assert bad.connection_state is WbConnectionState.CONNECTION_BLOCKED


def test_exact_read_allowlist_and_no_write_capability_enabled() -> None:
    expected = {
        ("GET", MARKETPLACE_PROD_HOST, "/api/v3/orders/new"),
        ("GET", MARKETPLACE_PROD_HOST, "/api/v3/orders"),
        ("GET", MARKETPLACE_PROD_HOST, "/api/marketplace/v3/fbs/orders/archive"),
        ("POST", MARKETPLACE_PROD_HOST, "/api/v3/orders/status"),
        ("POST", MARKETPLACE_PROD_HOST, "/api/marketplace/v3/orders/meta"),
        ("GET", MARKETPLACE_PROD_HOST, "/api/v3/supplies"),
        ("GET", MARKETPLACE_PROD_HOST, "/api/v3/supplies/{supplyId}"),
        ("GET", MARKETPLACE_PROD_HOST, "/api/marketplace/v3/supplies/{supplyId}/order-ids"),
        ("POST", ANALYTICS_PROD_HOST, "/api/analytics/v1/order-feed"),
        ("GET", ANALYTICS_PROD_HOST, "/api/v1/analytics/goods-return"),
        ("GET", COMMON_PROD_HOST, "/api/v1/seller-info"),
        ("GET", STATISTICS_PROD_HOST, "/api/v1/supplier/sales"),
    }
    actual = {(x.method, x.host, x.path_template) for x in WB_READ_CAPABILITIES.values()}
    assert actual == expected
    assert all(x.read_only for x in WB_READ_CAPABILITIES.values())
    assert all(not x["enabled"] and x["disabled_reason"] == "M9_READ_ONLY_SCOPE" for x in WB_MUTATION_CAPABILITIES.values())
    assert not PRODUCTION_WB_WRITE_ENABLED


def test_typed_transport_internal_auth_has_no_bearer_and_no_caller_host_path_method() -> None:
    fake = FakeAdapter()
    transport = WbReadTransport(fake, WbEnvironment.PRODUCTION)
    transport.fbs_current(FbsCurrentQuery(100, 0, 1_789_000_000, 1_789_000_100), prod_token(WbTokenCategory.MARKETPLACE))
    method, url, headers, params, body = fake.calls[-1]
    assert method == "GET"
    assert url == f"https://{MARKETPLACE_PROD_HOST}/api/v3/orders"
    assert headers["Authorization"] == "WB-TOKEN-CANARY"
    assert not headers["Authorization"].startswith("Bearer ")
    assert params["limit"] == 100 and params["next"] == 0 and body is None
    assert set(inspect.signature(transport.fbs_current).parameters) == {"q", "token"}
    assert "headers" not in inspect.signature(transport.fbs_current).parameters


def test_sandbox_marketplace_uses_test_token_and_sandbox_host() -> None:
    fake = FakeAdapter()
    transport = WbReadTransport(fake, WbEnvironment.SANDBOX)
    token = WbRuntimeToken("TEST-CANARY", secret_ref="secret://test", token_type=WbTokenType.TEST, categories=(WbTokenCategory.MARKETPLACE,))
    transport.fbs_new(token)
    assert fake.calls[-1][1] == f"https://{MARKETPLACE_SANDBOX_HOST}/api/v3/orders/new"
    with pytest.raises(WbSecurityError):
        transport.order_feed(OrderFeedQuery(NOW, NOW + timedelta(days=1)), token)


def test_current_and_archive_validation_and_cursor_semantics() -> None:
    FbsCurrentQuery(1, 0, 100, 100 + 30 * 86400).params()
    FbsCurrentQuery(1000).params()
    with pytest.raises(WbContractError): FbsCurrentQuery(0).params()
    with pytest.raises(WbContractError): FbsCurrentQuery(1001).params()
    with pytest.raises(WbContractError): FbsCurrentQuery(10, 0, 100, 100 + 31 * 86400).params()
    assert FbsArchiveQuery(2026, 9, 100, 0).params()["next"] == 0
    assert FbsArchiveQuery(2026, 9, 1000, 2**40).params()["next"] == 2**40
    with pytest.raises(WbContractError): FbsArchiveQuery(2026, 13, 100, 0).params()
    with pytest.raises(WbContractError): FbsArchiveQuery(2026, 9, 99, 0).params()
    assert CURRENT_ARCHIVE_TRANSITION_POLICY.overlap_required if hasattr(CURRENT_ARCHIVE_TRANSITION_POLICY, "overlap_required") else CURRENT_ARCHIVE_TRANSITION_POLICY.enabled
    assert not CURRENT_ARCHIVE_TRANSITION_POLICY.current_disappearance_means_cancel
    assert not CURRENT_ARCHIVE_TRANSITION_POLICY.archive_absence_means_delete


def test_order_feed_31day_snapshot_replay_restart_and_unknowns() -> None:
    q = OrderFeedQuery(NOW, NOW + timedelta(days=31), offset=0, limit=None)
    body = q.body()
    assert "limit" not in body["pagination"]
    with pytest.raises(WbContractError):
        OrderFeedQuery(NOW, NOW + timedelta(days=31, seconds=1)).body()
    cycle = OrderFeedCycle(1, NOW, NOW + timedelta(days=2), "cycle-1")
    established = cycle.establish_snapshot("2026-09-18T00:00:00Z")
    replay = established.commit_page(next_offset=100, page=0, durable_batch_committed=False, now=NOW)
    assert replay.offset == 0
    committed = established.commit_page(next_offset=100, page=0, durable_batch_committed=True, now=NOW)
    assert committed.offset == 100 and committed.snapshot_time == established.snapshot_time
    restarted = committed.restart("cycle-2")
    assert restarted.snapshot_time is None and restarted.offset == 0
    assert parse_order_feed_status("cancel").known
    assert not parse_order_feed_status("buyout").known
    assert parse_order_feed_status("FutureStatus").raw == "FutureStatus"
    assert parse_order_feed_cancel_type("app").known
    assert not parse_order_feed_cancel_type("future").known


def test_rate_profiles_are_token_type_aware_and_base_never_inherits_personal() -> None:
    limiter = WbRateLimiter()
    marketplace = limiter.rule("MARKETPLACE_FBS", WbTokenType.PERSONAL, WbEnvironment.PRODUCTION)
    assert (marketplace.limit, marketplace.period_seconds, marketplace.interval_seconds, marketplace.burst, marketplace.four_x_weight) == (300, 60, 0.2, 20, 10)
    assert limiter.rule("MARKETPLACE_FBS", WbTokenType.TEST, WbEnvironment.SANDBOX).interval_seconds == 1
    assert limiter.rule("ORDER_FEED", WbTokenType.PERSONAL, WbEnvironment.PRODUCTION).period_seconds == 60
    assert limiter.rule("ORDER_FEED", WbTokenType.BASE, WbEnvironment.PRODUCTION).period_seconds == 10800
    assert limiter.rule("SUPPLIER_SALES", WbTokenType.BASE, WbEnvironment.PRODUCTION).period_seconds == 7200
    gr = limiter.rule("GOODS_RETURN", WbTokenType.BASE, WbEnvironment.PRODUCTION)
    assert (gr.period_seconds, gr.limit, gr.interval_seconds, gr.burst) == (3600, 2, 1800.0, 1)
    seller = limiter.rule("SELLER_INFO", WbTokenType.PERSONAL, WbEnvironment.PRODUCTION)
    assert (seller.period_seconds, seller.limit, seller.burst) == (60, 1, 10)
    assert limiter.response_weight("MARKETPLACE_FBS", 400, WbEnvironment.PRODUCTION) == 10
    assert limiter.response_weight("ORDER_FEED", 400, WbEnvironment.PRODUCTION) == 1


def test_identity_rid_srid_are_separate_and_never_join_rule() -> None:
    ident = FbsOrderIdentity(1, 2**40, order_uid="uid", rid="RID-A", srid="SRID-B")
    assert ident.rid == "RID-A" and ident.srid == "SRID-B"
    assert not rid_srid_equality_is_join_rule()


def test_meta_details_current_surface_and_autobind_gate() -> None:
    parsed = parse_meta_details({"metaDetails": {"future": {"status": "x"}}, "meta": {"legacy": True}})
    assert parsed.raw_sanitized["future"]["status"] == "x"
    assert parsed.legacy_meta_present
    assert not WB_API_SGTIN_AUTOBIND_ENABLED
    assert decide_cis_cardinality([], deterministic_validated_count=0) is M9Decision.WAIT_FOR_EVIDENCE
    assert decide_cis_cardinality(["one"], deterministic_validated_count=1) is M9Decision.CIS_PREFLIGHT
    assert decide_cis_cardinality(["one", "two"], deterministic_validated_count=0) is M9Decision.MANUAL_REVIEW
    assert decide_cis_cardinality(["one"], deterministic_validated_count=1, reused_on_live_order=True) is M9Decision.MANUAL_REVIEW


class TestKeyProvider:
    __test__ = False
    def __init__(self, key: bytes) -> None:
        self.key = key
    def get_key(self, key_version: str) -> bytes:
        assert key_version == "test-key-v1"
        return self.key


def test_exact_sgtin_encrypted_at_rest_gs_preserved_and_aad_bound() -> None:
    exact = "010460123456789021SERIAL\x1d91CRYPTO\x1d92TAIL"
    binding = MarkingBinding(1, 999, WbEvidenceSource.WB_API, NOW)
    vault = MarkingVault(TestKeyProvider(b"K" * 32), "test-key-v1")
    envelope = vault.encrypt(exact, binding=binding)
    assert exact.encode() not in envelope.ciphertext
    assert exact not in repr(envelope)
    assert envelope.fingerprint_sha256 == hashlib.sha256(exact.encode()).hexdigest()
    assert vault.decrypt(envelope, binding=binding) == exact
    with pytest.raises(Exception):
        vault.decrypt(envelope, binding=replace(binding, assembly_order_id=1000))
    with pytest.raises(Exception):
        MarkingVault(TestKeyProvider(b"Z" * 32), "test-key-v1").decrypt(envelope, binding=binding)


def test_multisource_conflicts_fail_closed_and_xlsx_adapter_reuses_p0_evidence() -> None:
    fp = hashlib.sha256(b"same").hexdigest()
    assert reconcile_source_marking(fp, fp) is M9Decision.CIS_PREFLIGHT
    assert reconcile_source_marking(fp, hashlib.sha256(b"other").hexdigest()) is M9Decision.MANUAL_REVIEW
    assert reconcile_source_marking(None, fp) is M9Decision.CIS_PREFLIGHT
    assert reconcile_source_marking(fp, None, identity_conflict=True) is M9Decision.MANUAL_REVIEW
    row = adapt_p0_xlsx_row({"event_id": "e1", "assembly_order_id": 7, "kiz": "SECRET-KIZ", "amount": 100})
    assert row.source is WbEvidenceSource.WB_XLSX
    assert row.marking_fingerprint and "SECRET-KIZ" not in repr(row.normalized)


def test_paid_source_gate_makes_distance_ready_impossible() -> None:
    assert not AUTO_DISTANCE_READY_ENABLED
    assert not PAID_SOURCE_CONTRACT_PINNED
    result = evaluate_distance_candidate(
        marketplace_sold=True,
        supplier_sales_match=True,
        m1_ok=True,
        m2_ok=True,
        m6_safe=True,
        duplicate_completed_m5=False,
        identity_conflict=False,
    )
    assert result is M9Decision.WAIT_FOR_EVIDENCE
    assert evaluate_distance_candidate(
        marketplace_sold=True, supplier_sales_match=True, m1_ok=False, m2_ok=True, m6_safe=True,
        duplicate_completed_m5=False, identity_conflict=False,
    ) is M9Decision.MANUAL_REVIEW
    assert SUPPLIER_SALES_ROLE == "TEMPORARY_PAYMENT_CONFIRMATION_COMPATIBILITY_EVIDENCE"
    assert set(SUPPLIER_SALES_DEPRECATION_STATE) == {"CURRENTLY_CALLABLE", "FUTURE_SHUTDOWN_ANNOUNCED"}


def test_physical_return_completed_dt_gate() -> None:
    naive = parse_goods_return_timestamp("2026-09-18T12:00:00")
    aware = parse_goods_return_timestamp("2026-09-18T12:00:00+03:00")
    assert naive.parsed is None and naive.semantics is TimestampSemantics.TIMEZONE_UNKNOWN
    assert aware.parsed is not None and aware.semantics is TimestampSemantics.OFFSET_EXPLICIT
    assert evaluate_remote_sale_return_candidate(
        previous_distance_reconciled=True, completed_dt_present=True, deterministic_cis=True,
        m1_fresh_ok=True, m1_return_state_ok=True, m2_ok=True, m6_safe=True,
        duplicate_completed_return=False, identity_conflict=False,
    ) is M9Decision.REMOTE_SALE_RETURN_READY
    assert evaluate_remote_sale_return_candidate(
        previous_distance_reconciled=False, completed_dt_present=True, deterministic_cis=True,
        m1_fresh_ok=True, m1_return_state_ok=True, m2_ok=True, m6_safe=True,
        duplicate_completed_return=False, identity_conflict=False,
    ) is M9Decision.WAIT_FOR_EVIDENCE
    assert evaluate_remote_sale_return_candidate(
        previous_distance_reconciled=True, completed_dt_present=False, deterministic_cis=True,
        m1_fresh_ok=True, m1_return_state_ok=True, m2_ok=True, m6_safe=True,
        duplicate_completed_return=False, identity_conflict=False,
    ) is M9Decision.WAIT_FOR_EVIDENCE


def test_cancellation_matrix_no_synthetic_true_api_cancel() -> None:
    assert cancellation_decision("seller_cancel_before_sale", prior_confirmed_sale=False) is M9Decision.NO_ACTION
    assert cancellation_decision("delivery", prior_confirmed_sale=False) is M9Decision.WAIT_FOR_EVIDENCE
    assert cancellation_decision("return_requested", prior_confirmed_sale=True) is M9Decision.WAIT_FOR_EVIDENCE
    assert cancellation_decision("physically_returned_completed_dt", prior_confirmed_sale=True) is M9Decision.CIS_PREFLIGHT
    assert cancellation_decision("physically_returned_completed_dt", prior_confirmed_sale=True, existing_distance=True) is M9Decision.MANUAL_REVIEW


def test_fulfillment_boundary_rejects_non_fbs() -> None:
    require_fbs(FulfillmentModel.FBS)
    for model in (FulfillmentModel.FBO, FulfillmentModel.FBW, FulfillmentModel.DBS, FulfillmentModel.DBW):
        with pytest.raises(WbContractError):
            require_fbs(model)


def test_error_parser_json_problem_and_unknown_preserves_without_retryability() -> None:
    json_err = parse_wb_error(WbHttpResponse(400, "application/json; charset=utf-8", b'{"code":"X","message":"bad","requestId":"r1"}'))
    assert json_err.code == "X" and json_err.message == "bad" and json_err.request_id == "r1"
    problem = parse_wb_error(WbHttpResponse(429, "application/problem+json", b'{"title":"too many","detail":"slow"}'))
    assert problem.title == "too many" and problem.detail == "slow"
    unknown = parse_wb_error(WbHttpResponse(500, "text/plain", b"future body"))
    assert unknown.raw_sanitized["raw"] == "future body"
    assert not hasattr(json_err, "retryable") and not hasattr(json_err, "terminal")
    secret = parse_wb_error(WbHttpResponse(401, "text/plain", b"TOKEN-CANARY"), secret_canaries=("TOKEN-CANARY",))
    assert "TOKEN-CANARY" not in repr(secret)


def test_models_and_migration_have_no_plaintext_token_or_cis_columns() -> None:
    conn = set(WbConnectionRecord.__table__.columns.keys())
    assert "token" not in conn and "raw_token" not in conn and "authorization" not in conn
    assert {"secret_ref", "token_type", "token_categories", "participant_inn", "wb_tin"} <= conn
    marking = set(WbMarkingBindingRecord.__table__.columns.keys())
    assert not {"cis", "sgtin", "kiz", "plaintext", "full_marking"} & marking
    assert {"ciphertext", "nonce", "auth_tag", "fingerprint_sha256", "masked_value"} <= marking
    assert "rid" in WbOrderRecord.__table__.columns and "srid" in WbOrderRecord.__table__.columns
    assert "srid" in WbEventRecord.__table__.columns
    assert "completed_dt_raw" in WbReturnRecord.__table__.columns
    assert "snapshot_time" in WbSyncCursorRecord.__table__.columns
    assert "decision" in WbReconciliationRecord.__table__.columns
    assert "contract_status" in WbPaidEvidenceRecord.__table__.columns
    text = Path("migrations/versions/0010_m9_wb.py").read_text(encoding="utf-8").lower()
    assert 'down_revision = "0009_m8_suz"' in text
    for forbidden in ('column("token"', 'column("raw_token"', 'column("authorization"', 'column("cis"', 'column("sgtin"', 'column("kiz"', 'column("plaintext"'):
        assert forbidden not in text


def test_no_generic_wb_proxy_or_forbidden_mutation_paths_in_m9_source() -> None:
    source = Path("src/wbcz/wb_fbs.py").read_text(encoding="utf-8")
    forbidden = (
        "GENERIC_WB_PROXY", "RAW_WB_URL", "RAW_WB_HOST", "RAW_WB_PATH", "RAW_WB_METHOD",
        '"/api/v3/orders/{orderId}/meta/sgtin"', "PATCH /", "PUT /", "DELETE /",
    )
    for marker in forbidden:
        assert marker not in source
    assert "M10" not in source
