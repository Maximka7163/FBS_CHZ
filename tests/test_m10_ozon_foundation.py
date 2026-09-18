from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from wbcz.ozon_foundation import (
    API_KEY_LOGGING_ALLOWED,
    AUTO_DISTANCE_READY_ENABLED,
    AUTO_REMOTE_SALE_RETURN_READY_ENABLED,
    CANONICAL_AUTH_HEADER_API_KEY,
    CANONICAL_AUTH_HEADER_CLIENT_ID,
    CANONICAL_JSON_CONTENT_TYPE,
    CIS_LOGGING_ALLOWED,
    DEPRECATED_OR_FORBIDDEN_REMOTE_PATHS,
    FRONTEND_FREEZE_ACTIVE,
    GLOBAL_OZON_LIMIT_RPS,
    INVENTED_BURST_CAPACITY,
    MARK_VALUE_EXTRACTION_ENABLED,
    M10_WIRE_READY,
    M5LocalOperation,
    M5TypedLocalDecisionReference,
    OZON_API_CIS_AUTOBIND_ENABLED,
    OZON_AUTH_HEADER_POLICY,
    OZON_ENDPOINT_RATE_PROFILES_PINNED,
    OZON_EXECUTABLE_REMOTE_CAPABILITIES,
    OZON_INN_AUTOBIND_ENABLED,
    OZON_MARKING_VAULT_FORMAT,
    OZON_PROD_HOST,
    OZON_REMOTE_CAPABILITIES,
    OzonCapabilityDisabled,
    OzonCapabilityName,
    OzonClientIdRateLimiter,
    OzonConnection,
    OzonConnectionState,
    OzonMarkingBinding,
    OzonMarkingEnvelope,
    OzonMarkingVault,
    OzonOpaqueIdentity,
    OzonRuntimeApiKey,
    OzonSafetyDecision,
    OzonSecurityError,
    OzonSyncCheckpoint,
    PAID_SOURCE_PINNED,
    PAYMENT_CONFIRMATION_CONTRACT_PINNED,
    PHYSICAL_SELLER_RETURN_CONTRACT_PINNED,
    PRODUCTION_OZON_WRITE_ENABLED,
    TRUE_API_WRITE_FROM_M10,
    assert_remote_path_allowed,
    automatic_m5_reference_from_ozon_evidence,
    cis_can_be_derived_from_product_identifiers,
    evaluate_distance_safety,
    evaluate_remote_sale_return_safety,
    exact_marking_fingerprint,
    exemplar_id_equals_cis_is_join_rule,
    posting_number_equals_order_id_is_join_rule,
    require_remote_capability,
    runtime_api_key,
    sanitize_ozon_error,
    sanitize_ozon_evidence,
    sku_equals_product_id_is_join_rule,
)
from wbcz_web.models.ozon import (
    OzonConnectionRecord,
    OzonEventRecord,
    OzonItemRecord,
    OzonMarkingBindingRecord,
    OzonPaidEvidenceRecord,
    OzonPostingRecord,
    OzonReconciliationRecord,
    OzonReturnRecord,
    OzonSyncCursorRecord,
)


NOW = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)


class SecretProvider:
    def __init__(self, secret: str) -> None:
        self.secret = secret
        self.calls: list[str] = []

    def get_secret(self, secret_ref: str) -> str:
        self.calls.append(secret_ref)
        return self.secret


class KeyProvider:
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.calls: list[str] = []

    def get_key(self, key_version: str) -> bytes:
        self.calls.append(key_version)
        return self.key


def test_hard_safe_foundation_gates_are_closed() -> None:
    assert not M10_WIRE_READY
    assert not PRODUCTION_OZON_WRITE_ENABLED
    assert not OZON_INN_AUTOBIND_ENABLED
    assert not OZON_API_CIS_AUTOBIND_ENABLED
    assert not MARK_VALUE_EXTRACTION_ENABLED
    assert not PAYMENT_CONFIRMATION_CONTRACT_PINNED
    assert not PAID_SOURCE_PINNED
    assert not PHYSICAL_SELLER_RETURN_CONTRACT_PINNED
    assert not AUTO_DISTANCE_READY_ENABLED
    assert not AUTO_REMOTE_SALE_RETURN_READY_ENABLED
    assert not TRUE_API_WRITE_FROM_M10
    assert not API_KEY_LOGGING_ALLOWED
    assert not CIS_LOGGING_ALLOWED
    assert FRONTEND_FREEZE_ACTIVE
    assert OZON_EXECUTABLE_REMOTE_CAPABILITIES == ()


def test_connection_preserves_client_id_and_uses_secret_ref_only() -> None:
    expires = NOW + timedelta(days=30)
    connection = OzonConnection(
        participant_inn="1234567890",
        client_id="Client-CaseSensitive-001",
        api_key_secret_ref="secret://ozon/key-1",
        api_key_expires_at=expires,
        roles_metadata=("role-a",),
        capability_metadata=("local-only",),
        connection_state=OzonConnectionState.LOCAL_CONFIGURED,
    )
    assert connection.client_id == "Client-CaseSensitive-001"
    assert connection.api_key_secret_ref == "secret://ozon/key-1"
    assert connection.api_key_expires_at == expires
    assert not hasattr(connection, "api_key")
    assert not hasattr(connection, "authorization")


def test_runtime_api_key_is_memory_only_and_repr_str_redacted() -> None:
    secret = "OZON-API-KEY-SECRET-CANARY"
    provider = SecretProvider(secret)
    connection = OzonConnection(
        participant_inn="1234567890",
        client_id="cid",
        api_key_secret_ref="secret://ozon/main",
        api_key_expires_at=NOW,
    )
    token = runtime_api_key(connection, provider)
    assert provider.calls == ["secret://ozon/main"]
    assert token.client_id == "cid"
    assert token.expires_at == NOW
    assert secret not in repr(token)
    assert secret not in str(token)
    assert "REDACTED" in repr(token)


def test_expiry_is_explicit_only_and_no_legacy_formula_exists() -> None:
    connection = OzonConnection("1234567890", "cid", "secret://legacy")
    assert connection.api_key_expires_at is None
    source = Path("src/wbcz/ozon_foundation.py").read_text(encoding="utf-8")
    assert "created_at + timedelta" not in source
    assert "months=3" not in source
    assert "90 * 86400" not in source


def test_auth_header_policy_is_canonical_and_not_caller_controlled() -> None:
    assert CANONICAL_AUTH_HEADER_CLIENT_ID == "Client-Id"
    assert CANONICAL_AUTH_HEADER_API_KEY == "Api-Key"
    assert CANONICAL_JSON_CONTENT_TYPE == "application/json"
    assert not OZON_AUTH_HEADER_POLICY.caller_controlled_auth_headers
    assert not OZON_AUTH_HEADER_POLICY.arbitrary_headers_supported


def test_capability_registry_contains_exact_accepted_disabled_metadata() -> None:
    expected = {
        OzonCapabilityName.FBS_LIST: ("POST", "/v4/posting/fbs/list"),
        OzonCapabilityName.FBS_UNFULFILLED: ("POST", "/v4/posting/fbs/unfulfilled/list"),
        OzonCapabilityName.FBS_GET: ("POST", "/v3/posting/fbs/get"),
        OzonCapabilityName.EXEMPLAR_STATUS: ("POST", "/v5/fbs/posting/product/exemplar/status"),
        OzonCapabilityName.RETURNS_LIST: ("POST", "/v1/returns/list"),
        OzonCapabilityName.SELLER_INFO: ("POST", "/v1/seller/info"),
        OzonCapabilityName.ROLES: ("POST", "/v1/roles"),
        OzonCapabilityName.WAREHOUSE_LIST: ("POST", "/v2/warehouse/list"),
    }
    assert set(OZON_REMOTE_CAPABILITIES) == set(expected)
    for name, cap in OZON_REMOTE_CAPABILITIES.items():
        method, path = expected[name]
        assert cap.host == OZON_PROD_HOST
        assert cap.method == method
        assert cap.path == path
        assert not cap.enabled
        assert not cap.contract_pinned
        assert not cap.rate_profile_pinned
        assert cap.request_contract is None
        assert cap.response_contract is None
        assert cap.pagination_contract is None
        assert cap.endpoint_rate_limit is None
        assert cap.disabled_reason == "OFFICIAL_CONTRACT_NOT_PINNED"
    assert len(OZON_REMOTE_CAPABILITIES) == 8
    assert len(OZON_EXECUTABLE_REMOTE_CAPABILITIES) == 0


def test_every_remote_capability_fails_locally_without_adapter_or_network_surface() -> None:
    class FakeAdapter:
        def __init__(self) -> None:
            self.calls = 0

        def send(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError("adapter must never be reachable")

    fake = FakeAdapter()
    for name in OzonCapabilityName:
        with pytest.raises(OzonCapabilityDisabled):
            require_remote_capability(name)
    assert fake.calls == 0

    module_source = Path("src/wbcz/ozon_foundation.py").read_text(encoding="utf-8")
    for forbidden in (
        "class OzonHttpAdapter", "class OzonReadTransport", "GenericOzonClient",
        "requests.", "httpx.", "urllib.request", "RAW_OZON_URL", "RAW_OZON_PATH",
        "RAW_OZON_METHOD", "RAW_OZON_HEADERS",
    ):
        assert forbidden not in module_source


def test_deprecated_and_forbidden_remote_paths_are_rejected() -> None:
    required = {
        "/v3/posting/fbs/list",
        "/v3/posting/fbs/unfulfilled/list",
        "/v3/finance/transaction/list",
        "/v3/finance/transaction/totals",
    }
    assert required <= DEPRECATED_OR_FORBIDDEN_REMOTE_PATHS
    for path in required:
        with pytest.raises(OzonCapabilityDisabled):
            assert_remote_path_allowed(path)


def test_rate_foundation_is_global_50_per_second_per_client_id_without_burst_metadata() -> None:
    assert GLOBAL_OZON_LIMIT_RPS == 50
    assert not OZON_ENDPOINT_RATE_PROFILES_PINNED
    assert not INVENTED_BURST_CAPACITY
    limiter = OzonClientIdRateLimiter()
    for _ in range(50):
        assert limiter.consume(client_id="client-a", now_monotonic=0.0).allowed
    blocked = limiter.consume(client_id="client-a", now_monotonic=0.0)
    assert not blocked.allowed
    assert blocked.retry_after_seconds == pytest.approx(1.0)
    assert limiter.consume(client_id="client-b", now_monotonic=0.0).allowed
    assert limiter.consume(client_id="client-a", now_monotonic=1.0).allowed


def test_rate_limiter_has_no_remote_adapter_attachment() -> None:
    sig = inspect.signature(OzonClientIdRateLimiter.consume)
    assert set(sig.parameters) == {"self", "client_id", "now_monotonic"}
    assert "adapter" not in sig.parameters
    assert "capability" not in sig.parameters
    for cap in OZON_REMOTE_CAPABILITIES.values():
        assert cap.endpoint_rate_limit is None


def test_opaque_identity_preserves_exact_values_and_has_no_equivalence_rules() -> None:
    identity = OzonOpaqueIdentity(
        posting_number="Posting/Case-ABC",
        order_id="Order-X",
        product_id="000123",
        offer_id="Offer-Case",
        sku="000123",
        barcode="04601234567890",
        warehouse_id="WH-001",
        delivery_method_id="DM-001",
        exemplar_id="EX-001",
        return_id="RET-001",
        report_id="REP-001",
        finance_id="FIN-001",
    )
    assert identity.posting_number == "Posting/Case-ABC"
    assert identity.product_id == "000123"
    assert identity.sku == "000123"
    assert not sku_equals_product_id_is_join_rule()
    assert not posting_number_equals_order_id_is_join_rule()
    assert not exemplar_id_equals_cis_is_join_rule()
    assert not cis_can_be_derived_from_product_identifiers()


def test_marking_vault_roundtrip_preserves_exact_source_representation() -> None:
    key = b"k" * 32
    provider = KeyProvider(key)
    vault = OzonMarkingVault(provider, "test-key-v1")
    exact = "010460123456789021SERIAL\x1d91ABCD\x1d92CRYPTO-TAIL"
    binding = OzonMarkingBinding(
        connection_id=1,
        source_capability=OzonCapabilityName.EXEMPLAR_STATUS,
        posting_number="POST-1",
        item_ref="ITEM-1",
        exemplar_id="EX-1",
        observed_at=NOW,
    )
    envelope = vault.encrypt(exact, binding=binding)
    assert envelope.vault_format == OZON_MARKING_VAULT_FORMAT
    assert envelope.plaintext_sha256 == hashlib.sha256(exact.encode()).hexdigest()
    assert envelope.ciphertext_sha256 == hashlib.sha256(envelope.ciphertext + envelope.auth_tag).hexdigest()
    assert exact not in repr(envelope)
    assert vault.decrypt(envelope, binding=binding) == exact
    assert provider.calls


def test_marking_fingerprint_changes_on_one_byte_mutation() -> None:
    a = "MARKING-A"
    b = "MARKING-B"
    assert exact_marking_fingerprint(a) != exact_marking_fingerprint(b)


def test_marking_vault_wrong_key_wrong_aad_and_ciphertext_mutation_fail() -> None:
    binding = OzonMarkingBinding(1, OzonCapabilityName.EXEMPLAR_STATUS, "P1", "I1", "E1", NOW)
    vault = OzonMarkingVault(KeyProvider(b"a" * 32), "v1")
    envelope = vault.encrypt("CIS-SECRET", binding=binding)

    wrong_key = OzonMarkingVault(KeyProvider(b"b" * 32), "v1")
    with pytest.raises(OzonSecurityError):
        wrong_key.decrypt(envelope, binding=binding)

    wrong_binding = OzonMarkingBinding(1, OzonCapabilityName.EXEMPLAR_STATUS, "P2", "I1", "E1", NOW)
    with pytest.raises(OzonSecurityError):
        vault.decrypt(envelope, binding=wrong_binding)

    mutated = replace(
        envelope,
        ciphertext=(bytes([envelope.ciphertext[0] ^ 1]) + envelope.ciphertext[1:]),
    )
    with pytest.raises(OzonSecurityError):
        vault.decrypt(mutated, binding=binding)


def test_recursive_sanitizer_removes_nested_products_exemplars_marks_canary() -> None:
    canary = "CIS-NESTED-CANARY"
    payload = {
        "products": [
            {
                "product_id": "P-1",
                "exemplars": [
                    {
                        "exemplar_id": "E-1",
                        "marks": [{"value": canary, "future": "inside-mark"}],
                        "futureNonSensitive": {"ok": True},
                    }
                ],
            }
        ],
        "futureRoot": {"keep": 7},
    }
    safe = sanitize_ozon_evidence(payload)
    rendered = repr(safe)
    assert canary not in rendered
    assert safe["products"][0]["exemplars"][0]["marks"] == "REDACTED"
    assert safe["products"][0]["exemplars"][0]["futureNonSensitive"] == {"ok": True}
    assert safe["futureRoot"] == {"keep": 7}


def test_recursive_sanitizer_direct_and_discriminator_forms() -> None:
    payload = {
        "sgtin": "DIRECT-SGTIN",
        "cis": "DIRECT-CIS",
        "kiz": "DIRECT-KIZ",
        "markingCode": "DIRECT-MARKING",
        "future": [
            {"key": "sgtin", "value": "DISC-ONE"},
            {"type": "marking", "values": ["DISC-A", "DISC-B"]},
            {"kind": "cis", "data": {"value": "DISC-NESTED"}},
            {"type": "futureType", "data": {"value": "keep", "x": 1}},
        ],
    }
    safe = sanitize_ozon_evidence(payload)
    rendered = repr(safe)
    for secret in (
        "DIRECT-SGTIN", "DIRECT-CIS", "DIRECT-KIZ", "DIRECT-MARKING",
        "DISC-ONE", "DISC-A", "DISC-B", "DISC-NESTED",
    ):
        assert secret not in rendered
    assert safe["future"][3]["data"] == {"value": "keep", "x": 1}


def test_recursive_sanitizer_handles_tuple_list_mapping_combinations() -> None:
    payload = (
        {"future": "keep"},
        [{"key": "kiz", "value": "TUPLE-CANARY"}],
    )
    safe = sanitize_ozon_evidence(payload)
    assert isinstance(safe, list)
    assert "TUPLE-CANARY" not in repr(safe)
    assert safe[0]["future"] == "keep"


def test_error_sanitizer_blocks_api_key_and_marking_canaries() -> None:
    payload = {
        "message": "future error",
        "Api-Key": "API-KEY-CANARY",
        "details": [{"type": "sgtin", "data": {"value": "CIS-ERROR-CANARY"}}],
        "future": {"keep": True},
    }
    evidence = sanitize_ozon_error(payload)
    rendered = repr(evidence.raw_sanitized)
    assert "API-KEY-CANARY" not in rendered
    assert "CIS-ERROR-CANARY" not in rendered
    assert evidence.raw_sanitized["future"] == {"keep": True}
    assert "CIS-ERROR-CANARY" not in repr(evidence)


def test_marking_immutability_policy_has_no_normalizer_or_derivation() -> None:
    source = Path("src/wbcz/ozon_foundation.py").read_text(encoding="utf-8").lower()
    assert "strip_gs" not in source
    assert "strip_crypto" not in source
    assert "rebuild_cis" not in source
    assert "generate_cis" not in source
    assert not MARK_VALUE_EXTRACTION_ENABLED


def test_sync_checkpoint_is_wire_opaque_and_preserves_exact_cursor_values() -> None:
    checkpoint = OzonSyncCheckpoint(
        connection_id=1,
        feed="future-feed",
        cycle_id="Cycle-A",
        cursor_opaque="CuRsOr/Exact==",
        offset_opaque="000001",
        window_start_raw="future-start-format",
        window_end_raw="future-end-format",
        snapshot_opaque="Snapshot-X",
        generation=3,
    )
    assert checkpoint.cursor_opaque == "CuRsOr/Exact=="
    assert checkpoint.offset_opaque == "000001"
    assert checkpoint.window_start_raw == "future-start-format"
    source = inspect.getsource(OzonSyncCheckpoint)
    for forbidden in ("page_size", "has_next", "limit", "sort_order", "date_window_days"):
        assert forbidden not in source


def test_local_reconciliation_is_project_state_not_ozon_status_mapping() -> None:
    from wbcz.ozon_foundation import OzonLocalReconciliationState
    expected = {
        "OZON_ORDER_DISCOVERED", "OZON_CIS_MISSING", "OZON_CIS_CAPTURED",
        "OZON_CIS_VERIFIED", "OZON_SALE_PENDING", "OZON_DELIVERY_CONFIRMED",
        "OZON_PAYMENT_PENDING", "OZON_SALE_CONFIRMED", "DISTANCE_PENDING",
        "DISTANCE_SUBMITTED", "DISTANCE_RECONCILED", "OZON_RETURN_PENDING",
        "OZON_ITEM_RETURNED", "REMOTE_RETURN_PENDING", "REMOTE_RETURN_RECONCILED",
        "CANCELLED_NO_ACTION", "MANUAL_REVIEW",
    }
    assert {x.value for x in OzonLocalReconciliationState} == expected


def test_payment_and_delivery_evidence_never_produce_distance_ready() -> None:
    for kwargs in (
        dict(payment_evidence_present=True, delivery_like_evidence_present=False, paid_amount_candidate_present=False),
        dict(payment_evidence_present=False, delivery_like_evidence_present=True, paid_amount_candidate_present=False),
        dict(payment_evidence_present=False, delivery_like_evidence_present=False, paid_amount_candidate_present=True),
        dict(payment_evidence_present=True, delivery_like_evidence_present=True, paid_amount_candidate_present=True),
    ):
        decision = evaluate_distance_safety(**kwargs)
        assert decision is OzonSafetyDecision.WAIT_FOR_EVIDENCE
        assert decision.value != "DISTANCE_READY"


def test_return_or_refund_never_produces_remote_sale_return_ready() -> None:
    decision = evaluate_remote_sale_return_safety(
        return_or_refund_evidence_present=True,
        physical_seller_return_evidence_present=False,
    )
    assert decision is OzonSafetyDecision.WAIT_FOR_EVIDENCE
    assert decision.value != "REMOTE_SALE_RETURN_READY"
    physical = evaluate_remote_sale_return_safety(
        return_or_refund_evidence_present=False,
        physical_seller_return_evidence_present=True,
    )
    assert physical is OzonSafetyDecision.WAIT_FOR_EVIDENCE


def test_aggregate_or_identity_ambiguity_is_manual_review() -> None:
    assert evaluate_distance_safety(
        payment_evidence_present=False,
        delivery_like_evidence_present=False,
        paid_amount_candidate_present=False,
        aggregate_ambiguous=True,
    ) is OzonSafetyDecision.MANUAL_REVIEW
    assert evaluate_remote_sale_return_safety(
        return_or_refund_evidence_present=False,
        physical_seller_return_evidence_present=False,
        identity_conflict=True,
    ) is OzonSafetyDecision.MANUAL_REVIEW


def test_m1_m2_m4_m5_m6_interfaces_exist_but_automatic_m5_handoff_is_disabled() -> None:
    from wbcz.ozon_foundation import (
        M1PreflightAdapter,
        M2ProductEvidenceAdapter,
        M4ReconciliationReferenceAdapter,
        M5TypedDecisionAdapter,
        M6AggregateAdapter,
    )
    for protocol in (
        M1PreflightAdapter,
        M2ProductEvidenceAdapter,
        M4ReconciliationReferenceAdapter,
        M5TypedDecisionAdapter,
        M6AggregateAdapter,
    ):
        assert protocol is not None

    reference = M5TypedLocalDecisionReference(
        operation=M5LocalOperation.DISTANCE,
        connection_id=1,
        posting_number="P-1",
        marking_fingerprint="a" * 64,
        evidence_fingerprint="b" * 64,
        manually_authorized=False,
    )
    assert reference.operation is M5LocalOperation.DISTANCE
    assert not hasattr(reference, "url")
    assert not hasattr(reference, "document")
    assert not hasattr(reference, "api_key")

    with pytest.raises(OzonSecurityError):
        automatic_m5_reference_from_ozon_evidence(reference)


def test_persistence_models_have_no_plaintext_api_key_or_cis_columns() -> None:
    connection_columns = set(OzonConnectionRecord.__table__.columns.keys())
    assert {"participant_inn", "client_id", "api_key_secret_ref", "api_key_expires_at"} <= connection_columns
    assert not {"api_key", "raw_api_key", "authorization", "auth_header", "secret"} & connection_columns

    marking_columns = set(OzonMarkingBindingRecord.__table__.columns.keys())
    assert {
        "ciphertext", "nonce", "auth_tag", "key_version", "vault_format",
        "aad_hash", "plaintext_sha256", "ciphertext_sha256", "masked_value",
    } <= marking_columns
    assert not {"cis", "sgtin", "kiz", "marking", "marking_code", "plaintext", "full_marking"} & marking_columns

    assert "posting_number" in OzonPostingRecord.__table__.columns
    assert "exemplar_id_opaque" in OzonItemRecord.__table__.columns
    assert "return_id_opaque" in OzonReturnRecord.__table__.columns
    assert "cursor_opaque" in OzonSyncCursorRecord.__table__.columns
    assert "raw_evidence_sanitized" in OzonEventRecord.__table__.columns
    assert "evidence_redacted" in OzonReconciliationRecord.__table__.columns
    assert "semantics" in OzonPaidEvidenceRecord.__table__.columns


def test_migration_is_additive_head_0011_without_plaintext_secret_or_marking_columns() -> None:
    text = Path("migrations/versions/0011_m10_ozon.py").read_text(encoding="utf-8").lower()
    assert 'revision = "0011_m10_ozon"' in text
    assert 'down_revision = "0010_m9_wb"' in text
    for forbidden in (
        'column("api_key"', 'column("raw_api_key"', 'column("authorization"',
        'column("cis"', 'column("sgtin"', 'column("kiz"', 'column("plaintext"',
    ):
        assert forbidden not in text
    for table in (
        "ozon_connections", "ozon_postings", "ozon_items", "ozon_marking_bindings",
        "ozon_events", "ozon_returns", "ozon_sync_cursors", "ozon_reconciliation",
        "ozon_paid_evidence",
    ):
        assert f'"{table}"' in text


def test_source_has_no_executable_remote_surface_or_guessed_wire_contract() -> None:
    source = Path("src/wbcz/ozon_foundation.py").read_text(encoding="utf-8")
    forbidden = (
        "OzonRequest(", "GenericOzonClient", "execute(", "adapter.send(", "requests.",
        "httpx.", "RAW_OZON_URL", "RAW_OZON_HOST", "RAW_OZON_PATH", "RAW_OZON_METHOD",
        "RAW_OZON_HEADERS", "page_size", "has_next",
    )
    for marker in forbidden:
        assert marker not in source
    assert "request_contract: object | None = None" in source
    assert "response_contract: object | None = None" in source
    assert "pagination_contract: object | None = None" in source
    assert "endpoint_rate_limit: object | None = None" in source
