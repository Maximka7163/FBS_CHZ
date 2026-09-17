from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from wbcz.suz_foundation import (
    API_V3_MAX_CODES_SINGLE_GTIN_ORDER,
    EXACT_SERIAL_CHARSET,
    KM_VAULT_FORMAT_VERSION,
    LP_DEFAULT_PAYMENT_MODE,
    LP_MANUAL_APPLICATION_PAYMENT_ALLOWED,
    LP_MANUAL_APPLICATION_REPORT_ALLOWED,
    MAX_ACTIVE_ORDERS,
    MAX_GTINS_PER_ORDER,
    M8_CORE_SUZ_HTTP_LOCATION,
    PRODUCTION_SUZ_CORE_TRANSPORT_ENABLED,
    PRODUCTION_SUZ_WRITE_ENABLED,
    REPEAT_FULL_KM_FETCH_WINDOW_DAYS,
    SELF_MADE_CLIENT_SERIAL_LENGTH,
    STATIC_TOKEN_FALLBACK,
    SUZ_AUTH_CHALLENGE_SIGNATURE_MODE,
    SUZ_AUTH_TOKEN_LIFETIME_HOURS,
    SUZ_CORE_CAPABILITIES,
    SUZ_RPS_LIMIT,
    TOKEN_PERSISTENCE_POLICY,
    UNRETRIEVED_KM_WINDOW_DAYS,
    AmbiguousCreateLedger,
    DomainCisType,
    DynamicSuzToken,
    ErrorKnowledge,
    FetchRecovery,
    FetchRecoveryState,
    KmBlockEvidence,
    KmPayloadKind,
    KmRecoveryValue,
    KmVault,
    LocalM8State,
    M2ProductEvidence,
    M8WireContractNotEnabled,
    PACKAGE_ISSUANCE_CAPABILITIES,
    PaymentType,
    RawSuzStatus,
    ReleaseMethod,
    SerialNumberType,
    SubmissionState,
    SuzConnection,
    SuzContractError,
    SuzOrderDraft,
    SuzOrderItem,
    SuzRemoteIdentifiers,
    SuzSecurityError,
    SuzTokenSession,
    TokenLifecycleState,
    VaultBinding,
    classify_suz_error,
    normalized_order_request_sha256,
    parse_buffer_raw_status,
    parse_order_raw_status,
    preflight_m2_products,
    prepare_lp_manual_application_report,
    redact_sensitive_mapping,
    redact_text,
    require_suz_core_capability,
    serials_sha256,
    verify_repeat_recovery_payload,
)
from wbcz_web.models.suz import (
    SuzCodeBlockRecord,
    SuzConnectionRecord,
    SuzKmVaultRecord,
    SuzOrderItemRecord,
    SuzOrderRecord,
    SuzReconciliationEventRecord,
)


NOW = datetime(2026, 9, 18, 0, 0, tzinfo=timezone.utc)


def operator_item(gtin: str, quantity: int = 1, *, cis_type: DomainCisType = DomainCisType.UNIT) -> SuzOrderItem:
    return SuzOrderItem(gtin, quantity, SerialNumberType.OPERATOR, None, cis_type)


def draft(*items: SuzOrderItem, payment: PaymentType = PaymentType.EMISSION, release: ReleaseMethod = ReleaseMethod.REMAINS, producer: str | None = None) -> SuzOrderDraft:
    return SuzOrderDraft("lp", tuple(items), release, payment, producer=producer)


def test_connection_identifiers_are_opaque_and_preserve_exact_value() -> None:
    connection = SuzConnection(
        participant_inn="1234567890",
        oms_id="Oms/ID-AbC-001",
        oms_connection="Conn.MixedCase/001",
        environment="PRODUCTION_METADATA_ONLY",
        installation_name="Ufa Windows Agent",
    )
    assert connection.oms_id == "Oms/ID-AbC-001"
    assert connection.oms_connection == "Conn.MixedCase/001"
    with pytest.raises(SuzContractError):
        SuzConnection("123", "", "Conn", "TEST", "x")


def test_all_suz_remote_identifiers_are_opaque_and_exact() -> None:
    ids = SuzRemoteIdentifiers(
        remote_order_id="Order/Mixed-01",
        remote_block_id="Block/Mixed-02",
        remote_package_id="Package/Mixed-03",
        remote_report_id="Report/Mixed-04",
        oms_id="Oms/Mixed-05",
        oms_connection="Conn/Mixed-06",
    )
    assert ids.remote_order_id == "Order/Mixed-01"
    assert ids.remote_block_id == "Block/Mixed-02"
    assert ids.remote_package_id == "Package/Mixed-03"
    assert ids.remote_report_id == "Report/Mixed-04"
    with pytest.raises(SuzContractError):
        SuzRemoteIdentifiers(remote_report_id="")


def test_dynamic_token_is_10h_memory_only_and_redacted() -> None:
    token = DynamicSuzToken("clientToken-CANARY-SECRET", "Conn-A", NOW)
    assert SUZ_AUTH_TOKEN_LIFETIME_HOURS == 10
    assert TOKEN_PERSISTENCE_POLICY == "MEMORY_ONLY"
    assert not STATIC_TOKEN_FALLBACK
    assert token.expires_at == NOW + timedelta(hours=10)
    assert token.state_at(NOW + timedelta(hours=9, minutes=59)) is TokenLifecycleState.ACTIVE
    assert token.state_at(NOW + timedelta(hours=10)) is TokenLifecycleState.EXPIRED
    assert "clientToken-CANARY-SECRET" not in repr(token)
    assert "clientToken-CANARY-SECRET" not in str(token)
    assert "REDACTED" in repr(token)
    assert token.fingerprint == hashlib.sha256(b"clientToken-CANARY-SECRET").hexdigest()


def test_new_token_supersedes_previous_for_same_connection_only() -> None:
    session = SuzTokenSession()
    first = session.issue("first-secret", "Conn-A", NOW)
    other = session.issue("other-secret", "Conn-B", NOW)
    second = session.issue("second-secret", "Conn-A", NOW + timedelta(minutes=1))
    assert first.state_at(NOW + timedelta(minutes=2)) is TokenLifecycleState.SUPERSEDED
    assert second.state_at(NOW + timedelta(minutes=2)) is TokenLifecycleState.ACTIVE
    assert other.state_at(NOW + timedelta(minutes=2)) is TokenLifecycleState.ACTIVE
    second.invalidate()
    assert second.state_at(NOW + timedelta(minutes=3)) is TokenLifecycleState.INVALIDATED


def test_auth_signature_policy_reuses_attached_m3_boundary_only() -> None:
    assert SUZ_AUTH_CHALLENGE_SIGNATURE_MODE == "ATTACHED"
    assert M8_CORE_SUZ_HTTP_LOCATION == "UNRESOLVED"
    assert not PRODUCTION_SUZ_CORE_TRANSPORT_ENABLED
    assert not PRODUCTION_SUZ_WRITE_ENABLED


def test_lp_order_accepts_1_to_10_unique_gtins_and_rejects_11() -> None:
    one = draft(operator_item("gtin-1"))
    one.validate()
    ten = draft(*(operator_item(f"gtin-{i}") for i in range(10)))
    ten.validate()
    assert MAX_GTINS_PER_ORDER == 10
    with pytest.raises(SuzContractError):
        draft(*(operator_item(f"gtin-{i}") for i in range(11))).validate()


def test_lp_order_rejects_duplicate_gtin_and_nonpositive_quantity() -> None:
    with pytest.raises(SuzContractError):
        draft(operator_item("same"), operator_item("same")).validate()
    with pytest.raises(SuzContractError):
        draft(operator_item("x", 0)).validate()
    with pytest.raises(SuzContractError):
        draft(operator_item("x", True)).validate()


def test_single_gtin_2m_limit_does_not_become_multi_gtin_total_or_item_limit() -> None:
    draft(operator_item("single", API_V3_MAX_CODES_SINGLE_GTIN_ORDER)).validate()
    with pytest.raises(SuzContractError):
        draft(operator_item("single", API_V3_MAX_CODES_SINGLE_GTIN_ORDER + 1)).validate()
    draft(
        operator_item("a", API_V3_MAX_CODES_SINGLE_GTIN_ORDER + 1),
        operator_item("b", API_V3_MAX_CODES_SINGLE_GTIN_ORDER + 1),
    ).validate()
    assert MAX_ACTIVE_ORDERS == 100
    assert SUZ_RPS_LIMIT is None


def test_serial_mode_contract_and_unknown_charset_policy() -> None:
    with pytest.raises(SuzContractError):
        draft(SuzOrderItem("g", 1, SerialNumberType.OPERATOR, ("123456789012",))).validate()
    with pytest.raises(SuzContractError):
        draft(SuzOrderItem("g", 1, SerialNumberType.SELF_MADE, None)).validate()
    with pytest.raises(SuzContractError):
        draft(SuzOrderItem("g", 2, SerialNumberType.SELF_MADE, ("123456789012",))).validate()
    with pytest.raises(SuzContractError):
        draft(SuzOrderItem("g", 2, SerialNumberType.SELF_MADE, ("123456789012", "123456789012"))).validate()
    with pytest.raises(SuzContractError):
        draft(SuzOrderItem("g", 1, SerialNumberType.SELF_MADE, ("short",))).validate()
    arbitrary_12_chars = "ab!@#$%^&*12"
    assert len(arbitrary_12_chars) == SELF_MADE_CLIENT_SERIAL_LENGTH == 12
    draft(SuzOrderItem("g", 1, SerialNumberType.SELF_MADE, (arbitrary_12_chars,))).validate()
    assert EXACT_SERIAL_CHARSET == "UNKNOWN"


def test_serials_are_hashable_without_plaintext_persistence_requirement() -> None:
    serials = ("123456789012", "ABCDEFGHIJKL")
    digest = serials_sha256(serials)
    assert digest and len(digest) == 64
    assert digest != serials_sha256(("123456789012", "ABCDEFGHIJKM"))


def test_payment_and_manual_application_report_are_fail_closed_for_ordinary_lp() -> None:
    assert LP_DEFAULT_PAYMENT_MODE == "EMISSION"
    assert not LP_MANUAL_APPLICATION_PAYMENT_ALLOWED
    assert not LP_MANUAL_APPLICATION_REPORT_ALLOWED
    draft(operator_item("g"), payment=PaymentType.EMISSION).validate()
    with pytest.raises(SuzContractError):
        draft(operator_item("g"), payment=PaymentType.APPLICATION).validate()
    with pytest.raises(M8WireContractNotEnabled):
        prepare_lp_manual_application_report()


def test_release_method_domain_rules_do_not_invent_wire_mapping() -> None:
    draft(operator_item("g"), release=ReleaseMethod.REAPPLY, producer="Factory").validate()
    with pytest.raises(SuzContractError):
        draft(operator_item("g", cis_type=DomainCisType.KIK), release=ReleaseMethod.REAPPLY).validate()
    with pytest.raises(SuzContractError):
        draft(operator_item("g"), release=ReleaseMethod.CROSSBORDER, producer="Factory").validate()


def test_package_boundary_preserves_m6_and_blocks_ordinary_kitu_kigu_ordering() -> None:
    assert PACKAGE_ISSUANCE_CAPABILITIES[DomainCisType.UNIT] == "SUPPORTED_CORE_CODE_ISSUANCE_CONCEPT"
    assert PACKAGE_ISSUANCE_CAPABILITIES[DomainCisType.KIK] == "WIRE_VALUE_UNKNOWN"
    assert PACKAGE_ISSUANCE_CAPABILITIES[DomainCisType.KIN] == "WIRE_VALUE_UNKNOWN"
    for kind in (DomainCisType.KITU, DomainCisType.KIGU, DomainCisType.ATK):
        with pytest.raises(SuzContractError):
            draft(operator_item("g", cis_type=kind)).validate()


def test_order_hash_is_immutable_domain_evidence_not_wire_serialization() -> None:
    first = draft(operator_item("g", 2))
    second = draft(operator_item("g", 3))
    assert normalized_order_request_sha256(first) != normalized_order_request_sha256(second)
    assert len(normalized_order_request_sha256(first)) == 64


class FakeM2Adapter:
    def __init__(self, rows: dict[str, M2ProductEvidence]) -> None:
        self.rows = rows

    def lookup(self, gtin: str) -> M2ProductEvidence | None:
        return self.rows.get(gtin)


def test_m2_read_only_product_preflight_adapter() -> None:
    order = draft(operator_item("g1"), operator_item("g2"))
    ok = FakeM2Adapter({
        "g1": M2ProductEvidence("g1", True, "lp", True, {"source": "m2"}),
        "g2": M2ProductEvidence("g2", True, "lp", None, {"source": "m2"}),
    })
    assert len(preflight_m2_products(order, ok)) == 2
    with pytest.raises(SuzContractError):
        preflight_m2_products(order, FakeM2Adapter({"g1": M2ProductEvidence("g1", True, "lp")}))
    with pytest.raises(SuzContractError):
        preflight_m2_products(draft(operator_item("g1")), FakeM2Adapter({"g1": M2ProductEvidence("g1", True, "shoes")}))
    with pytest.raises(SuzContractError):
        preflight_m2_products(draft(operator_item("g1")), FakeM2Adapter({"g1": M2ProductEvidence("g1", True, "lp", False)}))


def test_all_core_capabilities_are_disabled_and_have_no_guessed_wire_metadata() -> None:
    assert SUZ_CORE_CAPABILITIES
    for capability in SUZ_CORE_CAPABILITIES.values():
        assert not capability.enabled
        assert capability.disabled_reason == "OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED"
        assert capability.method is None
        assert capability.path is None
        assert capability.base is None
        assert capability.request_contract is None
        assert capability.response_contract is None
        with pytest.raises(M8WireContractNotEnabled):
            require_suz_core_capability(capability.capability_name)


def test_known_and_unknown_raw_statuses_preserve_exact_string_without_terminal_aliases() -> None:
    assert parse_order_raw_status("CREATED") == RawSuzStatus("CREATED", True)
    assert parse_order_raw_status("PENDING") == RawSuzStatus("PENDING", True)
    assert parse_order_raw_status("APPROVED") == RawSuzStatus("APPROVED", True)
    assert parse_order_raw_status("CLOSED") == RawSuzStatus("CLOSED", True)
    assert parse_order_raw_status("Future.MixedCase") == RawSuzStatus("Future.MixedCase", False)
    assert parse_buffer_raw_status("ACTIVE") == RawSuzStatus("ACTIVE", True)
    assert parse_buffer_raw_status("PENDING") == RawSuzStatus("PENDING", True)
    assert parse_buffer_raw_status("EXHAUSTED") == RawSuzStatus("EXHAUSTED", True)
    unknown = parse_buffer_raw_status("Доступен")
    assert unknown.raw_value == "Доступен" and not unknown.known
    assert not hasattr(unknown, "terminal")


def test_error_registry_preserves_exact_family_and_unknown_without_retryability() -> None:
    exact_codes = (
        1090,1100,1110,1140,1150,1160,1170,1350,
        1010,1050,1055,1060,1065,1330,
        3030,3050,3100,3120,3150,3300,3320,3325,3340,3350,3770,3780,3820,3910,3920,3996,5010,5020,5050,
        3310,3360,3370,3390,3800,2200,3010,3810,3710,
    )
    for code in exact_codes:
        evidence = classify_suz_error(code)
        assert evidence.raw_code == str(code)
        assert evidence.knowledge is ErrorKnowledge.CONFIRMED_EXACT
        assert evidence.categories
        assert not hasattr(evidence, "retryable")
        assert not hasattr(evidence, "terminal")
    assert classify_suz_error(3360).categories == ("FETCH", "CLOSE")
    for code in (3160, 3180, 3220):
        evidence = classify_suz_error(code)
        assert evidence.knowledge is ErrorKnowledge.CONFIRMED_FAMILY_ONLY
        assert evidence.meaning is None
    unknown = classify_suz_error("future-code-X")
    assert unknown.raw_code == "future-code-X"
    assert unknown.knowledge is ErrorKnowledge.UNKNOWN_FUTURE


def test_local_reconciliation_states_are_project_states_and_ready_for_m5_is_only_handoff() -> None:
    assert LocalM8State.READY_FOR_M5.value == "READY_FOR_M5"
    assert LocalM8State.CODES_DURABLY_STORED.value == "CODES_DURABLY_STORED"
    assert LocalM8State.REMOTE_ORDER_CONFIRMED.value != LocalM8State.CODES_DURABLY_STORED.value


def test_ambiguous_create_never_allows_blind_replay() -> None:
    ledger = AmbiguousCreateLedger("op-1", "a" * 64)
    assert ledger.state is SubmissionState.NOT_SUBMITTED
    unknown = ledger.submission_unknown()
    assert unknown.state is SubmissionState.SUBMISSION_UNKNOWN
    assert not unknown.blind_replay_allowed
    lookup = unknown.require_remote_lookup()
    assert lookup.state is SubmissionState.REMOTE_LOOKUP_REQUIRED
    with pytest.raises(M8WireContractNotEnabled):
        require_suz_core_capability("GET_ORDER")


def test_ambiguous_fetch_cannot_advance_to_fresh_block_and_models_repeat_recovery_only() -> None:
    recovery = FetchRecovery(FetchRecoveryState.FETCH_IN_FLIGHT).network_ambiguous()
    assert recovery.state is FetchRecoveryState.FETCH_AMBIGUOUS
    with pytest.raises(SuzContractError):
        recovery.request_fresh_next_block()
    repeat = recovery.identify_historical_block("Block/MixedCase-01")
    assert repeat.state is FetchRecoveryState.REPEAT_RECOVERY_REQUIRED
    assert repeat.remote_block_id == "Block/MixedCase-01"
    with pytest.raises(M8WireContractNotEnabled):
        require_suz_core_capability("REPEAT_KM_BLOCK")
    assert recovery.unresolved().state is FetchRecoveryState.MANUAL_REVIEW


def test_repeat_recovery_requires_exact_hash_and_count_match_before_commit() -> None:
    raw = b"historical-exact-block"
    digest = hashlib.sha256(raw).hexdigest()
    assert verify_repeat_recovery_payload(
        expected_payload_sha256=digest, expected_code_count=3, exact_payload=raw, code_count=3
    )
    assert not verify_repeat_recovery_payload(
        expected_payload_sha256=digest, expected_code_count=3, exact_payload=raw + b"x", code_count=3
    )
    assert not verify_repeat_recovery_payload(
        expected_payload_sha256=digest, expected_code_count=3, exact_payload=raw, code_count=2
    )


def test_immutable_km_block_evidence_hashes_exact_bytes() -> None:
    raw = b"KM\x1dEXACT\x00PAYLOAD"
    changed = b"KM\x1dEXACT\x00PAYLOAd"
    first = KmBlockEvidence.from_exact_payload(
        order_id="Order-X", gtin="GTIN-X", remote_block_id="Block-X", code_count=1,
        exact_payload=raw, received_at=NOW, recovery_state=FetchRecoveryState.FETCH_RESPONSE_RECEIVED,
    )
    second = KmBlockEvidence.from_exact_payload(
        order_id="Order-X", gtin="GTIN-X", remote_block_id="Block-X", code_count=1,
        exact_payload=changed, received_at=NOW, recovery_state=FetchRecoveryState.FETCH_RESPONSE_RECEIVED,
    )
    assert first.exact_payload_sha256 == hashlib.sha256(raw).hexdigest()
    assert first.exact_payload_sha256 != second.exact_payload_sha256
    assert first.remote_block_id == "Block-X"


class TestKeyProvider:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def get_key(self, key_version: str) -> bytes:
        assert key_version == "test-key-v1"
        return self.key


def binding(**changes: str | None) -> VaultBinding:
    values = {
        "participant_inn": "1234567890",
        "oms_connection": "Conn-A",
        "order_local_id": "order-local-1",
        "gtin": "04600000000001",
        "remote_block_id": "block-A",
    }
    values.update(changes)
    return VaultBinding(**values)  # type: ignore[arg-type]


def test_km_vault_aes256_gcm_round_trip_and_key_version() -> None:
    raw = b"full-KM-canary\x1dwith-crypto-tail"
    vault = KmVault(TestKeyProvider(b"K" * 32), "test-key-v1")
    envelope = vault.encrypt(raw, binding=binding(), code_count=1)
    assert vault.decrypt(envelope, binding=binding()) == raw
    assert envelope.key_version == "test-key-v1"
    assert envelope.vault_format_version == KM_VAULT_FORMAT_VERSION
    assert envelope.plaintext_sha256 == hashlib.sha256(raw).hexdigest()
    assert raw not in envelope.ciphertext
    assert "full-KM-canary" not in repr(envelope)


def test_km_vault_wrong_aad_wrong_key_and_ciphertext_mutation_fail() -> None:
    raw = b"KM-SECRET-RAW"
    good = KmVault(TestKeyProvider(b"K" * 32), "test-key-v1")
    envelope = good.encrypt(raw, binding=binding(), code_count=1)
    with pytest.raises(SuzSecurityError):
        good.decrypt(envelope, binding=binding(gtin="different"))
    bad_key = KmVault(TestKeyProvider(b"Z" * 32), "test-key-v1")
    with pytest.raises(SuzSecurityError):
        bad_key.decrypt(envelope, binding=binding())
    mutated = replace(envelope, ciphertext=bytes([envelope.ciphertext[0] ^ 1]) + envelope.ciphertext[1:])
    with pytest.raises(SuzSecurityError):
        good.decrypt(mutated, binding=binding())


def test_ki_only_value_is_not_printable_as_datamatrix_and_no_reconstruction_exists() -> None:
    ki = KmRecoveryValue(KmPayloadKind.KI_ONLY, b"KI-only")
    full = KmRecoveryValue(KmPayloadKind.FULL_KM, b"full-km")
    assert not ki.printable_as_datamatrix
    assert full.printable_as_datamatrix
    assert not hasattr(ki, "reconstruct_full_km")


def test_remote_recovery_windows_are_metadata_not_destructive_local_retention() -> None:
    assert UNRETRIEVED_KM_WINDOW_DAYS == 90
    assert REPEAT_FULL_KM_FETCH_WINDOW_DAYS == 2


def test_redaction_removes_sensitive_canaries_from_structured_and_text_surfaces() -> None:
    secrets = {
        "clientToken": "TOKEN-CANARY",
        "registrationKey": "REGKEY-CANARY",
        "signature": "SIGNATURE-CANARY",
        "pin": "1234-CANARY",
        "private_key": "PRIVATE-KEY-CANARY",
        "full_km": "KM-CANARY",
        "safe": "kept",
    }
    redacted = redact_sensitive_mapping(secrets)
    rendered = repr(redacted)
    for canary in ("TOKEN-CANARY", "REGKEY-CANARY", "SIGNATURE-CANARY", "1234-CANARY", "PRIVATE-KEY-CANARY", "KM-CANARY"):
        assert canary not in rendered
    assert redacted["safe"] == "kept"
    text = "TOKEN-CANARY REGKEY-CANARY SIGNATURE-CANARY KM-CANARY"
    cleaned = redact_text(text, ["TOKEN-CANARY", "REGKEY-CANARY", "SIGNATURE-CANARY", "KM-CANARY"])
    assert "CANARY" not in cleaned


def test_persistence_models_have_no_plaintext_token_registration_key_or_km_columns() -> None:
    connection_columns = set(SuzConnectionRecord.__table__.columns.keys())
    assert "client_token" not in connection_columns
    assert "clientToken" not in connection_columns
    assert "registration_key" not in connection_columns
    assert "registrationKey" not in connection_columns
    assert "token" not in connection_columns
    assert {"token_issued_at", "token_expires_at", "last_auth_at", "token_fingerprint"} <= connection_columns

    vault_columns = set(SuzKmVaultRecord.__table__.columns.keys())
    assert "plaintext" not in vault_columns
    assert "full_km" not in vault_columns
    assert "raw_km" not in vault_columns
    assert {"ciphertext", "nonce", "auth_tag", "key_version", "aad_hash", "plaintext_sha256", "ciphertext_sha256"} <= vault_columns

    item_columns = set(SuzOrderItemRecord.__table__.columns.keys())
    assert "serial_numbers" not in item_columns
    assert {"serial_count", "serials_sha256"} <= item_columns
    assert "remote_order_id" in SuzOrderRecord.__table__.columns
    assert "remote_block_id" in SuzCodeBlockRecord.__table__.columns
    assert "details_redacted" in SuzReconciliationEventRecord.__table__.columns


def test_migration_is_additive_and_contains_no_secret_or_plaintext_km_column() -> None:
    text = Path("migrations/versions/0009_m8_suz.py").read_text(encoding="utf-8")
    assert 'down_revision = "0008_m7_edo_lite_foundation"' in text
    lowered = text.lower()
    for forbidden in ("clienttoken", "registrationkey", "registration_key", 'column("token"', "plaintext_km", "full_km", "raw_km"):
        assert forbidden not in lowered
    assert '"ciphertext"' in text and '"nonce"' in text and '"auth_tag"' in text


def test_no_generic_suz_transport_or_guessed_endpoint_is_present_in_foundation_source() -> None:
    text = Path("src/wbcz/suz_foundation.py").read_text(encoding="utf-8")
    forbidden = (
        "GENERIC_SUZ_HTTP", "RAW_SUZ_URL", "RAW_SUZ_METHOD", "RAW_SUZ_HEADERS",
        "ARBITRARY_SUZ_BODY", "SuzRequest(", "base_url", 'path="/api/', '"/orders"', '"/codes"',
    )
    for marker in forbidden:
        assert marker not in text
    assert "ARBITRARY_SIGNER" not in text


def test_no_m5_or_m6_automatic_mutation_is_introduced() -> None:
    source = Path("src/wbcz/suz_foundation.py").read_text(encoding="utf-8")
    assert "introduce_goods(" not in source
    assert "aggregation_document(" not in source
