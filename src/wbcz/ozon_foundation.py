from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


M10_WIRE_READY = False
PRODUCTION_OZON_WRITE_ENABLED = False
OZON_INN_AUTOBIND_ENABLED = False
OZON_API_CIS_AUTOBIND_ENABLED = False
MARK_VALUE_EXTRACTION_ENABLED = False
PAYMENT_CONFIRMATION_CONTRACT_PINNED = False
PAID_SOURCE_PINNED = False
PHYSICAL_SELLER_RETURN_CONTRACT_PINNED = False
AUTO_DISTANCE_READY_ENABLED = False
AUTO_REMOTE_SALE_RETURN_READY_ENABLED = False
TRUE_API_WRITE_FROM_M10 = False
FRONTEND_FREEZE_ACTIVE = True
API_KEY_LOGGING_ALLOWED = False
CIS_LOGGING_ALLOWED = False
GLOBAL_OZON_LIMIT_RPS = 50
OZON_ENDPOINT_RATE_PROFILES_PINNED = False
INVENTED_BURST_CAPACITY = False
OZON_MARKING_VAULT_FORMAT = "M10_OZON_AES256_GCM_V1"
OZON_PROD_HOST = "api-seller.ozon.ru"

CANONICAL_AUTH_HEADER_CLIENT_ID = "Client-Id"
CANONICAL_AUTH_HEADER_API_KEY = "Api-Key"
CANONICAL_JSON_CONTENT_TYPE = "application/json"


class OzonFoundationError(RuntimeError):
    pass


class OzonContractError(OzonFoundationError):
    pass


class OzonSecurityError(OzonFoundationError):
    pass


class OzonCapabilityDisabled(OzonFoundationError):
    def __init__(self, capability: "OzonCapabilityName", reason: str) -> None:
        self.capability = capability
        self.reason = reason
        super().__init__(f"Ozon capability {capability.value} is disabled: {reason}")


def _opaque(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OzonContractError(f"{field_name} must be a non-empty opaque string")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OzonContractError("timezone-aware datetime required")
    return value.astimezone(timezone.utc)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def stable_hash(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()
    return _sha(raw)


class OzonConnectionState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    LOCAL_CONFIGURED = "LOCAL_CONFIGURED"
    CONNECTION_BLOCKED = "CONNECTION_BLOCKED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class OzonConnection:
    participant_inn: str
    client_id: str
    api_key_secret_ref: str
    api_key_expires_at: datetime | None = None
    roles_metadata: tuple[str, ...] = ()
    capability_metadata: tuple[str, ...] = ()
    connection_state: OzonConnectionState = OzonConnectionState.UNVERIFIED
    last_verified_at: datetime | None = None

    def __post_init__(self) -> None:
        _opaque(self.participant_inn, "participant_inn")
        _opaque(self.client_id, "client_id")
        _opaque(self.api_key_secret_ref, "api_key_secret_ref")
        if self.api_key_expires_at is not None:
            _utc(self.api_key_expires_at)


class OzonSecretProvider(Protocol):
    def get_secret(self, secret_ref: str) -> str: ...


class OzonRuntimeApiKey:
    __slots__ = ("_secret", "client_id", "secret_ref", "expires_at")

    def __init__(
        self,
        secret: str,
        *,
        client_id: str,
        secret_ref: str,
        expires_at: datetime | None = None,
    ) -> None:
        self._secret = _opaque(secret, "Api-Key")
        self.client_id = _opaque(client_id, "client_id")
        self.secret_ref = _opaque(secret_ref, "secret_ref")
        self.expires_at = _utc(expires_at) if expires_at is not None else None

    def _secret_for_future_internal_transport_only(self) -> str:
        return self._secret

    def __repr__(self) -> str:
        return (
            "OzonRuntimeApiKey(secret=<REDACTED>, "
            f"client_id={self.client_id!r}, secret_ref={self.secret_ref!r}, expires_at={self.expires_at!r})"
        )

    __str__ = __repr__


def runtime_api_key(connection: OzonConnection, provider: OzonSecretProvider) -> OzonRuntimeApiKey:
    return OzonRuntimeApiKey(
        provider.get_secret(connection.api_key_secret_ref),
        client_id=connection.client_id,
        secret_ref=connection.api_key_secret_ref,
        expires_at=connection.api_key_expires_at,
    )


@dataclass(frozen=True, slots=True)
class OzonAuthHeaderPolicy:
    client_id_header: str = CANONICAL_AUTH_HEADER_CLIENT_ID
    api_key_header: str = CANONICAL_AUTH_HEADER_API_KEY
    content_type_header: str = "Content-Type"
    json_content_type: str = CANONICAL_JSON_CONTENT_TYPE
    caller_controlled_auth_headers: bool = False
    arbitrary_headers_supported: bool = False


OZON_AUTH_HEADER_POLICY = OzonAuthHeaderPolicy()


class OzonCapabilityName(str, Enum):
    FBS_LIST = "FBS_LIST"
    FBS_UNFULFILLED = "FBS_UNFULFILLED"
    FBS_GET = "FBS_GET"
    EXEMPLAR_STATUS = "EXEMPLAR_STATUS"
    RETURNS_LIST = "RETURNS_LIST"
    SELLER_INFO = "SELLER_INFO"
    ROLES = "ROLES"
    WAREHOUSE_LIST = "WAREHOUSE_LIST"


@dataclass(frozen=True, slots=True)
class OzonRemoteCapability:
    name: OzonCapabilityName
    host: str
    method: str
    path: str
    enabled: bool = False
    contract_pinned: bool = False
    rate_profile_pinned: bool = False
    request_contract: object | None = None
    response_contract: object | None = None
    pagination_contract: object | None = None
    endpoint_rate_limit: object | None = None
    disabled_reason: str = "OFFICIAL_CONTRACT_NOT_PINNED"

    def require_enabled(self) -> None:
        if (
            not self.enabled
            or not self.contract_pinned
            or not self.rate_profile_pinned
            or self.request_contract is None
            or self.response_contract is None
        ):
            raise OzonCapabilityDisabled(self.name, self.disabled_reason)
        raise OzonSecurityError("M10 safe foundation has no executable Ozon transport")


OZON_REMOTE_CAPABILITIES: Mapping[OzonCapabilityName, OzonRemoteCapability] = {
    OzonCapabilityName.FBS_LIST: OzonRemoteCapability(
        OzonCapabilityName.FBS_LIST, OZON_PROD_HOST, "POST", "/v4/posting/fbs/list"
    ),
    OzonCapabilityName.FBS_UNFULFILLED: OzonRemoteCapability(
        OzonCapabilityName.FBS_UNFULFILLED, OZON_PROD_HOST, "POST", "/v4/posting/fbs/unfulfilled/list"
    ),
    OzonCapabilityName.FBS_GET: OzonRemoteCapability(
        OzonCapabilityName.FBS_GET, OZON_PROD_HOST, "POST", "/v3/posting/fbs/get"
    ),
    OzonCapabilityName.EXEMPLAR_STATUS: OzonRemoteCapability(
        OzonCapabilityName.EXEMPLAR_STATUS, OZON_PROD_HOST, "POST", "/v5/fbs/posting/product/exemplar/status"
    ),
    OzonCapabilityName.RETURNS_LIST: OzonRemoteCapability(
        OzonCapabilityName.RETURNS_LIST, OZON_PROD_HOST, "POST", "/v1/returns/list"
    ),
    OzonCapabilityName.SELLER_INFO: OzonRemoteCapability(
        OzonCapabilityName.SELLER_INFO, OZON_PROD_HOST, "POST", "/v1/seller/info"
    ),
    OzonCapabilityName.ROLES: OzonRemoteCapability(
        OzonCapabilityName.ROLES, OZON_PROD_HOST, "POST", "/v1/roles"
    ),
    OzonCapabilityName.WAREHOUSE_LIST: OzonRemoteCapability(
        OzonCapabilityName.WAREHOUSE_LIST, OZON_PROD_HOST, "POST", "/v2/warehouse/list"
    ),
}

OZON_EXECUTABLE_REMOTE_CAPABILITIES = tuple(
    cap.name for cap in OZON_REMOTE_CAPABILITIES.values() if cap.enabled
)

DEPRECATED_OR_FORBIDDEN_REMOTE_PATHS = frozenset(
    {
        "/v3/posting/fbs/list",
        "/v3/posting/fbs/unfulfilled/list",
        "/v3/finance/transaction/list",
        "/v3/finance/transaction/totals",
        "/v6/fbs/posting/product/exemplar/create-or-get",
        "/v6/fbs/posting/product/exemplar/set",
        "/v5/fbs/posting/product/exemplar/validate",
        "/v1/fbs/posting/product/exemplar/update",
    }
)


def require_remote_capability(name: OzonCapabilityName) -> OzonRemoteCapability:
    capability = OZON_REMOTE_CAPABILITIES[name]
    capability.require_enabled()
    return capability


def assert_remote_path_allowed(path: str) -> None:
    if path in DEPRECATED_OR_FORBIDDEN_REMOTE_PATHS:
        raise OzonCapabilityDisabled(OzonCapabilityName.FBS_LIST, "DEPRECATED_OR_FORBIDDEN_REMOTE_PATH")
    raise OzonCapabilityDisabled(OzonCapabilityName.FBS_LIST, "RAW_REMOTE_PATH_EXECUTION_FORBIDDEN")


@dataclass(frozen=True, slots=True)
class OzonRateLimitDecision:
    allowed: bool
    retry_after_seconds: float


class OzonClientIdRateLimiter:
    """Schema-independent rolling one-second admission state. Not connected to remote execution."""

    def __init__(self) -> None:
        self._history: dict[str, deque[float]] = defaultdict(deque)

    def consume(self, *, client_id: str, now_monotonic: float) -> OzonRateLimitDecision:
        key = _opaque(client_id, "client_id")
        now = float(now_monotonic)
        history = self._history[key]
        threshold = now - 1.0
        while history and history[0] <= threshold:
            history.popleft()
        if len(history) >= GLOBAL_OZON_LIMIT_RPS:
            return OzonRateLimitDecision(False, max(0.0, 1.0 - (now - history[0])))
        history.append(now)
        return OzonRateLimitDecision(True, 0.0)


@dataclass(frozen=True, slots=True)
class OzonOpaqueIdentity:
    posting_number: str | None = None
    order_id: str | None = None
    product_id: str | None = None
    offer_id: str | None = None
    sku: str | None = None
    barcode: str | None = None
    warehouse_id: str | None = None
    delivery_method_id: str | None = None
    exemplar_id: str | None = None
    return_id: str | None = None
    report_id: str | None = None
    finance_id: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "posting_number", "order_id", "product_id", "offer_id", "sku", "barcode",
            "warehouse_id", "delivery_method_id", "exemplar_id", "return_id", "report_id", "finance_id",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _opaque(value, field_name)


def sku_equals_product_id_is_join_rule() -> bool:
    return False


def exemplar_id_equals_cis_is_join_rule() -> bool:
    return False


def posting_number_equals_order_id_is_join_rule() -> bool:
    return False


def cis_can_be_derived_from_product_identifiers() -> bool:
    return False


class OzonEvidenceConflictState(str, Enum):
    NONE = "NONE"
    CONFLICT = "CONFLICT"
    MULTIPLE_CANDIDATES = "MULTIPLE_CANDIDATES"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class OzonLocalEvidence:
    connection_id: int
    source_capability: OzonCapabilityName
    source_fingerprint: str
    observed_at: datetime
    identities: OzonOpaqueIdentity
    sanitized_raw_hash: str
    evidence_hash: str
    evidence_type: str
    conflict_state: OzonEvidenceConflictState = OzonEvidenceConflictState.NONE

    def __post_init__(self) -> None:
        if type(self.connection_id) is not int or self.connection_id <= 0:
            raise OzonContractError("connection_id invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.source_fingerprint):
            raise OzonContractError("source_fingerprint must be sha256 hex")
        if not re.fullmatch(r"[0-9a-f]{64}", self.sanitized_raw_hash):
            raise OzonContractError("sanitized_raw_hash must be sha256 hex")
        if not re.fullmatch(r"[0-9a-f]{64}", self.evidence_hash):
            raise OzonContractError("evidence_hash must be sha256 hex")
        _utc(self.observed_at)
        _opaque(self.evidence_type, "evidence_type")


_SENSITIVE_DIRECT_KEYS = frozenset(
    {
        "sgtin", "sgtins", "cis", "cises", "kiz", "kizes", "mark", "marks",
        "marking", "markings", "markingcode", "markingcodes", "fullmarking",
        "fullmarkings",
    }
)
_SENSITIVE_DISCRIMINATOR_FIELDS = frozenset({"key", "type", "name", "field", "kind"})
_SENSITIVE_ASSOCIATED_FIELDS = frozenset(
    {"value", "values", "data", "code", "codes", "mark", "marks", "sgtin", "sgtins", "cis", "cises", "kiz", "kizes"}
)
_SECRET_KEYS = frozenset(
    {"apikey", "api_key", "authorization", "secret", "rawsecret", "token", "accesstoken", "clientsecret", "privatekey", "pin", "signature"}
)


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _direct_sensitive_key(key: str) -> bool:
    compact = _compact(key)
    return (
        compact in {_compact(x) for x in _SENSITIVE_DIRECT_KEYS}
        or compact.startswith("sgtin")
        or compact.startswith("marking")
        or compact.startswith("cis")
        or compact.startswith("kiz")
    )


def _secret_key(key: str) -> bool:
    compact = _compact(key)
    normalized = {_compact(x) for x in _SECRET_KEYS}
    return (
        compact in normalized
        or compact.endswith("apikey")
        or compact.endswith("secret")
        or compact.endswith("token")
    )


def _mapping_has_marking_discriminator(value: Mapping[object, object]) -> bool:
    for raw_key, item in value.items():
        if _compact(str(raw_key)) in _SENSITIVE_DISCRIMINATOR_FIELDS and isinstance(item, str):
            if _direct_sensitive_key(item):
                return True
    return False


def sanitize_ozon_evidence(value: object, *, marking_context: bool = False) -> object:
    if isinstance(value, Mapping):
        discriminator_sensitive = marking_context or _mapping_has_marking_discriminator(value)
        out: dict[str, object] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            compact = _compact(key)
            if _secret_key(key) or _direct_sensitive_key(key):
                out[key] = "REDACTED"
            elif discriminator_sensitive and compact in {_compact(x) for x in _SENSITIVE_ASSOCIATED_FIELDS}:
                out[key] = "REDACTED"
            else:
                out[key] = sanitize_ozon_evidence(item, marking_context=discriminator_sensitive)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize_ozon_evidence(item, marking_context=marking_context) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class OzonSanitizedErrorEvidence:
    code: str | None
    message: str | None
    raw_sanitized: object

    def __repr__(self) -> str:
        return (
            f"OzonSanitizedErrorEvidence(code={self.code!r}, message={self.message!r}, "
            "raw_sanitized=<SANITIZED>)"
        )


def sanitize_ozon_error(payload: object) -> OzonSanitizedErrorEvidence:
    safe = sanitize_ozon_evidence(payload)
    mapping = safe if isinstance(safe, Mapping) else {}
    code = str(mapping["code"]) if mapping.get("code") is not None else None
    message = str(mapping["message"]) if mapping.get("message") is not None else None
    return OzonSanitizedErrorEvidence(code, message, safe)


class OzonMarkingKeyProvider(Protocol):
    def get_key(self, key_version: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class OzonMarkingBinding:
    connection_id: int
    source_capability: OzonCapabilityName
    posting_number: str | None
    item_ref: str | None
    exemplar_id: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self.connection_id) is not int or self.connection_id <= 0:
            raise OzonContractError("connection_id invalid")
        for field_name in ("posting_number", "item_ref", "exemplar_id"):
            value = getattr(self, field_name)
            if value is not None:
                _opaque(value, field_name)
        _utc(self.observed_at)


@dataclass(frozen=True, slots=True)
class OzonMarkingEnvelope:
    ciphertext: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    auth_tag: bytes = field(repr=False)
    key_version: str
    vault_format: str
    aad_hash: str
    plaintext_sha256: str
    ciphertext_sha256: str
    masked_value: str
    source_capability: OzonCapabilityName
    created_at: datetime

    def __repr__(self) -> str:
        return (
            "OzonMarkingEnvelope(value=<REDACTED>, "
            f"key_version={self.key_version!r}, plaintext_sha256={self.plaintext_sha256!r}, "
            f"ciphertext_sha256={self.ciphertext_sha256!r}, masked_value={self.masked_value!r})"
        )


def mask_marking(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


class OzonMarkingVault:
    def __init__(self, provider: OzonMarkingKeyProvider, key_version: str) -> None:
        self._provider = provider
        self._key_version = _opaque(key_version, "key_version")

    @staticmethod
    def _aad(binding: OzonMarkingBinding, plaintext_sha256: str) -> bytes:
        payload = {
            "connection_id": binding.connection_id,
            "source_capability": binding.source_capability.value,
            "posting_number": binding.posting_number,
            "item_ref": binding.item_ref,
            "exemplar_id": binding.exemplar_id,
            "plaintext_sha256": plaintext_sha256,
            "vault_format": OZON_MARKING_VAULT_FORMAT,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def encrypt(self, exact_value: str, *, binding: OzonMarkingBinding) -> OzonMarkingEnvelope:
        raw = _opaque(exact_value, "marking").encode()
        key = self._provider.get_key(self._key_version)
        if len(key) != 32:
            raise OzonSecurityError("AES-256 key required")
        plaintext_sha256 = _sha(raw)
        aad = self._aad(binding, plaintext_sha256)
        nonce = os.urandom(12)
        sealed = AESGCM(key).encrypt(nonce, raw, aad)
        ciphertext, auth_tag = sealed[:-16], sealed[-16:]
        return OzonMarkingEnvelope(
            ciphertext=ciphertext,
            nonce=nonce,
            auth_tag=auth_tag,
            key_version=self._key_version,
            vault_format=OZON_MARKING_VAULT_FORMAT,
            aad_hash=_sha(aad),
            plaintext_sha256=plaintext_sha256,
            ciphertext_sha256=_sha(ciphertext + auth_tag),
            masked_value=mask_marking(exact_value),
            source_capability=binding.source_capability,
            created_at=_utc(binding.observed_at),
        )

    def decrypt(self, envelope: OzonMarkingEnvelope, *, binding: OzonMarkingBinding) -> str:
        key = self._provider.get_key(envelope.key_version)
        if len(key) != 32:
            raise OzonSecurityError("AES-256 key required")
        if _sha(envelope.ciphertext + envelope.auth_tag) != envelope.ciphertext_sha256:
            raise OzonSecurityError("ciphertext fingerprint mismatch")
        aad = self._aad(binding, envelope.plaintext_sha256)
        if _sha(aad) != envelope.aad_hash:
            raise OzonSecurityError("AAD mismatch")
        try:
            raw = AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext + envelope.auth_tag, aad)
        except InvalidTag as exc:
            raise OzonSecurityError("marking authentication failed") from exc
        if _sha(raw) != envelope.plaintext_sha256:
            raise OzonSecurityError("plaintext fingerprint mismatch")
        return raw.decode()


def exact_marking_fingerprint(exact_value: str) -> str:
    return _sha(_opaque(exact_value, "marking").encode())


class OzonLocalReconciliationState(str, Enum):
    OZON_ORDER_DISCOVERED = "OZON_ORDER_DISCOVERED"
    OZON_CIS_MISSING = "OZON_CIS_MISSING"
    OZON_CIS_CAPTURED = "OZON_CIS_CAPTURED"
    OZON_CIS_VERIFIED = "OZON_CIS_VERIFIED"
    OZON_SALE_PENDING = "OZON_SALE_PENDING"
    OZON_DELIVERY_CONFIRMED = "OZON_DELIVERY_CONFIRMED"
    OZON_PAYMENT_PENDING = "OZON_PAYMENT_PENDING"
    OZON_SALE_CONFIRMED = "OZON_SALE_CONFIRMED"
    DISTANCE_PENDING = "DISTANCE_PENDING"
    DISTANCE_SUBMITTED = "DISTANCE_SUBMITTED"
    DISTANCE_RECONCILED = "DISTANCE_RECONCILED"
    OZON_RETURN_PENDING = "OZON_RETURN_PENDING"
    OZON_ITEM_RETURNED = "OZON_ITEM_RETURNED"
    REMOTE_RETURN_PENDING = "REMOTE_RETURN_PENDING"
    REMOTE_RETURN_RECONCILED = "REMOTE_RETURN_RECONCILED"
    CANCELLED_NO_ACTION = "CANCELLED_NO_ACTION"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class OzonSafetyDecision(str, Enum):
    WAIT_FOR_EVIDENCE = "WAIT_FOR_EVIDENCE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    NO_ACTION = "NO_ACTION"


@dataclass(frozen=True, slots=True)
class OzonPaidEvidence:
    source: str
    raw_amount: object
    currency: str | None
    scale: int | None
    semantics: str
    confidence_state: str
    observed_at: datetime

    def __post_init__(self) -> None:
        _opaque(self.source, "source")
        _opaque(self.semantics, "semantics")
        _opaque(self.confidence_state, "confidence_state")
        _utc(self.observed_at)


def evaluate_distance_safety(
    *,
    payment_evidence_present: bool,
    delivery_like_evidence_present: bool,
    paid_amount_candidate_present: bool,
    identity_conflict: bool = False,
    aggregate_ambiguous: bool = False,
) -> OzonSafetyDecision:
    if identity_conflict or aggregate_ambiguous:
        return OzonSafetyDecision.MANUAL_REVIEW
    if payment_evidence_present or delivery_like_evidence_present or paid_amount_candidate_present:
        return OzonSafetyDecision.WAIT_FOR_EVIDENCE
    return OzonSafetyDecision.WAIT_FOR_EVIDENCE


def evaluate_remote_sale_return_safety(
    *,
    return_or_refund_evidence_present: bool,
    physical_seller_return_evidence_present: bool,
    identity_conflict: bool = False,
    aggregate_ambiguous: bool = False,
) -> OzonSafetyDecision:
    if identity_conflict or aggregate_ambiguous:
        return OzonSafetyDecision.MANUAL_REVIEW
    if return_or_refund_evidence_present or physical_seller_return_evidence_present:
        return OzonSafetyDecision.WAIT_FOR_EVIDENCE
    return OzonSafetyDecision.WAIT_FOR_EVIDENCE


@dataclass(frozen=True, slots=True)
class OzonSyncCheckpoint:
    connection_id: int
    feed: str
    cycle_id: str | None = None
    cursor_opaque: str | None = None
    offset_opaque: str | None = None
    window_start_raw: str | None = None
    window_end_raw: str | None = None
    snapshot_opaque: str | None = None
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None
    last_error_redacted: str | None = None
    generation: int = 0

    def __post_init__(self) -> None:
        if type(self.connection_id) is not int or self.connection_id <= 0:
            raise OzonContractError("connection_id invalid")
        _opaque(self.feed, "feed")
        for field_name in (
            "cycle_id", "cursor_opaque", "offset_opaque", "window_start_raw",
            "window_end_raw", "snapshot_opaque",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _opaque(value, field_name)
        if type(self.generation) is not int or self.generation < 0:
            raise OzonContractError("generation invalid")
        if self.last_success_at is not None:
            _utc(self.last_success_at)
        if self.last_attempt_at is not None:
            _utc(self.last_attempt_at)


class M1PreflightAdapter(Protocol):
    def inspect_current_cis_state(self, marking_fingerprint: str) -> object: ...


class M2ProductEvidenceAdapter(Protocol):
    def inspect_product_evidence(self, *, product_id: str | None, offer_id: str | None, sku: str | None) -> object: ...


class M4ReconciliationReferenceAdapter(Protocol):
    def lookup_operation_reference(self, *, operation: str, evidence_fingerprint: str) -> object: ...


class M6AggregateAdapter(Protocol):
    def inspect_aggregate_relation(self, marking_fingerprint: str) -> object: ...


class M5LocalOperation(str, Enum):
    DISTANCE = "DISTANCE"
    REMOTE_SALE_RETURN = "REMOTE_SALE_RETURN"


@dataclass(frozen=True, slots=True)
class M5TypedLocalDecisionReference:
    operation: M5LocalOperation
    connection_id: int
    posting_number: str
    marking_fingerprint: str
    evidence_fingerprint: str
    manually_authorized: bool = False

    def __post_init__(self) -> None:
        if type(self.connection_id) is not int or self.connection_id <= 0:
            raise OzonContractError("connection_id invalid")
        _opaque(self.posting_number, "posting_number")
        for field_name in ("marking_fingerprint", "evidence_fingerprint"):
            value = getattr(self, field_name)
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise OzonContractError(f"{field_name} must be sha256 hex")


class M5TypedDecisionAdapter(Protocol):
    def accept_local_reference(self, reference: M5TypedLocalDecisionReference) -> object: ...


def automatic_m5_reference_from_ozon_evidence(*_: object, **__: object) -> M5TypedLocalDecisionReference:
    raise OzonSecurityError("automatic M5 decisions from Ozon evidence are disabled")
