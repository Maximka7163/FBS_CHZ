from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from typing import Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


M8_RESEARCH_ID = "M8-SUZ-RESEARCH-001"
PRODUCTION_SUZ_CORE_TRANSPORT_ENABLED = False
PRODUCTION_SUZ_WRITE_ENABLED = False
M8_CORE_SUZ_HTTP_LOCATION = "UNRESOLVED"
SUZ_AUTH_CHALLENGE_SIGNATURE_MODE = "ATTACHED"
SUZ_AUTH_TOKEN_LIFETIME_HOURS = 10
TOKEN_PERSISTENCE_POLICY = "MEMORY_ONLY"
STATIC_TOKEN_FALLBACK = False

MAX_GTINS_PER_ORDER = 10
API_V3_MAX_CODES_SINGLE_GTIN_ORDER = 2_000_000
MAX_ACTIVE_ORDERS = 100
SUZ_RPS_LIMIT: int | None = None

LP_DEFAULT_PAYMENT_MODE = "EMISSION"
LP_MANUAL_APPLICATION_PAYMENT_ALLOWED = False
LP_MANUAL_APPLICATION_REPORT_ALLOWED = False
SELF_MADE_CLIENT_SERIAL_LENGTH = 12
EXACT_SERIAL_CHARSET = "UNKNOWN"

UNRETRIEVED_KM_WINDOW_DAYS = 90
REPEAT_FULL_KM_FETCH_WINDOW_DAYS = 2
LOCAL_VAULT_RETENTION_POLICY = "PROJECT_POLICY_NOT_FINALIZED"
KM_VAULT_FORMAT_VERSION = "M8_AES256_GCM_V1"
NO_FULL_KM_LOGGING = True
NO_KM_IN_ERROR_MESSAGES = True
NO_KM_IN_TELEMETRY = True
MASK_KM_BY_DEFAULT = True


class SuzFoundationError(RuntimeError):
    pass


class SuzContractError(SuzFoundationError):
    pass


class SuzSecurityError(SuzFoundationError):
    pass


class M8WireContractNotEnabled(SuzFoundationError):
    pass


def _opaque(value: str, field: str) -> str:
    if not isinstance(value, str) or value == "" or not value.strip():
        raise SuzContractError(f"{field} must be a non-empty opaque string")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SuzContractError("timezone-aware datetime required")
    return value.astimezone(timezone.utc)


def sha256_hex(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise SuzContractError("exact bytes are required")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class SuzConnection:
    participant_inn: str
    oms_id: str
    oms_connection: str
    environment: str
    installation_name: str
    token_issued_at: datetime | None = None
    token_expires_at: datetime | None = None
    last_auth_at: datetime | None = None
    connection_state: str = "NOT_ACQUIRED"

    def __post_init__(self) -> None:
        _opaque(self.participant_inn, "participant_inn")
        _opaque(self.oms_id, "oms_id")
        _opaque(self.oms_connection, "oms_connection")
        _opaque(self.environment, "environment")
        _opaque(self.installation_name, "installation_name")


@dataclass(frozen=True, slots=True)
class SuzRemoteIdentifiers:
    remote_order_id: str | None = None
    remote_block_id: str | None = None
    remote_package_id: str | None = None
    remote_report_id: str | None = None
    oms_id: str | None = None
    oms_connection: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "remote_order_id", "remote_block_id", "remote_package_id",
            "remote_report_id", "oms_id", "oms_connection",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _opaque(value, field_name)


class TokenLifecycleState(str, Enum):
    NOT_ACQUIRED = "NOT_ACQUIRED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"
    INVALIDATED = "INVALIDATED"


class DynamicSuzToken:
    __slots__ = ("_token", "oms_connection", "issued_at", "expires_at", "_superseded", "_invalidated")

    def __init__(self, token: str, oms_connection: str, issued_at: datetime) -> None:
        self._token = _opaque(token, "dynamic SUZ token")
        self.oms_connection = _opaque(oms_connection, "oms_connection")
        self.issued_at = _utc(issued_at)
        self.expires_at = self.issued_at + timedelta(hours=SUZ_AUTH_TOKEN_LIFETIME_HOURS)
        self._superseded = False
        self._invalidated = False

    @property
    def token(self) -> str:
        return self._token

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self._token.encode("utf-8")).hexdigest()

    def state_at(self, now: datetime) -> TokenLifecycleState:
        current = _utc(now)
        if self._invalidated:
            return TokenLifecycleState.INVALIDATED
        if self._superseded:
            return TokenLifecycleState.SUPERSEDED
        if current >= self.expires_at:
            return TokenLifecycleState.EXPIRED
        return TokenLifecycleState.ACTIVE

    def invalidate(self) -> None:
        self._invalidated = True

    def _supersede(self) -> None:
        self._superseded = True

    def __repr__(self) -> str:
        return (
            "DynamicSuzToken(token=<REDACTED>, "
            f"oms_connection={self.oms_connection!r}, issued_at={self.issued_at.isoformat()!r}, "
            f"expires_at={self.expires_at.isoformat()!r})"
        )

    __str__ = __repr__


class SuzTokenSession:
    def __init__(self) -> None:
        self._active: dict[str, DynamicSuzToken] = {}

    def issue(self, token: str, oms_connection: str, issued_at: datetime) -> DynamicSuzToken:
        connection = _opaque(oms_connection, "oms_connection")
        previous = self._active.get(connection)
        if previous is not None:
            previous._supersede()
        current = DynamicSuzToken(token, connection, issued_at)
        self._active[connection] = current
        return current

    def current(self, oms_connection: str) -> DynamicSuzToken | None:
        return self._active.get(_opaque(oms_connection, "oms_connection"))


class SerialNumberType(str, Enum):
    OPERATOR = "OPERATOR"
    SELF_MADE = "SELF_MADE"


class PaymentType(IntEnum):
    EMISSION = 1
    APPLICATION = 2


class ReleaseMethod(str, Enum):
    REMAINS = "REMAINS"
    REMARK = "REMARK"
    REAPPLY = "REAPPLY"
    CROSSBORDER = "CROSSBORDER"


class DomainCisType(str, Enum):
    UNIT = "UNIT"
    KIK = "KIK"
    KIN = "KIN"
    KITU = "KITU"
    KIGU = "KIGU"
    ATK = "ATK"


WIRE_VALUE_UNKNOWN = "WIRE_VALUE_UNKNOWN"
PACKAGE_ISSUANCE_CAPABILITIES: Mapping[DomainCisType, str] = {
    DomainCisType.UNIT: "SUPPORTED_CORE_CODE_ISSUANCE_CONCEPT",
    DomainCisType.KIK: WIRE_VALUE_UNKNOWN,
    DomainCisType.KIN: WIRE_VALUE_UNKNOWN,
    DomainCisType.KITU: "NOT_ORDINARY_LP_SUZ_ORDER_CAPABILITY",
    DomainCisType.KIGU: "NOT_ORDINARY_LP_SUZ_ORDER_CAPABILITY",
    DomainCisType.ATK: "NOT_ORDINARY_M8_ISSUANCE",
}


@dataclass(frozen=True, slots=True)
class SuzOrderItem:
    gtin: str
    quantity: int
    serial_number_type: SerialNumberType
    serial_numbers: tuple[str, ...] | None = None
    cis_type: DomainCisType = DomainCisType.UNIT
    raw_template_id: str | None = None

    def validate(self, *, product_group: str) -> None:
        _opaque(self.gtin, "gtin")
        if type(self.quantity) is not int or self.quantity <= 0:
            raise SuzContractError("quantity must be a positive integer")
        if self.serial_number_type is SerialNumberType.OPERATOR:
            if self.serial_numbers is not None:
                raise SuzContractError("OPERATOR serial mode requires serial_numbers to be absent")
        elif self.serial_number_type is SerialNumberType.SELF_MADE:
            if self.serial_numbers is None:
                raise SuzContractError("SELF_MADE serial mode requires serial_numbers")
            if len(self.serial_numbers) != self.quantity:
                raise SuzContractError("SELF_MADE serial count must equal quantity")
            if len(set(self.serial_numbers)) != len(self.serial_numbers):
                raise SuzContractError("duplicate SELF_MADE serials are not allowed")
            if product_group == "lp":
                for serial in self.serial_numbers:
                    if not isinstance(serial, str) or len(serial) != SELF_MADE_CLIENT_SERIAL_LENGTH:
                        raise SuzContractError("lp SELF_MADE client serial fragment must be exactly 12 characters")
        else:  # pragma: no cover - enum constrains normal construction
            raise SuzContractError("unsupported serial mode")


@dataclass(frozen=True, slots=True)
class SuzOrderDraft:
    product_group: str
    items: tuple[SuzOrderItem, ...]
    release_method: ReleaseMethod
    payment_type: PaymentType = PaymentType.EMISSION
    raw_create_method_type: str | None = None
    service_provider_id: str | None = None
    producer: str | None = None

    def validate(self) -> None:
        if self.product_group != "lp":
            raise SuzContractError("M8 foundation supports product_group=lp only")
        if not 1 <= len(self.items) <= MAX_GTINS_PER_ORDER:
            raise SuzContractError(f"order must contain 1..{MAX_GTINS_PER_ORDER} GTIN positions")
        seen_gtins: set[str] = set()
        for item in self.items:
            item.validate(product_group=self.product_group)
            if item.gtin in seen_gtins:
                raise SuzContractError("duplicate GTIN positions are not allowed")
            seen_gtins.add(item.gtin)
            if item.cis_type in {DomainCisType.KITU, DomainCisType.KIGU, DomainCisType.ATK}:
                raise SuzContractError("requested package type is not an ordinary lp SUZ ordering capability")
        if len(self.items) == 1 and self.items[0].quantity > API_V3_MAX_CODES_SINGLE_GTIN_ORDER:
            raise SuzContractError("single-GTIN order exceeds confirmed 2,000,000-code limit")
        if self.payment_type is PaymentType.APPLICATION and not LP_MANUAL_APPLICATION_PAYMENT_ALLOWED:
            raise SuzContractError("ordinary lp payment-by-application is not allowed")
        if self.release_method is ReleaseMethod.REAPPLY:
            if any(item.cis_type is not DomainCisType.UNIT for item in self.items):
                raise SuzContractError("REAPPLY requires UNIT cis type")
        if self.producer is not None and self.release_method not in {
            ReleaseMethod.REMAINS,
            ReleaseMethod.REMARK,
            ReleaseMethod.REAPPLY,
        }:
            raise SuzContractError("producer is not allowed for this release method")


def normalized_order_request_sha256(draft: SuzOrderDraft) -> str:
    draft.validate()
    payload = {
        "product_group": draft.product_group,
        "release_method": draft.release_method.value,
        "payment_type": int(draft.payment_type),
        "raw_create_method_type": draft.raw_create_method_type,
        "service_provider_id": draft.service_provider_id,
        "producer": draft.producer,
        "items": [
            {
                "gtin": item.gtin,
                "quantity": item.quantity,
                "serial_number_type": item.serial_number_type.value,
                "serial_numbers": list(item.serial_numbers) if item.serial_numbers is not None else None,
                "cis_type": item.cis_type.value,
                "raw_template_id": item.raw_template_id,
            }
            for item in draft.items
        ],
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def serials_sha256(serials: Sequence[str] | None) -> str | None:
    if serials is None:
        return None
    raw = json.dumps(list(serials), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class M2ProductEvidence:
    gtin: str
    exists: bool
    product_group: str | None
    card_ready: bool | None = None
    readiness_evidence: Mapping[str, object] | None = None


class M2ProductEvidenceAdapter(Protocol):
    def lookup(self, gtin: str) -> M2ProductEvidence | None: ...


def preflight_m2_products(draft: SuzOrderDraft, adapter: M2ProductEvidenceAdapter) -> tuple[M2ProductEvidence, ...]:
    draft.validate()
    evidence: list[M2ProductEvidence] = []
    for item in draft.items:
        found = adapter.lookup(item.gtin)
        if found is None or not found.exists:
            raise SuzContractError("missing M2 product evidence")
        if found.gtin != item.gtin:
            raise SuzContractError("M2 product evidence GTIN mismatch")
        if found.product_group != "lp":
            raise SuzContractError("M2 product evidence is not lp")
        if found.card_ready is False:
            raise SuzContractError("M2 product/card readiness evidence rejects order")
        evidence.append(found)
    return tuple(evidence)


def prepare_lp_manual_application_report() -> None:
    raise M8WireContractNotEnabled("M8_WIRE_CONTRACT_NOT_ENABLED:LP_MANUAL_APPLICATION_REPORT_DISABLED")


@dataclass(frozen=True, slots=True)
class SuzCoreCapability:
    capability_name: str
    enabled: bool = False
    disabled_reason: str = "OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED"
    method: str | None = None
    path: str | None = None
    base: str | None = None
    request_contract: str | None = None
    response_contract: str | None = None


_CORE_CAPABILITY_NAMES = (
    "CREATE_ORDER",
    "GET_ORDER",
    "GET_ORDER_STATUS",
    "GET_BUFFER_STATUS",
    "FETCH_KM",
    "LIST_KM_BLOCKS",
    "REPEAT_KM_BLOCK",
    "CLOSE_ORDER",
    "CANCEL_ORDER",
    "REJECT_KM",
    "APPLICATION_REPORT",
    "REPORT_STATUS",
    "SUZ_HEALTH",
)
SUZ_CORE_CAPABILITIES: Mapping[str, SuzCoreCapability] = {
    name: SuzCoreCapability(name) for name in _CORE_CAPABILITY_NAMES
}


def require_suz_core_capability(name: str) -> SuzCoreCapability:
    capability = SUZ_CORE_CAPABILITIES.get(name)
    if capability is None or not capability.enabled:
        raise M8WireContractNotEnabled("M8_WIRE_CONTRACT_NOT_ENABLED")
    return capability


KNOWN_ORDER_RAW_STATUSES = frozenset({"CREATED", "PENDING", "APPROVED", "CLOSED"})
KNOWN_BUFFER_RAW_STATUSES = frozenset({"ACTIVE", "PENDING", "EXHAUSTED"})


@dataclass(frozen=True, slots=True)
class RawSuzStatus:
    raw_value: str
    known: bool


def parse_order_raw_status(value: str) -> RawSuzStatus:
    raw = _opaque(value, "raw order status")
    return RawSuzStatus(raw, raw in KNOWN_ORDER_RAW_STATUSES)


def parse_buffer_raw_status(value: str) -> RawSuzStatus:
    raw = _opaque(value, "raw buffer status")
    return RawSuzStatus(raw, raw in KNOWN_BUFFER_RAW_STATUSES)


class ErrorKnowledge(str, Enum):
    CONFIRMED_EXACT = "CONFIRMED_EXACT"
    CONFIRMED_FAMILY_ONLY = "CONFIRMED_FAMILY_ONLY"
    UNKNOWN_FUTURE = "UNKNOWN_FUTURE"


@dataclass(frozen=True, slots=True)
class SuzErrorEvidence:
    raw_code: str
    categories: tuple[str, ...]
    knowledge: ErrorKnowledge
    meaning: str | None = None


SUZ_ERROR_REGISTRY: Mapping[str, tuple[str, ...]] = {
    **{code: ("AUTH",) for code in ("1090", "1100", "1110", "1140", "1150", "1160", "1170", "1350")},
    **{code: ("SIGNATURE",) for code in ("1010", "1050", "1055", "1060", "1065", "1330")},
    **{code: ("ORDER",) for code in ("3030", "3050", "3100", "3120", "3150", "3300", "3320", "3325", "3340", "3350", "3770", "3780", "3820", "3910", "3920", "3996", "5010", "5020", "5050")},
    **{code: ("FETCH",) for code in ("3310", "3370", "3390", "3800")},
    "3360": ("FETCH", "CLOSE"),
    **{code: ("CLOSE",) for code in ("2200", "3010", "3810")},
    "3710": ("REPEAT_FETCH",),
}


def classify_suz_error(raw_code: str | int) -> SuzErrorEvidence:
    code = str(raw_code)
    if code in SUZ_ERROR_REGISTRY:
        return SuzErrorEvidence(code, SUZ_ERROR_REGISTRY[code], ErrorKnowledge.CONFIRMED_EXACT)
    try:
        number = int(code)
    except ValueError:
        number = -1
    if 3160 <= number <= 3220:
        return SuzErrorEvidence(code, ("SERIAL_ERROR_FAMILY",), ErrorKnowledge.CONFIRMED_FAMILY_ONLY)
    return SuzErrorEvidence(code, (), ErrorKnowledge.UNKNOWN_FUTURE)


class LocalM8State(str, Enum):
    LOCAL_ORDER_PREPARED = "LOCAL_ORDER_PREPARED"
    LOCAL_ORDER_SIGNED = "LOCAL_ORDER_SIGNED"
    ORDER_SUBMISSION_UNKNOWN = "ORDER_SUBMISSION_UNKNOWN"
    REMOTE_ORDER_CONFIRMED = "REMOTE_ORDER_CONFIRMED"
    ORDER_PROCESSING = "ORDER_PROCESSING"
    CODES_AVAILABLE = "CODES_AVAILABLE"
    FETCH_IN_PROGRESS = "FETCH_IN_PROGRESS"
    FETCH_AMBIGUOUS = "FETCH_AMBIGUOUS"
    BLOCK_FETCHED_NOT_COMMITTED = "BLOCK_FETCHED_NOT_COMMITTED"
    CODES_DURABLY_STORED = "CODES_DURABLY_STORED"
    AUTO_APPLICATION_PENDING = "AUTO_APPLICATION_PENDING"
    AUTO_APPLICATION_RECONCILED = "AUTO_APPLICATION_RECONCILED"
    ORDER_CLOSED = "ORDER_CLOSED"
    READY_FOR_M5 = "READY_FOR_M5"
    ORDER_REJECTED = "ORDER_REJECTED"
    ORDER_CANCELLED = "ORDER_CANCELLED"
    REPORT_ERROR = "REPORT_ERROR"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class SubmissionState(str, Enum):
    NOT_SUBMITTED = "NOT_SUBMITTED"
    SUBMISSION_UNKNOWN = "SUBMISSION_UNKNOWN"
    REMOTE_LOOKUP_REQUIRED = "REMOTE_LOOKUP_REQUIRED"
    REMOTE_CONFIRMED = "REMOTE_CONFIRMED"
    CONFLICT = "CONFLICT"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class AmbiguousCreateLedger:
    operation_id: str
    request_sha256: str
    state: SubmissionState = SubmissionState.NOT_SUBMITTED

    def __post_init__(self) -> None:
        _opaque(self.operation_id, "operation_id")
        if len(self.request_sha256) != 64:
            raise SuzContractError("request_sha256 must be a SHA-256 hex digest")

    def submission_unknown(self) -> "AmbiguousCreateLedger":
        return AmbiguousCreateLedger(self.operation_id, self.request_sha256, SubmissionState.SUBMISSION_UNKNOWN)

    def require_remote_lookup(self) -> "AmbiguousCreateLedger":
        if self.state is not SubmissionState.SUBMISSION_UNKNOWN:
            raise SuzContractError("remote lookup is only required after ambiguous submission")
        return AmbiguousCreateLedger(self.operation_id, self.request_sha256, SubmissionState.REMOTE_LOOKUP_REQUIRED)

    @property
    def blind_replay_allowed(self) -> bool:
        return False


class FetchRecoveryState(str, Enum):
    FETCH_REQUEST_PREPARED = "FETCH_REQUEST_PREPARED"
    FETCH_IN_FLIGHT = "FETCH_IN_FLIGHT"
    FETCH_RESPONSE_RECEIVED = "FETCH_RESPONSE_RECEIVED"
    BLOCK_IDENTIFIED = "BLOCK_IDENTIFIED"
    BLOCK_ENCRYPTING = "BLOCK_ENCRYPTING"
    BLOCK_DURABLY_STORED = "BLOCK_DURABLY_STORED"
    FETCH_AMBIGUOUS = "FETCH_AMBIGUOUS"
    REPEAT_RECOVERY_REQUIRED = "REPEAT_RECOVERY_REQUIRED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass(frozen=True, slots=True)
class FetchRecovery:
    state: FetchRecoveryState
    remote_block_id: str | None = None

    def network_ambiguous(self) -> "FetchRecovery":
        return FetchRecovery(FetchRecoveryState.FETCH_AMBIGUOUS)

    def request_fresh_next_block(self) -> "FetchRecovery":
        if self.state is FetchRecoveryState.FETCH_AMBIGUOUS:
            raise SuzContractError("fresh next-block fetch is forbidden after FETCH_AMBIGUOUS")
        return FetchRecovery(FetchRecoveryState.FETCH_REQUEST_PREPARED)

    def identify_historical_block(self, remote_block_id: str) -> "FetchRecovery":
        if self.state is not FetchRecoveryState.FETCH_AMBIGUOUS:
            raise SuzContractError("historical block recovery requires FETCH_AMBIGUOUS")
        return FetchRecovery(FetchRecoveryState.REPEAT_RECOVERY_REQUIRED, _opaque(remote_block_id, "remote_block_id"))

    def unresolved(self) -> "FetchRecovery":
        return FetchRecovery(FetchRecoveryState.MANUAL_REVIEW)


def verify_repeat_recovery_payload(
    *,
    expected_payload_sha256: str,
    expected_code_count: int,
    exact_payload: bytes,
    code_count: int,
) -> bool:
    if len(expected_payload_sha256) != 64:
        raise SuzContractError("expected_payload_sha256 must be a SHA-256 hex digest")
    if type(expected_code_count) is not int or expected_code_count < 0:
        raise SuzContractError("expected_code_count must be non-negative")
    if type(code_count) is not int or code_count < 0:
        raise SuzContractError("code_count must be non-negative")
    return code_count == expected_code_count and sha256_hex(exact_payload) == expected_payload_sha256


class KmPayloadKind(str, Enum):
    FULL_KM = "FULL_KM"
    KI_ONLY = "KI_ONLY"


@dataclass(frozen=True, slots=True)
class KmRecoveryValue:
    kind: KmPayloadKind
    exact_bytes: bytes

    @property
    def printable_as_datamatrix(self) -> bool:
        return self.kind is KmPayloadKind.FULL_KM


@dataclass(frozen=True, slots=True)
class KmBlockEvidence:
    order_id: str
    gtin: str
    remote_block_id: str | None
    code_count: int
    exact_payload_sha256: str
    ciphertext_sha256: str | None
    received_at: datetime
    recovery_state: FetchRecoveryState

    @classmethod
    def from_exact_payload(
        cls,
        *,
        order_id: str,
        gtin: str,
        remote_block_id: str | None,
        code_count: int,
        exact_payload: bytes,
        received_at: datetime,
        recovery_state: FetchRecoveryState,
        ciphertext_sha256: str | None = None,
    ) -> "KmBlockEvidence":
        if type(code_count) is not int or code_count < 0:
            raise SuzContractError("code_count must be a non-negative integer")
        return cls(
            _opaque(order_id, "order_id"),
            _opaque(gtin, "gtin"),
            _opaque(remote_block_id, "remote_block_id") if remote_block_id is not None else None,
            code_count,
            sha256_hex(exact_payload),
            ciphertext_sha256,
            _utc(received_at),
            recovery_state,
        )


@dataclass(frozen=True, slots=True)
class VaultBinding:
    participant_inn: str
    oms_connection: str
    order_local_id: str
    gtin: str
    remote_block_id: str | None
    vault_format_version: str = KM_VAULT_FORMAT_VERSION

    def aad(self) -> bytes:
        data = {
            "participant_inn": _opaque(self.participant_inn, "participant_inn"),
            "oms_connection": _opaque(self.oms_connection, "oms_connection"),
            "order_local_id": _opaque(self.order_local_id, "order_local_id"),
            "gtin": _opaque(self.gtin, "gtin"),
            "remote_block_id": _opaque(self.remote_block_id, "remote_block_id") if self.remote_block_id is not None else None,
            "vault_format_version": self.vault_format_version,
        }
        return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class KmVaultKeyProvider(Protocol):
    def get_key(self, key_version: str) -> bytes: ...


@dataclass(frozen=True, slots=True, repr=False)
class VaultEnvelope:
    ciphertext: bytes
    nonce: bytes
    auth_tag: bytes
    key_version: str
    vault_format_version: str
    aad_hash: str
    plaintext_sha256: str
    ciphertext_sha256: str
    code_count: int

    def __repr__(self) -> str:
        return (
            "VaultEnvelope(ciphertext=<REDACTED>, nonce=<REDACTED>, auth_tag=<REDACTED>, "
            f"key_version={self.key_version!r}, vault_format_version={self.vault_format_version!r}, "
            f"aad_hash={self.aad_hash!r}, plaintext_sha256={self.plaintext_sha256!r}, "
            f"ciphertext_sha256={self.ciphertext_sha256!r}, code_count={self.code_count})"
        )


class KmVault:
    def __init__(self, key_provider: KmVaultKeyProvider, key_version: str) -> None:
        self._key_provider = key_provider
        self.key_version = _opaque(key_version, "key_version")

    def _key(self) -> bytes:
        key = self._key_provider.get_key(self.key_version)
        if not isinstance(key, bytes) or len(key) != 32:
            raise SuzSecurityError("KM vault key provider must return a 32-byte AES-256 key")
        return key

    def encrypt(self, exact_payload: bytes, *, binding: VaultBinding, code_count: int) -> VaultEnvelope:
        if not isinstance(exact_payload, bytes):
            raise SuzContractError("exact KM payload must be bytes")
        if type(code_count) is not int or code_count < 0:
            raise SuzContractError("code_count must be a non-negative integer")
        aad = binding.aad()
        nonce = os.urandom(12)
        combined = AESGCM(self._key()).encrypt(nonce, exact_payload, aad)
        ciphertext, tag = combined[:-16], combined[-16:]
        return VaultEnvelope(
            ciphertext=ciphertext,
            nonce=nonce,
            auth_tag=tag,
            key_version=self.key_version,
            vault_format_version=binding.vault_format_version,
            aad_hash=hashlib.sha256(aad).hexdigest(),
            plaintext_sha256=hashlib.sha256(exact_payload).hexdigest(),
            ciphertext_sha256=hashlib.sha256(combined).hexdigest(),
            code_count=code_count,
        )

    def decrypt(self, envelope: VaultEnvelope, *, binding: VaultBinding) -> bytes:
        if envelope.key_version != self.key_version:
            raise SuzSecurityError("KM vault key version mismatch")
        aad = binding.aad()
        if hashlib.sha256(aad).hexdigest() != envelope.aad_hash:
            raise SuzSecurityError("KM vault AAD mismatch")
        try:
            raw = AESGCM(self._key()).decrypt(
                envelope.nonce,
                envelope.ciphertext + envelope.auth_tag,
                aad,
            )
        except InvalidTag as exc:
            raise SuzSecurityError("KM vault authentication failed") from exc
        if hashlib.sha256(raw).hexdigest() != envelope.plaintext_sha256:
            raise SuzSecurityError("KM vault plaintext hash mismatch")
        if hashlib.sha256(envelope.ciphertext + envelope.auth_tag).hexdigest() != envelope.ciphertext_sha256:
            raise SuzSecurityError("KM vault ciphertext hash mismatch")
        return raw


def envelope_to_persistence(envelope: VaultEnvelope) -> Mapping[str, object]:
    return {
        "ciphertext": envelope.ciphertext,
        "nonce": envelope.nonce,
        "auth_tag": envelope.auth_tag,
        "key_version": envelope.key_version,
        "vault_format_version": envelope.vault_format_version,
        "aad_hash": envelope.aad_hash,
        "plaintext_sha256": envelope.plaintext_sha256,
        "ciphertext_sha256": envelope.ciphertext_sha256,
        "code_count": envelope.code_count,
    }


_SENSITIVE_KEY_FRAGMENTS = (
    "clienttoken",
    "registrationkey",
    "signature",
    "privatekey",
    "private_key",
    "pin",
    "fullkm",
    "full_km",
    "km_payload",
    "exact_payload",
)


def redact_sensitive_mapping(value: Mapping[str, object]) -> dict[str, object]:
    def clean(item: object) -> object:
        if isinstance(item, Mapping):
            output: dict[str, object] = {}
            for key, nested in item.items():
                normalized = str(key).replace("-", "").replace("_", "").lower()
                if any(fragment.replace("_", "") in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS):
                    output[str(key)] = "REDACTED"
                else:
                    output[str(key)] = clean(nested)
            return output
        if isinstance(item, (list, tuple)):
            return [clean(x) for x in item]
        return item

    return clean(value)  # type: ignore[return-value]


def redact_text(text: str, sensitive_values: Sequence[str | bytes]) -> str:
    result = str(text)
    for secret in sensitive_values:
        if isinstance(secret, bytes):
            candidates = [secret.decode("utf-8", errors="ignore"), base64.b64encode(secret).decode("ascii")]
        else:
            candidates = [secret]
        for candidate in candidates:
            if candidate:
                result = result.replace(candidate, "REDACTED")
    return result
