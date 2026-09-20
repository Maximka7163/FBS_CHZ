from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite


ENVELOPE_VERSION = "SELLARI_PRINT_HPKE_V1"
SUITE_ID = "DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM"
PRINT_PROTOCOL_VERSION = "printing-agent-v2"
REQUIRED_CAPABILITIES = frozenset({
    "PRINTING_SENSITIVE_DELIVERY_V1",
    "HPKE_X25519_AES128GCM_V1",
})
PUBLIC_KEY_ALGORITHM = "HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM"
_CONTEXT_FIELDS = (
    "delivery_reservation_id",
    "print_execution_id",
    "print_job_id",
    "print_job_item_id",
    "stored_full_km_item_id",
    "organisation_id",
    "participant_id",
    "agent_binding_id",
    "payload_sha256",
    "template_version_id",
    "layout_sha256",
    "recipient_key_version",
    "expires_at",
)
_SUITE = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
_ENC_LENGTH = KEM.X25519.enc_length()


class SensitiveEnvelopeError(ValueError):
    pass


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise SensitiveEnvelopeError("invalid base64url value")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise SensitiveEnvelopeError("invalid base64url value") from exc


def canonical_context(value: Mapping[str, Any]) -> bytes:
    if set(value) != set(_CONTEXT_FIELDS):
        raise SensitiveEnvelopeError("delivery context fields mismatch")
    normalized: dict[str, str | int] = {}
    for key in _CONTEXT_FIELDS:
        item = value[key]
        if key == "recipient_key_version":
            if type(item) is not int or item < 1:
                raise SensitiveEnvelopeError("invalid recipient key version")
            normalized[key] = item
            continue
        if not isinstance(item, str) or not item or len(item) > 256:
            raise SensitiveEnvelopeError("invalid delivery context value")
        normalized[key] = item
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def context_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_context(value)).hexdigest()


def public_key_fingerprint(public_key_raw: bytes) -> str:
    if not isinstance(public_key_raw, bytes) or len(public_key_raw) != 32:
        raise SensitiveEnvelopeError("recipient public key must be 32 raw bytes")
    try:
        x25519.X25519PublicKey.from_public_bytes(public_key_raw)
    except ValueError as exc:
        raise SensitiveEnvelopeError("invalid X25519 public key") from exc
    return hashlib.sha256(b"sellari-print-hpke-public-v1\0" + public_key_raw).hexdigest()


def seal_full_km(
    *,
    recipient_public_key_raw: bytes,
    plaintext_full_km: bytes,
    context: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(plaintext_full_km, bytes) or not plaintext_full_km:
        raise SensitiveEnvelopeError("plaintext payload must be exact non-empty bytes")
    try:
        public_key = x25519.X25519PublicKey.from_public_bytes(recipient_public_key_raw)
    except ValueError as exc:
        raise SensitiveEnvelopeError("invalid X25519 public key") from exc
    context_bytes = canonical_context(context)
    # RFC 9180 single-shot auxiliary authenticated context is bound through info.
    # No ECDH/HKDF/AEAD composition is implemented here; pyca/cryptography owns it.
    info = ENVELOPE_VERSION.encode("ascii") + b"\0" + context_bytes
    sealed = _SUITE.encrypt(plaintext_full_km, public_key, info=info)
    enc, ciphertext = sealed[:_ENC_LENGTH], sealed[_ENC_LENGTH:]
    return {
        "envelope_version": ENVELOPE_VERSION,
        "hpke_suite_id": SUITE_ID,
        "recipient_key_version": int(context["recipient_key_version"]),
        "enc": b64e(enc),
        "ciphertext": b64e(ciphertext),
        "payload_sha256": str(context["payload_sha256"]),
        "context_sha256": hashlib.sha256(context_bytes).hexdigest(),
        "expires_at": str(context["expires_at"]),
    }


def open_full_km(
    *,
    recipient_private_key_raw: bytes,
    enc_b64: str,
    ciphertext_b64: str,
    context: Mapping[str, Any],
) -> bytes:
    if not isinstance(recipient_private_key_raw, bytes) or len(recipient_private_key_raw) != 32:
        raise SensitiveEnvelopeError("recipient private key must be 32 raw bytes")
    try:
        private_key = x25519.X25519PrivateKey.from_private_bytes(recipient_private_key_raw)
    except ValueError as exc:
        raise SensitiveEnvelopeError("invalid X25519 private key") from exc
    context_bytes = canonical_context(context)
    info = ENVELOPE_VERSION.encode("ascii") + b"\0" + context_bytes
    try:
        return _SUITE.decrypt(b64d(enc_b64) + b64d(ciphertext_b64), private_key, info=info)
    except Exception as exc:
        raise SensitiveEnvelopeError("HPKE envelope authentication failed") from exc
