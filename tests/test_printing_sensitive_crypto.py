from __future__ import annotations

from dataclasses import replace
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM

from wbcz.printing_agent_v2 import (
    AgentPrintKeyStore,
    AgentSensitiveReplayStore,
    DpapiProtector,
    SensitiveDeliveryAgent,
)
from wbcz.printing_sensitive import (
    ENVELOPE_VERSION,
    SUITE_ID,
    SensitiveEnvelopeError,
    b64d,
    b64e,
    context_sha256,
    open_full_km,
    seal_full_km,
)
from starlette.requests import Request

from wbcz.windows_agent import AgentAuthError
from wbcz_web.api.agent_routes import _machine_principal
from wbcz_web.config import WebConfig


def _context(*, key_version: int = 1) -> dict:
    return {
        "delivery_reservation_id": "reservation-001",
        "print_execution_id": "execution-001",
        "print_job_id": "job-001",
        "print_job_item_id": "item-001",
        "stored_full_km_item_id": "stored-001",
        "organisation_id": "org-001",
        "participant_id": "participant-001",
        "agent_binding_id": "binding-001",
        "payload_sha256": "a" * 64,
        "template_version_id": "template-version-001",
        "layout_sha256": "b" * 64,
        "recipient_key_version": key_version,
        "expires_at": "2026-09-21T00:10:00Z",
    }


def _flip(value: str) -> str:
    raw = bytearray(b64d(value))
    raw[-1] ^= 1
    return b64e(bytes(raw))


def test_rfc9180_exact_suite_and_official_a1_x25519_key_material():
    # RFC 9180 Appendix A.1 official vector: KEM 0x0020, KDF 0x0001,
    # AEAD 0x0001. The public keys below must derive from the published
    # recipient and deterministic sender private keys.
    assert KEM.X25519.enc_length() == 32
    assert SUITE_ID == "DHKEM_X25519_HKDF_SHA256__HKDF_SHA256__AES_128_GCM"
    assert KDF.HKDF_SHA256 is not None
    assert AEAD.AES_128_GCM is not None
    sk_r = bytes.fromhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
    pk_r = bytes.fromhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
    sk_e = bytes.fromhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
    pk_e = bytes.fromhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
    assert x25519.X25519PrivateKey.from_private_bytes(sk_r).public_key().public_bytes_raw() == pk_r
    assert x25519.X25519PrivateKey.from_private_bytes(sk_e).public_key().public_bytes_raw() == pk_e


def test_hpke_roundtrip_wrong_key_modified_enc_ciphertext_and_context_fail_closed():
    recipient = x25519.X25519PrivateKey.generate()
    context = _context()
    payload = b"010460000000001221PHASEA\x1d91TEST\x1d92CANARY"
    context["payload_sha256"] = __import__("hashlib").sha256(payload).hexdigest()
    envelope = seal_full_km(
        recipient_public_key_raw=recipient.public_key().public_bytes_raw(),
        plaintext_full_km=payload,
        context=context,
    )
    assert envelope["envelope_version"] == ENVELOPE_VERSION
    assert envelope["hpke_suite_id"] == SUITE_ID
    assert envelope["context_sha256"] == context_sha256(context)
    assert open_full_km(
        recipient_private_key_raw=recipient.private_bytes_raw(),
        enc_b64=envelope["enc"],
        ciphertext_b64=envelope["ciphertext"],
        context=context,
    ) == payload

    wrong = x25519.X25519PrivateKey.generate()
    with pytest.raises(SensitiveEnvelopeError):
        open_full_km(
            recipient_private_key_raw=wrong.private_bytes_raw(),
            enc_b64=envelope["enc"],
            ciphertext_b64=envelope["ciphertext"],
            context=context,
        )
    with pytest.raises(SensitiveEnvelopeError):
        open_full_km(
            recipient_private_key_raw=recipient.private_bytes_raw(),
            enc_b64=_flip(envelope["enc"]),
            ciphertext_b64=envelope["ciphertext"],
            context=context,
        )
    with pytest.raises(SensitiveEnvelopeError):
        open_full_km(
            recipient_private_key_raw=recipient.private_bytes_raw(),
            enc_b64=envelope["enc"],
            ciphertext_b64=_flip(envelope["ciphertext"]),
            context=context,
        )
    modified = dict(context)
    modified["print_job_item_id"] = "item-modified"
    with pytest.raises(SensitiveEnvelopeError):
        open_full_km(
            recipient_private_key_raw=recipient.private_bytes_raw(),
            enc_b64=envelope["enc"],
            ciphertext_b64=envelope["ciphertext"],
            context=modified,
        )


class _FakeProtector:
    def __init__(self) -> None:
        self.last_plaintext: bytes | None = None

    def protect(self, plaintext: bytes) -> bytes:
        self.last_plaintext = bytes(plaintext)
        return bytes(value ^ 0xA5 for value in plaintext)

    def unprotect(self, protected: bytes) -> bytes:
        return bytes(value ^ 0xA5 for value in protected)


def test_agent_dpapi_boundary_and_replay_store_never_persist_plaintext(tmp_path: Path):
    protector = _FakeProtector()
    key_path = tmp_path / "printing-key.json"
    replay_path = tmp_path / "printing-replay.sqlite3"
    store = AgentPrintKeyStore(key_path, protector=protector)
    generated = store.generate()
    assert protector.last_plaintext is not None
    assert protector.last_plaintext not in key_path.read_bytes()
    store.bind_server_version(1)

    payload = b"010460000000001221PHASEA\x1d91TEST\x1d92AGENT-CANARY-991"
    context = _context()
    context["payload_sha256"] = __import__("hashlib").sha256(payload).hexdigest()
    envelope = seal_full_km(
        recipient_public_key_raw=b64d(generated.public_key_b64),
        plaintext_full_km=payload,
        context=context,
    )
    agent_envelope = {
        **envelope,
        "delivery_reservation_id": context["delivery_reservation_id"],
        "print_execution_id": context["print_execution_id"],
        "print_job_item_id": context["print_job_item_id"],
        "context": context,
    }
    captured: list[bytes] = []
    agent = SensitiveDeliveryAgent(store, AgentSensitiveReplayStore(replay_path))
    ack = agent.open_verify_and_ack(agent_envelope, consume_in_memory=captured.append)
    assert captured == [payload]
    assert ack == {
        "delivery_reservation_id": context["delivery_reservation_id"],
        "payload_sha256": context["payload_sha256"],
        "context_sha256": envelope["context_sha256"],
    }
    assert payload not in replay_path.read_bytes()
    assert envelope["ciphertext"].encode("ascii") not in replay_path.read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="real DPAPI only runs on Windows")
def test_real_windows_dpapi_roundtrip_synthetic_only():
    protector = DpapiProtector()
    synthetic = b"synthetic-x25519-private-key-" + b"x" * 8
    protected = protector.protect(synthetic)
    assert protected != synthetic
    assert protector.unprotect(protected) == synthetic


def test_production_execution_gate_and_remote_suz_gate_remain_independent():
    base = WebConfig(
        "postgresql+psycopg://wbcz:strong-password@db.example.invalid:5432/wbcz",
        "1234567890",
        environment="production",
        cookie_secure=True,
        trusted_hosts=("mark.sellari.ru",),
        build_sha="a" * 40,
        audit_pseudonym_key="a" * 32,
        agent_enabled=True,
        agent_legacy_bootstrap_enabled=False,
        printing_enabled=True,
        suz_km_keyring_root="/safe/keyring",
    )
    with pytest.raises(ValueError, match="Physical print execution remains blocked"):
        replace(base, print_execution_enabled=True).validate_for_startup()
    with pytest.raises(ValueError, match="FULL KM SUZ acquisition remains blocked"):
        replace(base, suz_full_km_remote_acquisition_enabled=True).validate_for_startup()



def test_browser_cookie_without_machine_bearer_cannot_authorize_v2_delivery():
    scope = {
        "type": "http",
        "method": "POST",
        "scheme": "https",
        "path": "/api/agent/v2/printing/payload-deliveries/r1/issue",
        "raw_path": b"/api/agent/v2/printing/payload-deliveries/r1/issue",
        "query_string": b"",
        "headers": [(b"cookie", b"wbcz_session=synthetic-browser-session")],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 443),
        "app": SimpleNamespace(
            state=SimpleNamespace(
                config=SimpleNamespace(agent_enabled=True)
            )
        ),
    }
    request = Request(scope)
    with pytest.raises(AgentAuthError, match="machine bearer required"):
        _machine_principal(request, object())



def test_agent_keeps_hpke_plaintext_in_memory_through_server_ack_then_consumes(tmp_path: Path):
    protector = _FakeProtector()
    key_path = tmp_path / "printing-key-phase-c.json"
    replay_path = tmp_path / "printing-replay-phase-c.sqlite3"
    store = AgentPrintKeyStore(key_path, protector=protector)
    generated = store.generate()
    store.bind_server_version(1)

    payload = b"010460000000001221PHASEC-MEMORY\x1d91TEST\x1d92ACK-BRIDGE"
    context = _context()
    context["payload_sha256"] = __import__("hashlib").sha256(payload).hexdigest()
    envelope = seal_full_km(
        recipient_public_key_raw=b64d(generated.public_key_b64),
        plaintext_full_km=payload,
        context=context,
    )
    agent_envelope = {
        **envelope,
        "delivery_reservation_id": context["delivery_reservation_id"],
        "print_execution_id": context["print_execution_id"],
        "print_job_item_id": context["print_job_item_id"],
        "context": context,
    }
    order: list[str] = []
    consumed: list[bytes] = []

    def acknowledge(ack):
        order.append("ack")
        assert ack["payload_sha256"] == context["payload_sha256"]
        return {
            "state": "ACKNOWLEDGED",
            "delivery_reservation_id": ack["delivery_reservation_id"],
        }

    def consume_after_ack(value: bytes):
        order.append("physical")
        consumed.append(bytes(value))

    agent = SensitiveDeliveryAgent(store, AgentSensitiveReplayStore(replay_path))
    ack = agent.open_verify_ack_then_consume(
        agent_envelope,
        acknowledge=acknowledge,
        consume_after_ack=consume_after_ack,
    )
    assert order == ["ack", "physical"]
    assert consumed == [payload]
    assert ack["delivery_reservation_id"] == context["delivery_reservation_id"]
    assert payload not in replay_path.read_bytes()

    replay = sqlite3.connect(replay_path)
    try:
        state = replay.execute(
            "SELECT state FROM print_sensitive_replay WHERE execution_id=?",
            (context["print_execution_id"],),
        ).fetchone()[0]
    finally:
        replay.close()
    assert state == "ACKNOWLEDGED"


def test_agent_never_enters_physical_callback_when_server_ack_fails(tmp_path: Path):
    protector = _FakeProtector()
    store = AgentPrintKeyStore(tmp_path / "key.json", protector=protector)
    generated = store.generate()
    store.bind_server_version(1)
    payload = b"010460000000001221PHASEC-NOACK\x1d91TEST\x1d92BLOCK"
    context = _context()
    context["payload_sha256"] = __import__("hashlib").sha256(payload).hexdigest()
    envelope = seal_full_km(
        recipient_public_key_raw=b64d(generated.public_key_b64),
        plaintext_full_km=payload,
        context=context,
    )
    agent_envelope = {
        **envelope,
        "delivery_reservation_id": context["delivery_reservation_id"],
        "print_execution_id": context["print_execution_id"],
        "print_job_item_id": context["print_job_item_id"],
        "context": context,
    }
    called: list[bytes] = []
    agent = SensitiveDeliveryAgent(
        store, AgentSensitiveReplayStore(tmp_path / "replay.sqlite3")
    )
    with pytest.raises(SensitiveEnvelopeError, match="did not acknowledge"):
        agent.open_verify_ack_then_consume(
            agent_envelope,
            acknowledge=lambda ack: {"state": "FAILED"},
            consume_after_ack=called.append,
        )
    assert called == []
