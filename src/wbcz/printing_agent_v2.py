from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Callable, Protocol

from cryptography.hazmat.primitives.asymmetric import x25519

from wbcz.printer_profiles import DISCOVERY_CAPABILITY
from wbcz.physical_printing import PHYSICAL_CAPABILITY, PhysicalPrintRuntime
from wbcz.printing_sensitive import (
    ENVELOPE_VERSION,
    PRINT_PROTOCOL_VERSION,
    REQUIRED_CAPABILITIES,
    SUITE_ID,
    SensitiveEnvelopeError,
    b64e,
    context_sha256,
    open_full_km,
    public_key_fingerprint,
)


class PrivateKeyProtector(Protocol):
    def protect(self, plaintext: bytes) -> bytes: ...
    def unprotect(self, protected: bytes) -> bytes: ...


class DpapiProtector:
    """Narrow Windows DPAPI adapter. No certificate, PIN or signing key is involved."""

    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    @classmethod
    def _input_blob(cls, data: bytes):
        buffer = ctypes.create_string_buffer(data)
        blob = cls._DATA_BLOB(
            len(data),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        )
        return blob, buffer

    def _crypt(self, data: bytes, *, protect: bool) -> bytes:
        if os.name != "nt":
            raise OSError("Windows DPAPI is unavailable on this platform")
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        source, keepalive = self._input_blob(data)
        result = self._DATA_BLOB()
        if protect:
            ok = crypt32.CryptProtectData(
                ctypes.byref(source),
                "Sellari printing HPKE private key",
                None,
                None,
                None,
                self.CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(result),
            )
        else:
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(source),
                None,
                None,
                None,
                None,
                self.CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(result),
            )
        _ = keepalive
        if not ok:
            raise ctypes.WinError()
        try:
            return ctypes.string_at(result.pbData, result.cbData)
        finally:
            kernel32.LocalFree(result.pbData)

    def protect(self, plaintext: bytes) -> bytes:
        return self._crypt(plaintext, protect=True)

    def unprotect(self, protected: bytes) -> bytes:
        return self._crypt(protected, protect=False)


@dataclass(frozen=True, slots=True)
class GeneratedPrintKey:
    public_key_b64: str
    public_key_fingerprint: str


class AgentPrintKeyStore:
    """DPAPI-protected local X25519 key file.

    The file contains only a protected private-key blob plus public metadata.
    Raw private bytes exist only transiently in process memory.
    """

    def __init__(self, path: str | Path, protector: PrivateKeyProtector | None = None) -> None:
        self.path = Path(path)
        self.protector = protector or DpapiProtector()

    def generate(self) -> GeneratedPrintKey:
        private = x25519.X25519PrivateKey.generate()
        private_raw = private.private_bytes_raw()
        public_raw = private.public_key().public_bytes_raw()
        try:
            protected = self.protector.protect(private_raw)
        finally:
            private_raw = b""
        fingerprint = public_key_fingerprint(public_raw)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "format": "sellari-print-dpapi-key-v1",
            "public_key": b64e(public_raw),
            "public_key_fingerprint": fingerprint,
            "protected_private_key": base64.urlsafe_b64encode(protected).decode("ascii"),
            "server_key_version": None,
        }
        self.path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return GeneratedPrintKey(document["public_key"], fingerprint)

    def bind_server_version(self, key_version: int) -> None:
        document = self._load()
        if type(key_version) is not int or key_version < 1:
            raise ValueError("invalid server key version")
        document["server_key_version"] = key_version
        self.path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    def _load(self) -> dict:
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if value.get("format") != "sellari-print-dpapi-key-v1":
            raise ValueError("unsupported print key file")
        return value

    def open_private_key(self) -> bytes:
        document = self._load()
        try:
            protected = base64.urlsafe_b64decode(document["protected_private_key"])
            raw = self.protector.unprotect(protected)
        except Exception as exc:
            raise ValueError("print private key unavailable") from exc
        if len(raw) != 32:
            raw = b""
            raise ValueError("print private key length invalid")
        return raw

    def public_metadata(self) -> dict:
        document = self._load()
        return {
            "public_key": document["public_key"],
            "public_key_fingerprint": document["public_key_fingerprint"],
            "server_key_version": document.get("server_key_version"),
        }


class AgentSensitiveReplayStore:
    """Safe local replay evidence only; never stores FULL KM, ciphertext or private keys."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS print_sensitive_replay (
                  execution_id TEXT PRIMARY KEY,
                  print_job_item_id TEXT NOT NULL,
                  reservation_id TEXT NOT NULL,
                  payload_sha256 TEXT NOT NULL,
                  context_sha256 TEXT NOT NULL,
                  state TEXT NOT NULL,
                  key_version INTEGER NOT NULL,
                  first_seen_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  safe_error_code TEXT
                )
                """
            )

    def _connect(self):
        return sqlite3.connect(self.path)

    def record(
        self,
        *,
        execution_id: str,
        print_job_item_id: str,
        reservation_id: str,
        payload_sha256: str,
        context_sha256: str,
        state: str,
        key_version: int,
        safe_error_code: str | None = None,
    ) -> None:
        if state not in {"OPENED_VERIFIED", "ACKNOWLEDGED", "FAILED"}:
            raise ValueError("invalid sensitive replay state")
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as db:
            existing = db.execute(
                "SELECT reservation_id,payload_sha256,context_sha256,key_version FROM print_sensitive_replay WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
            fingerprint = (reservation_id, payload_sha256, context_sha256, key_version)
            if existing is not None and tuple(existing) != fingerprint:
                raise ValueError("sensitive delivery replay conflict")
            db.execute(
                """
                INSERT INTO print_sensitive_replay (
                  execution_id,print_job_item_id,reservation_id,payload_sha256,context_sha256,
                  state,key_version,first_seen_at,updated_at,safe_error_code
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(execution_id) DO UPDATE SET
                  state=excluded.state,updated_at=excluded.updated_at,safe_error_code=excluded.safe_error_code
                """,
                (
                    execution_id, print_job_item_id, reservation_id, payload_sha256, context_sha256,
                    state, key_version, now, now, safe_error_code,
                ),
            )


class SensitiveDeliveryAgent:
    def __init__(self, key_store: AgentPrintKeyStore, replay_store: AgentSensitiveReplayStore) -> None:
        self.key_store = key_store
        self.replay_store = replay_store

    @staticmethod
    def capabilities(*, physical_runtime: PhysicalPrintRuntime | None = None) -> dict:
        capabilities = set(REQUIRED_CAPABILITIES) | {DISCOVERY_CAPABILITY}
        result = {
            "print_protocol_version": PRINT_PROTOCOL_VERSION,
            "capabilities": sorted(capabilities),
        }
        if physical_runtime is not None:
            physical = physical_runtime.capability_report()
            if physical.get("renderer_version") and physical.get("decoder_version") != "unavailable":
                capabilities.add(PHYSICAL_CAPABILITY)
                result.update({
                    "capabilities": sorted(capabilities),
                    "printing_contract_version": physical["printing_contract_version"],
                    "layout_schema_version": physical["layout_schema_version"],
                    "renderer_version": physical["renderer_version"],
                    "libdmtx_version": physical["libdmtx_version"],
                    "decoder_version": physical["decoder_version"],
                })
        return result

    def open_verify_and_ack(
        self,
        envelope: dict,
        *,
        consume_in_memory: Callable[[bytes], None] | None = None,
    ) -> dict[str, str]:
        required = {
            "delivery_reservation_id", "print_execution_id", "print_job_item_id",
            "envelope_version", "hpke_suite_id", "recipient_key_version", "enc",
            "ciphertext", "payload_sha256", "context_sha256", "expires_at", "context",
        }
        if set(envelope) != required:
            raise SensitiveEnvelopeError("printing-agent-v2 envelope fields mismatch")
        context = envelope["context"]
        if not isinstance(context, dict):
            raise SensitiveEnvelopeError("printing-agent-v2 context missing")
        if envelope["envelope_version"] != ENVELOPE_VERSION or envelope["hpke_suite_id"] != SUITE_ID:
            raise SensitiveEnvelopeError("unsupported printing HPKE envelope")
        if context_sha256(context) != envelope["context_sha256"]:
            raise SensitiveEnvelopeError("delivery context SHA-256 mismatch")
        local = self.key_store.public_metadata()
        if local.get("server_key_version") != int(envelope["recipient_key_version"]):
            raise SensitiveEnvelopeError("recipient key version mismatch")
        private_raw = self.key_store.open_private_key()
        plaintext = b""
        try:
            plaintext = open_full_km(
                recipient_private_key_raw=private_raw,
                enc_b64=envelope["enc"],
                ciphertext_b64=envelope["ciphertext"],
                context=context,
            )
            digest = hashlib.sha256(plaintext).hexdigest()
            if digest != envelope["payload_sha256"]:
                raise SensitiveEnvelopeError("payload SHA-256 mismatch")
            if consume_in_memory is not None:
                consume_in_memory(plaintext)
        finally:
            private_raw = b""
            plaintext = b""
        self.replay_store.record(
            execution_id=envelope["print_execution_id"],
            print_job_item_id=envelope["print_job_item_id"],
            reservation_id=envelope["delivery_reservation_id"],
            payload_sha256=envelope["payload_sha256"],
            context_sha256=envelope["context_sha256"],
            state="OPENED_VERIFIED",
            key_version=int(envelope["recipient_key_version"]),
        )
        return {
            "delivery_reservation_id": envelope["delivery_reservation_id"],
            "payload_sha256": envelope["payload_sha256"],
            "context_sha256": envelope["context_sha256"],
        }
