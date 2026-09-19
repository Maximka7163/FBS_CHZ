from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Protocol


class AgentCredentialStore(Protocol):
    def load(self) -> str | None: ...
    def save(self, credential: str) -> None: ...


class MemoryAgentCredentialStore:
    def __init__(self) -> None:
        self._value: str | None = None

    def load(self) -> str | None:
        return self._value

    def save(self, credential: str) -> None:
        if len(credential) < 43:
            raise ValueError("invalid permanent agent credential")
        self._value = credential


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes):
    buffer = ctypes.create_string_buffer(data)
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


class DpapiAgentCredentialStore:
    """Windows user/machine-scoped DPAPI store for the permanent agent credential."""

    def __init__(self, path: str | Path, *, machine_scope: bool = False) -> None:
        self.path = Path(path)
        self.machine_scope = bool(machine_scope)

    @staticmethod
    def _require_windows():
        if os.name != "nt":
            raise RuntimeError("DPAPI credential storage requires Windows")

    def _protect(self, raw: bytes) -> bytes:
        self._require_windows()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        incoming, keep = _blob(raw)
        outgoing = _DataBlob()
        flags = 0x4 if self.machine_scope else 0
        ok = crypt32.CryptProtectData(
            ctypes.byref(incoming), "WBCZ M15 Agent Credential", None, None, None, flags, ctypes.byref(outgoing)
        )
        del keep
        if not ok:
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(outgoing.pbData, outgoing.cbData)
        finally:
            kernel32.LocalFree(outgoing.pbData)

    def _unprotect(self, sealed: bytes) -> bytes:
        self._require_windows()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        incoming, keep = _blob(sealed)
        outgoing = _DataBlob()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(incoming), None, None, None, None, 0, ctypes.byref(outgoing)
        )
        del keep
        if not ok:
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(outgoing.pbData, outgoing.cbData)
        finally:
            kernel32.LocalFree(outgoing.pbData)

    def load(self) -> str | None:
        if not self.path.exists():
            return None
        sealed = base64.b64decode(self.path.read_bytes(), validate=True)
        value = self._unprotect(sealed).decode("utf-8")
        if len(value) < 43:
            raise ValueError("stored agent credential is invalid")
        return value

    def save(self, credential: str) -> None:
        if not isinstance(credential, str) or len(credential) < 43:
            raise ValueError("invalid permanent agent credential")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        sealed = base64.b64encode(self._protect(credential.encode("utf-8")))
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("wb") as out:
            out.write(sealed)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


@dataclass(frozen=True, slots=True)
class EnrollmentResponse:
    compatibility: str
    binding_id: str | None
    permanent_credential: str | None
    credential_version: int | None


def parse_enrollment_response(raw: bytes) -> EnrollmentResponse:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid enrollment response") from exc
    if not isinstance(data, dict):
        raise ValueError("invalid enrollment response")
    compatibility = str(data.get("compatibility") or "")
    credential = data.get("permanent_credential")
    if credential is not None and (not isinstance(credential, str) or len(credential) < 43):
        raise ValueError("invalid enrollment credential")
    binding_id = data.get("binding_id")
    if binding_id is not None and not isinstance(binding_id, str):
        raise ValueError("invalid enrollment binding")
    version = data.get("credential_version")
    if version is not None and type(version) is not int:
        raise ValueError("invalid credential version")
    return EnrollmentResponse(compatibility, binding_id, credential, version)
