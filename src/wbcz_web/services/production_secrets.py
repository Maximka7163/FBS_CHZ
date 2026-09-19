from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from wbcz.m11_reports import ArtifactKeyProvider
from wbcz_web.services.integration_secrets import (
    SecretCapability, SecretProviderError, SecretProviderWriteUnavailable,
    SecretValue, SecretVersion, StagedSecret,
)


_SECRET_FORMAT = "WBCZ-M15-AES256GCM-v1"


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb", closefd=True) as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        _fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _read_32_byte_key(path: Path) -> bytes:
    raw = path.read_bytes()
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            decoded = bytes.fromhex(stripped.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            decoded = b""
        if len(decoded) == 32:
            return decoded
    if len(raw) == 32:
        return raw
    raise SecretProviderError("MASTER_KEY_INVALID")


def _safe_ref_dir(root: Path, ref: str) -> Path:
    digest = hashlib.sha256(ref.encode("utf-8")).hexdigest()
    return root / "refs" / digest


def _aad(ref: str, version: str, scope: str, purpose: str) -> bytes:
    return json.dumps(
        {"format": _SECRET_FORMAT, "ref": ref, "version": version, "scope": scope, "purpose": purpose},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


class EncryptedVersionedFilesystemSecretProvider:
    """Replaceable production provider with encrypted version files and atomic activation.

    PostgreSQL stores opaque refs/versions only. The master key is read from a
    separately permissioned host path and never copied into provider metadata.
    """

    def __init__(self, root: str | Path, *, master_key_path: str | Path) -> None:
        self.root = Path(root).resolve()
        self.master_key_path = Path(master_key_path).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    @property
    def capabilities(self) -> SecretCapability:
        return (
            SecretCapability.READ | SecretCapability.WRITE | SecretCapability.VERSION
            | SecretCapability.REVOKE | SecretCapability.STAGE_ACTIVATE
        )

    def _key(self) -> bytes:
        try:
            return _read_32_byte_key(self.master_key_path)
        except FileNotFoundError as exc:
            raise SecretProviderError("MASTER_KEY_UNAVAILABLE") from exc

    @staticmethod
    def _version() -> str:
        return "v_" + secrets.token_hex(12)

    @staticmethod
    def _ref() -> str:
        return "fssec://" + secrets.token_hex(24)

    def _version_path(self, ref: str, version: str) -> Path:
        if not ref.startswith("fssec://") or not version.startswith("v_"):
            raise SecretProviderError("SECRET_REFERENCE_INVALID")
        return _safe_ref_dir(self.root, ref) / (version + ".json")

    def _active_path(self, ref: str) -> Path:
        if not ref.startswith("fssec://"):
            raise SecretProviderError("SECRET_REFERENCE_INVALID")
        return _safe_ref_dir(self.root, ref) / "active.json"

    def stage(self, scope: str, purpose: str, value: str) -> StagedSecret:
        if not isinstance(value, str) or not value:
            raise SecretProviderError("SECRET_MISSING")
        ref, version = self._ref(), self._version()
        nonce = os.urandom(12)
        aad = _aad(ref, version, scope, purpose)
        sealed = AESGCM(self._key()).encrypt(nonce, value.encode("utf-8"), aad)
        record = {
            "format": _SECRET_FORMAT,
            "ref": ref,
            "version": version,
            "scope": scope,
            "purpose": purpose,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(sealed).decode("ascii"),
        }
        _atomic_write(
            self._version_path(ref, version),
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        return StagedSecret(ref, version)

    def _record(self, ref: str, version: str) -> Mapping[str, Any]:
        try:
            value = json.loads(self._version_path(ref, version).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise SecretProviderError("SECRET_MISSING") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SecretProviderError("SECRET_CIPHERTEXT_CORRUPT") from exc
        if not isinstance(value, dict) or value.get("format") != _SECRET_FORMAT:
            raise SecretProviderError("SECRET_CIPHERTEXT_CORRUPT")
        if value.get("ref") != ref or value.get("version") != version:
            raise SecretProviderError("SECRET_AAD_MISMATCH")
        return value

    def get_version(self, ref: str, version: str) -> SecretValue:
        record = self._record(ref, version)
        try:
            nonce = base64.b64decode(str(record["nonce"]), validate=True)
            sealed = base64.b64decode(str(record["ciphertext"]), validate=True)
            aad = _aad(ref, version, str(record["scope"]), str(record["purpose"]))
            plain = AESGCM(self._key()).decrypt(nonce, sealed, aad)
            value = plain.decode("utf-8")
        except Exception as exc:
            if isinstance(exc, SecretProviderError):
                raise
            raise SecretProviderError("SECRET_DECRYPT_FAILED") from exc
        return SecretValue(value, version)

    def active_version(self, ref: str) -> str:
        try:
            data = json.loads(self._active_path(ref).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise SecretProviderError("SECRET_MISSING") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SecretProviderError("SECRET_ACTIVE_POINTER_CORRUPT") from exc
        version = data.get("version") if isinstance(data, dict) else None
        if not isinstance(version, str):
            raise SecretProviderError("SECRET_ACTIVE_POINTER_CORRUPT")
        return version

    def get(self, ref: str) -> SecretValue:
        return self.get_version(ref, self.active_version(ref))

    def activate(self, staged: StagedSecret) -> SecretVersion:
        # Decrypt before publishing to prove the staged ciphertext/key/AAD is valid.
        self.get_version(staged.ref, staged.version)
        pointer = json.dumps(
            {"format": _SECRET_FORMAT, "version": staged.version},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        _atomic_write(self._active_path(staged.ref), pointer)
        return SecretVersion(staged.ref, staged.version)

    def revoke(self, ref: str, version: str) -> None:
        version_path = self._version_path(ref, version)
        active_path = self._active_path(ref)
        try:
            if active_path.exists() and self.active_version(ref) == version:
                active_path.unlink(missing_ok=True)
                _fsync_dir(active_path.parent)
        finally:
            version_path.unlink(missing_ok=True)
            if version_path.parent.exists():
                _fsync_dir(version_path.parent)

    def destroy_staged(self, staged: StagedSecret) -> None:
        try:
            active = self.active_version(staged.ref)
        except SecretProviderError:
            active = None
        if active != staged.version:
            path = self._version_path(staged.ref, staged.version)
            path.unlink(missing_ok=True)
            if path.parent.exists():
                _fsync_dir(path.parent)


class VersionedFilesystemKeyProvider(ArtifactKeyProvider):
    """Read-only key-ring adapter; active and historical versions stay addressable."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def _path(self, key_version: str) -> Path:
        if not key_version or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in key_version):
            raise RuntimeError("invalid key version")
        return self.root / (key_version + ".key")

    def get_key(self, key_version: str) -> bytes:
        try:
            key = _read_32_byte_key(self._path(key_version))
        except SecretProviderError as exc:
            raise RuntimeError("artifact key unavailable") from exc
        except FileNotFoundError as exc:
            raise RuntimeError("artifact key unavailable") from exc
        return key

    def available_versions(self) -> tuple[str, ...]:
        if not self.root.is_dir():
            return ()
        return tuple(sorted(p.stem for p in self.root.glob("*.key") if p.is_file()))


def build_production_secret_provider(config: Any):
    if getattr(config, "environment", None) != "production":
        raise SecretProviderWriteUnavailable("production provider requested outside production")
    return EncryptedVersionedFilesystemSecretProvider(
        config.secret_provider_root,
        master_key_path=config.secret_provider_master_key_path,
    )


def build_artifact_key_provider(config: Any) -> ArtifactKeyProvider:
    if getattr(config, "artifact_keyring_root", None):
        return VersionedFilesystemKeyProvider(config.artifact_keyring_root)
    # Test/development compatibility remains runtime-only and is never used by
    # production validation after M15.
    from wbcz_web.services.reports import EnvironmentArtifactKeyProvider
    return EnvironmentArtifactKeyProvider()
