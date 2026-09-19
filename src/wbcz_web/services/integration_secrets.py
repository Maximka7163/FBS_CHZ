from __future__ import annotations

from dataclasses import dataclass
from enum import Flag, auto
import secrets
from typing import Protocol


class SecretProviderError(RuntimeError):
    pass


class SecretProviderWriteUnavailable(SecretProviderError):
    pass


class SecretProviderAtomicRotationUnsupported(SecretProviderError):
    pass


class SecretCapability(Flag):
    READ = auto()
    WRITE = auto()
    VERSION = auto()
    REVOKE = auto()
    STAGE_ACTIVATE = auto()


@dataclass(frozen=True, slots=True)
class SecretValue:
    value: str
    version: str | None = None

    def __repr__(self) -> str:
        return "SecretValue(value=<REDACTED>, version=%r)" % (self.version,)

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class StagedSecret:
    ref: str
    version: str


@dataclass(frozen=True, slots=True)
class SecretVersion:
    ref: str
    version: str


class SecretProvider(Protocol):
    @property
    def capabilities(self) -> SecretCapability: ...

    def get(self, ref: str) -> SecretValue: ...

    def stage(self, scope: str, purpose: str, value: str) -> StagedSecret: ...

    def activate(self, staged: StagedSecret) -> SecretVersion: ...

    def revoke(self, ref: str, version: str) -> None: ...

    def destroy_staged(self, staged: StagedSecret) -> None: ...


class ReadOnlySecretProvider:
    """Legacy read adapter. It intentionally has no writable fallback."""

    def __init__(self, getter=None) -> None:
        self._getter = getter

    @property
    def capabilities(self) -> SecretCapability:
        return SecretCapability.READ if self._getter is not None else SecretCapability(0)

    def get(self, ref: str) -> SecretValue:
        if self._getter is None:
            raise SecretProviderError("SECRET_PROVIDER_UNAVAILABLE")
        return SecretValue(str(self._getter(ref)))

    def stage(self, scope: str, purpose: str, value: str) -> StagedSecret:
        del scope, purpose, value
        raise SecretProviderWriteUnavailable("SECRET_PROVIDER_WRITE_UNAVAILABLE")

    def activate(self, staged: StagedSecret) -> SecretVersion:
        del staged
        raise SecretProviderWriteUnavailable("SECRET_PROVIDER_WRITE_UNAVAILABLE")

    def revoke(self, ref: str, version: str) -> None:
        del ref, version
        raise SecretProviderWriteUnavailable("SECRET_PROVIDER_WRITE_UNAVAILABLE")

    def destroy_staged(self, staged: StagedSecret) -> None:
        del staged


class InMemorySecretProvider:
    """Deterministic-capability test provider. Never selected as production storage."""

    def __init__(self, *, stage_activate: bool = True) -> None:
        self._values: dict[tuple[str, str], str] = {}
        self._active: dict[str, str] = {}
        self._counter = 0
        self._stage_activate = bool(stage_activate)

    @property
    def capabilities(self) -> SecretCapability:
        value = SecretCapability.READ | SecretCapability.WRITE | SecretCapability.VERSION | SecretCapability.REVOKE
        if self._stage_activate:
            value |= SecretCapability.STAGE_ACTIVATE
        return value

    def _next(self) -> tuple[str, str]:
        self._counter += 1
        return f"mem://m14/{self._counter}", f"v{self._counter}"

    def get(self, ref: str) -> SecretValue:
        version = self._active.get(ref)
        if version is None:
            raise SecretProviderError("SECRET_MISSING")
        value = self._values.get((ref, version))
        if value is None:
            raise SecretProviderError("SECRET_MISSING")
        return SecretValue(value, version)

    def stage(self, scope: str, purpose: str, value: str) -> StagedSecret:
        if not self._stage_activate:
            raise SecretProviderAtomicRotationUnsupported("SECRET_PROVIDER_ATOMIC_ROTATION_UNSUPPORTED")
        if not isinstance(value, str) or not value:
            raise SecretProviderError("SECRET_MISSING")
        ref, version = self._next()
        self._values[(ref, version)] = value
        return StagedSecret(ref, version)

    def activate(self, staged: StagedSecret) -> SecretVersion:
        if not self._stage_activate:
            raise SecretProviderAtomicRotationUnsupported("SECRET_PROVIDER_ATOMIC_ROTATION_UNSUPPORTED")
        if (staged.ref, staged.version) not in self._values:
            raise SecretProviderError("SECRET_MISSING")
        self._active[staged.ref] = staged.version
        return SecretVersion(staged.ref, staged.version)

    def revoke(self, ref: str, version: str) -> None:
        self._values.pop((ref, version), None)
        if self._active.get(ref) == version:
            self._active.pop(ref, None)

    def destroy_staged(self, staged: StagedSecret) -> None:
        if self._active.get(staged.ref) != staged.version:
            self._values.pop((staged.ref, staged.version), None)


def require_safe_rotation(provider: SecretProvider) -> None:
    required = SecretCapability.WRITE | SecretCapability.VERSION | SecretCapability.STAGE_ACTIVATE
    if provider.capabilities & required != required:
        raise SecretProviderAtomicRotationUnsupported("SECRET_PROVIDER_ATOMIC_ROTATION_UNSUPPORTED")


def provision_agent_credential() -> str:
    # 48 random bytes -> high entropy URL-safe bearer; shown exactly once.
    return secrets.token_urlsafe(48)
