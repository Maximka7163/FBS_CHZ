from __future__ import annotations

from collections.abc import Collection
import unicodedata

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError

MIN_PASSWORD_LENGTH = 15
NEW_PASSWORD_MAX_LENGTH = 256
MAX_PASSWORD_LENGTH = NEW_PASSWORD_MAX_LENGTH  # compatibility alias for new-password policy
VERIFY_MAX_PASSWORD_LENGTH = 4096

DEFAULT_PASSWORD_BLOCKLIST = frozenset({
    "passwordpassword", "password123456", "qwertyqwerty123",
    "123456789012345", "adminadminadmin1", "letmeinletmein123",
})
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def normalize_new_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Пароль обязателен")
    return unicodedata.normalize("NFC", password)


def validate_password(password: str, *, blocklist: Collection[str] | None = None) -> None:
    normalized = normalize_new_password(password)
    if len(normalized) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Пароль должен содержать минимум {MIN_PASSWORD_LENGTH} символов")
    if len(normalized) > NEW_PASSWORD_MAX_LENGTH:
        raise ValueError(f"Пароль не должен превышать {NEW_PASSWORD_MAX_LENGTH} символов")
    denied = (
        DEFAULT_PASSWORD_BLOCKLIST
        if blocklist is None
        else frozenset(str(x).strip().casefold() for x in blocklist)
    )
    if normalized.strip().casefold() in denied:
        raise ValueError("Пароль запрещён локальной политикой")


def hash_password(password: str, *, blocklist: Collection[str] | None = None) -> str:
    normalized = normalize_new_password(password)
    validate_password(normalized, blocklist=blocklist)
    return _HASHER.hash(normalized)


def hash_verified_password_for_rehash(password: str) -> str:
    """Rehash an already verified legacy password without changing its semantics."""
    if not isinstance(password, str) or len(password) > VERIFY_MAX_PASSWORD_LENGTH:
        raise ValueError("legacy password cannot be safely rehashed")
    return _HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    if not isinstance(password, str) or len(password) > VERIFY_MAX_PASSWORD_LENGTH:
        return False
    try:
        return bool(_HASHER.verify(stored_hash, password))
    except (VerifyMismatchError, VerificationError, ValueError, TypeError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    try:
        return bool(_HASHER.check_needs_rehash(stored_hash))
    except (ValueError, TypeError):
        return True
