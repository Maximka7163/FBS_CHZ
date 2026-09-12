from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16, type=Type.ID)


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Пароль должен содержать минимум 12 символов")
    return _HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return bool(_HASHER.verify(stored_hash, password))
    except (VerifyMismatchError, VerificationError, ValueError):
        return False
