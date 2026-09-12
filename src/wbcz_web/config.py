from __future__ import annotations

from dataclasses import dataclass
import os

from wbcz.control_engine import validate_owner_inn


@dataclass(frozen=True, slots=True)
class WebConfig:
    database_url: str
    own_inn: str
    environment: str = "development"
    session_ttl_seconds: int = 12 * 60 * 60
    cookie_secure: bool = False
    session_cookie_name: str = "wbcz_session"
    csrf_cookie_name: str = "wbcz_csrf"

    @classmethod
    def from_env(cls) -> "WebConfig":
        env = os.getenv("WBCZ_ENV", "development").strip().lower()
        if env not in {"development", "test", "production"}:
            raise ValueError("WBCZ_ENV must be development, test or production")
        db = os.getenv("WBCZ_DATABASE_URL", "").strip()
        if not db:
            if env == "production":
                raise ValueError("WBCZ_DATABASE_URL is required in production")
            db = "postgresql+psycopg://wbcz:wbcz_dev@127.0.0.1:5433/wbcz"
        if not db.startswith("postgresql+") and not db.startswith("postgresql://"):
            raise ValueError("Web v0.5 requires PostgreSQL; SQLite is not supported")
        own_inn = os.getenv("WBCZ_OWN_INN", "1234567890" if env != "production" else "").strip()
        validate_owner_inn(own_inn)
        ttl = int(os.getenv("WBCZ_SESSION_TTL_SECONDS", str(12 * 60 * 60)))
        if ttl < 300 or ttl > 30 * 24 * 60 * 60:
            raise ValueError("WBCZ_SESSION_TTL_SECONDS is out of range")
        return cls(database_url=db, own_inn=own_inn, environment=env, session_ttl_seconds=ttl, cookie_secure=env == "production")
