from __future__ import annotations

from dataclasses import dataclass
import os
import re

from sqlalchemy.engine import make_url

from wbcz.control_engine import validate_owner_inn


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def _csv_hosts(raw: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(part.strip() for part in raw.split(",") if part.strip()))


@dataclass(frozen=True, slots=True)
class WebConfig:
    database_url: str
    own_inn: str
    environment: str = "development"
    session_ttl_seconds: int = 12 * 60 * 60
    cookie_secure: bool = False
    session_cookie_name: str = "wbcz_session"
    csrf_cookie_name: str = "wbcz_csrf"
    debug: bool = False
    trusted_hosts: tuple[str, ...] = ("testserver", "localhost", "127.0.0.1")
    app_version: str = "0.5.1"
    build_sha: str = "dev"

    def validate_for_startup(self) -> "WebConfig":
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("WBCZ_ENV must be development, test or production")
        if not self.database_url.startswith("postgresql+") and not self.database_url.startswith("postgresql://"):
            raise ValueError("Web v0.5.1 requires PostgreSQL; SQLite is not supported")
        validate_owner_inn(self.own_inn)
        if self.session_ttl_seconds < 300 or self.session_ttl_seconds > 30 * 24 * 60 * 60:
            raise ValueError("WBCZ_SESSION_TTL_SECONDS is out of range")
        if not self.session_cookie_name or not self.csrf_cookie_name:
            raise ValueError("Cookie names must not be empty")
        if self.session_cookie_name == self.csrf_cookie_name:
            raise ValueError("Session and CSRF cookie names must differ")
        if not self.trusted_hosts:
            raise ValueError("WBCZ_TRUSTED_HOSTS must not be empty")
        if self.environment == "production":
            if not self.cookie_secure:
                raise ValueError("WBCZ_COOKIE_SECURE must be true in production")
            if self.debug:
                raise ValueError("WBCZ_DEBUG must be false in production")
            if "*" in self.trusted_hosts:
                raise ValueError("Wildcard trusted hosts are forbidden in production")
            if not re.fullmatch(r"[0-9a-fA-F]{7,64}", self.build_sha):
                raise ValueError("WBCZ_BUILD_SHA must be a real git/build SHA in production")
            url = make_url(self.database_url)
            if not url.username or not url.password or not url.host or not url.database:
                raise ValueError("Production WBCZ_DATABASE_URL must include user, password, host and database")
            password = str(url.password).strip().lower()
            if not password or password in {"password", "postgres", "wbcz", "changeme", "change_me"} or "replace_with" in password:
                raise ValueError("Production database password is missing or unsafe placeholder")
        return self

    @classmethod
    def from_env(cls) -> "WebConfig":
        env = os.getenv("WBCZ_ENV", "development").strip().lower()
        db = os.getenv("WBCZ_DATABASE_URL", "").strip()
        if not db:
            if env == "production":
                raise ValueError("WBCZ_DATABASE_URL is required in production")
            db = "postgresql+psycopg://wbcz:wbcz_dev@127.0.0.1:5433/wbcz"
        own_inn = os.getenv("WBCZ_OWN_INN", "1234567890" if env != "production" else "").strip()
        ttl = int(os.getenv("WBCZ_SESSION_TTL_SECONDS", str(12 * 60 * 60)))
        secure = _env_bool("WBCZ_COOKIE_SECURE", env == "production")
        debug = _env_bool("WBCZ_DEBUG", False)
        trusted_raw = os.getenv("WBCZ_TRUSTED_HOSTS", "").strip()
        if not trusted_raw:
            if env == "production":
                raise ValueError("WBCZ_TRUSTED_HOSTS is required in production")
            trusted_raw = "testserver,localhost,127.0.0.1"
        config = cls(
            database_url=db,
            own_inn=own_inn,
            environment=env,
            session_ttl_seconds=ttl,
            cookie_secure=secure,
            session_cookie_name=os.getenv("WBCZ_SESSION_COOKIE_NAME", "wbcz_session").strip(),
            csrf_cookie_name=os.getenv("WBCZ_CSRF_COOKIE_NAME", "wbcz_csrf").strip(),
            debug=debug,
            trusted_hosts=_csv_hosts(trusted_raw),
            app_version=os.getenv("WBCZ_APP_VERSION", "0.5.1").strip() or "0.5.1",
            build_sha=os.getenv("WBCZ_BUILD_SHA", "dev").strip(),
        )
        return config.validate_for_startup()
