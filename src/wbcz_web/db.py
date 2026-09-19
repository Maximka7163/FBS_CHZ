from __future__ import annotations

from collections.abc import Iterator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import WebConfig


def _postgres_options(config: WebConfig) -> str:
    app_name = "".join(ch for ch in config.db_application_name if ch.isalnum() or ch in "._-")[:63] or "wbcz"
    return " ".join((
        f"-c statement_timeout={int(config.db_statement_timeout_ms)}",
        f"-c lock_timeout={int(config.db_lock_timeout_ms)}",
        f"-c idle_in_transaction_session_timeout={int(config.db_idle_transaction_timeout_ms)}",
        f"-c application_name={app_name}",
    ))


def build_engine(config: WebConfig):
    kwargs = dict(
        pool_pre_ping=True,
        pool_size=int(config.db_pool_size),
        max_overflow=int(config.db_max_overflow),
        pool_timeout=float(config.db_pool_timeout_seconds),
        pool_recycle=int(config.db_pool_recycle_seconds),
        future=True,
    )
    if config.database_url.startswith("postgresql"):
        kwargs["connect_args"] = {"options": _postgres_options(config)}
    return create_engine(config.database_url, **kwargs)


def build_session_factory(config: WebConfig):
    return sessionmaker(bind=build_engine(config), expire_on_commit=False, class_=Session)


def session_scope(factory) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
