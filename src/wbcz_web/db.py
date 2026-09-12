from __future__ import annotations

from collections.abc import Iterator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import WebConfig


def build_engine(config: WebConfig):
    return create_engine(config.database_url, pool_pre_ping=True, future=True)


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
