from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from wbcz_web.auth import (
    hash_password,
    hash_verified_password_for_rehash,
    new_session_token,
    normalize_new_password,
    password_needs_rehash,
    token_hash,
    verify_password,
)
from wbcz_web.config import WebConfig
from wbcz_web.models import (
    LoginAttemptRecord,
    LoginThrottleStateRecord,
    PasswordHistoryRecord,
    SessionRecord,
    User,
)
from wbcz_web.repositories import AuditRepository, SessionRepository, UserRepository


class AuthenticationError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: str | None) -> str:
    return hashlib.sha256((value or "").encode()).hexdigest()


class AuthService:
    def __init__(self, db: Session, config: WebConfig) -> None:
        self.db = db
        self.config = config
        self.users = UserRepository(db)
        self.sessions = SessionRepository(db)
        self.audit = AuditRepository(db)

    def _source_throttled(self, remote: str | None) -> bool:
        if not remote:
            return False
        cutoff = _now() - timedelta(seconds=self.config.login_throttle_window_seconds)
        failed = self.db.scalar(
            select(func.count())
            .select_from(LoginAttemptRecord)
            .where(
                LoginAttemptRecord.attempted_at >= cutoff,
                LoginAttemptRecord.successful.is_(False),
                LoginAttemptRecord.remote_hash == _digest(remote),
            )
        )
        return int(failed or 0) >= self.config.login_throttle_max_failures

    def _attempt(self, username: str, remote: str | None, success: bool) -> None:
        self.db.add(
            LoginAttemptRecord(
                username_hash=_digest(username.casefold()),
                remote_hash=_digest(remote),
                successful=success,
                attempted_at=_now(),
            )
        )
        self.db.flush()

    def _account_state(self, user_id: int, *, lock: bool = True) -> LoginThrottleStateRecord:
        stmt = select(LoginThrottleStateRecord).where(LoginThrottleStateRecord.user_id == user_id)
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            row = LoginThrottleStateRecord(user_id=user_id, consecutive_failures=0, password_locked=False)
            self.db.add(row)
            self.db.flush()
        return row

    def _delay_seconds(self, failures: int) -> int:
        free = self.config.login_account_free_failures
        if failures <= free:
            return 0
        step = min(failures - free - 1, 16)
        delay = self.config.login_account_initial_delay_seconds * (2 ** step)
        return min(delay, self.config.login_account_delay_cap_seconds)

    def _account_is_blocked(self, state: LoginThrottleStateRecord, *, now: datetime) -> bool:
        if state.password_locked:
            return True
        return state.blocked_until is not None and state.blocked_until > now

    def _record_account_failure(self, state: LoginThrottleStateRecord, *, now: datetime) -> None:
        state.consecutive_failures = int(state.consecutive_failures or 0) + 1
        state.last_failure_at = now
        if state.consecutive_failures >= self.config.login_account_lock_failures:
            state.password_locked = True
            state.blocked_until = None
        else:
            delay = self._delay_seconds(state.consecutive_failures)
            state.blocked_until = now + timedelta(seconds=delay) if delay else None
        self.db.flush()

    def _reset_account_progression(self, state: LoginThrottleStateRecord, *, now: datetime) -> None:
        state.consecutive_failures = 0
        state.blocked_until = None
        state.password_locked = False
        state.last_success_at = now
        self.db.flush()

    def reset_password_authenticator_lock(self, user_id: int, *, actor_user_id: int | None = None) -> None:
        user = self.users.by_id(user_id)
        if user is None:
            raise KeyError("user not found")
        state = self._account_state(user.id, lock=True)
        state.consecutive_failures = 0
        state.blocked_until = None
        state.password_locked = False
        self.db.flush()
        self.audit.append(
            "PASSWORD_AUTHENTICATOR_UNLOCKED",
            user_id=actor_user_id,
            entity_type="user",
            entity_id=str(user.id),
            metadata={"controlled_recovery": True},
        )

    def login(
        self,
        username: str,
        password: str,
        *,
        csrf_token: str | None = None,
        remote_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[User, str]:
        username = username.strip()
        user = self.users.by_username(username)
        if self._source_throttled(remote_address):
            self.audit.append(
                "LOGIN_THROTTLED",
                user_id=user.id if user is not None else None,
                entity_type="user" if user is not None else "auth",
                entity_id=str(user.id) if user is not None else _digest(remote_address),
                metadata={"scope":"source"},
            )
            raise AuthenticationError("Неверный логин или пароль")

        now = _now()
        account_state = self._account_state(user.id, lock=True) if user is not None else None
        if account_state is not None and self._account_is_blocked(account_state, now=now):
            self._attempt(username, remote_address, False)
            self.audit.append("LOGIN_THROTTLED", user_id=user.id, entity_type="user", entity_id=str(user.id), metadata={"scope":"account"})
            raise AuthenticationError("Неверный логин или пароль")

        password_valid = user is not None and verify_password(user.password_hash, password)
        account_active = bool(
            user is not None
            and user.is_active
            and user.account_state == "ACTIVE"
        )
        if not password_valid or user is None or not account_active:
            self._attempt(username, remote_address, False)
            if user is not None and not password_valid and account_state is not None:
                self._record_account_failure(account_state, now=now)
            self.audit.append(
                "LOGIN_FAILED",
                user_id=user.id if user is not None else None,
                entity_type="user" if user is not None else "auth",
                entity_id=str(user.id) if user is not None else _digest(username.casefold()),
            )
            raise AuthenticationError("Неверный логин или пароль")

        assert account_state is not None
        self._reset_account_progression(account_state, now=now)
        self._attempt(username, remote_address, True)

        if password_needs_rehash(user.password_hash):
            try:
                user.password_hash = hash_verified_password_for_rehash(password)
                user.password_changed_at = user.password_changed_at or now
            except ValueError:
                # Legacy verification remains valid even when a historical password
                # exceeds today's new-password policy.
                pass

        token = new_session_token()
        row = SessionRecord(
            user_id=user.id,
            token_hash=token_hash(token),
            csrf_token_hash=token_hash(csrf_token) if csrf_token else None,
            password_version=user.password_version,
            client_ip_hash=_digest(remote_address) if remote_address else None,
            user_agent_hash=_digest(user_agent) if user_agent else None,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=self.config.session_ttl_seconds),
        )
        self.db.add(row)
        self.db.flush()
        self.audit.append("LOGIN_SUCCESS", user_id=user.id, entity_type="session", entity_id=row.id)
        return user, token

    def authenticate_token(self, token: str | None) -> tuple[User, SessionRecord]:
        if not token:
            raise AuthenticationError("Требуется авторизация")
        row = self.sessions.active_by_hash(token_hash(token))
        if row is None:
            raise AuthenticationError("Сессия недействительна")
        now = _now()
        if row.last_seen_at <= now - timedelta(seconds=self.config.session_idle_timeout_seconds):
            self.sessions.revoke(row)
            raise AuthenticationError("Сессия недействительна")
        user = self.users.by_id(row.user_id)
        if (
            user is None
            or not user.is_active
            or user.account_state != "ACTIVE"
            or row.password_version != user.password_version
        ):
            self.sessions.revoke(row)
            raise AuthenticationError("Сессия недействительна")
        row.last_seen_at = now
        self.db.flush()
        return user, row

    def bind_csrf(self, session: SessionRecord, csrf_token: str) -> None:
        session.csrf_token_hash = token_hash(csrf_token)
        self.db.flush()

    def revoke_presented_session(self, raw_token: str | None, *, reason: str) -> None:
        if not raw_token:
            return
        row = self.sessions.active_by_hash(token_hash(raw_token))
        if row is None:
            return
        self.sessions.revoke(row)
        self.audit.append(
            "SESSION_REVOKED",
            user_id=row.user_id,
            entity_type="session",
            entity_id=row.id,
            metadata={"reason": reason[:64]},
        )

    def csrf_matches(self, session: SessionRecord, csrf_token: str) -> bool:
        return bool(session.csrf_token_hash) and session.csrf_token_hash == token_hash(csrf_token)

    def logout(self, session_id: str, user_id: int) -> None:
        row = self.db.get(SessionRecord, session_id)
        if row is not None and row.user_id == user_id and row.revoked_at is None:
            self.sessions.revoke(row)
        self.audit.append("LOGOUT", user_id=user_id, entity_type="session", entity_id=session_id)

    def logout_all(self, user_id: int, *, except_session_id: str | None = None) -> int:
        n = self.sessions.revoke_all_for_user(user_id, except_session_id=except_session_id)
        self.audit.append(
            "LOGOUT_ALL",
            user_id=user_id,
            entity_type="user",
            entity_id=str(user_id),
            metadata={"count": n},
        )
        return n

    def change_password(self, user: User, *, current_password: str, new_password: str) -> None:
        if not verify_password(user.password_hash, current_password):
            raise AuthenticationError("Неверный текущий пароль")
        normalized_new = normalize_new_password(new_password)
        if verify_password(user.password_hash, new_password) or verify_password(user.password_hash, normalized_new):
            raise ValueError("Новый пароль должен отличаться от текущего")
        history = list(
            self.db.scalars(
                select(PasswordHistoryRecord)
                .where(PasswordHistoryRecord.user_id == user.id)
                .order_by(PasswordHistoryRecord.created_at.desc(), PasswordHistoryRecord.id.desc())
                .limit(self.config.password_history_count)
            )
        )
        if any(
            verify_password(item.password_hash, new_password)
            or verify_password(item.password_hash, normalized_new)
            for item in history
        ):
            raise ValueError("Этот пароль недавно использовался")

        new_hash = hash_password(normalized_new)
        self.db.add(PasswordHistoryRecord(user_id=user.id, password_hash=user.password_hash))
        user.password_hash = new_hash
        user.password_changed_at = _now()
        user.password_version += 1
        user.password_must_change = False
        state = self._account_state(user.id, lock=True)
        self._reset_account_progression(state, now=_now())
        revoked = self.sessions.revoke_all_for_user(user.id)
        self.audit.append("PASSWORD_CHANGED", user_id=user.id, entity_type="user", entity_id=str(user.id))
        self.audit.append(
            "SESSION_REVOKED",
            user_id=user.id,
            entity_type="user",
            entity_id=str(user.id),
            metadata={"count": revoked, "reason": "password_changed"},
        )
        self.db.flush()
