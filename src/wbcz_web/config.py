from __future__ import annotations

from dataclasses import dataclass, field
import os
import re

from sqlalchemy.engine import make_url

from wbcz.control_engine import validate_owner_inn
from wbcz.document_assembler import OrganisationType, P0OrganisationConfig


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


def _env_optional_bool(name: str) -> bool | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true, false or unset")


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
    agent_enabled: bool = False
    agent_machine_token: str | None = None
    agent_job_lease_seconds: int = 90
    agent_poll_initial_seconds: int = 10
    agent_poll_max_seconds: int = 120
    agent_poll_max_attempts: int = 60
    agent_legacy_bootstrap_enabled: bool = True
    agent_health_online_seconds: int = 120
    agent_health_stale_seconds: int = 600
    integration_check_cooldown_seconds: int = 30
    integration_check_user_limit_per_minute: int = 10
    certificate_expiry_critical_days: int = 7
    certificate_expiry_soon_days: int = 30
    true_api_write_enabled: bool = False
    true_api_reports_enabled: bool = False
    report_artifact_root: str | None = None
    report_temp_root: str | None = None
    report_artifact_key_version: str = "m11-v1"
    report_max_local_rows: int = 1_000_000
    report_max_artifact_bytes: int = 2 * 1024 * 1024 * 1024
    report_remote_download_byte_ceiling: int = 2 * 1024 * 1024 * 1024
    report_db_fetch_batch_size: int = 500
    report_snapshot_timeout_seconds: int = 900
    report_worker_timeout_seconds: int = 1800
    report_temp_storage_ceiling_bytes: int = 2 * 1024 * 1024 * 1024
    report_min_free_disk_bytes: int = 64 * 1024 * 1024
    organisation_type: OrganisationType | None = None
    activity_fias_id: str | None = None
    activity_kpp: str | None = None
    remote_sale_return_paid: bool | None = None
    session_idle_timeout_seconds: int = 30 * 60
    login_throttle_window_seconds: int = 15 * 60
    login_throttle_max_failures: int = 10
    password_history_count: int = 5
    public_registration_enabled: bool = False
    login_account_free_failures: int = 5
    login_account_initial_delay_seconds: int = 30
    login_account_delay_cap_seconds: int = 15 * 60
    login_account_lock_failures: int = 100
    audit_pseudonym_key: str | None = None
    audit_pseudonym_key_id: str = "audit-v1"
    m15_strict_production: bool = False
    process_role: str = "web"
    app_url: str | None = None
    migration_database_url: str | None = None
    trusted_proxy_cidrs: tuple[str, ...] = ()
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_pool_timeout_seconds: int = 30
    db_pool_recycle_seconds: int = 1800
    db_statement_timeout_ms: int = 30000
    db_lock_timeout_ms: int = 5000
    db_idle_transaction_timeout_ms: int = 60000
    db_application_name: str = "wbcz-web"
    worker_concurrency: int = 1
    worker_heartbeat_seconds: int = 15
    worker_stale_seconds: int = 90
    worker_lease_seconds: int = 120
    scheduler_interval_seconds: int = 30
    scheduler_max_age_seconds: int = 86400
    secret_provider_root: str | None = None
    secret_provider_master_key_path: str | None = None
    artifact_keyring_root: str | None = None
    audit_key_path: str | None = None
    backup_status_path: str | None = None
    normal_json_body_limit_bytes: int = 1024 * 1024
    max_active_sessions_per_user: int = 10
    agent_enrollment_ttl_seconds: int = 600
    agent_protocol_current: str = "m15-v1"
    agent_protocol_minimum: str = "m14-v1"
    agent_minimum_version: str = "0.5.1"

    def organisation_document_config(self) -> P0OrganisationConfig | None:
        if self.organisation_type is None:
            return None
        if self.activity_fias_id is None:
            raise ValueError("WBCZ_ACTIVITY_FIAS_ID is required when organisation type is configured")
        return P0OrganisationConfig(
            participant_inn=self.own_inn,
            organisation_type=self.organisation_type,
            fias_id=self.activity_fias_id,
            kpp=self.activity_kpp,
            remote_sale_return_paid=self.remote_sale_return_paid,
        )

    def validate_for_startup(self) -> "WebConfig":
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("WBCZ_ENV must be development, test or production")
        if not self.database_url.startswith("postgresql+") and not self.database_url.startswith("postgresql://"):
            raise ValueError("Web v0.5.1 requires PostgreSQL; SQLite is not supported")
        validate_owner_inn(self.own_inn)
        if self.session_ttl_seconds < 300 or self.session_ttl_seconds > 30 * 24 * 60 * 60:
            raise ValueError("WBCZ_SESSION_TTL_SECONDS is out of range")
        if self.session_idle_timeout_seconds < 300 or self.session_idle_timeout_seconds > self.session_ttl_seconds:
            raise ValueError("WBCZ_SESSION_IDLE_TIMEOUT_SECONDS is out of range")
        if not 60 <= self.login_throttle_window_seconds <= 24 * 60 * 60:
            raise ValueError("WBCZ_LOGIN_THROTTLE_WINDOW_SECONDS is out of range")
        if not 3 <= self.login_throttle_max_failures <= 100:
            raise ValueError("WBCZ_LOGIN_THROTTLE_MAX_FAILURES is out of range")
        if not 1 <= self.password_history_count <= 24:
            raise ValueError("WBCZ_PASSWORD_HISTORY_COUNT is out of range")
        if self.login_account_free_failures != 5:
            raise ValueError("WBCZ_LOGIN_ACCOUNT_FREE_FAILURES must remain 5 for M12")
        if not 1 <= self.login_account_initial_delay_seconds <= 60:
            raise ValueError("WBCZ_LOGIN_ACCOUNT_INITIAL_DELAY_SECONDS is out of range")
        if self.login_account_delay_cap_seconds < self.login_account_initial_delay_seconds or self.login_account_delay_cap_seconds > 15 * 60:
            raise ValueError("WBCZ_LOGIN_ACCOUNT_DELAY_CAP_SECONDS is out of range")
        if self.login_account_lock_failures != 100:
            raise ValueError("WBCZ_LOGIN_ACCOUNT_LOCK_FAILURES must remain 100 for M12")
        if self.public_registration_enabled:
            raise ValueError("Public registration runtime remains disabled in M12")
        if self.audit_pseudonym_key is not None and len(self.audit_pseudonym_key.encode("utf-8")) < 32:
            raise ValueError("WBCZ_AUDIT_PSEUDONYM_KEY must be at least 32 UTF-8 bytes")
        if not self.audit_pseudonym_key_id or len(self.audit_pseudonym_key_id) > 64:
            raise ValueError("WBCZ_AUDIT_PSEUDONYM_KEY_ID is invalid")
        if not self.session_cookie_name or not self.csrf_cookie_name:
            raise ValueError("Cookie names must not be empty")
        if self.session_cookie_name == self.csrf_cookie_name:
            raise ValueError("Session and CSRF cookie names must differ")
        if not self.trusted_hosts:
            raise ValueError("WBCZ_TRUSTED_HOSTS must not be empty")
        if not 15 <= self.agent_job_lease_seconds <= 60 * 60:
            raise ValueError("WBCZ_AGENT_JOB_LEASE_SECONDS is out of range")
        if not 1 <= self.agent_poll_initial_seconds <= 60 * 60:
            raise ValueError("WBCZ_AGENT_POLL_INITIAL_SECONDS is out of range")
        if self.agent_poll_max_seconds < self.agent_poll_initial_seconds or self.agent_poll_max_seconds > 24 * 60 * 60:
            raise ValueError("WBCZ_AGENT_POLL_MAX_SECONDS is out of range")
        if not 1 <= self.agent_poll_max_attempts <= 1000:
            raise ValueError("WBCZ_AGENT_POLL_MAX_ATTEMPTS is out of range")
        if not 1 <= self.agent_health_online_seconds < self.agent_health_stale_seconds <= 86400:
            raise ValueError("M14 agent health thresholds are invalid")
        if not 1 <= self.integration_check_cooldown_seconds <= 3600:
            raise ValueError("WBCZ_INTEGRATION_CHECK_COOLDOWN_SECONDS is out of range")
        if not 1 <= self.integration_check_user_limit_per_minute <= 100:
            raise ValueError("WBCZ_INTEGRATION_CHECK_USER_LIMIT_PER_MINUTE is out of range")
        if not 1 <= self.certificate_expiry_critical_days < self.certificate_expiry_soon_days <= 365:
            raise ValueError("M14 certificate expiry thresholds are invalid")
        if self.true_api_write_enabled:
            raise ValueError("Production True API write remains disabled pending runtime contract tests")
        if self.true_api_reports_enabled and not self.agent_enabled:
            raise ValueError("True API reports require the Windows agent boundary")
        if self.report_artifact_root is not None and not self.report_artifact_root.strip():
            raise ValueError("WBCZ_REPORT_ARTIFACT_ROOT must be non-empty when configured")
        if self.report_temp_root is not None and not self.report_temp_root.strip():
            raise ValueError("WBCZ_REPORT_TEMP_ROOT must be non-empty when configured")
        if not self.report_artifact_key_version.strip():
            raise ValueError("WBCZ_REPORT_ARTIFACT_KEY_VERSION must not be empty")
        report_limits = {
            "WBCZ_REPORT_MAX_LOCAL_ROWS": self.report_max_local_rows,
            "WBCZ_REPORT_MAX_ARTIFACT_BYTES": self.report_max_artifact_bytes,
            "WBCZ_REPORT_REMOTE_DOWNLOAD_BYTE_CEILING": self.report_remote_download_byte_ceiling,
            "WBCZ_REPORT_DB_FETCH_BATCH_SIZE": self.report_db_fetch_batch_size,
            "WBCZ_REPORT_SNAPSHOT_TIMEOUT_SECONDS": self.report_snapshot_timeout_seconds,
            "WBCZ_REPORT_WORKER_TIMEOUT_SECONDS": self.report_worker_timeout_seconds,
            "WBCZ_REPORT_TEMP_STORAGE_CEILING_BYTES": self.report_temp_storage_ceiling_bytes,
            "WBCZ_REPORT_MIN_FREE_DISK_BYTES": self.report_min_free_disk_bytes,
        }
        for name, value in report_limits.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.report_db_fetch_batch_size > 100_000:
            raise ValueError("WBCZ_REPORT_DB_FETCH_BATCH_SIZE is out of range")
        if self.report_snapshot_timeout_seconds > 24 * 60 * 60:
            raise ValueError("WBCZ_REPORT_SNAPSHOT_TIMEOUT_SECONDS is out of range")
        if self.report_worker_timeout_seconds > 7 * 24 * 60 * 60:
            raise ValueError("WBCZ_REPORT_WORKER_TIMEOUT_SECONDS is out of range")
        if self.organisation_type is None:
            if self.activity_fias_id or self.activity_kpp or self.remote_sale_return_paid is not None:
                raise ValueError("WBCZ_ORGANISATION_TYPE is required when P0 organisation fields are configured")
        else:
            self.organisation_document_config()
        if self.agent_enabled and self.agent_legacy_bootstrap_enabled:
            token = self.agent_machine_token or ""
            minimum = 32 if self.environment == "production" else 16
            if len(token) < minimum:
                raise ValueError(f"WBCZ_AGENT_MACHINE_TOKEN must be at least {minimum} characters when legacy bootstrap is enabled")
            normalized = token.strip().lower()
            if normalized in {"changeme", "change_me", "password", "secret", "agent-token", "replace_me"} or "replace_with" in normalized:
                raise ValueError("WBCZ_AGENT_MACHINE_TOKEN is an unsafe placeholder")
        if self.environment == "production":
            if not self.audit_pseudonym_key:
                raise ValueError("WBCZ_AUDIT_PSEUDONYM_KEY is required in production")
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
        if self.environment == "production" and self.m15_strict_production:
            self.validate_m15_production_runtime()
        return self

    def validate_m15_production_runtime(self) -> "WebConfig":
        if self.environment != "production":
            return self
        if self.process_role not in {"web", "worker"}:
            raise ValueError("WBCZ_PROCESS_ROLE must be web or worker")
        if not self.app_url or not self.app_url.startswith("https://"):
            raise ValueError("WBCZ_APP_URL must be an https URL in strict production")
        if self.migration_database_url and self.migration_database_url == self.database_url:
            raise ValueError("runtime and migrator database credentials must be separated")
        if not self.trusted_proxy_cidrs:
            raise ValueError("WBCZ_TRUSTED_PROXY_CIDRS is required in strict production")
        if self.agent_legacy_bootstrap_enabled:
            raise ValueError("WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED must be false after M15 cutover")
        if self.agent_machine_token:
            raise ValueError("WBCZ_AGENT_MACHINE_TOKEN global bootstrap is forbidden after M15 cutover")
        required_paths = {
            "WBCZ_REPORT_ARTIFACT_ROOT": self.report_artifact_root,
            "WBCZ_REPORT_TEMP_ROOT": self.report_temp_root,
            "WBCZ_SECRET_PROVIDER_ROOT": self.secret_provider_root,
            "WBCZ_SECRET_PROVIDER_MASTER_KEY_PATH": self.secret_provider_master_key_path,
            "WBCZ_ARTIFACT_KEYRING_ROOT": self.artifact_keyring_root,
            "WBCZ_AUDIT_KEY_PATH": self.audit_key_path,
            "WBCZ_BACKUP_STATUS_PATH": self.backup_status_path,
        }
        missing = [name for name, value in required_paths.items() if not value]
        if missing:
            raise ValueError("strict production paths missing: " + ",".join(sorted(missing)))
        ints = {
            "WBCZ_DB_POOL_SIZE": self.db_pool_size,
            "WBCZ_DB_POOL_TIMEOUT_SECONDS": self.db_pool_timeout_seconds,
            "WBCZ_DB_POOL_RECYCLE_SECONDS": self.db_pool_recycle_seconds,
            "WBCZ_DB_STATEMENT_TIMEOUT_MS": self.db_statement_timeout_ms,
            "WBCZ_DB_LOCK_TIMEOUT_MS": self.db_lock_timeout_ms,
            "WBCZ_DB_IDLE_TRANSACTION_TIMEOUT_MS": self.db_idle_transaction_timeout_ms,
            "WBCZ_WORKER_CONCURRENCY": self.worker_concurrency,
            "WBCZ_WORKER_HEARTBEAT_SECONDS": self.worker_heartbeat_seconds,
            "WBCZ_WORKER_STALE_SECONDS": self.worker_stale_seconds,
            "WBCZ_WORKER_LEASE_SECONDS": self.worker_lease_seconds,
            "WBCZ_SCHEDULER_INTERVAL_SECONDS": self.scheduler_interval_seconds,
            "WBCZ_AGENT_ENROLLMENT_TTL_SECONDS": self.agent_enrollment_ttl_seconds,
            "WBCZ_NORMAL_JSON_BODY_LIMIT_BYTES": self.normal_json_body_limit_bytes,
            "WBCZ_MAX_ACTIVE_SESSIONS_PER_USER": self.max_active_sessions_per_user,
        }
        if any(type(value) is not int or value <= 0 for value in ints.values()):
            raise ValueError("M15 production numeric settings must be positive integers")
        if self.worker_stale_seconds <= self.worker_heartbeat_seconds:
            raise ValueError("worker stale threshold must exceed heartbeat interval")
        if self.worker_lease_seconds <= self.worker_heartbeat_seconds:
            raise ValueError("worker lease must exceed heartbeat interval")
        if self.db_max_overflow < 0:
            raise ValueError("WBCZ_DB_MAX_OVERFLOW must be non-negative")
        if not re.fullmatch(r"m\d+-v\d+", self.agent_protocol_current):
            raise ValueError("WBCZ_AGENT_PROTOCOL_CURRENT is invalid")
        if not re.fullmatch(r"m\d+-v\d+", self.agent_protocol_minimum):
            raise ValueError("WBCZ_AGENT_PROTOCOL_MINIMUM is invalid")
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
        token = os.getenv("WBCZ_AGENT_MACHINE_TOKEN", "")
        organisation_raw = os.getenv("WBCZ_ORGANISATION_TYPE", "").strip().upper()
        try:
            organisation_type = OrganisationType(organisation_raw) if organisation_raw else None
        except ValueError as exc:
            raise ValueError("WBCZ_ORGANISATION_TYPE must be LEGAL_ENTITY or INDIVIDUAL_ENTREPRENEUR") from exc
        fias_id = os.getenv("WBCZ_ACTIVITY_FIAS_ID", "").strip() or None
        kpp = os.getenv("WBCZ_ACTIVITY_KPP", "").strip() or None
        config = cls(
            database_url=db,
            own_inn=own_inn,
            environment=env,
            session_ttl_seconds=ttl,
            session_idle_timeout_seconds=int(os.getenv("WBCZ_SESSION_IDLE_TIMEOUT_SECONDS", "1800")),
            login_throttle_window_seconds=int(os.getenv("WBCZ_LOGIN_THROTTLE_WINDOW_SECONDS", "900")),
            login_throttle_max_failures=int(os.getenv("WBCZ_LOGIN_THROTTLE_MAX_FAILURES", "10")),
            password_history_count=int(os.getenv("WBCZ_PASSWORD_HISTORY_COUNT", "5")),
            public_registration_enabled=_env_bool("WBCZ_PUBLIC_REGISTRATION_ENABLED", False),
            login_account_free_failures=int(os.getenv("WBCZ_LOGIN_ACCOUNT_FREE_FAILURES", "5")),
            login_account_initial_delay_seconds=int(os.getenv("WBCZ_LOGIN_ACCOUNT_INITIAL_DELAY_SECONDS", "30")),
            login_account_delay_cap_seconds=int(os.getenv("WBCZ_LOGIN_ACCOUNT_DELAY_CAP_SECONDS", "900")),
            login_account_lock_failures=int(os.getenv("WBCZ_LOGIN_ACCOUNT_LOCK_FAILURES", "100")),
            audit_pseudonym_key=os.getenv("WBCZ_AUDIT_PSEUDONYM_KEY", "").strip() or None,
            audit_pseudonym_key_id=os.getenv("WBCZ_AUDIT_PSEUDONYM_KEY_ID", "audit-v1").strip() or "audit-v1",
            m15_strict_production=_env_bool("WBCZ_M15_STRICT_PRODUCTION", False),
            process_role=os.getenv("WBCZ_PROCESS_ROLE", "web").strip().lower() or "web",
            app_url=os.getenv("WBCZ_APP_URL", "").strip() or None,
            migration_database_url=os.getenv("WBCZ_MIGRATION_DATABASE_URL", "").strip() or None,
            trusted_proxy_cidrs=_csv_hosts(os.getenv("WBCZ_TRUSTED_PROXY_CIDRS", "")),
            db_pool_size=int(os.getenv("WBCZ_DB_POOL_SIZE", "5")),
            db_max_overflow=int(os.getenv("WBCZ_DB_MAX_OVERFLOW", "5")),
            db_pool_timeout_seconds=int(os.getenv("WBCZ_DB_POOL_TIMEOUT_SECONDS", "30")),
            db_pool_recycle_seconds=int(os.getenv("WBCZ_DB_POOL_RECYCLE_SECONDS", "1800")),
            db_statement_timeout_ms=int(os.getenv("WBCZ_DB_STATEMENT_TIMEOUT_MS", "30000")),
            db_lock_timeout_ms=int(os.getenv("WBCZ_DB_LOCK_TIMEOUT_MS", "5000")),
            db_idle_transaction_timeout_ms=int(os.getenv("WBCZ_DB_IDLE_TRANSACTION_TIMEOUT_MS", "60000")),
            db_application_name=os.getenv("WBCZ_DB_APPLICATION_NAME", "wbcz-web").strip() or "wbcz-web",
            worker_concurrency=int(os.getenv("WBCZ_WORKER_CONCURRENCY", "1")),
            worker_heartbeat_seconds=int(os.getenv("WBCZ_WORKER_HEARTBEAT_SECONDS", "15")),
            worker_stale_seconds=int(os.getenv("WBCZ_WORKER_STALE_SECONDS", "90")),
            worker_lease_seconds=int(os.getenv("WBCZ_WORKER_LEASE_SECONDS", "120")),
            scheduler_interval_seconds=int(os.getenv("WBCZ_SCHEDULER_INTERVAL_SECONDS", "30")),
            scheduler_max_age_seconds=int(os.getenv("WBCZ_SCHEDULER_MAX_AGE_SECONDS", "86400")),
            secret_provider_root=os.getenv("WBCZ_SECRET_PROVIDER_ROOT", "").strip() or None,
            secret_provider_master_key_path=os.getenv("WBCZ_SECRET_PROVIDER_MASTER_KEY_PATH", "").strip() or None,
            artifact_keyring_root=os.getenv("WBCZ_ARTIFACT_KEYRING_ROOT", "").strip() or None,
            audit_key_path=os.getenv("WBCZ_AUDIT_KEY_PATH", "").strip() or None,
            backup_status_path=os.getenv("WBCZ_BACKUP_STATUS_PATH", "").strip() or None,
            normal_json_body_limit_bytes=int(os.getenv("WBCZ_NORMAL_JSON_BODY_LIMIT_BYTES", str(1024 * 1024))),
            max_active_sessions_per_user=int(os.getenv("WBCZ_MAX_ACTIVE_SESSIONS_PER_USER", "10")),
            agent_enrollment_ttl_seconds=int(os.getenv("WBCZ_AGENT_ENROLLMENT_TTL_SECONDS", "600")),
            agent_protocol_current=os.getenv("WBCZ_AGENT_PROTOCOL_CURRENT", "m15-v1").strip() or "m15-v1",
            agent_protocol_minimum=os.getenv("WBCZ_AGENT_PROTOCOL_MINIMUM", "m14-v1").strip() or "m14-v1",
            agent_minimum_version=os.getenv("WBCZ_AGENT_MINIMUM_VERSION", "0.5.1").strip() or "0.5.1",
            cookie_secure=secure,
            session_cookie_name=os.getenv("WBCZ_SESSION_COOKIE_NAME", "wbcz_session").strip(),
            csrf_cookie_name=os.getenv("WBCZ_CSRF_COOKIE_NAME", "wbcz_csrf").strip(),
            debug=debug,
            trusted_hosts=_csv_hosts(trusted_raw),
            app_version=os.getenv("WBCZ_APP_VERSION", "0.5.1").strip() or "0.5.1",
            build_sha=os.getenv("WBCZ_BUILD_SHA", "dev").strip(),
            agent_enabled=_env_bool("WBCZ_AGENT_ENABLED", False),
            agent_machine_token=token if token else None,
            agent_job_lease_seconds=int(os.getenv("WBCZ_AGENT_JOB_LEASE_SECONDS", "90")),
            agent_poll_initial_seconds=int(os.getenv("WBCZ_AGENT_POLL_INITIAL_SECONDS", "10")),
            agent_poll_max_seconds=int(os.getenv("WBCZ_AGENT_POLL_MAX_SECONDS", "120")),
            agent_poll_max_attempts=int(os.getenv("WBCZ_AGENT_POLL_MAX_ATTEMPTS", "60")),
            agent_legacy_bootstrap_enabled=_env_bool("WBCZ_AGENT_LEGACY_BOOTSTRAP_ENABLED", True),
            agent_health_online_seconds=int(os.getenv("WBCZ_AGENT_HEALTH_ONLINE_SECONDS", "120")),
            agent_health_stale_seconds=int(os.getenv("WBCZ_AGENT_HEALTH_STALE_SECONDS", "600")),
            integration_check_cooldown_seconds=int(os.getenv("WBCZ_INTEGRATION_CHECK_COOLDOWN_SECONDS", "30")),
            integration_check_user_limit_per_minute=int(os.getenv("WBCZ_INTEGRATION_CHECK_USER_LIMIT_PER_MINUTE", "10")),
            certificate_expiry_critical_days=int(os.getenv("WBCZ_CERTIFICATE_EXPIRY_CRITICAL_DAYS", "7")),
            certificate_expiry_soon_days=int(os.getenv("WBCZ_CERTIFICATE_EXPIRY_SOON_DAYS", "30")),
            true_api_write_enabled=_env_bool("WBCZ_TRUE_API_WRITE_ENABLED", False),
            true_api_reports_enabled=_env_bool("WBCZ_TRUE_API_REPORTS_ENABLED", False),
            report_artifact_root=os.getenv("WBCZ_REPORT_ARTIFACT_ROOT", "").strip() or None,
            report_temp_root=os.getenv("WBCZ_REPORT_TEMP_ROOT", "").strip() or None,
            report_artifact_key_version=os.getenv("WBCZ_REPORT_ARTIFACT_KEY_VERSION", "m11-v1").strip() or "m11-v1",
            report_max_local_rows=int(os.getenv("WBCZ_REPORT_MAX_LOCAL_ROWS", "1000000")),
            report_max_artifact_bytes=int(os.getenv("WBCZ_REPORT_MAX_ARTIFACT_BYTES", str(2 * 1024 * 1024 * 1024))),
            report_remote_download_byte_ceiling=int(os.getenv("WBCZ_REPORT_REMOTE_DOWNLOAD_BYTE_CEILING", str(2 * 1024 * 1024 * 1024))),
            report_db_fetch_batch_size=int(os.getenv("WBCZ_REPORT_DB_FETCH_BATCH_SIZE", "500")),
            report_snapshot_timeout_seconds=int(os.getenv("WBCZ_REPORT_SNAPSHOT_TIMEOUT_SECONDS", "900")),
            report_worker_timeout_seconds=int(os.getenv("WBCZ_REPORT_WORKER_TIMEOUT_SECONDS", "1800")),
            report_temp_storage_ceiling_bytes=int(os.getenv("WBCZ_REPORT_TEMP_STORAGE_CEILING_BYTES", str(2 * 1024 * 1024 * 1024))),
            report_min_free_disk_bytes=int(os.getenv("WBCZ_REPORT_MIN_FREE_DISK_BYTES", str(64 * 1024 * 1024))),
            organisation_type=organisation_type,
            activity_fias_id=fias_id,
            activity_kpp=kpp,
            remote_sale_return_paid=_env_optional_bool("WBCZ_REMOTE_SALE_RETURN_PAID"),
        )
        return config.validate_for_startup()
