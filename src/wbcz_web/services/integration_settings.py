from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from wbcz.models import canonical_json
from wbcz.wb_fbs import (
    StatefulWbRateLimiter, WbConnection, WbConnectionState, WbEnvironment, WbReadTransport,
    WbRateLimitExceeded, WbTokenCategory, WbTokenType, runtime_token,
    verify_seller_identity,
)
from wbcz.windows_agent import AgentJob, AgentJobType, AgentResult, P0_PG
from wbcz_web.models import (
    AgentBindingRecord, AgentCertificateObservationRecord, IntegrationHealthCheckRecord,
    OzonConnectionRecord, ParticipantRecord, SuzConnectionRecord, TrueApiConnectionRecord,
    WbConnectionRecord,
)
from wbcz_web.repositories import SqlAlchemyAgentJobStore
from wbcz_web.services.agent_bindings import AgentBindingService
from wbcz_web.services.audit_history import (
    ActorContext, ActorKind, AuditOutcome, AuditService, AuditTenantScope,
    AuthorizationDecision, SubjectRef, SubjectType, TraceContext,
)
from wbcz_web.services.integration_secrets import (
    SecretCapability, SecretProvider, SecretProviderAtomicRotationUnsupported,
    SecretProviderError, SecretProviderWriteUnavailable, StagedSecret,
    require_safe_rotation,
)
from wbcz_web.services.integration_status import (
    capability_projection, certificate_expiry_status,
)
from wbcz_web.services.tenant import active_tenant


ERROR_CODES = frozenset({
    "CONFIG_MISSING","SECRET_MISSING","SECRET_PROVIDER_UNAVAILABLE","SECRET_EXPIRED",
    "AGENT_OFFLINE","AGENT_STALE","AGENT_PROTOCOL_MISMATCH","CERTIFICATE_NOT_FOUND",
    "CERTIFICATE_NO_PRIVATE_KEY","CERTIFICATE_EXPIRED","CERTIFICATE_NOT_YET_VALID",
    "CERTIFICATE_PARTICIPANT_MISMATCH","CRYPTO_PROVIDER_UNAVAILABLE","AUTH_FAILED",
    "REMOTE_UNAVAILABLE","RATE_LIMITED","REMOTE_IDENTITY_MISMATCH","CONTRACT_BLOCKED",
    "FEATURE_DISABLED","CHECK_IN_PROGRESS","UNKNOWN_REMOTE_ERROR",
    "REAL_CERT_READ_ONLY_AUTHORIZATION_REQUIRED","CERTIFICATE_SELECTION_REQUIRED",
    "SECRET_PROVIDER_WRITE_UNAVAILABLE","SECRET_PROVIDER_ATOMIC_ROTATION_UNSUPPORTED",
})

_ALLOWED_COMPONENTS = frozenset({
    "AGENT_REACHABILITY","CRYPTO_PROVIDER","CERTIFICATE_PRESENT",
    "CERTIFICATE_TIME_VALIDITY","CERTIFICATE_PRIVATE_KEY","CERTIFICATE_COMPATIBILITY",
    "CERTIFICATE_PARTICIPANT_MATCH","TRUE_API_AUTH","TRUE_API_READ_PROBE",
    "WRITE_FEATURE_GATE",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_error(code: str | None) -> str | None:
    return code if code in ERROR_CODES else ("UNKNOWN_REMOTE_ERROR" if code else None)


class IntegrationSettingsError(RuntimeError):
    pass


class IntegrationNotFound(KeyError):
    pass


class IntegrationCheckBlocked(IntegrationSettingsError):
    pass


class IntegrationSettingsService:
    def __init__(
        self,
        db: Session,
        config,
        *,
        secret_provider: SecretProvider,
        wb_http_adapter=None,
        wb_rate_limiter: StatefulWbRateLimiter | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.secret_provider = secret_provider
        self.wb_http_adapter = wb_http_adapter
        self.wb_rate_limiter = wb_rate_limiter or StatefulWbRateLimiter()
        self.scope = active_tenant(db)

    def _trace(self) -> dict[str, Any]:
        value = self.db.info.get("audit_trace")
        return value if isinstance(value, dict) else {}

    def _audit(
        self,
        event_type: str,
        *,
        subject_type: SubjectType,
        subject_id: str,
        metadata: Mapping[str, Any],
        actor_kind: ActorKind = ActorKind.USER,
        user_id: int | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        event_key_suffix: str | None = None,
        machine_principal: str | None = None,
    ) -> None:
        actor = (
            ActorContext(ActorKind.USER, user_id=user_id)
            if actor_kind is ActorKind.USER
            else ActorContext(actor_kind, machine_principal=machine_principal or "windows-agent")
        )
        trace = self._trace()
        AuditService(
            self.db,
            pseudonym_key=self.db.info.get("audit_pseudonym_key"),
            pseudonym_key_id=self.db.info.get("audit_pseudonym_key_id"),
        ).append(
            event_type=event_type,
            actor=actor,
            tenant=AuditTenantScope(self.scope.organisation_id, self.scope.participant_id),
            subject=SubjectRef(subject_type, str(subject_id)),
            outcome=outcome,
            authorization_decision=(
                AuthorizationDecision.ALLOW if actor_kind is ActorKind.USER
                else AuthorizationDecision.NOT_APPLICABLE
            ),
            trace=TraceContext(
                request_id=trace.get("request_id"),
                correlation_id=trace.get("correlation_id"),
                causation_id=trace.get("causation_id"),
                operation_id=str(subject_id),
                event_key=(
                    f"m14:{event_type}:{subject_type.value}:{subject_id}:{event_key_suffix or trace.get('request_id') or 'event'}"
                )[:256],
            ),
            metadata=dict(metadata),
        )

    def _subject(self, kind: str) -> SubjectType:
        return {
            "true-api": SubjectType.INTEGRATION_CONNECTION,
            "wb": SubjectType.WB_CONNECTION,
            "ozon": SubjectType.OZON_CONNECTION,
            "suz": SubjectType.SUZ_CONNECTION,
        }[kind]

    def _model(self, kind: str):
        return {
            "true-api": TrueApiConnectionRecord,
            "wb": WbConnectionRecord,
            "ozon": OzonConnectionRecord,
            "suz": SuzConnectionRecord,
        }.get(kind)

    def _get(self, kind: str, object_id: str | int, *, lock: bool = False):
        model = self._model(kind)
        if model is None:
            raise IntegrationNotFound("integration not found")
        value: Any = object_id
        if kind in {"wb","ozon","suz"}:
            try:
                value = int(object_id)
            except (TypeError, ValueError) as exc:
                raise IntegrationNotFound("integration not found") from exc
        stmt = select(model).where(
            model.id == value,
            model.organisation_id == self.scope.organisation_id,
            model.participant_id == self.scope.participant_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = self.db.scalar(stmt)
        if row is None:
            raise IntegrationNotFound("integration not found")
        return row

    def _latest_health(self, kind: str, object_id: str | int) -> IntegrationHealthCheckRecord | None:
        return self.db.scalar(
            select(IntegrationHealthCheckRecord)
            .where(
                IntegrationHealthCheckRecord.organisation_id == self.scope.organisation_id,
                IntegrationHealthCheckRecord.participant_id == self.scope.participant_id,
                IntegrationHealthCheckRecord.integration_type == kind.upper().replace("-", "_"),
                IntegrationHealthCheckRecord.connection_id == str(object_id),
                IntegrationHealthCheckRecord.completed_at.is_not(None),
            )
            .order_by(
                IntegrationHealthCheckRecord.completed_at.desc(),
                IntegrationHealthCheckRecord.created_at.desc(),
            )
            .limit(1)
        )

    def _secret_ref(self, kind: str, row) -> str | None:
        if kind == "wb":
            return row.active_secret_ref or row.secret_ref
        if kind == "ozon":
            return row.active_secret_ref or row.api_key_secret_ref
        return None

    def _configuration_status(self, kind: str, row) -> str:
        if kind == "true-api":
            if row.state == "ARCHIVED":
                return "ARCHIVED"
            if row.state == "DISABLED":
                return "DISABLED"
            return "CONFIGURED" if row.primary_agent_binding_id else "INCOMPLETE"
        if row.archived_at:
            return "ARCHIVED"
        if not row.is_enabled:
            return "DISABLED"
        if kind in {"wb","ozon"} and not self._secret_ref(kind, row):
            return "INCOMPLETE"
        return "CONFIGURED"

    def _runtime_status(self, kind: str, row, latest: IntegrationHealthCheckRecord | None) -> str:
        if self._configuration_status(kind, row) in {"DISABLED","ARCHIVED"}:
            return "UNKNOWN"
        if latest is None:
            return "UNKNOWN"
        if latest.overall_status == "READY":
            return "READY"
        if latest.overall_status in {"DEGRADED","BLOCKED","NOT_TESTED"}:
            return "DEGRADED"
        if latest.overall_status == "CHECKING":
            return "CHECKING"
        return "ERROR"

    def _contract_status(self, kind: str) -> str:
        return "BLOCKED" if kind in {"ozon","suz"} else "AVAILABLE"

    def _feature_gate_status(self, kind: str) -> str:
        if kind == "true-api" and not self.config.true_api_write_enabled:
            return "DISABLED"
        return "ENABLED"

    def _capabilities(self) -> list[dict[str, Any]]:
        true_conn = self.db.scalar(select(TrueApiConnectionRecord).where(
            TrueApiConnectionRecord.organisation_id == self.scope.organisation_id,
            TrueApiConnectionRecord.participant_id == self.scope.participant_id,
            TrueApiConnectionRecord.state != "ARCHIVED",
        ))
        binding = AgentBindingService(self.db).primary_for_active_scope()
        true_health = self._latest_health("true-api", true_conn.id) if true_conn else None
        auth_ready = bool(
            true_health and
            (true_health.component_statuses_json or {}).get("TRUE_API_AUTH", {}).get("status") == "READY"
        )
        wb_ready = bool(self.db.scalar(
            select(IntegrationHealthCheckRecord.id).where(
                IntegrationHealthCheckRecord.organisation_id == self.scope.organisation_id,
                IntegrationHealthCheckRecord.participant_id == self.scope.participant_id,
                IntegrationHealthCheckRecord.integration_type == "WB",
                IntegrationHealthCheckRecord.overall_status == "READY",
                IntegrationHealthCheckRecord.completed_at.is_not(None),
            ).limit(1)
        ))
        return capability_projection(
            true_api_configured=true_conn is not None,
            true_api_auth_ready=auth_ready,
            agent_ready=binding is not None,
            wb_ready=wb_ready,
            true_api_write_enabled=bool(self.config.true_api_write_enabled),
            reports_enabled=bool(self.config.true_api_reports_enabled),
        )

    def dto(self, kind: str, row) -> dict[str, Any]:
        latest = self._latest_health(kind, row.id)
        participant = self.db.get(ParticipantRecord, self.scope.participant_id)
        blockers: list[str] = []
        if kind == "ozon":
            blockers.append("M10_EXECUTABLE_READ_CAPABILITIES_NONE")
        if kind == "suz":
            blockers.append("OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED")
        if kind == "true-api" and not self.config.true_api_write_enabled:
            blockers.append("TRUE_API_PRODUCTION_WRITE_DISABLED")
        if kind == "true-api" and not self.config.true_api_real_read_enabled:
            blockers.append("REAL_CERT_READ_ONLY_AUTHORIZATION_REQUIRED")
        result = {
            "id": str(row.id),
            "type": kind,
            "display_name": (
                getattr(row, "display_name", None)
                or {"true-api":"True API","wb":"Wildberries","ozon":"Ozon","suz":"SUZ"}[kind]
            ),
            "participant": {
                "id": self.scope.participant_id,
                "inn": participant.inn if participant else self.scope.participant_inn,
                "display_name": participant.display_name if participant else None,
            },
            "configuration_status": self._configuration_status(kind, row),
            "runtime_status": self._runtime_status(kind, row, latest),
            "contract_status": self._contract_status(kind),
            "feature_gate_status": self._feature_gate_status(kind),
            "enabled": row.state == "ENABLED" if kind == "true-api" else bool(row.is_enabled and not row.archived_at),
            "secret_configured": bool(self._secret_ref(kind, row)) if kind in {"wb","ozon"} else None,
            "last_check_at": _iso(getattr(row, "last_check_at", None)),
            "last_check_status": latest.overall_status if latest else None,
            "last_success_at": _iso(
                latest.completed_at if latest and latest.overall_status == "READY" else None
            ),
            "error_code": latest.error_code if latest else getattr(row, "last_error_code", None),
            "recommended_action": None,
            "capabilities": self._capabilities(),
            "blockers": blockers,
            "read_only": True if kind == "true-api" else None,
            "real_read_authorized": bool(self.config.true_api_real_read_enabled) if kind == "true-api" else None,
            "requires_local_action": bool(
                kind == "true-api" and row.certificate_selection_state == "PENDING_LOCAL_APPLY"
            ) if kind == "true-api" else False,
            "action_code": (
                "APPLY_CERTIFICATE_LOCALLY"
                if kind == "true-api" and row.certificate_selection_state == "PENDING_LOCAL_APPLY"
                else None
            ),
        }
        if kind == "true-api":
            cert = (
                self.db.get(AgentCertificateObservationRecord, row.observed_certificate_observation_id)
                if row.observed_certificate_observation_id else None
            )
            result["certificate"] = {
                "thumbprint": cert.thumbprint if cert else None,
                "valid_to": _iso(cert.valid_to) if cert else None,
                "days_remaining": (
                    max(0, int((cert.valid_to.astimezone(timezone.utc) - _now()).total_seconds() // 86400))
                    if cert and cert.valid_to else None
                ),
                "status": cert.readiness_state if cert else "UNKNOWN",
                "expiry_state": cert.expiry_state if cert else "UNKNOWN",
                "selection_state": row.certificate_selection_state,
            }
        if kind == "ozon":
            result["wire_readiness"] = row.wire_readiness
            result["local_validation_state"] = row.local_validation_state
        if kind == "suz":
            result["wire_readiness"] = row.wire_readiness
            result["local_config_state"] = row.local_config_state
        return result

    def list_connections(self) -> list[dict[str, Any]]:
        rows: list[tuple[str, Any]] = []
        for kind, model in (
            ("true-api", TrueApiConnectionRecord), ("wb", WbConnectionRecord),
            ("ozon", OzonConnectionRecord), ("suz", SuzConnectionRecord),
        ):
            found = list(self.db.scalars(select(model).where(
                model.organisation_id == self.scope.organisation_id,
                model.participant_id == self.scope.participant_id,
            ).order_by(model.created_at, model.id)))
            rows.extend((kind, row) for row in found)
        return [self.dto(kind, row) for kind, row in rows]

    def create_true_api(
        self, *, environment: str, primary_agent_binding_id: str | None, user_id: int
    ) -> dict[str, Any]:
        existing = self.db.scalar(select(TrueApiConnectionRecord).where(
            TrueApiConnectionRecord.organisation_id == self.scope.organisation_id,
            TrueApiConnectionRecord.participant_id == self.scope.participant_id,
            TrueApiConnectionRecord.state != "ARCHIVED",
        ).with_for_update())
        if existing is not None:
            raise ValueError("participant already has a live True API connection")
        binding = None
        if primary_agent_binding_id:
            binding = self.db.scalar(select(AgentBindingRecord).where(
                AgentBindingRecord.id == primary_agent_binding_id,
                AgentBindingRecord.organisation_id == self.scope.organisation_id,
                AgentBindingRecord.participant_id == self.scope.participant_id,
                AgentBindingRecord.state == "ACTIVE",
                AgentBindingRecord.is_primary.is_(True),
            ))
            if binding is None:
                raise ValueError("primary agent binding is not active for participant")
        row = TrueApiConnectionRecord(
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            environment=(environment or "PRODUCTION").upper(),
            state="ENABLED",
            primary_agent_binding_id=binding.id if binding else None,
            desired_capabilities_json=[],
            observed_capabilities_json=[],
        )
        self.db.add(row); self.db.flush()
        self._audit(
            "CONNECTION_CREATED", subject_type=SubjectType.INTEGRATION_CONNECTION,
            subject_id=row.id, user_id=user_id,
            metadata={"integration_type":"TRUE_API","connection_type":"true-api","connection_id":row.id,"enabled":True},
        )
        return self.dto("true-api", row)

    def create_wb(self, data: Mapping[str, Any], *, user_id: int) -> dict[str, Any]:
        environment = str(data.get("environment") or "PRODUCTION").upper()
        token_type = str(data.get("token_type") or "PERSONAL").upper()
        WbEnvironment(environment); WbTokenType(token_type)
        categories = [str(v).upper() for v in (data.get("token_categories") or ["ANY"])]
        for value in categories:
            WbTokenCategory(value)
        row = WbConnectionRecord(
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            display_name=str(data.get("display_name") or "Wildberries")[:200],
            is_enabled=True,
            environment=environment,
            participant_inn=self.scope.participant_inn,
            token_type=token_type,
            token_categories=categories,
            token_scopes=[str(x)[:128] for x in (data.get("token_scopes") or [])],
            secret_ref=None,
            active_secret_ref=None,
            connection_state=WbConnectionState.UNVERIFIED.value,
            rate_profile=str(data.get("rate_profile"))[:64] if data.get("rate_profile") else None,
            health_metadata_json={},
        )
        self.db.add(row); self.db.flush()
        self._audit(
            "CONNECTION_CREATED", subject_type=SubjectType.WB_CONNECTION,
            subject_id=str(row.id), user_id=user_id,
            metadata={"integration_type":"WB","connection_type":"wb","connection_id":str(row.id),"enabled":True},
        )
        return self.dto("wb", row)

    def create_ozon(self, data: Mapping[str, Any], *, user_id: int) -> dict[str, Any]:
        client_id = str(data.get("client_id") or "").strip()
        if not client_id or len(client_id) > 256:
            raise ValueError("client_id is required")
        row = OzonConnectionRecord(
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            display_name=str(data.get("display_name") or "Ozon")[:200],
            is_enabled=True,
            environment=str(data.get("environment") or "PRODUCTION").upper(),
            participant_inn=self.scope.participant_inn,
            client_id=client_id,
            api_key_secret_ref=None,
            active_secret_ref=None,
            roles_metadata=[],
            capability_metadata=[],
            connection_state="CONFIGURED",
            local_validation_state="INCOMPLETE",
            wire_readiness="BLOCKED",
            blocker_code="M10_EXECUTABLE_READ_CAPABILITIES_NONE",
            health_metadata_json={},
        )
        self.db.add(row); self.db.flush()
        self._audit(
            "CONNECTION_CREATED", subject_type=SubjectType.OZON_CONNECTION,
            subject_id=str(row.id), user_id=user_id,
            metadata={"integration_type":"OZON","connection_type":"ozon","connection_id":str(row.id),"enabled":True},
        )
        return self.dto("ozon", row)

    def create_suz(self, data: Mapping[str, Any], *, user_id: int) -> dict[str, Any]:
        oms_connection = str(data.get("oms_connection") or "").strip()
        oms_id = str(data.get("oms_id") or "").strip()
        if not oms_connection or not oms_id:
            raise ValueError("oms_id and oms_connection are required")
        row = SuzConnectionRecord(
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            display_name=str(data.get("display_name") or "SUZ")[:200],
            is_enabled=True,
            participant_inn=self.scope.participant_inn,
            oms_id=oms_id,
            oms_connection=oms_connection,
            environment=str(data.get("environment") or "PRODUCTION").upper(),
            installation_name=str(data.get("installation_name") or "Windows Agent")[:200],
            connection_state="NOT_ACQUIRED",
            local_config_state="CONFIGURED",
            wire_readiness="BLOCKED",
            blocker_code="OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED",
            health_metadata_json={},
        )
        self.db.add(row); self.db.flush()
        self._audit(
            "CONNECTION_CREATED", subject_type=SubjectType.SUZ_CONNECTION,
            subject_id=str(row.id), user_id=user_id,
            metadata={"integration_type":"SUZ","connection_type":"suz","connection_id":str(row.id),"enabled":True},
        )
        return self.dto("suz", row)

    def update_connection(
        self, kind: str, object_id: str, changes: Mapping[str, Any], *, user_id: int
    ) -> dict[str, Any]:
        row = self._get(kind, object_id, lock=True)
        allowed = {"display_name"}
        if kind == "wb":
            allowed |= {"rate_profile"}
        changed: list[str] = []
        for key, value in changes.items():
            if key not in allowed:
                raise ValueError(f"field is not mutable: {key}")
            if key == "display_name":
                value = str(value or "").strip()[:200] or None
            if key == "rate_profile":
                value = str(value or "").strip()[:64] or None
            if getattr(row, key) != value:
                setattr(row, key, value); changed.append(key)
        self.db.flush()
        if changed:
            self._audit(
                "CONNECTION_UPDATED", subject_type=self._subject(kind), subject_id=str(row.id),
                user_id=user_id,
                metadata={"integration_type":kind.upper().replace("-","_"),"connection_type":kind,"connection_id":str(row.id),"changed_fields":changed},
            )
        return self.dto(kind, row)

    def lifecycle(self, kind: str, object_id: str, action: str, *, user_id: int) -> dict[str, Any]:
        row = self._get(kind, object_id, lock=True)
        now = _now()
        if kind == "true-api":
            if action == "enable" and row.state != "ARCHIVED":
                row.state = "ENABLED"
            elif action == "disable" and row.state != "ARCHIVED":
                row.state = "DISABLED"
            elif action == "archive":
                row.state = "ARCHIVED"; row.archived_at = now
            else:
                raise ValueError("invalid lifecycle transition")
        else:
            if action == "enable" and not row.archived_at:
                row.is_enabled = True
            elif action == "disable" and not row.archived_at:
                row.is_enabled = False
            elif action == "archive":
                row.is_enabled = False; row.archived_at = now
            else:
                raise ValueError("invalid lifecycle transition")
        self.db.flush()
        self._audit(
            {"enable":"CONNECTION_ENABLED","disable":"CONNECTION_DISABLED","archive":"CONNECTION_ARCHIVED"}[action],
            subject_type=self._subject(kind), subject_id=str(row.id), user_id=user_id,
            metadata={"integration_type":kind.upper().replace("-","_"),"connection_type":kind,"connection_id":str(row.id)},
        )
        return self.dto(kind, row)

    def set_secret(self, kind: str, object_id: str, raw_secret: str, *, user_id: int) -> dict[str, Any]:
        if kind not in {"wb","ozon"}:
            raise ValueError("browser secret input is allowed only for WB/Ozon")
        if not isinstance(raw_secret, str) or not raw_secret or len(raw_secret.encode("utf-8")) > 16 * 1024:
            raise ValueError("credential is missing or exceeds 16 KiB")
        row = self._get(kind, object_id, lock=True)
        require_safe_rotation(self.secret_provider)
        old_ref = row.active_secret_ref or (row.secret_ref if kind == "wb" else row.api_key_secret_ref)
        old_version = row.active_secret_version
        staged: StagedSecret | None = None
        try:
            staged = self.secret_provider.stage(
                f"{self.scope.organisation_id}:{self.scope.participant_id}:{kind}:{row.id}",
                f"{kind}-credential",
                raw_secret,
            )
            row.pending_secret_ref = staged.ref
            row.pending_secret_version = staged.version
            row.secret_rotation_state = "PENDING"
            self.db.commit()  # durable pointer before provider activation
        except Exception:
            self.db.rollback()
            if staged is not None:
                self.secret_provider.destroy_staged(staged)
            raise

        try:
            active = self.secret_provider.activate(staged)
        except Exception:
            # Old active stays authoritative; pending evidence is durable for recovery.
            row = self._get(kind, object_id, lock=True)
            row.secret_rotation_state = "PENDING_FAILED"
            self.db.commit()
            raise

        try:
            row = self._get(kind, object_id, lock=True)
            if row.pending_secret_ref != active.ref or row.pending_secret_version != active.version:
                raise IntegrationSettingsError("pending secret state changed during activation")
            row.active_secret_ref = active.ref
            row.active_secret_version = active.version
            row.pending_secret_ref = None
            row.pending_secret_version = None
            row.secret_rotation_state = "ACTIVE"
            row.secret_configured_at = _now()
            if kind == "wb":
                row.secret_ref = None
            else:
                row.api_key_secret_ref = None
            self.db.flush()
            event = "SECRET_ROTATED" if old_ref else "SECRET_SET"
            metadata = {
                "integration_type": kind.upper(),
                "connection_id": str(row.id),
                "new_version": active.version,
                "rotation_state": "ACTIVE",
            }
            if old_version:
                metadata["old_version"] = old_version
            self._audit(
                event, subject_type=self._subject(kind), subject_id=str(row.id),
                user_id=user_id, metadata=metadata,
                event_key_suffix=f"{row.id}:{active.version}",
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            # Provider may already have activated. Durable PENDING state permits reconciliation.
            raise
        return self.dto(kind, row)

    def revoke_secret(self, kind: str, object_id: str, *, user_id: int) -> dict[str, Any]:
        if kind not in {"wb","ozon"}:
            raise ValueError("secret revoke is supported only for WB/Ozon")
        row = self._get(kind, object_id, lock=True)
        ref = row.active_secret_ref
        version = row.active_secret_version
        if not ref or not version:
            raise SecretProviderAtomicRotationUnsupported("SECRET_PROVIDER_ATOMIC_ROTATION_UNSUPPORTED")
        if not (self.secret_provider.capabilities & SecretCapability.REVOKE):
            raise SecretProviderWriteUnavailable("SECRET_PROVIDER_WRITE_UNAVAILABLE")
        self.secret_provider.revoke(ref, version)
        row.active_secret_ref = None
        row.active_secret_version = None
        row.pending_secret_ref = None
        row.pending_secret_version = None
        row.secret_rotation_state = "REVOKED"
        row.secret_configured_at = None
        if kind == "wb":
            row.secret_ref = None
        else:
            row.api_key_secret_ref = None
        self.db.flush()
        self._audit(
            "SECRET_REVOKED", subject_type=self._subject(kind), subject_id=str(row.id),
            user_id=user_id,
            metadata={"integration_type":kind.upper(),"connection_id":str(row.id),"old_version":version},
            event_key_suffix=f"{row.id}:{version}:revoked",
        )
        return self.dto(kind, row)

    def reconcile_secret_rotation(self, kind: str, object_id: str, *, user_id: int) -> dict[str, Any]:
        if kind not in {"wb","ozon"}:
            raise ValueError("secret reconciliation is supported only for WB/Ozon")
        row = self._get(kind, object_id, lock=True)
        if not row.pending_secret_ref or not row.pending_secret_version:
            return self.dto(kind, row)
        try:
            value = self.secret_provider.get(row.pending_secret_ref)
        except SecretProviderError as exc:
            raise IntegrationSettingsError("SECRET_PROVIDER_UNAVAILABLE") from exc
        if value.version != row.pending_secret_version:
            raise IntegrationSettingsError("pending provider version does not match database")
        row.active_secret_ref = row.pending_secret_ref
        row.active_secret_version = row.pending_secret_version
        row.pending_secret_ref = None
        row.pending_secret_version = None
        row.secret_rotation_state = "ACTIVE"
        row.secret_configured_at = _now()
        self.db.flush()
        self._audit(
            "SECRET_ROTATED", subject_type=self._subject(kind), subject_id=str(row.id),
            user_id=user_id,
            metadata={
                "integration_type":kind.upper(),"connection_id":str(row.id),
                "new_version":row.active_secret_version,"rotation_state":"ACTIVE",
            },
        )
        return self.dto(kind, row)

    def _start_check(
        self, kind: str, row, *, check_kind: str, user_id: int, binding_id: str | None = None
    ) -> tuple[IntegrationHealthCheckRecord, bool]:
        now = _now()
        inflight = self.db.scalar(select(IntegrationHealthCheckRecord).where(
            IntegrationHealthCheckRecord.organisation_id == self.scope.organisation_id,
            IntegrationHealthCheckRecord.participant_id == self.scope.participant_id,
            IntegrationHealthCheckRecord.integration_type == kind.upper().replace("-","_"),
            IntegrationHealthCheckRecord.connection_id == str(row.id),
            IntegrationHealthCheckRecord.completed_at.is_(None),
        ).limit(1))
        if inflight is not None:
            raise IntegrationCheckBlocked("CHECK_IN_PROGRESS")
        cooldown = int(getattr(self.config, "integration_check_cooldown_seconds", 30))
        recent = self.db.scalar(
            select(IntegrationHealthCheckRecord).where(
                IntegrationHealthCheckRecord.organisation_id == self.scope.organisation_id,
                IntegrationHealthCheckRecord.participant_id == self.scope.participant_id,
                IntegrationHealthCheckRecord.integration_type == kind.upper().replace("-","_"),
                IntegrationHealthCheckRecord.connection_id == str(row.id),
                IntegrationHealthCheckRecord.overall_status == "READY",
                IntegrationHealthCheckRecord.completed_at >= now - timedelta(seconds=cooldown),
            ).order_by(IntegrationHealthCheckRecord.completed_at.desc()).limit(1)
        )
        if recent is not None:
            return recent, True
        per_minute = int(getattr(self.config, "integration_check_user_limit_per_minute", 10))
        count = int(self.db.scalar(select(func.count()).select_from(IntegrationHealthCheckRecord).where(
            IntegrationHealthCheckRecord.requested_by_user_id == user_id,
            IntegrationHealthCheckRecord.started_at >= now - timedelta(minutes=1),
        )) or 0)
        if count >= per_minute:
            raise IntegrationCheckBlocked("RATE_LIMITED")
        trace = self._trace()
        check = IntegrationHealthCheckRecord(
            organisation_id=self.scope.organisation_id,
            participant_id=self.scope.participant_id,
            integration_type=kind.upper().replace("-","_"),
            connection_type=kind,
            connection_id=str(row.id),
            agent_binding_id=binding_id,
            check_kind=check_kind,
            started_at=now,
            overall_status="CHECKING",
            component_statuses_json={},
            capabilities_json=self._capabilities(),
            remote_identity_json={},
            certificate_snapshot_json={},
            requested_by_user_id=user_id,
            correlation_id=trace.get("correlation_id"),
        )
        self.db.add(check); self.db.flush()
        self._audit(
            "CONNECTION_CHECK_STARTED", subject_type=self._subject(kind), subject_id=str(row.id),
            user_id=user_id, outcome=AuditOutcome.PENDING,
            metadata={
                "integration_type":kind.upper().replace("-","_"),"connection_id":str(row.id),
                "check_kind":check_kind,"reused":False,
            },
            event_key_suffix=check.id,
        )
        return check, False

    def _complete_check(
        self,
        check: IntegrationHealthCheckRecord,
        *,
        overall: str,
        components: Mapping[str, Any],
        error_code: str | None = None,
        redacted_message: str | None = None,
        remote_identity: Mapping[str, Any] | None = None,
        certificate: Mapping[str, Any] | None = None,
        evidence_sha256: str | None = None,
        actor_kind: ActorKind = ActorKind.USER,
        user_id: int | None = None,
        machine_principal: str | None = None,
    ) -> None:
        check.completed_at = _now()
        check.overall_status = overall
        check.component_statuses_json = dict(components)
        check.error_code = _safe_error(error_code)
        check.redacted_message = (redacted_message or "")[:500] or None
        check.remote_identity_json = dict(remote_identity or {})
        check.certificate_snapshot_json = dict(certificate or {})
        check.evidence_sha256 = evidence_sha256
        check.capabilities_json = self._capabilities()
        self.db.flush()
        event = "CONNECTION_CHECK_COMPLETED" if overall in {"READY","DEGRADED","NOT_TESTED","BLOCKED"} else "CONNECTION_CHECK_FAILED"
        metadata = {
            "integration_type": check.integration_type,
            "connection_id": check.connection_id,
            "check_kind": check.check_kind,
        }
        if event == "CONNECTION_CHECK_COMPLETED":
            metadata.update({
                "overall_status": overall,
                "component_statuses": {k: (v.get("status") if isinstance(v, dict) else str(v)) for k,v in components.items()},
                "capability_names": [x.get("name") for x in check.capabilities_json if isinstance(x, dict)],
                "evidence_sha256": evidence_sha256,
            })
        else:
            metadata.update({"error_code":check.error_code,"redacted_message":check.redacted_message})
        self._audit(
            event,
            subject_type=self._subject(check.connection_type),
            subject_id=str(check.connection_id),
            user_id=user_id,
            actor_kind=actor_kind,
            outcome=AuditOutcome.SUCCESS if event == "CONNECTION_CHECK_COMPLETED" else AuditOutcome.FAILED,
            metadata=metadata,
            event_key_suffix=check.id,
            machine_principal=machine_principal,
        )

    def check(self, kind: str, object_id: str, *, user_id: int) -> dict[str, Any]:
        row = self._get(kind, object_id, lock=True)
        if self._configuration_status(kind, row) in {"DISABLED","ARCHIVED"}:
            raise IntegrationCheckBlocked("FEATURE_DISABLED")
        if kind == "true-api":
            return self._check_true_api(row, user_id=user_id)
        if kind == "wb":
            return self._check_wb(row, user_id=user_id)
        if kind == "ozon":
            return self._check_ozon(row, user_id=user_id)
        if kind == "suz":
            return self._check_suz(row, user_id=user_id)
        raise IntegrationNotFound("integration not found")

    def _check_true_api(self, row: TrueApiConnectionRecord, *, user_id: int) -> dict[str, Any]:
        binding = AgentBindingService(self.db).primary_for_active_scope()
        if binding is None:
            raise IntegrationCheckBlocked("AGENT_OFFLINE")
        if row.primary_agent_binding_id and row.primary_agent_binding_id != binding.id:
            raise IntegrationCheckBlocked("AGENT_PROTOCOL_MISMATCH")
        if row.primary_agent_binding_id is None:
            row.primary_agent_binding_id = binding.id

        if not self.config.true_api_real_read_enabled:
            check, reused = self._start_check(
                "true-api", row, check_kind="LOCAL_CERTIFICATE_READINESS", user_id=user_id, binding_id=binding.id
            )
            if reused:
                return {**self.health_dto(check), "reused": True}
            status = self.certificate_status()
            observation = status.get("observation") if isinstance(status, dict) else None
            cert_ready = bool(
                observation
                and observation.get("readiness_state") == "READY"
                and status.get("status") == "ACTIVE_READY"
            )
            reason = (
                "REAL_CERT_READ_ONLY_AUTHORIZATION_REQUIRED"
                if cert_ready
                else str(status.get("reason_code") or "CERTIFICATE_NOT_FOUND")
            )
            components = {
                "AGENT_REACHABILITY": {"status": "READY"},
                "CRYPTO_PROVIDER": {
                    "status": "READY" if observation and observation.get("compatibility") == "GOST_CRYPTOPRO" else "ERROR"
                },
                "CERTIFICATE_PRESENT": {"status": "READY" if observation else "ERROR"},
                "CERTIFICATE_TIME_VALIDITY": {"status": "READY" if cert_ready else "ERROR"},
                "CERTIFICATE_PRIVATE_KEY": {
                    "status": "READY" if observation and observation.get("has_private_key") else "ERROR"
                },
                "CERTIFICATE_COMPATIBILITY": {
                    "status": "READY" if observation and observation.get("compatibility") == "GOST_CRYPTOPRO" else "ERROR"
                },
                "CERTIFICATE_PARTICIPANT_MATCH": {
                    "status": "READY" if observation and observation.get("match_state") == "MATCH" else "ERROR"
                },
                "TRUE_API_AUTH": {
                    "status": "BLOCKED",
                    "reason_code": "REAL_CERT_READ_ONLY_AUTHORIZATION_REQUIRED",
                },
                "TRUE_API_READ_PROBE": {"status": "NOT_TESTED"},
                "WRITE_FEATURE_GATE": {"status": "BLOCKED"},
            }
            self._complete_check(
                check,
                overall="BLOCKED" if cert_ready else "ERROR",
                components=components,
                error_code=reason,
                certificate=observation or {},
                user_id=user_id,
            )
            row.last_check_at = check.completed_at
            row.last_error_code = reason
            self.db.flush()
            return {**self.health_dto(check), "reused": False}

        check, reused = self._start_check(
            "true-api", row, check_kind="TRUE_API_TYPED_AGENT", user_id=user_id, binding_id=binding.id
        )
        if reused:
            return {**self.health_dto(check), "reused": True}
        job = AgentJob(
            job_id="job_" + hashlib.sha256(f"m14-health:{check.id}:{binding.id}".encode()).hexdigest()[:32],
            job_type=AgentJobType.INTEGRATION_HEALTH,
            operation_id=f"m14-health:{check.id}",
            pg=P0_PG,
            expected_inn=self.scope.participant_inn,
            read_payload={"check_id":check.id,"check_kind":"TRUE_API","read_probe":"NOT_TESTED"},
        )
        SqlAlchemyAgentJobStore(self.db, lease_seconds=self.config.agent_job_lease_seconds).enqueue(
            job, purpose="INTEGRATION_HEALTH"
        )
        self.db.flush()
        return {**self.health_dto(check), "reused": False}

    def _check_wb(self, row: WbConnectionRecord, *, user_id: int) -> dict[str, Any]:
        check, reused = self._start_check("wb", row, check_kind="REMOTE_READ_ONLY", user_id=user_id)
        if reused:
            return {**self.health_dto(check), "reused": True}
        ref = self._secret_ref("wb", row)
        if not ref:
            self._complete_check(check, overall="ERROR", components={"SECRET":{"status":"ERROR"}}, error_code="SECRET_MISSING", user_id=user_id)
            return {**self.health_dto(check), "reused": False}
        if self.wb_http_adapter is None:
            self._complete_check(check, overall="ERROR", components={"REMOTE_READ":{"status":"ERROR"}}, error_code="REMOTE_UNAVAILABLE", user_id=user_id)
            return {**self.health_dto(check), "reused": False}
        try:
            token = self.secret_provider.get(ref)
        except SecretProviderError:
            self._complete_check(check, overall="ERROR", components={"SECRET":{"status":"ERROR"}}, error_code="SECRET_PROVIDER_UNAVAILABLE", user_id=user_id)
            return {**self.health_dto(check), "reused": False}
        try:
            rate_scope_ref = f"wb:{row.id}:{row.active_secret_version or token.version or 'v0'}"
            connection = WbConnection(
                environment=WbEnvironment(row.environment),
                participant_inn=self.scope.participant_inn,
                secret_ref=rate_scope_ref,
                token_type=WbTokenType(row.token_type),
                token_categories=tuple(WbTokenCategory(v) for v in row.token_categories),
                token_scopes=tuple(row.token_scopes or ()),
                wb_sid=row.wb_sid, wb_tin=row.wb_tin,
                token_expires_at=row.token_expires_at,
                rate_profile=row.rate_profile,
                connection_state=WbConnectionState(row.connection_state),
            )
            class OneSecret:
                def get_secret(self, secret_ref: str) -> str:
                    if secret_ref != rate_scope_ref:
                        raise KeyError("secret not available")
                    return token.value
            response = WbReadTransport(
                self.wb_http_adapter, connection.environment, rate_limiter=self.wb_rate_limiter
            ).seller_info(runtime_token(connection, OneSecret()))
            evidence = hashlib.sha256(response.body).hexdigest()
            if response.status_code == 429:
                raise WbRateLimitExceeded("SELLER_INFO", 30)
            if not 200 <= response.status_code < 300:
                code = "AUTH_FAILED" if response.status_code in {401,403} else "REMOTE_UNAVAILABLE"
                self._complete_check(
                    check, overall="ERROR", components={"WB_SELLER_INFO":{"status":"ERROR"}},
                    error_code=code, evidence_sha256=evidence, user_id=user_id,
                )
            else:
                payload = json.loads(response.body.decode("utf-8"))
                verified, identity = verify_seller_identity(connection, payload)
                row.wb_sid, row.wb_tin = identity.sid, identity.tin
                row.connection_state = verified.connection_state.value
                row.last_verified_at = _now()
                duplicate = self.db.scalar(select(WbConnectionRecord).where(
                    WbConnectionRecord.id != row.id,
                    WbConnectionRecord.organisation_id == self.scope.organisation_id,
                    WbConnectionRecord.participant_id == self.scope.participant_id,
                    WbConnectionRecord.environment == row.environment,
                    WbConnectionRecord.wb_sid == identity.sid,
                    WbConnectionRecord.wb_tin == identity.tin,
                    WbConnectionRecord.is_enabled.is_(True),
                    WbConnectionRecord.archived_at.is_(None),
                ).limit(1))
                if duplicate is not None:
                    row.last_error_code = "CONFIG_MISSING"
                    self._complete_check(
                        check, overall="ERROR",
                        components={"WB_SELLER_INFO":{"status":"ERROR","reason_code":"CONFIG_MISSING"}},
                        error_code="CONFIG_MISSING",
                        redacted_message="Trusted duplicate WB seller identity is already configured.",
                        remote_identity={"sid":identity.sid,"tin":identity.tin},
                        evidence_sha256=evidence, user_id=user_id,
                    )
                elif identity.tin != self.scope.participant_inn:
                    row.last_error_code = "REMOTE_IDENTITY_MISMATCH"
                    self._complete_check(
                        check, overall="ERROR",
                        components={"WB_SELLER_INFO":{"status":"ERROR","reason_code":"REMOTE_IDENTITY_MISMATCH"}},
                        error_code="REMOTE_IDENTITY_MISMATCH",
                        remote_identity={"sid":identity.sid,"tin":identity.tin},
                        evidence_sha256=evidence, user_id=user_id,
                    )
                else:
                    row.last_error_code = None
                    self._complete_check(
                        check, overall="READY",
                        components={"WB_SELLER_INFO":{"status":"READY"}},
                        remote_identity={"sid":identity.sid,"tin":identity.tin},
                        evidence_sha256=evidence, user_id=user_id,
                    )
        except WbRateLimitExceeded:
            self._complete_check(check, overall="ERROR", components={"WB_SELLER_INFO":{"status":"ERROR"}}, error_code="RATE_LIMITED", user_id=user_id)
        except Exception:
            self._complete_check(check, overall="ERROR", components={"WB_SELLER_INFO":{"status":"ERROR"}}, error_code="UNKNOWN_REMOTE_ERROR", user_id=user_id)
        row.last_check_at = check.completed_at
        return {**self.health_dto(check), "reused": False}

    def _check_ozon(self, row: OzonConnectionRecord, *, user_id: int) -> dict[str, Any]:
        check, reused = self._start_check("ozon", row, check_kind="LOCAL_ONLY", user_id=user_id)
        if reused:
            return {**self.health_dto(check), "reused": True}
        secret_ref = self._secret_ref("ozon", row)
        provider_configured = False
        if secret_ref:
            try:
                self.secret_provider.get(secret_ref)
                provider_configured = True
            except SecretProviderError:
                provider_configured = False
        configured = bool(row.client_id and provider_configured)
        expired = bool(row.api_key_expires_at and row.api_key_expires_at <= _now())
        row.local_validation_state = "CONFIGURED" if configured and not expired else "INCOMPLETE"
        row.wire_readiness = "BLOCKED"
        row.blocker_code = "M10_EXECUTABLE_READ_CAPABILITIES_NONE"
        row.last_check_at = _now()
        components = {
            "LOCAL_CONFIGURATION":{"status":"READY" if configured else "ERROR"},
            "SECRET":{"status":"READY" if provider_configured else "ERROR"},
            "REMOTE_WIRE":{"status":"BLOCKED","reason_code":"CONTRACT_BLOCKED"},
        }
        self._complete_check(
            check, overall="BLOCKED" if configured and not expired else "ERROR",
            components=components,
            error_code="SECRET_EXPIRED" if expired else (None if configured else "CONFIG_MISSING"),
            redacted_message="Remote Ozon check is not implemented in accepted M10 contract.",
            user_id=user_id,
        )
        return {**self.health_dto(check), "reused": False}

    def _check_suz(self, row: SuzConnectionRecord, *, user_id: int) -> dict[str, Any]:
        check, reused = self._start_check("suz", row, check_kind="LOCAL_ONLY", user_id=user_id)
        if reused:
            return {**self.health_dto(check), "reused": True}
        binding = AgentBindingService(self.db).primary_for_active_scope()
        configured = bool(row.oms_id and row.oms_connection and row.environment)
        row.local_config_state = "CONFIGURED" if configured and binding is not None else "INCOMPLETE"
        row.wire_readiness = "BLOCKED"
        row.blocker_code = "OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED"
        row.last_check_at = _now()
        self._complete_check(
            check,
            overall="BLOCKED" if configured and binding is not None else "ERROR",
            components={
                "LOCAL_CONFIGURATION":{"status":"READY" if configured else "ERROR"},
                "AGENT_REACHABILITY":{"status":"READY" if binding is not None else "ERROR","reason_code":None if binding is not None else "AGENT_OFFLINE"},
                "SUZ_CORE_WIRE":{"status":"BLOCKED","reason_code":"CONTRACT_BLOCKED"},
            },
            error_code=None if configured and binding is not None else ("AGENT_OFFLINE" if binding is None else "CONFIG_MISSING"),
            redacted_message="Full SUZ wire remains blocked on pinned official programmer manual.",
            user_id=user_id,
        )
        return {**self.health_dto(check), "reused": False}

    def apply_agent_health_result(self, binding: AgentBindingRecord, result: AgentResult) -> None:
        payload = result.read_result if isinstance(result.read_result, dict) else {}
        if payload.get("type") != "M14_INTEGRATION_HEALTH":
            raise ValueError("not an M14 health result")
        check_id = payload.get("check_id")
        check = self.db.scalar(select(IntegrationHealthCheckRecord).where(
            IntegrationHealthCheckRecord.id == check_id,
            IntegrationHealthCheckRecord.organisation_id == binding.organisation_id,
            IntegrationHealthCheckRecord.participant_id == binding.participant_id,
            IntegrationHealthCheckRecord.agent_binding_id == binding.id,
            IntegrationHealthCheckRecord.completed_at.is_(None),
        ).with_for_update())
        if check is None:
            raise IntegrationNotFound("integration health check not found")
        raw_components = payload.get("components") if isinstance(payload.get("components"), dict) else {}
        components: dict[str, Any] = {}
        for key, value in raw_components.items():
            if key not in _ALLOWED_COMPONENTS or not isinstance(value, dict):
                continue
            status = str(value.get("status") or "UNKNOWN")[:32]
            reason = _safe_error(str(value.get("reason_code"))) if value.get("reason_code") else None
            components[key] = {"status":status, **({"reason_code":reason} if reason else {})}

        conn = self._get("true-api", str(check.connection_id), lock=True)
        cert_raw = payload.get("certificate") if isinstance(payload.get("certificate"), dict) else {}
        cert_snapshot: dict[str, Any] = {}
        if cert_raw.get("thumbprint"):
            thumb = re.sub(r"[^0-9A-F]", "", str(cert_raw.get("thumbprint")).upper())[:160]
            valid_from, valid_to = _parse_dt(cert_raw.get("valid_from")), _parse_dt(cert_raw.get("valid_to"))
            subject_text = str(cert_raw.get("subject") or "")
            cert_inn = str(cert_raw.get("certificate_inn") or "") or None
            if cert_inn is None and subject_text:
                matched = re.search(r"(?:OID\.1\.2\.643\.100\.4|INN|ИНН)\s*[=:]\s*(\d{10}|\d{12})", subject_text, re.IGNORECASE)
                cert_inn = matched.group(1) if matched else None
            expiry = certificate_expiry_status(
                valid_to,
                critical_days=int(getattr(self.config, "certificate_expiry_critical_days", 7)),
                soon_days=int(getattr(self.config, "certificate_expiry_soon_days", 30)),
            )
            match = "MATCH" if cert_inn == self.scope.participant_inn else ("MISMATCH" if cert_inn else "UNKNOWN")
            has_key = bool(cert_raw.get("has_private_key"))
            compatible = str(cert_raw.get("compatibility") or "") == "GOST_CRYPTOPRO"
            not_yet_valid = bool(valid_from and valid_from > _now())
            selection_match = not conn.desired_certificate_ref or conn.desired_certificate_ref == thumb
            ready = (
                has_key and compatible and not not_yet_valid
                and expiry in {"VALID","EXPIRING_SOON","EXPIRING_CRITICAL"}
                and match == "MATCH" and selection_match
            )
            reason = (
                "CERTIFICATE_PARTICIPANT_MISMATCH" if match == "MISMATCH"
                else "CERTIFICATE_NO_PRIVATE_KEY" if not has_key
                else "CRYPTO_PROVIDER_UNAVAILABLE" if not compatible
                else "CERTIFICATE_NOT_YET_VALID" if not_yet_valid
                else "CERTIFICATE_EXPIRED" if expiry == "EXPIRED"
                else "CERTIFICATE_NOT_FOUND" if not selection_match
                else None
            )
            cert = AgentCertificateObservationRecord(
                agent_binding_id=binding.id,
                organisation_id=binding.organisation_id,
                participant_id=binding.participant_id,
                thumbprint=thumb,
                subject=subject_text[:2000] or None,
                issuer=str(cert_raw.get("issuer") or "")[:2000] or None,
                certificate_inn=cert_inn if cert_inn and cert_inn.isdigit() and len(cert_inn) in {10,12} else None,
                valid_from=valid_from,
                valid_to=valid_to,
                algorithm=str(cert_raw.get("algorithm") or "")[:128] or None,
                has_private_key=has_key,
                crypto_provider=str(cert_raw.get("crypto_provider") or "")[:160] or None,
                compatibility="GOST_CRYPTOPRO" if compatible else "UNSUPPORTED",
                key_usage_summary=[],
                serial=str(cert_raw.get("serial") or "")[:160] or None,
                observed_at=_now(),
                readiness_state="READY" if ready else "NOT_READY",
                match_state=match,
                expiry_state=expiry,
                reason_code=reason,
            )
            self.db.add(cert); self.db.flush()
            conn.observed_certificate_observation_id = cert.id
            cert_snapshot = {
                "thumbprint":cert.thumbprint,"certificate_inn":cert.certificate_inn,
                "valid_from":_iso(cert.valid_from),"valid_to":_iso(cert.valid_to),
                "has_private_key":cert.has_private_key,"compatibility":cert.compatibility,
                "readiness_state":cert.readiness_state,"match_state":cert.match_state,
                "expiry_state":cert.expiry_state,"reason_code":cert.reason_code,
            }
            if conn.desired_certificate_ref:
                conn.certificate_selection_state = (
                    "READY" if conn.desired_certificate_ref == cert.thumbprint and ready
                    else "MISMATCH"
                )
            elif ready:
                conn.certificate_selection_state = "READY"

        auth_ready = components.get("TRUE_API_AUTH", {}).get("status") == "READY"
        if auth_ready:
            binding.last_true_api_auth_at = _now()
            conn.last_auth_success_at = _now()
        binding.last_error_code = _safe_error(result.error_code)
        binding.capabilities_sanitized = {
            "true_api_auth": auth_ready,
            "read_probe": "NOT_TESTED",
        }
        observed_cert = (
            self.db.get(AgentCertificateObservationRecord, conn.observed_certificate_observation_id)
            if conn.observed_certificate_observation_id else None
        )
        backend_cert_ready = bool(observed_cert and observed_cert.readiness_state == "READY")
        if result.outcome == "HEALTH_READY" and backend_cert_ready and auth_ready:
            overall = "READY"
        elif result.outcome in {"HEALTH_READY","HEALTH_DEGRADED"} and auth_ready:
            overall = "DEGRADED"
        else:
            overall = "ERROR"
        evidence = hashlib.sha256(canonical_json({
            "components":components,"certificate":cert_snapshot,"outcome":result.outcome,
        }).encode("utf-8")).hexdigest()
        self._complete_check(
            check, overall=overall, components=components,
            error_code=result.error_code, certificate=cert_snapshot,
            evidence_sha256=evidence, actor_kind=ActorKind.WINDOWS_AGENT,
            machine_principal=f"agent-binding:{binding.id}",
        )
        conn.last_check_at = check.completed_at
        conn.last_error_code = _safe_error(result.error_code)
        self.db.flush()

    def record_certificate_inventory(
        self,
        binding_id: str,
        *,
        candidates: list[Mapping[str, Any]],
        selected_thumbprint: str | None,
        cryptopro_available: bool,
    ) -> dict[str, Any]:
        binding = self.db.scalar(select(AgentBindingRecord).where(
            AgentBindingRecord.id == binding_id,
            AgentBindingRecord.organisation_id == self.scope.organisation_id,
            AgentBindingRecord.participant_id == self.scope.participant_id,
            AgentBindingRecord.state == "ACTIVE",
        ).with_for_update())
        if binding is None:
            raise IntegrationNotFound("agent binding not found")
        if len(candidates) > 64:
            raise ValueError("certificate candidate limit exceeded")

        now = _now()
        observed: list[AgentCertificateObservationRecord] = []
        for raw in candidates:
            thumb = re.sub(r"[^0-9A-F]", "", str(raw.get("thumbprint") or "").upper())[:160]
            if len(thumb) < 32:
                continue
            subject = str(raw.get("subject") or "")[:2000]
            cert_inn = str(raw.get("certificate_inn") or "") or None
            if cert_inn is None and subject:
                matched = re.search(
                    r"(?:OID\.1\.2\.643\.100\.4|INN|ИНН)\s*[=:]\s*(\d{10}|\d{12})",
                    subject,
                    re.IGNORECASE,
                )
                cert_inn = matched.group(1) if matched else None
            valid_from = _parse_dt(raw.get("valid_from"))
            valid_to = _parse_dt(raw.get("valid_to"))
            expiry = certificate_expiry_status(
                valid_to,
                critical_days=int(getattr(self.config, "certificate_expiry_critical_days", 7)),
                soon_days=int(getattr(self.config, "certificate_expiry_soon_days", 30)),
            )
            match_state = (
                "MATCH" if cert_inn == self.scope.participant_inn
                else "MISMATCH" if cert_inn
                else "UNKNOWN"
            )
            has_key = bool(raw.get("has_private_key"))
            compatible = cryptopro_available and str(raw.get("compatibility") or "") == "GOST_CRYPTOPRO"
            not_yet_valid = bool(valid_from and valid_from > now)
            ready = (
                has_key
                and compatible
                and not not_yet_valid
                and expiry in {"VALID", "EXPIRING_SOON", "EXPIRING_CRITICAL"}
                and match_state == "MATCH"
            )
            reason = (
                "CERTIFICATE_PARTICIPANT_MISMATCH" if match_state == "MISMATCH"
                else "CERTIFICATE_NO_PRIVATE_KEY" if not has_key
                else "CRYPTO_PROVIDER_UNAVAILABLE" if not compatible
                else "CERTIFICATE_NOT_YET_VALID" if not_yet_valid
                else "CERTIFICATE_EXPIRED" if expiry == "EXPIRED"
                else "CERTIFICATE_PARTICIPANT_MISMATCH" if match_state == "UNKNOWN"
                else None
            )
            row = self.db.scalar(select(AgentCertificateObservationRecord).where(
                AgentCertificateObservationRecord.agent_binding_id == binding.id,
                AgentCertificateObservationRecord.organisation_id == binding.organisation_id,
                AgentCertificateObservationRecord.participant_id == binding.participant_id,
                AgentCertificateObservationRecord.thumbprint == thumb,
            ).order_by(AgentCertificateObservationRecord.observed_at.desc()).limit(1).with_for_update())
            if row is None:
                row = AgentCertificateObservationRecord(
                    agent_binding_id=binding.id,
                    organisation_id=binding.organisation_id,
                    participant_id=binding.participant_id,
                    thumbprint=thumb,
                    observed_at=now,
                    readiness_state="UNKNOWN",
                    match_state="UNKNOWN",
                    expiry_state="UNKNOWN",
                )
                self.db.add(row)
            row.subject = subject or None
            row.issuer = str(raw.get("issuer") or "")[:2000] or None
            row.certificate_inn = cert_inn if cert_inn and cert_inn.isdigit() and len(cert_inn) in {10, 12} else None
            row.valid_from = valid_from
            row.valid_to = valid_to
            row.algorithm = str(raw.get("public_key_oid") or raw.get("signature_oid") or "")[:128] or None
            row.has_private_key = has_key
            row.crypto_provider = str(raw.get("crypto_provider") or "")[:160] or None
            row.compatibility = "GOST_CRYPTOPRO" if compatible else "UNSUPPORTED"
            row.serial = str(raw.get("serial") or "")[:160] or None
            row.observed_at = now
            row.readiness_state = "READY" if ready else "NOT_READY"
            row.match_state = match_state
            row.expiry_state = expiry
            row.reason_code = reason
            observed.append(row)
        self.db.flush()

        normalized_selected = (
            re.sub(r"[^0-9A-F]", "", selected_thumbprint.upper())[:160]
            if selected_thumbprint else None
        )
        eligible = [row for row in observed if row.readiness_state == "READY"]
        conn = self.db.scalar(select(TrueApiConnectionRecord).where(
            TrueApiConnectionRecord.organisation_id == self.scope.organisation_id,
            TrueApiConnectionRecord.participant_id == self.scope.participant_id,
            TrueApiConnectionRecord.state != "ARCHIVED",
        ).with_for_update())
        auto_selected = False
        if conn is not None:
            by_thumb = {row.thumbprint: row for row in observed}
            if conn.desired_certificate_ref:
                desired = by_thumb.get(conn.desired_certificate_ref)
                if desired is None or desired.readiness_state != "READY":
                    conn.desired_certificate_ref = None
                    conn.certificate_selection_state = "NONE"
                    conn.observed_certificate_observation_id = None
            if not conn.desired_certificate_ref and len(eligible) == 1:
                conn.desired_certificate_ref = eligible[0].thumbprint
                conn.certificate_selection_state = "PENDING_LOCAL_APPLY"
                auto_selected = True
            if conn.desired_certificate_ref:
                desired = by_thumb.get(conn.desired_certificate_ref)
                if normalized_selected:
                    if (
                        desired is not None
                        and normalized_selected == conn.desired_certificate_ref
                        and desired.readiness_state == "READY"
                    ):
                        conn.certificate_selection_state = "READY"
                        conn.observed_certificate_observation_id = desired.id
                    else:
                        conn.certificate_selection_state = "MISMATCH"
                        conn.observed_certificate_observation_id = None
                else:
                    conn.certificate_selection_state = "PENDING_LOCAL_APPLY"
                    conn.observed_certificate_observation_id = None

        binding.capabilities_sanitized = {
            **dict(binding.capabilities_sanitized or {}),
            "cryptopro_available": bool(cryptopro_available),
            "certificate_candidate_count": len(observed),
            "certificate_eligible_count": len(eligible),
            "certificate_discovery": True,
            "certificate_discovery_observed_at": _iso(now),
            "certificate_current_thumbprints": [row.thumbprint for row in observed],
            "certificate_eligible_thumbprints": [row.thumbprint for row in eligible],
        }
        self.db.flush()

        def public(row: AgentCertificateObservationRecord) -> dict[str, Any]:
            return {
                "id": row.id,
                "thumbprint": row.thumbprint,
                "subject": row.subject,
                "issuer": row.issuer,
                "certificate_inn": row.certificate_inn,
                "valid_from": _iso(row.valid_from),
                "valid_to": _iso(row.valid_to),
                "has_private_key": row.has_private_key,
                "crypto_provider": row.crypto_provider,
                "compatibility": row.compatibility,
                "match_state": row.match_state,
                "expiry_state": row.expiry_state,
                "readiness_state": row.readiness_state,
                "reason_code": row.reason_code,
                "observed_at": _iso(row.observed_at),
            }

        return {
            "cryptopro_available": bool(cryptopro_available),
            "candidates": [public(row) for row in observed],
            "selected_thumbprint": normalized_selected,
            "desired_certificate_thumbprint": conn.desired_certificate_ref if conn else None,
            "selection_state": conn.certificate_selection_state if conn else "NONE",
            "auto_selected": auto_selected,
        }


    def select_certificate(self, connection_id: str, thumbprint: str, *, user_id: int) -> dict[str, Any]:
        row = self._get("true-api", connection_id, lock=True)
        normalized = re.sub(r"[^0-9A-F]", "", thumbprint.upper())
        if len(normalized) < 32 or len(normalized) > 160:
            raise ValueError("certificate thumbprint is invalid")
        binding = AgentBindingService(self.db).primary_for_active_scope()
        if binding is None:
            raise ValueError("active Windows agent is required")
        current_thumbprints = {
            str(value)
            for value in (binding.capabilities_sanitized or {}).get("certificate_current_thumbprints", [])
            if isinstance(value, str)
        }
        if normalized not in current_thumbprints:
            raise ValueError("certificate is not a current ready participant-matching candidate")
        candidate = self.db.scalar(select(AgentCertificateObservationRecord).where(
            AgentCertificateObservationRecord.organisation_id == self.scope.organisation_id,
            AgentCertificateObservationRecord.participant_id == self.scope.participant_id,
            AgentCertificateObservationRecord.agent_binding_id == binding.id,
            AgentCertificateObservationRecord.thumbprint == normalized,
        ).order_by(AgentCertificateObservationRecord.observed_at.desc()).limit(1))
        if candidate is None or candidate.readiness_state != "READY":
            raise ValueError("certificate is not a current ready participant-matching candidate")
        row.desired_certificate_ref = normalized
        row.certificate_selection_state = "PENDING_LOCAL_APPLY"
        self.db.flush()
        self._audit(
            "CERTIFICATE_SELECTION_CHANGED", subject_type=SubjectType.INTEGRATION_CONNECTION,
            subject_id=row.id, user_id=user_id,
            metadata={"connection_id":row.id,"certificate_thumbprint":normalized,"selection_state":"PENDING_LOCAL_APPLY"},
        )
        return self.dto("true-api", row)

    def certificate_status(self) -> dict[str, Any]:
        binding = AgentBindingService(self.db).primary_for_active_scope()
        if binding is None:
            return {
                "status": "NOT_READY",
                "reason_code": "AGENT_OFFLINE",
                "observation": None,
                "candidates": [],
                "eligible_count": 0,
                "selection_state": "NONE",
                "desired_certificate_thumbprint": None,
                "cryptopro_available": False,
                "discovery_observed_at": None,
            }
        capabilities = dict(binding.capabilities_sanitized or {})
        current_thumbprints = [
            str(value)
            for value in capabilities.get("certificate_current_thumbprints", [])
            if isinstance(value, str)
        ]
        current_set = set(current_thumbprints)
        rows = (
            list(self.db.scalars(select(AgentCertificateObservationRecord).where(
                AgentCertificateObservationRecord.organisation_id == self.scope.organisation_id,
                AgentCertificateObservationRecord.participant_id == self.scope.participant_id,
                AgentCertificateObservationRecord.agent_binding_id == binding.id,
                AgentCertificateObservationRecord.thumbprint.in_(current_set),
            ).order_by(AgentCertificateObservationRecord.observed_at.desc())))
            if current_set else []
        )
        by_thumb = {row.thumbprint: row for row in rows}
        current = [by_thumb[thumb] for thumb in current_thumbprints if thumb in by_thumb]
        eligible = [row for row in current if row.readiness_state == "READY"]
        conn = self.db.scalar(select(TrueApiConnectionRecord).where(
            TrueApiConnectionRecord.organisation_id == self.scope.organisation_id,
            TrueApiConnectionRecord.participant_id == self.scope.participant_id,
            TrueApiConnectionRecord.state != "ARCHIVED",
        ))
        desired = conn.desired_certificate_ref if conn else None
        desired_current = next((row for row in current if desired and row.thumbprint == desired), None)
        selected = desired_current if desired_current and desired_current.readiness_state == "READY" else None
        if selected is None and not desired and len(eligible) == 1:
            selected = eligible[0]

        def public(row: AgentCertificateObservationRecord) -> dict[str, Any]:
            return {
                "id": row.id,
                "thumbprint": row.thumbprint,
                "subject": row.subject,
                "issuer": row.issuer,
                "certificate_inn": row.certificate_inn,
                "valid_from": _iso(row.valid_from),
                "valid_to": _iso(row.valid_to),
                "algorithm": row.algorithm,
                "has_private_key": row.has_private_key,
                "crypto_provider": row.crypto_provider,
                "compatibility": row.compatibility,
                "match_state": row.match_state,
                "expiry_state": row.expiry_state,
                "readiness_state": row.readiness_state,
                "reason_code": row.reason_code,
                "observed_at": _iso(row.observed_at),
            }

        selection_state = conn.certificate_selection_state if conn else "NONE"
        if not current:
            status, reason = "NOT_READY", "CERTIFICATE_NOT_FOUND"
        elif not eligible:
            status = "NOT_READY"
            reason = next((row.reason_code for row in current if row.reason_code), "CERTIFICATE_NOT_FOUND")
        elif desired:
            if selected is None:
                status = "NOT_READY"
                reason = desired_current.reason_code if desired_current and desired_current.reason_code else "CERTIFICATE_NOT_FOUND"
            elif selection_state == "READY":
                status, reason = "ACTIVE_READY", None
            elif selection_state == "PENDING_LOCAL_APPLY":
                status, reason = "SELECTED_PENDING_APPLY", None
            else:
                status, reason = "NOT_READY", "CERTIFICATE_NOT_FOUND"
        elif len(eligible) > 1:
            status, reason = "SELECTION_REQUIRED", "CERTIFICATE_SELECTION_REQUIRED"
        else:
            status, reason = "DISCOVERED_READY", None
        return {
            "status": status,
            "reason_code": reason,
            "observation": public(selected or desired_current) if (selected or desired_current) else None,
            "candidates": [public(row) for row in current],
            "eligible_count": len(eligible),
            "selection_state": selection_state,
            "desired_certificate_thumbprint": desired,
            "cryptopro_available": bool(capabilities.get("cryptopro_available")),
            "discovery_observed_at": capabilities.get("certificate_discovery_observed_at"),
        }

    def health_dto(self, check: IntegrationHealthCheckRecord) -> dict[str, Any]:
        if check.organisation_id != self.scope.organisation_id or check.participant_id != self.scope.participant_id:
            raise IntegrationNotFound("health check not found")
        return {
            "id":check.id,"integration_type":check.integration_type,
            "connection_type":check.connection_type,"connection_id":check.connection_id,
            "check_kind":check.check_kind,"started_at":_iso(check.started_at),
            "completed_at":_iso(check.completed_at),"overall_status":check.overall_status,
            "components":dict(check.component_statuses_json or {}),
            "capabilities":list(check.capabilities_json or []),
            "latency_ms":check.latency_ms,"remote_identity":dict(check.remote_identity_json or {}),
            "certificate":dict(check.certificate_snapshot_json or {}),
            "error_code":check.error_code,"message":check.redacted_message,
            "evidence_sha256":check.evidence_sha256,
        }

    def health(self, kind: str, object_id: str) -> dict[str, Any]:
        row = self._get(kind, object_id)
        latest = self._latest_health(kind, row.id)
        return {
            "connection": self.dto(kind, row),
            "latest": self.health_dto(latest) if latest else None,
        }

    def health_by_id(self, check_id: str) -> dict[str, Any]:
        check = self.db.scalar(select(IntegrationHealthCheckRecord).where(
            IntegrationHealthCheckRecord.id == check_id,
            IntegrationHealthCheckRecord.organisation_id == self.scope.organisation_id,
            IntegrationHealthCheckRecord.participant_id == self.scope.participant_id,
        ))
        if check is None:
            raise IntegrationNotFound("health check not found")
        return self.health_dto(check)

    def environment_capabilities(self) -> dict[str, Any]:
        provider_caps = self.secret_provider.capabilities
        return {
            "environment": self.config.environment,
            "agent_protocol": {"supported":"m14-v1","enabled":bool(self.config.agent_enabled)},
            "true_api_write_gate": bool(self.config.true_api_write_enabled),
            "true_api_real_read_gate": bool(self.config.true_api_real_read_enabled),
            "true_api_reports_gate": bool(self.config.true_api_reports_enabled),
            "secret_provider": {
                "read": bool(provider_caps & SecretCapability.READ),
                "write": bool(provider_caps & SecretCapability.WRITE),
                "version": bool(provider_caps & SecretCapability.VERSION),
                "revoke": bool(provider_caps & SecretCapability.REVOKE),
                "stage_activate": bool(provider_caps & SecretCapability.STAGE_ACTIVATE),
            },
            "audit_enabled": True,
            "capabilities": self._capabilities(),
            "blockers": {
                "EDO_XML_WRITE":"M7_OFFICIAL_XSD_NOT_PINNED",
                "SUZ_ORDER":"OFFICIAL_SUZ_PROGRAMMER_MANUAL_NOT_PINNED",
                "OZON_READ":"M10_EXECUTABLE_READ_CAPABILITIES_NONE",
            },
        }

    def agent_status(self) -> dict[str, Any]:
        rows = list(self.db.scalars(select(AgentBindingRecord).where(
            AgentBindingRecord.organisation_id == self.scope.organisation_id,
            AgentBindingRecord.participant_id == self.scope.participant_id,
            AgentBindingRecord.state != "ARCHIVED",
        ).order_by(AgentBindingRecord.is_primary.desc(), AgentBindingRecord.created_at)))
        service = AgentBindingService(self.db)
        return {
            "bindings":[service.status(
                row,
                online_seconds=int(getattr(self.config, "agent_health_online_seconds", 120)),
                stale_seconds=int(getattr(self.config, "agent_health_stale_seconds", 600)),
            ) for row in rows],
            "legacy_global_agent_allowed": False if any(r.state == "ACTIVE" for r in rows) else bool(
                getattr(self.config, "agent_legacy_bootstrap_enabled", True) and self.config.agent_machine_token
            ),
        }
