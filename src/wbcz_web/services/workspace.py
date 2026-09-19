from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from wbcz.document_assembler import DocumentAssemblyManualReview
from wbcz.models import Decision
from wbcz.write_pipeline import InvalidWriteOperation, WriteState
from wbcz_web.config import WebConfig
from wbcz_web.models import AgentJobRecord, BootstrapRecord, CheckRecord, WriteOperationRecord
from wbcz_web.repositories import AuditRepository, ImportRepository
from wbcz_web.services.agent_orchestration import CONTROL_CIS, POLL, RECONCILIATION_CIS, WRITE
from wbcz_web.services.document_orchestration import AgentOrchestrationBroker
from wbcz_web.services.imports import import_view, record_to_event
from wbcz_web.services.tenant import active_tenant, optional_tenant


READY_DECISIONS = frozenset({Decision.READY_TO_WITHDRAW.value, Decision.READY_TO_RETURN.value})
_DONE_DECISIONS = frozenset({Decision.ALREADY_DONE.value, Decision.NO_ACTION.value})

_REASON_GUIDANCE: dict[str, tuple[str, str, str]] = {
    "OWNER_MISMATCH": (
        "КИЗ принадлежит другой организации",
        "Владелец КИЗ в Честном знаке не совпадает с организацией этого сервиса.",
        "Проверьте владельца КИЗ и выберите корректную организацию. Автоматическое действие заблокировано.",
    ),
    "OWNER_UNKNOWN": (
        "Не удалось определить владельца КИЗ",
        "True API не вернул владельца КИЗ.",
        "Проверьте КИЗ вручную в Честном знаке и повторите контроль позже.",
    ),
    "SALE_RECEIPT_MISSING": (
        "Не хватает данных чека для продажи",
        "В архиве WB нет подтверждённых данных чека, необходимых для безопасного вывода.",
        "Получите архив WB с данными чека и загрузите его снова.",
    ),
    "RETURN_RECEIPT_MISSING": (
        "Не хватает данных чека для возврата",
        "В архиве WB нет подтверждённых данных чека, необходимых для безопасного возврата.",
        "Получите архив WB с данными чека и загрузите его снова.",
    ),
    "WRONG_PRODUCT_GROUP": (
        "КИЗ относится к другой товарной группе",
        "P0 поддерживает только товарную группу lp (одежда).",
        "Обработайте этот КИЗ вне текущего P0-сценария.",
    ),
    "UNKNOWN_CHZ_STATUS": (
        "Неизвестное состояние КИЗ",
        "Состояние Честного знака не входит в безопасно поддерживаемый P0-набор.",
        "Откройте КИЗ в Честном знаке и проверьте его вручную.",
    ),
    "NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL": (
        "Причина выбытия требует проверки",
        "КИЗ выбыл не по причине дистанционной продажи либо причина не подтверждена.",
        "Проверьте документ и причину выбытия вручную. Автоматический возврат запрещён.",
    ),
    "LEGAL_ENTITY_RULES_UNDEFINED": (
        "Продажа требует ручной проверки",
        "Для этого события backend не подтвердил безопасное правило автоматической обработки.",
        "Проверьте условия продажи вручную.",
    ),
    "STATE_LOOKUP_OR_NORMALIZATION_FAILED": (
        "Не удалось проверить КИЗ",
        "Backend не получил корректное состояние КИЗ из источника истины.",
        "Повторите проверку. Если ошибка сохранится, проверьте подключение и КИЗ вручную.",
    ),
    "HISTORY_ORDER_AMBIGUOUS": (
        "Неоднозначная история КИЗ",
        "Несколько событий этого КИЗ невозможно безопасно упорядочить автоматически.",
        "Откройте детали строки и проверьте историю событий вручную.",
    ),
    "ORGANISATION_CONFIG_MISSING": (
        "Не настроены данные организации",
        "Backend не может собрать официальный документ без явной конфигурации организации и места деятельности.",
        "Настройте production-конфигурацию организации. Не заполняйте недостающие поля догадками.",
    ),
    "REMOTE_SALE_RETURN_PAID_REQUIRED": (
        "Не указан признак оплаты возврата",
        "Для REMOTE_SALE_RETURN backend требует явный признак paid.",
        "Настройте признак paid для возврата перед повторной обработкой.",
    ),
    "RETURN_PRIMARY_DOCUMENT_REQUIRED": (
        "Нужен первичный документ возврата",
        "Для оплаченного возврата официальный payload требует первичный документ.",
        "Добавьте подтверждённый первичный документ. Backend не подставляет данные автоматически.",
    ),
    "LK_RECEIPT_UNSUPPORTED_CURRENCY": (
        "Неподдерживаемая валюта",
        "P0-сценарий LK_RECEIPT поддерживает только RUB.",
        "Проверьте исходные данные WB вручную.",
    ),
    "WB_EVENT_DATE_REQUIRED": (
        "Нет даты события WB",
        "Для официального документа нужна подтверждённая дата события.",
        "Загрузите архив WB, содержащий дату операции.",
    ),
    "WB_CIS_INVALID": (
        "Некорректный КИЗ",
        "КИЗ не прошёл обязательную нормализацию backend.",
        "Сверьте КИЗ с исходным архивом WB и Честным знаком.",
    ),
    "POLL_ATTEMPT_LIMIT": (
        "Результат документа не подтверждён",
        "Backend исчерпал безопасный лимит проверок статуса документа.",
        "Проверьте документ и КИЗ вручную перед любым повтором.",
    ),
    "POLL_DOCUMENT_ID_MISSING": (
        "Не получен идентификатор документа",
        "Невозможно безопасно продолжить проверку результата без documentId.",
        "Проверьте сохранённый ответ True API вручную.",
    ),
}


def _decision_label(decision: str | None) -> str:
    return {
        Decision.READY_TO_WITHDRAW.value: "Готово к выводу",
        Decision.READY_TO_RETURN.value: "Готово к возврату",
        Decision.ALREADY_DONE.value: "Уже выполнено",
        Decision.NO_ACTION.value: "Действие не требуется",
        Decision.MANUAL_REVIEW.value: "Требует внимания",
        Decision.ERROR.value: "Ошибка",
    }.get(decision or "", "Не проверено")


def _operation_label(operation: str) -> str:
    return {"SALE": "Продажа", "RETURN": "Возврат"}.get(operation, operation)


def _chz_label(snapshot: dict[str, Any] | None) -> str:
    if not snapshot:
        return "—"
    status = snapshot.get("status")
    reason = snapshot.get("withdrawReason")
    if status == "IN_CIRCULATION":
        return "В обороте"
    if status == "WITHDRAWN" and reason == "DISTANCE":
        return "Выбыл · дистанционная продажа"
    if status == "WITHDRAWN":
        return "Выбыл"
    return str(status or "—")


def _guidance(reason: str | None, error: str | None) -> tuple[str | None, str | None, str | None]:
    if reason and reason in _REASON_GUIDANCE:
        return _REASON_GUIDANCE[reason]
    if error:
        return (
            "Требуется проверка",
            "Backend остановил автоматическую обработку этой строки.",
            "Откройте детали и проверьте сохранённую ошибку. Не повторяйте действие вслепую.",
        )
    if reason:
        return (
            "Требуется проверка",
            "Backend не разрешил автоматическую обработку этой строки.",
            "Откройте детали и проверьте причину вручную.",
        )
    return None, None, None


def _batch_state(db: Session, event_ids: list[str]):
    if not event_ids:
        return {}, {}, {}

    latest_checks = (
        select(CheckRecord.event_id, func.max(CheckRecord.id).label("latest_id"))
        .where(CheckRecord.event_id.in_(event_ids))
        .group_by(CheckRecord.event_id)
        .subquery()
    )
    checks = {
        row.event_id: row
        for row in db.scalars(
            select(CheckRecord).join(latest_checks, CheckRecord.id == latest_checks.c.latest_id)
        )
    }

    writes: dict[str, WriteOperationRecord] = {}
    for row in db.scalars(
        select(WriteOperationRecord)
        .where(WriteOperationRecord.event_id.in_(event_ids))
        .order_by(WriteOperationRecord.updated_at, WriteOperationRecord.operation_id)
    ):
        writes[row.event_id] = row

    jobs: dict[tuple[str, str], AgentJobRecord] = {}
    for row in db.scalars(
        select(AgentJobRecord)
        .where(
            AgentJobRecord.event_id.in_(event_ids),
            AgentJobRecord.purpose.in_((CONTROL_CIS, WRITE, POLL, RECONCILIATION_CIS)),
        )
        .order_by(AgentJobRecord.created_at, AgentJobRecord.job_id)
    ):
        if row.event_id:
            jobs[(row.event_id, row.purpose)] = row
    return checks, writes, jobs


def _pipeline_state(
    check: CheckRecord | None,
    write: WriteOperationRecord | None,
    jobs: dict[str, AgentJobRecord],
) -> tuple[str, str, str, str]:
    if write is not None:
        state = WriteState(write.state)
        if state is WriteState.SUCCEEDED:
            return "COMPLETED", "Выполнено", "DONE", "Выполнено"
        if state in {WriteState.FAILED, WriteState.ERROR}:
            return "ERROR", "Ошибка", "ERROR", "Не выполнено"
        if state is WriteState.MANUAL_REVIEW:
            return "MANUAL_REVIEW", "Требует внимания", "ATTENTION", "Нужна ручная проверка"
        if state in {WriteState.PREPARED, WriteState.AWAITING_SIGNATURE}:
            write_job = jobs.get(WRITE)
            if write_job and write_job.state == "LEASED":
                return "WAITING_SIGNATURE", "Ожидает подписи", "PROCESSING", "В работе"
            return "WAITING_AGENT", "Ожидает агента", "PROCESSING", "В работе"
        if state in {WriteState.SIGNED, WriteState.SUBMITTING}:
            return "SENDING", "Отправляется", "PROCESSING", "В работе"
        if state in {WriteState.SUBMITTED, WriteState.PROCESSING, WriteState.RECONCILIATION_REQUIRED}:
            return "VERIFYING", "Проверяем результат", "PROCESSING", "В работе"

    if check is None:
        control_job = jobs.get(CONTROL_CIS)
        if control_job and control_job.state in {"PENDING", "LEASED"}:
            return "CHECKING", "Проверяем КИЗ", "PROCESSING", "Проверка"
        return "NOT_CHECKED", "Не проверено", "OTHER", "—"

    if check.decision in READY_DECISIONS:
        return "READY", "Готово к обработке", "READY", "Готово"
    if check.decision == Decision.MANUAL_REVIEW.value:
        return "MANUAL_REVIEW", "Требует внимания", "ATTENTION", "Нужна ручная проверка"
    if check.decision == Decision.ERROR.value:
        return "ERROR", "Ошибка", "ERROR", "Не выполнено"
    if check.decision in _DONE_DECISIONS:
        return "ALREADY_DONE", "Выполнено / не требуется", "DONE", "Готово"
    return "NOT_CHECKED", "Не проверено", "OTHER", "—"


def workspace_items(db: Session, import_id: str) -> list[dict[str, Any]]:
    imports = ImportRepository(db)
    if imports.get(import_id) is None:
        raise KeyError("Импорт не найден")
    records = imports.ordered_event_records(import_id)
    event_ids = [row.event_id for row in records]
    checks, writes, jobs = _batch_state(db, event_ids)
    result: list[dict[str, Any]] = []

    for row in records:
        event = record_to_event(row)
        check = checks.get(row.event_id)
        write = writes.get(row.event_id)
        event_jobs = {
            purpose: jobs[(row.event_id, purpose)]
            for purpose in (CONTROL_CIS, WRITE, POLL, RECONCILIATION_CIS)
            if (row.event_id, purpose) in jobs
        }
        ui_state, state_label, filter_group, result_label = _pipeline_state(check, write, event_jobs)
        reason = check.reason if check else None
        error = check.error if check else None
        attention_title, attention_detail, user_action = _guidance(reason, error)
        decision = check.decision if check else None
        action_label = (
            "Вывести из оборота"
            if decision == Decision.READY_TO_WITHDRAW.value
            else "Возврат в оборот"
            if decision == Decision.READY_TO_RETURN.value
            else "—"
        )
        result.append(
            {
                "event_id": row.event_id,
                "kiz": event.kiz,
                "operation": event.operation.value,
                "operation_label": _operation_label(event.operation.value),
                "chz_status": _chz_label(check.snapshot if check else None),
                "decision": decision,
                "decision_label": _decision_label(decision),
                "action_label": action_label,
                "result_label": result_label,
                "ui_state": ui_state,
                "state_label": state_label,
                "filter_group": filter_group,
                "ready_for_bulk": decision in READY_DECISIONS and write is None,
                "reason": reason,
                "error": error,
                "attention_title": attention_title,
                "attention_detail": attention_detail,
                "user_action": user_action,
                "checked_at": check.checked_at.isoformat() if check and check.checked_at else None,
                "write_operation_id": write.operation_id if write else None,
                "write_state": write.state if write else None,
                "document_id": write.document_id if write else None,
                "details": {
                    "task_number": event.task_number,
                    "sticker": event.sticker,
                    "receipt_number": event.receipt_number,
                    "fiscal_drive_number": event.fiscal_drive_number,
                    "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
                    "amount": str(event.amount),
                    "currency": event.currency,
                    "reason_code": reason,
                },
            }
        )
    return result


def bulk_preview(db: Session, import_id: str) -> dict[str, Any]:
    items = workspace_items(db, import_id)
    eligible = [item for item in items if item["ready_for_bulk"]]
    return {
        "eligible_count": len(eligible),
        "withdraw_count": sum(item["decision"] == Decision.READY_TO_WITHDRAW.value for item in eligible),
        "return_count": sum(item["decision"] == Decision.READY_TO_RETURN.value for item in eligible),
        "excluded_count": len(items) - len(eligible),
        "event_ids": [item["event_id"] for item in eligible],
    }


def _history_status(items: list[dict[str, Any]]) -> tuple[str, str]:
    groups = Counter(item["filter_group"] for item in items)
    states = {item["ui_state"] for item in items}
    if groups["ERROR"]:
        return "error", "Есть ошибки"
    if groups["ATTENTION"]:
        return "attention", "Требует внимания"
    if states.intersection({"CHECKING", "WAITING_AGENT", "WAITING_SIGNATURE", "SENDING", "VERIFYING"}):
        return "processing", "В работе"
    if groups["READY"]:
        return "ready", "Готово к действиям"
    if items and groups["DONE"] == len(items):
        return "completed", "Обработан"
    if any(item["decision"] for item in items):
        return "checked", "Проверен"
    return "uploaded", "Загружен"


def workspace_history(db: Session, limit: int = 10) -> list[dict[str, Any]]:
    imports = ImportRepository(db)
    result: list[dict[str, Any]] = []
    for row in imports.list_recent(limit=limit):
        items = workspace_items(db, row.id)
        status, status_label = _history_status(items)
        value = import_view(row)
        value.update({"workflow_status": status, "workflow_status_label": status_label})
        result.append(value)
    return result


def workspace_overview(db: Session, config: WebConfig, import_id: str) -> dict[str, Any]:
    imports = ImportRepository(db)
    row = imports.get(import_id)
    if row is None:
        raise KeyError("Импорт не найден")
    items = workspace_items(db, import_id)
    counts = Counter(item["filter_group"] for item in items)
    return {
        "file": import_view(row),
        "items": items,
        "filters": {
            "ALL": len(items),
            "READY": counts["READY"],
            "PROCESSING": counts["PROCESSING"],
            "ATTENTION": counts["ATTENTION"],
            "DONE": counts["DONE"],
            "ERROR": counts["ERROR"],
        },
        "bulk": bulk_preview(db, import_id),
        "runtime": {
            "agent_enabled": config.agent_enabled,
            "production_write_enabled": config.true_api_write_enabled,
        },
    }


class BulkActionUnavailable(InvalidWriteOperation):
    pass


def execute_bulk_actions(db: Session, config: WebConfig, import_id: str, user_id: int) -> dict[str, Any]:
    if not config.agent_enabled or not config.agent_machine_token:
        raise BulkActionUnavailable("Windows agent is not configured; ready actions were not started")

    imports = ImportRepository(db)
    if imports.get(import_id) is None:
        raise KeyError("Импорт не найден")

    broker = AgentOrchestrationBroker(db, config)
    started: list[str] = []
    manual_review: list[str] = []
    already_started = 0
    withdraw = 0
    returns = 0

    for row in imports.ordered_event_records(import_id):
        check = imports.latest_check(row.event_id)
        if check is None or check.decision not in READY_DECISIONS:
            continue
        scope = optional_tenant(db)
        if scope is None and db.get(BootstrapRecord,1) is not None:
            raise PermissionError("active tenant scope required")
        existing_stmt=select(WriteOperationRecord).where(WriteOperationRecord.event_id==row.event_id)
        if scope is not None:
            existing_stmt=existing_stmt.where(
                WriteOperationRecord.organisation_id==scope.organisation_id,
                WriteOperationRecord.participant_id==scope.participant_id,
            )
        existing=db.scalar(existing_stmt.limit(1))
        if existing is not None:
            already_started += 1
            continue
        decision = Decision(check.decision)
        event = record_to_event(row)
        try:
            document = broker.document_assembler.build_exact(event, decision)
            broker.prepare_approved_write(row.event_id, document, decision=decision)
        except DocumentAssemblyManualReview as exc:
            check.decision = Decision.MANUAL_REVIEW.value
            check.reason = exc.reason
            check.error = "DOCUMENT_ASSEMBLY_BLOCKED"
            manual_review.append(row.event_id)
            continue
        started.append(row.event_id)
        if decision is Decision.READY_TO_WITHDRAW:
            withdraw += 1
        else:
            returns += 1

    AuditRepository(db).append(
        "BULK_ACTION_STARTED",
        user_id=user_id,
        entity_type="import",
        entity_id=import_id,
        metadata={
            "started": len(started),
            "withdraw": withdraw,
            "return": returns,
            "manual_review": len(manual_review),
            "already_started": already_started,
            "production_write_enabled": config.true_api_write_enabled,
        },
    )
    db.flush()
    return {
        "started_count": len(started),
        "withdraw_count": withdraw,
        "return_count": returns,
        "manual_review_count": len(manual_review),
        "already_started_count": already_started,
        "started_event_ids": started,
        "manual_review_event_ids": manual_review,
        "production_write_enabled": config.true_api_write_enabled,
    }
