import "./app.css";
import * as api from "./api";
import type {
  BulkPreview,
  EventDetail,
  FileItem,
  FilterKey,
  UserInfo,
  WorkspaceItem,
  WorkspaceView,
  AgentBindingStatus,
  CertificateStatus,
  EnrollmentIntent,
  IntegrationItem,
  LocalTrueApiStatus,
} from "./types";
import { filterWorkspaceItems, shortKiz, shouldPollWorkspace, stateTone } from "./workflow";

const app = document.querySelector<HTMLDivElement>("#app")!;
const LOCAL_FBS_ONLY = import.meta.env.VITE_SELLARI_LOCAL_FBS_ONLY === "true";
const BRAND_NAME = LOCAL_FBS_ONLY ? "Sellari" : "markflow";

let user: UserInfo | null = null;
let homeHistory: FileItem[] = [];
let current: WorkspaceView | null = null;
let filter: FilterKey = "ALL";
let query = "";
let openDetail: string | null = null;
let detailCache = new Map<string, EventDetail>();
let uploading = false;
let checking = false;
let bulkBusy = false;
let pollTimer: number | null = null;
let enrollmentIntent: EnrollmentIntent | null = null;
let kiLookupMessage = "";
let localTrueApiStatus: LocalTrueApiStatus | null = null;
let localTrueApiBusy = false;
let viewToken = 0;

const icons = {
  mark: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.3c3.5 4.2 6 7 6 10.3a6 6 0 1 1-12 0c0-3.3 2.5-6.1 6-10.3Z" fill="currentColor"/><path d="M9.7 16.6c1.7.7 3.7-.1 4.5-1.7" fill="none" stroke="white" stroke-width="1.35" stroke-linecap="round"/></svg>`,
  upload: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V5m0 0-4 4m4-4 4 4M5 15v3.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V15" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  search: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.7" cy="10.7" r="5.7" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m15.1 15.1 4 4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,
  file: `<svg viewBox="0 0 24 28" aria-hidden="true"><path d="M5.5 1.5h8.8l5.2 5.2V25a1.5 1.5 0 0 1-1.5 1.5H5.5A1.5 1.5 0 0 1 4 25V3a1.5 1.5 0 0 1 1.5-1.5Z" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M14 1.8V7h5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 12.3h8M8 15.5h8M8 18.7h5" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
  chevron: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8.5 10 3.5 3.5 3.5-3.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  copy: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="10" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M15 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>`,
  close: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 7 10 10M17 7 7 17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,
};

function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (char) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!,
  );
}

function stopPolling(): void {
  if (pollTimer !== null) window.clearTimeout(pollTimer);
  pollTimer = null;
}

function importFromUrl(): string | null {
  return new URL(window.location.href).searchParams.get("import");
}

function viewFromUrl(): string | null {
  return new URL(window.location.href).searchParams.get("view");
}

function setViewUrl(view: string | null): void {
  const url = new URL(window.location.href);
  if (view) {
    url.searchParams.set("view", view);
    url.searchParams.delete("import");
  } else {
    url.searchParams.delete("view");
  }
  window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
}

function setImportUrl(importId: string | null): void {
  const url = new URL(window.location.href);
  if (importId) url.searchParams.set("import", importId);
  else url.searchParams.delete("import");
  window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
}

function fmtHistoryDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function fmtDate(value: string | null): string {
  if (!value) return "—";
  return new Date(value).toLocaleDateString("ru-RU");
}

function shell(content: string): void {
  const initials = (user?.username || "").slice(0, 2).toUpperCase();
  app.innerHTML = `
    <header class="topbar">
      <button id="nav-workspace" class="brand-button">${BRAND_NAME}</button>
      <div class="topbar-right">
        ${LOCAL_FBS_ONLY ? "" : '<button id="nav-settings" class="quiet-button">Настройки</button>'}
        <span class="safety-indicator"><i></i>DRY RUN</span>
        <span class="safety-indicator"><i></i>Отправка в ЧЗ отключена</span>
        <span class="profile" title="${esc(user?.username || "")}">${esc(initials)}</span>
        <button id="logout" class="quiet-button">Выйти</button>
      </div>
    </header>
    <aside class="rail" aria-label="Навигация"><button id="rail-workspace" class="rail-mark" title="WB FBS">${icons.mark}</button></aside>
    <main class="main">${content}</main>
    <div id="toast-root" class="toast-root" aria-live="polite"></div>`;
  document.querySelector<HTMLButtonElement>("#nav-workspace")?.addEventListener("click", () => {
    setViewUrl(null);
    void restoreInitialView();
  });
  document.querySelector<HTMLButtonElement>("#rail-workspace")?.addEventListener("click", () => {
    setViewUrl(null);
    void restoreInitialView();
  });
  document.querySelector<HTMLButtonElement>("#nav-settings")?.addEventListener("click", () => {
    void openIntegrations();
  });
  document.querySelector<HTMLButtonElement>("#logout")?.addEventListener("click", async () => {
    stopPolling();
    await api.logout();
    await api.seedCsrf();
    user = null;
    renderLogin();
  });
}

function renderLogin(error = ""): void {
  stopPolling();
  app.innerHTML = `<main class="login-page"><form id="login" class="login-card">
    <div class="login-brand">${BRAND_NAME}</div>
    <h1>Маркировка</h1>
    <p>Рабочая область WB FBS</p>
    ${error ? `<div class="login-error">${esc(error)}</div>` : ""}
    <label>Логин<input id="username" autocomplete="username" required></label>
    <label>Пароль<input id="password" type="password" autocomplete="current-password" required></label>
    <button class="primary-button wide" type="submit">Войти</button>
  </form></main>`;
  document.querySelector<HTMLFormElement>("#login")!.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      user = await api.login(
        document.querySelector<HTMLInputElement>("#username")!.value,
        document.querySelector<HTMLInputElement>("#password")!.value,
      );
      await refreshLocalTrueApiStatus();
      await restoreInitialView();
    } catch (e) {
      renderLogin(readError(e));
    }
  });
}

function pageHeading(): string {
  return `<div class="page-heading"><h1>Вывод и возврат КИЗ · WB FBS</h1></div>`;
}

function uploadBlock(): string {
  return `<section id="dropzone" class="dropzone ${uploading ? "busy" : ""}" tabindex="0" aria-label="Загрузить XLSX Wildberries">
    <input id="file" type="file" accept=".xlsx" hidden ${uploading ? "disabled" : ""}>
    <div class="drop-icon">${uploading ? '<span class="spinner"></span>' : icons.upload}</div>
    <strong>${uploading ? "Загружаем файл…" : "Перетащите XLSX сюда"}</strong>
    <span>${uploading ? "Проверяем структуру на backend" : "или нажмите, чтобы выбрать файл"}</span>
  </section>
  <details class="wb-hint"><summary>Как получить файл WB</summary><p>В кабинете Wildberries выгрузите XLSX-архив FBS с КИЗ и данными операций. Загружайте исходный файл без ручного редактирования.</p></details>`;
}

function kiLookupBlock(): string {
  return `<section class="ki-lookup-card">
    <div><strong>Поиск КИ в Честном знаке</strong><span>Только чтение · свежий /cises/info</span></div>
    <form id="ki-lookup-form">
      <input id="ki-lookup-value" autocomplete="off" placeholder="Введите КИ">
      <button class="secondary-button" type="submit">Проверить</button>
    </form>
    ${kiLookupMessage ? `<p class="ki-lookup-result">${esc(kiLookupMessage)}</p>` : ""}
  </section>`;
}

function localTrueApiBlock(): string {
  if (!LOCAL_FBS_ONLY) return "";
  if (!localTrueApiStatus) {
    return `<section class="ki-lookup-card"><div><strong>Честный знак / CryptoPro</strong><span>Проверяем локальную УКЭП…</span></div></section>`;
  }
  const status = localTrueApiStatus;
  const selected = status.candidates.find((item) => item.thumbprint === status.selected_thumbprint);
  const candidates = status.candidates.filter((item) => item.eligible);
  const candidateRows = !status.selected_thumbprint
    ? candidates.map((candidate) => `<div class="certificate-row">
        <div><b>${esc(candidate.subject || candidate.thumbprint)}</b><small>${esc(candidate.certificate_inn || "ИНН не извлечён")} · до ${esc(candidate.valid_to || "—")}</small></div>
        <button class="quiet-button" data-local-cert="${esc(candidate.thumbprint)}">Выбрать</button>
      </div>`).join("")
    : "";
  const connection = status.authenticated
    ? `<span>Подключено · только чтение${status.expire_date ? ` · сессия до ${esc(fmtHistoryDate(status.expire_date))}` : ""}</span>`
    : status.selected_thumbprint
      ? `<button id="local-true-api-auth" class="secondary-button" ${localTrueApiBusy ? "disabled" : ""}>${localTrueApiBusy ? "Подключаем…" : "Войти через CryptoPro / УКЭП"}</button>`
      : candidateRows || '<span>Подходящая УКЭП не найдена. Проверьте CryptoPro и сертификат.</span>';
  return `<section class="ki-lookup-card">
    <div><strong>Честный знак / CryptoPro</strong><span>${status.authenticated ? "Real read-only включён" : "Business writes отключены"}</span></div>
    ${selected ? `<p class="integration-note">Сертификат: ${esc(selected.subject || selected.thumbprint)}</p>` : ""}
    ${connection}
    ${status.error_code ? `<p class="login-error">${esc(status.error_code)}</p>` : ""}
    <p class="integration-note">PIN запрашивает CryptoPro локально; Sellari не сохраняет PIN, ключ или uuidToken.</p>
  </section>`;
}

function rerenderCurrentSurface(): void {
  if (current) renderWorkspace();
  else renderHome();
}

async function refreshLocalTrueApiStatus(): Promise<void> {
  if (!LOCAL_FBS_ONLY || !user) return;
  try {
    localTrueApiStatus = await api.localTrueApiStatus();
  } catch (error) {
    localTrueApiStatus = null;
    showToast(readError(error), "error");
  }
}

function bindLocalTrueApi(): void {
  if (!LOCAL_FBS_ONLY) return;
  document.querySelectorAll<HTMLButtonElement>("[data-local-cert]").forEach((button) => {
    button.addEventListener("click", async () => {
      const thumbprint = button.dataset.localCert || "";
      if (!thumbprint || localTrueApiBusy) return;
      localTrueApiBusy = true;
      rerenderCurrentSurface();
      try {
        localTrueApiStatus = await api.selectLocalTrueApiCertificate(thumbprint);
        showToast("УКЭП выбрана");
      } catch (error) {
        showToast(readError(error), "error");
      } finally {
        localTrueApiBusy = false;
        rerenderCurrentSurface();
      }
    });
  });
  document.querySelector<HTMLButtonElement>("#local-true-api-auth")?.addEventListener("click", async () => {
    if (localTrueApiBusy) return;
    localTrueApiBusy = true;
    rerenderCurrentSurface();
    try {
      await api.authenticateLocalTrueApi();
      await refreshLocalTrueApiStatus();
      showToast("True API подключён в режиме только чтения");
    } catch (error) {
      await refreshLocalTrueApiStatus();
      showToast(readError(error), "error");
    } finally {
      localTrueApiBusy = false;
      rerenderCurrentSurface();
    }
  });
}

async function runKiLookup(): Promise<void> {
  const input = document.querySelector<HTMLInputElement>("#ki-lookup-value");
  const value = input?.value.trim() || "";
  if (!value) return;
  kiLookupMessage = "Выполняем безопасный read-only запрос…";
  renderHome();
  try {
    if (LOCAL_FBS_ONLY) {
      const response = await api.localCisesInfo([value]);
      const item = response.items[0];
      const state = item?.normalized;
      kiLookupMessage = state
        ? `${state.status || "—"} · владелец ${state.owner_inn || "—"} · ${state.product_group || "lp"} · сейчас`
        : `ЧЗ не вернул состояние КИ${item?.item_error?.code ? ` · ${item.item_error.code}` : ""}`;
      await refreshLocalTrueApiStatus();
      renderHome();
      return;
    }
    const queued = await api.queueKiInfo([value]);
    for (let attempt = 0; attempt < 40; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 500));
      const status = await api.kiRequest(queued.request_id);
      if (status.status === "completed") {
        const item = status.result?.items?.[0];
        const state = item?.normalized;
        kiLookupMessage = state
          ? `${state.status || "—"} · владелец ${state.owner_inn || "—"} · ${state.product_name || state.gtin || "товар"} · ${status.fetched_at || "сейчас"}`
          : `ЧЗ не вернул состояние КИ${item?.item_error?.code ? ` · ${item.item_error.code}` : ""}`;
        renderHome();
        return;
      }
      if (status.status === "failed") {
        kiLookupMessage = "Read-only запрос завершился ошибкой. Production writes не выполнялись.";
        renderHome();
        return;
      }
    }
    kiLookupMessage = "Ответ ещё не получен. Повторите проверку позже.";
  } catch (error) {
    kiLookupMessage = readError(error);
  }
  renderHome();
}

function historySection(items: FileItem[], currentId: string | null): string {
  return `<section class="history-section" id="history">
    <div class="section-title"><h2>История файлов</h2></div>
    ${items.length ? `<div class="history-list">${items.map((item) => `
      <button class="history-row ${item.id === currentId ? "active" : ""}" data-open-import="${esc(item.id)}">
        <span class="history-file-icon">${icons.file}</span>
        <span class="history-name"><b>${esc(item.filename)}</b><small>${fmtHistoryDate(item.imported_at)}</small></span>
        <span class="history-status status-${esc(item.workflow_status || "uploaded")}"><i></i>${esc(item.workflow_status_label || "Загружен")}</span>
        <span class="history-kiz">${item.unique_kiz} КИЗ</span>
      </button>`).join("")}</div>` : `<div class="history-empty">Загруженных файлов пока нет</div>`}
  </section>`;
}

function bindHistory(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-open-import]").forEach((button) => {
    button.addEventListener("click", () => void openImport(button.dataset.openImport!));
  });
}

function bindUpload(): void {
  const drop = document.querySelector<HTMLElement>("#dropzone");
  const input = document.querySelector<HTMLInputElement>("#file");
  if (!drop || !input) return;
  const pick = () => { if (!uploading) input.click(); };
  drop.addEventListener("click", pick);
  drop.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); pick(); }
  });
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    if (file) void loadFile(file);
  });
  drop.addEventListener("dragover", (event) => { event.preventDefault(); if (!uploading) drop.classList.add("drag"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("drag");
    const file = event.dataTransfer?.files?.[0];
    if (file && !uploading) void loadFile(file);
  });
}

function renderHome(): void {
  current = null;
  filter = "ALL";
  query = "";
  openDetail = null;
  setImportUrl(null);
  shell(`${pageHeading()}${localTrueApiBlock()}${kiLookupBlock()}${uploadBlock()}${historySection(homeHistory, null)}`);
  bindLocalTrueApi();
  document.querySelector<HTMLFormElement>("#ki-lookup-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    void runKiLookup();
  });
  bindUpload();
  bindHistory();
}

async function refreshHomeHistory(): Promise<void> {
  const home = await api.workspaceHome();
  homeHistory = home.history;
}

async function loadFile(file: File): Promise<void> {
  if (!file.name.toLocaleLowerCase("ru-RU").endsWith(".xlsx")) {
    showToast("Поддерживается только формат XLSX", "error");
    return;
  }
  uploading = true;
  renderHome();
  try {
    const imported = await api.upload(file);
    await refreshHomeHistory();
    await openImport(imported.id, true);
  } catch (e) {
    showToast(readError(e), "error");
    uploading = false;
    renderHome();
  } finally {
    uploading = false;
  }
}

const filterLabels: Record<FilterKey, string> = {
  ALL: "Все",
  READY: "Готово",
  PROCESSING: "В работе",
  ATTENTION: "Требует внимания",
  DONE: "Выполнено",
  ERROR: "Ошибка",
};

function filterBar(view: WorkspaceView): string {
  return `<div class="filter-line">
    <div class="filter-tabs" role="tablist" aria-label="Фильтр состояний">
      ${(Object.keys(filterLabels) as FilterKey[]).map((key) => `<button class="filter-tab ${filter === key ? "active" : ""}" data-filter="${key}">${filterLabels[key]}<span>${view.filters[key] || 0}</span></button>`).join("")}
    </div>
    <label class="search-field">${icons.search}<input id="search" autocomplete="off" placeholder="Поиск по КИЗ" value="${esc(query)}"></label>
  </div>`;
}

function decisionBadge(item: WorkspaceItem): string {
  const tone = stateTone(item);
  return `<span class="badge ${tone}">${esc(item.decision_label)}</span>`;
}

function stateCell(item: WorkspaceItem): string {
  const tone = stateTone(item);
  return `<span class="result-state ${tone}"><i></i>${esc(item.state_label)}</span>`;
}

function tableRows(view: WorkspaceView): string {
  const list = filterWorkspaceItems(view.items, filter, query);
  if (!list.length) return `<tr><td colspan="6"><div class="table-empty">По этому фильтру строк нет</div></td></tr>`;
  return list.map((item) => `
    <tr class="work-row tone-${stateTone(item)}">
      <td><div class="kiz-line"><code title="${esc(item.kiz)}">${esc(shortKiz(item.kiz))}</code><button class="copy-button" data-copy-kiz="${esc(item.kiz)}" title="Копировать КИЗ">${icons.copy}</button></div></td>
      <td>${esc(item.operation_label)}</td>
      <td>${esc(item.chz_status)}</td>
      <td>${decisionBadge(item)}</td>
      <td>${item.action_label !== "—" ? `<span class="action-text">${esc(item.action_label)}</span>` : '<span class="dash">—</span>'}</td>
      <td><div class="result-cell">${stateCell(item)}<button class="detail-toggle ${openDetail === item.event_id ? "open" : ""}" data-detail="${esc(item.event_id)}" title="Подробности">${icons.chevron}</button></div></td>
    </tr>
    ${openDetail === item.event_id ? `<tr class="detail-row"><td colspan="6"><div id="detail-${esc(item.event_id)}" class="detail-panel">${detailMarkup(item, detailCache.get(item.event_id))}</div></td></tr>` : ""}`
  ).join("");
}

function detailMarkup(item: WorkspaceItem, detail?: EventDetail): string {
  const problem = item.filter_group === "ATTENTION" || item.filter_group === "ERROR";
  return `<div class="detail-layout">
    ${problem ? `<section class="problem-card ${item.filter_group === "ERROR" ? "error" : "attention"}">
      <strong>${esc(item.attention_title || item.decision_label)}</strong>
      <p>${esc(item.attention_detail || "Backend остановил автоматическую обработку.")}</p>
      ${item.user_action ? `<div class="user-action"><span>Что делать</span>${esc(item.user_action)}</div>` : ""}
    </section>` : ""}
    <section class="detail-data">
      <div><span>КИЗ</span><code>${esc(item.kiz)}</code></div>
      <div><span>Задание WB</span><b>${esc(item.details.task_number || "—")}</b></div>
      <div><span>Стикер</span><b>${esc(item.details.sticker || "—")}</b></div>
      <div><span>Дата операции</span><b>${fmtDate(item.details.occurred_at)}</b></div>
      <div><span>Чек</span><b>${esc(item.details.receipt_number || "—")}</b></div>
      <div><span>Сумма</span><b>${esc(item.details.amount)} ${esc(item.details.currency)}</b></div>
      <div><span>Источник WB</span><b>${esc(item.details.source_file || "—")} · строка ${esc(item.details.source_row_number || "—")}</b></div>
      <div><span>Свежесть ЧЗ</span><b>${esc(item.fetched_at || "—")}</b></div>
      <div><span>status</span><b>${esc(item.status || "—")}</b></div>
      <div><span>statusEx</span><b>${esc(item.statusEx || "—")}</b></div>
      <div><span>Причина выбытия</span><b>${esc(item.withdrawReason || "—")}</b></div>
      <div><span>Владелец</span><b>${esc(item.ownerInn || "—")}</b></div>
      <div><span>Владелец совпадает</span><b>${item.owner_match == null ? "—" : item.owner_match ? "Да" : "Нет"}</b></div>
      <div><span>Товарная группа</span><b>${esc(item.productGroup || "—")}</b></div>
      <div><span>Источник</span><b>${esc(item.source || "—")}</b></div>
    </section>
    ${detail ? `<section class="kiz-history"><div class="detail-section-head"><strong>История КИЗ</strong><span>${detail.history.length}</span></div>${detail.history.map((entry) => `<div class="history-event"><span>${esc(entry.operation === "SALE" ? "Продажа" : entry.operation === "RETURN" ? "Возврат" : entry.operation)}</span><span>${fmtDate(entry.occurred_at)}</span><span>Задание ${esc(entry.task_number)}</span></div>`).join("")}${detail.history_order_ambiguous ? '<p class="inline-warning">Порядок событий неоднозначен — автоматическое действие запрещено.</p>' : ""}</section>` : '<div class="detail-loading">Загружаем историю…</div>'}
    ${(item.reason || item.error) ? `<details class="technical-detail"><summary>Технические детали</summary><code>${esc(item.reason || "")}${item.error ? ` · ${esc(item.error)}` : ""}</code></details>` : ""}
  </div>`;
}

function statusBanner(view: WorkspaceView): string {
  const processing = view.filters.PROCESSING || 0;
  const ready = view.bulk.eligible_count;
  if (checking) return `<div class="workflow-status progress"><span class="spinner"></span><strong>Проверяем КИЗ</strong><span>Результаты появятся в таблице</span></div>`;
  if (processing) return `<div class="workflow-status progress"><span class="pulse"></span><strong>Обработка продолжается</strong><span>Состояние восстанавливается из backend; страницу можно обновить</span></div>`;
  if (ready) return `<div class="workflow-status ready"><span class="dot"></span><strong>Готово к обработке</strong><span>Backend разрешил ${ready} ${plural(ready, "действие", "действия", "действий")}</span></div>`;
  return "";
}

function bulkBar(view: WorkspaceView): string {
  const total = view.bulk.eligible_count;
  if (view.runtime.fbs_dry_run_only || !view.runtime.production_write_enabled) {
    const title = view.runtime.fbs_dry_run_only
      ? "DRY RUN — реальные действия отключены"
      : "READ ONLY — реальные действия отключены";
    return `<div class="bulk-bar"><div class="bulk-copy"><strong>${title}</strong><span>Результаты проверки доступны только для просмотра; backend запрещает создание операций и WRITE jobs.</span></div></div>`;
  }
  return `<div class="bulk-bar">
    <div class="bulk-copy">${total ? `<strong>${total} ${plural(total, "готовое действие", "готовых действия", "готовых действий")}</strong><span>Состав определён backend</span>` : `<strong>Готовых действий нет</strong><span>Сначала проверьте КИЗ или устраните проблемы</span>`}</div>
    <button id="bulk-action" class="primary-button" ${total === 0 || bulkBusy ? "disabled" : ""}>${bulkBusy ? '<span class="spinner light"></span>Запускаем…' : "Выполнить готовые действия"}</button>
  </div>`;
}

function workspaceMarkup(view: WorkspaceView): string {
  return `${pageHeading()}
  ${localTrueApiBlock()}
  <section class="workspace-card">
    <div class="active-file-row">
      <div class="active-file"><span class="file-icon">${icons.file}</span><div><strong>${esc(view.file.filename)}</strong><span>${view.file.unique_kiz} КИ · Все ${view.items.length}</span></div></div>
      <div class="file-actions"><button id="check" class="secondary-button" ${checking ? "disabled" : ""}>${checking ? '<span class="spinner"></span>Проверяем…' : "Проверить КИЗ"}</button><button id="replace" class="quiet-button">Другой файл</button></div>
    </div>
    ${statusBanner(view)}
    ${filterBar(view)}
    <div class="table-shell"><table class="work-table"><thead><tr><th>КИЗ</th><th>Операция WB</th><th>Состояние ЧЗ</th><th>Решение</th><th>Действие</th><th>Результат</th></tr></thead><tbody id="work-rows">${tableRows(view)}</tbody></table></div>
    ${bulkBar(view)}
  </section>
  ${historySection(homeHistory, view.file.id)}`;
}

function renderWorkspace(): void {
  if (!current) return;
  shell(workspaceMarkup(current));
  bindLocalTrueApi();
  bindWorkspaceEvents();
  bindHistory();
}

function bindRowEvents(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-copy-kiz]").forEach((button) => {
    button.addEventListener("click", async () => {
      await navigator.clipboard.writeText(button.dataset.copyKiz || "");
      showToast("КИЗ скопирован");
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-detail]").forEach((button) => {
    button.addEventListener("click", async () => {
      const id = button.dataset.detail!;
      openDetail = openDetail === id ? null : id;
      renderWorkspace();
      if (openDetail && !detailCache.has(id)) {
        try {
          detailCache.set(id, await api.eventDetail(id));
          if (openDetail === id) renderWorkspace();
        } catch (e) {
          showToast(readError(e), "error");
        }
      }
    });
  });
}

function bindWorkspaceEvents(): void {
  document.querySelector<HTMLButtonElement>("#replace")?.addEventListener("click", () => {
    stopPolling();
    renderHome();
  });
  document.querySelector<HTMLButtonElement>("#check")?.addEventListener("click", () => void runCheck());
  document.querySelector<HTMLInputElement>("#search")?.addEventListener("input", (event) => {
    query = (event.target as HTMLInputElement).value;
    renderTableOnly();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      filter = button.dataset.filter as FilterKey;
      renderWorkspace();
    });
  });
  bindRowEvents();
  document.querySelector<HTMLButtonElement>("#bulk-action")?.addEventListener("click", () => void confirmBulk());
}

function renderTableOnly(): void {
  if (!current) return;
  const body = document.querySelector<HTMLTableSectionElement>("#work-rows");
  if (!body) { renderWorkspace(); return; }
  body.innerHTML = tableRows(current);
  bindRowEvents();
}

async function openImport(importId: string, replaceUrl = true): Promise<void> {
  stopPolling();
  const token = ++viewToken;
  if (replaceUrl) setImportUrl(importId);
  filter = "ALL";
  query = "";
  openDetail = null;
  detailCache.clear();
  try {
    const [view, home] = await Promise.all([api.workspace(importId), api.workspaceHome()]);
    if (token !== viewToken) return;
    current = view;
    homeHistory = home.history;
    renderWorkspace();
    schedulePollIfNeeded(token);
  } catch (e) {
    showToast(readError(e), "error");
    await refreshHomeHistory();
    renderHome();
  }
}

async function refreshCurrent(token = viewToken): Promise<void> {
  if (!current) return;
  const importId = current.file.id;
  const [view, home] = await Promise.all([api.workspace(importId), api.workspaceHome()]);
  if (token !== viewToken || current?.file.id !== importId) return;
  current = view;
  homeHistory = home.history;
  renderWorkspace();
  schedulePollIfNeeded(token);
}

function schedulePollIfNeeded(token: number): void {
  stopPolling();
  if (!current || !shouldPollWorkspace(current.items)) return;
  pollTimer = window.setTimeout(async () => {
    try { await refreshCurrent(token); }
    catch (e) { showToast(readError(e), "error"); }
  }, 1800);
}

async function runCheck(): Promise<void> {
  if (!current || checking) return;
  if (LOCAL_FBS_ONLY && !localTrueApiStatus?.authenticated) {
    showToast("Сначала выберите УКЭП и войдите в True API через CryptoPro", "warn");
    return;
  }
  checking = true;
  renderWorkspace();
  try {
    await api.control(current.file.id);
    await refreshCurrent();
  } catch (e) {
    showToast(readError(e), "error");
  } finally {
    checking = false;
    if (current) renderWorkspace();
  }
}

async function confirmBulk(): Promise<void> {
  if (!current || bulkBusy) return;
  try {
    const preview = await api.bulkPreview(current.file.id);
    if (!preview.eligible_count) {
      showToast("Backend не разрешил ни одного готового действия");
      await refreshCurrent();
      return;
    }
    renderBulkModal(preview);
  } catch (e) {
    showToast(readError(e), "error");
  }
}

function renderBulkModal(preview: BulkPreview): void {
  const root = document.createElement("div");
  root.className = "modal-root";
  root.innerHTML = `<div class="modal-backdrop" data-close-modal></div><section class="confirm-modal" role="dialog" aria-modal="true" aria-labelledby="bulk-title">
    <button class="modal-close" data-close-modal title="Закрыть">${icons.close}</button>
    <h2 id="bulk-title">Выполнить готовые действия?</h2>
    <p>Состав повторно рассчитан backend. Проблемные и уже обработанные строки не попадут в выполнение.</p>
    <div class="confirm-counts"><div><b>${preview.eligible_count}</b><span>Всего</span></div><div><b>${preview.withdraw_count}</b><span>Выводов</span></div><div><b>${preview.return_count}</b><span>Возвратов</span></div></div>
    <div class="confirm-note">Отправка в production True API сейчас отключена системным gate. Интерфейс не может включить её.</div>
    <div class="modal-actions"><button class="secondary-button" data-close-modal>Отмена</button><button id="confirm-bulk" class="primary-button">Выполнить ${preview.eligible_count}</button></div>
  </section>`;
  document.body.appendChild(root);
  const close = () => root.remove();
  root.querySelectorAll<HTMLElement>("[data-close-modal]").forEach((element) => element.addEventListener("click", close));
  root.querySelector<HTMLButtonElement>("#confirm-bulk")!.addEventListener("click", async () => {
    close();
    if (!current) return;
    bulkBusy = true;
    renderWorkspace();
    try {
      const result = await api.executeBulk(current.file.id);
      if (result.manual_review_count) {
        showToast(`${result.manual_review_count} ${plural(result.manual_review_count, "строка требует", "строки требуют", "строк требуют")} внимания`, "warn");
      } else {
        showToast(`Запущено: ${result.started_count}`);
      }
      await refreshCurrent();
    } catch (e) {
      showToast(readError(e), "error");
    } finally {
      bulkBusy = false;
      if (current) renderWorkspace();
    }
  });
}

function integrationSemanticStatus(item: IntegrationItem | undefined): string {
  if (!item) return "Не настроено";
  if (item.error_code || item.runtime_status === "ERROR") return "Ошибка";
  if (item.type === "suz" || item.type === "ozon" || item.contract_status === "BLOCKED") return "Ограничено";
  if (item.runtime_status === "READY") return "Настроено";
  if (item.configuration_status === "INCOMPLETE") return "Настройка";
  return "Требуется проверка";
}

function integrationCard(
  type: string,
  title: string,
  item: IntegrationItem | undefined,
  body: string,
): string {
  return `<section class="integration-card" data-integration="${esc(type)}">
    <div class="integration-card-head">
      <div><h2>${esc(title)}</h2><span>${esc(integrationSemanticStatus(item))}</span></div>
      ${item?.last_check_at ? `<small>Проверка: ${esc(fmtHistoryDate(item.last_check_at))}</small>` : ""}
    </div>
    ${body}
  </section>`;
}

async function openIntegrations(): Promise<void> {
  stopPolling();
  setViewUrl("integrations");
  shell(`<div class="page-heading"><h1>Настройки → Интеграции</h1></div><div class="settings-loading">Загружаем состояние интеграций…</div>`);
  try {
    const [list, agent, cert] = await Promise.all([
      api.integrations(),
      api.agentStatus(),
      api.certificateStatus(),
    ]);
    renderIntegrations(list.items, agent.bindings, cert);
  } catch (error) {
    shell(`<div class="page-heading"><h1>Настройки → Интеграции</h1></div><div class="login-error">${esc(readError(error))}</div>`);
  }
}

function renderIntegrations(
  items: IntegrationItem[],
  agents: AgentBindingStatus[],
  cert: CertificateStatus,
): void {
  const byType = new Map(items.map((item) => [item.type, item]));
  const trueApi = byType.get("true-api");
  const wb = byType.get("wb");
  const ozon = byType.get("ozon");
  const suz = byType.get("suz");
  const primaryAgent = agents[0];

  const candidateMarkup = cert.candidates.length
    ? cert.candidates.map((candidate) => `<div class="certificate-row">
        <div><b>${esc(candidate.subject || candidate.thumbprint)}</b><small>${esc(candidate.certificate_inn || "ИНН не извлечён")} · до ${esc(candidate.valid_to || "—")}</small></div>
        <span class="mini-state">${esc(candidate.readiness_state === "READY" ? "Подходит" : candidate.reason_code || "Не готов")}</span>
        ${trueApi && candidate.readiness_state === "READY" && cert.eligible_count > 1
          ? `<button class="quiet-button" data-select-cert="${esc(candidate.thumbprint)}">Выбрать</button>`
          : ""}
      </div>`).join("")
    : '<p class="integration-note">Сертификаты УКЭП пока не обнаружены агентом.</p>';

  const trueBody = `
    <div class="integration-notices"><b>Только чтение</b><span>Отправка документов в ЧЗ отключена</span></div>
    ${trueApi ? "" : '<button id="create-true-api" class="secondary-button">Настроить True API</button>'}
    <div class="integration-subsection">
      <strong>Windows Agent</strong>
      <p>${primaryAgent ? `${esc(primaryAgent.runtime_status)} · последний heartbeat ${esc(primaryAgent.last_seen_at || "—")}` : "Агент не зарегистрирован"}</p>
      ${primaryAgent ? "" : '<button id="create-enrollment" class="secondary-button">Создать код подключения</button>'}
      ${enrollmentIntent ? `<div class="enrollment-code"><span>Одноразовый код, действует 10 минут</span><code>${esc(enrollmentIntent.enrollment_token)}</code><button id="copy-enrollment" class="quiet-button">Копировать</button></div>` : ""}
    </div>
    <div class="integration-subsection"><strong>CryptoPro / УКЭП</strong><p>CryptoPro: ${cert.cryptopro_available ? "доступен" : "не подтверждён"}</p><p>${cert.status === "ACTIVE_READY" ? "Выбранный сертификат применён агентом." : cert.status === "SELECTED_PENDING_APPLY" ? "Сертификат выбран; ожидается подтверждение применения агентом." : cert.status === "SELECTION_REQUIRED" ? "Нужно выбрать один из подходящих сертификатов." : "Финальная готовность сертификата не подтверждена."}</p>${candidateMarkup}</div>
    ${trueApi ? '<button id="check-true-api" class="secondary-button">Проверить готовность</button>' : ""}
    <p class="integration-note">${trueApi?.real_read_authorized ? "Read-only production auth разрешён." : "Первый реальный /auth/key → УКЭП → /simpleSignIn → /cises/info ожидает отдельного разрешения."}</p>`;

  const wbBody = wb
    ? `<p class="integration-note">${wb.secret_configured ? "Токен сохранён" : "Токен не сохранён"}</p>
       <div class="inline-form"><input id="wb-token" type="password" placeholder="Новый WB token"><button id="save-wb-token" class="secondary-button">Заменить</button></div>
       <div class="card-actions"><button id="check-wb" class="quiet-button">Проверить</button><button id="revoke-wb" class="quiet-button">Отозвать</button></div>`
    : `<div class="inline-form"><input id="wb-token" type="password" placeholder="WB API token"><button id="save-wb-token" class="secondary-button">Сохранить</button></div><p class="integration-note">После сохранения статус будет «Токен сохранён», а не «Подключено».</p>`;

  const ozonBody = ozon
    ? `<p class="integration-note">${ozon.secret_configured ? "Данные доступа сохранены" : "API Key не сохранён"}</p><p class="integration-limit">Чтение данных Ozon сейчас недоступно</p>
       <div class="inline-form"><input id="ozon-key" type="password" placeholder="Новый API Key"><button id="save-ozon-key" class="secondary-button">Заменить</button></div><button id="revoke-ozon" class="quiet-button">Отозвать</button>`
    : `<div class="stack-form"><input id="ozon-client" placeholder="Client-Id"><input id="ozon-key" type="password" placeholder="API Key"><button id="save-ozon" class="secondary-button">Сохранить</button></div><p class="integration-limit">Чтение данных Ozon сейчас недоступно</p>`;

  const suzBody = suz
    ? '<p class="integration-note">Параметры СУЗ сохранены</p><p class="integration-limit">API СУЗ ограничено: заказы КМ и production calls отключены.</p>'
    : `<div class="stack-form"><input id="suz-oms-id" placeholder="omsId"><input id="suz-oms-connection" placeholder="omsConnection"><button id="save-suz" class="secondary-button">Сохранить параметры</button></div><p class="integration-limit">clientToken / registrationKey не запрашиваются.</p>`;

  shell(`<div class="page-heading settings-heading"><div><h1>Настройки → Интеграции</h1><p>Все статусы показывают фактическую проверенность, а не факт сохранения полей.</p></div><button id="refresh-integrations" class="quiet-button">Обновить</button></div>
    <div class="integration-grid">
      ${integrationCard("true-api", "Честный знак / True API", trueApi, trueBody)}
      ${integrationCard("suz", "СУЗ", suz, suzBody)}
      ${integrationCard("wb", "Wildberries", wb, wbBody)}
      ${integrationCard("ozon", "Ozon", ozon, ozonBody)}
    </div>`);

  document.querySelector<HTMLButtonElement>("#refresh-integrations")?.addEventListener("click", () => void openIntegrations());
  document.querySelector<HTMLButtonElement>("#create-enrollment")?.addEventListener("click", async () => {
    try { enrollmentIntent = await api.createEnrollment(); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  });
  document.querySelector<HTMLButtonElement>("#copy-enrollment")?.addEventListener("click", async () => {
    if (enrollmentIntent) await navigator.clipboard.writeText(enrollmentIntent.enrollment_token);
  });
  document.querySelector<HTMLButtonElement>("#create-true-api")?.addEventListener("click", async () => {
    try { await api.createTrueApi(); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  });
  document.querySelectorAll<HTMLButtonElement>("[data-select-cert]").forEach((button) => button.addEventListener("click", async () => {
    if (!trueApi) return;
    try { await api.selectCertificate(trueApi.id, button.dataset.selectCert || ""); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  }));
  document.querySelector<HTMLButtonElement>("#check-true-api")?.addEventListener("click", async () => {
    if (!trueApi) return;
    try { await api.checkIntegration("true-api", trueApi.id); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  });

  document.querySelector<HTMLButtonElement>("#save-wb-token")?.addEventListener("click", async () => {
    const token = document.querySelector<HTMLInputElement>("#wb-token")?.value || "";
    if (!token) return;
    try {
      const connection = wb || await api.createWb();
      await api.setIntegrationSecret("wb", connection.id, token);
      await openIntegrations();
    } catch (e) { showToast(readError(e), "error"); }
  });
  document.querySelector<HTMLButtonElement>("#check-wb")?.addEventListener("click", async () => {
    if (!wb) return;
    try { await api.checkIntegration("wb", wb.id); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  });
  document.querySelector<HTMLButtonElement>("#revoke-wb")?.addEventListener("click", async () => {
    if (!wb) return;
    try { await api.revokeIntegrationSecret("wb", wb.id); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  });

  const saveOzon = async () => {
    const key = document.querySelector<HTMLInputElement>("#ozon-key")?.value || "";
    if (!key) return;
    try {
      const connection = ozon || await api.createOzon(document.querySelector<HTMLInputElement>("#ozon-client")?.value || "");
      await api.setIntegrationSecret("ozon", connection.id, key);
      await openIntegrations();
    } catch (e) { showToast(readError(e), "error"); }
  };
  document.querySelector<HTMLButtonElement>("#save-ozon")?.addEventListener("click", saveOzon);
  document.querySelector<HTMLButtonElement>("#save-ozon-key")?.addEventListener("click", saveOzon);
  document.querySelector<HTMLButtonElement>("#revoke-ozon")?.addEventListener("click", async () => {
    if (!ozon) return;
    try { await api.revokeIntegrationSecret("ozon", ozon.id); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  });

  document.querySelector<HTMLButtonElement>("#save-suz")?.addEventListener("click", async () => {
    const omsId = document.querySelector<HTMLInputElement>("#suz-oms-id")?.value || "";
    const omsConnection = document.querySelector<HTMLInputElement>("#suz-oms-connection")?.value || "";
    if (!omsId || !omsConnection) return;
    try { await api.createSuz(omsId, omsConnection); await openIntegrations(); } catch (e) { showToast(readError(e), "error"); }
  });
}

function showToast(message: string, tone: "normal" | "warn" | "error" = "normal"): void {
  const root = document.querySelector<HTMLDivElement>("#toast-root");
  if (!root) return;
  const node = document.createElement("div");
  node.className = `toast ${tone}`;
  node.textContent = message;
  root.appendChild(node);
  requestAnimationFrame(() => node.classList.add("show"));
  window.setTimeout(() => { node.classList.remove("show"); window.setTimeout(() => node.remove(), 180); }, 3200);
}

function plural(n: number, one: string, few: string, many: string): string {
  const mod100 = n % 100;
  if (mod100 >= 11 && mod100 <= 14) return many;
  const mod10 = n % 10;
  return mod10 === 1 ? one : mod10 >= 2 && mod10 <= 4 ? few : many;
}

function readError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function restoreInitialView(): Promise<void> {
  if (!LOCAL_FBS_ONLY && viewFromUrl() === "integrations") {
    await openIntegrations();
    return;
  }
  const home = await api.workspaceHome();
  homeHistory = home.history;
  const requested = importFromUrl();
  const target = requested || home.active_import_id;
  if (target) await openImport(target, !requested);
  else renderHome();
}

window.addEventListener("popstate", () => {
  if (!LOCAL_FBS_ONLY && viewFromUrl() === "integrations") {
    void openIntegrations();
    return;
  }
  const importId = importFromUrl();
  if (importId) void openImport(importId, false);
  else renderHome();
});

(async () => {
  await api.seedCsrf();
  try {
    user = await api.me();
    await refreshLocalTrueApiStatus();
    await restoreInitialView();
  } catch {
    renderLogin();
  }
})();
