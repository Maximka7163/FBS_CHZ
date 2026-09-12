import "./app.css";
import * as api from "./api";
import type { EventItem, FileItem, Mode } from "./types";

const app = document.querySelector<HTMLDivElement>("#app")!;
let current: FileItem | null = null;
let rows: EventItem[] = [];
let mode: Mode = "CONTROL";
let selected = new Set<string>();
let decisionFilter = "ALL";
let search = "";
let preview: unknown = null;
let selectionSummary: unknown = null;
let selectionRequest = 0;

const esc = (value: unknown) =>
  String(value ?? "").replace(/[&<>"']/g, (char) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!,
  );

function shell(body: string, user = "") {
  app.innerHTML = `<div class="top"><b>Маркировка</b><div>${
    user
      ? `<span class="muted">${esc(user)}</span><button id="logout" class="ghost">Выйти</button>`
      : ""
  }</div></div><div class="layout"><aside><div class="rail active">М</div></aside><main>${body}</main></div>`;
  document.querySelector("#logout")?.addEventListener("click", async () => {
    await api.logout();
    await api.seedCsrf();
    renderLogin();
  });
}

function renderLogin(error = "") {
  app.innerHTML = `<div class="login-wrap"><form class="login-card" id="login"><div class="brand">Маркировка</div><h1>Вход</h1><p>Закрытая рабочая область</p>${
    error ? `<div class="errorbox">${esc(error)}</div>` : ""
  }<label>Логин<input id="u" autocomplete="username" required></label><label>Пароль<input id="p" type="password" autocomplete="current-password" required></label><button class="primary">Войти</button></form></div>`;
  document.querySelector<HTMLFormElement>("#login")!.onsubmit = async (event) => {
    event.preventDefault();
    try {
      await api.login(
        document.querySelector<HTMLInputElement>("#u")!.value,
        document.querySelector<HTMLInputElement>("#p")!.value,
      );
      await renderHome();
    } catch (error) {
      renderLogin((error as Error).message);
    }
  };
}

async function renderHome() {
  const user = await api.me();
  const list = (await api.files()) as FileItem[];
  shell(
    `<div class="headline"><div><h1>Вывод и возврат КИЗ · WB FBS</h1><span class="safety">Тестовый контроль ЧЗ · Отправка документов отключена</span></div></div><label class="drop"><input id="file" type="file" accept=".xlsx"><strong>Загрузить XLSX Wildberries</strong><span>Перетащите файл или нажмите для выбора</span></label><section class="recent"><h2>Последние файлы</h2>${
      list.length
        ? list
            .map(
              (file) =>
                `<button class="file-row" data-id="${file.id}"><span><b>${esc(file.filename)}</b><small>${esc(file.imported_at || "")}</small></span><span>${file.new_events} новых · ${file.duplicate_events} duplicate · ${file.unique_kiz} КИЗ</span><span>${file.repeated ? "Повторный" : "Обработан"}</span></button>`,
            )
            .join("")
        : `<div class="empty">Файлов пока нет</div>`
    }</section>`,
    user.username,
  );
  document.querySelectorAll<HTMLElement>(".file-row").forEach((element) => {
    element.onclick = () => openFile(element.dataset.id!);
  });
  document.querySelector<HTMLInputElement>("#file")!.onchange = async (event) => {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file) return;
    try {
      const result = await api.upload(file);
      await openFile(result.id);
    } catch (error) {
      alert((error as Error).message);
    }
  };
}

function filtered() {
  return rows.filter(
    (row) =>
      (decisionFilter === "ALL" || row.decision === decisionFilter) &&
      (!search || row.kiz.toLowerCase().includes(search.toLowerCase())),
  );
}

const modeLabels: Record<Mode, string> = {
  AUTO: "Автоматически",
  CONTROL: "Контроль",
  WITHDRAW_ONLY: "Вывод из оборота",
  RETURN_ONLY: "Возврат в оборот",
};

function renderWorkspace(user: string) {
  if (!current) return;
  const visible = filtered();
  const modeButtons = (Object.keys(modeLabels) as Mode[])
    .map(
      (item) =>
        `<button type="button" class="mode-button ${mode === item ? "active" : ""}" data-mode="${item}">${modeLabels[item]}</button>`,
    )
    .join("");
  shell(
    `<div class="file-head"><div><button id="back" class="back">←</button><b>${esc(current.filename)}</b><span>${current.unique_kiz} КИЗ · ${current.row_count} строк</span></div><span class="safety">Тестовый контроль ЧЗ · Отправка документов отключена</span></div><div class="mode-group">${modeButtons}</div><div class="toolbar"><input id="search" placeholder="Поиск КИЗ" value="${esc(search)}"><select id="filter"><option value="ALL">Все решения</option>${[
      "READY_TO_WITHDRAW",
      "READY_TO_RETURN",
      "ALREADY_DONE",
      "MANUAL_REVIEW",
      "ERROR",
    ]
      .map(
        (item) => `<option ${decisionFilter === item ? "selected" : ""}>${item}</option>`,
      )
      .join("")}</select><button id="check" class="primary">Проверить КИЗ</button><small>${visible.length} видимых</small></div><div class="table-wrap"><table><thead><tr><th><input id="all" type="checkbox"></th><th>КИЗ</th><th>Операция WB</th><th>Дата</th><th>Чек</th><th>Решение</th><th>Причина</th></tr></thead><tbody>${visible
      .map(
        (row) =>
          `<tr><td><input class="sel" type="checkbox" data-id="${row.event_id}" ${selected.has(row.event_id) ? "checked" : ""}></td><td class="mono">${esc(row.kiz)}</td><td>${esc(row.operation)}</td><td>${esc(row.occurred_at || "—")}</td><td>${esc(row.receipt_number || "—")}</td><td>${row.decision ? `<span class="pill ${row.decision}">${esc(row.decision)}</span>` : "—"}</td><td>${esc(row.reason_text || row.reason || "—")}</td></tr>`,
      )
      .join("")}</tbody></table></div>${
      selected.size
        ? `<div class="opbar"><b>Выбрано ${selected.size}</b><span>${mode === "CONTROL" ? "Только контроль состояния" : "Preview без отправки"}</span>${mode !== "CONTROL" ? `<button id="preview" class="primary">Проверить состав</button>` : ""}</div>`
        : ""
    }`,
    user,
  );

  document.querySelector("#back")!.addEventListener("click", () => {
    current = null;
    rows = [];
    selected.clear();
    preview = null;
    selectionSummary = null;
    selectionRequest++;
    renderHome();
  });
  document.querySelector<HTMLInputElement>("#search")!.oninput = (event) => {
    search = (event.target as HTMLInputElement).value;
    renderWorkspace(user);
  };
  document.querySelector<HTMLSelectElement>("#filter")!.onchange = (event) => {
    decisionFilter = (event.target as HTMLSelectElement).value;
    renderWorkspace(user);
  };
  document.querySelectorAll<HTMLInputElement>(".sel").forEach((box) => {
    box.onchange = () => {
      box.checked ? selected.add(box.dataset.id!) : selected.delete(box.dataset.id!);
      preview = null;
      selectionSummary = null;
      selectionRequest++;
      renderWorkspace(user);
    };
  });
  document.querySelector<HTMLInputElement>("#all")!.onchange = (event) => {
    const checked = (event.target as HTMLInputElement).checked;
    for (const row of visible) checked ? selected.add(row.event_id) : selected.delete(row.event_id);
    preview = null;
    selectionSummary = null;
    selectionRequest++;
    renderWorkspace(user);
  };

  document.querySelectorAll<HTMLButtonElement>('[data-mode]').forEach((button) => {
    button.addEventListener("click", () => {
      const nextMode = button.dataset.mode as Mode;
      if (nextMode === mode) return;
      mode = nextMode;
      selected.clear();
      preview = null;
      selectionSummary = null;
      selectionRequest++;
      renderWorkspace(user);
    });
  });
  const checkButton = document.querySelector<HTMLButtonElement>("#check")!;
  checkButton.addEventListener("click", async () => {
    selectionSummary = await api.control(
      current!.id,
      mode,
      selected.size ? [...selected] : null,
    );
    rows = await api.events(current!.id);
    preview = null;
    renderWorkspace(user);
  });
  document.querySelector<HTMLButtonElement>("#preview")?.addEventListener("click", async () => {
    preview = await api.preview(current!.id, mode, [...selected]);
    const result = preview as {
      eligible_count: number;
      withdraw_count: number;
      return_count: number;
      excluded_count: number;
    };
    alert(
      `Допустимо: ${result.eligible_count}\nВывод: ${result.withdraw_count}\nВозврат: ${result.return_count}\nИсключено: ${result.excluded_count}`,
    );
  });
}

async function openFile(id: string) {
  const user = await api.me();
  current = await api.fileInfo(id);
  rows = await api.events(id);
  selected.clear();
  preview = null;
  selectionSummary = null;
  selectionRequest++;
  search = "";
  decisionFilter = "ALL";
  mode = "CONTROL";
  renderWorkspace(user.username);
}

(async () => {
  await api.seedCsrf();
  try {
    await api.me();
    await renderHome();
  } catch {
    renderLogin();
  }
})();
