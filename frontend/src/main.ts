import {api, upload} from './api.js'
import type {ImportItem, EventItem} from './types'

const app = document.querySelector<HTMLDivElement>('#app')!

type OperationMode = 'AUTO' | 'CONTROL' | 'WITHDRAW_ONLY' | 'RETURN_ONLY'

type PreviewItem = {event_id:string;kiz:string;operation:string;decision:string|null;reason?:string;reason_text?:string}
type Preview = {
  mode: OperationMode
  selected_count: number
  eligible_count: number
  withdraw_count: number
  return_count: number
  excluded_count: number
  included: PreviewItem[]
  excluded: PreviewItem[]
  production_submission_available: boolean
}


let current: any = null
let events: EventItem[] = []
let selected = new Set<string>()
let filter = 'all'
let query = ''
let checking = false
let preview: Preview | null = null
let selectionSummary: Preview | null = null
let detail: string | null = null
let selectionRequest = 0
let mode: OperationMode = 'AUTO'

const decLabel: Record<string,string> = {
  READY_TO_WITHDRAW: 'Нужно вывести',
  READY_TO_RETURN: 'Нужно вернуть',
  ALREADY_DONE: 'Уже обработано',
  MANUAL_REVIEW: 'Требует проверки',
  ERROR: 'Ошибка',
}
const reasonLabel: Record<string,string> = {
  OTHER_OWNER: 'Другой владелец',
  OWNER_UNKNOWN: 'Владелец не определён',
  NON_DISTANCE_OR_UNKNOWN_WITHDRAWAL: 'Другая причина выбытия',
  UNKNOWN_STATUS: 'Неизвестное состояние',
  UNKNOWN_OR_CONFLICTING_STATUS_EX: 'Состояние требует ручной проверки',
  INCONSISTENT_WITHDRAW_REASON: 'Противоречивое состояние выбытия',
  LEGAL_ENTITY_RULES_UNDEFINED: 'Требуется ручная проверка правила продажи',
  STATE_LOOKUP_OR_NORMALIZATION_FAILED: 'Нет результата локальной проверки',
  SALE_ALREADY_WITHDRAWN_DISTANCE: 'Уже выведен из оборота',
  RETURN_ALREADY_IN_CIRCULATION: 'Уже в обороте',
  NOT_CHECKED: 'Событие ещё не проверено',
  HISTORY_ORDER_AMBIGUOUS: 'История событий КИЗ неоднозначна',
}

const modeLabel: Record<OperationMode,string> = {
  AUTO: 'Автоматически',
  CONTROL: 'Контроль',
  WITHDRAW_ONLY: 'Вывод из оборота',
  RETURN_ONLY: 'Возврат в оборот',
}
const modeHint: Record<OperationMode,string> = {
  AUTO: 'Backend сам разделит допустимый состав на вывод и возврат',
  CONTROL: 'Только проверка состояния, без operation preview',
  WITHDRAW_ONLY: 'В состав попадут только КИЗ с рекомендацией «Нужно вывести»',
  RETURN_ONLY: 'В состав попадут только КИЗ с рекомендацией «Нужно вернуть»',
}

const fmt = (s:string) => new Date(s).toLocaleString('ru-RU', {dateStyle:'short', timeStyle:'short'})
const date = (s:string|null) => s ? new Date(s).toLocaleDateString('ru-RU') : '—'
const sleep = (ms:number) => new Promise(resolve => setTimeout(resolve, ms))

const icons = {
  mark: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.25c3.6 4.3 6.1 7.15 6.1 10.45A6.1 6.1 0 1 1 5.9 13.7C5.9 10.4 8.4 7.55 12 3.25Z" fill="currentColor"/><path d="M10 16.8c1.55.55 3.4-.15 4.1-1.75" fill="none" stroke="white" stroke-width="1.35" stroke-linecap="round"/></svg>`,
  help: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M9.8 9.4a2.35 2.35 0 0 1 4.5 1c0 1.8-2.3 2-2.3 3.55" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><circle cx="12" cy="17" r="1" fill="currentColor"/></svg>`,
  search: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.8" cy="10.8" r="5.7" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m15.2 15.2 4 4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>`,
  file: `<svg viewBox="0 0 24 28" aria-hidden="true"><path d="M5 1.5h9l5 5V25a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 4 25V3A1.5 1.5 0 0 1 5.5 1.5Z" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M14 1.8V7h5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="m8 12 3 4m0-4-3 4m5-4h3m-3 2h2.6m-2.6 2h3" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`,
  eye: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.4 12s3.1-5 8.6-5 8.6 5 8.6 5-3.1 5-8.6 5-8.6-5-8.6-5Z" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="2.2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>`,
  chevron: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8.5 10 3.5 3.5 3.5-3.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  copy: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="10" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M15 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>`,
}

async function init(){
  renderShell()
  await renderHome()
}

function renderShell(){
  app.innerHTML = `
    <header class="topbar">
      <div class="brand">markflow</div>
      <div class="topbar-right">
        <span class="test-mode"><span class="mode-dot"></span>Тестовый режим</span>
        <div class="profile" aria-label="Профиль">MM</div>
      </div>
    </header>
    <aside class="rail" aria-label="Навигация">
      <button class="rail-btn active" title="Вывод и ввод в оборот" aria-label="Вывод и ввод в оборот">${icons.mark}</button>
      <button class="rail-help" title="Помощь" aria-label="Помощь">${icons.help}</button>
    </aside>
    <main id="main" class="main"></main>
    <div id="toast-root" class="toast-root" aria-live="polite"></div>`
}

function main(){return document.querySelector<HTMLElement>('#main')!}

function setMainMode(mode:'home'|'workspace'){
  main().className = `main ${mode === 'home' ? 'home-main' : 'workspace-main'}`
}

function pageTitle(){
  return `<div class="page-title"><h1>Вывод и ввод в оборот (FBS WB)</h1><button class="title-help" title="Справка" aria-label="Справка">${icons.help}</button></div>`
}

async function renderHome(){
  setMainMode('home')
  current = null
  events = []
  selected.clear()
  preview = null
  selectionSummary = null
  detail = null
  filter = 'all'
  query = ''
  const imports = await api<ImportItem[]>('/api/imports?limit=10')
  main().innerHTML = `
    ${pageTitle()}
    <section class="upload-zone" id="drop" tabindex="0" aria-label="Загрузить XLSX">
      <input id="file" type="file" accept=".xlsx" hidden>
      <div class="upload-copy">
        <strong>Перетащите файл сюда</strong>
        <span>или нажмите для выбора</span>
        <small>Поддерживается формат XLSX</small>
      </div>
    </section>
    <section class="recent">
      <div class="section-head"><h2>Последние файлы</h2></div>
      ${imports.length ? historyTable(imports) : '<div class="empty-history">Загруженных файлов пока нет</div>'}
    </section>`

  const input = document.querySelector<HTMLInputElement>('#file')!
  const drop = document.querySelector<HTMLElement>('#drop')!
  drop.onclick = () => input.click()
  drop.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); input.click() } }
  input.onchange = () => input.files?.[0] && loadFile(input.files[0])
  drop.ondragover = e => {e.preventDefault(); drop.classList.add('drag')}
  drop.ondragleave = () => drop.classList.remove('drag')
  drop.ondrop = e => {e.preventDefault(); drop.classList.remove('drag'); const f=e.dataTransfer?.files[0]; if(f) loadFile(f)}
  document.querySelectorAll<HTMLElement>('[data-open]').forEach(x => x.onclick = () => openImport(x.dataset.open!))
}

function historyTable(items:ImportItem[]){
  return `<div class="history-wrap"><table class="history">
    <thead><tr><th>Дата и время</th><th>Имя файла</th><th>Событий</th><th>КИЗ</th><th>Статус</th><th class="action-head">Открыть</th></tr></thead>
    <tbody>${items.map(i => {
      const status = i.repeated
        ? `<span class="status repeat">Повторно загружен <span class="status-detail">· новых 0 · duplicate ${i.duplicate_events}</span></span>`
        : i.status === 'processed'
          ? '<span class="status ok">Обработан</span>'
          : '<span class="status bad">Ошибка</span>'
      return `<tr>
        <td class="date-cell">${fmt(i.uploaded_at)}</td>
        <td class="file-name"><span class="xlsx-icon">${icons.file}</span><span>${esc(i.filename)}</span></td>
        <td>${i.row_count}</td><td>${i.unique_kiz}</td><td>${status}</td>
        <td class="action-cell"><button class="icon-btn open-file" data-open="${i.fingerprint}" title="Открыть файл" aria-label="Открыть файл">${icons.eye}</button></td>
      </tr>`
    }).join('')}</tbody>
  </table></div>`
}

async function loadFile(file:File){
  if(!file.name.toLowerCase().endsWith('.xlsx')){ showToast('Поддерживается только формат XLSX', 'error'); return }
  try{
    const result = await upload(file)
    await openImport(result.fingerprint)
  }catch(e){ showToast(readError(e), 'error') }
}

async function openImport(fp:string){
  try{
    current = await api<any>(`/api/imports/${fp}`)
    events = await api<EventItem[]>(`/api/imports/${fp}/events`)
    selected.clear()
    preview = null
    selectionSummary = null
    detail = null
    filter = 'all'
    query = ''
    mode = 'AUTO'
    renderWorkspace()
  }catch(e){ showToast(readError(e), 'error') }
}

function renderWorkspace(){
  setMainMode('workspace')
  const checked = events.some(e => e.decision)
  const selectable = mode !== 'CONTROL'
  main().innerHTML = `
    <section class="workspace">
      <div class="workspace-header">
        <div>
          ${pageTitle()}
          <div class="file-context">
            <span class="xlsx-icon large">${icons.file}</span>
            <div class="file-context-copy">
              <strong>${esc(current.filename)}</strong>
              <small>Загружен ${fmt(current.uploaded_at)} · ${current.event_count} событий · ${current.unique_kiz} КИЗ</small>
            </div>
          </div>
        </div>
        <button id="replace" class="text-btn replace-btn">Заменить файл</button>
      </div>
      <div class="mode-row">
        <div class="mode-switch" role="group" aria-label="Режим работы">
          ${(['AUTO','CONTROL','WITHDRAW_ONLY','RETURN_ONLY'] as OperationMode[]).map(value => `<button class="mode-option ${mode===value?'active':''}" data-mode="${value}" aria-pressed="${mode===value}">${modeLabel[value]}</button>`).join('')}
        </div>
        <span class="mode-hint">${modeHint[mode]}</span>
      </div>
      <div class="toolbar">
        <label class="search-wrap">${icons.search}<input id="search" autocomplete="off" placeholder="Поиск по КИЗ"></label>
        <div class="select-wrap"><select id="filter" aria-label="Фильтр рекомендации">
          <option value="all">Все рекомендации</option>
          <option value="READY_TO_WITHDRAW">Нужно вывести</option>
          <option value="READY_TO_RETURN">Нужно вернуть</option>
          <option value="ALREADY_DONE">Уже обработано</option>
          <option value="MANUAL_REVIEW">Требует проверки</option>
          <option value="ERROR">Ошибка</option>
        </select>${icons.chevron}</div>
        <button id="check" class="secondary-btn check-btn">${checking ? '<span class="spinner"></span>Проверяем…' : checked ? 'Повторить проверку' : 'Проверить КИЗ'}</button>
        <span id="check-status" class="check-status">${checking ? 'Обновляем строки' : checked ? 'Проверено локально' : 'Локальная проверка'}</span>
        <span class="shown" id="shown"></span>
      </div>
      <div class="table-shell">
        <table class="events ${selectable?'':'control-table'}">
          <thead><tr>
            ${selectable ? '<th class="check-col"><input id="all" type="checkbox" aria-label="Выбрать видимые строки"></th>' : ''}
            <th>КИЗ</th><th>Операция WB</th><th>Дата WB</th><th>Рекомендация</th><th>Состояние</th><th class="detail-col"></th>
          </tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
      <div id="operation" class="operation-zone"></div>
    </section>`

  document.querySelector('#replace')!.addEventListener('click', renderHome)
  document.querySelectorAll<HTMLButtonElement>('[data-mode]').forEach(button => button.onclick = () => {
    const next = button.dataset.mode as OperationMode
    if(next === mode) return
    mode = next
    selected.clear()
    preview = null
    selectionSummary = null
    selectionRequest++
    renderWorkspace()
  })
  const checkButton = document.querySelector<HTMLButtonElement>('#check')!
  checkButton.disabled = checking
  checkButton.addEventListener('click', runCheck)
  const search = document.querySelector<HTMLInputElement>('#search')!
  search.value = query
  search.oninput = e => {query=(e.target as HTMLInputElement).value; renderRows()}
  const filterEl = document.querySelector<HTMLSelectElement>('#filter')!
  filterEl.value = filter
  filterEl.onchange = e => {filter=(e.target as HTMLSelectElement).value; renderRows()}
  const all = document.querySelector<HTMLInputElement>('#all')
  if(all) all.onchange = async e => {
    const on=(e.target as HTMLInputElement).checked
    visible().forEach(x => on ? selected.add(x.event_id) : selected.delete(x.event_id))
    preview=null
    await refreshSelectionSummary()
    renderRows()
    renderOperation()
  }
  renderRows()
  renderOperation()
}

function visible(){
  const needle = query.trim()
  return events.filter(e => (filter === 'all' || e.decision === filter) && (!needle || e.kiz.includes(needle)))
}

function renderRows(){
  const body = document.querySelector<HTMLTableSectionElement>('#rows')
  if(!body) return
  const list = visible()
  const selectable = mode !== 'CONTROL'
  const shown = document.querySelector('#shown')
  if(shown) shown.textContent = `${list.length} из ${events.length}`
  const all = document.querySelector<HTMLInputElement>('#all')
  if(all){
    const picked = list.filter(e => selected.has(e.event_id)).length
    all.checked = list.length > 0 && picked === list.length
    all.indeterminate = picked > 0 && picked < list.length
  }

  body.innerHTML = list.map(e => `
    <tr class="event-row ${selected.has(e.event_id) ? 'selected' : ''}">
      ${selectable ? `<td><input data-pick="${e.event_id}" type="checkbox" aria-label="Выбрать событие" ${selected.has(e.event_id)?'checked':''}></td>` : ''}
      <td><div class="kiz-cell"><code title="${esc(e.kiz)}">${short(e.kiz)}</code><button class="copy-kiz" data-copy="${esc(e.kiz)}" title="Копировать полный КИЗ" aria-label="Копировать полный КИЗ">${icons.copy}</button></div></td>
      <td>${esc(e.operation)}</td>
      <td>${date(e.occurred_at)}</td>
      <td>${decisionBadge(e)}</td>
      <td>${stateText(e)}</td>
      <td><button class="icon-btn detail-btn ${detail===e.event_id?'open':''}" data-detail="${e.event_id}" title="Подробности" aria-label="Подробности">${icons.chevron}</button></td>
    </tr>
    ${detail===e.event_id ? `<tr class="detail-row"><td colspan="${selectable?7:6}"><div id="detail"></div></td></tr>` : ''}
  `).join('')

  body.querySelectorAll<HTMLInputElement>('[data-pick]').forEach(x => x.onchange = async () => {
    x.checked ? selected.add(x.dataset.pick!) : selected.delete(x.dataset.pick!)
    preview = null
    await refreshSelectionSummary()
    renderRows()
    renderOperation()
  })
  body.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach(x => x.onclick = async e => {
    e.stopPropagation()
    await navigator.clipboard.writeText(x.dataset.copy || '')
    showToast('КИЗ скопирован')
  })
  body.querySelectorAll<HTMLElement>('[data-detail]').forEach(x => x.onclick = async () => {
    detail = detail === x.dataset.detail ? null : x.dataset.detail!
    renderRows()
    if(detail){
      const d=await api<any>(`/api/events/${detail}`)
      renderDetail(d)
    }
  })
}

function decisionBadge(e:EventItem){
  if(!e.decision) return '<span class="state-empty">Не проверено</span>'
  const tone = e.decision === 'ERROR' ? 'danger' : e.decision === 'MANUAL_REVIEW' ? 'warn' : e.decision === 'ALREADY_DONE' ? 'neutral' : 'good'
  return `<span class="badge ${tone}">${decLabel[e.decision] || e.decision}</span>`
}

function stateText(e:EventItem){
  if(e.error) return '<span class="state-with-dot danger-text"><i></i>Нет результата</span>'
  if(e.reason && e.decision === 'MANUAL_REVIEW') return `<span class="state-with-dot warn-text"><i></i>${esc(reasonLabel[e.reason] || e.reason)}</span>`
  return e.checked_at ? '<span class="state-with-dot checked-text"><i></i>Проверено</span>' : '<span class="state-empty">—</span>'
}

async function renderDetail(d:any){
  const el = document.querySelector('#detail')
  if(!el) return
  el.innerHTML = `
    <div class="detail-grid">
      <section class="detail-primary"><span class="detail-label">Полный КИЗ</span><div class="copy-line"><code>${esc(d.kiz)}</code><button id="copy" class="mini-action">${icons.copy}<span>Копировать</span></button></div></section>
      <section><span class="detail-label">Исходное событие WB</span><p>${esc(d.operation)} · ${date(d.occurred_at)}</p><p class="muted">Задание ${esc(d.task_number)} · стикер ${esc(d.sticker)}</p></section>
      <section><span class="detail-label">Результат проверки</span><p>${d.decision ? decLabel[d.decision] || d.decision : 'Не проверено'}</p><p class="muted">${esc(reasonLabel[d.reason] || d.reason || d.error || '—')}</p></section>
    </div>
    <div class="history-block">
      <div class="history-title"><span class="detail-label">История этого КИЗ</span><span>${d.history.length} ${plural(d.history.length, 'событие', 'события', 'событий')}</span></div>
      <div class="history-events">${d.history.map((h:any) => `<div class="history-event"><span>${esc(h.operation)}</span><span>${date(h.occurred_at)}</span><span class="muted">Задание ${esc(h.task_number)}</span></div>`).join('')}</div>
      ${d.history_order_ambiguous ? '<p class="warning-note">Порядок части событий неоднозначен. Интерфейс не определяет «последнее» событие самостоятельно.</p>' : ''}
    </div>`
  document.querySelector('#copy')!.addEventListener('click', async () => {
    await navigator.clipboard.writeText(d.kiz)
    showToast('КИЗ скопирован')
  })
}

async function runCheck(){
  if(checking) return
  checking = true
  preview = null
  selectionSummary = null
  renderWorkspace()
  try{
    await Promise.all([
      api(`/api/imports/${current.fingerprint}/check`, {method:'POST'}),
      sleep(500),
    ])
    events = await api<EventItem[]>(`/api/imports/${current.fingerprint}/events`)
    if(selected.size) await refreshSelectionSummary()
  }catch(e){
    showToast(readError(e), 'error')
  }finally{
    checking = false
    renderWorkspace()
  }
}

async function requestPreview(): Promise<Preview>{
  return api<Preview>('/api/operation-preview', {
    method:'POST',
    headers:{'content-type':'application/json'},
    body:JSON.stringify({
      import_id: current.fingerprint,
      mode,
      selected_event_ids:[...selected],
    }),
  })
}

async function refreshSelectionSummary(){
  const request = ++selectionRequest
  if(mode === 'CONTROL' || !selected.size){ selectionSummary=null; return }
  try{
    const result = await requestPreview()
    if(request === selectionRequest) selectionSummary = result
  }catch(e){
    if(request === selectionRequest) selectionSummary = null
    showToast(readError(e), 'error')
  }
}

function renderOperation(){
  const op = document.querySelector<HTMLDivElement>('#operation')
  if(!op) return
  if(mode === 'CONTROL' || (!selected.size && !preview)){ op.innerHTML=''; return }

  const summary = selectionSummary
  const values = summary ? {
    selected: summary.selected_count,
    ready: summary.eligible_count,
    withdraw: summary.withdraw_count,
    returns: summary.return_count,
    excluded: summary.excluded_count,
  } : {selected:selected.size, ready:'—', withdraw:'—', returns:'—', excluded:'—'}

  op.innerHTML = `
    <div class="operation-bar ${preview?'with-preview':''}">
      <div class="op-counts">
        ${countItem(values.selected,'Выбрано')}${countItem(values.ready,'Допустимо')}${countItem(values.withdraw,'Вывод')}${countItem(values.returns,'Возврат')}${countItem(values.excluded,'Исключено')}
      </div>
      <button id="preview" class="primary-btn" ${selectionSummary?'':'disabled'}>Проверить состав</button>
    </div>
    ${preview ? previewHtml(preview) : ''}`

  const btn = document.querySelector<HTMLButtonElement>('#preview')
  if(btn) btn.addEventListener('click', async () => {
    try{
      preview = await requestPreview()
      selectionSummary = preview
      renderOperation()
    }catch(e){ showToast(readError(e), 'error') }
  })
}

function countItem(value:number|string,label:string){
  return `<span><b>${value}</b><small>${label}</small></span>`
}

function previewHtml(p:Preview){
  const reasons = new Map<string,number>()
  p.excluded.forEach(x => { const label=x.reason_text || x.reason || 'Исключено backend'; reasons.set(label, (reasons.get(label) || 0) + 1) })
  const modeTitle = p.mode === 'AUTO' ? 'Автоматический состав' : p.mode === 'WITHDRAW_ONLY' ? 'Состав на вывод из оборота' : 'Состав на возврат в оборот'
  return `<div class="preview">
    <div class="preview-head"><div><h2>${modeTitle}</h2><p>${esc(current.filename)} · состав рассчитан backend по сохранённым решениям</p></div><span class="preview-mode">${modeLabel[p.mode]}</span></div>
    <div class="preview-numbers">${countItem(p.eligible_count,'Допустимо')}${countItem(p.withdraw_count,'Вывод')}${countItem(p.return_count,'Возврат')}${countItem(p.excluded_count,'Исключено')}</div>
    ${p.excluded_count ? `<div class="excluded"><h3>Исключённые события</h3>${[...reasons].map(([r,n]) => `<div><span>${esc(r)}</span><b>${n}</b></div>`).join('')}</div>` : ''}
    <div class="preview-note"><span class="note-dot"></span><span>Состав готов только для dry-run review. Production True API, подпись и отправка не подключены.</span></div>
  </div>`
}

function short(s:string){return esc(s.length > 38 ? s.slice(0,24) + '…' + s.slice(-10) : s)}
function plural(n:number, one:string, few:string, many:string){const m=n%100;if(m>=11&&m<=14)return many;const r=n%10;return r===1?one:r>=2&&r<=4?few:many}
function readError(error:unknown){return error instanceof Error ? error.message : String(error)}
function showToast(message:string,tone:'normal'|'error'='normal'){
  const root=document.querySelector<HTMLDivElement>('#toast-root'); if(!root)return
  const node=document.createElement('div'); node.className=`toast ${tone==='error'?'error':''}`; node.textContent=message; root.appendChild(node)
  setTimeout(()=>node.classList.add('show'),0); setTimeout(()=>{node.classList.remove('show');setTimeout(()=>node.remove(),180)},2600)
}
function esc(s:any){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!))}

init()
