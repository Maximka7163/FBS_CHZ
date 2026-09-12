type RuntimeStatus = {
  mode: 'offline-dry-run' | 'live-read-only'
  tls_preflight_ok?: boolean
  authenticated?: boolean
  document_signing?: boolean
  submission?: boolean
}

type KizDiagnostics = {
  kiz: string
  status: string | null
  statusEx: string | null
  withdrawReason: string | null
  ownerInn: string | null
  owner_match: boolean | null
  productGroup: string | null
  decision: string
  reason: string
  error: string | null
}

let liveState: RuntimeStatus | null = null
let diagnostics: KizDiagnostics | null = null
let action: 'preflight' | 'auth' | null = null
let forcingControl = false

const originalFetch = window.fetch.bind(window)
window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const response = await originalFetch(input, init)
  const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname : input.url
  if (response.ok) {
    try {
      const data = await response.clone().json()
      if (url.includes('/api/status')) liveState = data as RuntimeStatus
      if (url.includes('/api/live/preflight')) {
        liveState = {...(liveState || {mode:'live-read-only'}), tls_preflight_ok:true}
      }
      if (url.includes('/api/live/authenticate')) {
        liveState = {...(liveState || {mode:'live-read-only'}), tls_preflight_ok:true, authenticated:true}
        queueMicrotask(forceControlOneKiz)
      }
      if (/\/api\/imports\/[^/]+\/check/.test(url) && data?.diagnostics) {
        diagnostics = data.diagnostics as KizDiagnostics
      }
    } catch (_) { /* non-JSON response */ }
  }
  queueMicrotask(inject)
  return response
}

function escapeHtml(value: unknown): string {
  return String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!))
}

async function refreshStatus(): Promise<void> {
  try {
    const r = await originalFetch('/api/status')
    if (r.ok) liveState = await r.json() as RuntimeStatus
  } catch (_) { /* main UI handles backend availability */ }
  inject()
}

async function runPreflight(): Promise<void> {
  if (action) return
  action = 'preflight'; inject()
  try {
    const r = await originalFetch('/api/live/preflight', {method:'POST'})
    const data = await r.json()
    if (!r.ok) throw new Error(data?.detail || 'TLS preflight failed')
    liveState = {...(liveState || {mode:'live-read-only'}), tls_preflight_ok:true, authenticated:false}
    showMessage('CryptoPro TLS доступен · True API доступен · УКЭП готова · challenge получен', false)
  } catch (e) {
    showMessage(e instanceof Error ? e.message : String(e), true)
  } finally { action = null; inject() }
}

async function runAuth(): Promise<void> {
  if (action || !liveState?.tls_preflight_ok) return
  action = 'auth'; inject()
  try {
    const r = await originalFetch('/api/live/authenticate', {method:'POST'})
    const data = await r.json()
    if (!r.ok) throw new Error(data?.detail || 'Authorization failed')
    liveState = {...(liveState || {mode:'live-read-only'}), tls_preflight_ok:true, authenticated:true}
    showMessage('Авторизация успешна. Отправка документов отключена.', false)
    forceControlOneKiz()
  } catch (e) {
    showMessage(e instanceof Error ? e.message : String(e), true)
  } finally { action = null; inject() }
}

function showMessage(text:string, error:boolean): void {
  const root = document.querySelector('#toast-root')
  if (!root) return
  const node = document.createElement('div')
  node.className = `toast ${error ? 'error' : ''} show`
  node.textContent = text
  root.appendChild(node)
  setTimeout(() => node.remove(), 3800)
}

function forceControlOneKiz(): void {
  if (forcingControl || liveState?.mode !== 'live-read-only' || !liveState.authenticated) return
  forcingControl = true
  try {
    const control = document.querySelector<HTMLButtonElement>('[data-mode="CONTROL"]')
    if (control && !control.classList.contains('active')) control.click()
    setTimeout(() => {
      const scope = document.querySelector<HTMLSelectElement>('#check-scope')
      if (scope && scope.value !== 'ONE') {
        scope.value = 'ONE'
        scope.dispatchEvent(new Event('change', {bubbles:true}))
      }
      inject()
    }, 0)
  } finally { setTimeout(() => { forcingControl = false }, 0) }
}

function connectionMarkup(): string {
  const preflight = !!liveState?.tls_preflight_ok
  const auth = !!liveState?.authenticated
  return `<section class="live-connect-row" aria-label="LIVE READ-ONLY подключение">
    <div class="live-connect-copy"><strong>LIVE READ-ONLY</strong><span>${auth ? 'Авторизация активна · отправка отключена' : preflight ? 'Подключение проверено · требуется авторизация' : 'Сначала проверьте CryptoPro TLS'}</span></div>
    <div class="live-connect-actions">
      <button id="live-preflight" class="secondary-btn" ${action?'disabled':''}>${action==='preflight'?'Проверяем…':'Проверить подключение'}</button>
      <button id="live-auth" class="secondary-btn" ${(!preflight || action || auth)?'disabled':''}>${action==='auth'?'Авторизуемся…':auth?'Авторизовано':'Авторизоваться'}</button>
    </div>
  </section>`
}

function diagnosticsMarkup(d:KizDiagnostics): string {
  const rows:[string,unknown][] = [
    ['status', d.status], ['statusEx', d.statusEx], ['withdrawReason', d.withdrawReason],
    ['ownerInn', d.ownerInn], ['owner match', d.owner_match], ['productGroup', d.productGroup],
    ['backend decision', d.decision], ['reason code', d.reason],
  ]
  return `<section class="live-kiz-diagnostics"><div><strong>Диагностика 1 КИЗ</strong><code>${escapeHtml(d.kiz)}</code></div><div class="live-diagnostic-grid">${rows.map(([k,v])=>`<span><small>${escapeHtml(k)}</small><b>${escapeHtml(v)}</b></span>`).join('')}</div>${d.error?`<p>${escapeHtml(d.error)}</p>`:''}</section>`
}

function inject(): void {
  if (liveState?.mode !== 'live-read-only') return
  const main = document.querySelector<HTMLElement>('#main')
  if (!main) return
  const title = main.querySelector('.page-title')
  if (title) {
    let row = main.querySelector<HTMLElement>('.live-connect-row')
    const html = connectionMarkup()
    if (!row) {
      title.insertAdjacentHTML('afterend', html)
      row = main.querySelector<HTMLElement>('.live-connect-row')
    } else if (row.outerHTML !== html) {
      row.outerHTML = html
    }
    main.querySelector<HTMLButtonElement>('#live-preflight')?.addEventListener('click', runPreflight)
    main.querySelector<HTMLButtonElement>('#live-auth')?.addEventListener('click', runAuth)
  }
  const check = main.querySelector<HTMLButtonElement>('#check')
  if (check && !liveState.authenticated) {
    check.disabled = true
    check.title = 'Сначала: Проверить подключение → Авторизоваться'
  }
  if (liveState.authenticated) forceControlOneKiz()
  const old = main.querySelector('.live-kiz-diagnostics')
  if (old) old.remove()
  if (diagnostics) {
    const table = main.querySelector('.table-shell')
    table?.insertAdjacentHTML('afterend', diagnosticsMarkup(diagnostics))
  }
}

const observer = new MutationObserver(() => queueMicrotask(inject))
observer.observe(document.documentElement, {subtree:true, childList:true})
void refreshStatus()
