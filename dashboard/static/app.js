let socket = null;
let scene, camera, renderer, controls, nodes3D = [], links3D = [], particles3D = [], nodePositions = {}, isScannerEnabled = true;
let instancedMesh, dummy = new THREE.Object3D(), meshColor = new THREE.Color();
let scanning = false, uptimeSeconds = 0, probeCount = 0;
let nodeDataByIndex = new Map(), hoveredNodeIdx = -1;
const raycaster = new THREE.Raycaster(), pointer = new THREE.Vector2();
let pointerDirty = false;
let portCache = new Map();
let vpW = 0, vpH = 0; // viewport-3d tracked size for feed-toggle resize sync
let topoFitKey = '', topoUserMoved = false; // keep the graph framed without fighting manual orbit
let _v = new THREE.Vector3();

// Access tokens live in memory only; the refresh token is an HttpOnly cookie.
let jwtToken = null;

// Session + operator context shown in the topbar (memory only).
let currentUser = {user: '', role: 'viewer'};
let sessionExpiresAt = 0;
let lastContext = null;

// Cached rows so filters can re-render without another API call.
let cveData = [];
let hostData = [];
let sentinelData = [];
let timelineData = [];
let auditLogData = [];
let drawerIp = '';
let cveLoaded = false, sentinelLoaded = false, lastStats = null, queueFilter = 'all';

// Cleanup tracking
let intervals = [];
let timeouts = [];
let fetchControllers = new Map();
let activePage = null;

/* ── OMNIBAR ── */
const omnibar = {
  el: document.getElementById('omnibar-modal'),
  input: document.getElementById('omnibar-input'),
  results: document.getElementById('omnibar-results'),
  items: [], selectedIdx: -1,
  open(){
    this.el.classList.add('show');
    setTimeout(()=>this.input.focus(),50);
    this.search();
  },
  close(){
    this.el.classList.remove('show');
    this.input.value='';
    this.results.innerHTML='';
  },
  search(q){
    q=(q||this.input.value||'').toLowerCase();
    const pages=['dashboard','network','targets','vulnerabilities','attacks','ai','wireless','remediation','shield','forge','sentinel','compliance','inventory','services','audit'];
    const pageLabels={'dashboard':'Dashboard','network':'Network Config','targets':'Target Library','vulnerabilities':'Vulnerabilities','attacks':'Attack Vectors','ai':'AI Analysis','wireless':'Wireless Intel','remediation':'Remediation','shield':'Shield Blocks','forge':'Forge Rules','sentinel':'Sentinel Alerts','compliance':'Compliance','inventory':'Host Inventory','services':'Active Services','audit':'Audit Log'};
    const actions=[{id:'toggleScan',label:'Run Scan'},{id:'exportPDF',label:'Export PDF'},{id:'pruneData',label:'Prune Database'}];
    const hosts=[...nodeDataByIndex.values()].map(n=>n.ip).filter(Boolean);
    let html='';
    if(!q){html='<div style="padding:20px;text-align:center;color:var(--t3);font-family:var(--mono);font-size:11px">Type to search pages, hosts, or commands</div>';this.results.innerHTML=html;this.items=[];return}
    // Pages
    const matchPages=pages.filter(p=>p.includes(q)||(pageLabels[p]||'').toLowerCase().includes(q));
    if(matchPages.length){html+='<div class="omni-group">PAGES</div>';matchPages.forEach(p=>{html+='<div class="omni-item" data-action="page" data-value="'+p+'"><svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2"><rect x=".5" y=".5" width="4.5" height="4.5" rx=".6"/><rect x="7" y=".5" width="4.5" height="4.5" rx=".6"/><rect x=".5" y="7" width="4.5" height="4.5" rx=".6"/><rect x="7" y="7" width="4.5" height="4.5" rx=".6"/></svg><span>'+pageLabels[p]+'</span></div>'})}
    // Actions
    const matchAct=actions.filter(a=>a.label.toLowerCase().includes(q)||a.id.toLowerCase().includes(q));
    if(matchAct.length){html+='<div class="omni-group">ACTIONS</div>';matchAct.forEach(a=>{html+='<div class="omni-item" data-action="cmd" data-value="'+a.id+'"><svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2"><polygon points="6,1 11,4 11,8 6,11 1,8 1,4"/><circle cx="6" cy="6" r="1.5"/></svg><span>'+a.label+'</span></div>'})}
    // Hosts
    const matchHosts=hosts.filter(h=>h.includes(q));
    if(matchHosts.length){html+='<div class="omni-group">HOSTS</div>';matchHosts.forEach(h=>{html+='<div class="omni-item" data-action="host" data-value="'+escAttr(h)+'"><svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2"><circle cx="6" cy="6" r="3.5"/><path d="M6 2v8M2 6h8"/></svg><span>'+esc(h)+'</span></div>'})}
    if(!html){html='<div style="padding:20px;text-align:center;color:var(--t3);font-family:var(--mono);font-size:11px">No results</div>'}
    this.results.innerHTML=html;
    this.items=this.results.querySelectorAll('.omni-item');
    this.selectedIdx=-1;
  },
  select(){
    if(this.selectedIdx<0||!this.items[this.selectedIdx])return;
    const item=this.items[this.selectedIdx];
    const action=item.dataset.action;
    const val=item.dataset.value;
    this.close();
    if(action==='page'){showPage(val);document.querySelectorAll('.si').forEach(t=>t.classList.remove('on'));const si=document.querySelector('.si[data-page="'+val+'"]');if(si)si.classList.add('on')}
    else if(action==='cmd'){if(val==='toggleScan')toggleScan();else if(val==='exportPDF')exportPDF();else if(val==='pruneData')pruneData()}
    else if(action==='host'){showPage('inventory')}
  },
  nav(dir){
    if(this.items.length===0)return;
    this.items.forEach(i=>i.classList.remove('selected'));
    this.selectedIdx=Math.max(0,Math.min(this.items.length-1,this.selectedIdx+dir));
    this.items[this.selectedIdx].classList.add('selected');
    this.items[this.selectedIdx].scrollIntoView({block:'nearest'});
  }
};
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key==='k'){e.preventDefault();if(omnibar.el.classList.contains('show'))omnibar.close();else omnibar.open()}
  if(omnibar.el.classList.contains('show')){
    if(e.key==='Escape'){e.preventDefault();omnibar.close()}
    if(e.key==='ArrowDown'){e.preventDefault();omnibar.nav(1)}
    if(e.key==='ArrowUp'){e.preventDefault();omnibar.nav(-1)}
    if(e.key==='Enter'){e.preventDefault();omnibar.select()}
  }
});
omnibar.input&&(omnibar.input.oninput=function(){omnibar.search(this.value)});

/* ── DONUT CLICK ── */
document.getElementById('donut')?.addEventListener('click', () => updateStats());

/* ── OUTPUT ESCAPING ──
   Every value that came from the DB/API must pass through esc() before being
   interpolated into innerHTML. Keeps stored XSS impossible even if a scanned
   host reports a hostile hostname/banner/CVE description. */
function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]
  ));
}
function escAttr(value) { return esc(value); }
function safeId(value) { const n = Number(value); return Number.isFinite(n) ? n : 0; }

/* ── AUTH (15-min in-memory access + HttpOnly refresh cookie) ── */
function authHeader() { return jwtToken ? { 'Authorization': 'Bearer ' + jwtToken } : {}; }

function connectSocket() {
  if (socket || !jwtToken || typeof io === 'undefined') return;
  socket = io({auth: {token: jwtToken}});
  initSocketHandlers();
}

/* ── SESSION UI (in-memory identity, role, expiry) ── */
function applySession(data) {
  if (!data) return;
  if (data.user) currentUser.user = data.user;
  if (data.role) currentUser.role = data.role;
  if (data.expires_in) sessionExpiresAt = Date.now() + Number(data.expires_in) * 1000;
  const initials = (currentUser.user || 'OP').replace(/[^a-zA-Z0-9]/g, '').slice(0, 2).toUpperCase() || 'OP';
  const av = document.getElementById('acct-avatar');
  if (av) av.textContent = initials;
  const nm = document.getElementById('acct-name');
  if (nm) nm.textContent = currentUser.user || '—';
  const rl = document.getElementById('acct-role');
  if (rl) rl.textContent = (currentUser.role || 'viewer') + ' · signed in';
  const cr = document.getElementById('ctx-role');
  if (cr) {
    cr.textContent = currentUser.role === 'operator' ? 'OPERATOR' : 'VIEW-ONLY';
    cr.style.color = currentUser.role === 'operator' ? '' : 'var(--amber)';
  }
  document.querySelectorAll('.op-only').forEach(el => {
    el.style.display = currentUser.role === 'operator' ? '' : 'none';
  });
  tickSession();
}

function tickSession() {
  const el = document.getElementById('acct-expiry');
  if (!el) return;
  if (!sessionExpiresAt) { el.textContent = '—'; return; }
  const left = Math.max(0, Math.round((sessionExpiresAt - Date.now()) / 1000));
  if (!left) { el.textContent = 'expired'; return; }
  const m = Math.floor(left / 60), s = left % 60;
  el.textContent = m + 'm ' + String(s).padStart(2, '0') + 's';
}

function toggleAccountMenu() {
  const menu = document.getElementById('acct-menu');
  const btn = document.getElementById('acct-avatar');
  if (!menu) return;
  const open = menu.classList.toggle('show');
  if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
}

function closeAccountMenu() {
  const menu = document.getElementById('acct-menu');
  const btn = document.getElementById('acct-avatar');
  if (menu) menu.classList.remove('show');
  if (btn) btn.setAttribute('aria-expanded', 'false');
}

document.addEventListener('click', ev => {
  const acct = document.getElementById('acct');
  if (acct && !acct.contains(ev.target)) closeAccountMenu();
  if (ev.target && ev.target.id === 'drawer-backdrop') closeHostDrawer();
});
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Escape') return;
  closeAccountMenu();
  if (drawerOpen()) closeHostDrawer();
});
// Keyboard activation for card-style controls (a div cannot be clicked by Enter).
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Enter' && ev.key !== ' ') return;
  const el = ev.target && ev.target.closest && ev.target.closest('[role="button"][data-action]');
  if (!el) return;
  ev.preventDefault();
  el.click();
});
window.addEventListener('hashchange', () => applyRoute());
window.addEventListener('popstate', () => applyRoute());

async function logout() {
  // Best-effort revoke; the cookie is cleared server-side even if the request
  // fails, and the in-memory token is dropped either way.
  try {
    await fetch('/api/v2/logout', {
      method: 'POST', headers: authHeader(), credentials: 'same-origin'
    });
  } catch (e) { /* already offline */ }
  jwtToken = null;
  sessionExpiresAt = 0;
  currentUser = {user: '', role: 'viewer'};
  window._dashInited = false;
  cveData = []; hostData = []; sentinelData = []; timelineData = [];
  auditLogData = [];
  closeHostDrawer({sync: false});
  // Do not leave the previous investigation target in the address bar — on a
  // shared workstation the next person should not see which host was open.
  // The visible page has to be reset too: initDashboard assumes the dashboard
  // markup is active, so leaving e.g. Inventory on screen desyncs the UI.
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const dashPage = document.getElementById('page-dashboard');
  if (dashPage) dashPage.classList.add('active');
  document.querySelectorAll('.si').forEach(t => t.classList.toggle('on', t.dataset.page === 'dashboard'));
  activePage = 'dashboard';
  localStorage.setItem('obsidios_page', 'dashboard');
  setRoute({k: 'page', v: 'dashboard'}, 'replace');
  ['cve-search', 'host-search', 'tl-search', 'sentinel-filter',
   'audit-search'].forEach(id => {
    const el = document.getElementById(id);
    if (el && el.tagName === 'INPUT') el.value = '';
  });
  ['tl-kind', 'audit-action', 'audit-outcome'].forEach(id => {
    const el = document.getElementById(id);
    if (el && el.tagName === 'SELECT') el.value = '';
  });
  const sf = document.getElementById('sentinel-filter');
  if (sf && sf.tagName === 'SELECT') sf.value = 'all';
  // The audit trail names accounts and addresses; do not leave it readable in
  // the DOM of a signed-out shared workstation.
  const auditBody = document.getElementById('audit-body');
  if (auditBody) auditBody.innerHTML = '';
  setText('audit-count', '0');
  if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
  if (socket) { try { socket.disconnect(); } catch (e) { /* noop */ } socket = null; }
  cleanup3D();
  intervals.forEach(i => clearInterval(i.handle));
  intervals = [];
  timeouts.forEach(t => clearTimeout(t.handle));
  timeouts = [];
  _clockStarted = false;
  closeAccountMenu();
  const modal = document.getElementById('login-modal');
  if (modal) modal.style.display = 'flex';
  const user = document.getElementById('login-username');
  const pass = document.getElementById('login-password');
  if (user) user.value = '';
  if (pass) pass.value = '';
  showToast('Signed out — session revoked', 'info');
}

/* ── OPERATIONAL CONTEXT BANNER ── */
function relTime(epochSeconds) {
  const n = Number(epochSeconds);
  if (!Number.isFinite(n) || n <= 0) return 'never';
  const diff = Math.max(0, Date.now() / 1000 - n);
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
  return new Date(n * 1000).toLocaleDateString();
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value === null || value === undefined ? '—' : String(value);
}

async function loadContext() {
  try {
    const res = await fetch('/api/v2/context', {headers: authHeader()});
    if (!res.ok) return;
    const c = await res.json();
    lastContext = c;
    setText('ctx-target', c.target);
    setText('ctx-profile', c.profile);
    const scanning = !!c.is_scanning;
    setText('ctx-scanner', scanning ? 'SCANNING' : (c.scanner_enabled ? 'ENABLED' : 'DISABLED'));
    const scannerEl = document.getElementById('ctx-scanner');
    if (scannerEl) scannerEl.style.color = scanning ? 'var(--red)' : (c.scanner_enabled ? 'var(--green)' : 'var(--t3)');
    setText('ctx-lastscan', c.last_scan ? relTime(c.last_scan.finished_at || c.last_scan.started_at) : 'never');
    setText('ctx-shield', c.shield_dry_run ? 'DRY-RUN' : 'ENFORCE');
    const shieldEl = document.getElementById('ctx-shield');
    if (shieldEl) shieldEl.style.color = c.shield_dry_run ? 'var(--amber)' : 'var(--red)';
    setText('ctx-blocks', c.active_blocks || 0);
    setText('ctx-unack', c.unacknowledged_alerts || 0);
    setText('acct-target', c.target);
    setText('acct-shield', c.shield_dry_run ? 'dry-run' : 'enforce');
    if (c.user) {
      currentUser.user = c.user;
      currentUser.role = c.role || currentUser.role;
      const av = document.getElementById('acct-avatar');
      if (av) av.textContent = (currentUser.user || 'OP').slice(0, 2).toUpperCase();
      setText('acct-name', currentUser.user);
      setText('acct-role', (currentUser.role || 'viewer') + ' · signed in');
    }
    renderOverview();
  } catch (e) {
    if (e && e.name !== 'AbortError') console.warn('Context banner:', e);
  }
}

async function performLogin() {
  const u = document.getElementById('login-username').value;
  const p = document.getElementById('login-password').value;
  try {
    const res = await fetch('/api/v2/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    if (res.ok) {
      const data = await res.json();
      jwtToken = data.token;
      applySession(data);
      document.getElementById('login-password').value = '';
      scheduleRefresh(data.expires_in || 900);
      connectSocket();
      document.getElementById('login-modal').style.display = 'none';
      initDashboard();
    } else {
      document.getElementById('login-error').style.display = 'block';
    }
  } catch(e) {
    document.getElementById('login-error').innerText = 'Connection error.';
    document.getElementById('login-error').style.display = 'block';
  }
}

let _refreshTimer = null;
function scheduleRefresh(expiresIn) {
  if (_refreshTimer) clearTimeout(_refreshTimer);
  const waitMs = Math.max((expiresIn - 60) * 1000, 30000);
  _refreshTimer = setTimeout(refreshToken, waitMs);
}

async function refreshToken() {
  try {
    const res = await fetch('/api/v2/refresh', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin'
    });
    if (!res.ok) return false;
    const data = await res.json();
    jwtToken = data.token;
    applySession(data);
    scheduleRefresh(data.expires_in || 900);
    connectSocket();
    return true;
  } catch(e) { return false; }
}

// Wrap fetch to refresh once on 401 caused by expiry.
const _origFetch = window.fetch.bind(window);
window.fetch = async function(url, opts) {
  const method = String((opts && opts.method) || 'GET').toUpperCase();
  const isApi = typeof url === 'string' && url.startsWith('/api/');
  let res;
  try {
    res = await _origFetch(url, opts);
  } catch (err) {
    if (isApi && err && err.name !== 'AbortError') {
      apiErrorToast(method, url, 'network unreachable');
    }
    throw err;
  }
  const noRetry = typeof url === 'string' && (url.includes('/api/v2/refresh') || url.includes('/api/v2/login'));
  if (res.status === 401 && !noRetry && typeof url === 'string' && url.startsWith('/api/')) {
    if (await refreshToken()) {
      opts = opts || {};
      opts.headers = Object.assign({}, opts.headers, authHeader());
      res = await _origFetch(url, opts);
    } else {
      jwtToken = null;
      if (socket) { socket.disconnect(); socket = null; }
      document.getElementById('login-modal').style.display = 'flex';
    }
  }
  // A failed write or a 5xx currently looks like an empty table in the UI;
  // surface it once per operation instead of only logging to the console.
  if (isApi && res.status >= 500) {
    apiErrorToast(method, url, 'HTTP ' + res.status);
  } else if (isApi && res.status === 403 && method !== 'GET' && method !== 'HEAD') {
    apiErrorToast(method, url, 'permission denied');
  }
  return res;
};

async function checkLogin() {
  // A valid refresh cookie re-establishes a session after reload; no tokens
  // are ever written to localStorage/sessionStorage.
  const ok = await refreshToken();
  if (ok) {
    document.getElementById('login-modal').style.display = 'none';
    initDashboard();
  } else {
    document.getElementById('login-modal').style.display = 'flex';
  }
}

/* ── CLOCK & UPTIME ── */
function tick(){
  const n=new Date();
  document.getElementById('clk').textContent=[n.getHours(),n.getMinutes(),n.getSeconds()].map(v=>String(v).padStart(2,'0')).join(':');
}
let _clockStarted = false;
function startClock(){
  if (_clockStarted) return;
  _clockStarted = true;
  safeInterval(tick, 1000, 'global'); tick();
  safeInterval(()=>{
    uptimeSeconds++;
    const m=Math.floor(uptimeSeconds/60),s=uptimeSeconds%60;
    document.getElementById('upt').textContent=String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
  }, 1000, 'global');
}
startClock();

/* ── TOAST ── */
const _TOAST_COLORS = {error: 'var(--red)', warn: 'var(--amber)', ok: 'var(--green)', info: 'var(--blue)'};
let _lastErrorToast = {key: '', at: 0};

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  const color = _TOAST_COLORS[type] || _TOAST_COLORS.info;
  toast.style.cssText = 'background:var(--s2);border:1px solid var(--b1);border-left:4px solid ' + color + ';padding:10px 16px;border-radius:var(--r);font-size:11px;font-family:var(--mono);color:var(--t2);animation:fi .2s ease;max-width:420px;box-shadow:var(--shadow-md)';
  toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), type === 'error' ? 5000 : 3000);
}

function apiErrorToast(method, url, detail) {
  const key = method + ' ' + url;
  const now = Date.now();
  // A page with five failing polls must not bury the operator in toasts.
  if (key === _lastErrorToast.key && now - _lastErrorToast.at < 5000) return;
  _lastErrorToast = {key, at: now};
  const path = String(url).split('?')[0]
    .replace(/^\/api\/v2\//, '')
    .replace(/^\/api\//, '');
  showToast(method + ' /' + path + ' failed — ' + detail, 'error');
}

/* ── NAVIGATION ── */
function showPage(id){
  // Cleanup previous page resources
  cleanupPage();

  // Cleanup 3D when leaving dashboard
  if (activePage === 'dashboard' && id !== 'dashboard') {
    cleanup3D();
  }

  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const pg=document.getElementById('page-'+id);
  if(pg)pg.classList.add('active');
  activePage = id;
  localStorage.setItem('obsidios_page', id);

    if(id==='dashboard') setTimeout(() => {
      if(!scene) init3D(); else animate();
     // Re-create polling intervals that cleanupPage() destroyed on leave
     updateStats();  // immediate fetch — no 5s gap
     safeInterval(updateStats, 5000, 'dashboard');
    safeInterval(loadShield, 10000, 'dashboard');
    safeInterval(loadOSINT, 30000, 'dashboard');
    // AI brief only updates on scan complete or manual refresh — no auto-poll
    safeInterval(fetchGraph, 30000, 'dashboard');
    safeInterval(pollNetworkStats, 1000, 'dashboard');
    const vp = document.getElementById('viewport-3d');
    if(renderer && vp) {
      const rw = vp.offsetWidth, rh = vp.offsetHeight;
      if(rw > 0 && rh > 0) {
        renderer.setSize(rw, rh);
        if(camera) { camera.aspect = rw / rh; camera.updateProjectionMatrix(); }
      }
    }
    drawSpk(); drawAct();
    fetchGraph();
  }, 100);
}

function siClick(el){
  if (drawerOpen()) closeHostDrawer({sync: false});
  document.querySelectorAll('.si').forEach(t=>t.classList.remove('on'));
  el.classList.add('on');
  gotoPage(el.dataset.page);
  setRoute({k:'page', v: el.dataset.page}, 'replace');
}

/* Single place that knows how to enter a page and warm its data. */
function gotoPage(id, opts){
  document.querySelectorAll('.si').forEach(t => {
    t.classList.toggle('on', t.dataset.page === id);
  });
  showPage(id);
  if (!opts || opts.load !== false) loadPageData(id);
}

function loadPageData(p){
  if(p==='dashboard'){ updateStats(); fetchGraph(); renderOverview(); }
  if(p==='timeline') loadTimeline();
  if(p==='targets') loadLibrary();
  if(p==='vulnerabilities') loadCVEs();
  if(p==='wireless') scanAndLoadWireless();
  if(p==='compliance') loadCompliance();
  if(p==='remediation') loadRemediation();
  if(p==='inventory') loadHosts();
  if(p==='services') loadServices();
  if(p==='shield') loadShield();
  if(p==='forge') loadForge();
  if(p==='sentinel') loadSentinelAlerts();
  if(p==='audit') loadAuditLog();
  if(p==='attacks') loadAttackVectors();
  if(p==='ai') loadAIBrief();
  if(p==='network') { loadConfig(); loadSchedule(); loadAlertConfig(); loadRetentionConfig(); }
}

function stab(el){
  document.querySelectorAll('.ptab').forEach(t=>t.classList.remove('on'));
  el.classList.add('on');
  // Show/hide term divs based on active tab
  ['raw','phantom','filtered'].forEach(t => {
    const d = document.getElementById('term-' + t);
    if(d) d.style.display = 'none';
  });
  const tab = el.textContent.trim().toLowerCase();
  const active = document.getElementById('term-' + tab);
  if(active) active.style.display = 'block';
  if(tab === 'phantom') loadPhantomFeed();
  if(tab === 'filtered') loadFilteredFeed();
}

/* ── CLEANUP ── */
function cleanupPage() {
  // Cancel all pending fetch requests for this page
  for (const [key, controller] of fetchControllers) {
    if (key.startsWith(activePage)) {
      if (!controller.signal.aborted) {
        controller.abort();
      }
      fetchControllers.delete(key);
    }
  }

  // Clear page-specific intervals
  const pageIntervals = intervals.filter(i => i.page === activePage);
  pageIntervals.forEach(interval => {
    clearInterval(interval.handle);
  });
  intervals = intervals.filter(i => i.page !== activePage);

  // Clear page-specific timeouts
  const pageTimeouts = timeouts.filter(t => t.page === activePage);
  pageTimeouts.forEach(timeout => {
    clearTimeout(timeout.handle);
  });
  timeouts = timeouts.filter(t => t.page !== activePage);
}

function safeInterval(callback, delay, page = 'global') {
  const handle = setInterval(callback, delay);
  intervals.push({ handle, page });
  return handle;
}

function safeTimeout(callback, delay, page = 'global') {
  const handle = setTimeout(callback, delay);
  timeouts.push({ handle, page });
  return handle;
}

/* ── MODAL ── */
function openModal(id){document.getElementById(id).classList.add('show');}
function closeModal(id){document.getElementById(id || 'detail-modal').classList.remove('show');}
document.querySelectorAll('.modal-overlay').forEach(m=>{
  m.addEventListener('click',e=>{if(e.target===m){if(m.id==='omnibar-modal')omnibar.close();else m.classList.remove('show')}});
});

/* ── FEED ── */
const term=document.getElementById('term-raw');
let feedIdx=0;
function addLog(k,m){
  if(!term) return;
  const n=new Date();
  const ts=[n.getHours(),n.getMinutes(),n.getSeconds()].map(v=>String(v).padStart(2,'0')).join(':');
  const el=document.createElement('div');el.className='tl';
  const tsEl=document.createElement('span');tsEl.className='tt';tsEl.textContent=ts;
  const kEl=document.createElement('span');kEl.className='tk '+k;kEl.textContent=String(k).toUpperCase();
  const mEl=document.createElement('span');mEl.className='tm';mEl.textContent=String(m ?? '');
  el.append(tsEl,kEl,mEl);
  term.appendChild(el);
  if(term.children.length>80) term.removeChild(term.firstChild);
  term.scrollTop=term.scrollHeight;
  // Update feed indicator when feed collapsed
  const feed=document.querySelector('.feed');
  const ind=document.getElementById('feed-indicator');
  if(feed.classList.contains('collapsed') && ind) {
    ind.textContent='['+ts+'] '+String(m ?? '');
    ind.style.display='block';
  }
}
function pulseSib(id){
  const el=document.getElementById(id);
  if(el){el.classList.remove('pulse');void el.offsetWidth;el.classList.add('pulse')}
}
function fmtNum(n){if(n===null||n===void 0)return'—';if(Math.abs(n)>=1e6)return(n/1e6).toFixed(1)+'M';if(Math.abs(n)>=1e3)return(n/1e3).toFixed(1)+'K';return String(n)}
function fmtBytes(b){if(b===null||b===void 0)return'—';if(b>=1e6)return(b/1e6).toFixed(1)+'MB';if(b>=1e3)return(b/1e3).toFixed(1)+'KB';return b+'B'}

/* ── SCAN TOGGLE ── */
async function toggleScan(){
  const btn = document.getElementById('scanbtn');
  const lbl = document.getElementById('scanlbl');
  btn.disabled = true;
  lbl.textContent = scanning ? 'Stopping...' : 'Starting...';
  if(jwtToken) {
    try {
      const controller = new AbortController();
      fetchControllers.set('toggleScan', controller);
      if (scanning) {
        await fetch('/api/actions/cancel_scan', {method:'POST', headers:authHeader(), signal: controller.signal});
      } else {
        await fetch('/api/actions/toggle_scanner', {method:'POST', headers:{...authHeader(),'Content-Type':'application/json'}, body:JSON.stringify({enabled: true}), signal: controller.signal});
        const res = await fetch('/api/actions/scan', {method:'POST', headers:authHeader(), signal: controller.signal});
        if (res.status === 409) showToast('A scan is already running', 'warn');
      }
      updateStats();
    } catch(e) {
      if (e.name !== 'AbortError') console.error('Toggle:', e);
    } finally {
      fetchControllers.delete('toggleScan');
      btn.disabled = false;
      loadContext();
    }
  }
}

/* ── COMMAND RAIL ── */
function toggleNav(){
  const shell = document.querySelector('.shell');
  if(!shell) return;
  const collapsed = shell.classList.toggle('collapsed');
  localStorage.setItem('obsidios_nav_collapsed', collapsed ? 'true' : 'false');
  const btn = document.querySelector('.rail-toggle');
  if(btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  if(btn) btn.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
  if(btn) btn.setAttribute('title', collapsed ? 'Expand navigation' : 'Collapse navigation');
  // Let the 3D viewport pick up the new width after the transition.
  safeTimeout(() => window.dispatchEvent(new Event('resize')), 230, 'global');
}

/* ── ZEN MODE ── */
function toggleZen(){
  document.querySelector('.shell').classList.toggle('zen');
  localStorage.setItem('obsidios_zen', document.querySelector('.shell').classList.contains('zen'));
}
function isTypingTarget(el) {
  if (!el) return false;
  const tag = String(el.tagName || '').toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable === true;
}
document.addEventListener('keydown', e=>{
  if(!e.ctrlKey && !e.metaKey && (e.key==='z'||e.key==='Z') && !omnibar.el.classList.contains('show') && !isTypingTarget(e.target)) { toggleZen(); }
});

/* ── NIGHT VISION ── */
function toggleNV(){
  document.querySelector('.shell').classList.toggle('nv');
  localStorage.setItem('obsidios_nv', document.querySelector('.shell').classList.contains('nv'));
}

function updateScanUI(){
  const btn = document.getElementById('scanbtn');
  const lbl = document.getElementById('scanlbl');
  const dot = document.getElementById('sdot');
  btn.classList.remove('idle', 'scanning', 'online');
  if (scanning) {
    lbl.textContent = 'Stop Scan';
    btn.classList.add('scanning');
    dot.classList.add('active');
  } else if (isScannerEnabled) {
    lbl.textContent = 'Scanner Online';
    btn.classList.add('online');
    dot.classList.remove('active');
  } else {
    lbl.textContent = 'Start Scan';
    btn.classList.add('idle');
    dot.classList.remove('active');
  }
}

/* ── PROFILE CARDS ── */
function selectProfileCard(p){
  document.querySelectorAll('.profile-card').forEach(c=>c.classList.remove('selected'));
  const el = document.getElementById('pcard-'+p);
  if(el) el.classList.add('selected');
  document.getElementById('nc-profile').value = p;
}

/* ── NETWORK CONFIG ── */
async function detectNetwork() {
  try {
    const controller = new AbortController();
    fetchControllers.set('detectNetwork', controller);
    const d = await (await fetch('/api/v2/config/detect-network', {headers: authHeader(), signal: controller.signal})).json();
    document.getElementById('nc-ip').value = d.cidr || '192.168.1.0/24';
  } catch(e) {
    if (e.name !== 'AbortError') console.error('DetectNet:', e);
  } finally {
    fetchControllers.delete('detectNetwork');
  }
}

async function applyTarget() {
  const target = document.getElementById('nc-ip').value || '192.168.1.0/24';
  const profile = document.getElementById('nc-profile').value;
  try {
    const controller = new AbortController();
    fetchControllers.set('applyTarget', controller);
    const res = await fetch('/api/v2/config/target', {method:'POST', headers:{...authHeader(),'Content-Type':'application/json'}, body:JSON.stringify({target, profile}), signal: controller.signal});
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      addLog('error', 'Target not applied: ' + (d.error || ('HTTP ' + res.status)));
      return;
    }
    document.getElementById('nc-active-target').textContent = 'Active Tactical Target: '+target;
    addLog('info', 'Target applied: '+target);
    loadContext();
    fetchGraph();
  } catch(e) {
    if (e.name !== 'AbortError') addLog('error', 'Failed to apply target');
  } finally {
    fetchControllers.delete('applyTarget');
  }
}

async function saveToLibrary() {
  const name = prompt('Target Designation:');
  if(!name) return;
  const target = document.getElementById('nc-ip').value;
  const profile = document.getElementById('nc-profile').value;
  try {
    const controller = new AbortController();
    fetchControllers.set('saveLibrary', controller);
    const res = await fetch('/api/v2/config/targets', {method:'POST', headers:{...authHeader(),'Content-Type':'application/json'}, body:JSON.stringify({name, target, profile}), signal: controller.signal});
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      addLog('error', 'Target not saved: ' + (d.error || ('HTTP ' + res.status)));
      return;
    }
    addLog('ok', 'Target '+target+' added to library');
  } catch(e) {
    if (e.name !== 'AbortError') {
      addLog('error', 'Failed to save target');
    }
  } finally {
    fetchControllers.delete('saveLibrary');
  }
}

async function loadConfig() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadConfig', controller);
    const d = await (await fetch('/api/v2/config/target', {headers: authHeader(), signal: controller.signal})).json();
    if(d.target) {
      document.getElementById('nc-active-target').textContent = 'Active Tactical Target: '+d.target;
      document.getElementById('nc-ip').value = d.target;
    }
  } catch(e) {
    if (e.name !== 'AbortError') {
      addLog('error', 'Failed to load config');
    }
  } finally {
    fetchControllers.delete('loadConfig');
  }
}

/* ── TARGET LIBRARY ── */
async function loadLibrary() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadLibrary', controller);
    const d = await (await fetch('/api/v2/config/targets', {headers: authHeader(), signal: controller.signal})).json();
    const tbody = document.getElementById('library-body');
    if(!d || !d.targets || !d.targets.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:24px;font-size:11px">No saved targets</td></tr>';
      return;
    }
    tbody.innerHTML = d.targets.map(t => {
      const id = safeId(t.id);
      return '<tr data-id="'+id+'" data-name="'+escAttr(t.name)+'" data-cidr="'+escAttr(t.target_cidr)+'" data-profile="'+escAttr(t.scan_profile)+'" data-action="useTargetFromRow">'
        + '<td class="td-primary">'+esc(t.name)+'</td>'
        + '<td class="td-mono">'+esc(t.target_cidr)+'</td>'
        + '<td><span class="badge badge-blue">'+esc(t.scan_profile)+'</span></td>'
        + '<td class="td-dim">'+esc(t.last_used_at||'Never')+'</td>'
        + '<td><button class="btn btn-primary" style="font-size:9px;padding:3px 10px" data-action="useTargetFromRow">Load</button></td></tr>';
    }).join('');
    } catch(e) {
      if (e.name !== 'AbortError') {
        addLog('error', 'Failed to load library');
      }
    } finally {
      fetchControllers.delete('loadLibrary');
    }
}

function useTargetFromRow(row) {
  if (!row) return;
  useTarget(row.dataset.id, row.dataset.name, row.dataset.cidr, row.dataset.profile);
}

async function useTarget(id, name, cidr, profile) {
  try {
    const controller = new AbortController();
    fetchControllers.set('useTarget', controller);
    await fetch('/api/v2/config/targets/'+id+'/use', {method:'POST', headers: authHeader(), signal: controller.signal});
  } catch(e) {
    if (e.name !== 'AbortError') console.error('useTarget:', e);
  } finally {
    fetchControllers.delete('useTarget');
  }
  document.getElementById('nc-ip').value = cidr;
  document.getElementById('nc-profile').value = profile;
  selectProfileCard(profile);
  document.getElementById('nc-active-target').textContent = 'Active Tactical Target: '+cidr;
  addLog('info', 'Loaded target: '+name+' ('+cidr+')');
}

/* ── CVEs ── */
function cveMatches(c, q, sev, verify) {
  if (sev && String(c.severity || '').toUpperCase() !== sev) return false;
  if (verify) {
    const status = String(c.verified_status || 'UNVERIFIED').toUpperCase();
    if (status !== verify) return false;
  }
  if (!q) return true;
  return [c.ip, c.cve_id, c.service, c.port, c.description, c.severity]
    .map(v => String(v === null || v === undefined ? '' : v).toLowerCase())
    .join(' ')
    .includes(q);
}

function renderCVEs() {
  const tbody = document.getElementById('cve-body');
  if (!tbody) return;
  const q = (document.getElementById('cve-search')?.value || '').trim().toLowerCase();
  const sevFilter = (document.getElementById('cve-sev')?.value || '').toUpperCase();
  const verify = (document.getElementById('cve-verify')?.value || '').toUpperCase();
  const data = cveData.filter(c => cveMatches(c, q, sevFilter, verify));
  renderOverview();
  const countEl = document.getElementById('vuln-count');
  if (countEl) {
    countEl.textContent = data.length === cveData.length
      ? fmtNum(data.length)
      : fmtNum(data.length) + ' / ' + fmtNum(cveData.length);
  }
  const sib = document.getElementById('vuln-sib');
  if (sib) { sib.textContent = cveData.length; pulseSib('vuln-sib'); }
  if (!cveData.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--t3);padding:24px">No vulnerabilities found</td></tr>';
    return;
  }
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--t3);padding:24px">No vulnerabilities match the current filters</td></tr>';
    return;
  }
  tbody.innerHTML = data.map(c => {
    const sev = c.severity || 'INFO';
    const cls = sev==='CRITICAL'?'badge-critical':sev==='HIGH'?'badge-high':sev==='MEDIUM'?'badge-medium':'badge-low';
    const verifyStatus = c.verified_status || 'UNVERIFIED';
    let verifyBadge = '';
    if(verifyStatus==='CONFIRMED') {
      verifyBadge = '<span style="font-family:var(--mono);font-size:9px;color:var(--red);background:var(--red3);padding:1px 6px;border-radius:2px">CONFIRMED</span>';
      if(c.detected_version) verifyBadge += '<div style="font-size:8px;color:var(--t3)">v' + esc(c.detected_version) + '</div>';
    } else if(verifyStatus==='NOT_AFFECTED') {
      verifyBadge = '<span style="font-family:var(--mono);font-size:9px;color:var(--green);background:rgba(52,211,153,0.08);padding:1px 6px;border-radius:2px">NOT AFFECTED</span>';
    } else if(verifyStatus==='VULNERABLE') {
      verifyBadge = '<span style="font-family:var(--mono);font-size:9px;color:var(--amber);background:var(--amber3);padding:1px 6px;border-radius:2px">VULNERABLE</span>';
      if(c.detected_version) verifyBadge += '<div style="font-size:8px;color:var(--t3)">v' + esc(c.detected_version) + '</div>';
    } else {
      verifyBadge = '<span style="font-family:var(--mono);font-size:9px;color:var(--t3)">unverified</span>';
    }
    const dismissBtn = '<button data-action="dismissCVE" data-port-id="'+safeId(c.port_id)+'" data-cve-id="'+safeId(c.cve_db_id)+'" style="background:transparent;border:1px solid var(--b1);color:var(--t3);font-size:9px;padding:2px 7px;border-radius:3px;cursor:pointer;font-family:var(--mono)" title="Dismiss">x</button>';
    return '<tr style="cursor:pointer" data-sev="'+escAttr(String(sev).toLowerCase())+'" data-action="openHost" data-ip="'+esc(c.ip||'')+'" title="Open host details"><td class="td-mono">'+esc(c.ip||'')+'</td><td><span style="color:var(--t1);font-family:var(--mono);font-size:11px;font-weight:500">'+esc(c.cve_id||'')+'</span></td><td class="td-dim">'+esc(c.cvss_v3||'N/A')+'</td><td><span class="badge '+cls+'">'+esc(sev)+'</span></td><td class="td-mono">'+esc(c.port||'')+'/'+esc(c.service||'')+'</td><td>'+verifyBadge+'</td><td style="color:var(--t3);font-size:10px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(c.description||'')+'</td><td>'+dismissBtn+'</td></tr>';
  }).join('');
}

async function loadCVEs() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadCVEs', controller);
    const res = await fetch('/api/v2/cves', {headers: authHeader(), signal: controller.signal});
    if (!res.ok) throw Error('HTTP ' + res.status);
    const d = await res.json();
    cveData = Array.isArray(d.data) ? d.data : [];
    cveLoaded = true;
    renderCVEs();
  } catch(e) {
    if (e.name !== 'AbortError') console.error('CVEs:', e);
  } finally {
    fetchControllers.delete('loadCVEs');
  }
}

async function dismissCVE(event, portId, cveId) {
  event.stopPropagation();
  try {
    const res = await fetch('/api/v2/cves/dismiss/'+portId+'/'+cveId, {method:'POST', headers: authHeader()});
    if(res.ok) {
      cveData = cveData.filter(c => !(Number(c.port_id) === portId && Number(c.cve_db_id) === cveId));
      renderCVEs();
      showToast('CVE dismissed', 'info');
    }
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Dismiss:', e);
  }
}

async function reverifyCVEs(event) {
  const btn = event.currentTarget || event.target;
  const original = btn.textContent;
  try {
    btn.textContent = 'Verifying...'; btn.disabled = true;
    const res = await fetch('/api/v2/cves/reverify', {method:'POST', headers: authHeader()});
    if (!res.ok) throw Error('HTTP ' + res.status);
    const d = await res.json();
    showToast('Verification complete: '+(d.updated||0)+' updated', 'info');
    await loadCVEs();
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Reverify:', e);
  } finally {
    btn.textContent = original || 'Reverify';
    btn.disabled = false;
  }
}

async function exportCVEs() {
  try {
    let cves = cveData;
    if (!cves.length) {
      const res = await fetch('/api/v2/cves', {headers: authHeader()});
      if (!res.ok) throw Error('HTTP ' + res.status);
      const d = await res.json();
      cves = Array.isArray(d.data) ? d.data : [];
    }
    if(!cves.length) { showToast('No CVEs to export', 'warn'); return; }
    const cell = v => {
      let s = String(v === null || v === undefined ? '' : v);
      // Neutralise spreadsheet formula injection on the client-side export too.
      if (/^[=+\-@\t\r\n]/.test(s)) s = "'" + s;
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const rows = [['Host','CVE ID','CVSS','Severity','Service','Port','Status','Description']];
    for(const c of cves) {
      rows.push([c.ip||'?', c.cve_id, c.cvss_v3||'', c.severity, c.service||'', c.port||'', c.verified_status||'UNVERIFIED', c.description||'']);
    }
    const csv = rows.map(r=>r.map(cell).join(',')).join('\n');
    const blob = new Blob([csv], {type:'text/csv'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'obsidios_cves_'+new Date().toISOString().slice(0,10)+'.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
    showToast('Exported '+cves.length+' CVEs', 'info');
  } catch(e) { console.error('ExportCVEs:', e); showToast('Export failed', 'error'); }
}

async function loadRetentionConfig() {
  try {
    const res = await fetch('/api/v2/system/retention', {headers: authHeader()});
    if(!res.ok) return;
    const d = await res.json();
    document.getElementById('nc-retention').value = d.days || 30;
  } catch(e) { /* ignore */ }
}

async function saveRetention() {
  const days = parseInt(document.getElementById('nc-retention').value) || 30;
  if(days < 1 || days > 365) { showToast('Retention must be 1–365 days', 'error'); return; }
  try {
    const res = await fetch('/api/v2/system/retention', {
      method:'POST',
      headers: Object.assign({'Content-Type':'application/json'}, authHeader()),
      body: JSON.stringify({days})
    });
    if(!res.ok) return;
    showToast('Retention set to ' + days + ' days', 'ok');
  } catch(e) { console.error('saveRetention:', e); }
}

async function pruneData() {
  const days = parseInt(document.getElementById('nc-retention').value) || 30;
  if(!confirm('Delete scan data older than ' + days + ' days?')) return;
  try {
    const res = await fetch('/api/v2/system/prune', {
      method:'POST',
      headers: Object.assign({'Content-Type':'application/json'}, authHeader()),
      body: JSON.stringify({days})
    });
    const d = await res.json();
    showToast('Pruned '+(d.deleted_scans||0)+' old scans (' + days + ' day retention)', 'ok');
  } catch(e) { console.error('Prune:', e); }
}

/* ── WIRELESS SCAN + LOAD ── */
async function scanAndLoadWireless() {
  const btn = document.querySelector('#page-wireless .btn-primary');
  if(btn) { btn.textContent = 'Scanning...'; btn.disabled = true; }
  try {
    await fetch('/api/v2/iris/scan_wireless', {method:'POST', headers:authHeader()});
  } catch(e) { showToast('Wireless scan failed: '+e.message, 'error'); }
  if(btn) { btn.textContent = 'Scan Wireless'; btn.disabled = false; }
  loadWireless();
}

/* ── WIRELESS ── */
async function loadWireless() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadWireless', controller);
    const d = await (await fetch('/api/v2/iris/wireless', {headers: authHeader(), signal: controller.signal})).json();
    const tbody = document.getElementById('wireless-body');
    const data = d.data || [];
    if(!data.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--t3);padding:16px 24px">No wireless threats detected</td></tr><tr><td colspan="6" style="text-align:center;color:var(--t4);font-size:10px;padding:0 24px 12px">Verify a wireless interface is available and configured in Settings</td></tr>';
      return;
    }
    tbody.innerHTML = data.map(w => {
      const enc = w.encryption || 'OPEN';
      const encCls = enc.includes('WPA3')?'enc-wpa3':enc==='OPEN'?'enc-open':'enc-wpa2';
      return '<tr><td><div style="font-family:var(--mono);font-size:11px;color:var(--t1);font-weight:500">'+esc(w.ssid||'Hidden')+'</div><div style="font-family:var(--mono);font-size:9px;color:var(--t3)">'+esc(w.bssid||'')+'</div></td><td class="td-mono">'+esc(w.threat_type||'802.11ac')+'</td><td><div class="sig-bar"><span class="on" style="height:4px"></span><span class="on" style="height:6px"></span><span class="on" style="height:9px"></span><span class="on" style="height:12px"></span></div></td><td><span class="enc-badge '+encCls+'">'+esc(enc)+'</span></td><td class="td-mono">'+esc(w.channel||'—')+'</td><td class="td-dim">'+(w.detected_at ? esc(new Date(w.detected_at*1000).toLocaleTimeString()) : '—')+'</td></tr>';
    }).join('');
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Wireless:', e);
  } finally {
    fetchControllers.delete('loadWireless');
  }
}

/* ── COMPLIANCE ── */
async function loadCompliance() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadCompliance', controller);
    const fw = document.getElementById('compliance-std').value;
    const d = await (await fetch('/api/v2/oracle/compliance?framework='+fw, {headers: authHeader(), signal: controller.signal})).json();
    document.getElementById('comp-score').textContent = (d.compliance_score||0)+'%';
    document.getElementById('comp-pass').textContent = d.compliant||0;
    document.getElementById('comp-fail').textContent = d.non_compliant||0;
    let pruned = document.getElementById('comp-policy');
    if(!pruned) {
      const cards = document.querySelector('.stat-cards');
      if(cards) {
        const el = document.createElement('div'); el.className = 'stat-card b';
        el.innerHTML = '<div class="sc-label">Policy</div><div class="sc-val" id="comp-policy" style="color:var(--amber)">0</div>';
        cards.appendChild(el);
      }
    }
    const pe = document.getElementById('comp-policy');
    if(pe) pe.textContent = d.policy_required||0;
    let pelt = document.getElementById('comp-partial');
    if(!pelt) {
      const cards = document.querySelector('.stat-cards');
      if(cards) {
        const el = document.createElement('div'); el.className = 'stat-card b';
        el.innerHTML = '<div class="sc-label">Partial</div><div class="sc-val" id="comp-partial" style="color:var(--purple)">0</div>';
        cards.appendChild(el);
      }
    }
    const pp = document.getElementById('comp-partial');
    if(pp) pp.textContent = d.partial||0;
    const tbody = document.getElementById('comp-body');
    const findings = d.findings || [];
    if(!findings.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:24px">No compliance data</td></tr>';
      return;
    }
    tbody.innerHTML = findings.map(f => {
      const sev = f.severity || 'LOW';
      const cls = sev==='CRITICAL'?'badge-critical':sev==='HIGH'?'badge-high':sev==='MEDIUM'?'badge-medium':'badge-low';
      let color, label;
      if(f.status === 'COMPLIANT') { color = 'var(--green)'; label = 'PASS'; }
      else if(f.status === 'NON-COMPLIANT') { color = 'var(--red)'; label = 'FAIL'; }
      else if(f.status === 'PARTIAL') { color = 'var(--purple)'; label = 'PARTIAL'; }
      else { color = 'var(--amber)'; label = 'POLICY'; }
      const verify = f.verification === 'policy' ? 'Policy Review' : f.verification === 'partial' ? 'Scan + Policy' : 'Scan';
      const issues = Array.isArray(f.issues) ? f.issues.map(esc).join(', ') : '';
      return '<tr><td>'+esc(f.requirement)+'</td><td><span class="badge '+cls+'">'+esc(sev)+'</span></td><td><span style="color:'+color+';font-family:var(--mono);font-size:10px;font-weight:500">'+label+'</span></td><td class="td-dim">'+(issues||'No issues detected')+'</td><td style="font-size:9px;color:var(--t3);font-family:var(--mono)">'+verify+'</td></tr>';
    }).join('');
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Compliance:', e);
  } finally {
    fetchControllers.delete('loadCompliance');
  }
}

/* ── REMEDIATION ── */
async function loadRemediation() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadRemediation', controller);
    const d = await (await fetch('/api/v2/oracle/patch_priority', {headers: authHeader(), signal: controller.signal})).json();
    const tbody = document.getElementById('remediation-body');
    const list = d.priority_list || [];
    document.getElementById('rem-sib').textContent = list.length;
    if(!list.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--t3);padding:24px">No remediation items</td></tr>';
      return;
    }
    tbody.innerHTML = list.map((p, idx) => {
      const pri = idx < 2 ? 'pri-1' : idx < 4 ? 'pri-2' : 'pri-3';
      const risk = Number(p.network_risk) || 0;
      const riskColor = risk > 7 ? 'var(--red)' : risk > 4 ? 'var(--amber)' : 'var(--green)';
      const riskBar = Math.max(0, Math.min(100, (risk/10)*100));
      const exploitable = !!p.exploitable;
      const target = (p.ip || '') + (p.port ? ':' + p.port : '');
      return '<tr><td><span class="pri-badge '+pri+'">P'+(idx+1)+'</span></td><td class="td-mono">'+esc(p.cve_id)+'</td><td class="td-mono">'+esc(target)+'</td><td><div style="display:flex;align-items:center;gap:7px"><div style="width:50px;height:3px;background:var(--b0);border-radius:2px;overflow:hidden"><div style="width:'+riskBar+'%;height:100%;background:'+riskColor+'"></div></div><span style="font-family:var(--mono);font-size:9px;color:'+riskColor+'">'+esc(risk)+'</span></div></td><td>'+(exploitable?'<span class="exploit-yes">YES</span>':'<span class="exploit-no">NO</span>')+'</td><td style="font-size:10px;color:var(--t2)">'+(Number(p.attack_paths) > 0 ? 'Critical Patch' : 'Standard')+'</td></tr>';
    }).join('');
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Remediation:', e);
  } finally {
    fetchControllers.delete('loadRemediation');
  }
}

/* ── HOST INVENTORY ── */
function hostMatches(h, q) {
  if (!q) return true;
  return [h.ip, h.hostname, h.os_name, h.mac, h.vendor]
    .map(v => String(v === null || v === undefined ? '' : v).toLowerCase())
    .join(' ')
    .includes(q);
}

function renderHosts() {
  const container = document.getElementById('inv-list');
  if (!container) return;
  const q = (document.getElementById('host-search')?.value || '').trim().toLowerCase();
  const hosts = hostData.filter(h => hostMatches(h, q));
  const countEl = document.getElementById('inv-count');
  if (countEl) {
    countEl.textContent = hosts.length === hostData.length
      ? fmtNum(hosts.length)
      : fmtNum(hosts.length) + ' / ' + fmtNum(hostData.length);
  }
  if(!hostData.length) { container.innerHTML = '<div class="empty-state"><div class="empty-state-title">No hosts discovered</div></div>'; return; }
  if(!hosts.length) { container.innerHTML = '<div class="empty-state"><div class="empty-state-title">No hosts match the current filter</div></div>'; return; }
  container.innerHTML = hosts.map(h => {
    const risk = Number(h.risk_score) || 0;
    const riskColor = obsidiosRisk.color(risk);
    const online = true;
    const riskBar = obsidiosRisk.bar(risk);
    return '<div class="hi-card" role="button" tabindex="0" data-action="openHost" data-ip="'+esc(h.ip||'')+'" aria-label="Open details for '+esc(h.ip||'host')+'"><div class="hi-top"><div style="width:7px;height:7px;border-radius:50%;background:'+(online?'var(--green)':'var(--red)')+';box-shadow:0 0 5px '+(online?'var(--green)':'var(--red)')+';flex-shrink:0"></div><div class="hi-ip">'+esc(h.ip||'')+'</div><div class="hi-os">'+esc(h.os_name||'Unknown')+'</div><div class="hi-risk" style="color:'+riskColor+'">Risk '+esc(risk)+'</div><span style="color:var(--t3);font-size:11px;margin-left:2px" aria-hidden="true">›</span></div><div class="hi-bar"><div class="hi-bar-fill" style="width:'+riskBar+'%;background:'+riskColor+'"></div></div><div class="hi-meta"><div class="hi-m">Hostname <span>'+esc(h.hostname||'—')+'</span></div><div class="hi-m">Vendor <span>'+esc(h.vendor||'—')+'</span></div><div class="hi-m">Asset Value <span>'+esc(h.asset_value||'—')+'</span></div><div class="hi-m">MAC <span>'+esc(h.mac||'—')+'</span></div></div></div>';
  }).join('');
}

async function loadHosts() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadHosts', controller);
    const res = await fetch('/api/v2/details/hosts', {headers: authHeader(), signal: controller.signal});
    if (!res.ok) throw Error('HTTP ' + res.status);
    const d = await res.json();
    hostData = Array.isArray(d.data) ? d.data : [];
    renderHosts();
    // Keep the Overview card in step: it may have rendered before this
    // payload (or the 3D graph) arrived.
    renderSelectedAsset();
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Hosts:', e);
  } finally {
    fetchControllers.delete('loadHosts');
  }
}

/* ── SERVICES ── */
async function loadServices() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadServices', controller);
    const res = await fetch('/api/v2/details/ports', {headers: authHeader(), signal: controller.signal});
    const d = await res.json();
    const tbody = document.getElementById('svc-body');
    const services = d.data || [];
    document.getElementById('svc-count').textContent = services.length;
    if(!services.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--t3);padding:24px">No services found</td></tr>';
      return;
    }
    tbody.innerHTML = services.map(s => {
      const open = s.state === 'open';
      return '<tr style="cursor:pointer" data-action="openHost" data-ip="'+esc(s.ip||'')+'" title="Open host details"><td><span style="font-family:var(--mono);color:var(--blue)">'+esc(s.port)+'/'+esc(s.protocol||'tcp')+'</span></td><td class="td-primary">'+esc((s.service||'unknown').toUpperCase())+'</td><td class="td-mono">'+esc(s.ip)+'</td><td class="td-dim">'+esc(s.version||'—')+'</td><td><span class="svc-state svc-'+(open?'open':'filtered')+'">'+(open?'OPEN':'FILTERED')+'</span></td><td class="td-dim">'+esc(s.risk_score!=null?Math.round(s.risk_score):'—')+'</td></tr>';
    }).join('');
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Services:', e);
  } finally {
    fetchControllers.delete('loadServices');
  }
}

/* ── MODALS (Hosts/Services detail) ── */
async function showModal(type) {
  const modal = document.getElementById('detail-modal');
  modal.classList.add('show');
  document.getElementById('modal-title').textContent = type==='hosts' ? 'Host Inventory' : 'Active Services';
  document.getElementById('modal-content').innerHTML = '<div style="padding:16px;text-align:center;color:var(--t3);font-family:var(--mono)">Loading...</div>';
  try {
    const controller = new AbortController();
    fetchControllers.set('showModal', controller);
    const res = await fetch('/api/v2/details/'+type, {headers: authHeader(), signal: controller.signal});
    const d = await res.json();
    let h = '<table><thead><tr><th>Asset</th><th>Info</th><th>Risk</th></tr></thead><tbody>';
    (d.data||[]).forEach(r => {
      const risk = Number(r.risk_score) || 0;
      const riskColor = risk > 7 ? 'var(--red)' : risk > 4 ? 'var(--amber)' : 'var(--green)';
      h += '<tr><td class="td-mono">'+esc(r.ip||r.port||'')+'</td><td style="color:var(--t2);font-size:10px;font-family:var(--mono)">'+esc(r.os_name||r.service||'')+'</td><td><span style="font-family:var(--mono);color:'+riskColor+'">'+esc(risk)+'</span></td></tr>';
    });
    document.getElementById('modal-content').innerHTML = h + '</tbody></table>';
  } catch(e) {
    if (e.name !== 'AbortError') {
      document.getElementById('modal-content').innerHTML = '<div style="padding:16px;text-align:center;color:var(--red);font-family:var(--mono)">Failed to load data</div>';
    }
  } finally {
    fetchControllers.delete('showModal');
  }
}


/* ── ATTACK VECTORS (accordion) ── */
async function loadAttackVectors() {
  const list = document.getElementById('attack-hosts-list');
  const summaryEl = document.getElementById('attack-summary');
  const totalEl = document.getElementById('attack-total');
  const hostsEl = document.getElementById('attack-hosts');
  if (!list) return;
  list.innerHTML = '<div style="padding:24px;text-align:center;color:var(--t3);font-family:var(--mono)">Loading...</div>';
  try {
    const res = await fetch('/api/v2/offensive/attack_vectors', {headers: authHeader()});
    if (!res.ok) throw new Error('Failed');
    const d = await res.json();
    if (totalEl) totalEl.textContent = d.total_techniques || 0;
    if (hostsEl) hostsEl.textContent = (d.findings||[]).length;
    if (summaryEl) summaryEl.textContent = d.summary || '';
    let html = '';
    (d.findings || []).forEach((host, hi) => {
      const totalForHost = (host.attacks||[]).length;
      const hostRisk = Number(host.risk) || 0;
      html += '<div class="host-card">'
        + '<div class="host-header" data-action="toggleHost">'
        + '<span style="font-family:var(--mono);font-weight:500;color:var(--t1)">' + esc(host.ip) + '</span>'
        + (host.hostname ? '<span style="font-size:9px;color:var(--t3)">' + esc(host.hostname) + '</span>' : '')
        + '<span style="font-size:9px;color:var(--t2)">' + esc(host.os||'Unknown') + '</span>'
        + '<span style="font-family:var(--mono);font-size:9px;color:' + (hostRisk > 50 ? 'var(--red)' : hostRisk > 20 ? 'var(--amber)' : 'var(--green)') + '">risk ' + esc(hostRisk) + '</span>'
        + '<span class="sib a" style="margin-left:0">' + totalForHost + '</span>'
        + '<span class="arrow">▸</span>'
        + '</div>'
        + '<div class="host-body">';
      (host.attacks || []).forEach(a => {
        let badgeClass = 'ab-srv';
        const t = (a.technique||'').toLowerCase();
        if (t.includes('brute')||t.includes('creds')||t.includes('pass')||t.includes('hash')||t.includes('default')) badgeClass = 'ab-creds';
        else if (t.includes('relay')||t.includes('later')||t.includes('pivot')||t.includes('tunnel')||t.includes('hijack')) badgeClass = 'ab-lat';
        else if (t.includes('exfil')||t.includes('dump')||t.includes('extract')) badgeClass = 'ab-exfil';
        html += '<div class="attack-row">'
          + '<span class="td-mono" style="color:var(--t2)">' + esc(a.port) + '</span>'
          + '<span class="badge ' + badgeClass + '">' + esc(a.service) + '</span>'
          + '<span class="attack-tech">' + esc(a.technique) + '</span>'
          + '<span class="attack-tool">' + esc(a.tool) + '</span>'
          + '<div class="attack-detail">' + esc(a.detail) + '</div>'
          + '</div>';
      });
      html += '</div></div>';
    });
    if (!html) html = '<div style="padding:24px;text-align:center;color:var(--t3);font-family:var(--mono)">No attack vectors yet. Run a scan first.</div>';
    list.innerHTML = html;
    document.getElementById('attack-sib').textContent = d.total_techniques || 0; pulseSib('attack-sib');
  } catch(e) {
    if (e.name !== 'AbortError') list.innerHTML = '<div style="padding:24px;text-align:center;color:var(--red);font-family:var(--mono)">Failed to load attack vectors</div>';
  }
}

function toggleHost(el) {
  el.classList.toggle('open');
  const body = el.nextElementSibling;
  if (body) body.classList.toggle('open');
}

/* ── PHANTOM FEED (attack paths) ── */
async function loadPhantomFeed() {
  const term = document.getElementById('term-phantom');
  if(!term) return;
  term.innerHTML = '<div style="padding:16px;color:var(--t3);font-family:var(--mono)">Loading attack paths...</div>';
  try {
    const res = await fetch('/api/v2/details/paths', {headers: authHeader()});
    if(!res.ok) throw new Error('Failed');
    const d = await res.json();
    if(!d.data || d.data.length === 0) {
      term.innerHTML = '<div style="padding:16px;color:var(--t3);font-family:var(--mono)">No attack paths identified. Run a scan first.</div>';
      return;
    }
    let html = '';
    d.data.forEach((p, i) => {
      let pathStr = 'Unknown path';
      try {
        const steps = JSON.parse(p.path_json);
        pathStr = steps.map(s => esc(s.ip || s.host || '?')).join(' <span style="color:var(--t3)">→</span> ');
      } catch(e) {}
      html += '<div class="log-line" style="border-left:2px solid var(--red);padding:6px 8px;margin-bottom:4px">'
        + '<div style="font-size:9px;color:var(--t3);font-family:var(--mono)">PATH #' + (i+1) + ' <span style="color:var(--amber)">ROI: ' + esc(p.attacker_roi || 'N/A') + '</span></div>'
        + '<div style="font-size:10px;color:var(--t1);font-family:var(--mono);padding:4px 0">' + pathStr + '</div>'
        + (p.narrative ? '<div style="font-size:9px;color:var(--t2)">' + esc(String(p.narrative).substring(0, 120)) + '...</div>' : '')
        + '</div>';
    });
    term.innerHTML = html;
  } catch(e) {
    if(e.name !== 'AbortError') term.innerHTML = '<div style="padding:16px;color:var(--red);font-family:var(--mono)">Failed to load attack paths</div>';
  }
}

/* ── FILTERED FEED (services with FILTERED state) ── */
async function loadFilteredFeed() {
  const term = document.getElementById('term-filtered');
  if(!term) return;
  term.innerHTML = '<div style="padding:16px;color:var(--t3);font-family:var(--mono)">Loading filtered services...</div>';
  try {
    const res = await fetch('/api/v2/details/ports?state=filtered', {headers: authHeader()});
    if(!res.ok) throw new Error('Failed');
    const d = await res.json();
    const filtered = (d.data||[]).filter(p => p.state && p.state.toUpperCase() === 'FILTERED');
    if(filtered.length === 0) {
      term.innerHTML = '<div style="padding:16px;color:var(--t3);font-family:var(--mono)">No filtered ports detected. <span style="color:var(--t2)">Filtered ports may indicate a firewall between the scanner and host.</span></div>';
      return;
    }
    let html = '<div style="font-size:9px;color:var(--t3);font-family:var(--mono);padding-bottom:6px">' + filtered.length + ' filtered port(s) detected</div>';
    filtered.forEach(p => {
      html += '<div class="log-line" style="border-left:2px solid var(--amber);padding:4px 8px;margin-bottom:2px;font-size:10px;font-family:var(--mono)">'
        + '<span style="color:var(--t2)">' + esc(p.ip) + '</span> '
        + '<span style="color:var(--amber)">' + esc(p.port) + '/' + esc(p.protocol||'tcp') + '</span> '
        + '<span style="color:var(--t3)">' + esc(p.service||'unknown') + '</span>'
        + '</div>';
    });
    term.innerHTML = html;
  } catch(e) {
    if(e.name !== 'AbortError') term.innerHTML = '<div style="padding:16px;color:var(--red);font-family:var(--mono)">Failed to load filtered ports</div>';
  }
}

/* ── SHIELD PAGE ── */
async function loadShield() {
  const tbody = document.getElementById('shield-body');
  if(!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--t3);padding:16px">Loading...</td></tr>';
  try {
    const res = await fetch('/api/v2/shield/actions?active=1', {headers: authHeader()});
    if(!res.ok) throw Error('Failed');
    const d = await res.json();
    const data = d.data || [];
    document.getElementById('shield-total').textContent = data.length;
    document.getElementById('shield-sib').textContent = data.length; pulseSib('shield-sib');
    if(data.length===0) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--t3);padding:16px">No active shield blocks</td></tr>'; return; }
    let rows = '';
    data.forEach(a => {
      const ts = a.taken_at ? new Date(a.taken_at*1000).toLocaleTimeString() : '--';
      rows += '<tr><td class="td-mono" style="color:var(--t2)">'+esc(ts)+'</td><td class="td-mono td-primary">'+esc(a.target_ip||'-')+'</td><td><span class="badge '+(a.action_type==='QUARANTINE_HOST'?'badge-critical':'badge-high')+'">'+esc(a.action_type||'')+'</span></td><td style="font-size:9px;color:var(--t2)">'+esc(a.rule_applied||'-')+'</td><td style="font-size:9px;color:var(--t2)">'+esc(a.justification||'')+'</td><td><button class="btn btn-secondary" style="font-size:8px;padding:2px 8px" data-action="revertShield" data-id="'+safeId(a.id)+'">Revert</button></td></tr>';
    });
    tbody.innerHTML = rows;
  } catch(e) {
    if(e.name!=='AbortError') tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--red);padding:16px">Failed to load shield data</td></tr>';
  }
}
async function revertShield(id) {
  try {
    const res = await fetch('/api/v2/shield/revert/'+id, {method:'POST', headers:authHeader()});
    if(res.ok) {
      showToast('Shield block reverted', 'ok');
      loadShield();
      loadContext();
      refreshDrawer();
      return;
    }
    if (res.status === 404) showToast('Shield action not found', 'error');
    else if (res.status !== 403) showToast('Rollback failed — the block is still active', 'error');
  } catch(e) {
    if (e.name !== 'AbortError') console.error('revertShield:', e);
  }
}

/* ── FORGE RULES PAGE ── */
function renderForgeDelivery(d) {
  const el = document.getElementById('forge-delivery');
  if (!el) return;
  if (!d) {
    el.className = 'forge-status warn';
    el.innerHTML = '<span class="fs-state">NEVER DELIVERED</span>'
      + '<span class="fs-detail">No ruleset has been written yet. Run a scan, or press Redeploy.</span>';
    return;
  }
  const map = {
    DEPLOYED:          ['ok',   'DEPLOYED',                        'file written and Suricata reloaded'],
    WRITTEN:           ['warn', 'WRITTEN — NO RELOAD CONFIGURED',  'the sensor will not see this until it reloads'],
    WRITTEN_NO_RELOAD: ['err',  'WRITTEN — RELOAD FAILED',         'file updated but the sensor did not reload'],
    FAILED:            ['err',  'DELIVERY FAILED',                 'previous ruleset left in place'],
    EMPTY:             ['warn', 'NO ACTIVE RULES',                 'nothing to write'],
  };
  const info = map[d.state] || ['warn', String(d.state || 'UNKNOWN'), ''];
  el.className = 'forge-status ' + info[0];
  const bits = [
    '<span class="fs-state">' + esc(info[1]) + '</span>',
    '<span class="fs-detail">' + esc(String(d.rule_count || 0)) + ' rules · ' + esc(relTime(d.written_at)) + '</span>',
  ];
  if (d.error) bits.push('<span class="fs-detail" style="color:var(--red)">' + esc(d.error) + '</span>');
  else bits.push('<span class="fs-detail" style="color:var(--t3)">' + esc(info[2]) + '</span>');
  if (d.reload_output && d.state !== 'DEPLOYED') {
    bits.push('<span class="fs-detail">reload: ' + esc(d.reload_output) + '</span>');
  }
  if (d.path) bits.push('<span class="fs-path">' + esc(d.path) + '</span>');
  el.innerHTML = bits.join('');
}

async function loadForge() {
  const tbody = document.getElementById('forge-body');
  if(!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:16px">Loading...</td></tr>';
  try {
    const res = await fetch('/api/v2/forge/rules', {headers: authHeader()});
    if(!res.ok) throw Error('Failed');
    const d = await res.json();
    const rules = d.data || [];
    renderForgeDelivery(d.delivery);
    // The table is a rule library; the badge and header only count rules that
    // are actually enforced. Retired-path rules stay visible but excluded.
    const activeRules = rules.filter(r => r.is_active).length;
    document.getElementById('forge-total').textContent = rules.length + ' rules · ' + activeRules + ' active';
    document.getElementById('forge-sib').textContent = activeRules; pulseSib('forge-sib');
    if(rules.length===0) { tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:16px">No rules generated yet. Run a scan + attack simulation first.</td></tr>'; return; }
    let rows = '';
    rules.forEach(r => {
      const ruleShort = esc((r.rule_text||'').substring(0, 60));
      const rid = safeId(r.id);
      // "In sensor" is not a toggle: it is whether this rule was in a ruleset
      // that was actually written. Nothing in the UI can fake it.
      const inSensor = !!(r.delivered_at && r.is_active);
      const sensorCell = inSensor
        ? '<span class="badge badge-critical">YES</span><br><span style="font-size:8px;color:var(--t3)">'+esc(relTime(r.delivered_at))+'</span>'
        : '<span class="badge badge-low">NO</span>';
      const actBtn = r.is_active
        ? '<button class="btn btn-secondary" style="font-size:8px;padding:2px 8px;border-color:rgba(241,100,121,.3);color:var(--red)" data-action="toggleDeploy" data-id="'+rid+'" title="Remove from the live ruleset">Exclude</button>'
        : '<button class="btn btn-primary" style="font-size:8px;padding:2px 8px" data-action="toggleDeploy" data-id="'+rid+'" title="Add to the live ruleset">Include</button>';
      rows += '<tr><td class="td-mono" style="color:var(--t2)">'+esc(r.rule_sid)+'</td><td><span class="badge badge-blue">'+esc(r.rule_category||'')+'</span></td><td style="font-size:9px;color:var(--t2);font-family:var(--mono)">'+esc(r.mitre_technique||'-')+'</td><td style="font-family:var(--mono);font-size:8px;color:var(--t1);max-width:260px;word-break:break-all">'+ruleShort+'</td><td>'+sensorCell+'</td><td style="font-size:9px;color:var(--t2)">'+safeId(r.true_positives)+'/'+safeId(r.false_positives)+'</td><td>'+actBtn+'</td></tr>';
    });
    tbody.innerHTML = rows;
  } catch(e) {
    if(e.name!=='AbortError') tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--red);padding:16px">Failed to load forge rules</td></tr>';
  }
}

/* ── FORGE DEPLOY ── */
async function toggleDeploy(ruleId) {
  try {
    const res = await fetch('/api/v2/forge/deploy/'+ruleId, {method:'POST', headers:authHeader()});
    const d = await res.json().catch(() => ({}));
    if(res.ok) {
      addLog('info', 'Forge rule #'+safeId(ruleId)+' '+(d.is_active?'included in':'excluded from')+' the ruleset');
    } else {
      const why = (d.delivery && d.delivery.error) || 'unknown error';
      showToast('Ruleset update failed: ' + why, 'error');
      addLog('error', 'Forge rule #'+safeId(ruleId)+' unchanged');
    }
    loadForge();
  } catch(e) { addLog('error', 'Deploy failed'); }
}

/* ── FORGE REDEPLOY ── */
async function rewriteForge() {
  try {
    const res = await fetch('/api/v2/forge/rewrite', {method:'POST', headers:authHeader()});
    const d = await res.json().catch(() => ({}));
    const state = (d.delivery && d.delivery.state) || 'UNKNOWN';
    if(res.ok) {
      addLog('success', 'Ruleset rewritten — ' + state);
    } else {
      const why = (d.delivery && d.delivery.error) || 'unknown error';
      showToast('Ruleset rewrite failed: ' + why, 'error');
    }
    loadForge();
  } catch(e) { addLog('error', 'Rewrite failed'); }
}

/* ── SCHEDULE CONFIG ── */
async function loadSchedule() {
  try {
    const res = await fetch('/api/v2/config/schedule', {headers:authHeader()});
    if(!res.ok) return;
    const d = await res.json();
    document.getElementById('nc-sched-freq').value = d.frequency || '';
    document.getElementById('nc-sched-time').value = d.time || '02:00';
    document.getElementById('nc-sched-enabled').checked = d.enabled || false;
    let status = 'No schedule configured';
    if (d.enabled) {
      status = d.frequency === 'hourly'
        ? 'Scheduled: every hour'
        : 'Scheduled: '+(d.frequency||'')+' at '+d.time+' (local time)';
      if (d.next_run) {
        const next = new Date(d.next_run);
        if (!isNaN(next)) status += ' · next '+next.toLocaleString();
      }
    }
    document.getElementById('nc-sched-status').textContent = status;
  } catch(e) {}
}
async function saveSchedule() {
  try {
    const freq = document.getElementById('nc-sched-freq').value;
    const time = document.getElementById('nc-sched-time').value;
    const enabled = document.getElementById('nc-sched-enabled').checked;
    const res = await fetch('/api/v2/config/schedule', {
      method:'POST', headers:{...authHeader(),'Content-Type':'application/json'},
      body: JSON.stringify({frequency:freq, time:time, enabled:enabled})
    });
    if(res.ok) loadSchedule();
  } catch(e) {}
}

/* ── ALERT CONFIG ── */
async function loadAlertConfig() {
  try {
    const res = await fetch('/api/v2/alerts/config', {headers:authHeader()});
    if(!res.ok) return;
    const d = await res.json();
    document.getElementById('nc-alert-discord').checked = d.critical_to_discord || false;
    document.getElementById('nc-alert-dash').checked = d.high_to_dashboard || false;
  } catch(e) {}
}
async function saveAlertConfig() {
  try {
    const discord = document.getElementById('nc-alert-discord').checked;
    const dash = document.getElementById('nc-alert-dash').checked;
    await fetch('/api/v2/alerts/config', {
      method:'POST', headers:{...authHeader(),'Content-Type':'application/json'},
      body: JSON.stringify({critical_to_discord: discord, high_to_dashboard: dash})
    });
  } catch(e) {}
}

/* ── SENTINEL ALERTS ── */
async function loadSentinelAlerts() {
  const tbody = document.getElementById('sentinel-body');
  if(!tbody) return;
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--t3);padding:16px">Loading...</td></tr>';
  try {
    const res = await fetch('/api/v2/sentinel/alerts', {headers: authHeader()});
    if(!res.ok) throw Error('HTTP ' + res.status);
    const d = await res.json();
    sentinelData = Array.isArray(d.data) ? d.data : [];
    sentinelLoaded = true;
    renderSentinelAlerts();
    renderOverview();
  } catch(e) {
    if(e.name !== 'AbortError') tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--red);padding:16px">Failed to load sentinel alerts</td></tr>';
  }
}

function renderSentinelAlerts() {
  const tbody = document.getElementById('sentinel-body');
  if(!tbody) return;
  const filter = document.getElementById('sentinel-filter')?.value || 'all';
  const alerts = sentinelData.filter(a => {
    if (filter === 'unacked') return !a.acknowledged && alertActionable(a);
    if (filter === 'predicted') return !!a.predicted;
    return true;
  });
  const unacked = actionableUnacked().length;
  const activePred = livePredicted().length;
  setText('sentinel-total', sentinelData.length);
  setText('sentinel-predicted', activePred);
  setText('sentinel-unacked', unacked);
  const predEl = document.getElementById('sentinel-predicted');
  if (predEl) predEl.title = 'Predicted paths whose hosts are still live (acknowledged or not)';
  const sib = document.getElementById('sentinel-sib');
  if (sib) { sib.textContent = unacked; pulseSib('sentinel-sib'); }
  if(!sentinelData.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--t3);padding:16px">No alerts yet — SENTINEL is monitoring for Suricata events matching FORGE rules</td></tr>';
    return;
  }
  if(!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--t3);padding:16px">No alerts match the current filter</td></tr>';
    return;
  }
  const canAck = currentUser.role === 'operator';
  tbody.innerHTML = alerts.map(a => {
    const time = a.alerted_at ? new Date(a.alerted_at*1000).toLocaleTimeString() : '—';
    const sevNum = Number(a.severity) || 3;
    const sevLabel = sevNum<=1?'CRITICAL':sevNum<=2?'HIGH':'INFO';
    const sevCls = sevNum<=1?'badge-critical':sevNum<=2?'badge-high':'badge-blue';
    const predictedBadge = a.predicted
      ? (a.actionable === false
          ? '<span class="badge badge-low" title="Path or endpoint no longer live — kept for history">STALE</span>'
          : '<span class="badge badge-critical" title="PHANTOM predicted this attack path">PREDICTED</span>')
      : '<span class="badge badge-medium" title="Unexpected alert">NEW</span>';
    const msg = (a.message||'').substring(0, 80);
    let ackCell;
    if (a.acknowledged) {
      ackCell = '<span class="badge badge-low" title="Acknowledged">ACKED</span>';
    } else if (canAck) {
      ackCell = '<button class="ack-btn" data-action="ackAlert" data-id="'+safeId(a.id)+'">Ack</button>';
    } else {
      ackCell = '<span style="color:var(--amber);font-size:9px" title="Viewer role cannot acknowledge">open</span>';
    }
    return '<tr data-alert-id="'+safeId(a.id)+'">'
      + '<td class="td-dim">'+esc(time)+'</td>'
      + '<td class="td-mono" style="color:var(--t2)">'+esc(a.rule_sid)+'</td>'
      + '<td class="td-mono" style="color:var(--amber)">'+esc(a.src_ip)+'</td>'
      + '<td class="td-mono">'+esc(a.dst_ip)+(a.dst_port?':'+esc(a.dst_port):'')+'</td>'
      + '<td><span class="badge badge-blue">'+esc(a.rule_category||'IDS')+'</span></td>'
      + '<td style="font-size:9.5px;color:var(--t2);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(msg)+'</td>'
      + '<td><span class="badge '+sevCls+'">'+sevLabel+'</span> '+predictedBadge+'</td>'
      + '<td>'+ackCell+'</td>'
      + '</tr>';
  }).join('');
}

async function ackAlert(el) {
  const id = Number(el.dataset.id);
  if (!id) return;
  el.disabled = true;
  try {
    const res = await fetch('/api/v2/sentinel/alerts/' + id + '/ack', {method: 'POST', headers: authHeader()});
    if (!res.ok) throw Error('HTTP ' + res.status);
    showToast('Alert acknowledged', 'ok');
    await loadSentinelAlerts();
    loadContext();
    refreshDrawer();
  } catch (e) {
    if (e.name !== 'AbortError') console.error('ackAlert:', e);
    el.disabled = false;
  }
}

async function ackAllAlerts() {
  if (!window.confirm('Acknowledge every unacknowledged SENTINEL alert?')) return;
  try {
    const res = await fetch('/api/v2/sentinel/alerts/ack_all', {method: 'POST', headers: authHeader()});
    if (!res.ok) throw Error('HTTP ' + res.status);
    showToast('All alerts acknowledged', 'ok');
    await loadSentinelAlerts();
    loadContext();
    refreshDrawer();
  } catch (e) {
    if (e.name !== 'AbortError') console.error('ackAllAlerts:', e);
  }
}

function gotoSentinel() {
  gotoPage('sentinel');
  setRoute({k: 'page', v: 'sentinel'}, 'replace');
}

/* ── ANOMALOUS PORTS ── */
async function loadAnomalousPorts() {
  const feed = document.getElementById('anomaly-port-feed');
  if(!feed) return;
  try {
    const res = await fetch('/api/v2/details/anomalous_ports', {headers: authHeader()});
    if(!res.ok) throw Error('Failed');
    const d = await res.json();
    const data = d.data || [];
    setText('anomaly-count', data.length);
    if(data.length === 0) { feed.innerHTML = '<div style="font-size:10px;color:var(--t3);font-family:var(--mono)">No anomalous ports detected</div>'; return; }
    let html = '';
    data.forEach(h => {
      const typeLabel = (h.detected_type||[]).map(esc).join(', ');
      html += '<div style="padding:6px 0;border-bottom:1px solid var(--b0);font-size:10px">'
        + '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'
        + '<span style="font-family:var(--mono);color:var(--t1);font-weight:500">' + esc(h.ip) + '</span>'
        + '<span style="font-size:8px;color:var(--t3);font-family:var(--mono)">' + typeLabel + '</span>'
        + '</div>';
      (h.anomalous_ports||[]).forEach(p => {
        html += '<div style="display:flex;align-items:center;gap:6px;padding:2px 0 2px 12px">'
          + '<span style="color:var(--red);font-family:var(--mono)">' + esc(p.port) + '/' + esc(p.protocol||'tcp') + '</span>'
          + '<span style="color:var(--t2)">' + esc(p.service||'unknown') + '</span>'
          + '<span style="font-size:8px;color:var(--amber);font-family:var(--mono)">unexpected</span>'
          + '</div>';
      });
      html += '</div>';
    });
    feed.innerHTML = html;
  } catch(e) {
    if(e.name !== 'AbortError') feed.innerHTML = '<div style="font-size:10px;color:var(--red);font-family:var(--mono)">Failed to load</div>';
  }
}

async function loadAIBrief() {
  const narrativeEl = document.getElementById('ai-narrative-page');
  const remediationEl = document.getElementById('ai-remediation-page');
  if(!narrativeEl || !remediationEl) return;
  try {
    const res = await fetch('/api/v2/oracle/ai_brief', {headers: authHeader()});
    if(!res.ok) throw new Error('Failed');
    const d = await res.json();
    const narrative = d.narrative || 'No narrative available. Run a scan to generate one.';
    const remediation = d.remediation || 'No remediation available. Run a scan to generate one.';
    narrativeEl.innerHTML = esc(narrative).replace(/\n/g, '<br>');
    remediationEl.innerHTML = esc(remediation).replace(/\n/g, '<br>');
  } catch(e) {
    if(e.name !== 'AbortError') {
      narrativeEl.innerHTML = 'No narrative available. Run a scan to generate one.';
      remediationEl.innerHTML = 'No remediation data. Run a scan to generate.';
    }
  }
}

/* ── SOCKETIO EVENTS (registered after authenticated connect) ── */
function initSocketHandlers() {
  if(!socket) return;
  socket.on('connect_error', function() {
    // Token expired between refresh cycles: drop the socket; the fetch wrapper
    // will re-establish an authenticated connection after the next refresh.
    try { socket.disconnect(); } catch(e) {}
    socket = null;
  });

  socket.on('host_event', function(data) {
    showToast('['+(data.type||'EVENT')+'] '+(data.ip||'')+' is now '+(data.status||data.type||'UP'), data.type==='DOWN'?'error':'info');
    updateStats();
    fetchGraph();
  });

  socket.on('log_event', function(data) {
    addLog(data.level ? data.level.toLowerCase() : 'info', data.message);
  });

  socket.on('scan_progress', function(data) {
    const status = data.status || '';
    const msg = data.message || '';
    const phase = data.phase || '';
    const prog = data.progress || 0;

    addLog(status==='running'?'info':status==='complete'?'ok':'warn', 'SCAN '+status.toUpperCase()+': '+msg);
    updateStats();

    if (status === 'complete') {
      loadHosts();
      fetchGraph();
      loadAIBrief();
      if(document.querySelector('.ptab.on').textContent.trim() === 'Phantom') loadPhantomFeed();
    } else if (status === 'running' || status === 'refresh') {
      loadHosts();
      fetchGraph();
    }
  });
}

/* ── THREE.JS 3D MAP ── */
function init3D() {
  const container = document.getElementById('viewport-3d');
  if(!container) return;
  const w = container.clientWidth || container.offsetWidth || 800;
  const h = container.clientHeight || container.offsetHeight || 600;
  scene = new THREE.Scene(); scene.background = new THREE.Color(0x090b10);
  camera = new THREE.PerspectiveCamera(55, w / Math.max(h, 1), 0.1, 2000);
  camera.position.set(60, 55, 90);
  camera.lookAt(0, 0, 0);
  renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
  renderer.setSize(w, h);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  container.appendChild(renderer.domElement);
  controls = new THREE.OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true; controls.dampingFactor = 0.08;
  controls.target.set(0, 0, 0);
  // Once the operator moves the camera, leave their framing alone.
  controls.addEventListener('start', () => { topoUserMoved = true; });
  scene.add(new THREE.AmbientLight(0xffffff, 0.8));
  const p = new THREE.PointLight(0x5b8dee, 1.2, 800); p.position.set(60, 60, 60); scene.add(p);
  const p2 = new THREE.PointLight(0xffffff, 0.4, 500); p2.position.set(-30, -20, -40); scene.add(p2);
  // Use MeshLambertMaterial for reliable instanced color rendering
  const geo = new THREE.BoxGeometry(4, 4, 4);
  const mat = new THREE.MeshLambertMaterial({ color: 0xffffff });
  instancedMesh = new THREE.InstancedMesh(geo, mat, 1000);
  instancedMesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
  scene.add(instancedMesh);
    renderer.domElement.addEventListener('mousemove', (e) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      pointerDirty = true;
    });
  // Resize handler
  window.addEventListener('resize', () => {
    if(!renderer || !camera || !container) return;
    const rw = container.clientWidth || container.offsetWidth;
    const rh = container.clientHeight || container.offsetHeight;
    if(rw > 0 && rh > 0) {
      vpW = rw; vpH = rh;
      renderer.setSize(rw, rh);
      camera.aspect = rw / Math.max(rh, 1);
      camera.updateProjectionMatrix();
      fitTopologyCamera(false);
    }
  });
  animate();
}

/* Frame every node in the topology card. The graph is laid out at random
   radii, and the card is much narrower than the old full-width map, so a
   fixed camera leaves assets off-canvas. Refit on node-set and aspect changes;
   a manual orbit opts out until the node set changes. */
function fitTopologyCamera(force) {
  if(!camera || !controls || !nodes3D.length) return;
  if(topoUserMoved && !force) return;
  const box = new THREE.Box3();
  nodes3D.forEach(n => { if(n.position) box.expandByPoint(n.position); });
  if(box.isEmpty()) return;
  const center = box.getCenter(new THREE.Vector3());
  const radius = Math.max(box.getBoundingSphere(new THREE.Sphere()).radius + 12, 24);
  const fov = camera.fov * Math.PI / 180;
  const aspect = Math.max(camera.aspect || 1, 0.5);
  const fitH = radius / Math.sin(fov / 2);
  const fitW = radius / Math.sin(Math.atan(Math.tan(fov / 2) * aspect));
  const dist = Math.max(fitH, fitW) * 1.12;
  const dir = camera.position.clone().sub(controls.target || new THREE.Vector3());
  if(!(dir.lengthSq() > 0.001)) dir.set(0.55, 0.5, 0.8);
  dir.normalize();
  controls.target.copy(center);
  camera.position.copy(center).addScaledVector(dir, dist);
  camera.lookAt(center);
  camera.updateProjectionMatrix();
  controls.update();
}

function getShortName(node) {
  let os = node.os || 'UNK';
  if (os.toLowerCase().includes('linux')) os = 'LNX';
  else if (os.toLowerCase().includes('windows')) os = 'WIN';
  else if (os.toLowerCase().includes('darwin') || os.toLowerCase().includes('mac')) os = 'MAC';
  else if (os.length > 5) os = os.substring(0, 4).toUpperCase();
  const parts = (node.id||node.ip||'').split('.');
  return os+' .'+parts[parts.length-1];
}

function update3DMap(data) {
  if (!data || !data.nodes || !instancedMesh) return;
  if (data.nodes.length > instancedMesh.count) {
    scene.remove(instancedMesh); instancedMesh.dispose();
    const geo = new THREE.BoxGeometry(4, 4, 4);
    const mat = new THREE.MeshLambertMaterial({ color: 0xffffff });
    instancedMesh = new THREE.InstancedMesh(geo, mat, data.nodes.length + 100);
    scene.add(instancedMesh);
  }
  instancedMesh.count = data.nodes.length;
  const newNodesMap = new Map();
  // Build blast radius lookup
  const blastIps = new Set(), exposedIps = new Set();
  if (data.blast_radius) {
    data.blast_radius.forEach(b => {
      if (b.is_source) blastIps.add(b.ip);
      else exposedIps.add(b.ip);
    });
  }
  data.nodes.forEach((n, idx) => {
    let pos = nodePositions[n.id || n.ip];
    if (!pos) {
      const angle = (idx / data.nodes.length) * Math.PI * 2;
      const radius = 60 + Math.random() * 40;
      pos = new THREE.Vector3(Math.cos(angle)*radius, (Math.random()-0.5)*80, Math.sin(angle)*radius);
      nodePositions[n.id || n.ip] = pos;
    }
    dummy.position.copy(pos);
    const ip = n.id || n.ip;
    const isBlast = blastIps.has(ip);
    const isExposed = exposedIps.has(ip);
    if (isBlast) dummy.scale.set(2.2, 0.7, 2.2);
    else if (n.risk > 50 || ip.endsWith('.1')) dummy.scale.set(1.5, 0.5, 1.5);
    else dummy.scale.set(1, 1, 1);
    dummy.updateMatrix();
    instancedMesh.setMatrixAt(idx, dummy.matrix);
    const os_l = (n.os || '').toLowerCase();
    const c = (n.status === 'OFFLINE' || n.type === 'DOWN') ? 0xf16479
        : isBlast ? 0xf16479   /* RED for critical blast source */
        : isExposed ? 0xf59e0b /* ORANGE for exposed neighbor */
        : os_l.includes('linux') ? 0x5b8dee
        : os_l.includes('windows') ? 0x34d399
        : os_l.includes('darwin') || os_l.includes('mac') ? 0xa78bfa
        : 0x2dd4bf;
    meshColor.setHex(c);
    instancedMesh.setColorAt(idx, meshColor);
    newNodesMap.set(ip, {node: n, index: idx, pos: pos});
    nodeDataByIndex.set(idx, {ip: ip, os: n.os || 'Unknown', risk: n.risk || 0, status: n.status || 'Active', blast: isBlast, exposed: isExposed});
  });
  instancedMesh.instanceMatrix.needsUpdate = true;
  if (instancedMesh.instanceColor) instancedMesh.instanceColor.needsUpdate = true;
  
  nodes3D.forEach(n => { if (n.userData.label) n.userData.label.remove(); });
  nodes3D = [];
  newNodesMap.forEach((v, id) => {
    const label = document.createElement('div');
    label.className = 'label-3d';
    label.innerText = getShortName(v.node);
    document.getElementById('viewport-3d').appendChild(label);
    nodes3D.push({ userData: {id: id, label: label}, position: v.pos });
  });
  
  links3D.forEach(l => scene.remove(l)); particles3D.forEach(p => scene.remove(p));
  links3D = []; particles3D = [];
  if (data.links) {
    data.links.forEach(l => {
      const srcId = typeof l.source === 'object' ? (l.source.id||l.source.ip) : l.source;
      const tgtId = typeof l.target === 'object' ? (l.target.id||l.target.ip) : l.target;
      const src = newNodesMap.get(srcId);
      const tgt = newNodesMap.get(tgtId);
      if (src && tgt) {
        const isKillChain = l.type === 'KILL_CHAIN';
        const geometry = new THREE.BufferGeometry().setFromPoints([src.pos, tgt.pos]);
        const material = new THREE.LineBasicMaterial({
          color: isKillChain ? 0xf16479 : 0x5b8dee,
          transparent: true,
          opacity: isKillChain ? 1.0 : 0.3
        });
        const line = new THREE.Line(geometry, material);
        scene.add(line); links3D.push(line);
        if (isKillChain) {
          const sp = new THREE.Mesh(new THREE.SphereGeometry(1.2, 8, 8), new THREE.MeshBasicMaterial({color: 0xf16479}));
          sp.userData = { src: src.pos.clone(), tgt: tgt.pos.clone(), t: Math.random() };
          scene.add(sp); particles3D.push(sp);
        }
      }
    });
  }
  const fitKey = [...newNodesMap.keys()].sort().join('|');
  if(fitKey !== topoFitKey) {
    topoFitKey = fitKey;
    topoUserMoved = false;
    fitTopologyCamera(true);
  }
}

function animate() {
  if(!renderer || !controls || activePage !== 'dashboard') return;
  requestAnimationFrame(animate);
  controls.update();
  // Sync renderer/camera if container resized (e.g. feed toggle)
  const vp = document.getElementById('viewport-3d');
  if(renderer && camera && vp) {
    const rw = vp.clientWidth, rh = vp.clientHeight;
    if(rw > 0 && rh > 0 && (rw !== vpW || rh !== vpH)) {
      vpW = rw; vpH = rh;
      renderer.setSize(rw, rh);
      camera.aspect = rw / rh;
      camera.updateProjectionMatrix();
      fitTopologyCamera(false);
    }
  }
  particles3D.forEach(p => {
    p.userData.t += 0.005;
    if(p.userData.t > 1) p.userData.t = 0;
    if(p.userData.src && p.userData.tgt) p.position.lerpVectors(p.userData.src, p.userData.tgt, p.userData.t);
  });
  const container = document.getElementById('viewport-3d');
  if(container && camera) {
    const wH = container.clientWidth / 2, hH = container.clientHeight / 2;
    nodes3D.forEach(n => {
      if (n.userData.label) {
        _v.copy(n.position); _v.project(camera);
        n.userData.label.style.left = (_v.x * wH) + wH + 'px';
        n.userData.label.style.top = -(_v.y * hH) + hH + 'px';
        n.userData.label.style.display = (_v.z > -1 && _v.z < 1) ? 'block' : 'none';
        const dsq = camera.position.distanceToSquared(n.position);
        n.userData.label.style.transform = 'translate(-50%, -100%) scale('+Math.max(0.6, 1.4 - (Math.sqrt(dsq) / 500))+')';
      }
    });
  }
  if(renderer && scene && camera) renderer.render(scene, camera);

  // 3D hover tooltip — only raycast on actual mouse movement
  const tip = document.getElementById('tip');
  if (!tip || !instancedMesh) return;
  if(pointerDirty) {
    pointerDirty = false;
    raycaster.setFromCamera(pointer, camera);
    const intersects = raycaster.intersectObject(instancedMesh);
    if (intersects.length > 0 && intersects[0].instanceId !== undefined) {
      const idx = intersects[0].instanceId;
      const nd = nodeDataByIndex.get(idx);
      if (nd && idx !== hoveredNodeIdx) {
        hoveredNodeIdx = idx;
        document.getElementById('tip-ip').textContent = nd.ip;
        document.getElementById('tip-os').textContent = nd.os;
        document.getElementById('tip-role').textContent = nd.risk > 50 ? 'Critical' : nd.risk > 20 ? 'Standard' : 'Low';
        document.getElementById('tip-status').textContent = nd.status || 'Active';
        const pdata = portCache.get(nd.ip);
        document.getElementById('tip-ports').textContent = pdata ? pdata.join(', ') : '—';
        tip.style.display = 'block';
      }
      const rect = renderer.domElement.getBoundingClientRect();
      tip.style.left = (pointer.x * 0.5 + 0.5) * rect.width + rect.left + 16 + 'px';
      tip.style.top = (pointer.y * -0.5 + 0.5) * rect.height + rect.top - 20 + 'px';
    } else {
      hoveredNodeIdx = -1;
      tip.style.display = 'none';
    }
  }
}

function cleanup3D() {
  if (renderer) {
    const container = document.getElementById('viewport-3d');
    const canvas = renderer.domElement;
    renderer.dispose();
    renderer.forceContextLoss && renderer.forceContextLoss();
    if(container && canvas && canvas.parentNode === container) container.removeChild(canvas);
    renderer = null;
  }
  nodeDataByIndex = new Map();
  hoveredNodeIdx = -1;
  if (instancedMesh) {
    scene && scene.remove(instancedMesh);
    instancedMesh.dispose();
    instancedMesh = null;
  }
  nodes3D.forEach(n => {
    if (n.userData.label && n.userData.label.parentNode) n.userData.label.remove();
    scene && scene.remove(n);
  });
  links3D.forEach(l => scene && scene.remove(l));
  particles3D.forEach(p => scene && scene.remove(p));
  nodes3D = []; links3D = []; particles3D = []; nodePositions = {};
  topoFitKey = ''; topoUserMoved = false;
  while(scene && scene.children.length > 0) {
    const child = scene.children[0];
    if (child.dispose) child.dispose();
    scene.remove(child);
  }
  scene = null;
  controls && controls.dispose && controls.dispose();
  controls = null;
  camera = null;
}

async function fetchGraph() {
  try {
    const controller = new AbortController();
    fetchControllers.set('fetchGraph', controller);
    const res = await fetch('/api/v2/graph', {headers: authHeader(), signal: controller.signal});
    if(res.ok) { const d = await res.json(); update3DMap(d); loadPortCache(); }
  } catch(e) {
    if (e.name === 'AbortError') return;
  } finally {
    fetchControllers.delete('fetchGraph');
  }
}

/* ── PORT CACHE (for 3D tooltip) ── */
async function loadPortCache() {
  try {
    const res = await fetch('/api/v2/details/ports', {headers: authHeader()});
    if(!res.ok) return;
    const d = await res.json();
    portCache.clear();
    (d.data||[]).forEach(p => {
      if(!portCache.has(p.ip)) portCache.set(p.ip, []);
      portCache.get(p.ip).push(p.port+'/'+(p.protocol||'tcp'));
    });
  } catch(e) {}
}

/* ── STATS POLL ── */
async function updateStats() {
  try {
    const controller = new AbortController();
    fetchControllers.set('updateStats', controller);
    const res = await fetch('/api/v2/stats', {headers: authHeader(), signal: controller.signal});
    if(!res.ok) {
      if(res.status === 401) { jwtToken = null; document.getElementById('login-modal').style.display = 'flex'; }
      return;
    }
    const d = await res.json();
    lastStats = d;
    const hosts = d.hosts || 0;
    const cves = d.cves || 0;
    const posture = Math.round(d.posture) || 0;
    
    document.getElementById('stat-hosts') && (document.getElementById('stat-hosts').innerText = fmtNum(hosts));
    document.getElementById('stat-cves') && (document.getElementById('stat-cves').innerText = fmtNum(cves));
    document.getElementById('rp-assets').textContent = fmtNum(hosts);
    document.getElementById('rp-cves').textContent = fmtNum(cves);
    document.getElementById('posture-val').textContent = posture;
    
    // Sidebar stats
    document.getElementById('sb-online').textContent = fmtNum(d.online || 0);
    document.getElementById('sb-offline').textContent = fmtNum(d.offline || 0);
    
    // Posture donut
    animateDonut(posture);
    
    // Risk bar — calculate from posture score
    const riskLevel = 10 - Math.round(posture / 10);
    document.getElementById('risk-bar').style.width = Math.min(100, riskLevel * 10) + '%';
    const levels = ['LOW','MEDIUM','HIGH','CRITICAL'];
    const colors = ['var(--green)','var(--amber)','var(--pink)','var(--red)'];
    const idx = riskLevel < 3 ? 0 : riskLevel < 6 ? 1 : riskLevel < 9 ? 2 : 3;
    document.getElementById('risk-label').textContent = levels[idx];
    document.getElementById('risk-label').style.color = colors[idx];

    // Semantic dimming — fade UI when safe
    const shell=document.querySelector('.shell');
    if(posture>=80 && (d.critical||0)===0 && (d.high||0)===0) shell.classList.add('dim');
    else shell.classList.remove('dim');

    // Status chips
    const engine = d.scanner_enabled ? (d.is_scanning ? 'Scanning' : 'Online') : 'Paused';
    document.getElementById('rp-engine').textContent = engine;
    document.getElementById('status-txt').textContent = d.is_scanning ? 'Scanning' : 'Nominal';
    document.getElementById('scan-txt').textContent = engine;
    document.getElementById('alert-txt').textContent = Number(d.alerts || 0) + ' Alerts';

    const wasScanning = scanning;
    isScannerEnabled = d.scanner_enabled;
    scanning = d.is_scanning;
    if (wasScanning && !scanning) fetchGraph();  // scan just finished → refresh 3D
    updateScanUI();

    // Scan cycle status
    document.getElementById('scs-status').textContent = d.is_scanning ? '🔄 Scanning' : d.scanner_enabled ? '✓ Online' : '✓ Idle';
    document.getElementById('scs-count').textContent = fmtNum(d.total_scans || 0);
    if (d.is_scanning) { document.getElementById('scs-last').textContent = 'Now'; } else { document.getElementById('scs-last').textContent = d.timestamp ? new Date(d.timestamp*1000).toLocaleTimeString() : '—'; }

    // Progress bar — polling-based (daemon has no SocketIO)
    const pwrap = document.getElementById('scs-prog-wrap');
    const pbar = document.getElementById('scs-prog-bar');
    const pphase = document.getElementById('scs-phase');
    if (d.is_scanning) {
        if(pwrap) { pwrap.style.display = 'block'; pwrap.style.opacity = '1'; }
        if(pbar) pbar.classList.add('scanning');
        if(pphase) { pphase.style.display = 'block'; pphase.textContent = d.scan_phase || 'Scanning...'; }
    } else if (d.scanner_enabled) {
        if(pwrap) { pwrap.style.display = 'block'; pwrap.style.opacity = '0.35'; }
        if(pbar) pbar.classList.remove('scanning');
        if(pphase) { pphase.style.display = 'block'; pphase.textContent = 'Scanner Online — waiting for next cycle'; }
    } else {
        if(pwrap) { pwrap.style.display = 'none'; pwrap.style.opacity = '1'; }
        if(pbar) pbar.classList.remove('scanning');
        if(pphase) pphase.style.display = 'none';
    }

    // Drift
    setText('drift-count', (d.recent_diffs || []).length);
    if(d.recent_diffs && d.recent_diffs.length) {
      document.getElementById('drift-feed').innerHTML = d.recent_diffs.map(df => '<div class="alrt"><div class="atag"><svg width="7" height="7" viewBox="0 0 7 7"><circle cx="3.5" cy="3.5" r="3.5" fill="var(--red)"/></svg>'+esc(df.diff_type||'EVENT')+'</div><div class="abody">'+esc(df.detail||'')+'</div></div>').join('');
    } else {
      document.getElementById('drift-feed').innerHTML = '<div style="font-size:10px;color:var(--t3);font-family:var(--mono)">No drift events</div>';
    }

    renderOverview();
    loadAnomalousPorts();

  } catch(e) {
    if (e.name !== 'AbortError') console.error('Stats:', e);
  } finally {
    fetchControllers.delete('updateStats');
  }
}

/* ── DONUT ANIMATION ── */
function animateDonut(targetPosture) {
  const donut = document.querySelector('.gw circle[stroke="url(#gg)"]');
  if(!donut) return;
  const circ = 2 * Math.PI * 25;
  const targetOffset = circ - (targetPosture/100) * circ;
  const current = parseFloat(donut.getAttribute('stroke-dashoffset')) || circ;
  if(Math.abs(targetOffset - current) < 0.5) { donut.setAttribute('stroke-dashoffset', targetOffset); return; }
  donut.setAttribute('stroke-dasharray', circ);
  const diff = targetOffset - current;
  const start = performance.now();
  const dur = 600;
  function frame(now) {
    const t = Math.min((now - start) / dur, 1);
    const ease = 1 - Math.pow(1 - t, 3);
    donut.setAttribute('stroke-dashoffset', current + diff * ease);
    if(t < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

let _osintAllData = [];

async function loadOSINT() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadOSINT', controller);
    const res = await fetch('/api/v2/iris/osint', {headers: authHeader(), signal: controller.signal});
    if(!res.ok) return;
    const d = await res.json();
    _osintAllData = d.data || [];
    setText('osint-count', _osintAllData.length);
    const filter = document.getElementById('osint-filter');
    const feed = document.getElementById('osint-feed');
    if(!feed || !filter) return;
    if(!_osintAllData.length) {
      feed.innerHTML = '<div style="font-size:10px;color:var(--t3);font-family:var(--mono)">No OSINT data</div>';
      return;
    }
    // Populate filter dropdown with unique targets
    const targets = [...new Set(_osintAllData.map(o => o.target).filter(Boolean))];
    const curVal = filter.value;
    filter.innerHTML = '<option value="">All Targets</option>' + targets.map(t => '<option value="'+escAttr(t)+'">'+esc(t)+'</option>').join('');
    filter.value = curVal && targets.includes(curVal) ? curVal : '';
    // Filter by selected target
    const filtered = filter.value ? _osintAllData.filter(o => o.target === filter.value) : _osintAllData;
    feed.innerHTML = filtered.map(o => {
      const sev = o.severity || 'INFO';
      const color = sev==='HIGH'?'var(--red)':sev==='MEDIUM'?'var(--amber)':'var(--blue)';
      return '<div class="osi"><div class="osidot" style="background:'+color+'"></div><div class="osi-body"><div class="osi-top"><span class="osname">'+esc(o.finding_type||'Data')+'</span>'+(o.target?' <span style="font-size:8px;color:var(--t3)">'+esc(o.target)+'</span>':'')+'</div><div class="osmeta">'+esc(o.description||'')+'</div></div><span class="osbtn">'+esc(sev)+'</span></div>';
    }).join('');
  } catch(e) {
    if (e.name !== 'AbortError') console.error('OSINT:', e);
  } finally {
    fetchControllers.delete('loadOSINT');
  }
}

async function loadShieldWidget() {
  try {
    const controller = new AbortController();
    fetchControllers.set('loadShieldWidget', controller);
    const res = await fetch('/api/v2/shield/actions?active=1', {headers: authHeader(), signal: controller.signal});
    const d = await res.json();
    const container = document.getElementById('shield-feed');
    if (!container) return;
    const list = (d && d.data) || [];
    setText('shield-widget-count', list.length);
    if (!list.length) {
      container.innerHTML = '<div style="font-size:10px;color:var(--t3);font-family:var(--mono)">No active blocks · Shield integrity 100%</div>';
      return;
    }
    container.innerHTML = list.map(a => '<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 8px;border-left:2px solid var(--red);background:var(--red3);border-radius:0 4px 4px 0;margin-bottom:4px"><div><span style="font-family:var(--mono);font-size:10px;color:var(--t1)">'+esc(a.target_ip)+'</span> <span style="font-size:9px;color:var(--t3)">('+esc(a.action_type)+')</span></div><button class="btn btn-secondary" style="font-size:7px;padding:2px 6px" data-action="revertShieldWidget" data-id="'+safeId(a.id)+'">RELEASE</button></div>').join('');
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Shield:', e);
  } finally {
    fetchControllers.delete('loadShieldWidget');
  }
}

async function revertShieldWidget(id) {
  try {
    const controller = new AbortController();
    fetchControllers.set('revertShieldWidget', controller);
    const res = await fetch('/api/v2/shield/revert/'+id, {method:'POST', headers: authHeader(), signal: controller.signal});
    if (!res.ok) {
      if (res.status === 404) showToast('Shield action not found', 'error');
      else if (res.status !== 403 && res.status < 500) showToast('Rollback failed — the block is still active', 'error');
      return;
    }
    showToast('Shield block reverted', 'ok');
    loadShieldWidget();
    loadShield();
    loadContext();
  } catch(e) {
    if (e.name !== 'AbortError') console.error('Revert:', e);
  } finally {
    fetchControllers.delete('revertShieldWidget');
  }
}

/* ── COMMAND DECK OVERVIEW ─────────────────────────────────────────────── */
function clip(s, n) {
  s = String(s === null || s === undefined ? '' : s);
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function alertSeverity(a) {
  const n = Number(a && a.severity) || 3;
  return n <= 1 ? 'critical' : n <= 2 ? 'high' : 'medium';
}

function findHostMeta(ip) {
  return (hostData || []).find(h => h.ip === ip) || null;
}

// The API marks predictions whose path or endpoints no longer exist as
// non-actionable. Older payloads omit the flag, so only an explicit false
// removes an alert from the current-work views.
function alertActionable(a) {
  return !a || a.actionable !== false;
}

function activePredicted() {
  return (sentinelData || []).filter(a => a.predicted && !a.acknowledged && alertActionable(a));
}

function livePredicted() {
  // Acking a prediction does not make its path disappear, so the Sentinel
  // header counts every still-reachable prediction, acked or not.
  return (sentinelData || []).filter(a => a.predicted && alertActionable(a));
}

function actionableUnacked() {
  return (sentinelData || []).filter(a => !a.acknowledged && alertActionable(a));
}

function distinctCveIds(list) {
  const seen = new Set();
  return (list || []).filter(c => {
    const key = c.cve_id || ('row:' + c.id);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderActionQueue() {
  const body = document.getElementById('queue-body');
  if (!body) return;
  const predicted = activePredicted();
  const criticalCves = (cveData || []).filter(c => String(c.severity || '').toUpperCase() === 'CRITICAL');
  const highCves = (cveData || []).filter(c => String(c.severity || '').toUpperCase() === 'HIGH');
  const medCves = (cveData || []).filter(c => String(c.severity || '').toUpperCase() === 'MEDIUM');

  const rows = [];
  predicted.forEach(a => {
    rows.push({
      kind: 'predicted', sev: 'critical', order: 0,
      title: 'Predicted attack path',
      tid: a.rule_sid ? 'SID ' + a.rule_sid : 'PREDICTED',
      desc: a.rule_category ? String(a.rule_category).toLowerCase() : '',
      meta: '<span class="mono">' + esc(a.src_ip || '—') + '</span> → <span class="mono">'
        + esc(a.dst_ip || '—') + (a.dst_port ? ':' + esc(a.dst_port) : '') + '</span>'
        + (a.message ? ' · ' + esc(clip(a.message, 54)) : ''),
      when: relTime(a.alerted_at),
      ip: a.src_ip || '',
    });
  });

  const cveRows = (list, sev) => list.slice()
    .sort((a, b) => Number(b.cvss_v3 || 0) - Number(a.cvss_v3 || 0))
    .forEach(c => rows.push({
      kind: 'cve', sev, order: 1,
      title: c.cve_id || 'CVE',
      tid: sev.toUpperCase(),
      desc: c.description ? clip(c.description, 62) : '',
      meta: '<span class="mono">' + esc(c.ip || '—') + '</span> · '
        + esc((c.port || '?') + '/' + (c.service || 'tcp')) + ' · CVSS '
        + esc(c.cvss_v3 || '—') + ' · ' + esc(String(c.verified_status || 'UNVERIFIED').replace(/_/g, ' ')),
      when: c.cvss_v3 ? 'CVSS ' + esc(c.cvss_v3) : '',
      ip: c.ip || '',
    }));
  cveRows(criticalCves, 'critical');
  cveRows(highCves, 'high');
  cveRows(medCves, 'medium');

  let shown = rows;
  if (queueFilter === 'critical') shown = rows.filter(r => r.sev === 'critical');
  else if (queueFilter === 'predicted') shown = rows.filter(r => r.kind === 'predicted');
  shown.sort((a, b) => (a.order - b.order) || 0);

  setText('queue-count', shown.length);
  if (!shown.length) {
    body.innerHTML = '<div class="qempty">Nothing needs action in this view.</div>';
    return;
  }

  const groups = queueFilter === 'predicted'
    ? [['predicted', 'Predicted', shown]]
    : queueFilter === 'critical'
      ? [['critical', 'Critical', shown]]
      : [
          ['critical', 'Critical', rows.filter(r => r.sev === 'critical')],
          ['high', 'High', rows.filter(r => r.sev === 'high')],
          ['medium', 'Medium', rows.filter(r => r.sev === 'medium')],
        ];

  const dotFor = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--amber)' };
  let html = '';
  groups.forEach(([key, label, items]) => {
    if (!items.length) return;
    html += '<div class="qgroup"><span class="qdot" style="background:' + dotFor[key] + '"></span>'
      + label + ' <span class="dim">· ' + items.length + '</span></div>';
    items.forEach(r => {
      const action = r.kind === 'predicted'
        ? '<button class="btn mini contain" data-action="gotoSentinel">Review</button>'
        : '<span class="btn mini secondary">Open host</span>';
      html += '<div class="qrow" data-sev="' + r.sev + '" data-action="openHost" data-ip="' + escAttr(r.ip) + '" title="Open ' + escAttr(r.ip||'host') + '">'
        + '<div><div class="qtitle">' + esc(r.title)
        + (r.tid ? ' <span class="tid">' + esc(r.tid) + '</span>' : '')
        + (r.desc ? ' <span class="qdim">· ' + esc(r.desc) + '</span>' : '')
        + '</div><div class="qmeta">' + r.meta + '</div></div>'
        + '<div class="qwhen">' + r.when + '</div>'
        + '<div class="qactions">' + action
        + '<svg class="q-arrow" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="m6 4 4 4-4 4"/></svg>'
        + '</div></div>';
    });
  });
  body.innerHTML = html;
}

function renderBrief() {
  const body = document.getElementById('brief-body');
  if (!body) return;
  const predicted = activePredicted();
  const unacked = actionableUnacked();
  const items = [];

  const byHost = {};
  (cveData || []).forEach(c => { if (c.ip) byHost[c.ip] = (byHost[c.ip] || 0) + 1; });
  const top = Object.entries(byHost).sort((a, b) => b[1] - a[1])[0];
  if (top) {
    const inbound = predicted.filter(a => a.dst_ip === top[0]).length;
    items.push({
      dot: 'var(--red)',
      html: '<b>Risk is concentrated.</b> ' + esc(top[0]) + ' holds ' + top[1] + ' of '
        + (cveData || []).length + ' findings'
        + (inbound ? ' and is the target of ' + inbound + ' predicted pivot' + (inbound === 1 ? '' : 's') : '')
        + '.',
    });
  } else {
    items.push({ dot: 'var(--green)', html: '<b>No mapped CVEs.</b> The last scan did not match known vulnerabilities.' });
  }

  const dry = !!(lastContext && lastContext.shield_dry_run);
  const blocks = lastContext ? Number(lastContext.active_blocks || 0) : 0;
  items.push({
    dot: dry ? 'var(--amber)' : 'var(--red)',
    html: '<b>SHIELD is ' + (dry ? 'in dry-run' : 'enforcing') + '.</b> ' + blocks
      + ' active block' + (blocks === 1 ? '' : 's') + ' '
      + (dry ? 'recorded but not enforced on the kernel.' : 'applied to the kernel.'),
  });

  if (unacked.length) {
    items.push({
      dot: 'var(--accent)',
      html: '<b>' + unacked.length + ' unacknowledged alert' + (unacked.length === 1 ? '' : 's') + '.</b>'
        + (predicted.length
          ? ' ' + predicted.length + ' predicted path' + (predicted.length === 1 ? '' : 's') + ' require review.'
          : ' No predicted paths are still reachable.'),
    });
  } else {
    items.push({ dot: 'var(--green)', html: '<b>Alert queue is clear.</b> No actionable unacknowledged Sentinel alerts.' });
  }

  body.innerHTML = items.slice(0, 3).map(i =>
    '<div class="brief-item"><span class="bdot" style="background:' + i.dot + '"></span><div>' + i.html + '</div></div>'
  ).join('');
  const now = new Date();
  setText('brief-foot', 'Updated ' + now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' · live');
}

function renderSelectedAsset() {
  const card = document.getElementById('ov-asset');
  if (!card) return;
  let best = null;
  nodeDataByIndex.forEach(v => {
    if (!best || Number(v.risk || 0) > Number(best.risk || 0)) best = v;
  });
  if (!best && (cveData || []).length) {
    const counts = {};
    cveData.forEach(c => { if (c.ip) counts[c.ip] = (counts[c.ip] || 0) + 1; });
    const ip = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    if (ip) best = { ip: ip[0], risk: 0, os: 'Unknown' };
  }
  // Inventory is fetched during init, before the 3D graph and CVE list settle.
  // Without this fallback the card degraded to "Asset" until Inventory opened.
  if (!best && (hostData || []).length) {
    const host = hostData.slice()
      .sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0))[0];
    if (host && host.ip) {
      best = { ip: host.ip, risk: Number(host.risk_score) || 0, os: host.os_name || 'Unknown' };
    }
  }
  if (!best) {
    setText('ov-asset-ip', 'No assets yet');
    setText('ov-asset-risk', 'RISK —');
    setText('ov-asset-sub', 'Run a scan to populate the command deck.');
    const emptyBar = document.getElementById('ov-asset-bar');
    if (emptyBar) emptyBar.style.width = '0%';
    const emptyChips = document.getElementById('ov-asset-chips');
    if (emptyChips) emptyChips.innerHTML = '<span>awaiting scan</span>';
    card.removeAttribute('data-action');
    card.setAttribute('aria-disabled', 'true');
    return;
  }
  const ip = best.ip || '';
  const meta = findHostMeta(ip);
  const risk = Number(best.risk || 0);
  setText('ov-asset-ip', ip || '—');
  setText('ov-asset-risk', 'RISK ' + (risk ? risk.toFixed(1) : '—'));
  setText('ov-asset-sub', [
    meta && meta.hostname,
    (meta && meta.os_name) || best.os,
    meta && meta.vendor,
  ].filter(Boolean).join(' · ') || 'Asset');
  const bar = document.getElementById('ov-asset-bar');
  if (bar) bar.style.width = Math.max(2, Math.min(100, risk)) + '%';
  const chips = document.getElementById('ov-asset-chips');
  if (chips) {
    const svc = [...new Set((cveData || []).filter(c => c.ip === ip)
      .map(c => (c.port || '?') + '/' + (c.service || 'tcp')))].slice(0, 4);
    chips.innerHTML = svc.length
      ? svc.map(s => '<span>' + esc(s) + '</span>').join('')
      : '<span>no exposed services mapped</span>';
  }
  card.setAttribute('data-action', 'openHost');
  card.setAttribute('data-ip', ip);
  card.removeAttribute('aria-disabled');
  card.setAttribute('aria-label', 'Open details for ' + (ip || 'asset'));
}

function renderOverview() {
  const predicted = activePredicted();
  const unacked = actionableUnacked();
  const critical = (cveData || []).filter(c => String(c.severity || '').toUpperCase() === 'CRITICAL');
  const high = (cveData || []).filter(c => String(c.severity || '').toUpperCase() === 'HIGH');
  // A CVE affecting two hosts is one vulnerability but two findings. The KPI
  // counts unique CVEs; the findings table counts affected host/port rows.
  const criticalIds = distinctCveIds(critical).length;
  const statsCritical = lastStats && Number.isFinite(Number(lastStats.critical_cves))
    ? Number(lastStats.critical_cves)
    : criticalIds;
  const assets = lastStats && Number.isFinite(Number(lastStats.hosts))
    ? Number(lastStats.hosts)
    : nodeDataByIndex.size;

  setText('ov-assets', assets || 0);
  setText('ov-predicted', predicted.length);
  setText('kpi-critical', statsCritical + predicted.length);
  setText('kpi-foot-critical', statsCritical + ' CVE' + (statsCritical === 1 ? '' : 's')
    + ' · ' + predicted.length + ' predicted');
  setText('kpi-foot-alerts', (sentinelData || []).length + ' total · ' + unacked.length + ' actionable');
  if (sentinelLoaded) setText('ctx-unack', unacked.length);
  if (lastStats) setText('kpi-foot-assets', (lastStats.online || 0) + ' live · ' + (lastStats.offline || 0) + ' offline');
  if (lastContext) {
    const dry = !!lastContext.shield_dry_run;
    const shieldFoot = document.getElementById('kpi-foot-shield');
    if (shieldFoot) {
      shieldFoot.innerHTML = dry
        ? '<span class="amber">DRY-RUN</span> · not enforcing'
        : '<span class="down">ENFORCE</span> · active';
    }
  }
  setText('topo-sub', (assets || 0) + ' assets · ' + predicted.length + ' predicted path' + (predicted.length === 1 ? '' : 's'));
  setText('find-total', (cveData || []).length);
  setText('find-critical', critical.length);
  setText('find-high', high.length);
  setText('find-predicted', predicted.length);
  renderActionQueue();
  renderBrief();
  renderSelectedAsset();
}

/* ── SPARKLINE ── */
const spkData=Array.from({length:60},()=>0);
function drawSpk(){
  const sc=document.getElementById('spark');
  if(!sc) return;
  const sctx=sc.getContext('2d');
  const W=sc.offsetWidth||244,H=28;sc.width=W;sc.height=H;
  const max=Math.max(...spkData),min=Math.min(...spkData),range=max-min||1;
  sctx.clearRect(0,0,W,H);
  const step=W/(spkData.length-1);
  sctx.beginPath();sctx.moveTo(0,H);
  spkData.forEach((v,i)=>sctx.lineTo(i*step,H-(v-min)/range*(H-4)-2));
  sctx.lineTo(W,H);sctx.closePath();
  const g=sctx.createLinearGradient(0,0,0,H);
  g.addColorStop(0,'rgba(91,141,238,.2)');g.addColorStop(1,'rgba(91,141,238,0)');
  sctx.fillStyle=g;sctx.fill();
  sctx.beginPath();
  spkData.forEach((v,i)=>{const x=i*step,y=H-(v-min)/range*(H-4)-2;i===0?sctx.moveTo(x,y):sctx.lineTo(x,y);});
  sctx.strokeStyle='#5b8dee';sctx.lineWidth=1.2;sctx.stroke();
  const lv=spkData[spkData.length-1];
  document.getElementById('spkval').textContent=lv+' ev/s';
}

/* ── ACTIVITY MONITOR ── */
const evData=Array.from({length:60},()=>0);
const bwData=Array.from({length:60},()=>0);
const latData=Array.from({length:60},()=>0);
let activeTab='events';
const tabCfg={
  events:{data:evData,color:'#5b8dee',label:'ev/s',dec:0},
  bandwidth:{data:bwData,color:'#2dd4bf',label:'MB/s',dec:2},
  latency:{data:latData,color:'#f59e0b',label:'ms',dec:0},
};
function drawAct(){
  const cfg=tabCfg[activeTab];const arr=cfg.data;
  const AC=document.getElementById('actcanvas');
  if(!AC) return;
  const actx=AC.getContext('2d');
  const W=AC.offsetWidth||244,H=AC.offsetHeight||64;
  AC.width=W;AC.height=H;
  const pad={t:5,r:4,b:16,l:32};
  const cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
  const max=Math.max(...arr),range=max||1;
  [0,.5,1].forEach(f=>{
    const y=pad.t+ch*(1-f);
    actx.strokeStyle='rgba(30,35,50,.9)';actx.lineWidth=1;
    actx.beginPath();actx.moveTo(pad.l,y);actx.lineTo(pad.l+cw,y);actx.stroke();
    actx.font="8px 'IBM Plex Mono',monospace";actx.fillStyle='rgba(61,74,96,.85)';actx.textAlign='right';
    actx.fillText(cfg.dec>0?(max*f).toFixed(1):Math.round(max*f),pad.l-3,y+3);
  });
  actx.textAlign='center';actx.fillStyle='rgba(61,74,96,.8)';actx.font="8px 'IBM Plex Mono',monospace";
  [0,1,2].forEach(i=>actx.fillText('-'+Math.round(60-i*30)+'s',pad.l+cw*(i/2),H-3));
  const step=cw/(arr.length-1);
  const pts=arr.map((v,i)=>({x:pad.l+i*step,y:pad.t+ch*(1-v/range)}));
  actx.beginPath();actx.moveTo(pts[0].x,pad.t+ch);
  pts.forEach(p=>actx.lineTo(p.x,p.y));
  actx.lineTo(pts[pts.length-1].x,pad.t+ch);actx.closePath();
  const grad=actx.createLinearGradient(0,pad.t,0,pad.t+ch);
  grad.addColorStop(0,cfg.color+'28');grad.addColorStop(1,cfg.color+'00');
  actx.fillStyle=grad;actx.fill();
  actx.beginPath();pts.forEach((p,i)=>i===0?actx.moveTo(p.x,p.y):actx.lineTo(p.x,p.y));
  actx.strokeStyle=cfg.color;actx.lineWidth=1.5;actx.lineJoin='round';actx.stroke();
  const lp=pts[pts.length-1];
  actx.beginPath();actx.arc(lp.x,lp.y,2.5,0,Math.PI*2);actx.fillStyle=cfg.color;actx.fill();
  const lv=arr[arr.length-1];
  document.getElementById('act-live').textContent=(cfg.dec>0?lv.toFixed(cfg.dec):lv)+' '+cfg.label;
  document.getElementById('act-live').style.color=cfg.color;
}
function switchAct(el,tab){
  document.querySelectorAll('.atab').forEach(t=>t.classList.remove('on'));
  el.classList.add('on');activeTab=tab;drawAct();
}

/* ── POLLING ── */
let bwHistory = Array.from({length: 10}, () => 0);
let latHistory = Array.from({length: 10}, () => 0);

async function pollNetworkStats() {
  try {
    const res = await fetch('/api/network/stats', {headers: authHeader()});
    if(!res.ok) return;
    const d = await res.json();
    const ev = Math.round(d.packets_per_sec);
    const bw = d.bandwidth_mbps;
    const lat = d.latency_ms;
    evData.shift(); evData.push(ev);
    spkData.shift(); spkData.push(ev);
    bwData.shift(); bwData.push(bw);
    bwHistory.shift(); bwHistory.push(bw);
    latData.shift(); latData.push(lat);
    latHistory.shift(); latHistory.push(lat);
    drawAct(); drawSpk();
    probeCount += Math.max(0, ev);
    const avgBW = (bwHistory.reduce((a,b) => a+b, 0) / bwHistory.length);
    const avgLat = (latHistory.reduce((a,b) => a+b, 0) / latHistory.length);
    document.getElementById('m-probes').textContent = fmtNum(probeCount);
    document.getElementById('m-bw').textContent = avgBW >= 1 ? avgBW.toFixed(1) + ' MB/s' : (avgBW*1024).toFixed(0) + ' KB/s';
    document.getElementById('m-lat').textContent = avgLat >= 1 ? avgLat.toFixed(0) + 'ms' : (avgLat*1000).toFixed(0) + 'µs';
  } catch(e) { /* ignore */ }
}

/* ── INIT ── */
function initDashboard() {
  // bfcache restores and repeated logins must not stack timers or sockets.
  if (window._dashInited) return;
  window._dashInited = true;
  startClock();
  activePage = 'dashboard'; // match HTML default active page
  // Restore the collapsed command rail
  if(localStorage.getItem('obsidios_nav_collapsed') === 'true') {
    document.querySelector('.shell').classList.add('collapsed');
    const navToggle = document.querySelector('.rail-toggle');
    if (navToggle) navToggle.setAttribute('aria-expanded', 'false');
  }
  // Restore Zen mode
  if(localStorage.getItem('obsidios_zen') === 'true') {
    document.querySelector('.shell').classList.add('zen');
  }
  // Restore Night Vision
  if(localStorage.getItem('obsidios_nv') === 'true') {
    document.querySelector('.shell').classList.add('nv');
  }
  // A deep link wins over the last page visited in this browser.
  const hasHash = !!parseRoute((location.hash || '').replace(/^#/, ''));
  const savedPage = hasHash ? null : localStorage.getItem('obsidios_page');
  if (hasHash) {
    safeTimeout(() => applyRoute(), 500, 'global');
  } else if (savedPage && savedPage !== 'dashboard') {
    // Show last page after initial dashboard setup is complete
    safeTimeout(() => gotoPage(savedPage), 500, 'global');
  }
  updateStats();
  loadShield();
  loadShieldWidget();
  loadOSINT();
  loadAIBrief();
  loadContext();
  loadCVEs();
  loadHosts();
  loadSentinelAlerts();
  // These three feed sidebar badges; leaving them lazy made the rail show
  // 0 until the operator opened the page, which read as "nothing to fix".
  loadForge();
  loadAttackVectors();
  loadRemediation();
  tickSession();
  safeInterval(tickSession, 1000, 'global');
  safeInterval(loadContext, 30000, 'global');
  safeTimeout(() => { drawSpk(); drawAct(); }, 300, 'dashboard');
  safeTimeout(renderOverview, 900, 'dashboard');
    safeInterval(updateStats, 5000, 'dashboard');
    safeInterval(loadShield, 10000, 'dashboard');
    safeInterval(loadShieldWidget, 30000, 'dashboard');
    safeInterval(loadOSINT, 30000, 'dashboard');
    safeInterval(fetchGraph, 30000, 'dashboard');
    safeInterval(pollNetworkStats, 1000, 'dashboard');
  addLog('info', 'Command center online — engine ready');
  // Init 3D first, then fetch graph data after renderer is ready
  if(!scene) {
    safeTimeout(() => { init3D(); fetchGraph(); loadPortCache(); }, 200, 'dashboard');
  }
}

/* ── CLEANUP ON UNLOAD ── */
window.addEventListener('beforeunload', () => {
  cleanupPage();
  cleanup3D();
  // Close socket connection
  if (socket) {
    socket.disconnect();
  }
  // Clear all intervals and timeouts
  intervals.forEach(i => clearInterval(i.handle));
  timeouts.forEach(t => clearTimeout(t.handle));
});

window.onload = checkLogin;

// Handle bfcache restoration — re-check scan state on back/forward
window.addEventListener('pageshow', function(e) {
  if (e.persisted && jwtToken) {
    initDashboard();
  }
});

function exportPDF(btn) {
  btn = btn || event?.target?.closest('button');
  if (!btn) return;
  btn.innerHTML = 'Generating...';
  btn.disabled = true;
  fetch('/api/v2/export/pdf', {headers: authHeader()})
    .then(r => {
      if (!r.ok) throw new Error('Export failed');
      return r.blob();
    })
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'obsidios_report.pdf';
      document.body.appendChild(a); a.click();
      a.remove(); URL.revokeObjectURL(url);
      btn.innerHTML = '<svg width="11" height="11" viewBox="0 0 11 11" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M2 7.5v1.5a1 1 0 0 0 1 1h5a1 1 0 0 0 1-1V7.5"/><path d="M5.5 7V1.5"/><path d="M3 4.5l2.5 2.5L8 4.5"/></svg> Download PDF';
      btn.disabled = false;
    })
    .catch(e => {
      btn.innerHTML = 'Error';
      btn.disabled = false;
      setTimeout(() => { btn.innerHTML = '<svg width="11" height="11" viewBox="0 0 11 11" fill="none" stroke="currentColor" stroke-width="1.2"><path d="M2 7.5v1.5a1 1 0 0 0 1 1h5a1 1 0 0 0 1-1V7.5"/><path d="M5.5 7V1.5"/><path d="M3 4.5l2.5 2.5L8 4.5"/></svg> Download PDF'; }, 2000);
    });
}

/* ── CLIPBOARD ── */
function legacyCopy(value) {
  const ta = document.createElement('textarea');
  ta.value = value;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:fixed;top:-1000px;left:-1000px;opacity:0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  ta.remove();
  return ok;
}

async function copyText(text, label) {
  const value = String(text === null || text === undefined ? '' : text);
  if (!value) return;
  let ok = false;
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value);
      ok = true;
    } catch (e) {
      // Permission denied or no transient activation — try the legacy path.
      ok = legacyCopy(value);
    }
  } else {
    ok = legacyCopy(value);
  }
  if (ok) showToast((label || 'Copied') + ': ' + value, 'info');
  else showToast('Copy blocked by the browser — select the value manually', 'error');
}

function copyButton(value, label, title) {
  const svg = '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="1" y="1" width="7" height="7" rx="1"/><path d="M3.5 10.5h6a1 1 0 0 0 1-1v-6"/></svg>';
  return '<button class="icon-btn" style="width:17px;height:17px" data-action="copy" '
    + 'data-copy="' + esc(value) + '" data-copy-label="' + esc(label) + '" '
    + 'title="' + esc(title || ('Copy ' + label)) + '" aria-label="' + esc(title || ('Copy ' + label)) + '">' + svg + '</button>';
}

/* ── HOST DRILL-DOWN DRAWER ── */
let _drawerFocus = null;

function drawerOpen() {
  const d = document.getElementById('host-drawer');
  return !!(d && !d.hidden);
}

async function openHostDrawer(ip, opts) {
  const options = opts || {};
  const target = String(ip || '').trim();
  if (!target) return;
  if (!options.quiet && drawerIp === target && drawerOpen()) return;
  drawerIp = target;
  const drawer = document.getElementById('host-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (!drawer || !backdrop) return;
  if (!drawerOpen()) {
    _drawerFocus = document.activeElement;
    drawer.hidden = false;
    backdrop.hidden = false;
    requestAnimationFrame(() => {
      drawer.classList.add('show');
      backdrop.classList.add('show');
    });
    const closeBtn = document.getElementById('drawer-close');
    if (closeBtn) closeBtn.focus();
  }
  setText('drawer-title', target);
  setText('drawer-sub', 'Loading host details…');
  const body = document.getElementById('drawer-body');
  if (body && !options.quiet) body.innerHTML = '<div class="dr-empty">Loading host details…</div>';
  if (options.sync !== false) setRoute({k: 'host', v: target}, 'push');
  try {
    const res = await fetch('/api/v2/details/host?ip=' + encodeURIComponent(target), {headers: authHeader()});
    if (drawerIp !== target) return;
    if (!res.ok) {
      const msg = res.status === 404 ? 'Host not found in the active inventory'
        : res.status === 400 ? 'Not a valid IP address'
        : 'Could not load host (HTTP ' + res.status + ')';
      setText('drawer-sub', 'Unavailable');
      if (body) body.innerHTML = '<div class="dr-empty">' + esc(msg) + '</div>';
      return;
    }
    const d = await res.json();
    if (drawerIp !== target) return;
    renderHostDrawer(d);
  } catch (e) {
    if (e.name === 'AbortError' || drawerIp !== target) return;
    setText('drawer-sub', 'Unavailable');
    if (body) body.innerHTML = '<div class="dr-empty">Network error while loading host</div>';
  }
}

function closeHostDrawer(opts) {
  const options = opts || {};
  const drawer = document.getElementById('host-drawer');
  const backdrop = document.getElementById('drawer-backdrop');
  if (!drawer || drawer.hidden) return;
  drawer.classList.remove('show');
  if (backdrop) backdrop.classList.remove('show');
  const finish = () => {
    drawer.hidden = true;
    if (backdrop) backdrop.hidden = true;
  };
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) finish(); else setTimeout(finish, 200);
  drawerIp = '';
  if (_drawerFocus && _drawerFocus.focus) {
    try { _drawerFocus.focus(); } catch (e) { /* detached */ }
  }
  _drawerFocus = null;
  if (options.sync !== false) setRoute({k: 'page', v: activePage || 'dashboard'}, 'replace');
}

function drSection(title, count, inner, emptyText) {
  const has = inner && inner.trim().length > 0;
  return '<div class="dr-sec"><div class="dr-sec-h">' + esc(title)
    + (count ? ' <span class="dr-n">' + esc(count) + '</span>' : '')
    + '</div>' + (has ? inner : '<div class="dr-empty">' + esc(emptyText || 'None') + '</div>') + '</div>';
}

function drKV(key, value, copyKind) {
  const v = value === null || value === undefined || value === '' ? '—' : value;
  const copy = copyKind ? ' ' + copyButton(value, copyKind) : '';
  return '<div class="dr-kv"><span>' + esc(key) + '</span><span title="' + esc(v) + '">' + esc(v) + copy + '</span></div>';
}

function renderHostDrawer(d) {
  const h = d.host || {};
  const ports = d.ports || [];
  const cves = d.cves || [];
  const alerts = d.alerts || [];
  const blocks = d.blocks || [];
  const body = document.getElementById('drawer-body');
  if (!body) return;

  setText('drawer-sub', [h.hostname, h.os_name, h.vendor].filter(Boolean).join(' · ') || 'No fingerprint data');

  const overview = '<div class="dr-grid">'
    + drKV('Hostname', h.hostname)
    + drKV('MAC', h.mac, 'MAC')
    + drKV('OS', h.os_name)
    + drKV('Vendor', h.vendor)
    + drKV('Risk', h.risk_score === null || h.risk_score === undefined ? '—' : Number(h.risk_score).toFixed(1))
    + drKV('Asset value', h.asset_value)
    + drKV('First seen', relTime(h.first_seen))
    + drKV('Last seen', relTime(h.last_seen))
    + '</div>';

  const portsHtml = ports.map(p => {
    const open = String(p.state || '').toLowerCase() === 'open';
    return '<div class="dr-row ' + (open ? 'ok' : 'warn') + '">'
      + '<span class="dr-grow" style="color:var(--t1);flex:0 0 96px">' + esc(p.port) + '/' + esc(p.protocol || 'tcp') + '</span>'
      + '<span class="dr-grow">' + esc(p.service || 'unknown') + '</span>'
      + '<span class="dr-grow" style="flex:0 0 auto;color:var(--t3)">' + esc(p.product || '') + ' ' + esc(p.version || '') + '</span>'
      + '<span class="badge ' + (open ? 'badge-low' : 'badge-medium') + '">' + esc(String(p.state || '').toUpperCase()) + '</span>'
      + '</div>';
  }).join('');

  const cvesHtml = cves.map(c => {
    const sev = String(c.severity || 'INFO').toUpperCase();
    const cls = sev === 'CRITICAL' ? 'badge-critical' : sev === 'HIGH' ? 'badge-high' : sev === 'MEDIUM' ? 'badge-medium' : 'badge-low';
    const rowCls = sev === 'CRITICAL' || sev === 'HIGH' ? 'crit' : 'warn';
    return '<div class="dr-row ' + rowCls + '">'
      + '<span class="dr-grow" style="color:var(--t1);flex:0 0 132px">' + esc(c.cve_id) + ' ' + copyButton(c.cve_id, 'CVE') + '</span>'
      + '<span class="badge ' + cls + '">' + esc(sev) + '</span>'
      + '<span class="dr-grow" style="color:var(--t3)">' + esc(c.port) + '/' + esc(c.service || '') + '</span>'
      + '<span class="dr-grow" style="flex:0 0 auto;color:var(--t3)">' + esc(c.verified_status || 'UNVERIFIED') + '</span>'
      + '</div>';
  }).join('');

  const alertsHtml = alerts.map(a => {
    const sev = Number(a.severity) || 3;
    const rowCls = sev <= 1 ? 'crit' : sev <= 2 ? 'warn' : '';
    const ts = a.alerted_at ? relTime(a.alerted_at) : '—';
    const ack = a.acknowledged
      ? '<span class="badge badge-low">ACKED</span>'
      : (currentUser.role === 'operator'
        ? '<button class="ack-btn" data-action="ackAlert" data-id="' + safeId(a.id) + '">Ack</button>'
        : '<span style="color:var(--amber);font-size:9px">open</span>');
    return '<div class="dr-row ' + rowCls + '">'
      + '<span class="dr-grow" style="flex:0 0 62px;color:var(--t3)">' + esc(ts) + '</span>'
      + '<span class="dr-grow" style="flex:0 0 84px;color:var(--amber)">' + esc(a.src_ip) + '</span>'
      + '<span class="dr-grow">' + esc(a.message || ('SID ' + a.rule_sid)) + '</span>'
      + ack
      + '</div>';
  }).join('');

  const blocksHtml = blocks.map(b => {
    const active = !!b.is_active;
    const revert = active && currentUser.role === 'operator'
      ? '<button class="btn btn-secondary" style="font-size:8px;padding:2px 7px" data-action="revertShield" data-id="' + safeId(b.id) + '">Revert</button>'
      : '';
    return '<div class="dr-row ' + (active ? 'warn' : 'ok') + '">'
      + '<span class="dr-grow" style="color:var(--t1);flex:0 0 118px">' + esc(b.action_type) + '</span>'
      + '<span class="dr-grow" style="color:var(--t3)">' + esc(b.justification || b.rule_applied || '') + '</span>'
      + '<span class="badge ' + (active ? 'badge-high' : 'badge-low') + '">' + (active ? 'ACTIVE' : 'REVERTED') + '</span>'
      + revert
      + '</div>';
  }).join('');

  body.innerHTML = drSection('Host', null, overview)
    + drSection('Open ports', ports.length, portsHtml, 'No ports recorded')
    + drSection('Vulnerabilities', cves.length, cvesHtml, 'No mapped CVEs')
    + drSection('Detections', alerts.length, alertsHtml, 'No alerts involving this host')
    + drSection('Shield actions', blocks.length, blocksHtml, 'No blocks on this host');
}

function refreshDrawer() {
  if (drawerIp && drawerOpen()) openHostDrawer(drawerIp, {sync: false, quiet: true});
}

/* ── AUDIT TIMELINE ── */
function tlFlagClass(status) {
  switch (String(status || '').toUpperCase()) {
    case 'DONE': case 'ACKED': case 'DEPLOYED': return 'ok';
    case 'OPEN': case 'FAILED': case 'ERROR': return 'bad';
    case 'RUNNING': case 'STAGED': case 'ACTIVE': return 'warn';
    default: return 'dim';
  }
}

function renderTimeline() {
  const list = document.getElementById('tl-list');
  if (!list) return;
  const kind = document.getElementById('tl-kind')?.value || '';
  const q = (document.getElementById('tl-search')?.value || '').trim().toLowerCase();
  const rows = timelineData.filter(e => {
    if (kind && e.kind !== kind) return false;
    if (!q) return true;
    return [e.kind, e.title, e.detail, e.status, e.host, e.id]
      .map(v => String(v === null || v === undefined ? '' : v).toLowerCase())
      .join(' ').includes(q);
  });
  setText('tl-count', rows.length === timelineData.length ? timelineData.length : rows.length + ' / ' + timelineData.length);
  if (!timelineData.length) {
    list.innerHTML = '<div class="dr-empty" style="padding:18px">No audit events recorded yet</div>';
    return;
  }
  if (!rows.length) {
    list.innerHTML = '<div class="dr-empty" style="padding:18px">No events match the current filters</div>';
    return;
  }
  list.innerHTML = rows.map(e => {
    const ts = Number(e.ts) || 0;
    const abs = ts ? new Date(ts * 1000).toLocaleString() : '—';
    const hostBtn = e.host
      ? '<button class="tl-host" data-action="openHost" data-ip="' + esc(e.host) + '">' + esc(e.host) + '</button>'
      : '';
    const counts = e.counts && (e.counts.hosts || e.counts.ports || e.counts.cves)
      ? ' · ' + (e.counts.hosts || 0) + ' hosts, ' + (e.counts.ports || 0) + ' ports, ' + (e.counts.cves || 0) + ' CVEs'
      : '';
    return '<div class="tl-item k-' + esc(e.kind) + '">'
      + '<div class="tl-time" title="' + esc(abs) + '">' + esc(relTime(ts)) + '<br>' + esc(abs.split(', ').pop() || '') + '</div>'
      + '<div class="tl-kind">' + esc(e.kind) + '</div>'
      + '<div class="tl-main"><div class="tl-title">' + esc(e.title) + '</div>'
      + '<div class="tl-detail">' + esc(e.detail) + esc(counts) + '</div></div>'
      + hostBtn
      + '<span class="tl-flag ' + tlFlagClass(e.status) + '">' + esc(e.status) + '</span>'
      + '</div>';
  }).join('');
}

async function loadTimeline() {
  const list = document.getElementById('tl-list');
  if (!list) return;
  if (!timelineData.length) list.innerHTML = '<div class="dr-empty" style="padding:18px">Loading…</div>';
  try {
    const res = await fetch('/api/v2/audit/timeline?limit=200', {headers: authHeader()});
    if (!res.ok) throw Error('HTTP ' + res.status);
    const d = await res.json();
    timelineData = Array.isArray(d.data) ? d.data : [];
    renderTimeline();
  } catch (e) {
    if (e.name !== 'AbortError') {
      list.innerHTML = '<div class="dr-empty" style="padding:18px;color:var(--red)">Failed to load the audit timeline</div>';
    }
  }
}

/* ── OPERATOR AUDIT LOG ── */
function auditActionOptions(actions) {
  const sel = document.getElementById('audit-action');
  if (!sel || !Array.isArray(actions)) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">All actions</option>' + actions.map(a => {
    const v = String(a || '');
    if (!v) return '';
    return '<option value="' + esc(v) + '">' + esc(v.replace(/_/g, ' ')) + '</option>';
  }).join('');
  sel.value = current && actions.includes(current) ? current : '';
}

function auditTargetHtml(target) {
  if (!target) return '<span class="td-dim">—</span>';
  const t = String(target);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    return '<button class="tl-host" data-action="openHost" data-ip="' + esc(t) + '">' + esc(t) + '</button>';
  }
  return '<span class="td-dim" title="' + esc(t) + '">' + esc(t) + '</span>';
}

function renderAuditLog() {
  const body = document.getElementById('audit-body');
  if (!body) return;
  const action = document.getElementById('audit-action')?.value || '';
  const outcome = document.getElementById('audit-outcome')?.value || '';
  const q = (document.getElementById('audit-search')?.value || '').trim().toLowerCase();
  const rows = auditLogData.filter(e => {
    if (action && e.action !== action) return false;
    if (outcome && (e.outcome || '') !== outcome) return false;
    if (!q) return true;
    return [e.actor, e.role, e.action, e.target, e.detail, e.ip, e.outcome]
      .map(v => String(v === null || v === undefined ? '' : v).toLowerCase())
      .join(' ').includes(q);
  });
  setText('audit-count', rows.length === auditLogData.length
    ? auditLogData.length
    : rows.length + ' / ' + auditLogData.length);
  if (!auditLogData.length) {
    body.innerHTML = '<tr><td colspan="8" class="dr-empty" style="padding:18px">No operator actions recorded yet</td></tr>';
    return;
  }
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="8" class="dr-empty" style="padding:18px">No entries match the current filters</td></tr>';
    return;
  }
  body.innerHTML = rows.map(e => {
    const ts = Number(e.ts) || 0;
    const abs = ts ? new Date(ts * 1000).toLocaleString() : '—';
    const detail = e.detail ? String(e.detail) : '';
    const ok = (e.outcome || 'success') === 'success';
    return '<tr>'
      + '<td class="td-dim" title="' + esc(abs) + '">' + esc(relTime(ts)) + ' · ' + esc(abs.split(', ').pop() || '') + '</td>'
      + '<td class="td-primary">' + esc(e.actor || '—') + '</td>'
      + '<td class="td-dim">' + esc(String(e.role || '—').toUpperCase()) + '</td>'
      + '<td class="td-mono" style="color:var(--t1)">' + esc(e.action || '—') + '</td>'
      + '<td>' + auditTargetHtml(e.target) + '</td>'
      + '<td class="td-dim" style="white-space:normal;max-width:320px;word-break:break-word" title="' + esc(detail) + '">' + (detail ? esc(detail) : '—') + '</td>'
      + '<td class="td-dim">' + esc(e.ip || '—') + '</td>'
      + '<td><span class="tl-flag ' + (ok ? 'ok' : 'bad') + '">' + esc(ok ? 'OK' : 'FAILED') + '</span></td>'
      + '</tr>';
  }).join('');
}

async function loadAuditLog() {
  const body = document.getElementById('audit-body');
  if (!body) return;
  if (!auditLogData.length) {
    body.innerHTML = '<tr><td colspan="8" class="dr-empty" style="padding:18px">Loading…</td></tr>';
  }
  try {
    const res = await fetch('/api/v2/audit/log?limit=500', {headers: authHeader()});
    if (res.status === 403) {
      setText('audit-count', '0');
      body.innerHTML = '<tr><td colspan="8" class="dr-empty" style="padding:18px">The audit log is restricted to operator accounts</td></tr>';
      return;
    }
    if (!res.ok) throw Error('HTTP ' + res.status);
    const d = await res.json();
    auditLogData = Array.isArray(d.data) ? d.data : [];
    auditActionOptions(Array.isArray(d.actions) ? d.actions : []);
    renderAuditLog();
  } catch (e) {
    if (e.name !== 'AbortError') {
      body.innerHTML = '<tr><td colspan="8" class="dr-empty" style="padding:18px;color:var(--red)">Failed to load the audit log</td></tr>';
    }
  }
}

/* ── DEEP LINKS ──
   #page=sentinel · #host=192.168.1.77 · #cve=CVE-2024-3094 · #alert=5
   Page navigation replaces the history entry; opening an investigation target
   pushes one so Back closes the drawer or returns to the filtered list. */
function pageIds() {
  return new Set(Array.from(document.querySelectorAll('.page')).map(p => p.id.replace('page-', '')));
}

function parseRoute(raw) {
  if (!raw) return null;
  const i = raw.indexOf('=');
  if (i < 0) return pageIds().has(raw) ? {k: 'page', v: raw} : null;
  const k = raw.slice(0, i);
  let v = raw.slice(i + 1);
  try { v = decodeURIComponent(v); } catch (e) { /* keep raw */ }
  if (k === 'page') return pageIds().has(v) ? {k: 'page', v} : null;
  if (k === 'host') return v ? {k: 'host', v} : null;
  if (k === 'cve') return v ? {k: 'cve', v} : null;
  if (k === 'alert') return /^\d+$/.test(v) ? {k: 'alert', v: Number(v)} : null;
  return null;
}

function routeRaw(route) {
  return route.k + '=' + encodeURIComponent(route.v);
}

// hashchange and popstate both fire for the same navigation; without this the
// handlers run twice and every deep link fetches its data twice.
let _appliedRoute = null;

function setRoute(route, mode) {
  if (!route) return;
  const url = '#' + routeRaw(route);
  if (location.hash === url) return;
  try {
    if (mode === 'push') history.pushState(null, '', url);
    else history.replaceState(null, '', url);
    _appliedRoute = routeRaw(route);
  } catch (e) { /* history unavailable */ }
}

let _applyingRoute = false;

function applyRoute() {
  if (_applyingRoute) return;
  const raw = (location.hash || '').replace(/^#/, '');
  if (raw === _appliedRoute) return;
  const route = parseRoute(raw);
  if (!route) { _appliedRoute = raw; return; }
  _appliedRoute = raw;
  _applyingRoute = true;
  try {
    // Any non-drawer route means the investigation view must close, otherwise
    // Back from a host drawer onto a CVE/alert link leaves it floating.
    if (route.k !== 'host' && drawerOpen()) closeHostDrawer({sync: false});
    if (route.k === 'page') {
      // Trust the DOM over the variable: they can drift after a logout/login.
      const shown = document.getElementById('page-' + route.v);
      if (activePage !== route.v || !shown || !shown.classList.contains('active')) gotoPage(route.v);
    } else if (route.k === 'host') {
      if (activePage !== 'inventory') gotoPage('inventory');
      openHostDrawer(route.v, {sync: false});
    } else if (route.k === 'cve') {
      focusCVE(route.v);
    } else if (route.k === 'alert') {
      focusAlert(route.v);
    }
  } finally {
    _applyingRoute = false;
  }
}

async function focusCVE(cveId) {
  if (activePage !== 'vulnerabilities') gotoPage('vulnerabilities', {load: false});
  await loadCVEs();
  const search = document.getElementById('cve-search');
  if (search) search.value = cveId;
  renderCVEs();
  const hit = cveData.some(c => String(c.cve_id || '').toUpperCase() === String(cveId).toUpperCase());
  if (!hit) showToast('No open findings for ' + cveId, 'warn');
}

async function focusAlert(alertId) {
  if (activePage !== 'sentinel') gotoPage('sentinel', {load: false});
  await loadSentinelAlerts();
  const filter = document.getElementById('sentinel-filter');
  if (filter) filter.value = 'all';
  renderSentinelAlerts();
  const row = document.querySelector('#sentinel-body tr[data-alert-id="' + safeId(alertId) + '"]');
  if (!row) { showToast('Alert ' + alertId + ' is not in the current window', 'warn'); return; }
  row.classList.add('hl');
  row.scrollIntoView({block: 'center'});
}

/* ── Delegated event dispatch ──────────────────────────────────────────────
   Inline on* attributes are disallowed by CSP (script-src 'self'). Static and
   generated markup carries data-action / data-change instead, so no string is
   ever evaluated as code. */
const CLICK_ACTIONS = {
  siClick: el => siClick(el),
  navPage: el => gotoPage(el.dataset.page),
  toggleNav: () => toggleNav(),
  qfilter: el => {
    queueFilter = el.dataset.arg || 'all';
    document.querySelectorAll('[data-action="qfilter"]').forEach(b => b.classList.toggle('on', b === el));
    renderActionQueue();
  },
  stab: el => stab(el),
  updateStats: () => updateStats(),
  toggleZen: () => toggleZen(),
  toggleScan: () => toggleScan(),
  toggleNV: () => toggleNV(),
  switchAct: el => switchAct(el, el.dataset.arg),
  showModal: el => showModal(el.dataset.arg),
  selectProfileCard: el => selectProfileCard(el.dataset.arg),
  scanAndLoadWireless: () => scanAndLoadWireless(),
  saveToLibrary: () => saveToLibrary(),
  saveRetention: () => saveRetention(),
  reverifyCVEs: (el, ev) => reverifyCVEs(ev),
  pruneData: () => pruneData(),
  omnibarOpen: () => omnibar.open(),
  loadShield: () => loadShield(),
  loadSentinelAlerts: () => loadSentinelAlerts(),
  loadForge: () => loadForge(),
  rewriteForge: () => rewriteForge(),
  loadAttackVectors: () => loadAttackVectors(),
  loadAIBrief: () => loadAIBrief(),
  exportPDF: () => exportPDF(),
  exportCVEs: () => exportCVEs(),
  detectNetwork: () => detectNetwork(),
  closeModal: () => closeModal(),
  applyTarget: () => applyTarget(),
  performLogin: () => performLogin(),
  toggleFeed: el => {
    const feed = document.querySelector('.feed');
    if (feed) feed.classList.toggle('collapsed');
    el.classList.toggle('on');
  },
  useTargetFromRow: el => useTargetFromRow(el.closest('tr')),
  toggleHost: el => toggleHost(el),
  revertShield: el => revertShield(Number(el.dataset.id)),
  toggleDeploy: el => toggleDeploy(Number(el.dataset.id)),
  revertShieldWidget: el => revertShieldWidget(Number(el.dataset.id)),
  dismissCVE: (el, ev) => {
    ev.stopPropagation();
    dismissCVE(ev, Number(el.dataset.portId), Number(el.dataset.cveId));
  },
  toggleAccountMenu: () => toggleAccountMenu(),
  logout: () => logout(),
  ackAlert: el => ackAlert(el),
  ackAllAlerts: () => ackAllAlerts(),
  gotoSentinel: () => gotoSentinel(),
  loadTimeline: () => loadTimeline(),
  loadAuditLog: () => loadAuditLog(),
  openHost: el => openHostDrawer(el.dataset.ip),
  closeDrawer: () => closeHostDrawer(),
  copy: el => copyText(el.dataset.copy, el.dataset.copyLabel),
  copyDrawerIp: () => copyText(drawerIp, 'IP'),
  copyHostLink: () => copyText(
    location.origin + location.pathname + '#host=' + encodeURIComponent(drawerIp), 'Link'
  ),
};

const CHANGE_ACTIONS = {
  loadOSINT: () => loadOSINT(),
  saveSchedule: () => saveSchedule(),
  saveAlertConfig: () => saveAlertConfig(),
  loadCompliance: () => loadCompliance(),
  filterCVEs: () => renderCVEs(),
  filterHosts: () => renderHosts(),
  filterSentinel: () => renderSentinelAlerts(),
  filterTimeline: () => renderTimeline(),
  filterAuditLog: () => renderAuditLog(),
};

const INPUT_ACTIONS = {
  filterCVEs: () => renderCVEs(),
  filterHosts: () => renderHosts(),
  filterTimeline: () => renderTimeline(),
  filterAuditLog: () => renderAuditLog(),
};

document.addEventListener('click', ev => {
  const el = ev.target.closest('[data-action]');
  if (!el) return;
  const fn = CLICK_ACTIONS[el.dataset.action];
  if (!fn) { console.warn('Unknown data-action:', el.dataset.action); return; }
  fn(el, ev);
});

document.addEventListener('change', ev => {
  const el = ev.target.closest('[data-change]');
  if (!el) return;
  const fn = CHANGE_ACTIONS[el.dataset.change];
  if (!fn) { console.warn('Unknown data-change:', el.dataset.change); return; }
  fn(el, ev);
});

document.addEventListener('input', ev => {
  const el = ev.target.closest('[data-input]');
  if (!el) return;
  const fn = INPUT_ACTIONS[el.dataset.input];
  if (!fn) return;
  fn(el, ev);
});
