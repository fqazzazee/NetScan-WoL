/* NetScan-WoL Command Hub — client.
 *
 * Plain ES2020, no framework and no build step. Two rules govern the whole
 * file:
 *
 *  1. Nothing from the network is ever assigned to innerHTML. Hostnames and
 *     vendor strings come from devices on an untrusted segment, and a printer
 *     with a crafted mDNS name should not be able to script this page. Every
 *     dynamic string goes through textContent via the el() helper.
 *  2. Every state-changing request carries the CSRF token from the session.
 */

'use strict';

/* ---------- tiny DOM helpers ---------- */

const $ = (id) => document.getElementById(id);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/** Build an element. Strings in children become text nodes, never markup. */
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

/* ---------- application state ---------- */

const state = {
  csrf: '',
  username: '',
  agents: [],
  hosts: [],
  scanHosts: [],
  // The agent that produced state.scanHosts, so row actions target the right
  // one even after the Scan view's dropdown changes.
  scanAgentID: '',
  view: 'agents',
};

/* ---------- API ---------- */

/** Thrown for any non-2xx response, carrying the server's message. */
class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Accept': 'application/json' },
    credentials: 'same-origin',
  };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (method !== 'GET' && state.csrf) opts.headers['X-NSW-CSRF'] = state.csrf;

  const res = await fetch(path, opts);
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { /* non-JSON error page */ } }

  if (!res.ok) {
    if (res.status === 401 && state.username) { showLogin('Session expired. Sign in again.'); }
    throw new ApiError((data && data.error) || `Request failed (${res.status})`, res.status);
  }
  return data;
}

const GET = (p) => api('GET', p);
const POST = (p, b) => api('POST', p, b);
const PATCH = (p, b) => api('PATCH', p, b);
const DEL = (p) => api('DELETE', p);

/* ---------- toasts ---------- */

function toast(message, kind = '') {
  const node = el('div', { class: `toast ${kind}`.trim(), text: message });
  $('toasts').append(node);
  setTimeout(() => node.remove(), kind === 'error' ? 7000 : 4000);
}

/* ---------- theme ---------- */

const THEMES = ['system', 'light', 'dark'];
const THEME_ICON = { system: '◐', light: '☀', dark: '☾' };

function applyTheme(theme) {
  if (theme === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
  $('theme-icon').textContent = THEME_ICON[theme] || '◐';
}

function initTheme() {
  // A stored choice always wins. With nothing stored the root carries no
  // data-theme attribute, so the CSS falls through to prefers-color-scheme.
  const stored = localStorage.getItem('nsw-theme');
  applyTheme(THEMES.includes(stored) ? stored : 'system');

  $('theme-btn').addEventListener('click', () => {
    const current = localStorage.getItem('nsw-theme') || 'system';
    const next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
    localStorage.setItem('nsw-theme', next);
    applyTheme(next);
    toast(`Theme: ${next === 'system' ? 'match device' : next}`);
  });
}

/* ---------- formatting ---------- */

function timeAgo(iso) {
  if (!iso || iso.startsWith('0001')) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 0) return 'just now';
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function fullTime(iso) {
  if (!iso || iso.startsWith('0001')) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

/* ---------- modal ---------- */

let modalCleanup = null;

function openModal(title, bodyNodes, footNodes) {
  $('modal-title').textContent = title;
  clear($('modal-body'));
  clear($('modal-foot'));
  [].concat(bodyNodes).forEach((n) => n && $('modal-body').append(n));
  [].concat(footNodes || []).forEach((n) => n && $('modal-foot').append(n));
  $('modal').hidden = false;

  const onKey = (e) => { if (e.key === 'Escape') closeModal(); };
  document.addEventListener('keydown', onKey);
  modalCleanup = () => document.removeEventListener('keydown', onKey);

  const firstInput = $('modal-body').querySelector('input, select, textarea, button');
  if (firstInput) firstInput.focus();
}

function closeModal() {
  $('modal').hidden = true;
  if (modalCleanup) { modalCleanup(); modalCleanup = null; }
}

/** A labelled input for use inside a modal. */
function field(id, label, opts = {}) {
  const input = el('input', Object.assign({ id }, opts));
  return { node: el('div', { class: 'field' }, [el('label', { for: id, text: label }), input]), input };
}

/* ---------- navigation ---------- */

const VIEWS = ['agents', 'scan', 'hosts', 'wake', 'history', 'enroll', 'audit', 'settings'];

const LOADERS = {
  agents: loadAgents,
  scan: loadScanView,
  hosts: loadHosts,
  wake: loadWakeView,
  history: loadHistory,
  enroll: loadTokens,
  audit: loadAudit,
  settings: loadSettings,
};

function show(view) {
  if (!VIEWS.includes(view)) view = 'agents';
  state.view = view;

  VIEWS.forEach((v) => { const s = $(`view-${v}`); if (s) s.hidden = v !== view; });
  $$('.nav-item, .tab').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $('sidenav').classList.remove('open');
  $('nav-toggle').setAttribute('aria-expanded', 'false');
  window.scrollTo(0, 0);
  if (location.hash !== `#${view}`) history.replaceState(null, '', `#${view}`);

  const load = LOADERS[view];
  if (load) load().catch((err) => toast(err.message, 'error'));
}

function initNav() {
  // One delegated listener covers the sidebar, the tab bar, the account menu
  // and every in-page "go here" button.
  document.addEventListener('click', (e) => {
    const trigger = e.target.closest('[data-view]');
    if (trigger) { show(trigger.dataset.view); $$('.menu[open]').forEach((m) => m.removeAttribute('open')); }

    const copyBtn = e.target.closest('[data-copy]');
    if (copyBtn) copyText($(copyBtn.dataset.copy).textContent);
  });

  $('nav-toggle').addEventListener('click', () => {
    const nav = $('sidenav');
    const open = nav.classList.toggle('open');
    $('nav-toggle').setAttribute('aria-expanded', String(open));
  });

  $('modal-close').addEventListener('click', closeModal);
  $('modal').addEventListener('click', (e) => { if (e.target === $('modal')) closeModal(); });

  window.addEventListener('hashchange', () => show(location.hash.slice(1)));
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard', 'ok');
  } catch {
    // Clipboard access needs a secure context. A hub reached over plain HTTP
    // by IP will land here, so say something useful rather than failing mute.
    toast('Could not copy automatically — select the text and copy it manually', 'error');
  }
}

/* ---------- authentication ---------- */

function showLogin(message) {
  $('app').hidden = true;
  $('login').hidden = false;
  $('login-error').textContent = message || '';
  state.csrf = '';
  state.username = '';
  $('login-user').focus();
}

function showApp() {
  $('login').hidden = true;
  $('app').hidden = false;
}

async function initAuth() {
  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.disabled = true;
    $('login-error').textContent = '';
    try {
      const res = await POST('/api/v1/auth/login', {
        username: $('login-user').value,
        password: $('login-pass').value,
      });
      state.csrf = res.csrf;
      state.username = res.username;
      $('login-pass').value = '';
      showApp();
      await afterLogin(res.must_change_password);
    } catch (err) {
      $('login-error').textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });

  $('logout-btn').addEventListener('click', async () => {
    try { await POST('/api/v1/auth/logout', {}); } catch { /* signing out anyway */ }
    showLogin('Signed out.');
  });

  $('change-pw-btn').addEventListener('click', () => openPasswordDialog(false));

  // Ask the server whether this browser already holds a session.
  try {
    const me = await GET('/api/v1/auth/me');
    state.csrf = me.csrf;
    state.username = me.username;
    showApp();
    await afterLogin(me.must_change_password);
  } catch {
    showLogin('');
  }
}

async function afterLogin(mustChange) {
  $('menu-user').textContent = state.username;
  try {
    const me = await GET('/api/v1/auth/me');
    if (me.hub_name) { $('hub-name').textContent = me.hub_name; document.title = `${me.hub_name} — Command Hub`; }
    // The server-side default only applies when this browser has no stored
    // preference of its own.
    if (!localStorage.getItem('nsw-theme') && me.default_theme) applyTheme(me.default_theme);
  } catch { /* non-fatal */ }

  show(location.hash.slice(1) || 'agents');
  if (mustChange) openPasswordDialog(true);
}

function openPasswordDialog(forced) {
  const current = field('pw-current', 'Current password', { type: 'password', autocomplete: 'current-password' });
  const next = field('pw-new', 'New password (at least 12 characters)', { type: 'password', autocomplete: 'new-password' });
  const again = field('pw-again', 'Repeat new password', { type: 'password', autocomplete: 'new-password' });
  const error = el('p', { class: 'form-error' });

  const save = el('button', { class: 'btn primary', text: 'Change password' });
  const cancel = forced ? null : el('button', { class: 'btn', text: 'Cancel', onclick: closeModal });

  save.addEventListener('click', async () => {
    error.textContent = '';
    if (next.input.value !== again.input.value) { error.textContent = 'The two new passwords do not match.'; return; }
    save.disabled = true;
    try {
      await POST('/api/v1/auth/password', { current: current.input.value, new: next.input.value });
      closeModal();
      // Changing the password invalidates every session, this one included.
      showLogin('Password changed. Sign in with the new one.');
    } catch (err) {
      error.textContent = err.message;
      save.disabled = false;
    }
  });

  openModal(
    forced ? 'Set a password' : 'Change password',
    [forced ? el('p', { class: 'muted', text: 'This account still uses the password printed at first start. Choose your own before going further.' }) : null,
      current.node, next.node, again.node, error],
    [save, cancel],
  );
}

/* ---------- agents ---------- */

async function loadAgents() {
  const data = await GET('/api/v1/agents');
  state.agents = data.agents || [];

  const list = $('agents-list');
  clear(list);
  $('agents-empty').hidden = state.agents.length > 0;

  for (const agent of state.agents) {
    list.append(agentCard(agent));
  }
  refreshAgentSelects();
}

function agentStatusChip(agent) {
  if (agent.disabled) return el('span', { class: 'chip danger', text: 'disabled' });
  if (agent.connected) return el('span', { class: 'chip ok', text: 'connected' });
  if (agent.online) return el('span', { class: 'chip warn', text: 'recently seen' });
  return el('span', { class: 'chip off', text: 'offline' });
}

function agentCard(agent) {
  const subnets = [];
  for (const ifi of agent.interfaces || []) {
    if (ifi.eligible) subnets.push(...(ifi.subnets || []));
  }

  const meta = el('dl', { class: 'card-meta' }, [
    el('dt', { text: 'Platform' }), el('dd', { text: agent.platform || 'unknown' }),
    el('dt', { text: 'System' }), el('dd', { text: `${agent.os || '?'}/${agent.arch || '?'}` }),
    el('dt', { text: 'Version' }), el('dd', { text: agent.version || '—' }),
    el('dt', { text: 'Networks' }), el('dd', { text: subnets.length ? subnets.join(', ') : 'none detected' }),
    el('dt', { text: 'Last seen' }), el('dd', { text: timeAgo(agent.last_seen) }),
    el('dt', { text: 'From' }), el('dd', { text: agent.remote_addr || '—' }),
  ]);

  const caps = el('div', { class: 'chip-row' },
    (agent.capabilities || []).map((c) => el('span', { class: 'chip', text: c })));

  const actions = el('div', { class: 'card-actions' }, [
    el('button', {
      class: 'btn small', text: 'Scan',
      onclick: () => { show('scan'); $('scan-agent').value = agent.id; onScanAgentChange(); },
    }),
    el('button', {
      class: 'btn small', text: 'Rediscover',
      onclick: async (e) => {
        e.target.disabled = true;
        try {
          await POST(`/api/v1/agents/${agent.id}/discover`, {});
          toast('Network topology refreshed', 'ok');
          await loadAgents();
        } catch (err) { toast(err.message, 'error'); e.target.disabled = false; }
      },
    }),
    el('button', { class: 'btn small', text: 'Rename', onclick: () => renameAgentDialog(agent) }),
    el('button', {
      class: 'btn small', text: agent.disabled ? 'Enable' : 'Disable',
      onclick: async () => {
        try {
          await PATCH(`/api/v1/agents/${agent.id}`, { disabled: !agent.disabled });
          await loadAgents();
        } catch (err) { toast(err.message, 'error'); }
      },
    }),
    el('button', { class: 'btn small danger', text: 'Remove', onclick: () => removeAgentDialog(agent) }),
  ]);

  return el('div', { class: 'card' }, [
    el('div', { class: 'card-head' }, [
      el('div', { class: 'card-title' }, [
        agent.name,
        el('div', { class: 'card-sub', text: agent.hostname || agent.id.slice(0, 12) }),
      ]),
      el('div', { class: 'chip-row' }, [agentStatusChip(agent)]),
    ]),
    meta,
    caps,
    agent.note ? el('p', { class: 'card-sub', text: agent.note }) : null,
    actions,
  ]);
}

function renameAgentDialog(agent) {
  const name = field('agent-name', 'Display name', { value: agent.name, maxlength: 100 });
  const note = field('agent-note', 'Note', { value: agent.note || '', maxlength: 200, placeholder: 'where it lives, what it covers' });
  const save = el('button', { class: 'btn primary', text: 'Save' });
  save.addEventListener('click', async () => {
    try {
      await PATCH(`/api/v1/agents/${agent.id}`, { name: name.input.value, note: note.input.value });
      closeModal();
      await loadAgents();
    } catch (err) { toast(err.message, 'error'); }
  });
  openModal('Rename agent', [name.node, note.node], [save, el('button', { class: 'btn', text: 'Cancel', onclick: closeModal })]);
}

function removeAgentDialog(agent) {
  const confirmBtn = el('button', { class: 'btn danger', text: 'Remove agent' });
  confirmBtn.addEventListener('click', async () => {
    try {
      await DEL(`/api/v1/agents/${agent.id}`);
      closeModal();
      toast(`Removed ${agent.name}`, 'ok');
      await loadAgents();
    } catch (err) { toast(err.message, 'error'); }
  });
  openModal('Remove agent', [
    el('p', { text: `Remove "${agent.name}" from this hub?` }),
    el('p', {
      class: 'muted small',
      text: 'Its certificate stops being accepted immediately. To bring the machine back you will need a new enrollment token.',
    }),
  ], [confirmBtn, el('button', { class: 'btn', text: 'Cancel', onclick: closeModal })]);
}

/** Repopulate every agent dropdown, preserving the current choice. */
function refreshAgentSelects() {
  for (const id of ['scan-agent', 'wake-agent']) {
    const sel = $(id);
    if (!sel) continue;
    const previous = sel.value;
    clear(sel);
    const usable = state.agents.filter((a) => !a.disabled);
    if (usable.length === 0) {
      sel.append(el('option', { value: '', text: 'No agents available' }));
      continue;
    }
    for (const a of usable) {
      sel.append(el('option', {
        value: a.id,
        text: a.connected ? a.name : `${a.name} (offline)`,
        disabled: !a.connected,
      }));
    }
    const stillThere = usable.some((a) => a.id === previous && a.connected);
    sel.value = stillThere ? previous : (usable.find((a) => a.connected) || {}).id || '';
  }
  onScanAgentChange();
}

/* ---------- scan ---------- */

async function loadScanView() {
  if (state.agents.length === 0) await loadAgents();
  else refreshAgentSelects();
}

/** Fill the interface dropdown from the selected agent's known topology. */
function onScanAgentChange() {
  const sel = $('scan-iface');
  if (!sel) return;
  const agent = state.agents.find((a) => a.id === $('scan-agent').value);
  clear(sel);
  sel.append(el('option', { value: '', text: 'All eligible (auto-discover)' }));
  for (const ifi of (agent && agent.interfaces) || []) {
    if (!ifi.eligible) continue;
    const label = ifi.subnets && ifi.subnets.length ? `${ifi.name} — ${ifi.subnets.join(', ')}` : ifi.name;
    sel.append(el('option', { value: ifi.name, text: label }));
  }
}

function initScan() {
  $('scan-agent').addEventListener('change', onScanAgentChange);
  $('agents-refresh').addEventListener('click', () => loadAgents().catch((e) => toast(e.message, 'error')));

  $('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const agentID = $('scan-agent').value;
    if (!agentID) { toast('Select a connected agent first', 'error'); return; }

    const btn = $('scan-run');
    const status = $('scan-status');
    btn.disabled = true;
    status.hidden = false;
    status.className = 'status busy';
    status.textContent = 'Scanning — ARP sweeps take a second per /24, longer with name resolution…';

    try {
      const data = await POST(`/api/v1/agents/${agentID}/scan`, {
        interface: $('scan-iface').value,
        subnet: $('scan-subnet').value.trim(),
        resolve_names: $('scan-names').checked,
      });
      renderScan(data.scan);
      status.className = 'status ok';
      status.textContent = `Found ${data.scan.hosts ? data.scan.hosts.length : 0} hosts.`;
    } catch (err) {
      status.className = 'status error';
      status.textContent = err.message;
      $('scan-results').hidden = true;
    } finally {
      btn.disabled = false;
    }
  });

  $('scan-filter').addEventListener('input', () => renderHostRows($('scan-table'), filterHosts(state.scanHosts, $('scan-filter').value), 'scan', state.scanAgentID));
}

function renderScan(rec) {
  state.scanHosts = rec.hosts || [];
  state.scanAgentID = rec.agent_id || '';
  $('scan-results').hidden = false;
  $('scan-count').textContent = String(state.scanHosts.length);

  const segs = $('scan-segments');
  clear(segs);
  for (const seg of rec.segments || []) {
    segs.append(el('div', { class: 'segment' }, [
      el('strong', { text: seg.interface }),
      el('span', { text: seg.subnet }),
      el('span', { class: `chip ${seg.error ? 'danger' : 'accent'}`, text: seg.method || 'unknown' }),
      el('span', { text: `${seg.host_count} hosts` }),
      seg.error ? el('span', { class: 'chip warn', text: seg.error }) : null,
    ]));
  }
  renderHostRows($('scan-table'), state.scanHosts, 'scan', state.scanAgentID);
}

function filterHosts(hosts, query) {
  const q = query.trim().toLowerCase();
  if (!q) return hosts;
  return hosts.filter((h) => [h.ip, h.mac, h.hostname, h.vendor, h.label]
    .filter(Boolean).some((v) => String(v).toLowerCase().includes(q)));
}

/**
 * Render a list of hosts. `mode` is 'scan' for discovered hosts (offering
 * "Save") or 'saved' for stored ones (offering "Wake" and "Remove").
 *
 * `agentID` is the agent those hosts were discovered by. It has to be passed
 * in rather than read from the Scan view's dropdown: a host list opened from
 * scan history belongs to whichever agent ran that scan, which is often not
 * the one currently selected.
 */
function renderHostRows(container, hosts, mode, agentID) {
  clear(container);
  if (hosts.length === 0) {
    container.append(el('div', { class: 'empty' }, [el('p', { text: 'Nothing to show.' })]));
    return;
  }
  for (const host of hosts) {
    container.append(hostRow(host, mode, agentID));
  }
}

function hostRow(host, mode, agentID) {
  const saved = mode === 'saved';
  const title = saved ? host.label : (host.hostname || host.ip);
  const ip = saved ? (host.last_ip || '—') : host.ip;

  const main = el('div', { class: 'host-main' }, [
    el('div', { class: 'host-name', text: title || '—' }),
    el('div', { class: 'host-mac', text: host.mac }),
    host.vendor ? el('div', { class: 'host-vendor', text: host.vendor }) : null,
  ]);

  const middle = el('div', {}, [
    el('div', { class: 'host-ip', text: ip }),
    saved && host.hostname ? el('div', { class: 'host-vendor', text: host.hostname }) : null,
    !saved && host.rtt_ms ? el('div', { class: 'host-vendor', text: `${host.rtt_ms.toFixed(1)} ms` }) : null,
  ]);

  const actions = el('div', { class: 'host-actions' });
  if (saved) {
    actions.append(
      el('button', { class: 'btn small primary', text: 'Wake', onclick: (e) => wakeSaved(host, e.target) }),
      el('button', { class: 'btn small', text: 'Edit', onclick: () => hostDialog(host) }),
      el('button', { class: 'btn small danger', text: 'Remove', onclick: () => deleteHost(host) }),
    );
  } else {
    actions.append(
      el('button', {
        class: 'btn small', text: 'Save',
        onclick: () => hostDialog({
          mac: host.mac, label: host.hostname || host.ip, last_ip: host.ip,
          hostname: host.hostname, vendor: host.vendor, agent_id: agentID || '',
        }),
      }),
      el('button', {
        class: 'btn small', text: 'Wake',
        onclick: async (e) => {
          if (!agentID) { toast('No agent is associated with this list', 'error'); return; }
          e.target.disabled = true;
          try {
            await POST(`/api/v1/agents/${agentID}/wake`, { mac: host.mac });
            toast(`Magic packet sent to ${host.mac}`, 'ok');
          } catch (err) { toast(err.message, 'error'); }
          e.target.disabled = false;
        },
      }),
    );
  }

  const row = el('div', { class: 'host' }, [main, middle, actions]);

  if (saved) {
    const bits = [];
    if (host.last_seen) bits.push(`seen ${timeAgo(host.last_seen)}`);
    if (host.last_wake) bits.push(`woken ${timeAgo(host.last_wake)}`);
    if (host.status) bits.push(host.status);
    if (bits.length) row.append(el('div', { class: 'host-extra', text: bits.join(' · ') }));
  }
  return row;
}

/* ---------- saved hosts ---------- */

async function loadHosts() {
  const data = await GET('/api/v1/hosts');
  state.hosts = data.hosts || [];
  $('hosts-empty').hidden = state.hosts.length > 0;
  renderHostRows($('hosts-list'), filterHosts(state.hosts, $('hosts-filter').value), 'saved');
}

function initHosts() {
  $('hosts-filter').addEventListener('input', () =>
    renderHostRows($('hosts-list'), filterHosts(state.hosts, $('hosts-filter').value), 'saved'));

  $('hosts-add').addEventListener('click', () => hostDialog({}));

  $('hosts-status').addEventListener('click', async (e) => {
    const agent = state.agents.find((a) => a.connected);
    if (!agent) { toast('No connected agent to probe from', 'error'); return; }
    const targets = state.hosts.filter((h) => h.last_ip).map((h) => ({ ip: h.last_ip, mac: h.mac }));
    if (targets.length === 0) { toast('No saved host has a known address yet — run a scan first', 'error'); return; }

    e.target.disabled = true;
    try {
      const res = await POST(`/api/v1/agents/${agent.id}/status`, { targets });
      const byMAC = new Map();
      for (const t of res.targets || []) byMAC.set((t.mac || '').toLowerCase(), t);
      for (const host of state.hosts) {
        const t = byMAC.get(host.mac.toLowerCase());
        if (!t) { host.status = ''; continue; }
        host.status = t.online
          ? `online via ${t.method}${t.mac_match ? '' : ' — MAC differs, the address may have been reassigned'}`
          : 'offline';
      }
      renderHostRows($('hosts-list'), filterHosts(state.hosts, $('hosts-filter').value), 'saved');
      toast('Status check complete', 'ok');
    } catch (err) { toast(err.message, 'error'); }
    e.target.disabled = false;
  });
}

function hostDialog(host) {
  const mac = field('h-mac', 'MAC address', { value: host.mac || '', placeholder: 'aa:bb:cc:dd:ee:ff', autocapitalize: 'none', spellcheck: 'false' });
  const label = field('h-label', 'Label', { value: host.label || '', maxlength: 80, placeholder: 'living room NAS' });
  const ip = field('h-ip', 'Last known IP', { value: host.last_ip || '', autocapitalize: 'none', spellcheck: 'false' });

  const agentSel = el('select', { id: 'h-agent' }, [el('option', { value: '', text: 'Any connected agent on its subnet' })]);
  for (const a of state.agents) {
    agentSel.append(el('option', { value: a.id, text: a.name, selected: a.id === host.agent_id }));
  }
  const agentField = el('div', { class: 'field' }, [el('label', { for: 'h-agent', text: 'Wake from' }), agentSel]);

  const port = field('h-port', 'WoL port (default 9)', { value: host.wake_port || '', type: 'number', min: 1, max: 65535 });
  const bcast = field('h-bcast', 'Broadcast address (optional)', { value: host.wake_broadcast || '', autocapitalize: 'none', spellcheck: 'false' });
  const note = field('h-note', 'Note', { value: host.note || '', maxlength: 200 });

  const save = el('button', { class: 'btn primary', text: 'Save host' });
  save.addEventListener('click', async () => {
    save.disabled = true;
    try {
      await POST('/api/v1/hosts', {
        mac: mac.input.value,
        label: label.input.value,
        last_ip: ip.input.value,
        hostname: host.hostname || '',
        vendor: host.vendor || '',
        agent_id: agentSel.value,
        wake_port: Number(port.input.value) || 0,
        wake_broadcast: bcast.input.value,
        note: note.input.value,
      });
      closeModal();
      toast('Host saved', 'ok');
      if (state.view === 'hosts') await loadHosts();
    } catch (err) { toast(err.message, 'error'); save.disabled = false; }
  });

  openModal(host.mac ? 'Edit host' : 'Add host',
    [mac.node, label.node, ip.node, agentField, port.node, bcast.node, note.node],
    [save, el('button', { class: 'btn', text: 'Cancel', onclick: closeModal })]);
}

async function wakeSaved(host, btn) {
  btn.disabled = true;
  try {
    const res = await POST(`/api/v1/hosts/${encodeURIComponent(host.mac)}/wake`, {});
    toast(`Magic packet sent via ${res.agent} (${res.wol.sent} packets)`, 'ok');
    await loadHosts();
  } catch (err) {
    toast(err.message, 'error');
    btn.disabled = false;
  }
}

function deleteHost(host) {
  const confirmBtn = el('button', { class: 'btn danger', text: 'Remove' });
  confirmBtn.addEventListener('click', async () => {
    try {
      await DEL(`/api/v1/hosts/${encodeURIComponent(host.mac)}`);
      closeModal();
      await loadHosts();
    } catch (err) { toast(err.message, 'error'); }
  });
  openModal('Remove host', [el('p', { text: `Remove "${host.label}" from saved hosts?` })],
    [confirmBtn, el('button', { class: 'btn', text: 'Cancel', onclick: closeModal })]);
}

/* ---------- wake ---------- */

async function loadWakeView() {
  if (state.agents.length === 0) await loadAgents();
  else refreshAgentSelects();
}

function initWake() {
  $('wake-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const agentID = $('wake-agent').value;
    if (!agentID) { toast('Select a connected agent first', 'error'); return; }

    const status = $('wake-status');
    status.hidden = false;
    status.className = 'status busy';
    status.textContent = 'Sending…';

    try {
      const res = await POST(`/api/v1/agents/${agentID}/wake`, {
        mac: $('wake-mac').value,
        broadcast: $('wake-broadcast').value.trim(),
        port: Number($('wake-port').value) || 0,
        count: Number($('wake-count').value) || 0,
        secure_on: $('wake-secureon').value.trim(),
      });
      status.className = 'status ok';
      status.textContent = `Sent ${res.sent} packets to ${res.destinations.join(', ')}.`;
    } catch (err) {
      status.className = 'status error';
      status.textContent = err.message;
    }
  });
}

/* ---------- history ---------- */

async function loadHistory() {
  const data = await GET('/api/v1/scans');
  const scans = data.scans || [];
  const list = $('history-list');
  clear(list);
  $('history-empty').hidden = scans.length > 0;
  $('history-detail').hidden = true;

  for (const rec of scans) {
    list.append(el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('div', { class: 'card-title' }, [
          rec.agent_name || rec.agent_id.slice(0, 8),
          el('div', { class: 'card-sub', text: fullTime(rec.started_at) }),
        ]),
        el('div', { class: 'chip-row' }, [el('span', { class: 'chip accent', text: `${rec.host_count} hosts` })]),
      ]),
      rec.triggered_by ? el('p', { class: 'card-sub', text: `run by ${rec.triggered_by}` }) : null,
      el('div', { class: 'card-actions' }, [
        el('button', { class: 'btn small', text: 'Open', onclick: () => openScanDetail(rec.id) }),
      ]),
    ]));
  }
}

async function openScanDetail(id) {
  try {
    const rec = await GET(`/api/v1/scans/${encodeURIComponent(id)}`);
    $('history-detail').hidden = false;
    $('history-detail-title').textContent = `${rec.agent_name || 'Scan'} — ${fullTime(rec.started_at)}`;
    // Wake and Save from a history entry must use the agent that ran the scan,
    // not whichever agent happens to be selected in the Scan view.
    renderHostRows($('history-hosts'), rec.hosts || [], 'scan', rec.agent_id);
    $('history-detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) { toast(err.message, 'error'); }
}

function initHistory() {
  $('history-refresh').addEventListener('click', () => loadHistory().catch((e) => toast(e.message, 'error')));
  $('history-close').addEventListener('click', () => { $('history-detail').hidden = true; });
}

/* ---------- enrollment ---------- */

async function loadTokens() {
  const data = await GET('/api/v1/tokens');
  const list = $('token-list');
  clear(list);

  for (const t of data.tokens || []) {
    const spent = t.max_uses > 0 && t.uses >= t.max_uses;
    const expired = t.expires_at && new Date(t.expires_at) < new Date();
    let chip;
    if (t.revoked) chip = el('span', { class: 'chip danger', text: 'revoked' });
    else if (spent) chip = el('span', { class: 'chip off', text: 'used' });
    else if (expired) chip = el('span', { class: 'chip off', text: 'expired' });
    else chip = el('span', { class: 'chip ok', text: 'active' });

    list.append(el('div', { class: 'card' }, [
      el('div', { class: 'card-head' }, [
        el('div', { class: 'card-title' }, [
          t.label || 'unlabelled',
          el('div', { class: 'card-sub', text: `created ${timeAgo(t.created_at)} by ${t.created_by || '—'}` }),
        ]),
        el('div', { class: 'chip-row' }, [chip]),
      ]),
      el('dl', { class: 'card-meta' }, [
        el('dt', { text: 'Uses' }), el('dd', { text: `${t.uses} of ${t.max_uses === 0 ? 'unlimited' : t.max_uses}` }),
        el('dt', { text: 'Expires' }), el('dd', { text: t.expires_at ? fullTime(t.expires_at) : 'never' }),
        el('dt', { text: 'Admitted' }), el('dd', { text: (t.agent_ids || []).length ? `${t.agent_ids.length} agent(s)` : 'none' }),
      ]),
      el('div', { class: 'card-actions' }, [
        el('button', {
          class: 'btn small danger', text: 'Revoke',
          onclick: async () => {
            try { await DEL(`/api/v1/tokens/${t.id}`); await loadTokens(); toast('Token revoked', 'ok'); }
            catch (err) { toast(err.message, 'error'); }
          },
        }),
      ]),
    ]));
  }
}

function initEnroll() {
  $('token-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type=submit]');
    btn.disabled = true;
    try {
      const res = await POST('/api/v1/tokens', {
        label: $('token-label').value.trim(),
        max_uses: Number($('token-uses').value) || 1,
        ttl_minutes: Number($('token-ttl').value) || 60,
      });
      $('token-reveal').hidden = false;
      $('token-secret').textContent = res.secret;
      $('token-cmd').textContent = res.join_command;
      $('token-reveal').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      await loadTokens();
    } catch (err) { toast(err.message, 'error'); }
    btn.disabled = false;
  });
}

/* ---------- audit ---------- */

async function loadAudit() {
  const data = await GET('/api/v1/audit?limit=200');
  const list = $('audit-list');
  clear(list);
  const entries = data.entries || [];
  if (entries.length === 0) {
    list.append(el('div', { class: 'empty' }, [el('p', { text: 'No audit entries yet.' })]));
    return;
  }
  for (const e of entries) {
    const parts = [e.actor, e.action];
    if (e.target) parts.push(`→ ${e.target}`);
    list.append(el('div', { class: `audit-row ${e.ok ? 'ok' : 'fail'}` }, [
      el('span', { class: 'audit-when', text: fullTime(e.at) }),
      el('span', { class: 'audit-what' }, [
        el('strong', { text: parts.join(' ') }),
        e.detail ? el('div', { class: 'muted small', text: e.detail }) : null,
        e.remote ? el('div', { class: 'muted small', text: `from ${e.remote}` }) : null,
      ]),
    ]));
  }
}

function initAudit() {
  $('audit-refresh').addEventListener('click', () => loadAudit().catch((e) => toast(e.message, 'error')));
}

/* ---------- settings ---------- */

async function loadSettings() {
  const s = await GET('/api/v1/settings');
  $('set-name').value = s.hub_name || '';
  $('set-theme').value = s.default_theme || 'system';
  $('set-timeout').value = s.scan_timeout_seconds || 60;
  $('set-history').value = s.history_limit || 50;
  $('set-window').value = s.agent_online_window_seconds || 90;
  $('set-names').checked = !!s.resolve_names;
}

function initSettings() {
  $('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const status = $('settings-status');
    try {
      const s = await api('PUT', '/api/v1/settings', {
        hub_name: $('set-name').value.trim(),
        default_theme: $('set-theme').value,
        scan_timeout_seconds: Number($('set-timeout').value),
        history_limit: Number($('set-history').value),
        agent_online_window_seconds: Number($('set-window').value),
        resolve_names: $('set-names').checked,
      });
      $('hub-name').textContent = s.hub_name;
      document.title = `${s.hub_name} — Command Hub`;
      status.hidden = false;
      status.className = 'status ok';
      status.textContent = 'Settings saved.';
    } catch (err) {
      status.hidden = false;
      status.className = 'status error';
      status.textContent = err.message;
    }
  });
}

/* ---------- boot ---------- */

function main() {
  initTheme();
  initNav();
  initScan();
  initHosts();
  initWake();
  initHistory();
  initEnroll();
  initAudit();
  initSettings();
  initAuth();

  // Keep the agent list fresh so connect/disconnect shows up without a manual
  // refresh, but only while that view is actually on screen.
  setInterval(() => {
    if (!$('app').hidden && state.view === 'agents') {
      loadAgents().catch(() => { /* transient; the next tick will retry */ });
    }
  }, 15000);
}

document.addEventListener('DOMContentLoaded', main);
