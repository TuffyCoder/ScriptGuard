/**
 * ScriptGuard - popup logic.
 *
 * Talks to two places:
 *   - the content script in the active tab (via tabs.sendMessage) to list
 *     the scripts of the current page and to add/delete page-scoped rules,
 *   - browser.storage / the background page for the global mode, global
 *     whitelist, regex rules, privacy shields and export/import.
 *
 * Everything is promise-based `browser.*` (Firefox MV2).
 */

'use strict';

/* ---------------------------------------------------------------------
 * Mode metadata shown in the selector
 * ------------------------------------------------------------------- */

const MODE_HINTS = {
  OFF: 'No deletion, no scanning, no firewall. Good for debugging.',
  BASIC: 'Remembered rules + your regex rules, plus the ad & tracker firewall and tracking-URL stripping.',
  PRO: 'Strong and usable: heuristics, trackers, ALL third-party scripts, ad firewall, spoofed fingerprints, cross-site channels blocked.',
  MAXIMUM: 'Nuclear: deletes EVERY script and strips eval, cookies, WebRTC, WebGPU, service workers, geolocation, camera, popups and all ad requests.'
};

const VALID_MODES = ['OFF', 'BASIC', 'PRO', 'MAXIMUM'];

const APP_VERSION = (function () {
  try { return browser.runtime.getManifest().version; }
  catch (e) { return '?'; }
})();

const FIREWALL_DEFAULTS = {
  adBlockMode: 'armed', stripTracking: true, gpc: true, autoWipe: false
};

/* ---------------------------------------------------------------------
 * State
 * ------------------------------------------------------------------- */

let currentTab = null;    // active tab (tabs.query)
let pageDomain = '';      // hostname of the active tab
let lastScripts = [];     // last script list from the content script
let lastCounters = { fingerprint: 0, webrtc: 0, blob: 0, eval: 0, popup: 0, channel: 0, privacy: 0, ad: 0 };
let lastReportText = '';

/* ---------------------------------------------------------------------
 * Boot
 * ------------------------------------------------------------------- */

init();

async function init() {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    currentTab = tabs[0] || null;
  } catch (e) {
    currentTab = null;
  }
  pageDomain = domainOfTab(currentTab);

  document.getElementById('ver').textContent = 'v' + APP_VERSION;
  document.getElementById('domain').textContent = pageDomain || '(this page)';
  renderMode();            // async fill
  loadReport();            // async fill
  loadNetStats();          // async fill
  renderGlobalWhitelist();
  renderSiteWhitelist();
  renderRegex();
  renderFirewall();
  renderShields();
  wireStaticControls();
  wireFirewallControls();
  restoreTrustToggle();
}

/* ---------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------- */

function domainOfTab(tab) {
  try {
    const url = new URL(tab && tab.url ? tab.url : '');
    if (url.protocol === 'http:' || url.protocol === 'https:') return url.hostname;
    return '';
  } catch (e) {
    return '';
  }
}

/** Same "last two labels" base-domain rule the content script uses. */
function baseDomain(host) {
  const parts = (host || '').split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function toast(text) {
  const el = document.getElementById('toast');
  el.textContent = text;
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), 2200);
}

function sendToContent(message) {
  if (!currentTab) return Promise.reject(new Error('no tab'));
  return browser.tabs.sendMessage(currentTab.id, message, { frameId: 0 });
}

/* ---------------------------------------------------------------------
 * Privacy mode selector
 * ------------------------------------------------------------------- */

async function renderMode() {
  let mode = 'BASIC';
  try {
    const res = await browser.storage.local.get('mode');
    if (res.mode && VALID_MODES.indexOf(res.mode) !== -1) mode = res.mode;
  } catch (e) { /* keep default */ }

  const chip = document.getElementById('modeChip');
  chip.textContent = mode;
  chip.className = 'mode-chip m-' + mode;
  document.getElementById('modeHint').textContent = MODE_HINTS[mode] || '';

  for (const btn of document.querySelectorAll('.mode-btn')) {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  }

  // Public IP section: VPN is the only real IP mask - recommend it
  // whenever the heavy modes are on.
  document.getElementById('vpnBadge').hidden = !(mode === 'PRO' || mode === 'MAXIMUM');

  renderShields();
}

for (const btn of document.querySelectorAll('.mode-btn')) {
  btn.addEventListener('click', async () => {
    const mode = btn.dataset.mode;
    await browser.storage.local.set({ mode: mode });
    renderMode();
    // Content scripts pick this up live via storage.onChanged.
  });
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.mode) renderMode();
  if (changes.stats) renderSiteStat();
  if (changes.globalWhitelist) renderGlobalWhitelist();
  if (changes.regexRules) renderRegex();
  if (changes.shields) renderShields();
  if (changes.firewall) { renderFirewall(); loadNetStats(); }
});

/* ---------------------------------------------------------------------
 * Page report (list of scripts + counters)
 * ------------------------------------------------------------------- */

async function loadReport() {
  const listEl = document.getElementById('scriptList');
  const emptyEl = document.getElementById('emptyMsg');
  listEl.textContent = '';
  lastScripts = [];

  if (!pageDomain) {
    emptyEl.hidden = false;
    emptyEl.textContent = 'ScriptGuard only works on http(s) pages.';
    document.getElementById('statDeleted').textContent = '0';
    document.getElementById('statSite').textContent = '0';
    document.getElementById('statFp').textContent = '0';
    return;
  }

  let res = null;
  try {
    res = await sendToContent({ type: 'sb:getReport' });
  } catch (e) {
    // Retry once without frameId (older option handling).
    try {
      res = await browser.tabs.sendMessage(currentTab.id, { type: 'sb:getReport' });
    } catch (e2) {
      res = null;
    }
  }

  if (!res || !res.ok) {
    emptyEl.hidden = false;
    emptyEl.textContent = 'No data yet. Reload the page after installing or updating.';
    renderSiteStat();
    return;
  }

  emptyEl.hidden = true;
  document.getElementById('statDeleted').textContent = String(res.report.deleted.length);
  if (res.report.counters) {
    lastCounters = Object.assign({}, lastCounters, res.report.counters);
    document.getElementById('statFp').textContent = String(res.report.counters.fingerprint || 0);
    document.getElementById('fpCount').textContent = String(res.report.counters.fingerprint || 0);
    document.getElementById('privacyCount').textContent =
      String((res.report.counters.privacy || 0));
    document.getElementById('adCount').textContent =
      String((res.report.counters.ad || 0) + (res.report.counters.popup || 0));
  }
  renderShields(res.report);
  renderSiteStat();

  lastScripts = Array.isArray(res.scripts) ? res.scripts : [];
  if (lastScripts.length === 0) {
    emptyEl.hidden = false;
    emptyEl.textContent = 'No scripts found on this page.';
    return;
  }

  for (const item of lastScripts) {
    listEl.appendChild(buildScriptRow(item));
  }
}

function renderSiteStat() {
  browser.storage.local.get('stats').then((res) => {
    const stats = res.stats || {};
    // Try base domain, then any parent key that matches.
    let total = 0;
    const host = pageDomain;
    for (const key of Object.keys(stats)) {
      if (key === host || host.endsWith('.' + key)) {
        total += stats[key] || 0;
        if (key === host) break;
      }
    }
    document.getElementById('statSite').textContent = String(total);
  }).catch(() => { /* ignore */ });
}

const STATUS_DOT = { blocked: 'blocked', pending: 'pending', executed: 'executed', whitelisted: 'whitelisted' };
const STATUS_TEXT = {
  blocked: 'deleted before execution',
  pending: 'loaded, not run yet',
  executed: 'already ran',
  whitelisted: 'always allowed'
};

function buildScriptRow(item) {
  const row = document.createElement('div');
  row.className = 'script-item';
  row.setAttribute('role', 'listitem');

  const row1 = document.createElement('div');
  row1.className = 'row1';

  const dot = document.createElement('span');
  dot.className = 'dot ' + (STATUS_DOT[item.status] || 'executed');
  dot.title = STATUS_TEXT[item.status] || item.status;

  const name = document.createElement('span');
  name.className = 's-name';
  name.textContent = item.name || item.pattern;
  name.title = item.name || item.pattern;

  const type = document.createElement('span');
  type.className = 's-type';
  type.textContent = item.type === 'inline' ? 'INLINE'
    : item.type === 'ad' ? 'AD' : 'EXT';

  row1.appendChild(dot);
  row1.appendChild(name);
  row1.appendChild(type);
  row.appendChild(row1);

  if (item.reason) {
    const reason = document.createElement('p');
    reason.className = 's-reason';
    reason.textContent = item.reason;
    row.appendChild(reason);
  }

  if (Array.isArray(item.heuristics) && item.heuristics.length > 0) {
    const hint = document.createElement('p');
    hint.className = 's-hint';
    hint.textContent = 'heuristic: ' + item.heuristics.join(' + ');
    hint.title = 'Suspicious signals detected. Heuristics never auto-delete in BASIC.';
    row.appendChild(hint);
  }

  const actions = document.createElement('div');
  actions.className = 's-actions';

  if (item.status === 'blocked') {
    if (item.reason === 'remembered rule' || item.reason === 'heuristic rule') {
      const unblock = document.createElement('button');
      unblock.className = 'small';
      unblock.textContent = 'Remove rule';
      unblock.addEventListener('click', () => removeRule(item.pattern));
      actions.appendChild(unblock);
    }
    actions.appendChild(alwaysAllow(item));
  } else {
    const del = document.createElement('button');
    del.className = 'small primary';
    del.textContent = 'Delete & Remember';
    del.addEventListener('click', () => rememberScript(item));
    actions.appendChild(del);
    actions.appendChild(alwaysAllow(item));
  }

  if (actions.childNodes.length > 0) row.appendChild(actions);
  return row;
}

function alwaysAllow(item) {
  const b = document.createElement('button');
  b.className = 'small';
  b.textContent = item.status === 'whitelisted' ? 'Remove whitelist' : 'Always allow';
  b.addEventListener('click', async () => {
    if (item.status === 'whitelisted') {
      await sendToContent({ type: 'sb:removeWhitelist', pattern: item.pattern });
      toast('Whitelist entry removed. Reload to re-evaluate.');
    } else {
      await sendToContent({
        type: 'sb:whitelist',
        patterns: [{ pattern: item.pattern, label: item.name }]
      });
      toast('Always allowed on this site. Applies on next load.');
    }
    renderSiteWhitelist();
    loadReport();
  });
  return b;
}

/* ---------------------------------------------------------------------
 * Learning actions ("Delete & Remember" / "Remove rule")
 * ------------------------------------------------------------------- */

async function rememberScript(item) {
  try {
    await sendToContent({
      type: 'sb:remember',
      patterns: [{ pattern: item.pattern, label: item.name }]
    });
    toast('Remembered. Deleted now if it had not run yet.');
  } catch (e) {
    toast('Could not reach the page. Reload and try again.');
  }
  loadReport();
}

async function removeRule(pattern) {
  try {
    await sendToContent({ type: 'sb:removeRule', pattern: pattern });
    toast('Rule removed. Reload the page to run it again.');
  } catch (e) {
    toast('Could not reach the page.');
  }
  loadReport();
}

/* ---------------------------------------------------------------------
 * Global whitelist (storage.local: globalWhitelist: string[])
 * ------------------------------------------------------------------- */

function makeChip(pattern, onRemove) {
  const chip = document.createElement('span');
  chip.className = 'chip';
  const t = document.createElement('span');
  t.className = 't';
  t.textContent = pattern;
  t.title = pattern;
  const x = document.createElement('button');
  x.textContent = '\u00d7';
  x.setAttribute('aria-label', 'Remove ' + pattern);
  x.addEventListener('click', onRemove);
  chip.appendChild(t);
  chip.appendChild(x);
  return chip;
}

async function renderGlobalWhitelist() {
  const box = document.getElementById('globalWhitelistChips');
  box.textContent = '';
  let list = [];
  try {
    const res = await browser.storage.local.get('globalWhitelist');
    list = Array.isArray(res.globalWhitelist) ? res.globalWhitelist : [];
  } catch (e) { /* ignore */ }

  if (list.length === 0) {
    const p = document.createElement('p');
    p.className = 'hint-line';
    p.textContent = 'No global patterns yet.';
    box.appendChild(p);
    return;
  }
  for (const pattern of list) {
    box.appendChild(makeChip(pattern, async () => {
      const cur = await browser.storage.local.get('globalWhitelist');
      const next = (cur.globalWhitelist || []).filter((p) => p !== pattern);
      await browser.storage.local.set({ globalWhitelist: next });
      toast('Removed from global whitelist.');
      renderGlobalWhitelist();
    }));
  }
}

async function addGlobalWhitelist() {
  const input = document.getElementById('globalAdd');
  const value = input.value.trim();
  if (!value) return;
  try {
    const cur = await browser.storage.local.get('globalWhitelist');
    const list = Array.isArray(cur.globalWhitelist) ? cur.globalWhitelist.slice() : [];
    if (list.indexOf(value) === -1) list.push(value);
    await browser.storage.local.set({ globalWhitelist: list });
    toast('Added to global whitelist (BASIC + PRO).');
    input.value = '';
    renderGlobalWhitelist();
  } catch (e) {
    toast('Could not save the pattern.');
  }
}

/* ---------------------------------------------------------------------
 * Per-site whitelist view (storage.local: whitelist[baseDomain]: string[])
 * ------------------------------------------------------------------- */

async function renderSiteWhitelist() {
  const box = document.getElementById('siteWhitelistChips');
  box.textContent = '';
  document.getElementById('siteKeyLabel').textContent = pageDomain ? baseDomain(pageDomain) : 'this site';
  if (!pageDomain) {
    const p = document.createElement('p');
    p.className = 'hint-line';
    p.textContent = 'Open an http(s) page to manage its whitelist.';
    box.appendChild(p);
    return;
  }
  let list = [];
  try {
    const res = await browser.storage.local.get('whitelist');
    const siteKey = baseDomain(pageDomain);
    list = Array.isArray(res.whitelist && res.whitelist[siteKey]) ? res.whitelist[siteKey] : [];
  } catch (e) { /* ignore */ }

  if (list.length === 0) {
    const p = document.createElement('p');
    p.className = 'hint-line';
    p.textContent = 'No patterns for this site yet. Use "Always allow" on a script.';
    box.appendChild(p);
    return;
  }
  for (const pattern of list) {
    box.appendChild(makeChip(pattern, async () => {
      try {
        await sendToContent({ type: 'sb:removeWhitelist', pattern: pattern });
        toast('Removed from site whitelist. Reload to re-evaluate.');
      } catch (e) {
        toast('Could not reach the page.');
      }
      renderSiteWhitelist();
      loadReport();
    }));
  }
}

async function addSiteWhitelist() {
  const input = document.getElementById('siteAdd');
  const value = input.value.trim();
  if (!value || !pageDomain) return;
  try {
    await sendToContent({
      type: 'sb:whitelist',
      patterns: [{ pattern: value, label: '' }]
    });
    toast('Added to ' + baseDomain(pageDomain) + ' whitelist (BASIC + PRO).');
    input.value = '';
    renderSiteWhitelist();
  } catch (e) {
    toast('Could not reach the page. Reload and try again.');
  }
}

/* ---------------------------------------------------------------------
 * Regex rules (storage.local: regexRules: string[] of RegExp sources)
 * ------------------------------------------------------------------- */

async function renderRegex() {
  const box = document.getElementById('regexChips');
  box.textContent = '';
  let list = [];
  try {
    const res = await browser.storage.local.get('regexRules');
    list = Array.isArray(res.regexRules) ? res.regexRules : [];
  } catch (e) { /* ignore */ }

  if (list.length === 0) {
    const p = document.createElement('p');
    p.className = 'hint-line';
    p.textContent = 'No regex rules yet.';
    box.appendChild(p);
    return;
  }
  for (const source of list) {
    box.appendChild(makeChip('/' + source + '/i', async () => {
      const cur = await browser.storage.local.get('regexRules');
      const next = (cur.regexRules || []).filter((p) => p !== source);
      await browser.storage.local.set({ regexRules: next });
      toast('Regex rule removed.');
      renderRegex();
    }));
  }
}

async function addRegex() {
  const input = document.getElementById('regexAdd');
  const value = input.value.trim().replace(/^\/(.*)\/[a-z]*$/i, '$1');
  if (!value) return;
  try {
    new RegExp(value, 'i'); // validation only - the content script compiles it
  } catch (e) {
    toast('Invalid regex: ' + e.message);
    return;
  }
  try {
    const cur = await browser.storage.local.get('regexRules');
    const list = Array.isArray(cur.regexRules) ? cur.regexRules.slice() : [];
    if (list.indexOf(value) === -1) list.push(value);
    await browser.storage.local.set({ regexRules: list });
    toast('Regex rule added. Applies in BASIC and PRO.');
    input.value = '';
    renderRegex();
  } catch (e) {
    toast('Could not save the regex rule.');
  }
}

/* ---------------------------------------------------------------------
 * Ad & tracker firewall (storage.local: firewall {...}, per-tab counts
 * live in the background page - fetched via sb:getNetStats)
 * ------------------------------------------------------------------- */

async function loadNetStats() {
  const stateEl = document.getElementById('fwState');
  const tabEl = document.getElementById('fwTab');
  const siteEl = document.getElementById('fwSite');
  const statNet = document.getElementById('statNet');
  let mode = 'BASIC';
  let fw = FIREWALL_DEFAULTS;
  try {
    const res = await browser.storage.local.get(['mode', 'firewall']);
    if (VALID_MODES.indexOf(res.mode) !== -1) mode = res.mode;
    fw = Object.assign({}, FIREWALL_DEFAULTS, res.firewall || {});
  } catch (e) { /* ignore */ }

  const active = mode !== 'OFF' && fw.adBlockMode !== 'off';

  stateEl.textContent = mode === 'OFF' ? 'FIREWALL IDLE (OFF mode)'
    : fw.adBlockMode === 'off' ? 'FIREWALL OFF'
    : 'FIREWALL ACTIVE';
  stateEl.className = active ? 'on' : 'off';

  let tabBlocked = 0;
  let siteBlocked = 0;
  try {
    const res = await browser.runtime.sendMessage({
      type: 'sb:getNetStats',
      tabId: currentTab ? currentTab.id : null
    });
    if (res && res.ok) {
      tabBlocked = res.tabBlocked || 0;
      siteBlocked = res.siteBlocked || 0;
    }
  } catch (e) { /* background unreachable - ignore */ }

  tabEl.textContent = tabBlocked + ' this tab';
  siteEl.textContent = siteBlocked + ' all time';
  tabEl.className = tabBlocked > 0 ? 'on' : 'off';
  siteEl.className = siteBlocked > 0 ? 'on' : 'off';
  if (statNet) statNet.textContent = String(tabBlocked);
}

async function renderFirewall() {
  let fw = FIREWALL_DEFAULTS;
  try {
    const res = await browser.storage.local.get('firewall');
    fw = Object.assign({}, FIREWALL_DEFAULTS, res.firewall || {});
  } catch (e) { /* ignore */ }
  document.getElementById('adBlockMode').value = fw.adBlockMode;
  document.getElementById('stripTracking').checked = fw.stripTracking !== false;
  document.getElementById('gpcToggle').checked = fw.gpc !== false;
  document.getElementById('autoWipe').checked = fw.autoWipe === true;
}

async function saveFirewall(patch) {
  try {
    const res = await browser.storage.local.get('firewall');
    const merged = Object.assign({}, FIREWALL_DEFAULTS, res.firewall || {}, patch);
    await browser.storage.local.set({ firewall: merged });
  } catch (e) {
    toast('Could not save the firewall setting.');
  }
}

function wireFirewallControls() {
  document.getElementById('adBlockMode').addEventListener('change', (ev) => {
    saveFirewall({ adBlockMode: ev.target.value });
    toast(ev.target.value === 'off'
      ? 'Ad firewall disabled.'
      : 'Ad firewall armed in BASIC, PRO & MAX. Reload pages to apply.');
    loadNetStats();
  });
  document.getElementById('stripTracking').addEventListener('change', (ev) => {
    saveFirewall({ stripTracking: ev.target.checked });
    toast(ev.target.checked ? 'Tracking parameters will be stripped.' : 'Tracking parameters kept.');
  });
  document.getElementById('gpcToggle').addEventListener('change', (ev) => {
    saveFirewall({ gpc: ev.target.checked });
    toast(ev.target.checked ? 'GPC + DNT signals on.' : 'GPC + DNT signals off.');
  });
  document.getElementById('autoWipe').addEventListener('change', (ev) => {
    saveFirewall({ autoWipe: ev.target.checked });
    toast(ev.target.checked
      ? 'Site data is wiped when its tab closes.'
      : 'Auto-wipe disabled.');
  });
}

/* ---------------------------------------------------------------------
 * Privacy shields (WebRTC + Blob kill-switch, fingerprint level)
 * ------------------------------------------------------------------- */

async function renderShields(liveReport) {
  let shields = { webrtc: true, blob: true };
  let mode = 'BASIC';
  try {
    const res = await browser.storage.local.get(['shields', 'mode']);
    if (res.shields && typeof res.shields === 'object') shields = res.shields;
    if (VALID_MODES.indexOf(res.mode) !== -1) mode = res.mode;
  } catch (e) { /* ignore */ }
  if (liveReport && liveReport.shields) {
    shields = { webrtc: !!liveReport.shields.webrtc, blob: !!liveReport.shields.blob };
  }

  const armed = mode === 'PRO' || mode === 'MAXIMUM';
  const webrtcEl = document.getElementById('shieldWebrtc');
  const blobEl = document.getElementById('shieldBlob');
  const fpEl = document.getElementById('fpLevel');
  const btn = document.getElementById('shieldToggle');
  const hint = document.getElementById('shieldHint');

  const stateLabel = (on) => (!on ? 'OFF' : armed ? 'ARMED' : 'IDLE (not ' + mode + ')');
  webrtcEl.textContent = stateLabel(shields.webrtc !== false);
  webrtcEl.className = 'v ' + (shields.webrtc !== false && armed ? 'on' : 'off');
  blobEl.textContent = stateLabel(shields.blob !== false);
  blobEl.className = 'v ' + (shields.blob !== false && armed ? 'on' : 'off');

  const fp = mode === 'MAXIMUM' ? 'DELETED (null)' : mode === 'PRO' ? 'SPOOFED (noise)' : 'off';
  fpEl.textContent = fp;
  fpEl.className = 'v ' + (mode === 'PRO' || mode === 'MAXIMUM' ? 'on' : 'off');

  const chanEl = document.getElementById('channelLevel');
  chanEl.textContent = mode === 'MAXIMUM' ? 'ALL BLOCKED'
    : mode === 'PRO' ? 'CROSS-SITE BLOCKED' : 'off';
  chanEl.className = 'v ' + (mode === 'PRO' || mode === 'MAXIMUM' ? 'on' : 'off');

  const allOn = shields.webrtc !== false && shields.blob !== false;
  btn.disabled = !armed;
  btn.classList.toggle('off', !allOn);
  btn.textContent = allOn ? 'Disable WebRTC & Blob' : 'Enable WebRTC & Blob';
  hint.textContent = !armed
    ? 'Shields are only available in PRO and MAXIMUM modes.'
    : allOn
      ? 'Kill-switch armed: RTCPeerConnection throws, JS blobs and blob: workers are blocked.'
      : 'Kill-switch disarmed - WebRTC and blob scripts run normally.';
}

document.getElementById('shieldToggle').addEventListener('click', async () => {
  try {
    const res = await browser.storage.local.get('shields');
    const cur = res.shields || {};
    const allOn = cur.webrtc !== false && cur.blob !== false;
    const next = { webrtc: !allOn, blob: !allOn };
    await browser.storage.local.set({ shields: next });
    toast(next.webrtc ? 'Privacy shields armed.' : 'Privacy shields disarmed.');
  } catch (e) {
    toast('Could not update the shields.');
  }
  renderShields();
});

/* ---------------------------------------------------------------------
 * Report generation (plain text - copy/paste, never auto-sent)
 * ------------------------------------------------------------------- */

async function generateReport() {
  const lines = [];
  let mode = 'BASIC';
  let shields = { webrtc: true, blob: true };
  let firewall = FIREWALL_DEFAULTS;
  let globalWl = [];
  let regexRules = [];
  let siteWl = [];
  try {
    const res = await browser.storage.local.get(['mode', 'shields', 'firewall', 'globalWhitelist', 'regexRules', 'whitelist']);
    if (VALID_MODES.indexOf(res.mode) !== -1) mode = res.mode;
    if (res.shields && typeof res.shields === 'object') shields = res.shields;
    firewall = Object.assign({}, FIREWALL_DEFAULTS, res.firewall || {});
    globalWl = Array.isArray(res.globalWhitelist) ? res.globalWhitelist : [];
    regexRules = Array.isArray(res.regexRules) ? res.regexRules : [];
    if (pageDomain && res.whitelist && Array.isArray(res.whitelist[baseDomain(pageDomain)])) {
      siteWl = res.whitelist[baseDomain(pageDomain)];
    }
  } catch (e) { /* ignore */ }

  const armed = mode === 'PRO' || mode === 'MAXIMUM';
  let netTab = 0;
  let netSite = 0;
  try {
    const res = await browser.runtime.sendMessage({
      type: 'sb:getNetStats', tabId: currentTab ? currentTab.id : null
    });
    if (res && res.ok) { netTab = res.tabBlocked || 0; netSite = res.siteBlocked || 0; }
  } catch (e) { /* ignore */ }

  lines.push('=== ScriptGuard Report ===');
  lines.push('domain:       ' + (pageDomain || '(this page)'));
  lines.push('mode:         ' + mode);
  lines.push('version:      ' + APP_VERSION);
  lines.push('generated:    ' + new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC');
  lines.push('');
  lines.push('-- deleted before execution (' + lastScripts.filter((s) => s.status === 'blocked').length + ') --');
  for (const s of lastScripts.filter((s) => s.status === 'blocked')) {
    lines.push('  [' + s.reason + '] ' + (s.name || s.pattern));
  }
  lines.push('');
  lines.push('-- whitelisted, this site (' + siteWl.length + ') --');
  for (const p of siteWl) lines.push('  ' + p);
  lines.push('-- global whitelist (' + globalWl.length + ') --');
  for (const p of globalWl) lines.push('  ' + p);
  lines.push('');
  lines.push('-- regex rules (' + regexRules.length + ') --');
  for (const p of regexRules) lines.push('  /' + p + '/i');
  lines.push('');
  const heur = lastScripts.filter((s) => Array.isArray(s.heuristics) && s.heuristics.length > 0);
  lines.push('-- heuristic detections (' + heur.length + ') --');
  for (const s of heur) {
    lines.push('  ' + (s.pattern || s.name));
    lines.push('    signals: ' + s.heuristics.join(', '));
  }
  lines.push('');
  lines.push('-- shields --');
  lines.push('webrtc:        ' + (shields.webrtc !== false ? 'ON' : 'OFF') + (armed ? '' : ' (inactive in ' + mode + ')'));
  lines.push('blob:          ' + (shields.blob !== false ? 'ON' : 'OFF') + (armed ? '' : ' (inactive in ' + mode + ')'));
  lines.push('fingerprint:   ' + (mode === 'MAXIMUM' ? 'deleted (null)' : mode === 'PRO' ? 'spoofed (noise)' : 'off'));
  lines.push('channels:      ' + (mode === 'MAXIMUM' ? 'all blocked' : mode === 'PRO' ? 'cross-site blocked' : 'off'));
  lines.push('probes hit:    fingerprint=' + (lastCounters.fingerprint || 0) +
    ' webrtc=' + (lastCounters.webrtc || 0) + ' blob=' + (lastCounters.blob || 0) +
    ' channels=' + (lastCounters.channel || 0) + ' privacy=' + (lastCounters.privacy || 0) +
    ' popups=' + (lastCounters.popup || 0));
  lines.push('');
  lines.push('-- firewall --');
  lines.push('ad requests:   ' + (firewall.adBlockMode === 'off' ? 'not blocking'
    : 'blocking in BASIC, PRO & MAX'));
  lines.push('blocked here:  ' + netTab + ' this tab, ' + netSite + ' all time, this site');
  lines.push('strip URLs:    ' + (firewall.stripTracking !== false ? 'ON (utm_*, fbclid, gclid, ...)' : 'OFF'));
  lines.push('gpc/dnt:       ' + (firewall.gpc !== false ? 'ON' : 'OFF'));
  lines.push('auto-wipe:     ' + (firewall.autoWipe === true ? 'ON (site data wiped on tab close)' : 'OFF'));
  lines.push('');
  lines.push('-- public IP --');
  lines.push('visible to websites. ScriptGuard blocks browser IP leaks');
  lines.push('(WebRTC, blob workers, fingerprint requests) but CANNOT');
  lines.push('hide or spoof your public IP. Use a VPN or Tor for that.');
  lines.push('');
  lines.push('ScriptGuard v' + APP_VERSION + ' - open source, no telemetry.');
  lines.push('This report was generated locally. Copy/paste it manually.');

  lastReportText = lines.join('\n');
  const out = document.getElementById('reportOut');
  out.textContent = lastReportText;
  out.classList.add('show');
  document.getElementById('copyReport').disabled = false;
}

async function copyReport() {
  if (!lastReportText) return;
  try {
    await navigator.clipboard.writeText(lastReportText);
    toast('Report copied to clipboard.');
  } catch (e) {
    toast('Copy failed - select the text manually.');
  }
}

/* ---------------------------------------------------------------------
 * Trust toggle / site reset / export / import
 * ------------------------------------------------------------------- */

function wireStaticControls() {
  document.getElementById('trustToggle').addEventListener('change', async (ev) => {
    if (!pageDomain) return;
    const res = await browser.storage.local.get('trustedSites');
    const list = Array.isArray(res.trustedSites) ? res.trustedSites.slice() : [];
    const idx = list.indexOf(pageDomain);
    if (ev.target.checked && idx === -1) list.push(pageDomain);
    if (!ev.target.checked && idx !== -1) list.splice(idx, 1);
    await browser.storage.local.set({ trustedSites: list });
    toast(ev.target.checked ? 'Domain trusted. Reload to release held scripts.' : 'Trust removed.');
    loadReport();
  });

  document.getElementById('resetSite').addEventListener('click', async () => {
    try {
      await sendToContent({ type: 'sb:resetSite' });
      toast('Forgot everything about ' + (pageDomain || 'this site') + '.');
    } catch (e) {
      toast('Could not reach the page.');
    }
    restoreTrustToggle();
    renderSiteWhitelist();
    loadReport();
  });

  document.getElementById('exportBtn').addEventListener('click', () => {
    browser.runtime.sendMessage({ type: 'sb:export' });
  });

  document.getElementById('importBtn').addEventListener('click', () => {
    document.getElementById('importFile').click();
  });

  document.getElementById('importFile').addEventListener('change', async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      await browser.runtime.sendMessage({ type: 'sb:import', data: data });
      toast('Rules imported and merged.');
      loadReport();
      renderGlobalWhitelist();
      renderRegex();
    } catch (e) {
      toast('Import failed: not a valid rules file.');
    }
    ev.target.value = '';
  });

  document.getElementById('globalAddBtn').addEventListener('click', addGlobalWhitelist);
  document.getElementById('globalAdd').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') addGlobalWhitelist();
  });

  document.getElementById('siteAddBtn').addEventListener('click', addSiteWhitelist);
  document.getElementById('siteAdd').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') addSiteWhitelist();
  });

  document.getElementById('regexAddBtn').addEventListener('click', addRegex);
  document.getElementById('regexAdd').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') addRegex();
  });

  document.getElementById('genReport').addEventListener('click', generateReport);
  document.getElementById('copyReport').addEventListener('click', copyReport);
}

async function restoreTrustToggle() {
  if (!pageDomain) return;
  try {
    const res = await browser.storage.local.get('trustedSites');
    const list = Array.isArray(res.trustedSites) ? res.trustedSites : [];
    document.getElementById('trustToggle').checked = list.indexOf(pageDomain) !== -1;
  } catch (e) { /* ignore */ }
}
