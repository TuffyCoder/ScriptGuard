/**
 * ScriptGuard - content script.
 *
 * Injected into every frame (top page + iframes) at `document_start`,
 * which is before the HTML parser has created any element. From here we
 * delete scripts BEFORE they execute, using three cooperating hooks:
 *
 *   1. `beforescriptexecute`  (main hook, Firefox-specific)
 *      Gecko fires this synchronously for EVERY script that is about to
 *      execute - parser-inserted, document.write() and dynamically
 *      injected alike. Calling event.preventDefault() stops the script
 *      from ever running, then we remove the node from the DOM.
 *
 *   2. MutationObserver (backup hook)
 *      Watches for newly inserted <script> nodes and removes pending
 *      ones early. Also tears ad iframes/images out of the DOM while
 *      the firewall is armed, and strips inline on*= handlers and
 *      javascript: links in MAXIMUM mode.
 *
 *   3. Page-world dispatcher (Privacy Shield / MAXIMUM mode)
 *      Content scripts run in an isolated sandbox, so page globals
 *      (eval, RTCPeerConnection, canvas APIs...) must be patched from
 *      INSIDE the page. We inject ONE small dispatcher script, marked
 *      with data-scriptguard-helper so our own hooks never delete it.
 *      It captures the original natives once and checks the current
 *      flags (mode + shields + firewall) at CALL time; the content
 *      script updates those flags live via a CustomEvent. That means
 *      switching modes mid-page never stacks wrappers and never leaves
 *      a protection stuck on - the wrapper simply consults the latest
 *      flags.
 *
 * Script deletion is DOM-level; ad/tracker requests are additionally
 * cancelled at the network layer by the background page's webRequest
 * firewall (see background.js).
 *
 * Rule precedence (v2 - ScriptGuard):
 *   OFF       nothing is ever deleted.
 *   BASIC     remembered rules + user regex rules only. Heuristic
 *             detections are REPORTED but never auto-deleted.
 *   PRO       BASIC + heuristic rules + known trackers + all third-party
 *             scripts. Honours per-site AND global whitelists.
 *   MAXIMUM   deletes ALL scripts. Ignores whitelists, regex and
 *             heuristics (only the site-level "trust" switch wins).
 *
 * Whitelists (per-site and global) override BASIC and PRO; they do NOT
 * override MAXIMUM. Regex rules delete matching scripts in BASIC and PRO.
 */

(function () {
  'use strict';

  /* ===================================================================
   * 1. Settings cache
   *
   * storage.local is asynchronous, but beforescriptexecute must be
   * attached synchronously. So we attach all hooks first with a safe
   * default config, then fill the real values in as soon as storage
   * resolves (usually well before the parser reaches the first
   * <script> tag). Until then we fail OPEN - never delete - so a cold
   * start can never break a page. The honest trade-off is documented
   * in the README.
   * =================================================================== */

  const SETTING_KEYS = [
    'mode', 'rules', 'whitelist', 'trustedSites', 'labels', 'stats',
    'globalWhitelist', 'regexRules', 'heuristics', 'shields', 'firewall'
  ];

  const config = {
    mode: 'BASIC',        // safe default until real settings arrive
    rules: {},            // site -> [pattern]  (learned deletions)
    whitelist: {},        // site -> [pattern]  (per-site allow list)
    trustedSites: [],     // [host]             (site-level trust)
    labels: {},           // site -> { pattern: label }
    stats: {},            // site -> deleted count
    globalWhitelist: [],  // [pattern]          (allow list, every site)
    regexRules: [],       // [RegExp source]    (user block regexes)
    heuristics: {},       // site -> [pattern]  (learned suspicious scripts)
    shields: { webrtc: true, blob: true },
    firewall: { adBlockMode: 'armed', stripTracking: true, gpc: true, autoWipe: false }
  };

  let settingsReady = false;

  /** Attribute that marks scripts injected by ScriptGuard itself. */
  const HELPER_ATTR = 'data-scriptguard-helper';

  /* ===================================================================
   * 2. Small utilities
   * =================================================================== */

  /** Hostname of the page this frame is showing. */
  function pageHost() {
    try {
      return location.hostname || '';
    } catch (e) {
      return '';
    }
  }

  /** Hostname of an arbitrary URL, resolved against the page. */
  function hostOf(url) {
    try {
      return new URL(url, location.href).hostname || '';
    } catch (e) {
      return '';
    }
  }

  /** Protocol of an arbitrary URL, e.g. "https:". */
  function protocolOf(url) {
    try {
      return new URL(url, location.href).protocol || '';
    } catch (e) {
      return '';
    }
  }

  /**
   * Normalize a script URL for storage/matching: same document, but
   * without query string and fragment, so "tracker.js?v=2" still matches
   * the stored "tracker.js" pattern tomorrow.
   */
  function normalizeUrl(rawUrl) {
    try {
      const u = new URL(rawUrl, location.href);
      u.search = '';
      u.hash = '';
      return u.href;
    } catch (e) {
      return String(rawUrl || '');
    }
  }

  /**
   * Naive "registrable domain" guess: the last two labels.
   * Good enough for a per-site tool (example.com, www.example.com and
   * cdn.example.com all collapse to "example.com"). Known limitation:
   * multi-part public suffixes like "co.uk" are treated as part of the
   * domain - documented in the README.
   */
  function baseDomain(host) {
    const parts = (host || '').split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    return parts.slice(-2).join('.');
  }

  /**
   * All domain keys that should be consulted for the current page:
   * ["a.b.example.com", "b.example.com", "example.com"].
   */
  function domainChain(host) {
    const parts = (host || '').split('.').filter(Boolean);
    const chain = [];
    for (let i = 0; i < parts.length - 1; i++) {
      chain.push(parts.slice(i).join('.'));
    }
    return chain.length ? chain : [host || ''];
  }

  /** Same site? Exact match, subdomain of each other, or same base domain. */
  function sameSite(hostA, hostB) {
    if (!hostA || !hostB) return true;
    if (hostA === hostB) return true;
    if (hostA.endsWith('.' + hostB) || hostB.endsWith('.' + hostA)) return true;
    return baseDomain(hostA) === baseDomain(hostB);
  }

  /** External <script src="..."> or inline <script>...</script>? */
  function isExternal(el) {
    return typeof el.src === 'string' && el.src.length > 0;
  }

  /**
   * Short, stable hash of an inline script's text (two 32-bit FNV-1a
   * rounds for fewer collisions). Two identical inline snippets on the
   * same site always produce the same "inline:<hash>" pattern.
   */
  function inlineHash(text) {
    let h1 = 0x811c9dc5;
    let h2 = 0x0158a3b7;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
      h2 = Math.imul(h2 ^ c, 0x85ebca6b) >>> 0;
    }
    return h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0');
  }

  /** Human-readable label for an inline script (used in the popup). */
  function inlineLabel(text) {
    const t = String(text || '').replace(/\s+/g, ' ').trim();
    if (!t) return '(empty inline script)';
    return t.length > 72 ? t.slice(0, 72) + '...' : t;
  }

  /** The storage pattern for a given script element. */
  function patternForScript(el) {
    if (isExternal(el)) {
      return normalizeUrl(el.src);
    }
    return 'inline:' + inlineHash(el.textContent || '');
  }

  /** Display name for a script element. */
  function describeScript(el) {
    if (isExternal(el)) return el.src;
    return inlineLabel(el.textContent || '');
  }

  /* ===================================================================
   * 3. Known tracker signatures (used by PRO mode)
   *
   * Deliberately readable and short - a human can audit this list.
   * Matched against the script URL and, for inline scripts, their code.
   * =================================================================== */

  const TRACKER_URL_PATTERNS = [
    /google-analytics\.com/i,
    /googletagmanager\.com/i,
    /googlesyndication\.com/i,
    /doubleclick\.net/i,
    /connect\.facebook\.net/i,
    /facebook\.net\/.+\/(fbevents|sdk)/i,
    /hotjar\.com/i,
    /static\.hotjar\.com/i,
    /cdn\.(mxpnl|segment)\.com/i,
    /mixpanel\.com/i,
    /api\.amplitude\.com/i,
    /clarity\.ms/i,
    /matomo|piwik\.js/i,
    /quantserve\.com/i,
    /scorecardresearch\.com/i,
    /criteo\.(com|net)/i,
    /taboola\.com/i,
    /outbrain\.com/i,
    /adnxs\.com/i,
    /moatads\.com/i,
    /mc\.yandex\.ru/i,
    /sentry-cdn\.com|ingest\.(sentry\.io|sentry\.io)/i,
    /fullstory\.com/i,
    /js-agent\.newrelic\.com/i,
    /static\.chartbeat\.com/i,
    /cdn\.parsely\.com/i,
    /cdn\.optimizely\.com/i,
    /script\.crazyegg\.com/i,
    /platform\.twitter\.com/i,
    /snap\.licdn\.com/i,
    /static\.ads-twitter\.com/i,
    /bat\.bing\.com/i
  ];

  const TRACKER_CODE_PATTERNS = [
    /\bdataLayer\s*=/,
    /\bgtag\s*\(\s*['"]/,
    /\bga\s*\(\s*['"]create['"]/,
    /\bfbq\s*\(\s*['"]init['"]/,
    /googletagmanager|google-analytics/,
    /\bym\s*\(\s*\d+\s*,/,
    /Ya\.Metrika/,
    /\b_hjSettings\s*=/,
    /\bmixpanel\s*\.\s*init/,
    /\bamplitude\s*\.\s*init/,
    /\bclarity\s*\(/,
    /piwik|matomo/i,
    /\b_tfa\s*=/,
    /\b_ttq\s*=/,
    /\b_lintrk\s*=/
  ];

  /** Does this script look like a known tracker? */
  function looksLikeTracker(el) {
    if (isExternal(el)) {
      const url = el.src;
      for (const re of TRACKER_URL_PATTERNS) {
        if (re.test(url)) return true;
      }
      // data:/blob: payloads carry their code inside the URL itself
      const proto = protocolOf(url);
      if (proto === 'data:') {
        try {
          const body = decodeURIComponent(url);
          for (const re of TRACKER_CODE_PATTERNS) {
            if (re.test(body)) return true;
          }
        } catch (e) { /* malformed data URL - ignore */ }
      }
      return false;
    }
    const text = el.textContent || '';
    for (const re of TRACKER_CODE_PATTERNS) {
      if (re.test(text)) return true;
    }
    return false;
  }

  /* ===================================================================
   * 3b. Heuristic suspicion signals (heuristic learning)
   *
   * These are NOT tracker signatures. They are weaker "this script is
   * poking at things trackers care about" signals: IP discovery via
   * WebRTC, canvas/WebGL/audio fingerprinting, beacons, cookie reads,
   * device attribute probing. A third-party script matching enough of
   * them is learned into the per-site heuristic rules (PRO only).
   * Never fires in BASIC mode - detection is reported, not enforced.
   * =================================================================== */

  const HEURISTIC_SIGNALS = [
    { id: 'webrtc-ip', re: /RTCPeerConnection|createDataChannel|stun:|turn:/i, label: 'WebRTC / ICE candidate gathering' },
    { id: 'canvas-fp', re: /toDataURL|toBlob|getImageData|measureText/i, label: 'canvas readback' },
    { id: 'webgl-fp', re: /getParameter|WEBGL_debug_renderer_info|UNMASKED_RENDERER/i, label: 'WebGL renderer probing' },
    { id: 'audio-fp', re: /AudioContext|createOscillator|getChannelData|getFloatFrequencyData/i, label: 'audio stack probing' },
    { id: 'beacon', re: /sendBeacon|navigator\.sendBeacon/i, label: 'sendBeacon telemetry' },
    { id: 'ws-channel', re: /new\s+WebSocket\s*\(/i, label: 'raw WebSocket channel' },
    { id: 'cookie-read', re: /document\s*\.\s*cookie/i, label: 'cookie access' },
    { id: 'hw-probe', re: /navigator\.(plugins|languages|hardwareConcurrency|deviceMemory)|screen\.(width|height|colorDepth)/i, label: 'device attribute probing' }
  ];

  /** Heuristic threshold: at least this many distinct signals. */
  const HEURISTIC_THRESHOLD = 2;

  /* ===================================================================
   * 3c. Ad infrastructure signatures (DOM ad removal)
   *
   * The background firewall cancels ad requests at the network layer;
   * this shorter list lets the content script ALSO tear the ad nodes
   * (iframes / images / scripts) out of the DOM, so empty ad boxes
   * collapse instead of leaving holes. Only the highest-volume ad hosts
   * live here - anything else dies on the network side anyway.
   * =================================================================== */

  const AD_HOSTS = [
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'googletagservices.com', 'google-analytics.com', 'googletagmanager.com',
    'app-measurement.com', 'adnxs.com', 'adsafeprotected.com', 'adform.net',
    'adroll.com', 'adsrvr.org', 'rubiconproject.com', 'pubmatic.com',
    'openx.net', 'criteo.com', 'criteo.net', 'casalemedia.com', 'indexww.com',
    'sharethrough.com', 'smartadserver.com', 'yieldmo.com', 'bidswitch.net',
    'districtm.io', 'media.net', '33across.com', 'engagebdr.com', 'sonobi.com',
    'gumgum.com', 'undertone.com', 'conversantmedia.com', 'advertising.com',
    'tremorhub.com', 'spotxchange.com', 'teads.tv', 'springserve.com',
    'triplelift.com', 'bidr.io', 'amazon-adsystem.com', 'taboola.com',
    'outbrain.com', 'revcontent.com', 'mgid.com', 'zergnet.com',
    'content-ad.net', 'ad-maven.com', 'propellerads.com', 'adcash.com',
    'popads.net', 'popcash.net', 'exoclick.com', 'juicyads.com',
    'hilltopads.net', 'moatads.com', 'doubleverify.com', 'scorecardresearch.com',
    'quantserve.com', 'comscore.com', 'sizmek.com', 'flashtalking.com',
    'chartbeat.com', 'connect.facebook.net', 'an.facebook.com',
    'ads-twitter.com', 'tr.snapchat.com', 'ads.pinterest.com',
    'ads.reddit.com', 'ads.tiktok.com', 'analytics.tiktok.com'
  ];

  const AD_PATH_RE = /\/(pagead|adsbygoogle|adserver|adframe|advert|popunder|prebid(\.js|-)|pubads|tag\/js\/gpt|bannerad|interstitial)/i;

  /** Is this URL pointing at ad infrastructure? */
  function isAdUrl(rawUrl) {
    if (!rawUrl) return false;
    try {
      const u = new URL(rawUrl, location.href);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
      const host = u.hostname.toLowerCase();
      for (const ad of AD_HOSTS) {
        if (host === ad || host.endsWith('.' + ad)) return true;
      }
      // generic ad paths only count on cross-origin requests
      if (baseDomain(host) !== baseDomain(pageHost()) && AD_PATH_RE.test(u.pathname)) {
        return true;
      }
    } catch (e) { /* not a URL - ignore */ }
    return false;
  }

  /** Is the DOM ad sweep active for the current mode + firewall setting?
   *  Ads are removed in EVERY active mode (BASIC, PRO, MAXIMUM); 'always'
   *  is accepted as a legacy alias of 'armed'. */
  function adSweepActive() {
    if (config.mode === 'OFF') return false;
    if (config.trustedSites.indexOf(pageHost()) !== -1) return false;
    const m = (config.firewall && config.firewall.adBlockMode) || 'armed';
    if (m === 'off') return false;
    return m === 'armed' || m === 'always';
  }

  /**
   * Run the heuristic scan. Returns null (not suspicious) or
   * { signals: [label...], score } for logging / popup / learning.
   */
  function heuristicScan(el) {
    const text = isExternal(el)
      ? String(el.src || '') + ' ' + String(el.textContent || '')
      : String(el.textContent || '');
    const signals = [];
    for (const sig of HEURISTIC_SIGNALS) {
      if (sig.re.test(text)) signals.push(sig.label);
    }
    if (signals.length < HEURISTIC_THRESHOLD) return null;
    return { signals: signals, score: signals.length };
  }

  /* ===================================================================
   * 4. Rule storage helpers (learning system)
   * =================================================================== */

  /** All stored patterns for a given map that apply to this page,
   *  following the domain chain upwards. */
  function patternsFor(mapKey) {
    const host = pageHost();
    const out = [];
    const map = config[mapKey] || {};
    for (const domain of domainChain(host)) {
      const list = map[domain];
      if (Array.isArray(list)) {
        for (const p of list) out.push(p);
      }
    }
    return out;
  }

  /** Does any of the given patterns match this script? Supports "*" suffix. */
  function patternMatches(patterns, el, pattern) {
    if (patterns.indexOf(pattern) !== -1) return true;
    if (isExternal(el)) {
      const norm = normalizeUrl(el.src);
      for (const p of patterns) {
        if (typeof p === 'string' && p.length > 1 && p.charAt(p.length - 1) === '*') {
          if (norm.startsWith(p.slice(0, -1))) return true;
        }
      }
    }
    return false;
  }

  /* ---- user regex rules (block lists, BASIC + PRO) ------------------ */

  const regexCache = new Map(); // source -> RegExp | null (invalid)

  function regexFor(source) {
    if (regexCache.has(source)) return regexCache.get(source);
    let re = null;
    try { re = new RegExp(source, 'i'); } catch (e) { re = null; }
    regexCache.set(source, re);
    return re;
  }

  /** Test the user's regex rules against this script. Returns the
   *  matching source string, or null. */
  function regexHit(el) {
    const sources = Array.isArray(config.regexRules) ? config.regexRules : [];
    if (sources.length === 0) return null;
    const subject = isExternal(el) ? el.src : String(el.textContent || '');
    if (!subject) return null;
    for (const source of sources) {
      const re = typeof source === 'string' ? regexFor(source) : null;
      if (re && re.test(subject)) return source;
    }
    return null;
  }

  /**
   * Add a pattern to a rule map ("rules" / "whitelist" / "heuristics")
   * for this site. Rules are stored under the BASE domain so they apply
   * to the whole site. Human labels are kept alongside for the popup.
   */
  async function addPattern(mapKey, pattern, label) {
    const host = pageHost();
    if (!host || !pattern) return;
    const siteKey = baseDomain(host);
    try {
      const snapshot = await browser.storage.local.get([mapKey, 'labels']);
      const map = Object.assign({}, snapshot[mapKey] || {});
      const list = Array.isArray(map[siteKey]) ? map[siteKey].slice() : [];
      if (list.indexOf(pattern) === -1) {
        list.push(pattern);
      }
      map[siteKey] = list;

      const patch = {};
      patch[mapKey] = map;

      if (label && mapKey !== 'heuristics') {
        const labels = Object.assign({}, snapshot.labels || {});
        const siteLabels = Object.assign({}, labels[siteKey] || {});
        siteLabels[pattern] = label;
        labels[siteKey] = siteLabels;
        patch.labels = labels;
        config.labels = labels;
      }

      await browser.storage.local.set(patch);
      config[mapKey] = map;
    } catch (e) { /* storage failure must never crash the page */ }
  }

  /** Remove one pattern from a rule map for this site. */
  async function removePattern(mapKey, pattern) {
    const host = pageHost();
    if (!host || !pattern) return;
    const siteKey = baseDomain(host);
    try {
      const snapshot = await browser.storage.local.get(mapKey);
      const map = Object.assign({}, snapshot[mapKey] || {});
      if (Array.isArray(map[siteKey])) {
        map[siteKey] = map[siteKey].filter((p) => p !== pattern);
        if (map[siteKey].length === 0) delete map[siteKey];
      }
      const patch = {};
      patch[mapKey] = map;
      await browser.storage.local.set(patch);
      config[mapKey] = map;
    } catch (e) { /* ignore */ }
  }

  /** Learn a suspicious third-party script into the heuristic rules. */
  async function learnHeuristic(pattern, signals) {
    const host = pageHost();
    if (!host || !pattern) return;
    const siteKey = baseDomain(host);
    try {
      const snapshot = await browser.storage.local.get('heuristics');
      const map = Object.assign({}, snapshot.heuristics || {});
      const list = Array.isArray(map[siteKey]) ? map[siteKey].slice() : [];
      if (list.indexOf(pattern) !== -1) return; // already learned
      list.push(pattern);
      map[siteKey] = list;
      await browser.storage.local.set({ heuristics: map });
      config.heuristics = map;
      console.log(
        '[ScriptGuard] heuristic learned for ' + siteKey + ': ' + pattern +
        ' (' + signals.length + ' signals: ' + signals.join(', ') + ')'
      );
    } catch (e) { /* ignore */ }
  }

  /** Forget everything ScriptGuard knows about the current site. */
  async function resetSite() {
    const host = pageHost();
    if (!host) return;
    try {
      const snapshot = await browser.storage.local.get(
        ['rules', 'whitelist', 'labels', 'stats', 'trustedSites', 'heuristics']
      );
      const patch = {};
      const keys = ['rules', 'whitelist', 'labels', 'stats', 'heuristics'];
      for (const key of keys) {
        const map = Object.assign({}, snapshot[key] || {});
        for (const domain of domainChain(host)) {
          delete map[domain];
        }
        delete map[baseDomain(host)];
        patch[key] = map;
      }
      patch.trustedSites = (snapshot.trustedSites || []).filter((h) => h !== host);
      await browser.storage.local.set(patch);
      config.rules = patch.rules;
      config.whitelist = patch.whitelist;
      config.heuristics = patch.heuristics;
    } catch (e) { /* ignore */ }
  }

  /* ----- per-site statistics (kept in storage, shown in the popup) --- */

  let statDelta = 0;
  let statTimer = null;

  function bumpStats(n) {
    statDelta += n;
    if (statTimer) return;
    statTimer = setTimeout(pushStats, 2000);
  }

  async function pushStats() {
    statTimer = null;
    const delta = statDelta;
    statDelta = 0;
    if (delta <= 0) return;
    const siteKey = baseDomain(pageHost());
    if (!siteKey) return;
    try {
      const snapshot = await browser.storage.local.get('stats');
      const stats = Object.assign({}, snapshot.stats || {});
      stats[siteKey] = (stats[siteKey] || 0) + delta;
      config.stats = stats;
      await browser.storage.local.set({ stats: stats });
    } catch (e) { /* ignore */ }
  }

  /* ===================================================================
   * 5. The decision engine
   *
   * decide(el) returns null (allow) or { reason, pattern } (delete).
   * This is where the four privacy modes live.
   *
   * Precedence:
   *   trust switch  >  MAXIMUM (delete all)  >  whitelists (per-site +
   *   global)  >  remembered rules  >  regex rules  >  heuristics (PRO)
   *   >  trackers  >  third-party.
   * =================================================================== */

  function decide(el) {
    if (config.mode === 'OFF') return null;                       // OFF: untouched
    if (el.hasAttribute(HELPER_ATTR)) return null;                // our own helper

    const host = pageHost();
    if (!host) return null;                                       // about:blank etc.
    if (config.trustedSites.indexOf(host) !== -1) return null;    // trusted site

    const pattern = patternForScript(el);

    // MAXIMUM is nuclear: delete ALL scripts. Whitelists, regex rules
    // and heuristic rules are NOT honoured in this mode.
    if (config.mode === 'MAXIMUM') {
      return { reason: 'maximum mode', pattern: pattern };
    }

    // Per-site whitelist and global whitelist win in BASIC and PRO.
    if (patternMatches(patternsFor('whitelist'), el, pattern)) return null;
    if (patternMatches(config.globalWhitelist || [], el, pattern)) return null;

    const remembered = patternMatches(patternsFor('rules'), el, pattern);

    if (config.mode === 'BASIC') {
      // BASIC: only what the user explicitly deleted before, plus the
      // user's own regex rules. Heuristics never auto-delete here.
      if (remembered) return { reason: 'remembered rule', pattern: pattern };
      if (regexHit(el)) return { reason: 'regex rule', pattern: pattern };
      return null;
    }

    // ---- PRO mode ----
    if (remembered) return { reason: 'remembered rule', pattern: pattern };
    if (regexHit(el)) return { reason: 'regex rule', pattern: pattern };

    if (patternMatches(patternsFor('heuristics'), el, pattern)) {
      return { reason: 'heuristic rule', pattern: pattern };
    }

    if (looksLikeTracker(el)) return { reason: 'tracking pattern', pattern: pattern };

    if (isExternal(el)) {
      const proto = protocolOf(el.src);
      if (proto === 'http:' || proto === 'https:') {
        // PRO: delete all third-party (cross-domain) scripts.
        if (!sameSite(hostOf(el.src), host)) {
          return { reason: 'third-party script', pattern: pattern };
        }
      } else if (proto === 'blob:' && config.shields && config.shields.blob) {
        // Blob shield: dynamic blob script injection is a classic IP
        // leak / evasion channel - delete before execution.
        return { reason: 'blob script', pattern: pattern };
      }
      // data: srcs fall through - only trackers were flagged above.
    }
    return null; // first-party inline scripts stay allowed in PRO
  }

  /* ===================================================================
   * 6. Deletion hooks
   * =================================================================== */

  /** Scripts that already executed - we never pretend to block these. */
  const executedScripts = new WeakSet();

  document.addEventListener('beforescriptexecute', function (event) {
    const el = event.target;
    const verdict = decide(el);
    if (verdict) {
      // preventDefault() means the script never executes in Gecko.
      event.preventDefault();
      try { el.remove(); } catch (e) { /* already gone */ }
      recordDeleted(el, verdict, false);
    }
    // Allowed scripts are marked by the afterscriptexecute listener.
  }, true);

  document.addEventListener('afterscriptexecute', function (event) {
    executedScripts.add(event.target);
  }, true);

  /**
   * Backup hook: watch the DOM for inserted <script> nodes and sweep
   * pending ones. Dynamically inserted inline scripts run synchronously
   * on insertion (beforescriptexecute still catches those first), but
   * external dynamic scripts typically wait for their download - this
   * observer deletes them during that window.
   *
   * The same observer also:
   *   - tears ad iframes/images out of the DOM (firewall on),
   *   - strips inline on*= handlers and javascript: links (MAXIMUM).
   */
  const INLINE_HANDLER_ATTRS = [
    'src', 'onload', 'onclick', 'onerror', 'onmouseover', 'onmouseout',
    'onmouseenter', 'onmouseleave', 'onmousedown', 'onmouseup', 'onmousemove',
    'onkeydown', 'onkeyup', 'onkeypress', 'onfocus', 'onblur', 'onsubmit',
    'onchange', 'oninput', 'ondblclick', 'oncontextmenu', 'onwheel',
    'onanimationstart', 'onanimationend', 'onpointerdown', 'onpointerover',
    'ontoggle'
  ];

  const observer = new MutationObserver(function (mutations) {
    if (config.mode === 'OFF' || !settingsReady) return;
    const maxOn = config.mode === 'MAXIMUM';
    const adsOn = adSweepActive();
    for (const m of mutations) {
      if (m.type === 'attributes') {
        const t = m.target;
        if (!t || !t.tagName) continue;
        if (maxOn && m.attributeName && m.attributeName.indexOf('on') === 0) {
          try { t.removeAttribute(m.attributeName); } catch (e) { /* gone */ }
          continue;
        }
        if (adsOn && m.attributeName === 'src' &&
            (t.tagName === 'IFRAME' || t.tagName === 'IMG') &&
            isAdUrl(t.getAttribute('src'))) {
          try { recordAd(t); t.remove(); } catch (e) { /* gone */ }
        }
        continue;
      }
      const added = m.addedNodes;
      for (let i = 0; i < added.length; i++) {
        const node = added[i];
        if (!node || !node.tagName) continue;
        if (node.tagName === 'SCRIPT') sweepScript(node);
        else if (adsOn && (node.tagName === 'IFRAME' || node.tagName === 'IMG')) sweepAdNode(node);
        else if (maxOn && node.nodeType === 1) sweepInlineHandlers(node);
      }
    }
  });
  observer.observe(document, {
    childList: true, subtree: true,
    attributes: true,
    attributeFilter: INLINE_HANDLER_ATTRS
  });

  function sweepScript(el) {
    if (!el || executedScripts.has(el)) return;
    if (!el.isConnected) return; // already removed (e.g. by the main hook)
    const verdict = decide(el);
    if (verdict) {
      try { el.remove(); } catch (e) { /* ignore */ }
      recordDeleted(el, verdict, true);
    }
  }

  /** Remove an ad iframe/image from the DOM and record it. */
  function sweepAdNode(el) {
    if (!el || !el.isConnected) return;
    if (isAdUrl(el.getAttribute('src'))) {
      try { recordAd(el); el.remove(); } catch (e) { /* ignore */ }
    }
  }

  /**
   * MAXIMUM: strip inline event handlers (onclick= etc.) and javascript:
   * URLs from a subtree - they execute code without a <script> tag, so
   * deleting script nodes alone is not nuclear enough.
   */
  function sweepInlineHandlers(root) {
    if (!root || !root.attributes) return;
    const targets = [root];
    try {
      if (root.querySelectorAll) {
        targets.push.apply(targets, root.querySelectorAll('*'));
      }
    } catch (e) { /* invalid subtree - ignore */ }
    for (const el of targets) {
      if (!el.attributes) continue;
      for (const attr of Array.prototype.slice.call(el.attributes)) {
        if (attr.name.indexOf('on') === 0) {
          try { el.removeAttribute(attr.name); } catch (e) { /* ignore */ }
        } else if (attr.name === 'href' &&
                   String(attr.value).trim().toLowerCase().indexOf('javascript:') === 0) {
          try { el.setAttribute('href', '#'); } catch (e) { /* ignore */ }
        }
      }
    }
  }

  /**
   * Re-evaluate every script node that is still in the DOM and has not
   * run yet (async/deferred downloads, preloaded nodes). Used after
   * settings load and whenever rules change mid-page.
   */
  function sweepPendingScripts() {
    if (config.mode === 'OFF' || !settingsReady) return;
    const nodes = Array.prototype.slice.call(document.scripts || []);
    for (const el of nodes) {
      if (executedScripts.has(el)) continue;
      sweepScript(el);
    }
  }

  /** Full-document sweep: scripts + ad nodes + (MAX) inline handlers. */
  function sweepDocument() {
    if (config.mode === 'OFF' || !settingsReady) return;
    sweepPendingScripts();
    if (adSweepActive()) {
      const nodes = document.querySelectorAll('iframe[src], img[src]');
      for (const el of nodes) sweepAdNode(el);
    }
    if (config.mode === 'MAXIMUM') {
      sweepInlineHandlers(document.body || document.documentElement);
    }
  }

  /* ===================================================================
   * 7. Page-world dispatcher (shields + fingerprint + MAXIMUM patch)
   *
   * ONE dispatcher script is injected the first time the page needs
   * protection (any mode except OFF). It captures the original natives
   * once, installs call-time wrappers, and listens for flag updates:
   *
   *   flags.maximum      MAXIMUM mode: neuter eval()/Function()/
   *                      string timers, return null/empty from
   *                      fingerprint APIs (delete the request).
   *   flags.fingerprint  'off' | 'noise' (PRO: spoof, do not break)
   *                      | 'null' (MAXIMUM: delete the request)
   *   flags.webrtc       WebRTC kill-switch (PRO + MAXIMUM)
   *   flags.blob         Blob kill-switch (PRO + MAXIMUM)
   *
   * The content script updates flags live via a CustomEvent, so mode
   * or shield changes never stack wrappers and are never stuck on.
   * The page world reports blocked probes back via postMessage.
   * =================================================================== */

  function buildDispatcherCode(flags) {
    const f = JSON.stringify(flags);
    return [
      '(function () {',
      '  "use strict";',
      '  var W = window;',
      '  if (W.__sg) return;            // already dispatched on this page',
      '  var S = W.__sg = {',
      '    flags: ' + f + ',',
      '    orig: {},',
      '    logged: {}',
      '  };',
      // Session-stable noise seed: fingerprint noise is consistent within a
      // page load (readbacks match each other) but changes across sessions,
      // so the device cannot be re-identified by comparing page loads.
      '  if (!S.seed) {',
      '    try { S.seed = crypto.getRandomValues(new Uint32Array(1))[0] >>> 0; } catch (e) { S.seed = (Date.now() * 2654435761) >>> 0; }',
      '  }',
      '  S.next = function () {',
      '    S.seed = (Math.imul(S.seed, 1664525) + 1013904223) >>> 0;',
      '    return S.seed / 4294967296;',
      '  };',
      '  function report(kind) {',
      '    try { W.postMessage({ __scriptguard_probe: kind }, "*"); } catch (e) {}',
      '  }',
      '  function logOnce(key, msg) {',
      '    if (S.logged[key]) return; S.logged[key] = true;',
      '    try { console.log(msg); } catch (e) {}',
      '  }',
      '  function keep(name, current) {',
      '    if (!(name in S.orig)) S.orig[name] = current;',
      '    return S.orig[name];',
      '  }',
      '  W.addEventListener("__scriptguard_flags", function (ev) {',
      '    try { var d = ev.detail || {}; for (var k in d) S.flags[k] = d[k]; } catch (e) {}',
      '  });',
      // ---- same-origin helpers for channel policies ----
      '  function baseHost(h) {',
      '    var p = String(h || "").split(".");',
      '    return p.length <= 2 ? p.join(".") : p.slice(-2).join(".");',
      '  }',
      '  function channelThird(url) {',
      '    try {',
      '      var u = new URL(url, location.href);',
      '      return baseHost(u.hostname) !== baseHost(location.hostname);',
      '    } catch (e) { return false; }',
      '  }',
      // ---- eval / Function / string timers (call-time gated) ----
      '  try {',
      '    var origEval = keep("eval", W.eval);',
      '    W.eval = function (code) {',
      '      if (S.flags.maximum) {',
      '        report("eval");',
      '        logOnce("eval", "ScriptGuard: eval() deleted in MAXIMUM mode.");',
      '        return undefined;',
      '      }',
      '      return origEval.apply(W, arguments);',
      '    };',
      '  } catch (e) {}',
      '  try {',
      '    var origFunction = keep("Function", W.Function);',
      '    var GuardedFunction = function () {',
      '      if (S.flags.maximum) {',
      '        report("eval");',
      '        throw new Error("ScriptGuard: new Function() is disabled in MAXIMUM mode");',
      '      }',
      '      return origFunction.apply(this, arguments);',
      '    };',
      '    GuardedFunction.prototype = origFunction.prototype;',
      '    GuardedFunction.prototype.constructor = GuardedFunction;',
      '    W.Function = GuardedFunction;',
      '  } catch (e) {}',
      '  try {',
      '    var origST = keep("setTimeout", W.setTimeout);',
      '    var origSI = keep("setInterval", W.setInterval);',
      '    W.setTimeout = function () {',
      '      if (S.flags.maximum && typeof arguments[0] === "string") return 0;',
      '      return origST.apply(W, arguments);',
      '    };',
      '    W.setInterval = function () {',
      '      if (S.flags.maximum && typeof arguments[0] === "string") return 0;',
      '      return origSI.apply(W, arguments);',
      '    };',
      '  } catch (e) {}',
      // ---- WebRTC kill-switch ----
      '  try {',
      '    var PC = W.RTCPeerConnection || W.webkitRTCPeerConnection || W.mozRTCPeerConnection;',
      '    if (PC) {',
      '      var origPC = keep("RTCPeerConnection", PC);',
      '      var GuardedPC = function () {',
      '        if (S.flags.webrtc) {',
      '          report("webrtc");',
      '          logOnce("webrtc", "ScriptGuard: WebRTC disabled to prevent IP leaks.");',
      '          throw new Error("ScriptGuard: RTCPeerConnection is disabled (Privacy Shield).");',
      '        }',
      '        return new origPC(arguments[0], arguments[1]);',
      '      };',
      '      GuardedPC.prototype = origPC.prototype;',
      '      W.RTCPeerConnection = GuardedPC;',
      '      W.webkitRTCPeerConnection = GuardedPC;',
      '      if (W.mozRTCPeerConnection) W.mozRTCPeerConnection = GuardedPC;',
      '    }',
      '  } catch (e) {}',
      // ---- Blob kill-switch ----
      '  try {',
      '    var origCreate = keep("createObjectURL", URL.createObjectURL);',
      '    URL.createObjectURL = function (obj) {',
      '      if (S.flags.blob) {',
      '        var type = "";',
      '        try { type = (obj && obj.type) || ""; } catch (e) {}',
      '        if (/javascript|ecmascript/i.test(type)) {',
      '          report("blob");',
      '          logOnce("blob", "ScriptGuard: Blob scripts blocked.");',
      '          return "blob:scriptguard-blocked";',
      '        }',
      '      }',
      '      return origCreate.apply(URL, arguments);',
      '    };',
      '    var origWorker = keep("Worker", W.Worker);',
      '    var GuardedWorker = function (a1, a2) {',
      '      if (S.flags.blob && typeof a1 === "string" && a1.indexOf("blob:") === 0) {',
      '        report("blob");',
      '        logOnce("blob", "ScriptGuard: Blob scripts blocked.");',
      '        throw new Error("ScriptGuard: blob: workers are blocked (Privacy Shield).");',
      '      }',
      '      return a2 === undefined ? new origWorker(a1) : new origWorker(a1, a2);',
      '    };',
      '    GuardedWorker.prototype = origWorker.prototype;',
      '    W.Worker = GuardedWorker;',
      '  } catch (e) {}',
      // ---- Data channels: WebSocket / EventSource / sendBeacon ----
      // PRO blocks cross-site channels (tracking beacons, exfil, binex),
      // MAXIMUM blocks them all. Same-site channels stay usable in PRO.
      '  try {',
      '    var origWS = keep("WebSocket", W.WebSocket);',
      '    var GuardedWS = function (url, protos) {',
      '      var pol = S.flags.channel || "off";',
      '      if (pol !== "off" && (pol === "block" || channelThird(url))) {',
      '        report("channel");',
      '        logOnce("ws", "ScriptGuard: cross-site WebSocket blocked (Privacy Shield).");',
      '        throw new Error("ScriptGuard: WebSocket blocked (Privacy Shield).");',
      '      }',
      '      return protos === undefined ? new origWS(url) : new origWS(url, protos);',
      '    };',
      '    GuardedWS.prototype = origWS.prototype;',
      '    GuardedWS.CONNECTING = 0; GuardedWS.OPEN = 1;',
      '    GuardedWS.CLOSING = 2; GuardedWS.CLOSED = 3;',
      '    W.WebSocket = GuardedWS;',
      '  } catch (e) {}',
      '  try {',
      '    var origES = keep("EventSource", W.EventSource);',
      '    if (origES) {',
      '      var GuardedES = function (url, cfg) {',
      '        var pol = S.flags.channel || "off";',
      '        if (pol !== "off" && (pol === "block" || channelThird(url))) {',
      '          report("channel");',
      '          logOnce("es", "ScriptGuard: cross-site EventSource blocked (Privacy Shield).");',
      '          throw new Error("ScriptGuard: EventSource blocked (Privacy Shield).");',
      '        }',
      '        return cfg === undefined ? new origES(url) : new origES(url, cfg);',
      '      };',
      '      GuardedES.prototype = origES.prototype;',
      '      GuardedES.CONNECTING = 0; GuardedES.OPEN = 1; GuardedES.CLOSED = 2;',
      '      W.EventSource = GuardedES;',
      '    }',
      '  } catch (e) {}',
      '  try {',
      '    var origBeacon = keep("sendBeacon", Navigator.prototype.sendBeacon);',
      '    Navigator.prototype.sendBeacon = function (url, data) {',
      '      var pol = S.flags.beacon || "off";',
      '      if (pol !== "off" && (pol === "block" || channelThird(url))) {',
      '        report("channel");',
      '        logOnce("beacon", "ScriptGuard: sendBeacon blocked (Privacy Shield).");',
      '        return false;',
      '      }',
      '      return origBeacon.apply(this, arguments);',
      '    };',
      '  } catch (e) {}',
      // ---- Privacy hardening (PRO + MAXIMUM) ----
      // Entropy sources that exist only to fingerprint or track the user,
      // each replaced with a fixed generic answer. Nothing here breaks a
      // page: every API degrades to a boring, identical value.
      '  var pv = S.flags.privacy || "off";',
      '  if (pv !== "off") {',
      '    try {',
      '      if (Navigator.prototype.getBattery) {',
      '        var origBat = keep("getBattery", Navigator.prototype.getBattery);',
      '        Navigator.prototype.getBattery = function () {',
      '          report("privacy");',
      '          return Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1,',
      '            addEventListener: function () {}, removeEventListener: function () {}, dispatchEvent: function () { return false; } });',
      '        };',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      if ("connection" in navigator || "connection" in Navigator.prototype) {',
      '        Object.defineProperty(navigator, "connection", { get: function () { return undefined; }, configurable: true });',
      '        Object.defineProperty(Navigator.prototype, "connection", { get: function () { return undefined; }, configurable: true });',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      if (W.SpeechSynthesis && W.SpeechSynthesis.prototype && W.SpeechSynthesis.prototype.getVoices) {',
      '        var origVoices = keep("getVoices", W.SpeechSynthesis.prototype.getVoices);',
      '        W.SpeechSynthesis.prototype.getVoices = function () {',
      '          report("privacy");',
      '          var all = origVoices.apply(this, arguments);',
      '          return all && all.length ? [all[0]] : all;',
      '        };',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      if (navigator.storage && navigator.storage.estimate) {',
      '        var origEst = keep("estimate", navigator.storage.estimate);',
      '        navigator.storage.estimate = function () {',
      '          report("privacy");',
      '          return Promise.resolve({ usage: 0, quota: 2147483648 });',
      '        };',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      Object.defineProperty(navigator, "hardwareConcurrency", { get: function () { return 4; }, configurable: true });',
      '      Object.defineProperty(Navigator.prototype, "hardwareConcurrency", { get: function () { return 4; }, configurable: true });',
      '    } catch (e) {}',
      '    try {',
      '      Object.defineProperty(navigator, "deviceMemory", { get: function () { return 8; }, configurable: true });',
      '      Object.defineProperty(Navigator.prototype, "deviceMemory", { get: function () { return 8; }, configurable: true });',
      '    } catch (e) {}',
      '    try {',
      '      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {',
      '        var origEnum = keep("enumerateDevices", navigator.mediaDevices.enumerateDevices);',
      '        navigator.mediaDevices.enumerateDevices = function () {',
      '          report("privacy");',
      '          return Promise.resolve([]);',
      '        };',
      '      }',
      '    } catch (e) {}',
      '  }',
      // ---- MAXIMUM nukes ----
      // Every remaining browser capability that can run code, reach a
      // sensor or persist between page loads is removed outright.
      '  if (S.flags.maximum) {',
      '    try {',
      '      if (navigator.serviceWorker && navigator.serviceWorker.register) {',
      '        navigator.serviceWorker.register = function () {',
      '          report("privacy");',
      '          logOnce("sw", "ScriptGuard: service worker registration blocked in MAXIMUM mode.");',
      '          return Promise.reject(new Error("ScriptGuard: service workers are disabled in MAXIMUM mode."));',
      '        };',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      if (navigator.geolocation) {',
      '        var denied = function (errCb) {',
      '          report("privacy");',
      '          if (typeof errCb === "function") errCb({ code: 1, PERMISSION_DENIED: 1, message: "ScriptGuard: geolocation disabled in MAXIMUM mode" });',
      '        };',
      '        navigator.geolocation.getCurrentPosition = function (_ok, err) { denied(err); };',
      '        navigator.geolocation.watchPosition = function (_ok, err) { denied(err); return 0; };',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      if (navigator.mediaDevices) {',
      '        if (navigator.mediaDevices.getUserMedia) {',
      '          navigator.mediaDevices.getUserMedia = function () {',
      '            report("privacy");',
      '            return Promise.reject(new Error("ScriptGuard: camera/microphone are disabled in MAXIMUM mode."));',
      '          };',
      '        }',
      '        if (navigator.mediaDevices.getDisplayMedia) {',
      '          navigator.mediaDevices.getDisplayMedia = function () {',
      '            report("privacy");',
      '            return Promise.reject(new Error("ScriptGuard: screen capture is disabled in MAXIMUM mode."));',
      '          };',
      '        }',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      if ("gpu" in navigator) {',
      '        Object.defineProperty(navigator, "gpu", { get: function () { return undefined; }, configurable: true });',
      '      }',
      '    } catch (e) {}',
      '    try {',
      '      Object.defineProperty(document, "cookie", { get: function () { return ""; }, set: function () {}, configurable: true });',
      '    } catch (e) {}',
      '    try {',
      '      Object.defineProperty(document, "referrer", { get: function () { return ""; }, configurable: true });',
      '    } catch (e) {}',
      '    try {',
      '      var origNow = keep("perfNow", W.performance.now.bind(W.performance));',
      '      W.performance.now = function () { return Math.round(origNow() / 100) * 100; };',
      '    } catch (e) {}',
      '    try {',
      '      var origGetContext = keep("getContext", HTMLCanvasElement.prototype.getContext);',
      '      HTMLCanvasElement.prototype.getContext = function (t) {',
      '        if (/^webgl2?$/i.test(String(t || ""))) {',
      '          report("fingerprint");',
      '          fpMsg(true);',
      '          return null;',
      '        }',
      '        return origGetContext.apply(this, arguments);',
      '      };',
      '    } catch (e) {}',
      '    try {',
      '      var origWinOpen = keep("open", W.open);',
      '      W.open = function () {',
      '        report("popup");',
      '        logOnce("popup", "ScriptGuard: window.open blocked in MAXIMUM mode.");',
      '        return null;',
      '      };',
      '    } catch (e) {}',
      '  }',
      // ---- Global Privacy Control signal ----
      '  try {',
      '    Object.defineProperty(Navigator.prototype, "globalPrivacyControl", { get: function () { return !!S.flags.gpc; }, configurable: true });',
      '  } catch (e) {}',
      // ---- Fingerprinting: canvas ----
      // Noise is a PURE function of (session seed, pixel index): two reads
      // of the same canvas always match (anti-bot detection looks for
      // mismatched readbacks), yet the pattern changes every session.
      '  function noiseByte(seed, i) {',
      '    var x = (Math.imul(seed ^ i, 2654435761) >>> 0);',
      '    x = (Math.imul(x ^ (x >>> 13), 1597334677) >>> 0);',
      '    return x / 4294967296;',
      '  }',
      '  function noiseImage(data) {',
      '    for (var i = 0; i < data.length; i += 4) {',
      '      if (noiseByte(S.seed, i) < 0.12) {',
      '        data[i] = (data[i] + (noiseByte(S.seed + 1, i) < 0.5 ? 1 : -1)) & 255;',
      '      }',
      '    }',
      '  }',
      '  function fpMsg(del) {',
      '    logOnce("fp", del ?',
      '      "ScriptGuard: fingerprint request deleted before execution." :',
      '      "ScriptGuard: fingerprint request spoofed before execution.");',
      '  }',
      '  try {',
      '    var origToDataURL = keep("toDataURL", HTMLCanvasElement.prototype.toDataURL);',
      '    HTMLCanvasElement.prototype.toDataURL = function () {',
      '      var level = S.flags.fingerprint || "off";',
      '      if (level === "off") return origToDataURL.apply(this, arguments);',
      '      report("fingerprint");',
      '      fpMsg(level === "null");',
      '      if (level === "null") return "data:,";',
      '      try {',
      '        if (this.width && this.height) {',
      '          var tmp = document.createElement("canvas");',
      '          tmp.width = this.width; tmp.height = this.height;',
      '          var tctx = tmp.getContext("2d");',
      '          if (tctx) {',
      '            tctx.drawImage(this, 0, 0);',
      '            var img = tctx.getImageData(0, 0, tmp.width, tmp.height);',
      '            noiseImage(img.data);',
      '            tctx.putImageData(img, 0, 0);',
      '            return origToDataURL.apply(tmp, arguments);',
      '          }',
      '        }',
      '      } catch (e) {}',
      '      return origToDataURL.apply(this, arguments);',
      '    };',
      '  } catch (e) {}',
      '  try {',
      '    var origToBlob = keep("toBlob", HTMLCanvasElement.prototype.toBlob);',
      '    HTMLCanvasElement.prototype.toBlob = function (cb) {',
      '      var level = S.flags.fingerprint || "off";',
      '      if (level === "off") return origToBlob.apply(this, arguments);',
      '      report("fingerprint");',
      '      fpMsg(level === "null");',
      '      if (level === "null") {',
      '        var blank = document.createElement("canvas");',
      '        blank.width = 1; blank.height = 1;',
      '        return origToBlob.apply(blank, arguments);',
      '      }',
      '      try {',
      '        if (this.width && this.height) {',
      '          var tmp = document.createElement("canvas");',
      '          tmp.width = this.width; tmp.height = this.height;',
      '          var tctx = tmp.getContext("2d");',
      '          if (tctx) {',
      '            tctx.drawImage(this, 0, 0);',
      '            var img = tctx.getImageData(0, 0, tmp.width, tmp.height);',
      '            noiseImage(img.data);',
      '            tctx.putImageData(img, 0, 0);',
      '            return origToBlob.apply(tmp, arguments);',
      '          }',
      '        }',
      '      } catch (e) {}',
      '      return origToBlob.apply(this, arguments);',
      '    };',
      '  } catch (e) {}',
      '  try {',
      '    var origGID = keep("getImageData", CanvasRenderingContext2D.prototype.getImageData);',
      '    CanvasRenderingContext2D.prototype.getImageData = function () {',
      '      var img = origGID.apply(this, arguments);',
      '      var level = S.flags.fingerprint || "off";',
      '      if (level === "off") return img;',
      '      report("fingerprint");',
      '      fpMsg(level === "null");',
      '      if (level === "null") { if (img && img.data) img.data.fill(0); }',
      '      else if (img && img.data) noiseImage(img.data);',
      '      return img;',
      '    };',
      '  } catch (e) {}',
      // ---- Fingerprinting: text metrics ----
      '  try {',
      '    var origMT = keep("measureText", CanvasRenderingContext2D.prototype.measureText);',
      '    CanvasRenderingContext2D.prototype.measureText = function () {',
      '      var m = origMT.apply(this, arguments);',
      '      var level = S.flags.fingerprint || "off";',
      '      if (level !== "off" && m && typeof m.width === "number") {',
      '        var t = String(arguments[0] || "");',
      '        var h = 0;',
      '        for (var q = 0; q < t.length; q++) h = (Math.imul(h ^ t.charCodeAt(q), 2654435761) >>> 0);',
      '        m.width += (noiseByte(S.seed ^ h, 0) - 0.5) * 0.05;',
      '      }',
      '      return m;',
      '    };',
      '  } catch (e) {}',
      // ---- Fingerprinting: WebGL ----
      '  try {',
      '    function patchGetParameter(proto) {',
      '      if (!proto || !proto.getParameter) return;',
      '      var orig = keep("getParameter_" + (proto === WebGLRenderingContext.prototype ? "gl1" : "gl2"), proto.getParameter);',
      '      proto.getParameter = function (p) {',
      '        var level = S.flags.fingerprint || "off";',
      '        if (level !== "off" && (p === 37445 || p === 37446)) {',
      '          report("fingerprint");',
      '          fpMsg(level === "null");',
      '          if (level === "null") return null;',
      '          return p === 37445 ? "Mozilla - ScriptGuard" : "ScriptGuard Protected Renderer";',
      '        }',
      '        return orig.apply(this, arguments);',
      '      };',
      '    }',
      '    function patchGetExtension(proto) {',
      '      if (!proto || !proto.getExtension) return;',
      '      var orig = keep("getExtension_" + (proto === WebGLRenderingContext.prototype ? "gl1" : "gl2"), proto.getExtension);',
      '      proto.getExtension = function (name) {',
      '        var level = S.flags.fingerprint || "off";',
      '        if (level !== "off" && /WEBGL_debug_renderer_info/i.test(String(name || ""))) {',
      '          report("fingerprint");',
      '          return null;',
      '        }',
      '        return orig.apply(this, arguments);',
      '      };',
      '    }',
      '    if (W.WebGLRenderingContext) { patchGetParameter(W.WebGLRenderingContext.prototype); patchGetExtension(W.WebGLRenderingContext.prototype); }',
      '    if (W.WebGL2RenderingContext) { patchGetParameter(W.WebGL2RenderingContext.prototype); patchGetExtension(W.WebGL2RenderingContext.prototype); }',
      '  } catch (e) {}',
      // ---- Fingerprinting: audio ----
      '  try {',
      '    var Ctx = W.AudioContext || W.webkitAudioContext;',
      '    var OffCtx = W.OfflineAudioContext || W.webkitOfflineAudioContext;',
      '    if (Ctx) {',
      '      var origCtx = keep("AudioContext", Ctx);',
      '      var GuardedAudio = function () {',
      '        if (S.flags.maximum) {',
      '          report("fingerprint");',
      '          fpMsg(true);',
      '          throw new Error("ScriptGuard: audio fingerprinting disabled (MAXIMUM mode).");',
      '        }',
      '        return new origCtx(arguments[0] !== undefined ? arguments[0] : undefined);',
      '      };',
      '      GuardedAudio.prototype = origCtx.prototype;',
      '      W.AudioContext = GuardedAudio;',
      '      if (W.webkitAudioContext) W.webkitAudioContext = GuardedAudio;',
      '    }',
      '    if (OffCtx) {',
      '      var origOff = keep("OfflineAudioContext", OffCtx);',
      '      var GuardedOff = function () {',
      '        if (S.flags.maximum) {',
      '          report("fingerprint");',
      '          fpMsg(true);',
      '          throw new Error("ScriptGuard: audio fingerprinting disabled (MAXIMUM mode).");',
      '        }',
      '        return new (Function.prototype.bind.apply(origOff, [null].concat(Array.prototype.slice.call(arguments))));',
      '      };',
      '      GuardedOff.prototype = origOff.prototype;',
      '      W.OfflineAudioContext = GuardedOff;',
      '      if (W.webkitOfflineAudioContext) W.webkitOfflineAudioContext = GuardedOff;',
      '    }',
      '    if (W.AudioBuffer && W.AudioBuffer.prototype && W.AudioBuffer.prototype.getChannelData) {',
      '      var origGCD = keep("getChannelData", W.AudioBuffer.prototype.getChannelData);',
      '      W.AudioBuffer.prototype.getChannelData = function () {',
      '        var arr = origGCD.apply(this, arguments);',
      '        var level = S.flags.fingerprint || "off";',
      '        if (level === "off") return arr;',
      '        report("fingerprint");',
      '        fpMsg(level === "null");',
      '        if (level === "null") { for (var j = 0; j < arr.length; j++) arr[j] = 0; return arr; }',
      '        for (var i = 0; i < arr.length; i++) {',
      '          arr[i] += (noiseByte(S.seed + 2, i) - 0.5) * 1e-7;',
      '        }',
      '        return arr;',
      '      };',
      '    }',
      '  } catch (e) {}',
      '})();'
    ].join('\n');
  }

  /** Compute the current patch flags from config.
   *
   *  maximum     MAXIMUM mode nukes (eval, timers, cookie, sw, gpu, ...)
   *  webrtc/blob classic kill-switches (PRO + MAX, individually togglable)
   *  fingerprint 'off' | 'noise' (PRO: spoof, do not break) | 'null' (MAX)
   *  channel     network channel policy for WebSocket/EventSource:
   *              'off' | 'third' (third-party blocked, PRO) | 'block' (MAX)
   *  beacon      same policy for sendBeacon
   *  privacy     extra API hardening: 'off' | 'pro' | 'max'
   *  gpc         Global Privacy Control signal
   */
  function currentPatchFlags() {
    const mode = config.mode;
    const armed = mode === 'PRO' || mode === 'MAXIMUM';
    return {
      maximum: mode === 'MAXIMUM',
      webrtc: armed && !!(config.shields && config.shields.webrtc),
      blob: armed && !!(config.shields && config.shields.blob),
      fingerprint: mode === 'MAXIMUM' ? 'null' : mode === 'PRO' ? 'noise' : 'off',
      channel: mode === 'MAXIMUM' ? 'block' : armed ? 'third' : 'off',
      beacon: mode === 'MAXIMUM' ? 'block' : armed ? 'third' : 'off',
      privacy: mode === 'MAXIMUM' ? 'max' : armed ? 'pro' : 'off',
      gpc: !!(config.firewall && config.firewall.gpc)
    };
  }

  /** Human-readable fingerprint level for the popup / report. */
  function fingerprintLevel() {
    return currentPatchFlags().fingerprint;
  }

  let dispatcherInjected = false;

  function updatePageFlags() {
    const flags = currentPatchFlags();
    if (!dispatcherInjected) {
      if (config.mode === 'OFF' || !settingsReady) return; // stay invisible
      dispatcherInjected = true;
      injectPatch(buildDispatcherCode(flags));
      return;
    }
    // Already dispatched: push the new flags into the page world.
    try {
      window.dispatchEvent(new CustomEvent('__scriptguard_flags', { detail: flags }));
    } catch (e) { /* page world gone */ }
  }

  function injectPatch(code) {
    const target = document.head || document.documentElement;
    if (!target) {
      // Extremely early - retry once the DOM exists.
      document.addEventListener('DOMContentLoaded', function () { injectPatch(code); });
      return;
    }
    try {
      const s = document.createElement('script');
      s.setAttribute(HELPER_ATTR, '1');
      s.textContent = code;
      target.appendChild(s);
      s.remove();
    } catch (e) {
      // A strict CSP can block inline scripts. Best effort only -
      // this is documented as a limitation of the page-world patch.
    }
  }

  /** Probes reported by the page world (counted for the popup/report). */
  const PROBE_COUNTER = {
    fingerprint: 'fingerprint',
    webrtc: 'webrtc',
    blob: 'blob',
    eval: 'eval',
    popup: 'popup',
    channel: 'channel',
    privacy: 'privacy'
  };

  window.addEventListener('message', function (event) {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || typeof d !== 'object' || typeof d.__scriptguard_probe !== 'string') return;
    const key = PROBE_COUNTER[d.__scriptguard_probe];
    if (key && typeof report.counters[key] === 'number') {
      report.counters[key] += 1;
    }
  });

  /* ===================================================================
   * 8. Reporting (what the popup and the badge display)
   * =================================================================== */

  const report = {
    deleted: [],   // { type, name, pattern, reason, late }
    allowedCount: 0,
    counters: { fingerprint: 0, webrtc: 0, blob: 0, eval: 0, popup: 0, channel: 0, privacy: 0, ad: 0 },
    heuristicDetections: [] // { pattern, name, signals } - reported, not deleted (BASIC)
  };

  /** Record an ad node (iframe/img) removed from the DOM. */
  function recordAd(el) {
    const src = el.src || '(no src)';
    report.deleted.push({
      type: 'ad',
      name: src,
      pattern: (() => {
        try { const u = new URL(src, location.href); u.search = ''; u.hash = ''; return u.href; }
        catch (e) { return String(src); }
      })(),
      reason: 'ad network request',
      late: false
    });
    report.counters.ad += 1;
    bumpStats(1);
    scheduleBadge();
  }

  function recordDeleted(el, verdict, late) {
    report.deleted.push({
      type: isExternal(el) ? 'external' : 'inline',
      name: describeScript(el),
      pattern: verdict.pattern,
      reason: verdict.reason,
      late: !!late
    });
    // Heuristic learning: a suspicious third-party script that was just
    // deleted in PRO is learned into the heuristic rules, so the
    // detection is visible, auditable and exportable.
    if (config.mode === 'PRO' && verdict.reason === 'third-party script' && isExternal(el)) {
      const scan = heuristicScan(el);
      if (scan) {
        learnHeuristic(verdict.pattern, scan.signals);
        report.heuristicDetections.push({
          pattern: verdict.pattern,
          name: describeScript(el),
          signals: scan.signals
        });
      }
    }
    bumpStats(1);
    scheduleBadge();
  }

  let badgeTimer = null;
  function scheduleBadge() {
    if (badgeTimer) return;
    badgeTimer = setTimeout(function () {
      badgeTimer = null;
      try {
        const p = browser.runtime.sendMessage({
          type: 'sb:blockedCount',
          count: report.deleted.length
        });
        if (p && typeof p.catch === 'function') p.catch(function () { /* popup closed etc. */ });
      } catch (e) { /* context invalidated during navigation */ }
    }, 400);
  }

  /** Snapshot of every script we know about on this page right now. */
  function listPageScripts() {
    const seen = Object.create(null);
    const list = [];

    // Scripts already deleted this page load.
    for (const d of report.deleted) {
      if (seen[d.pattern]) continue;
      seen[d.pattern] = true;
      list.push({
        type: d.type,
        name: d.name,
        pattern: d.pattern,
        status: 'blocked',
        reason: d.reason
      });
    }

    // Scripts currently in the DOM (ran, pending, or whitelisted).
    const wl = patternsFor('whitelist').concat(config.globalWhitelist || []);
    for (const el of Array.prototype.slice.call(document.scripts || [])) {
      let pattern = '';
      try { pattern = patternForScript(el); } catch (e) { continue; }
      if (!pattern || seen[pattern]) continue;
      seen[pattern] = true;

      let status = executedScripts.has(el) ? 'executed' : 'pending';
      if (config.mode !== 'OFF' && patternMatches(wl, el, pattern)) {
        status = 'whitelisted';
      }
      const entry = {
        type: isExternal(el) ? 'external' : 'inline',
        name: describeScript(el),
        pattern: pattern,
        status: status,
        reason: ''
      };
      // Surface heuristic detections on scripts that survived (BASIC):
      // reported so the user can decide, never auto-deleted here.
      if (status !== 'whitelisted' && isExternal(el) &&
          !sameSite(hostOf(el.src), pageHost())) {
        const scan = heuristicScan(el);
        if (scan) {
          entry.heuristics = scan.signals;
          if (config.mode === 'BASIC') {
            let already = false;
            for (const h of report.heuristicDetections) {
              if (h.pattern === pattern) { already = true; break; }
            }
            if (!already) {
              report.heuristicDetections.push({
                pattern: pattern,
                name: entry.name,
                signals: scan.signals
              });
            }
          }
        }
      }
      list.push(entry);
    }
    return list;
  }

  /* ===================================================================
   * 9. Messaging API (used by popup.js)
   * =================================================================== */

  browser.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (!msg || typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'sb:getReport': {
        // Synchronous snapshot of this frame (popup talks to the top frame).
        sendResponse({
          ok: true,
          frame: window.top === window ? 'top' : 'iframe',
          report: {
            mode: config.mode,
            domain: pageHost(),
            deleted: report.deleted,
            allowedCount: report.allowedCount,
            counters: report.counters,
            shields: currentPatchFlags(),
            fingerprintLevel: fingerprintLevel(),
            heuristicDetections: report.heuristicDetections
          },
          scripts: listPageScripts()
        });
        return; // sync response, channel can close
      }

      case 'sb:remember': {
        // msg.patterns: [{ pattern, label }]
        const respond = async function () {
          const items = Array.isArray(msg.patterns) ? msg.patterns : [];
          for (const item of items) {
            if (item && item.pattern) {
              await addPattern('rules', item.pattern, item.label || '');
            }
          }
          sweepPendingScripts(); // delete matching scripts that have not run yet
          sendResponse({ ok: true });
        };
        respond();
        return true; // keep the channel open for the async response
      }

      case 'sb:whitelist': {
        const respond = async function () {
          const items = Array.isArray(msg.patterns) ? msg.patterns : [];
          for (const item of items) {
            if (item && item.pattern) {
              await addPattern('whitelist', item.pattern, item.label || '');
            }
          }
          sendResponse({ ok: true });
        };
        respond();
        return true;
      }

      case 'sb:removeRule': {
        const respond = async function () {
          if (msg.pattern) await removePattern('rules', msg.pattern);
          sendResponse({ ok: true });
        };
        respond();
        return true;
      }

      case 'sb:removeWhitelist': {
        const respond = async function () {
          if (msg.pattern) await removePattern('whitelist', msg.pattern);
          sendResponse({ ok: true });
        };
        respond();
        return true;
      }

      case 'sb:resetSite': {
        const respond = async function () {
          await resetSite();
          sendResponse({ ok: true });
        };
        respond();
        return true;
      }
    }
  });

  /* ===================================================================
   * 10. Boot sequence
   * =================================================================== */

  // Load real settings as fast as possible.
  browser.storage.local.get(SETTING_KEYS).then(function (snapshot) {
    if (typeof snapshot.mode === 'string' && snapshot.mode) {
      config.mode = snapshot.mode;
    }
    for (const key of ['rules', 'whitelist', 'labels', 'stats', 'heuristics', 'shields']) {
      if (snapshot[key] && typeof snapshot[key] === 'object') {
        config[key] = snapshot[key];
      }
    }
    if (snapshot.firewall && typeof snapshot.firewall === 'object') {
      config.firewall = Object.assign(
        { adBlockMode: 'armed', stripTracking: true, gpc: true, autoWipe: false },
        snapshot.firewall
      );
    }
    if (Array.isArray(snapshot.trustedSites)) {
      config.trustedSites = snapshot.trustedSites;
    }
    if (Array.isArray(snapshot.globalWhitelist)) {
      config.globalWhitelist = snapshot.globalWhitelist;
    }
    if (Array.isArray(snapshot.regexRules)) {
      config.regexRules = snapshot.regexRules;
    }
    settingsReady = true;
    sweepDocument();         // scripts + ads + (MAX) inline handlers
    updatePageFlags();       // inject dispatcher / push new flags
  }).catch(function () {
    settingsReady = true;    // fail open, never half-configured
  });

  // Live-apply settings changed from the popup while a page is open.
  browser.storage.onChanged.addListener(function (changes, area) {
    if (area !== 'local') return;
    for (const key of SETTING_KEYS) {
      if (changes[key]) {
        const v = changes[key].newValue;
        if (key === 'trustedSites' || key === 'globalWhitelist' || key === 'regexRules') {
          config[key] = Array.isArray(v) ? v : [];
        } else if (key === 'mode') {
          config[key] = typeof v === 'string' && v ? v : 'BASIC';
        } else if (key === 'shields') {
          config[key] = v && typeof v === 'object'
            ? { webrtc: v.webrtc !== false, blob: v.blob !== false }
            : { webrtc: true, blob: true };
        } else if (key === 'firewall') {
          config[key] = Object.assign(
            { adBlockMode: 'armed', stripTracking: true, gpc: true, autoWipe: false },
            v && typeof v === 'object' ? v : {}
          );
        } else {
          config[key] = v && typeof v === 'object' ? v : {};
        }
      }
    }
    if (changes.mode || changes.shields || changes.firewall) updatePageFlags();
    sweepDocument();
  });
})();
