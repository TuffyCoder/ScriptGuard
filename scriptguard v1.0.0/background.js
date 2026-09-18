/**
 * ScriptGuard - persistent background page.
 *
 * The background page owns the network firewall because content scripts cannot
 * cancel requests before they leave the browser. It also keeps lightweight
 * per-tab/site counters and handles rules export/import.
 */
'use strict';

const DEFAULT_FIREWALL = {
  adBlockMode: 'armed',
  stripTracking: true,
  gpc: true,
  autoWipe: false
};

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

const AD_PATH = /\/(pagead|adsbygoogle|adserver|adframe|advert|popunder|prebid(?:\.js|-)|pubads|tag\/js\/gpt|bannerad|interstitial)/i;
const TRACKING_PARAMS = /^(utm_[a-z0-9_]+|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|_ga|_gl|yclid|zanpid|igshid|vero_id|vero_conv|s_kwcid)$/i;
const tabStats = new Map();
const siteStats = Object.create(null);
const openTabs = new Map();
let storageStatsSave = null;

function getFirewall() {
  return browser.storage.local.get(['mode', 'firewall']).then((res) => ({
    mode: typeof res.mode === 'string' ? res.mode : 'BASIC',
    firewall: Object.assign({}, DEFAULT_FIREWALL, res.firewall || {})
  }));
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

function baseDomain(host) {
  const parts = String(host || '').split('.').filter(Boolean);
  return parts.length <= 2 ? parts.join('.') : parts.slice(-2).join('.');
}

function isAdUrl(url) {
  const host = hostOf(url);
  if (!host) return false;
  if (AD_HOSTS.some((ad) => host === ad || host.endsWith('.' + ad))) return true;
  try {
    const parsed = new URL(url);
    return AD_PATH.test(parsed.pathname) && baseDomain(host) !== baseDomain(hostOf(parsed.origin));
  } catch (e) {
    return false;
  }
}

function shouldFirewallBlock(details, mode, firewall) {
  if (mode === 'OFF' || firewall.adBlockMode === 'off') return false;
  if (!details || !details.url || !/^https?:/i.test(details.url)) return false;
  return isAdUrl(details.url);
}

function increment(details, url) {
  const tabId = details.tabId;
  const host = baseDomain(hostOf(url));
  if (tabId >= 0) tabStats.set(tabId, (tabStats.get(tabId) || 0) + 1);
  if (host) siteStats[host] = (siteStats[host] || 0) + 1;
  scheduleStatsSave();
}

function scheduleStatsSave() {
  if (storageStatsSave) return;
  storageStatsSave = setTimeout(() => {
    storageStatsSave = null;
    browser.storage.local.set({ networkStats: siteStats }).catch(() => {});
  }, 1000);
}

function stripTracking(url) {
  try {
    const parsed = new URL(url);
    let changed = false;
    for (const key of Array.from(parsed.searchParams.keys())) {
      if (TRACKING_PARAMS.test(key)) {
        parsed.searchParams.delete(key);
        changed = true;
      }
    }
    return changed ? parsed.toString() : null;
  } catch (e) {
    return null;
  }
}

function requestHeaders(details) {
  return getFirewall().then(({ firewall }) => {
    if (!firewall.gpc) return {};
    const requestHeaders = details.requestHeaders || [];
    const set = (name, value) => {
      const existing = requestHeaders.find((h) => h.name.toLowerCase() === name.toLowerCase());
      if (existing) existing.value = value;
      else requestHeaders.push({ name, value });
    };
    set('DNT', '1');
    set('Sec-GPC', '1');
    return { requestHeaders };
  }).catch(() => ({}));
}

function onBeforeRequest(details) {
  return getFirewall().then(({ mode, firewall }) => {
    if (shouldFirewallBlock(details, mode, firewall)) {
      increment(details, details.url);
      return { cancel: true };
    }
    if (firewall.stripTracking && /^(http|https):/i.test(details.url)) {
      const redirectUrl = stripTracking(details.url);
      if (redirectUrl) return { redirectUrl };
    }
    return {};
  }).catch(() => ({}));
}

browser.webRequest.onBeforeRequest.addListener(
  onBeforeRequest,
  { urls: ['<all_urls>'] },
  ['blocking']
);

browser.webRequest.onBeforeSendHeaders.addListener(
  requestHeaders,
  { urls: ['<all_urls>'] },
  ['blocking', 'requestHeaders']
);

browser.tabs.onCreated.addListener((tab) => {
  if (tab && tab.id !== undefined) openTabs.set(tab.id, tab.url || '');
});

browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) openTabs.set(tabId, changeInfo.url);
});

browser.tabs.onRemoved.addListener((tabId) => {
  tabStats.delete(tabId);
  const url = openTabs.get(tabId) || '';
  openTabs.delete(tabId);
  getFirewall().then(({ firewall }) => {
    if (!firewall.autoWipe) return;
    const host = hostOf(url);
    if (!host) return;
    return browser.browsingData.remove({}), browser.browsingData.removeHost(host, {
      cookies: true, cache: true, localStorage: true, indexedDB: true,
      serviceWorkers: true, pluginData: true, downloads: false,
      formData: false, passwords: false, webSQL: true
    });
  }).catch(() => {});
});

browser.runtime.onMessage.addListener((message) => {
  if (!message || typeof message.type !== 'string') return undefined;
  if (message.type === 'sb:getNetStats') {
    const tabId = Number.isInteger(message.tabId) ? message.tabId : -1;
    return Promise.resolve({
      ok: true,
      tabBlocked: tabStats.get(tabId) || 0,
      siteBlocked: Object.values(siteStats).reduce((sum, n) => sum + n, 0)
    });
  }
  if (message.type === 'sb:export') {
    return browser.storage.local.get(null).then((data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      return browser.downloads ? browser.downloads.download({
        url: URL.createObjectURL(blob), filename: 'scriptguard-rules.json', saveAs: true
      }).then(() => ({ ok: true })) : { ok: false, error: 'downloads permission unavailable' };
    });
  }
  if (message.type === 'sb:import' && message.data && typeof message.data === 'object') {
    const allowed = ['mode', 'rules', 'whitelist', 'trustedSites', 'labels', 'stats',
      'globalWhitelist', 'regexRules', 'heuristics', 'shields', 'firewall'];
    const patch = {};
    for (const key of allowed) if (Object.prototype.hasOwnProperty.call(message.data, key)) patch[key] = message.data[key];
    return browser.storage.local.set(patch).then(() => ({ ok: true }));
  }
  return undefined;
});

browser.storage.local.get('networkStats').then((res) => {
  if (res.networkStats && typeof res.networkStats === 'object') Object.assign(siteStats, res.networkStats);
}).catch(() => {});
