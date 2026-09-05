# ScriptGuard

**Open-Source Privacy Shield & Script Control Extension**

ScriptGuard deletes scripts from pages **BEFORE they execute** — and stacks a
full privacy shield on top: an ad & tracker firewall at the network layer, a
WebRTC/Blob kill-switch, fingerprint request deletion, tracking-URL stripping,
GPC signals and an optional auto-wipe. No telemetry, GPLv3 licensed.

- **Repository:** <https://github.com/TuffyCoder/ScriptGuard>
- **YouTube:** <https://www.youtube.com/@TuffyCoder>
- **Reddit:** <https://reddit.com/user/FrostByteCreator>
- **TikTok:** <https://tiktok.com/TuffyCoderdev>

---

## What it does

### Script deletion (the core)

ScriptGuard hooks Gecko's `beforescriptexecute` event, which fires
synchronously for *every* script about to execute — parser-inserted,
`document.write()` and dynamically injected alike. A `MutationObserver`
backup sweep catches anything pending. Deleted scripts never run.

### Four privacy modes (toolbar icon color follows the mode)

| Mode | Toolbar icon | Behaviour |
| --- | --- | --- |
| **OFF** | gray | Nothing is touched. |
| **BASIC** | green | Remembered rules + your regex rules, plus the ad & tracker firewall and tracking-URL stripping. |
| **PRO** | yellow | Strong but usable: BASIC + heuristics + trackers + **all third-party scripts**, spoofed fingerprints, cross-site channels blocked. Honours whitelists. |
| **MAXIMUM** | red | Nuclear: deletes **ALL** scripts, strips inline handlers, kills eval/cookies/WebRTC/WebGPU/service workers/geolocation/camera/popups, blocks every channel. Ignores whitelists. |

### Ad & tracker firewall (the ad blocker)

A blocking `webRequest` firewall cancels requests to known ad and tracker
infrastructure **before anything is downloaded** — ad iframes, banner
networks, native-ad widgets, retargeting pixels and analytics beacons. On top
of that the content script tears the corresponding ad iframes/images out of
the DOM, so empty ad boxes collapse instead of leaving holes.

- Two arming levels: **block in BASIC, PRO & MAX** (default) or **do not block**.
  Only OFF mode silences the firewall — ads are gone in every active mode.
- `<a ping>` hyperlink auditing is always blocked while the firewall is armed.
- Per-tab and all-time per-site counters are shown in the popup.

### Privacy extras

- **Tracking-URL stripping** — `utm_*`, `fbclid`, `gclid`, `msclkid`,
  `twclid`, `mc_eid`, `_ga`, `yclid`, `spm` and ~60 more click-identifiers
  are removed from navigated URLs before the page sees them.
- **GPC + DNT headers** — every outgoing request carries
  `Sec-GPC: 1` and `DNT: 1`, and `navigator.globalPrivacyControl` reads
  `true` in the page. Tell every site you visit that you do not consent to
  sale/share of your data.
- **Auto-wipe (opt-in)** — when a tab closes, the site's cookies,
  localStorage, IndexedDB, service workers and storage cache are deleted.
  Sites forget you the moment you leave them.

### Rule layers

- **Remembered rules** — delete a script once ("Delete & Remember") and it is
  re-deleted on every future visit to that site.
- **Global whitelist** — patterns allowed on *every* site. Overrides BASIC and
  PRO. Does **not** override MAXIMUM.
- **Per-site whitelist** — patterns allowed for one domain ("Always allow").
  Overrides BASIC and PRO. Does **not** override MAXIMUM.
- **Regex rules** — user-supplied `RegExp` sources (case-insensitive).
  Matching scripts are deleted in BASIC and PRO.
- **Heuristic learning** — third-party scripts showing ≥2 suspicious signals
  (WebRTC IP discovery, canvas/WebGL/audio fingerprinting, beacons, cookie
  access, device probing) are learned into per-site heuristic rules in PRO.
  Heuristics **never** auto-delete in BASIC; detections are reported instead.
- **Trust switch** — a per-domain master bypass that wins in every mode.

### Privacy Shields (PRO + MAXIMUM)

- **WebRTC kill-switch** — `RTCPeerConnection` throws, so ICE/STUN candidate
  gathering can never leak your local IPs. Logged:
  `ScriptGuard: WebRTC disabled to prevent IP leaks.`
- **Blob kill-switch** — `URL.createObjectURL` returns a dead URL for
  JavaScript blobs and `blob:` workers are refused. Logged:
  `ScriptGuard: Blob scripts blocked.`
- **Fingerprint request deletion** — before the request happens:
  - PRO (spoof, do **not** break): canvas `toDataURL`/`toBlob`/`getImageData`
    get seeded noise, text metrics get microscopic jitter, WebGL
    renderer/vendor are spoofed and the `WEBGL_debug_renderer_info`
    extension returns `null`, audio buffers get tiny noise. The noise is
    **session-stable**: consistent within one page load, different in the
    next session — your device cannot be tracked across sessions by it.
  - MAXIMUM (delete): canvas readbacks return empty values, WebGL contexts
    return `null`, `getParameter` returns `null`,
    `AudioContext`/`OfflineAudioContext` throw.
  - Logged: `ScriptGuard: fingerprint request deleted before execution.`
- **Cross-site channels** — PRO blocks third-party `WebSocket`,
  `EventSource` and `sendBeacon` (tracking + exfiltration channels);
  MAXIMUM blocks them all.
- **Privacy API hardening** (PRO + MAXIMUM) — battery status reports a
  generic full battery, `navigator.connection` is gone, speech voices are
  reduced to one, storage quota is generic, CPU/RAM counts are fixed at 4/8,
  device enumeration returns an empty list. Every user looks identical.
- **MAXIMUM nukes** — on top of deleting every script: inline `on*=` handlers
  and `javascript:` links are stripped from the DOM, `eval`/`Function`/
  string timers are neutered, `document.cookie` and `document.referrer` are
  sealed, service-worker registration is refused, geolocation/camera/mic/
  screen-capture throw, `navigator.gpu` is gone, `performance.now` ticks in
  100 ms steps, and `window.open` returns `null`.
- Shields arm automatically in PRO and MAXIMUM and are toggleable in the popup.

### Public IP exposure (read this)

ScriptGuard blocks **browser-level** IP leaks (WebRTC, blob workers,
fingerprint-based inference) and warns you in the popup — but it **cannot**
hide or spoof your public IP. Only a **VPN, Tor or a proxy** can do that.

### Report

"Generate report" in the popup builds a plain-text report (mode, deleted
scripts, whitelists, regex rules, heuristic detections, shield status,
firewall stats, probe counters). You copy/paste it manually — **nothing is
ever sent anywhere**.

---

## Storage schema (browser.storage.local)

```json
{
  "mode": "PRO",
  "rules":         { "example.com": ["https://cdn.example.net/tracker.js"] },
  "whitelist":     { "example.com": ["https://cdn.jsdelivr.net/npm/jquery@3.7.1.min.js"] },
  "globalWhitelist": ["*cdn.example.net/*"],
  "regexRules":    ["analytics|telemetry"],
  "heuristics":    { "example.com": ["https://ads.partner-net.io/fp.js"] },
  "shields":       { "webrtc": true, "blob": true },
  "firewall":      { "adBlockMode": "armed", "stripTracking": true, "gpc": true, "autoWipe": false },
  "labels":        {},
  "trustedSites":  [],
  "stats":         { "example.com": 42 },
  "netStats":      { "example.com": 137 }
}
```

Export writes this document as JSON; import union-merges it back.

## Install (Firefox)

1. Download or clone this repository.
2. Open `about:debugging#/runtime/this-firefox`.
3. "Load Temporary Add-on…" → pick `manifest.json`.
4. The toolbar icon appears (green = BASIC). Click it to switch modes.

## Icons

The mode icons are generated by a pure-Pillow script (no network, no assets):
same shield in every theme, only the background colour changes — gray OFF,
green BASIC, yellow PRO, red MAXIMUM. The generator lives OUTSIDE the add-on
package (`../scriptguard-tools/generate_icons.py`) so no script files ship
inside the extension. Rebuild with:

    python3 ../scriptguard-tools/generate_icons.py icons

## Honest limitations

- The settings cache is asynchronous: for a few milliseconds on a cold start
  ScriptGuard fails **open** (never deletes) rather than break a page.
- Base-domain detection is the naive "last two labels" rule — `co.uk`-style
  public suffixes are not handled.
- A strict CSP can block the page-world dispatcher script; in that case the
  MAXIMUM `eval` patch and the page-world shields cannot arm on that page.
  The script deletion, ad firewall and header-level protections still work.
- MAXIMUM mode breaks most sites by design. Whitelists are ignored there.
- WebAssembly and browser-internal network requests are outside the reach of
  DOM-level deletion; the network firewall does not see requests made by the
  browser itself (safebrowsing, new-tab feeds, etc.).
- The ad firewall blocks domains from a curated static list. It is auditable
  and tunable, but not a filter-list subscription service.

## License

GPLv3 — see [LICENSE](LICENSE).
