/* ScriptGuard website — small, dependency-free enhancements.
   Everything degrades gracefully without JS: the FAQ stays native
   <details>, the mode demo just keeps its default panel. */

(function () {
  'use strict';

  /* ---------- current year ---------- */
  var yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());

  /* ---------- mobile nav ---------- */
  var toggle = document.getElementById('navToggle');
  var links = document.getElementById('navLinks');
  if (toggle && links) {
    toggle.addEventListener('click', function () {
      var open = links.classList.toggle('is-open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    // close the menu after tapping a link
    links.addEventListener('click', function (ev) {
      if (ev.target && ev.target.tagName === 'A') {
        links.classList.remove('is-open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  /* ---------- header shadow on scroll ---------- */
  var header = document.querySelector('.site-header');
  if (header) {
    var onScroll = function () {
      header.classList.toggle('is-scrolled', window.scrollY > 8);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  /* ---------- interactive privacy-mode demo ---------- */
  var MODES = {
    OFF: {
      icon: 'mode-off.png',
      name: 'OFF — invisible',
      desc: 'ScriptGuard goes fully dormant: no deletion, no scanning, no firewall. Useful for debugging a site or comparing behaviour.',
      list: [
        '• Nothing is blocked or deleted',
        '• Firewall idle, GPC signal off',
        '• Original page behaviour, untouched'
      ]
    },
    BASIC: {
      icon: 'mode-basic.png',
      name: 'BASIC — light & safe',
      desc: 'Remembered rules + your regex rules — plus the ad & tracker firewall and tracking-URL stripping in every mode.',
      list: [
        '✓ Blocks ad & tracker requests on every site',
        '✓ Strips utm_*, fbclid, gclid from links',
        '✓ Sends GPC "do not sell" signal',
        '• Scripts: only ones you deleted before'
      ]
    },
    PRO: {
      icon: 'mode-pro.png',
      name: 'PRO — strong but usable',
      desc: 'Privacy-focused daily driver: all third-party scripts and trackers deleted, fingerprinting spoofed with session-stable noise, cross-site channels blocked — first-party sites keep working.',
      list: [
        '✓ Everything in BASIC',
        '✓ Deletes ALL third-party scripts & known trackers',
        '✓ Canvas / WebGL / audio fingerprints spoofed',
        '✓ WebRTC + Blob kill-switches armed',
        '✓ Cross-site WebSocket / sendBeacon blocked',
        '• Whitelists honoured for anything you allow'
      ]
    },
    MAXIMUM: {
      icon: 'mode-maximum.png',
      name: 'MAXIMUM — nuclear',
      desc: 'Deletes EVERY script, strips inline handlers, seals cookies & referrer, kills WebRTC, WebGPU, service workers, geolocation, camera, popups — and blocks every channel. Most sites will break by design.',
      list: [
        '✓ Everything in PRO',
        '✓ Deletes ALL scripts + inline on* handlers',
        '✓ Fingerprint requests deleted, not spoofed',
        '✓ Cookies & referrer sealed, timers coarsened',
        '✓ Service workers, WebGPU, camera, geolocation: gone',
        '! Use for untrusted sites only'
      ]
    }
  };

  var modeButtons = document.querySelectorAll('.mode-btn');
  var modeIcon = document.getElementById('modeIcon');
  var modeName = document.getElementById('modeName');
  var modeDesc = document.getElementById('modeDesc');
  var modeList = document.getElementById('modeList');

  function setMode(key) {
    var m = MODES[key];
    if (!m || !modeName) return;
    if (modeIcon) {
      modeIcon.src = m.icon;
      modeIcon.alt = 'ScriptGuard icon in ' + key + ' mode';
    }
    modeName.textContent = m.name;
    modeDesc.textContent = m.desc;
    if (modeList) {
      modeList.textContent = '';
      m.list.forEach(function (item) {
        var li = document.createElement('li');
        li.textContent = item;
        modeList.appendChild(li);
      });
    }
    modeButtons.forEach(function (b) {
      var active = b.dataset.mode === key;
      b.classList.toggle('is-active', active);
      b.setAttribute('aria-selected', active ? 'true' : 'false');
    });
  }

  modeButtons.forEach(function (btn) {
    btn.addEventListener('click', function () { setMode(btn.dataset.mode); });
  });
  if (modeButtons.length) setMode('BASIC');

  /* ---------- FAQ: keep one item open at a time ---------- */
  var faqs = document.querySelectorAll('details.faq');
  faqs.forEach(function (d) {
    d.addEventListener('toggle', function () {
      if (!d.open) return;
      faqs.forEach(function (other) {
        if (other !== d) other.open = false;
      });
    });
  });

  /* ---------- reveal-on-scroll (dwell-time nicety) ---------- */
  var revealTargets = document.querySelectorAll(
    '.feature-card, .psb, .chip-group, .author-card, .eeat-item, .mode-demo, .table-wrap'
  );
  revealTargets.forEach(function (el) { el.classList.add('reveal'); });
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    revealTargets.forEach(function (el) { io.observe(el); });
  } else {
    revealTargets.forEach(function (el) { el.classList.add('is-visible'); });
  }

  /* ---------- playful live counter in the hero ---------- */
  var demoCount = document.getElementById('demoCount');
  if (demoCount) {
    var base = 1024;
    setInterval(function () {
      base += Math.floor(Math.random() * 3);
      demoCount.textContent = base.toLocaleString('en-US');
    }, 2600);
  }
})();
