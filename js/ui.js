/* UI helpers: escaping, icons, toasts, popovers, modals, clipboard, formatting. No dependencies. */
(function (root) {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
  }

  var ICONS = {
    dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.6"/><rect x="14" y="3" width="7" height="5" rx="1.6"/><rect x="14" y="12" width="7" height="9" rx="1.6"/><rect x="3" y="16" width="7" height="5" rx="1.6"/>',
    navigator: '<circle cx="12" cy="12" r="9"/><path d="m15.6 8.4-2 5.2-5.2 2 2-5.2z"/>',
    incidents: '<path d="M12 3.5 2.8 19.5h18.4z"/><path d="M12 10v4"/><path d="M12 17h.01"/>',
    playbooks: '<rect x="4" y="3" width="16" height="18" rx="2.4"/><path d="m8 9 1.5 1.5L12 8M8 15l1.5 1.5L12 14M14.5 9.5H17M14.5 15.5H17"/>',
    analytics: '<path d="M4 20V11M10 20V4M16 20v-6M2 20h20"/>',
    hunt: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5.5 5.5"/>',
    coverage: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="m14.5 17.5 2 2 4-4"/>',
    hardening: '<path d="M12 3 4.5 6v6c0 4.7 3.2 7.7 7.5 9 4.3-1.3 7.5-4.3 7.5-9V6z"/><path d="m9 12 2 2 4-4"/>',
    assets: '<rect x="3" y="4" width="18" height="6.5" rx="1.8"/><rect x="3" y="13.5" width="18" height="6.5" rx="1.8"/><path d="M7 7.2h.01M7 16.8h.01"/>',
    reports: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
    settings: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5.5 5.5"/>',
    bell: '<path d="M6 16v-5a6 6 0 0 1 12 0v5l1.6 2H4.4z"/><path d="M10 21h4"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1.1 1-1.1 1.8M12 17h.01"/>',
    calendar: '<rect x="3.5" y="5" width="17" height="15.5" rx="2.4"/><path d="M8 3v4M16 3v4M3.5 10h17"/>',
    filter: '<path d="M4 6h16M7 12h10M10 18h4"/>',
    share: '<circle cx="6" cy="12" r="2.4"/><circle cx="17.5" cy="6" r="2.4"/><circle cx="17.5" cy="18" r="2.4"/><path d="m8.2 10.9 7.1-3.8M8.2 13.1l7.1 3.8"/>',
    download: '<path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 20h14"/>',
    rerun: '<path d="M20 11a8 8 0 1 0-2.4 5.7"/><path d="M20 4v7h-7"/>',
    more: '<path d="M5 12h.01M12 12h.01M19 12h.01"/>',
    chev: '<path d="m6 9 6 6 6-6"/>',
    check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    moon: '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4 8.5 8.5 0 1 0 20 14.5z"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    zap: '<path d="M13 2.5 4.5 13.5H12l-1 8 8.5-11H12z"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12h.01"/>',
    copy: '<rect x="8.5" y="8.5" width="12" height="12" rx="2.2"/><path d="M15.5 8.5V5.7A2.2 2.2 0 0 0 13.3 3.5H5.7A2.2 2.2 0 0 0 3.5 5.7v7.6a2.2 2.2 0 0 0 2.2 2.2h2.8"/>',
    link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1"/>',
    play: '<path d="M7 4.5v15l12-7.5z"/>',
    pause: '<path d="M8 5v14M16 5v14"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    upload: '<path d="M12 20V9M7.5 13.5 12 9l4.5 4.5M5 4h14"/>',
    trash: '<path d="M4 7h16M9 7V4.5h6V7M6.5 7l1 13h9l1-13"/>',
    shield: '<path d="M12 3 4.5 6v6c0 4.7 3.2 7.7 7.5 9 4.3-1.3 7.5-4.3 7.5-9V6z"/>',
    book: '<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15H6.5A2.5 2.5 0 0 0 4 20.5z"/><path d="M4 20.5A2.5 2.5 0 0 0 6.5 23H20"/>'
  };
  function icon(name, extra) {
    return '<svg class="i ' + (extra || '') + '" viewBox="0 0 24 24" aria-hidden="true">' + (ICONS[name] || ICONS.info) + '</svg>';
  }

  // ----- toasts -----
  function toast(msg, kind, ms) {
    var box = $('#toasts'); if (!box) return;
    var el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, ms || 3800);
  }

  // ----- popover -----
  function closePop() { var p = $('#pop'); if (p) p.innerHTML = ''; }
  function pop(anchor, html, opts) {
    var p = $('#pop'); opts = opts || {};
    p.innerHTML = '<div class="pop" role="menu">' + html + '</div>';
    var el = p.firstChild, r = anchor.getBoundingClientRect();
    var left = (opts.align === 'left' ? r.left : r.right - el.offsetWidth) + window.scrollX;
    left = Math.max(8, Math.min(left, window.innerWidth - el.offsetWidth - 8 + window.scrollX));
    el.style.left = left + 'px';
    el.style.top = (r.bottom + window.scrollY + 6) + 'px';
    return el;
  }
  function isPopOpen() { var p = $('#pop'); return !!(p && p.firstChild); }

  // ----- modal -----
  function closeModal() { var m = $('#modal-root'); if (m) m.innerHTML = ''; }
  function modal(o) {
    var m = $('#modal-root');
    m.innerHTML = '<div class="mdl" data-act="modal-backdrop"><div class="sheet' + (o.wide ? ' wide' : '') + '" role="dialog" aria-modal="true" aria-label="' + esc(o.title || 'Dialog') + '">' +
      (o.bare ? '' : '<div class="mh"><h3>' + esc(o.title) + '</h3><button class="btn ghost sm" data-act="modal-close" aria-label="Close">' + icon('x') + '</button></div>') +
      '<div class="mb">' + o.body + '</div>' +
      (o.foot ? '<div class="mf">' + o.foot + '</div>' : '') + '</div></div>';
    var f = m.querySelector('input,textarea,select,button.primary');
    if (f && o.focus !== false) setTimeout(function () { try { f.focus(); } catch (e) { /* ignore */ } }, 0);
    return m;
  }
  function textModal(title, text, filename) {
    modal({
      title: title, wide: true,
      body: '<textarea class="input" id="tm-text" readonly spellcheck="false">' + esc(text) + '</textarea>',
      foot: '<span class="msg" id="tm-msg"></span><button class="btn" data-act="tm-download" data-name="' + esc(filename || 'export.txt') + '">' + icon('download') + 'Download</button><button class="btn primary" data-act="tm-copy">' + icon('copy') + 'Copy</button>'
    });
  }

  // ----- clipboard / download -----
  function copy(text) {
    var fallback = function () {
      var t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
      document.body.appendChild(t); t.select();
      var ok = false; try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(t);
      return ok ? Promise.resolve() : Promise.reject(new Error('copy blocked'));
    };
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).catch(fallback);
    return fallback();
  }
  function download(name, text, mime) {
    try {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: mime || 'text/plain' }));
      a.download = name; document.body.appendChild(a); a.click(); a.remove();
      return true;
    } catch (e) { return false; }
  }

  // ----- formatting -----
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmtDate(iso) { var d = new Date(iso); return isNaN(d) ? '-' : d.getDate() + ' ' + MON[d.getMonth()] + ', ' + d.getFullYear(); }
  function fmtDateTime(iso) { var d = new Date(iso); return isNaN(d) ? '-' : fmtDate(iso) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function toLocalInput(iso) { var d = new Date(iso); return isNaN(d) ? '' : d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function fmtCountdown(ms) {
    var neg = ms < 0; ms = Math.abs(ms);
    var h = Math.floor(ms / 3600000), m = Math.floor((ms % 3600000) / 60000);
    return (neg ? '-' : '') + h + 'h ' + pad(m) + 'm';
  }
  function initials(name) { return String(name || '?').split(/\s+/).map(function (p) { return p[0]; }).join('').slice(0, 2).toUpperCase() || '?'; }
  function avatar(name, sm) { return '<span class="avatar' + (sm ? ' sm' : '') + '" aria-hidden="true">' + esc(initials(name)) + '</span>'; }
  var STATUS_CLASS = { Triage: 'acc', Active: 'amber', Contained: 'green', Eradicated: 'green', Recovered: 'green', Closed: '', Breached: 'red' };
  function status(s) { return '<span class="status ' + (STATUS_CLASS[s] || '') + '">' + esc(s) + '</span>'; }

  root.UI = { $: $, esc: esc, icon: icon, toast: toast, pop: pop, closePop: closePop, isPopOpen: isPopOpen, modal: modal, closeModal: closeModal, textModal: textModal, copy: copy, download: download, fmtDate: fmtDate, fmtDateTime: fmtDateTime, toLocalInput: toLocalInput, fmtCountdown: fmtCountdown, avatar: avatar, status: status, pad: pad };
})(typeof self !== 'undefined' ? self : this);
