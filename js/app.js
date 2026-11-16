/* App shell: router, sidebar, top bar, global events, command palette, popovers. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, Views = root.Views, esc = UI.esc, icon = UI.icon;
  var App = root.App = { tab: {}, navOpen: true };
  var $ = UI.$;

  var NAV = [
    { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
    { id: 'navigator', label: 'Navigator', icon: 'navigator' },
    { id: 'incidents', label: 'Incidents', icon: 'incidents', badge: true },
    { id: 'playbooks', label: 'Playbooks', icon: 'playbooks' },
    { id: 'analytics', label: 'Analytics', icon: 'analytics', group: [{ id: 'hunt', label: 'Hunt', icon: 'hunt' }, { id: 'posture', label: 'Posture', icon: 'hardening' }, { id: 'validation', label: 'Validation', icon: 'check' }] },
    { id: 'assets', label: 'Assets', icon: 'assets' },
    { id: 'reports', label: 'Reports', icon: 'reports' },
    { id: 'prefs', label: 'Settings', icon: 'settings' }
  ];
  var RANGES = [[7, 'Last 7 days'], [30, 'Last 30 days'], [90, 'Last 90 days'], [0, 'All time']];
  var SEVS = ['SEV1', 'SEV2', 'SEV3', 'SEV4'], STATS = ['Triage', 'Active', 'Contained', 'Eradicated', 'Recovered', 'Closed', 'Breached'];

  Core.filter = { sev: [], status: [] };
  Core.rowSel = {};
  Core.filteredIncidents = function () {
    var f = Core.filter;
    return Core.incidentsInRange().filter(function (i) { return (!f.sev.length || f.sev.indexOf(i.severity) >= 0) && (!f.status.length || f.status.indexOf(i.status) >= 0); });
  };

  function current() { var n = location.hash.replace(/^#/, ''); return Views[n] ? n : 'dashboard'; }
  function curView() { return Views[current()]; }
  function curTab() { var v = curView(); return v.tabs ? (App.tab[current()] && v.tabs.indexOf(App.tab[current()]) >= 0 ? App.tab[current()] : v.tabs[0]) : null; }
  function rangeLabel() { var r = RANGES.find(function (x) { return x[0] === Core.settings.rangeDays; }); return r ? r[1] : 'All time'; }

  App.go = function (name) { if (current() === name && location.hash === '#' + name) App.render(); else location.hash = name; };

  // ---------- chrome ----------
  function renderSide() {
    var cur = current(), open = Core.incidents.filter(function (i) { return i.status === 'Triage' || i.status === 'Active'; }).length;
    var html = '<div class="brand"><span class="logo">' + icon('navigator') + '</span><span>IR-GPS</span></div><nav class="nav" aria-label="Main">';
    NAV.forEach(function (n) {
      if (n.group) {
        var any = n.group.some(function (g) { return g.id === cur; }), isOpen = App.navOpen || any;
        html += '<button class="grp' + (isOpen ? ' open' : '') + '" data-act="nav-group" aria-expanded="' + isOpen + '">' + icon(n.icon) + '<span>' + n.label + '</span>' + icon('chev', 'chev') + '</button>';
        if (isOpen) html += '<div class="sub">' + n.group.map(function (g) { return '<a href="#' + g.id + '" title="' + g.label + '"' + (cur === g.id ? ' class="on" aria-current="page"' : '') + '>' + icon(g.icon) + '<span>' + g.label + '</span></a>'; }).join('') + '</div>';
      } else html += '<a href="#' + n.id + '"' + (cur === n.id ? ' class="on" aria-current="page"' : '') + ' title="' + n.label + '">' + icon(n.icon) + '<span>' + n.label + '</span>' + (n.badge && open ? '<span class="badge">' + open + '</span>' : '') + '</a>';
    });
    html += '</nav><div class="grow"></div><div class="promo"><span class="ic">' + icon('zap') + '</span><p>Brief the board in one click. Share an executive summary of this incident.</p><button class="btn-white" data-act="share">Share update</button></div>' +
      '<label class="theme">' + icon(Core.settings.theme === 'light' ? 'sun' : 'moon') + '<span>Dark Mode</span><span class="switch"><input type="checkbox" data-act="theme"' + (Core.settings.theme !== 'light' ? ' checked' : '') + ' aria-label="Dark mode"><i></i></span></label>';
    $('#side').innerHTML = html;
  }

  function renderTop() {
    var v = curView(), cur = current(), tab = curTab(), unread = Core.unread();
    var html = '<div class="toprow"><h1>' + esc(v.title) + '</h1>' +
      '<button class="search" data-act="palette" aria-label="Search">' + icon('search') + '<span>Search assets, techniques, incidents</span><kbd>Ctrl K</kbd></button>' +
      '<button class="icbtn" data-act="bell" aria-label="Notifications">' + icon('bell') + (unread ? '<span class="dotb"></span>' : '') + '</button>' +
      '<button class="icbtn" data-act="help" aria-label="Help">' + icon('help') + '</button>' +
      '<button class="avatar" data-act="avatar" aria-label="Account" style="border:0;cursor:pointer">' + esc(UI.avatar(Core.settings.owner).replace(/<[^>]+>/g, '')) + '</button>' +
      (v.tabs || v.filters ? '' : '<button class="btn primary" data-act="share">' + icon('share') + 'Share</button>') + '</div>';
    var tabs = v.tabs ? '<div class="tabs" role="tablist">' + v.tabs.map(function (t) { return '<button class="tab' + (t === tab ? ' on' : '') + '" role="tab" aria-selected="' + (t === tab) + '" data-act="tab" data-t="' + esc(t) + '">' + esc(t) + '</button>'; }).join('') + '</div>' : '';
    var nf = Core.filter.sev.length + Core.filter.status.length;
    var tools = '<div class="row tools" style="margin-left:auto">' + (v.filters ? '<button class="pill" data-act="range">' + icon('calendar') + esc(rangeLabel()) + icon('chev') + '</button><button class="pill" data-act="filter">' + icon('filter') + 'Filter' + (nf ? ' <span class="chip acc">' + nf + '</span>' : '') + '</button>' : '') + '<button class="btn primary" data-act="share">' + icon('share') + 'Share</button></div>';
    if (v.tabs || v.filters) html += '<div class="row" style="justify-content:space-between;align-items:flex-end">' + (tabs || '<span></span>') + tools + '</div>';
    $('#top').innerHTML = html;
    document.title = 'IR-GPS · ' + v.title;
  }

  App.render = function () {
    var v = curView(), y = window.scrollY;
    renderSide(); renderTop();
    var el = $('#view');
    el.innerHTML = v.render(curTab());
    if (v.after) v.after();
    window.scrollTo(0, y);
  };

  // ---------- popovers / dialogs ----------
  function bell(el) {
    var items = Core.notifs.length ? Core.notifs.slice(0, 12).map(function (n) {
      return '<div class="nitem' + (n.read ? '' : ' unread') + '"><span class="chip ' + (n.type === 'breach' ? 'red' : n.type === 'reroute' ? 'amber' : n.type === 'contained' ? '' : 'acc') + '">' + esc(n.type) + '</span><div>' + esc(n.text) + '<small class="mut">' + new Date(n.at).toLocaleTimeString() + '</small></div></div>'; }).join('') : '<div class="empty">No notifications yet.<br><small>Reroutes, breaches and containment appear here.</small></div>';
    UI.pop(el, '<div class="sec">Notifications</div>' + items + (Core.notifs.length ? '<button class="item" data-act="notif-read">Mark all read</button>' : ''));
    Core.markRead(); renderTop();
  }
  function help() {
    UI.modal({ title: 'How IR-GPS works', body: '<ol style="margin:0;padding-left:20px;display:grid;gap:10px"><li><b>Pick a scenario</b> in the Navigator. It starts from a real-looking alert with a foothold and some time the attacker already had.</li>' +
      '<li><b>Read the ETA.</b> It is the predicted time until a crown jewel falls, with the route drawn on the map and listed turn by turn with ATT&amp;CK ids.</li>' +
      '<li><b>Contain.</b> Take the top recommendation or click any asset or path. The route recalculates the moment you act, just like a GPS reroute.</li>' +
      '<li><b>Press Start attacker</b> to replay the incident in real time and see whether your response keeps ahead.</li>' +
      '<li><b>Open an incident</b> to track regulatory clocks, a playbook and notes. Export a report when done.</li></ol><p class="mut" style="font-size:13px">Tip: <span class="mono">Ctrl K</span> or <span class="mono">/</span> opens search. Timings in the sample environment are illustrative, so calibrate them in Assets.</p>',
      foot: '<button class="btn primary" data-act="modal-close">Got it</button>' });
  }

  // ---------- command palette ----------
  var pal = { q: '', i: 0, items: [] };
  function palItems() {
    var out = [];
    NAV.forEach(function (n) { (n.group || [n]).forEach(function (g) { out.push({ g: 'Go to', t: g.label, hint: 'page', run: function () { App.go(g.id); } }); }); });
    out.push({ g: 'Actions', t: Core.isRunning() ? 'Pause attacker' : 'Start attacker', hint: 'sim', run: function () { App.go('navigator'); Core.toggle(); } });
    out.push({ g: 'Actions', t: 'Reset scenario', hint: 'sim', run: function () { Core.startScenario(Core.scnIdx); App.go('navigator'); } });
    out.push({ g: 'Actions', t: 'Open incident from current state', hint: 'case', run: function () { var i = Core.createIncident(); Views.incidents.sel = i.id; App.go('incidents'); } });
    out.push({ g: 'Actions', t: 'Share executive summary', hint: 'report', run: function () { share(); } });
    out.push({ g: 'Actions', t: 'Toggle dark mode', hint: 'theme', run: function () { Core.setSetting('theme', Core.settings.theme === 'light' ? 'dark' : 'light'); } });
    Core.env.scenarios.forEach(function (s, i) { out.push({ g: 'Scenarios', t: s.name, hint: 'scenario', run: function () { Core.startScenario(i); App.go('navigator'); } }); });
    Core.env.nodes.forEach(function (n) { out.push({ g: 'Assets', t: n.label, hint: n.crown ? 'crown jewel' : n.type, run: function () { Core.selected = { kind: 'node', id: n.id }; App.go('navigator'); Core.emit('state'); } }); });
    var seen = {};
    Core.env.edges.forEach(function (e) { if (!seen[e.tid]) { seen[e.tid] = 1; out.push({ g: 'Techniques', t: e.tid + ' ' + e.tname, hint: e.tactic, run: function () { Views.hunt.sel = e.tid; App.go('hunt'); } }); } });
    Core.incidents.forEach(function (i) { out.push({ g: 'Incidents', t: i.id + ' ' + i.title, hint: i.status, run: function () { Views.incidents.sel = i.id; App.go('incidents'); } }); });
    Core.REF.playbooks.forEach(function (p) { out.push({ g: 'Playbooks', t: p.name, hint: p.steps.length + ' steps', run: function () { Views.playbooks.sel = p.id; App.go('playbooks'); } }); });
    return out;
  }
  function palResults() {
    var q = pal.q.trim().toLowerCase(), items = pal.items.filter(function (x) { return !q || x.t.toLowerCase().indexOf(q) >= 0 || x.g.toLowerCase().indexOf(q) >= 0; }).slice(0, 14);
    pal.shown = items; pal.i = Math.min(pal.i, Math.max(0, items.length - 1));
    var last = '';
    return items.length ? items.map(function (x, i) { var h = x.g !== last ? '<div class="grp">' + esc(x.g) + '</div>' : ''; last = x.g; return h + '<button data-act="pal-run" data-i="' + i + '" class="' + (i === pal.i ? 'sel' : '') + '">' + esc(x.t) + '<small class="mut">' + esc(x.hint) + '</small></button>'; }).join('') : '<div class="empty">Nothing matches “' + esc(pal.q) + '”.</div>';
  }
  function openPalette() {
    pal = { q: '', i: 0, items: palItems(), shown: [] };
    UI.modal({ bare: true, title: 'Search', body: '<div class="psearch">' + icon('search') + '<input id="pal-in" data-act="pal-q" data-live="1" placeholder="Jump to a page, asset, technique, incident…" autocomplete="off" aria-label="Search"></div><div class="res" id="pal-res" style="max-height:52vh;overflow:auto;margin-top:8px">' + palResults() + '</div>' });
  }
  function palRun(i) { var it = pal.shown[i]; if (!it) return; UI.closeModal(); it.run(); }

  function share() { UI.textModal('Executive summary', root.Reports.execSummary(), 'ir-gps-exec-summary.txt'); }

  // ---------- dispatch ----------
  function isControl(el) { return /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName); }
  function dispatch(name, el, e) {
    switch (name) {
      case 'go': { var inc = el.getAttribute('data-inc'); if (inc) { Views.playbooks.inc = inc; var rec = Core.getIncident(inc); if (rec) Views.playbooks.sel = rec.playbookId; } UI.closePop(); UI.closeModal(); App.go(el.getAttribute('data-to')); return true; }
      case 'tab': App.tab[current()] = el.getAttribute('data-t'); App.render(); return true;
      case 'nav-group': App.navOpen = !App.navOpen; renderSide(); return true;
      case 'theme': Core.setSetting('theme', el.checked ? 'dark' : 'light'); return true;
      case 'palette': openPalette(); return true;
      case 'pal-q': pal.q = el.value; pal.i = 0; $('#pal-res').innerHTML = palResults(); return true;
      case 'pal-run': palRun(parseInt(el.getAttribute('data-i'), 10)); return true;
      case 'bell': bell(el); return true;
      case 'notif-read': Core.markRead(); UI.closePop(); renderTop(); return true;
      case 'help': help(); return true;
      case 'share': share(); return true;
      case 'avatar': UI.pop(el, '<div class="sec">' + esc(Core.settings.owner) + '</div><button class="item" data-act="go" data-to="prefs">' + icon('settings') + 'Settings</button><button class="item" data-act="help">' + icon('help') + 'How it works</button><button class="item" data-act="go" data-to="reports">' + icon('reports') + 'Reports</button>'); return true;
      case 'range': UI.pop(el, RANGES.map(function (r) { return '<button class="item" data-act="range-set" data-d="' + r[0] + '">' + (Core.settings.rangeDays === r[0] ? icon('check') : '<span style="width:18px"></span>') + r[1] + '</button>'; }).join(''), { align: 'left' }); return true;
      case 'range-set': UI.closePop(); Core.setSetting('rangeDays', parseInt(el.getAttribute('data-d'), 10)); return true;
      case 'filter': UI.pop(el, '<div class="sec">Severity</div>' + SEVS.map(function (s) { return '<label class="item"><input type="checkbox" data-act="flt" data-k="sev" data-v="' + s + '"' + (Core.filter.sev.indexOf(s) >= 0 ? ' checked' : '') + '>' + s + '</label>'; }).join('') +
        '<div class="sec">Status</div>' + STATS.map(function (s) { return '<label class="item"><input type="checkbox" data-act="flt" data-k="status" data-v="' + s + '"' + (Core.filter.status.indexOf(s) >= 0 ? ' checked' : '') + '>' + s + '</label>'; }).join('') + '<button class="item" data-act="flt-clear">Clear filters</button>', { align: 'left' }); return true;
      case 'flt': { var arr = Core.filter[el.getAttribute('data-k')], v = el.getAttribute('data-v'), ix = arr.indexOf(v); if (el.checked && ix < 0) arr.push(v); if (!el.checked && ix >= 0) arr.splice(ix, 1); App.render(); return true; }
      case 'flt-clear': Core.filter = { sev: [], status: [] }; UI.closePop(); App.render(); return true;
      case 'modal-close': UI.closeModal(); return true;
      case 'modal-backdrop': if (e && e.target === el) UI.closeModal(); return true;
      case 'tm-copy': { var t = $('#tm-text').value; UI.copy(t).then(function () { $('#tm-msg').textContent = 'Copied.'; }, function () { $('#tm-text').select(); $('#tm-msg').textContent = 'Copy is blocked here. Text is selected: press Ctrl+C.'; }); return true; }
      case 'tm-download': { var ok = UI.download(el.getAttribute('data-name'), $('#tm-text').value, 'text/plain'); $('#tm-msg').textContent = ok ? 'Download started. If nothing happened, use Copy.' : 'Downloads are blocked here. Use Copy.'; return true; }
    }
    var v = curView();
    if (v.act && v.act(name, el, e)) return true;
    for (var k in Views) { if (Views[k] !== v && Views[k].act && Views[k].act(name, el, e)) return true; }
    return false;
  }

  document.addEventListener('click', function (e) {
    if (!e.target.closest('.pop')) UI.closePop();
    var el = e.target.closest('[data-act]'); if (!el || isControl(el)) return;
    dispatch(el.getAttribute('data-act'), el, e);
  });
  document.addEventListener('change', function (e) { var el = e.target.closest('[data-act]'); if (el && isControl(el)) dispatch(el.getAttribute('data-act'), el, e); });
  document.addEventListener('input', function (e) { var el = e.target.closest('[data-act]'); if (el && el.hasAttribute('data-live') && isControl(el)) dispatch(el.getAttribute('data-act'), el, e); });
  document.addEventListener('pointermove', function (e) { if (current() !== 'dashboard') return; if (e.target.closest && e.target.closest('#chart')) Views.dashboard.hover(e); else Views.dashboard.leave(); });
  document.addEventListener('keydown', function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target.tagName || ''));
    if (e.key === 'Escape') { if ($('#modal-root').firstChild) UI.closeModal(); else if (UI.isPopOpen()) UI.closePop(); return; }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); return; }
    if (!typing && e.key === '/' && !$('#modal-root').firstChild) { e.preventDefault(); openPalette(); return; }
    if ($('#pal-in') && (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter')) {
      e.preventDefault();
      if (e.key === 'Enter') palRun(pal.i); else { pal.i = Math.max(0, Math.min(pal.shown.length - 1, pal.i + (e.key === 'ArrowDown' ? 1 : -1))); $('#pal-res').innerHTML = palResults(); var s = $('#pal-res .sel'); if (s && s.scrollIntoView) s.scrollIntoView({ block: 'nearest' }); }
      return;
    }
    if ((e.key === 'Enter' || e.key === ' ') && !typing) { var el = e.target.closest && e.target.closest('[data-act]'); if (el && !/^(BUTTON|A|LABEL)$/.test(el.tagName) && !isControl(el)) { e.preventDefault(); dispatch(el.getAttribute('data-act'), el, e); } }
  });
  window.addEventListener('hashchange', function () { UI.closePop(); App.render(); var v = $('#view'); try { v.focus({ preventScroll: true }); } catch (e) { /* ignore */ } window.scrollTo(0, 0); });

  // ---------- live updates ----------
  Core.on(function (kind) {
    if (kind === 'tick') { var v = curView(); if (v.tick) v.tick(); return; }
    if (kind === 'sim') {
      var c = current();
      if (c === 'navigator' || c === 'dashboard') App.render(); else { renderSide(); renderTop(); }
      return;
    }
    App.render();
  });
  setInterval(function () { var v = curView(); if (v.pulse) v.pulse(); }, 20000);

  // ---------- boot ----------
  Core.init();
  if (!location.hash) { try { history.replaceState(null, '', '#dashboard'); } catch (e) { location.hash = 'dashboard'; } }
  App.render();
})(typeof self !== 'undefined' ? self : this);
