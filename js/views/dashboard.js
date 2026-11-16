/* Dashboard: KPI cards, breach-ETA projection chart, exposure by tactic, incident history. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};
  var chart = null; // geometry of the last rendered chart, used by hover

  function kpi(o) {
    return '<section class="card kpi' + (o.hero ? ' hero' : '') + '"><div class="row" style="justify-content:space-between;flex-wrap:nowrap"><span class="kicon">' + icon(o.icon) + '</span>' +
      '<button class="kebab" data-act="kpi-menu" data-k="' + esc(o.key) + '" aria-label="More about ' + esc(o.label) + '">' + icon('more') + '</button></div>' +
      '<div class="lbl">' + esc(o.label) + '</div><div class="val">' + o.value + '</div><div class="foot">' + o.foot + '</div></section>';
  }

  function incRows(list, opts) {
    opts = opts || {};
    if (!list.length) return '<div class="empty">No incidents match the current filters. Open one from the Navigator, or widen the date range.</div>';
    var allOn = list.length && list.every(function (i) { return Core.rowSel[i.id]; });
    return '<div class="tablewrap"><table class="t"><thead><tr><th><input type="checkbox" data-act="row-all" aria-label="Select all"' + (allOn ? ' checked' : '') + '></th>' +
      '<th>Incident</th><th>Severity</th><th>Status</th><th>Opened</th><th>ETA at open</th><th>Time to contain</th><th></th></tr></thead><tbody>' +
      list.map(function (i) {
        var s = i.snapshot || {}, ttc = s.simStatus === 'contained' ? G.fmt(s.simT) : (s.simStatus === 'breach' ? 'Breached' : '-');
        return '<tr><td><input type="checkbox" data-act="row-sel" data-id="' + esc(i.id) + '" aria-label="Select ' + esc(i.id) + '"' + (Core.rowSel[i.id] ? ' checked' : '') + '></td>' +
          '<td><div class="who">' + UI.avatar(i.owner, true) + '<div><b>' + esc(i.title) + '</b><small class="mut">' + esc(i.id) + ' · ' + esc(i.owner) + (i.sample ? ' · sample' : '') + '</small></div></div></td>' +
          '<td><span class="sev ' + esc(i.severity) + '">' + esc(i.severity) + '</span></td><td>' + UI.status(i.status) + '</td>' +
          '<td>' + UI.fmtDate(i.createdAt) + '</td><td>' + (s.eta != null ? G.fmt(s.eta) : '-') + '</td><td>' + ttc + '</td>' +
          '<td><div class="row" style="flex-wrap:nowrap;justify-content:flex-end"><button class="btn sm" data-act="inc-download" data-id="' + esc(i.id) + '">' + icon('download') + 'Download</button>' +
          '<button class="btn sm" data-act="inc-rerun" data-id="' + esc(i.id) + '">' + icon('rerun') + 'Re-run</button></div></td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  root.IncRows = incRows;

  // ---------- area chart ----------
  function areaChart(p) {
    var W = 720, H = 300, L = 46, R = 16, T = 16, B = 32, cap = p.cap;
    var u = p.unmanaged, g = p.guided;
    var xmax = Math.max(30, u.points[u.points.length - 1].t, g.points[g.points.length - 1].t);
    var m = 30;
    [u, g].forEach(function (s) { s.points.forEach(function (q) { if (q.eta < cap) m = Math.max(m, q.eta); }); });
    var ymax = Math.ceil(m * 1.15 / 10) * 10;
    var X = function (t) { return L + (t / xmax) * (W - L - R); };
    var Y = function (v) { return T + (1 - Math.min(v, ymax) / ymax) * (H - T - B); };
    chart = { W: W, H: H, L: L, R: R, T: T, B: B, xmax: xmax, ymax: ymax, u: u, g: g, cap: cap, X: X, Y: Y };
    // Points where the attacker has no route (ETA at the cap) are not plotted as a line. A contained response ends with a dashed jump to the top.
    function real(s) { var r = s.points.filter(function (q) { return q.eta < cap; }); return r.length ? r : [s.points[0]]; }
    function line(s) { return real(s).map(function (q, i) { return (i ? 'L' : 'M') + X(q.t).toFixed(1) + ',' + Y(q.eta).toFixed(1); }).join(''); }
    function area(s) { var r = real(s), last = r[r.length - 1]; return line(s) + 'L' + X(last.t).toFixed(1) + ',' + Y(0) + 'L' + X(0) + ',' + Y(0) + 'Z'; }
    function tail(s, color) {
      if (s.status !== 'contained' || s.endAt == null) return '';
      var r = real(s), last = r[r.length - 1], x = X(s.endAt), anchor = x > W - 110 ? 'end' : 'start';
      return '<path d="M' + X(last.t).toFixed(1) + ',' + Y(last.eta).toFixed(1) + 'L' + x.toFixed(1) + ',' + (T + 4) + '" stroke="' + color + '" stroke-width="2" stroke-dasharray="4 4" fill="none"/>' +
        '<circle cx="' + x.toFixed(1) + '" cy="' + (T + 4) + '" r="5" fill="#34d399" stroke="var(--card)" stroke-width="2"/><text x="' + (x + (anchor === 'end' ? -10 : 10)) + '" y="' + (T + 8) + '" text-anchor="' + anchor + '" style="fill:var(--green);font-weight:600">Contained +' + Math.round(s.endAt) + 'm</text>';
    }
    var grid = '', ticks = 4, i;
    for (i = 0; i <= ticks; i++) {
      var v = ymax * i / ticks;
      grid += '<line x1="' + L + '" x2="' + (W - R) + '" y1="' + Y(v) + '" y2="' + Y(v) + '"/><text x="' + (L - 8) + '" y="' + (Y(v) + 4) + '" text-anchor="end">' + Math.round(v) + 'm</text>';
    }
    var xs = '', step = xmax > 120 ? 60 : xmax > 60 ? 20 : 10;
    for (var t = 0; t <= xmax; t += step) xs += '<text x="' + X(t) + '" y="' + (H - 8) + '" text-anchor="middle">+' + t + 'm</text>';
    function endDot(s, color) {
      if (s.endAt == null || s.status !== 'breach') return '';
      return '<circle cx="' + X(s.endAt) + '" cy="' + Y(0) + '" r="5" fill="' + color + '" stroke="var(--card)" stroke-width="2"/><text x="' + (X(s.endAt) + (X(s.endAt) > W - 110 ? -10 : 10)) + '" y="' + (Y(0) - 8) + '" text-anchor="' + (X(s.endAt) > W - 110 ? 'end' : 'start') + '" style="fill:#f87171;font-weight:600">Breach +' + Math.round(s.endAt) + 'm</text>';
    }
    var lagX = X(p.lag);
    return '<svg id="areasvg" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Projected breach ETA over the next ' + Math.round(xmax) + ' minutes, unmanaged versus guided response">' +
      '<defs><linearGradient id="gG" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8b5cf6" stop-opacity=".5"/><stop offset="1" stop-color="#8b5cf6" stop-opacity="0"/></linearGradient>' +
      '<linearGradient id="gU" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f87171" stop-opacity=".28"/><stop offset="1" stop-color="#f87171" stop-opacity="0"/></linearGradient></defs>' +
      '<g class="grid">' + grid + '</g>' + xs +
      '<line x1="' + lagX + '" x2="' + lagX + '" y1="' + T + '" y2="' + (H - B) + '" stroke="var(--line2)" stroke-dasharray="2 4"/><text x="' + (lagX + 6) + '" y="' + (T + 10) + '">response starts</text>' +
      '<path d="' + area(u) + '" fill="url(#gU)"/><path d="' + line(u) + '" fill="none" stroke="#f87171" stroke-width="2.2" stroke-linejoin="round"/>' +
      '<path d="' + area(g) + '" fill="url(#gG)"/><path d="' + line(g) + '" fill="none" stroke="#a78bfa" stroke-width="2.6" stroke-linejoin="round"/>' +
      endDot(u, '#f87171') + tail(g, '#a78bfa') + (g.status === 'breach' ? endDot(g, '#a78bfa') : '') +
      '<line id="hv" x1="0" x2="0" y1="' + T + '" y2="' + (H - B) + '" stroke="var(--mut)" stroke-dasharray="4 4" style="display:none"/>' +
      '<circle id="hvu" r="5" fill="#f87171" stroke="var(--card)" stroke-width="2" style="display:none"/><circle id="hvg" r="5" fill="#a78bfa" stroke="var(--card)" stroke-width="2" style="display:none"/></svg>';
  }

  function pointAt(s, t) {
    var pts = s.points, i = Math.max(0, Math.min(pts.length - 1, Math.round(t)));
    return pts[i];
  }
  function stateLabel(s, q, t) {
    if (s.endAt != null && t >= s.endAt) return s.status === 'breach' ? 'Breached' : 'Contained';
    return q.eta >= chart.cap ? 'No route' : G.fmt(q.eta) + ' to breach';
  }

  Views.dashboard = {
    title: 'Dashboard', tabs: ['Overview', 'Alerts', 'History'], filters: true,
    render: function (tab) {
      var a = Core.analysis, h = a.headline, live = Core.liveEta(), sev = G.severity(a, live);
      var expo = G.exposure(Core.env, Core.st), base = Core.baseline();
      var inRange = Core.filteredIncidents();
      var contained = Core.incidentsInRange().filter(function (i) { return i.snapshot && i.snapshot.simStatus === 'contained' && i.snapshot.simT > 0; });
      var mttc = contained.length ? contained.reduce(function (s, i) { return s + i.snapshot.simT; }, 0) / contained.length : null;
      var open = Core.incidents.filter(function (i) { return i.status === 'Triage' || i.status === 'Active'; }).length;
      var etaVal = !h ? 'Contained' : h.status === 'breached' ? 'Breached' : G.fmt(live);
      var etaFoot = !h ? '<span class="chip">' + sev.level + '</span> No route to any crown jewel' : h.status === 'breached' ? '<span class="chip red">' + sev.level + '</span> ' + esc(h.node.label) : '<span class="chip">' + sev.level + ' ' + sev.label + '</span> to ' + esc(h.node.label) + '<span class="rng-sub">' + esc(root.Unc.short()) + '</span>';
      var kpis = '<div class="grid g4">' +
        kpi({ key: 'eta', hero: true, icon: 'clock', label: 'Breach ETA', value: etaVal, foot: etaFoot }) +
        kpi({ key: 'exposure', icon: 'target', label: 'Exposure score', value: expo + '<small>/ 100</small>', foot: '<span class="chip ' + (expo > base.exposure ? 'amber' : '') + '">' + (expo === base.exposure ? 'at baseline' : (expo > base.exposure ? '+' : '') + (expo - base.exposure) + ' vs all controls on') + '</span>' }) +
        kpi({ key: 'crowns', icon: 'shield', label: 'Crown jewels in reach', value: a.reachable + '<small>of ' + a.destinations.length + '</small>', foot: a.reachable === 0 ? '<span class="chip">all protected</span>' : '<span class="chip red">' + a.destinations.filter(function (d) { return d.status === 'breached'; }).length + ' breached</span> ' + Core.env.nodes.filter(function (n) { return Core.st.removed.has(n.id); }).length + ' assets isolated' }) +
        kpi({ key: 'mttc', icon: 'zap', label: 'Mean time to contain', value: mttc == null ? '-' : G.fmt(mttc), foot: '<span class="chip mut">' + open + ' open</span> ' + contained.length + ' contained in range' }) + '</div>';

      if (tab === 'Alerts') return kpis + this.alerts();
      if (tab === 'History') return kpis + '<section class="card"><div class="chead"><h2>All incidents</h2><small>' + inRange.length + ' shown</small>' +
        '<button class="btn sm" data-act="export-incidents-csv">' + icon('download') + 'Export CSV</button></div>' + incRows(inRange) + '</section>';

      var proj = Core.projection(), tx = G.tacticExposure(Core.env, Core.st);
      var gS = proj.guided, uS = proj.unmanaged;
      var summary = (uS.status === 'breach' ? 'Left alone, the attacker reaches a crown jewel ' + G.fmt(uS.endAt) + ' from now. ' : 'Left alone, the attacker is not projected to breach. ') +
        (gS.status === 'contained' ? 'Following the top recommendation after a ' + proj.lag + ' min response lag contains it in ' + G.fmt(gS.endAt) + '.' : gS.status === 'breach' ? 'Even with guided response (' + proj.lag + ' min lag) the breach lands at ' + G.fmt(gS.endAt) + '. Shorten the lag or harden first.' : 'Guided response stays ahead of the attacker through the projection window.');
      var bars = tx.tactics.length ? tx.tactics.slice(0, 5).map(function (t) {
        return '<div class="bar"><span class="bi">' + esc(t.tactic.split(' ').map(function (w) { return w[0]; }).join('')) + '</span><div><div class="bt"><span>' + esc(t.tactic) + '</span><b>' + t.pct + '%</b></div><div class="track"><div class="fill" style="width:' + t.pct + '%"></div></div></div></div>';
      }).join('') : '<div class="empty">No predicted routes. Nothing reaches a crown jewel.</div>';
      return kpis + '<div class="grid g-chart"><section class="card"><div class="chead"><div><h2>Breach ETA projection</h2><small class="mut">Minutes until a crown jewel falls, replayed forward from now</small></div>' +
        '<div class="legend" style="margin-left:auto"><span><i style="background:#f87171"></i>Unmanaged</span><span><i style="background:#a78bfa"></i>Guided response</span></div></div>' +
        '<div class="chart" id="chart">' + areaChart(proj) + '<div class="tip" id="tip" style="display:none"></div></div>' +
        '<p class="mut" style="margin:10px 0 0;font-size:13px">' + esc(summary) + '</p></section>' +
        '<section class="card"><div class="chead"><h2>Exposure by tactic</h2><small>' + tx.total + ' predicted routes</small></div><div class="bars">' + bars + '</div>' +
        '<div class="hr"></div><button class="btn" data-act="go" data-to="posture" style="width:100%">' + icon('hardening') + 'See what hardening buys you</button></section></div>' +
        this.uncCards() +
        '<section class="card"><div class="chead"><h2>Incident history</h2><small>' + inRange.length + ' in range</small><button class="btn sm" data-act="go" data-to="incidents">Manage</button></div>' + incRows(inRange.slice(0, 5)) + '</section>';
    },
    uncCards: function () {
      var U = root.Unc, u = Core.unc();
      if (u.status !== 'at-risk') return '';
      var sn = Core.drivers();
      var retry = u.persistent ? 'attacker retries failed steps' : 'single attempt, breach chance is a lower bound';
      return '<div class="g2e">' +
        '<section class="card"><div class="chead"><div><h2>When the breach lands</h2><small class="mut">' + u.runs.toLocaleString() + ' simulated attacks · ' + esc(retry) + '</small></div></div>' + U.hist(u) +
        '<div class="histlegend"><span><i style="background:var(--red)"></i>fastest 10%</span><span><i style="background:var(--accent)"></i>likely range</span><span><i style="background:var(--mut2)"></i>slowest 10%</span><span><i style="background:var(--amber)"></i>fastest path</span></div>' +
        U.chances(u) + U.crowns(u) + '</section>' +
        '<section class="card"><div class="chead"><div><h2>What drives the ETA</h2><small class="mut">which assumption moves it most</small></div><button class="btn sm" data-act="go" data-to="validation">Check against real cases</button></div>' + U.tornado(sn) +
        '<p class="mut" style="font-size:12px;margin:12px 0 0">The numbers behind each step are priors until you calibrate them. <button class="linkbtn" data-act="go-cal">Add your own observations</button></p></section></div>';
    },
    alerts: function () {
      var a = Core.analysis, scn = Core.env.scenarios[Core.scnIdx], REF = Core.REF, sev = G.severity(a, Core.liveEta());
      var route = a.routes[0], seen = {}, tids = [];
      if (route) G.directions(Core.env, route).forEach(function (d) { if (!seen[d.tid]) { seen[d.tid] = 1; tids.push(d); } });
      var det = tids.length ? tids.map(function (d) {
        var r = REF.detect[d.tid];
        return '<div class="hop"><div class="hh"><span class="n">' + d.n + '</span><b>' + esc(d.tid + ' ' + d.tname) + '</b><span class="chip acc">' + esc(d.tactic || '') + '</span><span class="mut" style="margin-left:auto">in ' + G.fmt(d.at) + '</span></div>' +
          (r ? '<div class="mut" style="font-size:13px"><b style="color:var(--text)">Look for:</b> ' + esc(r.look) + '</div>' : '<div class="mut">No starter detection for this technique yet.</div>') +
          '<div class="row" style="margin-top:10px"><button class="btn sm" data-act="hunt" data-tid="' + esc(d.tid) + '">' + icon('hunt') + 'Open hunt guide</button></div></div>';
      }).join('') : '<div class="empty">No predicted route, so there is nothing to hunt for right now.</div>';
      var nf = Core.notifs.length ? Core.notifs.map(function (n) { return '<div class="nitem" style="display:grid;grid-template-columns:auto 1fr;gap:10px;padding:8px 0;border-top:1px solid var(--line)"><span class="chip ' + (n.type === 'breach' ? 'red' : n.type === 'reroute' ? 'amber' : '') + '">' + esc(n.type) + '</span><div>' + esc(n.text) + '<small class="mut" style="display:block">' + new Date(n.at).toLocaleTimeString() + '</small></div></div>'; }).join('') : '<div class="empty">Nothing yet. Press play in the Navigator to start the clock.</div>';
      return '<div class="grid g-chart" style="margin-top:0"><section class="card"><div class="chead"><h2>Active alert</h2><span class="sev ' + sev.level + '">' + sev.level + '</span></div>' +
        '<h3 style="text-transform:none;letter-spacing:0;font-size:16px;color:var(--text)">' + esc(scn.name) + '</h3><p class="mut" style="margin-top:0">' + esc(scn.summary) + '</p>' +
        '<div class="row"><button class="btn primary" data-act="go" data-to="navigator">' + icon('navigator') + 'Open in Navigator</button><button class="btn" data-act="new-incident">' + icon('plus') + 'Open incident</button></div>' +
        '<div class="hr"></div><div class="chead"><h2>Detections to check now</h2><small>along the fastest predicted route</small></div>' + det + '</section>' +
        '<section class="card"><div class="chead"><h2>Activity</h2></div>' + nf + '</section></div>';
    },
    hover: function (e) {
      var svg = document.getElementById('areasvg'); if (!svg || !chart) return;
      var tip = document.getElementById('tip'), wrap = document.getElementById('chart'), r = svg.getBoundingClientRect();
      var px = (e.clientX - r.left) / r.width * chart.W;
      if (px < chart.L || px > chart.W - chart.R) { this.leave(); return; }
      var t = Math.max(0, Math.min(chart.xmax, Math.round((px - chart.L) / (chart.W - chart.L - chart.R) * chart.xmax)));
      var u = pointAt(chart.u, t), g = pointAt(chart.g, t), x = chart.X(t);
      var hv = document.getElementById('hv'); hv.setAttribute('x1', x); hv.setAttribute('x2', x); hv.style.display = '';
      [['hvu', u], ['hvg', g]].forEach(function (p) { var c = document.getElementById(p[0]); c.setAttribute('cx', x); c.setAttribute('cy', chart.Y(p[1].eta)); c.style.display = ''; });
      tip.innerHTML = '<b>+' + t + ' min from now</b><div><span><i style="background:#a78bfa"></i>Guided</span><b>' + esc(stateLabel(chart.g, g, t)) + '</b></div><div><span><i style="background:#f87171"></i>Unmanaged</span><b>' + esc(stateLabel(chart.u, u, t)) + '</b></div>';
      tip.style.display = '';
      var wr = wrap.getBoundingClientRect(), left = (x / chart.W) * r.width + (r.left - wr.left);
      tip.style.left = Math.max(80, Math.min(left, wr.width - 80)) + 'px'; tip.style.top = Math.max(60, (chart.Y(Math.min(u.eta, g.eta)) / chart.H) * r.height - 12) + 'px';
    },
    leave: function () {
      ['hv', 'hvu', 'hvg', 'tip'].forEach(function (id) { var el = document.getElementById(id); if (el) el.style.display = 'none'; });
    },
    act: function (name, el) {
      switch (name) {
        case 'kpi-menu': {
          var k = el.getAttribute('data-k');
          var items = { eta: ['Open in Navigator', 'navigator'], exposure: ['See hardening advice', 'posture'], crowns: ['Open Navigator', 'navigator'], mttc: ['Manage incidents', 'incidents'] }[k];
          UI.pop(el, '<button class="item" data-act="go" data-to="' + items[1] + '">' + items[0] + '</button>' + (k === 'mttc' ? '<button class="item" data-act="export-incidents-csv">Export incidents CSV</button>' : ''));
          return true;
        }
        case 'row-all': {
          var on = el.checked; Core.filteredIncidents().forEach(function (i) { if (on) Core.rowSel[i.id] = 1; else delete Core.rowSel[i.id]; });
          root.App.render(); return true;
        }
        case 'row-sel': { if (el.checked) Core.rowSel[el.getAttribute('data-id')] = 1; else delete Core.rowSel[el.getAttribute('data-id')]; return true; }
        case 'inc-download': { var inc = Core.getIncident(el.getAttribute('data-id')); if (inc) root.Reports.downloadIncident(inc); return true; }
        case 'inc-rerun': { if (Core.rerun(el.getAttribute('data-id'))) root.App.go('navigator'); return true; }
        case 'export-incidents-csv': {
          var ids = Object.keys(Core.rowSel), list = ids.length ? Core.incidents.filter(function (i) { return Core.rowSel[i.id]; }) : Core.filteredIncidents();
          var ok = UI.download('incidents.csv', root.Reports.incidentsCsv(list), 'text/csv');
          if (!ok) UI.textModal('Incidents CSV', root.Reports.incidentsCsv(list), 'incidents.csv'); else UI.toast('Exported ' + list.length + ' incident(s).', 'ok');
          UI.closePop(); return true;
        }
        case 'hunt': { Views.hunt.sel = el.getAttribute('data-tid'); root.App.go('hunt'); return true; }
        case 'new-incident': { var i2 = Core.createIncident(); Views.incidents.sel = i2.id; UI.toast('Opened ' + i2.id + '.', 'ok'); root.App.go('incidents'); return true; }
      }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
