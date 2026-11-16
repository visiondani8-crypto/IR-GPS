/* Navigator: the GPS. Attack map, breach ETA, turn-by-turn route, ranked containment moves, what-if controls, live simulation. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};
  var GLYPH = { gateway: '⇄', workstation: '▭', server: '☰', identity: '◉', cloud: '☁', data: '⛁', saas: '⌘' };

  function geom(a, b) {
    var dx = b.x - a.x, dy = b.y - a.y, L = Math.hypot(dx, dy) || 1, ux = dx / L, uy = dy / L;
    var sx = a.x + ux * 24, sy = a.y + uy * 24, ex = b.x - ux * 28, ey = b.y - uy * 28;
    return { sx: sx, sy: sy, ex: ex, ey: ey, mx: (sx + ex) / 2 - uy * 14, my: (sy + ey) / 2 + ux * 14 };
  }
  function pathD(g) { return 'M' + g.sx.toFixed(1) + ',' + g.sy.toFixed(1) + ' Q' + g.mx.toFixed(1) + ',' + g.my.toFixed(1) + ' ' + g.ex.toFixed(1) + ',' + g.ey.toFixed(1); }
  function marker(id, color) { return '<marker id="' + id + '" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,1 L9,5 L0,9 z" fill="' + color + '"/></marker>'; }

  function attackerPos() {
    var sim = Core.sim, env = Core.env;
    if (sim.hop) {
      var a = env.byId[sim.hop.adj.from], b = env.byId[sim.hop.adj.to], g = geom(a, b), f = 1 - sim.hop.remaining / sim.hop.total, q = 1 - f;
      return { x: q * q * g.sx + 2 * q * f * g.mx + f * f * g.ex, y: q * q * g.sy + 2 * q * f * g.my + f * f * g.ey };
    }
    var n = sim.head && env.byId[sim.head];
    return n ? { x: n.x, y: n.y } : null;
  }

  function mapSvg() {
    var env = Core.env, st = Core.st, a = Core.analysis, out = '';
    var main = {}, alt = {};
    a.routes.forEach(function (r, i) { r.hops.forEach(function (h) { (i === Core.routeIdx ? main : alt)[h.id] = true; }); });
    out += '<defs>' + marker('ah', '#5b5b6b') + marker('ahr', '#fbbf24') + marker('aha', '#8a6a1f') + marker('ahg', '#34d399') + '</defs>';
    (env.zones || []).forEach(function (z, i) {
      out += '<rect class="zone' + (i % 2 ? ' alt' : '') + '" x="' + z.x0 + '" y="0" width="' + (z.x1 - z.x0) + '" height="640"/><text class="zlabel" x="' + ((z.x0 + z.x1) / 2) + '" y="24" text-anchor="middle">' + esc(z.name) + '</text>';
    });
    env.edges.forEach(function (e) {
      var d = pathD(geom(env.byId[e.from], env.byId[e.to])), dead = st.removed.has(e.from) || st.removed.has(e.to), blocked = st.blocked.has(e.id);
      var cls = 'edge' + (main[e.id] ? ' route' : alt[e.id] ? ' alt' : '') + (blocked ? ' blocked' : '') + (dead ? ' dead' : '');
      out += '<path class="' + cls + '" d="' + d + '" marker-end="url(#' + (main[e.id] ? 'ahr' : blocked ? 'ahg' : alt[e.id] ? 'aha' : 'ah') + ')"/>';
      out += '<path class="edge hit" d="' + d + '" data-act="map-edge" data-id="' + esc(e.id) + '"><title>' + esc(env.byId[e.from].label + ' → ' + env.byId[e.to].label + ': ' + e.tid + ' ' + e.tname) + '</title></path>';
    });
    var breached = {};
    a.destinations.forEach(function (d) { if (d.status === 'breached') breached[d.id] = true; });
    var sel = Core.selected;
    env.nodes.forEach(function (n) {
      var comp = st.compromised.has(n.id) && !st.removed.has(n.id), iso = st.removed.has(n.id);
      var cls = 'node' + (n.crown ? ' crown' : '') + (comp ? ' comp' : '') + (iso ? ' iso' : '') + (breached[n.id] ? ' breach' : '') + (sel && sel.kind === 'node' && sel.id === n.id ? ' sel' : '');
      out += '<g class="' + cls + '" data-act="map-node" data-id="' + esc(n.id) + '" tabindex="0" role="button" aria-label="' + esc(n.label + (comp ? ', compromised' : iso ? ', isolated' : '') + (n.crown ? ', crown jewel' : '')) + '" transform="translate(' + n.x + ',' + n.y + ')">';
      if (comp) out += '<circle class="pulse" r="21"/>';
      out += n.crown ? '<rect class="body" x="-17" y="-17" width="34" height="34" rx="6" transform="rotate(45)"/>' : '<circle class="body" r="19"/>';
      out += '<text class="glyph">' + (GLYPH[n.type] || '●') + '</text>';
      if (iso) out += '<path class="xmark" d="M-9,-9 L9,9 M9,-9 L-9,9"/>';
      out += '<text class="nlabel" y="' + (n.crown ? 35 : 34) + '">' + esc(n.label) + '</text></g>';
    });
    out += '<circle id="atk" class="attacker" r="7" cx="0" cy="0" style="display:none"/>';
    return out;
  }

  function bannerHtml() {
    var b = Core.banner;
    if (b && b.until && Date.now() > b.until) { Core.banner = null; b = null; }
    return '<div class="banner ' + (b ? 'show ' + esc(b.kind) : '') + '" id="banner" role="status">' + (b ? esc(b.text) : '') + '</div>';
  }

  function etaCard() {
    var a = Core.analysis, h = a.headline, route = a.routes[Core.routeIdx] || (h && h.route), cls = 'big', val, to, sub = '';
    if (!h) { val = 'Contained'; cls += ' ok'; to = 'No route to any crown jewel'; }
    else if (h.status === 'breached') { val = 'BREACHED'; cls += ' hot'; to = h.node.label; sub = 'Attacker already has access'; }
    else { val = G.fmt(Core.liveEta()); to = h.node.label; sub = route.hops.length + ' hops · ' + Math.round(route.p * 100) + '% chance every step works first time'; }
    var tabs = a.routes.map(function (r, i) { return '<button class="rtab' + (i === Core.routeIdx ? ' on' : '') + '" data-act="route" data-r="' + i + '">' + (i === 0 ? 'Fastest' : 'Alt ' + i) + ' · ' + G.fmt(r.minutes) + '</button>'; }).join('');
    var steps;
    if (!route) steps = '<li class="empty">' + (h ? 'The attacker is already at the destination. Move to eradication and recovery.' : 'No active route. Keep hunting for further footholds.') + '</li>';
    else steps = G.directions(Core.env, route).map(function (d) {
      return '<li class="step"><div class="tm">+' + G.fmt(d.at) + '</div><div><b>' + esc(d.from.label) + ' → ' + esc(d.to.label) + '</b><div class="tech">' + esc(d.tid + ' ' + d.tname) + ' · ' + esc(d.tactic || '') + '</div>' +
        '<div class="fix">Cut it: ' + esc(d.remedy || 'Block this path') + '</div><div class="row" style="margin-top:6px"><button class="btn sm" data-act="block" data-id="' + esc(d.edgeId) + '">Block</button><button class="btn sm ghost" data-act="hunt" data-tid="' + esc(d.tid) + '">Hunt</button><button class="btn sm ghost" data-act="why" data-id="' + esc(d.edgeId) + '">Why this number?</button></div></div></li>';
    }).join('');
    return '<section class="card"><h3>Estimated time to breach</h3><div class="eta"><div class="' + cls + '" id="eta">' + esc(val) + '</div><div class="to"><b>' + esc(to) + '</b><span id="etaSub">' + esc(sub) + '</span></div></div>' + (h && h.status !== 'breached' ? root.Unc.rangeBlock() : '') +
      '<div class="rtabs" role="tablist">' + tabs + '</div><h3 style="margin-top:14px">Turn-by-turn route</h3><ol class="steps">' + steps + '</ol></section>';
  }

  function recText(r) {
    if (r.contains) return 'Contains the attacker';
    var parts = [];
    if (r.delta > 0.5) parts.push('+' + G.fmt(r.delta) + ' delay');
    if (r.saved > 0) parts.push('protects ' + r.saved + ' crown jewel' + (r.saved > 1 ? 's' : ''));
    return parts.join(' · ');
  }
  function recsCard() {
    var env = Core.env, st = Core.st, sel = Core.selected, html = '';
    if (sel) {
      if (sel.kind === 'node') {
        var n = env.byId[sel.id];
        html += '<div class="rec"><div class="row"><b>Selected: ' + esc(n.label) + '</b></div><div class="meta">' + esc(n.type) + ' · ' + esc(n.zone || '') + ' · business impact ' + n.businessImpact + '/10' + (n.crown ? ' · crown jewel' : '') + '</div>' +
          '<button class="btn primary sm" data-act="isolate" data-id="' + esc(n.id) + '"' + (st.removed.has(n.id) ? ' disabled' : '') + '>' + esc(G.VERBS[n.type] || 'Isolate') + '</button></div>';
      } else {
        var e = env.edges.find(function (x) { return x.id === sel.id; });
        if (e) html += '<div class="rec"><div class="row"><b>Selected path</b></div><div class="meta">' + esc(env.byId[e.from].label + ' → ' + env.byId[e.to].label) + ' · ' + esc(e.tid + ' ' + e.tname) + '</div>' +
          '<button class="btn primary sm" data-act="block" data-id="' + esc(e.id) + '"' + (st.blocked.has(e.id) ? ' disabled' : '') + '>' + esc(e.remedy || 'Block this path') + '</button></div>';
      }
    }
    if (Core.sim.status !== 'running') html += '<div class="empty">' + (Core.sim.status === 'contained' ? 'Contained. Review the timeline, then export the report.' : 'A crown jewel was breached. Export the report to capture lessons learned.') + '</div>';
    else if (!Core.recs.length) html += '<div class="empty">No single move improves the position. Hunt for additional footholds.</div>';
    Core.recs.forEach(function (r, i) {
      html += '<div class="rec' + (i === 0 ? ' top' : '') + '"><div class="row" style="justify-content:space-between;flex-wrap:nowrap"><b>' + esc(r.verb) + '</b><span class="gain">' + esc(recText(r)) + '</span></div>' +
        '<div class="meta">' + esc(r.label) + '<br><span class="chip mut">impact ' + r.impact + '/10</span> <span class="chip mut">lands in ~' + r.exec + ' min</span></div>' +
        '<button class="btn ' + (i === 0 ? 'primary ' : '') + 'sm" data-act="rec" data-i="' + i + '">' + (i === 0 ? 'Take this turn' : 'Execute') + '</button></div>';
    });
    var pend = Core.pending.length ? '<div class="pending">In flight: ' + Core.pending.map(function (p) { return esc(p.text) + ' (' + G.fmt(Math.max(0, p.at - Core.sim.t)) + ')'; }).join('; ') + '</div>' : '';
    return '<section class="card"><div class="chead"><h2>Next best moves</h2><small>by delay gained vs. impact</small></div><div class="recs">' + html + '</div>' + pend + '</section>';
  }

  function destsCard() {
    var list = Core.analysis.destinations.map(function (d) {
      var cls = d.status === 'breached' ? 'hot' : d.status === 'at-risk' ? 'risk' : 'ok';
      var eta = d.status === 'breached' ? 'BREACHED' : d.status === 'at-risk' ? G.fmt(d.eta) : d.status === 'isolated' ? 'Isolated' : 'Safe';
      return '<div class="dest ' + cls + '"><b>' + esc(d.node.label) + '</b><span class="e">' + eta + '</span><small class="mut">' + (d.route ? Math.round(d.p * 100) + '% success · ' + d.route.hops.length + ' hops' : d.status === 'isolated' ? 'Taken offline' : 'No route') + '</small></div>';
    }).join('');
    return '<section class="card"><div class="chead"><h2>Crown jewels</h2></div><div class="dests">' + list + '</div></section>';
  }

  function ctlCard() {
    var list = Core.env.controls.map(function (c) {
      return '<label class="ctl"><input type="checkbox" data-act="ctl" data-c="' + esc(c.id) + '"' + (Core.st.controls[c.id] ? ' checked' : '') + '><div><b>' + esc(c.label) + '</b><span>' + esc(c.desc || '') + '</span></div></label>';
    }).join('');
    return '<section class="card"><div class="chead"><h2>What if…</h2><small>toggle a control, ETA recalculates</small></div>' + (list || '<div class="empty">No controls defined. Add some in Assets.</div>') + '</section>';
  }

  function logCard() {
    var items = Core.log.slice().reverse().map(function (l) { return '<li><span class="lt">' + Core.clockStr(l.t) + '</span><span class="' + esc(l.type) + '">' + esc(l.text) + '</span></li>'; }).join('');
    return '<section class="card"><div class="chead"><h2>Timeline</h2><small>' + Core.log.length + ' events</small></div><ul class="log">' + items + '</ul></section>';
  }

  Views.navigator = {
    title: 'Navigator',
    render: function () {
      var env = Core.env, sim = Core.sim, linked = Core.linkedId ? Core.getIncident(Core.linkedId) : null;
      var scn = env.scenarios.map(function (s, i) { return '<option value="' + i + '"' + (i === Core.scnIdx ? ' selected' : '') + '>' + esc(s.name) + '</option>'; }).join('');
      var spd = [1, 4, 16].map(function (v) { return '<button class="' + (Core.settings.simSpeed === v ? 'on' : '') + '" data-act="speed" data-v="' + v + '" aria-pressed="' + (Core.settings.simSpeed === v) + '">' + v + '×</button>'; }).join('');
      var profile = Core.REF.speedProfiles.find(function (p) { return p.id === Core.settings.speedProfile; });
      var left = '<section class="card"><div class="chead"><h2>Attack map</h2><select class="select" data-act="scenario" aria-label="Scenario">' + scn + '</select></div>' +
        '<div class="mapwrap">' + bannerHtml() + '<svg id="map" viewBox="0 0 1000 640" role="group" aria-label="Network attack map">' + mapSvg() + '</svg>' +
        '<div class="maplegend"><span><i class="dot" style="background:var(--red)"></i>Compromised</span><span><i class="dot" style="background:var(--amber)"></i>Predicted route</span><span><i class="dot" style="background:var(--green)"></i>Isolated / blocked</span><span>◇ Crown jewel</span></div></div>' +
        '<div class="simbar"><button class="btn primary" data-act="toggle"' + (sim.status !== 'running' ? ' disabled' : '') + '>' + icon(Core.isRunning() ? 'pause' : 'play') + (Core.isRunning() ? 'Pause' : sim.t > 0 ? 'Resume' : 'Start attacker') + '</button>' +
        '<button class="btn" data-act="reset">' + icon('rerun') + 'Reset</button><div class="clock"><small>Incident clock</small><b id="clk">' + Core.clockStr(sim.t) + '</b></div><div class="seg" role="group" aria-label="Simulation speed">' + spd + '</div>' +
        '<span class="hint">Pace: ' + esc(profile ? profile.label : '') + '. Click a node or path to contain it. Actions land after a short delay while the clock runs.</span></div>' +
        '<div class="simbar" style="margin-top:10px"><button class="btn" data-act="new-incident"' + (linked ? ' disabled' : '') + '>' + icon('incidents') + (linked ? esc(linked.id) + ' linked' : 'Open incident') + '</button>' +
        '<button class="btn" data-act="report">' + icon('reports') + 'Export report</button><button class="btn ghost" data-act="go" data-to="playbooks">' + icon('playbooks') + 'Playbook</button></div></section>' + logCard();
      return '<div class="grid g-nav"><div class="stack">' + left + '</div><div class="stack">' + etaCard() + recsCard() + destsCard() + ctlCard() + '</div></div>';
    },
    after: function () { this.tick(); },
    tick: function () {
      var clk = document.getElementById('clk'); if (!clk) return;
      clk.textContent = Core.clockStr(Core.sim.t);
      var h = Core.analysis.headline, eta = document.getElementById('eta');
      if (eta && h && h.status !== 'breached') eta.textContent = G.fmt(Core.liveEta());
      var ub = document.getElementById('uncBox');
      if (ub && Core.sim.status === 'running') { var now = Date.now(); if (now - (this._u || 0) > 450) { this._u = now; ub.innerHTML = root.Unc.rangeInner(); } }
      var banner = document.getElementById('banner');
      if (banner && Core.banner && Core.banner.until && Date.now() > Core.banner.until) { Core.banner = null; banner.className = 'banner'; banner.textContent = ''; }
      var atk = document.getElementById('atk'), p = attackerPos();
      if (atk) { if (p && Core.sim.status !== 'contained') { atk.setAttribute('cx', p.x.toFixed(1)); atk.setAttribute('cy', p.y.toFixed(1)); atk.style.display = ''; } else atk.style.display = 'none'; }
    },
    act: function (name, el) {
      var id = el && el.getAttribute && el.getAttribute('data-id');
      switch (name) {
        case 'toggle': Core.toggle(); return true;
        case 'reset': Core.startScenario(Core.scnIdx); return true;
        case 'scenario': Core.startScenario(parseInt(el.value, 10)); return true;
        case 'speed': Core.setSetting('simSpeed', parseInt(el.getAttribute('data-v'), 10)); return true;
        case 'route': Core.routeIdx = parseInt(el.getAttribute('data-r'), 10); Core.emit('state'); return true;
        case 'map-node': Core.select(Core.selected && Core.selected.id === id ? null : { kind: 'node', id: id }); return true;
        case 'map-edge': Core.select({ kind: 'edge', id: id }); return true;
        case 'isolate': Core.execute(Core.actionFromNode(id)); return true;
        case 'block': Core.execute(Core.actionFromEdge(id)); return true;
        case 'rec': Core.execute(Core.recs[parseInt(el.getAttribute('data-i'), 10)]); return true;
        case 'ctl': Core.setControl(el.getAttribute('data-c'), el.checked); return true;
        case 'hunt': Views.hunt.sel = el.getAttribute('data-tid'); root.App.go('hunt'); return true;
        case 'why': root.Unc.why(id); return true;
        case 'report': UI.textModal('Incident report (Markdown)', root.Reports.incidentMd(), 'ir-gps-report.md'); return true;
        case 'new-incident': { var inc = Core.createIncident(); Views.incidents.sel = inc.id; UI.toast('Opened ' + inc.id + '. It updates as you contain.', 'ok'); Core.emit('state'); return true; }
      }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
