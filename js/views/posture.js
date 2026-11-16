/* Posture: ATT&CK-style coverage matrix for your attack paths, plus a hardening advisor that prices each control. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};

  function matrix() {
    var st = Core.st, by = {};
    Core.env.edges.forEach(function (e) {
      var tac = e.tactic || 'Other', col = by[tac] || (by[tac] = {}), t = col[e.tid] || (col[e.tid] = { tid: e.tid, name: e.tname, tactic: tac, edges: [], controls: {}, mit: 0 });
      t.edges.push(e); e.controls.forEach(function (c) { t.controls[c] = true; });
      if (e.controls.some(function (c) { return st.controls[c]; })) t.mit++;
    });
    var order = Core.REF.tacticOrder.filter(function (t) { return by[t]; }).concat(Object.keys(by).filter(function (t) { return Core.REF.tacticOrder.indexOf(t) < 0; }).sort());
    return order.map(function (tac) {
      return { tactic: tac, techs: Object.keys(by[tac]).map(function (k) { var t = by[tac][k]; t.state = t.mit === t.edges.length ? 'covered' : t.mit > 0 ? 'partial' : 'gap'; return t; }) };
    });
  }

  Views.posture = {
    title: 'Posture', tabs: ['Coverage', 'Hardening'],
    render: function (tab) {
      if (tab === 'Hardening') return this.hardening();
      var cols = matrix(), all = [].concat.apply([], cols.map(function (c) { return c.techs; }));
      var n = function (s) { return all.filter(function (t) { return t.state === s; }).length; };
      var sum = '<div class="grid g3"><section class="card kpi"><div class="lbl">Covered</div><div class="val" style="color:var(--green)">' + n('covered') + '<small>of ' + all.length + '</small></div><div class="foot">Every use of the technique is slowed by an active control</div></section>' +
        '<section class="card kpi"><div class="lbl">Partial</div><div class="val" style="color:var(--amber)">' + n('partial') + '</div><div class="foot">Some paths mitigated, others open</div></section>' +
        '<section class="card kpi"><div class="lbl">Gaps</div><div class="val" style="color:var(--red)">' + n('gap') + '</div><div class="foot">No active control on any path using it</div></section></div>';
      var grid = cols.map(function (c) {
        return '<div class="mcol"><h4>' + esc(c.tactic) + ' <span class="mut">(' + c.techs.length + ')</span></h4>' + c.techs.map(function (t) {
          var ctl = Object.keys(t.controls).map(function (id) { var cc = Core.env.controls.find(function (x) { return x.id === id; }); return '<span class="cc ' + (Core.st.controls[id] ? 'on' : 'off') + '">' + esc(cc ? cc.label.split(' ')[0] : id) + '</span>'; }).join('');
          return '<button class="tcell ' + t.state + '" data-act="tech" data-tid="' + esc(t.tid) + '"><span class="id">' + esc(t.tid) + '</span><b>' + esc(t.name) + '</b><div class="cs">' + (ctl || '<span class="cc off">no control defined</span>') + '</div></button>';
        }).join('') + '</div>';
      }).join('');
      return sum + '<section class="card"><div class="chead"><h2>Control coverage of your attack paths</h2><div class="legend" style="margin-left:auto"><span><i style="background:var(--green)"></i>Covered</span><span><i style="background:var(--amber)"></i>Partial</span><span><i style="background:var(--red)"></i>Gap</span></div></div><div class="matrix">' + grid + '</div>' +
        '<p class="mut" style="font-size:12px;margin:8px 0 0">Shows only the techniques that appear on edges of your modelled environment, not the full ATT&amp;CK matrix. A control counts when it is switched on and listed against that edge.</p></section>';
    },
    hardening: function () {
      var rows = G.hardening(Core.env, Core.st, Core.env.scenarios), base = Core.baseline(), now = G.exposure(Core.env, Core.st);
      rows.forEach(function (r) { r.value = Math.abs(r.avgDeltaExp) + Math.abs(r.deltaEta) / 6; });
      rows.sort(function (a, b) { return b.value - a.value; });
      var maxV = Math.max(1, rows[0] ? rows[0].value : 1);
      var off = rows.filter(function (r) { return !r.enabled && (r.avgDeltaExp < 0 || r.deltaEta > 0); });
      var advice = off.length ? 'Switch on <b>' + esc(off[0].label) + '</b> first: it is worth ' + (off[0].deltaEta > 0 ? '+' + G.fmt(off[0].deltaEta) + ' of attacker delay on this incident' : 'a lower average exposure') + (off[0].avgDeltaExp < 0 ? ' and ' + Math.abs(off[0].avgDeltaExp) + ' points of average exposure across all scenarios.' : '.') : 'All controls that matter in this model are already on. Review the table for ones whose value is low.';
      var body = rows.map(function (r) {
        var eff = r.enabled ? 'Turning it off: ETA ' + (r.deltaEta ? G.fmt(Math.abs(r.deltaEta)) + ' ' + (r.deltaEta < 0 ? 'sooner' : 'later') : 'unchanged') : 'Turning it on: ETA ' + (r.deltaEta ? G.fmt(Math.abs(r.deltaEta)) + ' ' + (r.deltaEta > 0 ? 'later' : 'sooner') : 'unchanged');
        var avg = r.avgDeltaExp === 0 ? 'no change' : (r.avgDeltaExp > 0 ? '+' : '') + r.avgDeltaExp + ' pts';
        return '<tr><td><label class="switch" style="margin:0"><input type="checkbox" data-act="ctl" data-c="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + ' aria-label="Toggle ' + esc(r.label) + '"><i></i></label></td>' +
          '<td><b>' + esc(r.label) + '</b><small class="mut" style="display:block">' + esc(r.desc || '') + '</small></td><td>' + r.edges + '</td><td>' + esc(eff) + '</td><td>' + avg + '</td>' +
          '<td style="min-width:130px"><div class="track"><div class="fill' + (r.enabled ? '' : ' amber') + '" style="width:' + Math.round(100 * r.value / maxV) + '%"></div></div></td></tr>';
      }).join('');
      return '<div class="grid g3"><section class="card kpi"><div class="lbl">Exposure now</div><div class="val">' + now + '<small>/ 100</small></div><div class="foot">for the active scenario</div></section>' +
        '<section class="card kpi"><div class="lbl">With every control on</div><div class="val" style="color:var(--green)">' + base.exposure + '<small>/ 100</small></div><div class="foot">best case in this model</div></section>' +
        '<section class="card kpi"><div class="lbl">Fastest ETA, all controls on</div><div class="val">' + G.fmt(base.eta) + '</div><div class="foot">vs ' + G.fmt(Core.analysis.minEta) + ' now</div></section></div>' +
        '<section class="card"><div class="chead"><h2>Hardening advisor</h2><small>what each control buys you</small></div><p style="margin-top:0">' + advice + '</p><div class="tablewrap"><table class="t"><thead><tr><th>On</th><th>Control</th><th>Edges</th><th>Effect on this incident</th><th>Avg. exposure change across scenarios</th><th>Value</th></tr></thead><tbody>' + body + '</tbody></table></div>' +
        '<p class="mut" style="font-size:12px;margin:8px 0 0">Each control multiplies attacker time and success odds on the edges it is listed against. Values are model estimates: calibrate them in Assets. Exposure change is averaged over every scenario, so it shows the control’s general worth, not just today’s incident.</p></section>';
    },
    act: function (name, el) {
      if (name === 'tech') {
        var tid = el.getAttribute('data-tid'), t = null;
        matrix().forEach(function (c) { c.techs.forEach(function (x) { if (x.tid === tid) t = x; }); });
        if (!t) return true;
        var rows = t.edges.map(function (e) {
          var on = e.controls.filter(function (c) { return Core.st.controls[c]; });
          return '<tr><td>' + esc(Core.env.byId[e.from].label + ' → ' + Core.env.byId[e.to].label) + '</td><td>' + (on.length ? on.map(esc).join(', ') : '<span style="color:var(--red)">none active</span>') + '</td><td>' + esc(e.remedy || '-') + '</td></tr>';
        }).join('');
        UI.modal({ title: t.tid + ' ' + t.name, wide: true, body: '<p><span class="chip ' + (t.state === 'covered' ? '' : t.state === 'partial' ? 'amber' : 'red') + '">' + t.state + '</span> <span class="chip acc">' + esc(t.tactic) + '</span></p><div class="tablewrap"><table class="t"><thead><tr><th>Path</th><th>Active controls</th><th>How to cut it</th></tr></thead><tbody>' + rows + '</tbody></table></div>',
          foot: '<button class="btn" data-act="hunt" data-tid="' + esc(t.tid) + '">' + icon('hunt') + 'Hunt guide</button><button class="btn primary" data-act="modal-close">Close</button>' });
        return true;
      }
      if (name === 'ctl') { Core.setControl(el.getAttribute('data-c'), el.checked); return true; }
      if (name === 'hunt') { Views.hunt.sel = el.getAttribute('data-tid'); UI.closeModal(); root.App.go('hunt'); return true; }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
