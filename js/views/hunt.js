/* Hunt: what to look for, where, and a starter KQL query for each technique on your attack paths. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};

  function techniques() {
    var by = {}, onRoute = {};
    Core.analysis.routes.forEach(function (r) { r.hops.forEach(function (h) { onRoute[h.edge.tid] = true; }); });
    Core.env.edges.forEach(function (e) {
      var t = by[e.tid] || (by[e.tid] = { tid: e.tid, name: e.tname, tactic: e.tactic, edges: [], controls: {} });
      t.edges.push(e); e.controls.forEach(function (c) { t.controls[c] = true; });
    });
    return Object.keys(by).map(function (k) { by[k].onRoute = !!onRoute[k]; by[k].has = !!Core.REF.detect[k]; return by[k]; })
      .sort(function (a, b) { return (b.onRoute - a.onRoute) || a.tid.localeCompare(b.tid); });
  }

  function listHtml(q) {
    var sel = Views.hunt.sel, items = techniques().filter(function (t) { return !q || (t.tid + ' ' + t.name + ' ' + (t.tactic || '')).toLowerCase().indexOf(q.toLowerCase()) >= 0; });
    return items.map(function (t) {
      return '<button class="listbtn' + (t.tid === sel ? ' on' : '') + '" data-act="hunt-select" data-tid="' + esc(t.tid) + '"><div class="row" style="justify-content:space-between;flex-wrap:nowrap"><b>' + esc(t.name) + '</b>' + (t.onRoute ? '<span class="chip amber">on route</span>' : '') + '</div>' +
        '<small class="mut mono">' + esc(t.tid) + ' · ' + esc(t.tactic || '') + '</small></button>';
    }).join('') || '<div class="empty">No techniques match.</div>';
  }

  Views.hunt = {
    title: 'Hunt', sel: null, q: '',
    render: function () {
      var list = techniques();
      if (!list.some(function (t) { return t.tid === Views.hunt.sel; })) Views.hunt.sel = (list.find(function (t) { return t.onRoute; }) || list[0] || {}).tid;
      var t = list.find(function (x) { return x.tid === Views.hunt.sel; });
      var detail = '<div class="empty">No techniques in this environment.</div>';
      if (t) {
        var d = Core.REF.detect[t.tid], ctl = Object.keys(t.controls).map(function (id) { var c = Core.env.controls.find(function (x) { return x.id === id; }); return '<span class="cc ' + (Core.st.controls[id] ? 'on' : 'off') + '">' + esc(c ? c.label : id) + ' ' + (Core.st.controls[id] ? 'on' : 'off') + '</span>'; }).join('') || '<span class="mut">None defined</span>';
        var uses = t.edges.map(function (e) { return '<li>' + esc(Core.env.byId[e.from].label + ' → ' + Core.env.byId[e.to].label) + '<small class="mut"> · ~' + Math.round(e.minutes) + ' min, ' + Math.round(e.p * 100) + '% base success</small></li>'; }).join('');
        detail = '<div class="chead"><div><h2>' + esc(t.name) + '</h2><small class="mut mono">' + esc(t.tid) + ' · ' + esc(t.tactic || '') + '</small></div><a class="btn sm" style="margin-left:auto" href="' + esc(Core.REF.attackUrl(t.tid)) + '" target="_blank" rel="noopener">MITRE ATT&amp;CK ' + icon('link') + '</a></div>' +
          (t.onRoute ? '<p><span class="chip amber">On a predicted route</span> Hunting here shortens the time to find the attacker mid-path.</p>' : '') +
          (d ? '<h3>Where to look</h3><p style="margin-top:0">' + esc(d.src) + '</p><h3>What to look for</h3><p style="margin-top:0">' + esc(d.look) + '</p><div class="chead" style="margin-top:14px;margin-bottom:6px"><h3 style="margin:0">Starter query (KQL)</h3><button class="btn sm" style="margin-left:auto" data-act="hunt-copy">' + icon('copy') + 'Copy</button></div><pre class="code" id="kql">' + esc(d.kql) + '</pre><p class="mut" style="font-size:12px">Starter queries are examples. Tune thresholds and table names to your tenant and test in a non-production workspace first.</p>'
            : '<div class="note">No starter detection content for ' + esc(t.tid) + ' yet. Use the ATT&amp;CK page for data sources and detection ideas.</div>') +
          '<h3 style="margin-top:14px">Where this technique appears in your environment</h3><ul style="margin:0;padding-left:18px">' + uses + '</ul><h3 style="margin-top:14px">Controls that slow it</h3><div class="chips">' + ctl + '</div>';
      }
      return '<div class="grid g-split"><section class="card"><div class="chead"><h2>Techniques</h2><small>' + list.length + ' in this environment</small></div><input class="input" data-act="hunt-q" data-live="1" placeholder="Filter by name, id or tactic" value="' + esc(Views.hunt.q) + '" aria-label="Filter techniques" style="margin-bottom:10px"><div class="stack" id="hunt-list" style="gap:8px;max-height:70vh;overflow:auto">' + listHtml(Views.hunt.q) + '</div></section><section class="card">' + detail + '</section></div>';
    },
    act: function (name, el) {
      if (name === 'hunt-q') { this.q = el.value; document.getElementById('hunt-list').innerHTML = listHtml(this.q); return true; }
      if (name === 'hunt-select') { this.sel = el.getAttribute('data-tid'); root.App.render(); return true; }
      if (name === 'hunt-copy') { var txt = document.getElementById('kql').textContent; UI.copy(txt).then(function () { UI.toast('Query copied.', 'ok'); }, function () { UI.toast('Copy is blocked here. Select the query and copy manually.', 'err'); }); return true; }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
