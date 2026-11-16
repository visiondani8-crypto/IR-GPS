/* Validation: test the model's timing assumptions against documented public intrusions, and show the evidence behind them. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};
  var V = root.IRGPSVal, D = root.IRGPSValData;

  function f(x) { return G.fmt(x); }
  function caseOf(id) { return D.cases.find(function (c) { return c.id === id; }); }
  function link(url, text) { return '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(text) + '</a>'; }
  function ratioTxt(r) { return r >= 1 ? (r >= 10 ? Math.round(r) : r.toFixed(1)) + '× slower' : (1 / r >= 10 ? Math.round(1 / r) : (1 / r).toFixed(1)) + '× faster'; }

  function check(r) {
    var lo = Infinity, hi = 0;
    r.rows.forEach(function (x) { lo = Math.min(lo, x.p10, x.minutes); hi = Math.max(hi, x.p90, x.minutes); });
    lo = lo / 1.4; hi = hi * 1.4;
    var L = Math.log(lo), H = Math.log(hi);
    function pos(v) { return Math.max(0, Math.min(100, (Math.log(v) - L) / (H - L) * 100)); }
    var body = r.rows.map(function (x) {
      var c = caseOf(x.caseId), cls = x.inBand ? 'ok' : 'out';
      return '<tr><td><b>' + esc(x.label) + '</b><small class="mut" style="display:block">' + esc(c.name) + ' · ' + x.hops + ' hop' + (x.hops > 1 ? 's' : '') + ' · ' + link(c.url, 'report') + '</small></td>' +
        '<td><b>' + esc(f(x.minutes)) + '</b></td>' +
        '<td><div class="vtrack" role="img" aria-label="Observed ' + esc(f(x.minutes)) + ' against a model band of ' + esc(f(x.p10)) + ' to ' + esc(f(x.p90)) + '"><i class="band" style="left:' + pos(x.p10).toFixed(1) + '%;width:' + Math.max(1, pos(x.p90) - pos(x.p10)).toFixed(1) + '%"></i><i class="p50" style="left:' + pos(x.p50).toFixed(1) + '%"></i><i class="obs ' + (x.inBand ? '' : 'out') + '" style="left:' + pos(x.minutes).toFixed(1) + '%"></i></div>' +
        '<small class="mut">model: ' + esc(f(x.p10)) + ' – ' + esc(f(x.p90)) + ', typical ' + esc(f(x.p50)) + '</small></td>' +
        '<td><span class="chip ' + (x.inBand ? '' : x.side === 'faster' ? 'red' : 'amber') + '">' + (x.inBand ? 'inside band' : x.side === 'faster' ? 'faster than P10' : 'slower than P90') + '</span><small class="mut" style="display:block">' + esc(ratioTxt(x.ratio)) + ' than typical</small></td></tr>';
    }).join('');
    return '<div class="tablewrap"><table class="t vt"><thead><tr><th>Documented stretch</th><th>Observed</th><th>Model says (P10 to P90, log scale)</th><th>Result</th></tr></thead><tbody>' + body + '</tbody></table></div>' +
      '<div class="histlegend"><span><i style="background:var(--accent)"></i>model P10–P90</span><span><i style="background:var(--mut)"></i>typical (P50)</span><span><i style="background:var(--green)"></i>observed, inside</span><span><i style="background:var(--red)"></i>observed, outside</span></div>';
  }

  function dwellChart() {
    var s = V.dwellStats(), lo = Math.log(5), hi = Math.log(2400);
    function pos(v) { return (Math.log(v) - lo) / (hi - lo) * 100; }
    var dots = D.dwell.map(function (d) { return '<i class="obs" style="left:' + pos(d.minutes).toFixed(1) + '%" title="' + esc(d.label + ': ' + f(d.minutes) + (d.bound === 'max' ? ' or less' : '')) + '"></i>'; }).join('');
    var ticks = [[10, '10m'], [60, '1h'], [360, '6h'], [1440, '1d']].map(function (t) { return '<span style="position:absolute;left:' + pos(t[0]).toFixed(1) + '%;transform:translateX(-50%)">' + t[1] + '</span>'; }).join('');
    return '<div class="vtrack" style="margin:14px 0 6px">' + dots + '</div><div style="position:relative;height:16px;font-size:11px;color:var(--mut2)">' + ticks + '</div>' +
      '<p class="mut" style="margin:10px 0 0;font-size:13px">In ' + s.n + ' ransomware intrusions, a human took over a median of <b style="color:var(--text)">' + esc(f(s.median)) + '</b> after the first execution. ' + Math.round(s.within60 * 100) + '% were hands-on within an hour, ' + Math.round(s.within240 * 100) + '% within four, and the slowest waited ' + esc(f(s.max)) + '. The model\'s clock starts at your alert, so this wait is not in the ETA. It is why a quiet first hour proves little.</p>';
  }

  function modelCheck() {
    var r = Core.validation(), S = Core.settings.sigmaScale || 1, v = r.verdict;
    var head = '<section class="card"><div class="chead"><div><h2>Does the model agree with real intrusions?</h2><small class="mut">A plausibility check on ' + r.n + ' documented stretches from public reports. Not a proof.</small></div></div>' +
      '<div class="verdict ' + esc(v.level) + '"><span style="margin-top:2px">' + icon(v.level === 'ok' ? 'check' : 'info') + '</span><div><b>' + esc(v.headline) + '</b><span class="mut">' + esc(v.detail || '') + '</span></div></div>' +
      '<div class="rng-chips" style="margin-top:14px"><div class="rc"><b>' + r.inside + ' of ' + r.n + '</b><small>inside the P10–P90 band (80% expected)</small></div>' +
      '<div class="rc"><b>' + (r.bias ? r.bias.toFixed(2) + '×' : '-') + '</b><small>observed ÷ model typical, median</small></div>' +
      '<div class="rc"><b>' + (r.sharpness ? Math.round(r.sharpness) + '×' : '-') + '</b><small>how wide the bands are (P90 ÷ P10)</small></div></div>' +
      '<ul class="caveats">' + r.caveats.map(function (c) { return '<li>' + esc(c) + '</li>'; }).join('') + '</ul>';
    var actions = '';
    if (r.suggest && r.suggest.scale > S + 1e-9) actions = '<div class="hr"></div><div class="row"><div><b>Widen the model\'s spreads to ×' + r.suggest.scale + '?</b><small class="mut" style="display:block">That would have put ' + Math.round(r.suggest.coverage * 100) + '% of these cases inside the band. With this few cases, treat it as a nudge, not a fit.</small></div><button class="btn primary sm" style="margin-left:auto" data-act="val-widen" data-v="' + r.suggest.scale + '">Apply ×' + r.suggest.scale + '</button></div>';
    else if (S !== 1) actions = '<div class="hr"></div><div class="row"><div><b>Uncertainty width is ×' + S + '</b><small class="mut" style="display:block">Set in Settings or from this screen.</small></div><button class="btn sm" style="margin-left:auto" data-act="val-widen" data-v="1">Back to ×1</button></div>';
    head += actions + '</section>';
    var method = '<section class="card"><div class="chead"><h2>How this is tested</h2></div><ol class="plain" style="padding-left:18px;margin:0;display:grid;gap:8px;color:var(--mut);font-size:13px">' +
      '<li>Each row is a stretch of a real intrusion with a documented duration and a hop count. Hop counts are my reading of each report, listed on the Evidence tab.</li>' +
      '<li>For each row the model draws that many hops from your environment\'s post-foothold steps (median hop ' + esc(f(r.pool.median)) + ', ' + r.pool.hops + ' steps), with the same spreads, shared attacker pace and ' + (r.options.persistent ? 'retries' : 'single attempts') + ' as the live ETA.</li>' +
      '<li>It checks whether the real duration lands inside the model\'s P10–P90 band. Controls are ignored, because these victims were compromised anyway.</li>' +
      '<li>A wide band is easy to hit, so the screen also reports band width. Twelve or more rows would be needed before this could be called validation.</li></ol></section>';
    var rows = '<section class="card"><div class="chead"><h2>Documented stretches vs the model</h2><small>' + esc(Core.env.scenarios[Core.scnIdx].name) + ' environment, pace ×' + Core.st.speed + '</small></div>' + check(r) + '</section>';
    var ctx = '<section class="card"><div class="chead"><div><h2>Context: the wait before a human takes over</h2><small class="mut">Time from first execution to hands-on-keyboard, 10 public cases</small></div></div>' + dwellChart() + '</section>';
    return head + '<div class="g2e">' + method + ctx + '</div>' + rows;
  }

  function evidence() {
    var cases = D.cases.map(function (c) {
      return '<tr><td><b>' + esc(c.name) + '</b><small class="mut" style="display:block">' + esc(c.source) + ' · ' + esc(c.published) + ' · ' + link(c.url, 'open report') + '</small></td>' +
        '<td>' + esc(c.t0) + '</td><td><ul class="plain">' + c.milestones.map(function (m) { return '<li>' + (m.t != null ? '<b>' + (m.bound === 'max' ? '≤ ' : '') + esc(f(m.t)) + '</b> ' : '') + esc(m.label) + '</li>'; }).join('') + '</ul></td>' +
        '<td>' + (c.ttr ? '<b>' + esc(f(c.ttr)) + '</b>' : '-') + '</td></tr>';
    }).join('');
    var phases = D.phases.map(function (p) {
      return '<tr><td><b>' + esc(p.label) + '</b><small class="mut" style="display:block">' + esc(caseOf(p.caseId).name) + '</small></td><td>' + esc(f(p.minutes)) + '</td><td>' + p.hops + '</td><td class="mut" style="font-size:12px">' + esc(p.hopsBasis) + '</td></tr>';
    }).join('');
    var dwell = D.dwell.map(function (d) { return '<tr><td>' + link(d.url, d.label) + '</td><td>' + (d.bound === 'max' ? '≤ ' : '') + esc(f(d.minutes)) + '</td><td class="mut">' + esc(d.basis) + '</td></tr>'; }).join('');
    var bench = D.benchmarks.map(function (b) {
      return '<tr><td><b>' + esc(b.org) + '</b><small class="mut" style="display:block">' + esc(b.report) + '</small></td><td>' + esc(b.metric) + '</td><td><b>' + esc(f(b.minutes)) + '</b><small class="mut" style="display:block">' + esc(b.extra) + '</small></td><td>' + link(b.url, 'source') + '<small class="mut" style="display:block">' + esc(b.reliability) + '</small></td></tr>';
    }).join('');
    return '<section class="card"><div class="chead"><div><h2>Intrusions with documented timings</h2><small class="mut">Transcribed by hand from the reports. Times are as the reports give them, rounded. Check the source before relying on any row.</small></div></div>' +
      '<div class="tablewrap"><table class="t"><thead><tr><th>Case</th><th>T0 is</th><th>What the report documents</th><th>Time to ransom</th></tr></thead><tbody>' + cases + '</tbody></table></div></section>' +
      '<section class="card"><div class="chead"><div><h2>Stretches the model is tested on</h2><small class="mut">Duration and hop count per row. The hop count is my reading of the report, not a figure it states.</small></div></div>' +
      '<div class="tablewrap"><table class="t"><thead><tr><th>Stretch</th><th>Duration</th><th>Hops</th><th>Basis for the hop count</th></tr></thead><tbody>' + phases + '</tbody></table></div></section>' +
      '<section class="card"><div class="chead"><div><h2>Time to hands-on-keyboard</h2><small class="mut">Minutes from first execution to a human operating the intrusion</small></div></div>' +
      '<div class="tablewrap"><table class="t"><thead><tr><th>Case</th><th>Wait</th><th>What the report says</th></tr></thead><tbody>' + dwell + '</tbody></table></div></section>' +
      '<section class="card"><div class="chead"><div><h2>Vendor benchmarks (context, not tests)</h2><small class="mut">Their scopes differ from the model\'s ETA, which starts at your alert. Shown so you can see the order of magnitude.</small></div></div>' +
      '<div class="tablewrap"><table class="t"><thead><tr><th>Source</th><th>Measure</th><th>Value</th><th>Link</th></tr></thead><tbody>' + bench + '</tbody></table></div></section>';
  }

  Views.validation = {
    title: 'Validation', tabs: ['Model check', 'Evidence'],
    render: function (tab) { return tab === 'Evidence' ? evidence() : modelCheck(); },
    act: function (name, el) {
      if (name === 'val-widen') { Core.setSetting('sigmaScale', parseFloat(el.getAttribute('data-v'))); UI.toast('Uncertainty width set to ×' + Core.settings.sigmaScale + '.', 'ok'); return true; }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
