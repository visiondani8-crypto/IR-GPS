/* Shared uncertainty widgets: range bar, breach-time histogram, "what drives the ETA" bars, and the "Why this number?" modal. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc;
  var Unc = root.Unc = {};

  function niceMax(x) {
    var steps = [10, 15, 20, 30, 45, 60, 90, 120, 180, 240, 360, 480];
    for (var i = 0; i < steps.length; i++) if (x <= steps[i]) return steps[i];
    return Math.ceil(x / 60) * 60;
  }
  function pct(v, max) { return Math.max(0, Math.min(100, (v / max) * 100)); }
  function f(x) { return G.fmt(x); }
  function ok(u) { return u && u.status === 'at-risk' && u.p50 != null; }

  Unc.confBadge = function (conf, title) {
    var c = conf === 'high' || conf === 'med' ? conf : 'low';
    return '<span class="cf ' + c + '" title="' + esc(title || ({ low: 'Prior or illustrative value', med: 'Some evidence behind it', high: 'Well supported by observations' })[c]) + '">' + ({ low: 'Prior', med: 'Some data', high: 'Calibrated' })[c] + '</span>';
  };

  // The three headline probabilities.
  Unc.chances = function (u) {
    return '<div class="rng-chips">' + [15, 30, 60].map(function (T) {
      return '<div class="rc"><b>' + Math.round(100 * u.by[T]) + '%</b><small>within ' + T + ' min</small></div>';
    }).join('') + '</div>';
  };

  Unc.rangeInner = function () {
    var u = Core.unc();
    if (!ok(u)) return '';
    var max = niceMax(Math.max(u.p90 * 1.08, u.deterministic * 1.1, 10));
    var det = u.deterministic;
    var txt = u.persistent ? 'Counts retries after failed steps. A real attacker rarely gives up on one route.' :
      'Single attempt: failed steps end that route. Breach chance is a lower bound (' + Math.round(100 * u.pBreach) + '% of simulated attacks got through at all).';
    return '<div class="rng-head"><b>Likely range</b><span>' + f(u.p10) + ' – ' + f(u.p90) + '</span></div>' +
      '<div class="rng-bar" role="img" aria-label="Ten percent of simulated attacks reach a crown jewel within ' + esc(f(u.p10)) + ', half within ' + esc(f(u.p50)) + ', nine in ten within ' + esc(f(u.p90)) + '.">' +
      '<i class="band" style="left:' + pct(u.p10, max).toFixed(1) + '%;width:' + Math.max(1, pct(u.p90, max) - pct(u.p10, max)).toFixed(1) + '%"></i>' +
      '<i class="med" style="left:' + pct(u.p50, max).toFixed(1) + '%" title="Typical (median): ' + esc(f(u.p50)) + '"></i>' +
      (det > 0 && isFinite(det) ? '<i class="fast" style="left:' + pct(det, max).toFixed(1) + '%" title="Fastest path if every step works first time: ' + esc(f(det)) + '"></i>' : '') + '</div>' +
      '<div class="rng-axis"><span>0</span><span>' + max + ' min</span></div>' +
      '<p class="rng-note"><b>Typical ' + esc(f(u.p50)) + '.</b> One attack in ten lands within ' + esc(f(u.p10)) + ', nine in ten within ' + esc(f(u.p90)) + '. The amber marker is the fastest path if every step works first time.</p>' +
      Unc.chances(u) + '<p class="rng-note">' + esc(txt) + '</p>';
  };
  Unc.rangeBlock = function () {
    var inner = Unc.rangeInner();
    return inner ? '<div class="rng" id="uncBox">' + inner + '</div>' : '';
  };
  Unc.short = function () {
    var u = Core.unc();
    return ok(u) ? 'likely ' + f(u.p10) + ' – ' + f(u.p90) : '';
  };

  // Histogram of when the breach lands across the simulated attacks.
  Unc.hist = function (u) {
    if (!ok(u) || !u.hist.counts.length) return '<div class="empty">No simulated attack reaches a crown jewel.</div>';
    var W = 560, H = 190, L = 34, R = 10, T = 14, B = 28, h = u.hist, n = h.counts.length, peak = Math.max.apply(null, h.counts) || 1;
    var X = function (t) { return L + (Math.min(t, h.max) / h.max) * (W - L - R); };
    var bw = (W - L - R) / n, bars = '', i;
    for (i = 0; i < n; i++) {
      var ht = (h.counts[i] / peak) * (H - T - B), x = L + i * bw, mid = (i + 0.5) * h.width;
      var cls = mid <= u.p10 ? 'e' : mid <= u.p90 ? 'm' : 'l';
      bars += '<rect class="hb ' + cls + '" x="' + (x + 1).toFixed(1) + '" y="' + (H - B - ht).toFixed(1) + '" width="' + Math.max(1, bw - 2).toFixed(1) + '" height="' + Math.max(0, ht).toFixed(1) + '" rx="2"/>';
    }
    var ticks = '', step = h.max > 240 ? 60 : h.max > 120 ? 30 : h.max > 60 ? 15 : 10;
    for (var t = 0; t <= h.max; t += step) ticks += '<text x="' + X(t).toFixed(1) + '" y="' + (H - 8) + '" text-anchor="middle">' + t + 'm</text>';
    function mark(v, cls, label, dy) { return '<line class="hl ' + cls + '" x1="' + X(v).toFixed(1) + '" x2="' + X(v).toFixed(1) + '" y1="' + T + '" y2="' + (H - B) + '"/><text class="hm ' + cls + '" x="' + X(v).toFixed(1) + '" y="' + (T - 3 + (dy || 0)) + '" text-anchor="middle">' + label + '</text>'; }
    return '<svg viewBox="0 0 ' + W + ' ' + H + '" class="histsvg" role="img" aria-label="Distribution of simulated breach times. Typical ' + esc(f(u.p50)) + '.">' + bars +
      '<line class="hax" x1="' + L + '" x2="' + (W - R) + '" y1="' + (H - B) + '" y2="' + (H - B) + '"/>' + ticks +
      mark(u.p10, 'p10', 'P10') + mark(u.p50, 'p50', 'P50') + mark(u.p90, 'p90', 'P90') +
      (isFinite(u.deterministic) && u.deterministic > 0 && u.deterministic < h.max ? '<path class="hd" d="M' + X(u.deterministic).toFixed(1) + ',' + (H - B) + 'l-5,9h10z"><title>Fastest path if every step works first time: ' + esc(f(u.deterministic)) + '</title></path>' : '') + '</svg>';
  };

  Unc.crowns = function (u) {
    if (!ok(u)) return '';
    return '<div class="crwn">' + u.crowns.filter(function (c) { return c.pBreach > 0; }).slice(0, 5).map(function (c) {
      return '<div class="cr"><span><b>' + esc(c.label) + '</b><small class="mut"> first to fall in ' + Math.round(100 * c.first) + '% of runs</small></span><span class="cv">' + f(c.p50) + '<small class="mut"> typical</small></span></div>';
    }).join('') + '</div>';
  };

  // "What drives the ETA": one-at-a-time sensitivity.
  Unc.tornado = function (sn) {
    if (!sn || !sn.drivers.length) return '<div class="empty">Nothing to rank: no route to a crown jewel.</div>';
    var base = sn.baseValue, isMed = sn.metric === 'median';
    function dv(v) { return isMed ? f(v) : Math.round(v * 100) + '%'; }
    function delta(v) { var d = v - base; return isMed ? (d >= 0 ? '+' : '−') + f(Math.abs(d)).replace(/^0m$/, '0 min') : (d >= 0 ? '+' : '−') + Math.round(Math.abs(d) * 100) + ' pts'; }
    var scale = Math.max.apply(null, sn.drivers.map(function (d) { return Math.max(Math.abs(d.fast - base), Math.abs(d.slow - base)); })) || 1;
    var rows = sn.drivers.map(function (d) {
      var lw = Math.abs(d.fast - base) / scale * 50, rw = Math.abs(d.slow - base) / scale * 50;
      return '<div class="torn-row"><div class="tl"><b title="' + esc(d.label) + '">' + esc(d.label) + '</b><small>' + esc(d.detail) + '</small></div>' +
        '<div class="tb" role="img" aria-label="' + esc(d.label + ': ' + d.fastLabel + ' gives ' + dv(d.fast) + ', ' + d.slowLabel + ' gives ' + dv(d.slow)) + '"><i class="tr" style="width:' + lw.toFixed(1) + '%"></i><i class="tg" style="width:' + rw.toFixed(1) + '%"></i></div>' +
        '<div class="tv"><span class="r">' + esc(d.fastLabel) + ': ' + esc(dv(d.fast)) + ' (' + esc(delta(d.fast)) + ')</span><span class="g">' + esc(d.slowLabel) + ': ' + esc(dv(d.slow)) + ' (' + esc(delta(d.slow)) + ')</span></div></div>';
    }).join('');
    return '<p class="mut" style="margin:0 0 12px;font-size:13px">' + (isMed ? 'Effect on the typical (median) breach time, starting from ' + esc(f(base)) + '.' : 'Effect on the chance of breach within 60 minutes, starting from ' + Math.round(base * 100) + '%.') + ' Each bar moves one assumption at a time.</p><div class="torn">' + rows + '</div>';
  };

  // "Why this number?" for one step.
  Unc.why = function (edgeId) {
    var x = Core.explain(edgeId);
    if (!x) return;
    var S = Core.settings.sigmaScale || 1;
    var profile = Core.REF.speedProfiles.find(function (p) { return p.id === Core.settings.speedProfile; });
    var ctl = x.controls.length ? x.controls.map(function (c) {
      var def = Core.env.controls.find(function (k) { return k.id === c.id; });
      return '<li>' + esc(def ? def.label : c.id) + ': ' + (c.on ? '<b>on</b>, time ×' + G.MIT.minutes + ', success ×' + G.MIT.p : 'off, no effect') + '</li>';
    }).join('') : '<li>No control is listed against this step.</li>';
    var ev = x.source === 'calibrated' ? 'Fitted from <b>' + x.n + '</b> of your own observations.' :
      x.source === 'user' ? 'Set by hand. Not backed by observations.' : 'An illustrative starting value, not a measurement. Add observations to replace it.';
    var body = '<p class="mut" style="margin-top:0">' + esc(x.from.label) + ' → ' + esc(x.to.label) + ' · ' + esc(x.tid + ' ' + x.tname) + '</p>' +
      '<table class="t why"><tbody>' +
      '<tr><td>Starting estimate</td><td><b>' + esc(f(x.base)) + '</b> to complete, <b>' + Math.round(x.baseP * 100) + '%</b> chance it works first time</td></tr>' +
      '<tr><td>Attacker pace</td><td>× ' + x.speed + (profile ? ' (' + esc(profile.label) + ')' : '') + '</td></tr>' +
      '<tr><td>Controls</td><td><ul class="plain">' + ctl + '</ul></td></tr>' +
      '<tr><td>Used in the route</td><td><b>' + esc(f(x.effMinutes)) + '</b> and <b>' + Math.round(x.effP * 100) + '%</b></td></tr>' +
      '<tr><td>Spread</td><td>Typical time varies with σ = ' + x.sigma.toFixed(2) + (S !== 1 ? ' (width × ' + S + ')' : '') + ': 8 in 10 times fall between <b>' + esc(f(x.p10)) + '</b> and <b>' + esc(f(x.p90)) + '</b>, before the shared attacker-pace effect and retries.</td></tr>' +
      '<tr><td>Evidence</td><td>' + Unc.confBadge(x.conf) + ' ' + ev + '</td></tr></tbody></table>';
    UI.modal({ title: 'Why this number?', body: body, foot: '<button class="btn" data-act="modal-close">Close</button><button class="btn primary" data-act="go-cal">Calibrate from observations</button>' });
  };
})(typeof self !== 'undefined' ? self : this);
