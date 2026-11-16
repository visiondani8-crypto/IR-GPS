/*!
 * IR-GPS validation
 * Replays documented stretches of real intrusions through the model's own timing assumptions and reports
 * whether the observed durations fall where the model says they should.
 *
 * What this is, and is not
 *  - It is a plausibility check on a handful of public cases. With so few rows it cannot prove the model right;
 *    it can show where the model is clearly off, and it is honest about how little data it has.
 *  - Each documented stretch has a duration and a hop count. The model predicts that duration by drawing
 *    `hops` hops from YOUR environment's post-foothold edges (same lognormal spread, same shared attacker pace,
 *    same retries as the live Monte Carlo) and adding them up.
 *  - Controls are ignored: the victims in these reports were compromised, so whatever controls they had did not stop this.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./engine.js'), require('./validation-data.js'));
  else root.IRGPSVal = factory(root.IRGPS, root.IRGPSValData);
})(typeof self !== 'undefined' ? self : this, function (G, D) {
  'use strict';

  var MIN_FOR_CLAIM = 12;            // fewer rows than this and the verdict is labelled anecdotal
  var TARGET = 0.8;                  // a P10-P90 band should hold 80% of observations

  // Edges the attacker walks after getting a foothold (initial access is excluded: public timers start after it).
  function pool(env, state) {
    var rows = env.edges.filter(function (e) { return e.tactic !== 'Initial Access'; });
    if (!rows.length) rows = env.edges;
    return rows.map(function (e) { return { m: e.minutes * (state.speed || 1), p: Math.max(0.02, e.p), s: G.edgeSigma(e) }; });
  }

  function simulate(pl, hops, o) {
    var rand = G.rng(o.seed), n = o.runs, out = new Float64Array(n);
    for (var r = 0; r < n; r++) {
      var pace = Math.exp(o.paceSigma * G.gauss(rand)), tot = 0;
      for (var h = 0; h < hops; h++) {
        var e = pl[Math.floor(rand() * pl.length)];
        var t = e.m * Math.exp(e.s * o.sigmaScale * G.gauss(rand)) * pace, u = rand();
        if (o.persistent) { var k = e.p >= 1 ? 1 : 1 + Math.floor(Math.log(1 - u) / Math.log(1 - e.p)); t *= Math.min(k, G.MAX_ATTEMPTS); }
        tot += t;
      }
      out[r] = tot;
    }
    return out.sort();
  }

  function median(a) { var s = a.slice().sort(function (x, y) { return x - y; }), n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; }

  function checkPhases(pl, phases, o) {
    return phases.map(function (ph, i) {
      var pred = simulate(pl, ph.hops, { seed: o.seed + i * 101, runs: o.runs, paceSigma: o.paceSigma, sigmaScale: o.sigmaScale, persistent: o.persistent });
      var p10 = G.quantile(pred, 0.1), p50 = G.quantile(pred, 0.5), p90 = G.quantile(pred, 0.9);
      var below = 0; for (var j = 0; j < pred.length; j++) { if (pred[j] < ph.minutes) below++; else break; }
      var side = ph.minutes < p10 ? 'faster' : ph.minutes > p90 ? 'slower' : 'inside';
      return Object.assign({}, ph, { p10: p10, p50: p50, p90: p90, pit: below / pred.length, side: side, inBand: side === 'inside', ratio: ph.minutes / p50 });
    });
  }

  // opts: { runs, seed, persistent (default true), sigmaScale, paceSigma, phases }
  function run(env, state, opts) {
    opts = opts || {};
    var o = {
      runs: opts.runs || 4000, seed: opts.seed == null ? 2026 : opts.seed,
      persistent: opts.persistent !== false, sigmaScale: opts.sigmaScale == null ? 1 : opts.sigmaScale,
      paceSigma: opts.paceSigma == null ? G.PACE_SIGMA : opts.paceSigma
    };
    var phases = opts.phases || D.phases, pl = pool(env, state);
    var rows = checkPhases(pl, phases, o);
    var n = rows.length, inside = rows.filter(function (r) { return r.inBand; }).length;
    var faster = rows.filter(function (r) { return r.side === 'faster'; }).length, slower = rows.filter(function (r) { return r.side === 'slower'; }).length;
    var bias = n ? Math.exp(median(rows.map(function (r) { return Math.log(r.minutes / r.p50); }))) : null;
    var coverage = n ? inside / n : null;

    // smallest widening of the model's spreads that would have covered the target share of these rows
    var suggest = null;
    for (var s = 1; s <= 3.0001 && n; s += 0.1) {
      var rs = checkPhases(pl, phases, Object.assign({}, o, { sigmaScale: s, runs: 1500 }));
      var c = rs.filter(function (r) { return r.inBand; }).length / n;
      if (c >= TARGET) { suggest = { scale: Math.round(s * 10) / 10, coverage: c }; break; }
    }

    // Width matters as much as coverage: a band that says "4 to 86 minutes" is hard to prove wrong.
    var sharp = n ? median(rows.map(function (r) { return r.p90 / r.p10; })) : null;
    function ratioOf(list) { return list.length ? { n: list.length, ratio: Math.exp(median(list.map(function (r) { return Math.log(r.minutes / r.p50); }))) } : { n: 0, ratio: null }; }
    var split = { single: ratioOf(rows.filter(function (r) { return r.hops === 1; })), multi: ratioOf(rows.filter(function (r) { return r.hops > 1; })) };
    var caveats = [];
    if (n < MIN_FOR_CLAIM) caveats.push('Only ' + n + ' documented stretches. Fewer than ' + MIN_FOR_CLAIM + ' is anecdote, not validation.');
    if (sharp && sharp > 5) caveats.push('The model\'s bands are wide (P90 is ' + Math.round(sharp) + '× P10 for the median row), so a high hit rate says little about precision.');
    if (split.single.ratio && split.multi.ratio && split.single.ratio < 0.5 && split.multi.ratio > 0.9) caveats.push('Single documented steps ran about ' + (1 / split.single.ratio).toFixed(1) + '× faster than the model\'s median hop, while multi-hop stretches ran ' + split.multi.ratio.toFixed(1) + '× its prediction. A hop in the model is execution plus operator overhead, so the fastest documented steps are floors, not typical hops.');
    var verdict;
    if (!n) verdict = { level: 'info', headline: 'No cases to test.' };
    else if (coverage >= 0.7) verdict = { level: 'ok', headline: 'Consistent with these cases.', detail: inside + ' of ' + n + ' observations sit inside the model\'s P10–P90 band (80% expected).' };
    else if (slower >= faster) verdict = { level: 'warn', headline: 'Real intrusions were often slower than the model says.', detail: slower + ' of ' + n + ' observations ran longer than P90. Gaps while operators idle, work in shifts or wait are not in the hop times; the model\'s ETA is active attacker time.' };
    else verdict = { level: 'warn', headline: 'Real intrusions were often faster than the model says.', detail: faster + ' of ' + n + ' observations ran quicker than P10, so the model may understate how soon attackers get through. Consider a faster attacker profile.' };
    return {
      options: o, rows: rows, n: n, inside: inside, coverage: coverage, target: TARGET, faster: faster, slower: slower, bias: bias,
      suggest: suggest, verdict: verdict, anecdotal: n < MIN_FOR_CLAIM, minForClaim: MIN_FOR_CLAIM, sharpness: sharp, split: split, caveats: caveats,
      pool: { hops: pl.length, median: Math.exp(pl.reduce(function (a, e) { return a + Math.log(e.m); }, 0) / pl.length) }
    };
  }

  function dwellStats() {
    var v = D.dwell.map(function (d) { return d.minutes; }).sort(function (a, b) { return a - b; });
    return {
      n: v.length, min: v[0], max: v[v.length - 1], median: median(v),
      within60: v.filter(function (x) { return x <= 60; }).length / v.length,
      within240: v.filter(function (x) { return x <= 240; }).length / v.length,
      overOneDay: v.filter(function (x) { return x >= 1440; }).length
    };
  }

  function benchmarkRows() {
    return D.benchmarks.map(function (b) { return Object.assign({}, b); });
  }

  return { run: run, dwellStats: dwellStats, benchmarkRows: benchmarkRows, pool: pool, simulate: simulate, checkPhases: checkPhases, data: D, TARGET: TARGET, MIN_FOR_CLAIM: MIN_FOR_CLAIM };
});
