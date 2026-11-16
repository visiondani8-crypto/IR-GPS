/*!
 * IR-GPS calibration
 * Turns your own observations (red-team runs, purple-team exercises, past incidents, tabletop timings) into
 * per-hop timing and success estimates. Pure and dependency-free; works in the browser (window.IRGPSCal) and Node.
 *
 * Method
 *  - Hop durations are lognormal, so the fit works on ln(minutes): mean and standard deviation.
 *  - Few observations must not swing the model, so every fit is shrunk toward the prior with a small number of
 *    pseudo-observations (K_TIME for timing, K_PROB for success). One data point nudges; ten dominate.
 *  - Success chance is a Beta-style estimate: (successes + K_PROB * prior) / (attempts + K_PROB).
 *  - Confidence is a label derived from how many timings back the estimate (it sets the default spread).
 *  - The original prior is stored on the edge (`prior`), so re-fitting never double-counts and you can revert.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IRGPSCal = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var K_TIME = 3;          // prior weight for timing (in observations)
  var K_PROB = 4;          // prior weight for success chance (in attempts)
  var SIGMA_FLOOR = 0.2;   // never claim more certainty than this, however consistent the data looks
  var SIGMA = { high: 0.3, med: 0.5, low: 0.7 };
  var RANK = { low: 0, med: 1, high: 2 };

  function sigmaOf(e) {
    if (typeof e.sigma === 'number' && e.sigma > 0) return e.sigma;
    return SIGMA[e.conf] != null ? SIGMA[e.conf] : SIGMA.low;
  }
  function confForN(n) { return n >= 8 ? 'high' : n >= 3 ? 'med' : 'low'; }
  function r1(x) { return Math.round(x * 10) / 10; }
  function r2(x) { return Math.round(x * 100) / 100; }

  // Same id scheme the engine uses, so raw (un-prepared) environments can be matched too.
  function edgeIds(env) {
    var seen = {};
    return env.edges.map(function (e) {
      var base = e.from + '>' + e.to;
      seen[base] = (seen[base] || 0) + 1;
      return seen[base] > 1 ? base + '#' + seen[base] : base;
    });
  }

  // ---------- parsing ----------
  var ALIAS = {
    edge: 'edge', edge_id: 'edge', id: 'edge',
    from: 'from', source: 'from', src: 'from', to: 'to', target: 'to', dst: 'to', destination: 'to',
    technique: 'tid', tid: 'tid', attack: 'tid', mitre: 'tid', technique_id: 'tid',
    minutes: 'minutes', min: 'minutes', mins: 'minutes', duration: 'minutes', duration_min: 'minutes', duration_minutes: 'minutes', time: 'minutes',
    success: 'success', succeeded: 'success', ok: 'success', worked: 'success', result: 'success', outcome: 'success',
    note: 'note', notes: 'note', case: 'note', exercise: 'note', comment: 'note'
  };

  function splitLine(line, d) {
    var out = [], cur = '', q = false;
    for (var i = 0; i < line.length; i++) {
      var c = line[i];
      if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
      else if (c === '"') q = true;
      else if (c === d) { out.push(cur); cur = ''; }
      else cur += c;
    }
    out.push(cur);
    return out.map(function (s) { return s.trim(); });
  }

  function toBool(v) {
    if (v === true || v === false) return v;
    if (v == null) return null;
    var s = String(v).trim().toLowerCase();
    if (s === '') return null;
    if (['true', 'yes', 'y', '1', 'success', 'succeeded', 'worked', 'ok', 'pass', 'passed'].indexOf(s) >= 0) return true;
    if (['false', 'no', 'n', '0', 'fail', 'failed', 'blocked', 'detected', 'stopped'].indexOf(s) >= 0) return false;
    return undefined; // unrecognised
  }

  function norm(raw, where, errors) {
    var o = {};
    Object.keys(raw).forEach(function (k) { var a = ALIAS[String(k).trim().toLowerCase().replace(/[\s-]+/g, '_')]; if (a && raw[k] != null && raw[k] !== '') o[a] = raw[k]; });
    var row = { edge: o.edge ? String(o.edge).trim() : null, from: o.from ? String(o.from).trim() : null, to: o.to ? String(o.to).trim() : null, tid: o.tid ? String(o.tid).trim().toUpperCase() : null, minutes: null, success: null, note: o.note ? String(o.note) : '', where: where };
    if (o.minutes != null) {
      var m = typeof o.minutes === 'number' ? o.minutes : parseFloat(String(o.minutes).replace(/[^\d.\-]/g, ''));
      if (!(m > 0) || !isFinite(m)) { errors.push(where + ': minutes must be a positive number (got "' + o.minutes + '")'); return null; }
      // allow "2h", "90s" style suffixes
      var s = String(o.minutes).toLowerCase();
      if (/\d\s*h(ours?|rs?)?\b/.test(s)) m *= 60; else if (/\d\s*s(ec(onds?)?)?\b/.test(s) && !/\d\s*m/.test(s)) m /= 60;
      row.minutes = m;
    }
    if (o.success != null) {
      var b = toBool(o.success);
      if (b === undefined) { errors.push(where + ': could not read "' + o.success + '" as success/fail'); return null; }
      row.success = b;
    }
    if (!row.edge && !(row.from && row.to) && !row.tid) { errors.push(where + ': needs an edge, a from+to pair, or a technique id'); return null; }
    if (row.minutes == null && row.success == null) { errors.push(where + ': needs minutes and/or a success value'); return null; }
    return row;
  }

  // Accepts CSV/TSV with a header row, a JSON array, or { observations: [...] }.
  function parse(text) {
    var errors = [], rows = [];
    text = String(text == null ? '' : text).replace(/^﻿/, '').trim();
    if (!text) return { rows: [], errors: ['Nothing to import.'] };
    if (text[0] === '[' || text[0] === '{') {
      var data;
      try { data = JSON.parse(text); } catch (e) { return { rows: [], errors: ['Invalid JSON: ' + e.message] }; }
      var list = Array.isArray(data) ? data : data && Array.isArray(data.observations) ? data.observations : null;
      if (!list) return { rows: [], errors: ['JSON must be an array or { "observations": [...] }.'] };
      list.forEach(function (r, i) { var n = r && typeof r === 'object' ? norm(r, 'Item ' + (i + 1), errors) : (errors.push('Item ' + (i + 1) + ': not an object'), null); if (n) rows.push(n); });
      return { rows: rows, errors: errors };
    }
    var lines = text.split(/\r?\n/).filter(function (l) { return l.trim() && l.trim()[0] !== '#'; });
    var d = [',', '\t', ';'].reduce(function (best, c) { return (lines[0].split(c).length > lines[0].split(best).length) ? c : best; }, ',');
    var head = splitLine(lines[0], d).map(function (h) { return h.toLowerCase().replace(/[\s-]+/g, '_'); });
    if (!head.some(function (h) { return ALIAS[h]; })) return { rows: [], errors: ['First line must be a header such as: technique,minutes,success'] };
    for (var i = 1; i < lines.length; i++) {
      var cells = splitLine(lines[i], d), raw = {};
      head.forEach(function (h, j) { if (cells[j] != null) raw[h] = cells[j]; });
      var n = norm(raw, 'Line ' + (i + 1), errors);
      if (n) rows.push(n);
    }
    return { rows: rows, errors: errors };
  }

  // ---------- matching and fitting ----------
  function tidMatch(rowTid, edgeTid) {
    if (!rowTid || !edgeTid) return false;
    var r = rowTid.toUpperCase(), e = edgeTid.toUpperCase();
    return r === e || e.indexOf(r + '.') === 0;   // T1021 matches T1021.002; T1021.002 matches only itself
  }

  // Every observation lands on one or more edges: by edge id, else by from+to, else by technique.
  function assign(env, rows) {
    var ids = edgeIds(env), by = {}, unmatched = [];
    rows.forEach(function (r) {
      var hit = [], via;
      if (r.edge) { via = 'edge'; env.edges.forEach(function (e, i) { if (ids[i] === r.edge) hit.push(i); }); }
      if (!hit.length && r.from && r.to) { via = 'pair'; env.edges.forEach(function (e, i) { if (e.from === r.from && e.to === r.to) hit.push(i); }); }
      if (!hit.length && r.tid) { via = 'technique'; env.edges.forEach(function (e, i) { if (tidMatch(r.tid, e.tid)) hit.push(i); }); }
      if (!hit.length) { unmatched.push(r); return; }
      hit.forEach(function (i) { (by[ids[i]] = by[ids[i]] || { index: i, rows: [], via: {} }).rows.push(r); by[ids[i]].via[via] = (by[ids[i]].via[via] || 0) + 1; });
    });
    return { by: by, ids: ids, unmatched: unmatched };
  }

  function priorOf(e) {
    if (e.prior) return { minutes: e.prior.minutes, p: e.prior.p, sigma: e.prior.sigma, conf: e.prior.conf || 'low', sigmaSet: !!e.prior.sigmaSet };
    return { minutes: e.minutes, p: e.p, sigma: sigmaOf(e), conf: e.conf || 'low', sigmaSet: typeof e.sigma === 'number' && e.sigma > 0 };
  }

  function mean(a) { return a.reduce(function (s, x) { return s + x; }, 0) / a.length; }

  function fitEdge(e, rows) {
    var prior = priorOf(e);
    var xs = rows.filter(function (r) { return r.minutes != null; }).map(function (r) { return Math.log(r.minutes); });
    var tries = rows.filter(function (r) { return r.success != null; });
    var n = xs.length, post = { minutes: prior.minutes, p: prior.p, sigma: prior.sigma, conf: prior.conf };
    var obsMedian = null, obsSigma = null;
    if (n) {
      var mu = mean(xs);
      var v = n > 1 ? xs.reduce(function (s, x) { return s + (x - mu) * (x - mu); }, 0) / (n - 1) : prior.sigma * prior.sigma;
      obsMedian = Math.exp(mu); obsSigma = Math.sqrt(v);
      post.minutes = Math.exp((n * mu + K_TIME * Math.log(prior.minutes)) / (n + K_TIME));
      post.sigma = Math.max(SIGMA_FLOOR, Math.sqrt((n * v + K_TIME * prior.sigma * prior.sigma) / (n + K_TIME)));
      var byN = confForN(n);
      post.conf = RANK[byN] > RANK[prior.conf] ? byN : prior.conf;
    }
    var nTry = tries.length, wins = tries.filter(function (r) { return r.success; }).length;
    if (nTry) post.p = Math.min(1, Math.max(0.02, (wins + K_PROB * prior.p) / (nTry + K_PROB)));
    return { n: n, tries: nTry, wins: wins, prior: prior, post: post, obsMedian: obsMedian, obsSigma: obsSigma };
  }

  // env may be raw or prepared. Returns one entry per edge that received evidence.
  function fit(env, rows) {
    var a = assign(env, rows), fits = [];
    Object.keys(a.by).forEach(function (id) {
      var g = a.by[id], e = env.edges[g.index], f = fitEdge(e, g.rows);
      fits.push(Object.assign({
        edgeId: id, from: e.from, to: e.to, tid: e.tid, tname: e.tname,
        via: Object.keys(g.via).join('+'), shared: !!g.via.technique
      }, f));
    });
    fits.sort(function (x, y) { return y.n + y.tries - (x.n + x.tries) || (x.edgeId < y.edgeId ? -1 : 1); });
    return { fits: fits, unmatched: a.unmatched, observations: rows.length };
  }

  // Returns a new raw environment with the fitted numbers written onto the edges. Never mutates the input.
  function apply(env, fits) {
    var out = JSON.parse(JSON.stringify(env)), ids = edgeIds(out), byId = {}, changed = 0;
    fits.forEach(function (f) { byId[f.edgeId] = f; });
    out.edges.forEach(function (e, i) {
      var f = byId[ids[i]];
      if (!f) return;
      if (!e.prior) e.prior = priorOf(e);
      e.minutes = r1(Math.max(0.5, f.post.minutes));
      e.p = r2(Math.min(1, Math.max(0.02, f.post.p)));
      e.sigma = r2(f.post.sigma);
      e.conf = f.post.conf;
      e.source = 'calibrated';
      e.n = Math.max(f.n, f.tries);
      changed++;
    });
    return { env: out, changed: changed };
  }

  // Restore the priors on every calibrated edge (or only the listed edge ids).
  function revert(env, only) {
    var out = JSON.parse(JSON.stringify(env)), ids = edgeIds(out), changed = 0;
    out.edges.forEach(function (e, i) {
      if (!e.prior || (only && only.indexOf(ids[i]) < 0)) return;
      e.minutes = e.prior.minutes; e.p = e.prior.p;
      if (e.prior.conf && e.prior.conf !== 'low') e.conf = e.prior.conf; else delete e.conf;
      if (e.prior.sigmaSet) e.sigma = e.prior.sigma; else delete e.sigma;
      delete e.prior; delete e.source; delete e.n; changed++;
    });
    return { env: out, changed: changed };
  }

  // A short summary of how much of an environment rests on measurement rather than guesswork.
  function coverage(env) {
    var total = env.edges.length, cal = env.edges.filter(function (e) { return e.source === 'calibrated'; }).length;
    var byConf = { low: 0, med: 0, high: 0 };
    env.edges.forEach(function (e) { byConf[e.conf && SIGMA[e.conf] != null ? e.conf : 'low']++; });
    return { total: total, calibrated: cal, share: total ? cal / total : 0, byConf: byConf };
  }

  var TEMPLATE = 'technique,minutes,success,note\nT1021.002,6,true,purple team 2026-03\nT1021.002,11,true,purple team 2026-03\nT1021.002,,false,blocked by EDR\nT1003.001,4,true,red team\nws-hr-07>srv-file-01,9,true,tabletop timing\n';

  return {
    K_TIME: K_TIME, K_PROB: K_PROB, SIGMA_FLOOR: SIGMA_FLOOR, TEMPLATE: TEMPLATE,
    parse: parse, assign: assign, fit: fit, fitEdge: fitEdge, apply: apply, revert: revert, coverage: coverage,
    edgeIds: edgeIds, confForN: confForN, tidMatch: tidMatch
  };
});
