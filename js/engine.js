/*!
 * IR-GPS routing engine
 * Pure, dependency-free logic. Works in the browser (window.IRGPS) and in Node (require).
 *
 * Model
 *  - The environment is a directed graph. Nodes are assets/identities; edges are attacker moves
 *    (each mapped to a MITRE ATT&CK technique) with a base dwell time (minutes) and success probability.
 *  - Security controls are global toggles that slow an edge down and lower its success probability.
 *  - Given the set of compromised footholds, the engine finds the cheapest attacker route to every
 *    crown jewel (multi-source Dijkstra), reports an ETA, offers alternative routes (Yen's k-shortest),
 *    ranks containment actions by how much they delay or stop the attacker, and can run a live
 *    attacker simulation that re-routes when you contain a path (like a GPS recalculating).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IRGPS = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var K = 25;                        // weight of failure-risk in route cost: cost = minutes + K * -ln(p)
  var CAP = 480;                     // ETA used when a destination becomes unreachable (8h)
  var MIT = { minutes: 2.2, p: 0.5 }; // effect of each active control on a mitigated edge
  var HORIZON = 120;                 // exposure score looks 2 hours ahead
  var VS = '__source__';             // virtual source joining all footholds

  // Uncertainty model. Each hop's duration is lognormal: median = the edge's minutes, spread = sigma.
  // sigma comes from the edge (calibrated) or from its confidence label (prior values are wide on purpose).
  var SIGMA = { high: 0.3, med: 0.5, low: 0.7 };
  var PACE_SIGMA = 0.3;              // shared across the whole run: how fast THIS attacker is (skill, tooling, automation)
  var MAX_ATTEMPTS = 12;             // persistent attacker: cap on retries of one hop
  var Z90 = 1.2815515655;            // z for the 10th/90th percentile

  var VERBS = {
    workstation: 'Isolate host via EDR',
    server: 'Network-quarantine server',
    identity: 'Disable account and revoke sessions',
    cloud: 'Revoke role / disable service principal',
    data: 'Restrict access / take offline',
    gateway: 'Block at gateway and rotate access',
    saas: 'Revoke tokens and suspend integration'
  };
  var EXEC_MIN = { workstation: 2, server: 4, identity: 1, cloud: 3, data: 5, gateway: 6, saas: 2 };

  // ---------- environment ----------
  function validate(env) {
    var errs = [];
    if (!env || !Array.isArray(env.nodes) || !Array.isArray(env.edges)) return ['Environment needs "nodes" and "edges" arrays.'];
    var ids = {};
    env.nodes.forEach(function (n, i) {
      if (!n.id) errs.push('Node #' + i + ' has no id.');
      else if (ids[n.id]) errs.push('Duplicate node id: ' + n.id);
      ids[n.id] = true;
      if (typeof n.x !== 'number' || typeof n.y !== 'number') errs.push('Node ' + n.id + ' needs numeric x and y.');
    });
    env.edges.forEach(function (e, i) {
      if (!ids[e.from]) errs.push('Edge #' + i + ' unknown "from": ' + e.from);
      if (!ids[e.to]) errs.push('Edge #' + i + ' unknown "to": ' + e.to);
      if (!(e.minutes > 0)) errs.push('Edge ' + e.from + '>' + e.to + ' needs minutes > 0.');
      if (!(e.p > 0 && e.p <= 1)) errs.push('Edge ' + e.from + '>' + e.to + ' needs 0 < p <= 1.');
    });
    if (!env.nodes.some(function (n) { return n.crown; })) errs.push('Mark at least one node as "crown": true.');
    return errs;
  }

  // Place nodes in zone columns when an imported environment has no coordinates.
  function autoLayout(env) {
    var need = env.nodes.some(function (n) { return typeof n.x !== 'number' || typeof n.y !== 'number'; });
    if (!need) return env;
    var zones = [], by = {};
    env.nodes.forEach(function (n) { var z = n.zone || 'Network'; if (!by[z]) { by[z] = []; zones.push(z); } by[z].push(n); });
    var w = 1000 / zones.length;
    env.zones = zones.map(function (z, i) { return { name: z, x0: Math.round(i * w), x1: Math.round((i + 1) * w) }; });
    zones.forEach(function (z, i) {
      var list = by[z], gap = 540 / (list.length + 1);
      list.forEach(function (n, j) { n.zone = z; n.x = Math.round(i * w + w / 2); n.y = Math.round(60 + gap * (j + 1)); });
    });
    return env;
  }

  function prepare(env) {
    if (env && Array.isArray(env.nodes)) {
      env = JSON.parse(JSON.stringify(env));
      env.nodes.forEach(function (n) { if (n && n.id != null) { n.label = n.label || String(n.id); n.type = n.type || 'server'; } });
      autoLayout(env);
    }
    var errs = validate(env);
    if (errs.length) { var err = new Error(errs[0]); err.all = errs; throw err; }
    var seen = {};
    var out = env;
    out.nodes.forEach(function (n) { n.businessImpact = n.businessImpact == null ? 3 : n.businessImpact; });
    out.edges.forEach(function (e) {
      var base = e.from + '>' + e.to;
      seen[base] = (seen[base] || 0) + 1;
      e.id = seen[base] > 1 ? base + '#' + seen[base] : base;
      e.controls = e.controls || [];
      e.impact = e.impact == null ? 2 : e.impact;
    });
    out.controls = out.controls || [];
    out.byId = {};
    out.nodes.forEach(function (n) { out.byId[n.id] = n; });
    return out;
  }

  function makeState(env, scenario) {
    var controls = {};
    env.controls.forEach(function (c) { controls[c.id] = !!c.enabled; });
    return {
      controls: controls,
      speed: 1,
      compromised: new Set(scenario ? scenario.compromised : []),
      removed: new Set(),
      blocked: new Set()
    };
  }

  function cloneState(s) {
    return {
      controls: Object.assign({}, s.controls),
      speed: s.speed || 1,
      compromised: new Set(s.compromised),
      removed: new Set(s.removed),
      blocked: new Set(s.blocked),
      tweak: s.tweak ? JSON.parse(JSON.stringify(s.tweak)) : undefined
    };
  }

  function applyAction(state, action) {
    if (action.kind === 'isolate') state.removed.add(action.id);
    else if (action.kind === 'block') state.blocked.add(action.id);
    return state;
  }

  // ---------- graph ----------
  function effEdge(state, e) {
    var m = e.minutes * (state.speed || 1), p = e.p;
    // `tweak` is only used by sensitivity(): { edges: { id: { m, p } }, ctl: exponent on the control effect }
    var tw = state.tweak, te = tw && tw.edges && tw.edges[e.id], k = tw && tw.ctl != null ? tw.ctl : 1;
    if (te) { if (te.m) m *= te.m; if (te.p) p = Math.min(1, p * te.p); }
    for (var i = 0; i < e.controls.length; i++) {
      if (state.controls[e.controls[i]]) { m *= Math.pow(MIT.minutes, k); p *= Math.pow(MIT.p, k); }
    }
    p = Math.max(p, 0.02);
    return { minutes: m, p: p, cost: m + K * -Math.log(p) };
  }

  function edgeActive(state, e) {
    return !state.removed.has(e.from) && !state.removed.has(e.to) && !state.blocked.has(e.id);
  }

  function sourcesOf(state) {
    return Array.from(state.compromised).filter(function (id) { return !state.removed.has(id); });
  }

  function buildAdj(env, state, sources) {
    var adj = new Map();
    env.nodes.forEach(function (n) { adj.set(n.id, []); });
    env.edges.forEach(function (e) {
      if (!edgeActive(state, e)) return;
      var x = effEdge(state, e);
      adj.get(e.from).push({ from: e.from, to: e.to, id: e.id, edge: e, minutes: x.minutes, p: x.p, cost: x.cost });
    });
    adj.set(VS, sources.map(function (s) {
      return { from: VS, to: s, id: VS + '>' + s, minutes: 0, p: 1, cost: 0, virtual: true };
    }));
    return adj;
  }

  function dijkstra(adj, src, target, bannedNodes, bannedEdges) {
    var dist = new Map([[src, 0]]), prev = new Map(), done = new Set(), open = [[0, src]];
    while (open.length) {
      var bi = 0;
      for (var i = 1; i < open.length; i++) if (open[i][0] < open[bi][0]) bi = i;
      var cur = open.splice(bi, 1)[0], d = cur[0], u = cur[1];
      if (done.has(u)) continue;
      done.add(u);
      if (u === target) break;
      var list = adj.get(u) || [];
      for (var j = 0; j < list.length; j++) {
        var e = list[j];
        if (bannedNodes.has(e.to) || bannedEdges.has(e.id) || done.has(e.to)) continue;
        var nd = d + e.cost;
        if (nd < (dist.has(e.to) ? dist.get(e.to) : Infinity)) { dist.set(e.to, nd); prev.set(e.to, e); open.push([nd, e.to]); }
      }
    }
    if (!done.has(target)) return null;
    var edges = [], node = target;
    while (node !== src) { var pe = prev.get(node); edges.unshift(pe); node = pe.from; }
    return { cost: dist.get(target), edges: edges };
  }

  function startsWith(edges, root) {
    for (var i = 0; i < root.length; i++) if (!edges[i] || edges[i].id !== root[i].id) return false;
    return true;
  }
  function sameEdges(a, b) {
    return a.length === b.length && startsWith(a, b);
  }

  // Yen's k-shortest simple paths
  function kShortest(adj, src, target, k) {
    var first = dijkstra(adj, src, target, new Set(), new Set());
    if (!first) return [];
    var A = [first], B = [];
    for (var n = 1; n < k; n++) {
      var last = A[n - 1];
      for (var i = 0; i < last.edges.length; i++) {
        var root = last.edges.slice(0, i);
        var spurNode = i === 0 ? src : last.edges[i - 1].to;
        var be = new Set(), bn = new Set();
        A.forEach(function (p) { if (p.edges.length > i && startsWith(p.edges, root)) be.add(p.edges[i].id); });
        root.forEach(function (e) { bn.add(e.from); });
        var spur = dijkstra(adj, spurNode, target, bn, be);
        if (!spur) continue;
        var edges = root.concat(spur.edges);
        var dup = A.concat(B).some(function (p) { return sameEdges(p.edges, edges); });
        if (!dup) B.push({ cost: edges.reduce(function (s, e) { return s + e.cost; }, 0), edges: edges });
      }
      if (!B.length) break;
      B.sort(function (a, b) { return a.cost - b.cost; });
      A.push(B.shift());
    }
    return A;
  }

  function toRoute(r) {
    var hops = r.edges.filter(function (e) { return !e.virtual; });
    var minutes = 0, p = 1;
    hops.forEach(function (h) { minutes += h.minutes; p *= h.p; });
    return {
      start: hops.length ? hops[0].from : r.edges[0].to,
      end: hops.length ? hops[hops.length - 1].to : r.edges[0].to,
      hops: hops, minutes: minutes, p: p, cost: r.cost
    };
  }

  // ---------- analysis ----------
  function analyze(env, state, opts) {
    var k = opts && opts.k != null ? opts.k : 3;
    var sources = sourcesOf(state);
    var adj = buildAdj(env, state, sources);
    var dests = env.nodes.filter(function (n) { return n.crown; }).map(function (n) {
      if (state.removed.has(n.id)) return { id: n.id, node: n, status: 'isolated', eta: Infinity, p: 0, route: null };
      var r = dijkstra(adj, VS, n.id, new Set(), new Set());
      if (!r) return { id: n.id, node: n, status: 'safe', eta: Infinity, p: 0, route: null };
      var route = toRoute(r);
      return { id: n.id, node: n, status: route.hops.length === 0 ? 'breached' : 'at-risk', eta: route.minutes, p: route.p, route: route };
    });
    dests.sort(function (a, b) { return a.eta - b.eta || b.p - a.p; });
    var head = dests.find(function (d) { return d.route; }) || null;
    var routes = [];
    if (head && k > 0 && head.route.hops.length) routes = kShortest(adj, VS, head.id, k).map(toRoute);
    var reachable = dests.filter(function (d) { return d.route; }).length;
    return { destinations: dests, headline: head, routes: routes, reachable: reachable, minEta: head ? head.eta : Infinity };
  }

  function directions(env, route) {
    var t = 0;
    return route.hops.map(function (h, i) {
      t += h.minutes;
      var e = h.edge;
      return {
        n: i + 1, at: t, minutes: h.minutes, p: h.p, edgeId: h.id,
        from: env.byId[h.from], to: env.byId[h.to],
        tid: e.tid, tname: e.tname, tactic: e.tactic, remedy: e.remedy
      };
    });
  }

  // ---------- containment recommendations ----------
  function recommend(env, state, limit) {
    var base = analyze(env, state, { k: 0 });
    if (!base.headline) return [];
    var baseEta = Math.min(base.minEta, CAP);
    var cands = [];
    env.nodes.forEach(function (n) {
      if (state.removed.has(n.id)) return;
      cands.push({ kind: 'isolate', id: n.id, label: n.label, verb: VERBS[n.type] || 'Isolate', impact: n.businessImpact, exec: EXEC_MIN[n.type] || 3, type: n.type });
    });
    env.edges.forEach(function (e) {
      if (state.blocked.has(e.id) || state.removed.has(e.from) || state.removed.has(e.to)) return;
      cands.push({ kind: 'block', id: e.id, label: env.byId[e.from].label + ' → ' + env.byId[e.to].label, verb: e.remedy || 'Block this path', impact: e.impact, exec: 5, type: 'path', tid: e.tid });
    });
    var out = [];
    cands.forEach(function (c) {
      var s = applyAction(cloneState(state), c);
      var a = analyze(env, s, { k: 0 });
      var newEta = Math.min(a.minEta, CAP);
      var delta = newEta - baseEta;
      var saved = base.reachable - a.reachable;
      var score = (delta + 60 * saved) / (1 + 0.5 * c.impact);
      if (score > 0.5) out.push(Object.assign(c, { delta: delta, saved: saved, newEta: a.minEta, score: score, contains: !a.headline }));
    });
    out.sort(function (a, b) { return b.score - a.score; });
    return out.slice(0, limit || 6);
  }

  // ---------- live attacker simulation ----------
  function createSim(state) {
    var src = sourcesOf(state);
    return { t: 0, head: src[0] || null, hop: null, status: 'running', target: null };
  }

  function tick(env, state, sim, dt) {
    var events = [];
    var guard = 0;
    while (dt > 1e-9 && sim.status === 'running' && guard++ < 200) {
      if (sim.hop) {
        var he = sim.hop.adj.edge;
        if (!edgeActive(state, he)) {
          events.push({ t: sim.t, type: 'reroute', text: 'Path ' + env.byId[he.from].label + ' → ' + env.byId[he.to].label + ' was cut. Attacker is recalculating.' });
          sim.hop = null;
        }
      }
      if (!sim.hop) {
        var a = analyze(env, state, { k: 0 });
        if (!a.headline) { sim.status = 'contained'; events.push({ t: sim.t, type: 'contained', text: 'No route to any crown jewel remains. Attacker is contained.' }); break; }
        if (a.headline.status === 'breached') { sim.status = 'breach'; events.push({ t: sim.t, type: 'breach', text: 'Crown jewel breached: ' + a.headline.node.label + '.' }); break; }
        var first = a.headline.route.hops[0];
        sim.head = first.from;
        sim.hop = { adj: first, remaining: first.minutes, total: first.minutes };
        events.push({ t: sim.t, type: 'move', text: 'Attacker begins ' + first.edge.tid + ' ' + first.edge.tname + ': ' + env.byId[first.from].label + ' → ' + env.byId[first.to].label + '.' });
      }
      var use = Math.min(dt, sim.hop.remaining);
      sim.hop.remaining -= use; sim.t += use; dt -= use;
      if (sim.hop.remaining <= 1e-9) {
        var to = sim.hop.adj.to;
        state.compromised.add(to);
        sim.head = to;
        events.push({ t: sim.t, type: 'owned', text: 'Compromised ' + env.byId[to].label + '.' });
        sim.hop = null;
        if (env.byId[to].crown) { sim.status = 'breach'; events.push({ t: sim.t, type: 'breach', text: 'Crown jewel breached: ' + env.byId[to].label + '.' }); }
      }
    }
    return events;
  }


  // ---------- higher-level analytics ----------
  // Exposure score 0-100: how soon, on average, the crown jewels fall within a 2 hour horizon.
  // 100 = all breached already, 0 = nothing reachable inside the horizon.
  function exposure(env, state) {
    var a = analyze(env, state, { k: 0 });
    var crowns = a.destinations;
    if (!crowns.length) return 0;
    var sum = 0;
    crowns.forEach(function (d) { sum += Math.min(d.route ? d.eta : HORIZON, HORIZON) / HORIZON; });
    return Math.round(100 * (1 - sum / crowns.length));
  }

  // `eta` is optional: pass the live ETA (route minutes minus progress on the current hop) to match the on-screen clock.
  function severity(a, eta) {
    if (!a.headline) return { level: 'SEV4', label: 'Contained' };
    var e = eta == null ? a.minEta : eta;
    if (a.headline.status === 'breached' || e <= 15) return { level: 'SEV1', label: 'Critical' };
    if (e <= 60) return { level: 'SEV2', label: 'High' };
    return { level: 'SEV3', label: 'Medium' };
  }

  // Share of predicted routes (3 per reachable crown jewel) that pass through each ATT&CK tactic.
  function tacticExposure(env, state) {
    var sources = sourcesOf(state), adj = buildAdj(env, state, sources), routes = [];
    env.nodes.filter(function (n) { return n.crown && !state.removed.has(n.id); }).forEach(function (n) {
      kShortest(adj, VS, n.id, 3).forEach(function (r) { var t = toRoute(r); if (t.hops.length) routes.push(t); });
    });
    var count = {};
    routes.forEach(function (r) {
      var seen = {};
      r.hops.forEach(function (h) { var t = h.edge.tactic || 'Other'; if (!seen[t]) { seen[t] = 1; count[t] = (count[t] || 0) + 1; } });
    });
    var out = Object.keys(count).map(function (t) { return { tactic: t, routes: count[t], pct: Math.round(100 * count[t] / routes.length) }; });
    out.sort(function (a, b) { return b.pct - a.pct || a.tactic.localeCompare(b.tactic); });
    return { total: routes.length, tactics: out };
  }

  // What each security control buys you: change in ETA and exposure if you flip it, now and across all scenarios.
  function hardening(env, state, scenarios) {
    var base = analyze(env, state, { k: 0 });
    var expBase = exposure(env, state);
    function avgExp(controlsOverride) {
      if (!scenarios || !scenarios.length) return null;
      var tot = 0;
      scenarios.forEach(function (sc) {
        var s = makeState(env, sc); s.speed = state.speed; s.controls = Object.assign({}, state.controls, controlsOverride || {});
        tot += exposure(env, s);
      });
      return tot / scenarios.length;
    }
    var avgBase = avgExp();
    return env.controls.map(function (c) {
      var flip = {}; flip[c.id] = !state.controls[c.id];
      var s2 = cloneState(state); s2.controls[c.id] = flip[c.id];
      var a2 = analyze(env, s2, { k: 0 });
      var avg2 = avgExp(flip);
      var edges = env.edges.filter(function (e) { return e.controls.indexOf(c.id) >= 0; }).length;
      return {
        id: c.id, label: c.label, desc: c.desc, enabled: !!state.controls[c.id], edges: edges,
        etaNow: base.minEta, etaFlip: a2.minEta,
        deltaEta: (Math.min(a2.minEta, CAP) - Math.min(base.minEta, CAP)),
        expNow: expBase, expFlip: exposure(env, s2),
        avgDeltaExp: avg2 == null ? 0 : Math.round(avg2 - avgBase)
      };
    });
  }

  function cloneSim(sim) {
    return { t: sim.t, head: sim.head, status: sim.status, target: sim.target, hop: sim.hop ? { adj: sim.hop.adj, remaining: sim.hop.remaining, total: sim.hop.total } : null };
  }

  // Replay the incident forward twice: attacker unchecked vs. a responder following the top recommendation.
  function project(env, state0, sim0, o) {
    o = o || {};
    var lag = o.lag == null ? 5 : o.lag, cadence = o.cadence || 2, horizon = o.horizon || 240, step = o.step || 1;
    function run(guided) {
      var s = cloneState(state0), sm = cloneSim(sim0), pts = [], pend = [], acts = [], next = lag, endAt = null;
      for (var el = 0; el <= horizon; el += step) {
        var due = pend.filter(function (p) { return p.at <= el + 1e-9; });
        if (due.length) { pend = pend.filter(function (p) { return p.at > el + 1e-9; }); due.forEach(function (p) { applyAction(s, p.a); }); }
        var a = analyze(env, s, { k: 0 });
        var eta = a.headline ? Math.min(a.minEta, CAP) : CAP;
        if (sm.hop && a.headline && a.headline.route && a.headline.route.hops.length && a.headline.route.hops[0].id === sm.hop.adj.id) eta = Math.max(0, eta - (sm.hop.total - sm.hop.remaining));
        pts.push({ t: el, eta: eta });
        if (sm.status !== 'running') { endAt = el; break; }
        if (guided && el >= next) {
          var recs = recommend(env, s, 8);
          var pick = recs.find(function (r) { return !pend.some(function (p) { return p.a.kind === r.kind && p.a.id === r.id; }); });
          if (pick) { pend.push({ a: pick, at: el + pick.exec }); acts.push({ t: el, lands: el + pick.exec, action: pick }); }
          next = el + cadence;
        }
        tick(env, s, sm, step);
      }
      return { points: pts, status: sm.status, endAt: endAt, actions: acts };
    }
    var raw = run(false), guided = run(true);
    return { unmanaged: raw, guided: guided, lag: lag, cap: CAP };
  }

  // ---------- uncertainty: Monte Carlo ----------
  // Seeded, so the same inputs always give the same numbers (and what-if comparisons share random draws).
  function rng(seed) {
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) >>> 0;
      var t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function gauss(r) {
    var u = r(); if (u < 1e-12) u = 1e-12;
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * r());
  }
  function edgeSigma(e) {
    if (typeof e.sigma === 'number' && e.sigma > 0) return e.sigma;
    return SIGMA[e.conf] != null ? SIGMA[e.conf] : SIGMA.low;
  }
  function quantile(sorted, q) {
    var n = sorted.length; if (!n) return null;
    var pos = (n - 1) * q, lo = Math.floor(pos), hi = Math.ceil(pos);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
  }
  function heapPush(h, d, n) {
    var i = h.d.length; h.d.push(d); h.n.push(n);
    while (i > 0) { var p = (i - 1) >> 1; if (h.d[p] <= d) break; h.d[i] = h.d[p]; h.n[i] = h.n[p]; i = p; }
    h.d[i] = d; h.n[i] = n;
  }
  function heapPop(h) {
    var topN = h.n[0], topD = h.d[0], lastD = h.d.pop(), lastN = h.n.pop(), len = h.d.length;
    if (len) {
      var i = 0;
      for (;;) {
        var l = 2 * i + 1, r = l + 1, c = l;
        if (l >= len) break;
        if (r < len && h.d[r] < h.d[l]) c = r;
        if (h.d[c] >= lastD) break;
        h.d[i] = h.d[c]; h.n[i] = h.n[c]; i = c;
      }
      h.d[i] = lastD; h.n[i] = lastN;
    }
    h.top = topD;
    return topN;
  }

  var BINS = 28;
  var BY = [15, 30, 60, 120];

  function summarize(arr, runs) {
    var fin = [];
    for (var i = 0; i < arr.length; i++) if (arr[i] < Infinity) fin.push(arr[i]);
    var s = Float64Array.from(fin).sort();
    var by = {};
    BY.forEach(function (T) { var c = 0; for (var j = 0; j < s.length; j++) { if (s[j] <= T) c++; else break; } by[T] = c / runs; });
    return {
      sorted: s, pBreach: s.length / runs, by: by,
      p10: quantile(s, 0.1), p50: quantile(s, 0.5), p90: quantile(s, 0.9)
    };
  }

  // Samples the attack many times. Per run: one shared "attacker pace" draw, a lognormal duration per hop,
  // and either (persistent) geometric retries of failed hops or (single attempt) hops that simply fail.
  // The attacker takes the quickest route through whatever that run's dice left open.
  // o: { runs, seed, persistent (default true), sigmaScale, paceSigma, hop: {id, elapsed} }
  function monteCarlo(env, state, o) {
    o = o || {};
    var runs = Math.max(50, Math.round(o.runs || 1500));
    var seed = o.seed == null ? 1337 : o.seed;
    var sigmaScale = o.sigmaScale == null ? 1 : o.sigmaScale;
    var paceSigma = o.paceSigma == null ? PACE_SIGMA : o.paceSigma;
    var persistent = o.persistent !== false;
    var rand = rng(seed);

    var N = env.nodes.length, idx = {};
    env.nodes.forEach(function (n, i) { idx[n.id] = i; });
    var crowns = env.nodes.filter(function (n) { return n.crown && !state.removed.has(n.id); });
    var head = { runs: runs, seed: seed, persistent: persistent, sigmaScale: sigmaScale, paceSigma: paceSigma };

    if (crowns.some(function (n) { return state.compromised.has(n.id); })) {
      var z = { 15: 1, 30: 1, 60: 1, 120: 1 };
      return Object.assign(head, {
        status: 'breached', pBreach: 1, p10: 0, p50: 0, p90: 0, mean: 0, medianCapped: 0, deterministic: 0, by: z,
        hist: { max: 0, width: 0, counts: [], over: 0 }, edgeUse: {},
        crowns: crowns.map(function (n) { return { id: n.id, label: n.label, pBreach: state.compromised.has(n.id) ? 1 : 0, p10: 0, p50: 0, p90: 0, by: z, first: state.compromised.has(n.id) ? 1 : 0 }; })
      });
    }

    var E = [];
    env.edges.forEach(function (e) {
      if (!edgeActive(state, e)) return;
      var x = effEdge(state, e);
      E.push({ id: e.id, f: idx[e.from], t: idx[e.to], m: x.minutes, p: x.p, s: edgeSigma(e) * sigmaScale });
    });
    var adj = [], i;
    for (i = 0; i < N; i++) adj.push([]);
    var hopK = -1, hopElapsed = 0;
    E.forEach(function (e, k) { adj[e.f].push(k); if (o.hop && o.hop.id === e.id) { hopK = k; hopElapsed = o.hop.elapsed || 0; } });
    var srcs = sourcesOf(state).map(function (id) { return idx[id]; });
    var crownIdx = crowns.map(function (n) { return idx[n.id]; });
    var isCrown = new Int32Array(N).fill(-1);
    crownIdx.forEach(function (ix, j) { isCrown[ix] = j; });

    var times = new Float64Array(runs);
    var cTimes = crownIdx.map(function () { return new Float64Array(runs); });
    var first = crownIdx.map(function () { return 0; });
    var use = new Float64Array(E.length);
    var w = new Float64Array(E.length), ok = new Uint8Array(E.length);
    var dist = new Float64Array(N), prevE = new Int32Array(N), done = new Uint8Array(N);
    var deterministic = analyze(env, state, { k: 0 }).minEta;

    for (var r = 0; r < runs; r++) {
      var pace = Math.exp(paceSigma * gauss(rand));
      for (var k = 0; k < E.length; k++) {
        var e = E[k];
        var t = e.m * Math.exp(e.s * gauss(rand)) * pace;
        var u = rand();
        if (persistent) {
          var n = e.p >= 1 ? 1 : 1 + Math.floor(Math.log(1 - u) / Math.log(1 - e.p));
          if (n > MAX_ATTEMPTS) n = MAX_ATTEMPTS;
          t *= n; ok[k] = 1;
        } else ok[k] = u < e.p ? 1 : 0;
        if (k === hopK) t = Math.max(t - hopElapsed, 0.5);
        w[k] = t;
      }
      dist.fill(Infinity); prevE.fill(-1); done.fill(0);
      var heap = { d: [], n: [], top: 0 };
      for (i = 0; i < srcs.length; i++) { dist[srcs[i]] = 0; heapPush(heap, 0, srcs[i]); }
      var settled = 0;
      while (heap.d.length && settled < crownIdx.length) {
        var uNode = heapPop(heap), d = heap.top;
        if (done[uNode]) continue;
        done[uNode] = 1;
        if (isCrown[uNode] >= 0) settled++;
        var lst = adj[uNode];
        for (var q = 0; q < lst.length; q++) {
          var kk = lst[q];
          if (!ok[kk]) continue;
          var v = E[kk].t, nd = d + w[kk];
          if (nd < dist[v]) { dist[v] = nd; prevE[v] = kk; heapPush(heap, nd, v); }
        }
      }
      var best = Infinity, bj = -1;
      for (var j = 0; j < crownIdx.length; j++) {
        var dj = done[crownIdx[j]] ? dist[crownIdx[j]] : Infinity;
        cTimes[j][r] = dj;
        if (dj < best) { best = dj; bj = j; }
      }
      times[r] = best;
      if (bj >= 0) {
        first[bj]++;
        var node = crownIdx[bj];
        while (prevE[node] >= 0) { use[prevE[node]]++; node = E[prevE[node]].f; }
      }
    }

    var all = summarize(times, runs);
    var capped = Float64Array.from(times, function (x) { return Math.min(x, CAP); }).sort();
    var sum = 0; for (i = 0; i < all.sorted.length; i++) sum += all.sorted[i];
    var hist = { max: 0, width: 0, counts: [], over: 0 };
    if (all.sorted.length) {
      hist.max = Math.max(quantile(all.sorted, 0.95) * 1.15, 5);
      hist.width = hist.max / BINS;
      for (i = 0; i < BINS; i++) hist.counts.push(0);
      for (i = 0; i < all.sorted.length; i++) {
        var b = Math.floor(all.sorted[i] / hist.width);
        if (b >= BINS) hist.over++; else hist.counts[b]++;
      }
    }
    var edgeUse = {};
    E.forEach(function (e, kx) { if (use[kx] > 0) edgeUse[e.id] = use[kx] / runs; });
    return Object.assign(head, {
      status: all.sorted.length ? 'at-risk' : 'contained',
      pBreach: all.pBreach, p10: all.p10, p50: all.p50, p90: all.p90,
      mean: all.sorted.length ? sum / all.sorted.length : null,
      medianCapped: quantile(capped, 0.5), deterministic: deterministic, by: all.by, hist: hist, edgeUse: edgeUse,
      crowns: crowns.map(function (n, j) {
        var s = summarize(cTimes[j], runs);
        return { id: n.id, label: n.label, pBreach: s.pBreach, p10: s.p10, p50: s.p50, p90: s.p90, by: s.by, first: first[j] / runs };
      }).sort(function (a, b2) { return b2.first - a.first || b2.pBreach - a.pBreach; })
    });
  }

  // One-at-a-time sensitivity: nudge each assumption to an attacker-friendly and a defender-friendly value
  // and measure how far the headline moves. Uses the same random draws for every variant, so differences are real.
  function sensitivity(env, state, o) {
    o = o || {};
    var mc = { runs: o.runs || 500, seed: o.seed == null ? 4242 : o.seed, persistent: o.persistent !== false, sigmaScale: o.sigmaScale, paceSigma: o.paceSigma, hop: o.hop };
    var base = monteCarlo(env, state, mc);
    if (base.status !== 'at-risk') return { base: base, metric: 'median', unit: 'min', drivers: [] };
    var metric = base.pBreach >= 0.6 ? 'median' : 'by60';
    function val(r) { return metric === 'median' ? r.medianCapped : r.by[60]; }
    var baseVal = val(base), out = [];

    function drive(meta, mutate) {
      var f = cloneState(state), s = cloneState(state);
      mutate(f, 'fast'); mutate(s, 'slow');
      var a = val(monteCarlo(env, f, mc)), b = val(monteCarlo(env, s, mc));
      out.push(Object.assign({ fast: a, slow: b, swing: Math.abs(b - a) }, meta));
    }
    function twk(st) { st.tweak = st.tweak || { edges: {} }; st.tweak.edges = st.tweak.edges || {}; return st.tweak; }

    drive({ id: 'pace', kind: 'pace', label: 'Attacker pace', detail: 'How fast this attacker works overall.', fastLabel: '2× faster', slowLabel: '2× slower' },
      function (st, side) { st.speed = (st.speed || 1) * (side === 'fast' ? 0.5 : 2); });

    var usedActive = Object.keys(base.edgeUse).some(function (id) {
      var ed = env.edges.find(function (x) { return x.id === id; });
      return ed && ed.controls.some(function (c) { return state.controls[c]; });
    });
    if (usedActive) drive({ id: 'controls', kind: 'controls', label: 'Control effectiveness', detail: 'How much your active controls really slow and stop the attacker.', fastLabel: '50% weaker', slowLabel: '50% stronger' },
      function (st, side) { twk(st).ctl = side === 'fast' ? 0.5 : 1.5; });

    Object.keys(base.edgeUse).filter(function (id) { return base.edgeUse[id] >= 0.05; })
      .sort(function (a, b) { return base.edgeUse[b] - base.edgeUse[a]; }).slice(0, o.edges || 8).forEach(function (id) {
        var ed = env.edges.find(function (x) { return x.id === id; });
        var name = (ed.tname || 'Step') + ': ' + env.byId[ed.from].label + ' → ' + env.byId[ed.to].label;
        drive({ id: id + ':time', kind: 'edge-time', edgeId: id, label: name, detail: 'How long this step takes.', fastLabel: 'half the time', slowLabel: 'twice the time', use: base.edgeUse[id] },
          function (st, side) { twk(st).edges[id] = { m: side === 'fast' ? 0.5 : 2 }; });
        drive({ id: id + ':p', kind: 'edge-p', edgeId: id, label: name, detail: 'How often this step works first time.', fastLabel: 'works 1.5× as often', slowLabel: 'works half as often', use: base.edgeUse[id] },
          function (st, side) { twk(st).edges[id] = { p: side === 'fast' ? 1.5 : 0.5 }; });
      });

    out.sort(function (a, b) { return b.swing - a.swing; });
    return { base: base, baseValue: baseVal, metric: metric, unit: metric === 'median' ? 'min' : 'share', drivers: out.slice(0, o.limit || 8) };
  }

  // "Why this number?" for one hop: every factor that produced its minutes, probability and spread.
  function explainEdge(env, state, edgeId, o) {
    var e = env.edges.find(function (x) { return x.id === edgeId; });
    if (!e) return null;
    var x = effEdge(state, e), s = edgeSigma(e) * (o && o.sigmaScale != null ? o.sigmaScale : 1);
    return {
      id: e.id, from: env.byId[e.from], to: env.byId[e.to], tid: e.tid, tname: e.tname, tactic: e.tactic,
      base: e.minutes, baseP: e.p, speed: state.speed || 1,
      controls: e.controls.map(function (c) { return { id: c, on: !!state.controls[c] }; }),
      effMinutes: x.minutes, effP: x.p, sigma: s,
      p10: x.minutes * Math.exp(-Z90 * s), p90: x.minutes * Math.exp(Z90 * s),
      conf: e.conf || 'low', source: e.source || 'prior', n: e.n || 0
    };
  }

  function fmt(m) {
    if (m === Infinity || m == null) return '∞';
    m = Math.round(m);
    if (m < 60) return m + ' min';
    var h = Math.floor(m / 60), r = m % 60;
    return h + 'h ' + (r < 10 ? '0' : '') + r + 'm';
  }

  return {
    CAP: CAP, HORIZON: HORIZON, MIT: MIT, VERBS: VERBS,
    validate: validate, prepare: prepare, makeState: makeState, cloneState: cloneState,
    applyAction: applyAction, analyze: analyze, directions: directions, recommend: recommend,
    createSim: createSim, tick: tick, edgeActive: edgeActive, fmt: fmt,
    exposure: exposure, severity: severity, tacticExposure: tacticExposure, hardening: hardening, project: project, cloneSim: cloneSim,
    SIGMA: SIGMA, PACE_SIGMA: PACE_SIGMA, Z90: Z90, MAX_ATTEMPTS: MAX_ATTEMPTS, edgeSigma: edgeSigma, rng: rng, gauss: gauss, quantile: quantile,
    monteCarlo: monteCarlo, sensitivity: sensitivity, explainEdge: explainEdge
  };
});
