'use strict';
// Run: node tests/uncertainty.test.js
const assert = require('assert');
const G = require('../js/engine.js');
const sample = require('../js/data.js');

let passed = 0;
function t(name, fn) { fn(); passed++; console.log('  ok  ' + name); }

const env = G.prepare(sample);
const mk = (i, tweak) => { const s = G.makeState(env, sample.scenarios[i]); if (tweak) tweak(s); return s; };
const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, (msg || '') + ' expected ' + b + ' ± ' + tol + ', got ' + a);

// Tiny hand-built environments so the maths can be checked against closed forms.
function tiny(edges, extra) {
  return G.prepare(Object.assign({
    nodes: [
      { id: 'a', x: 10, y: 10 }, { id: 'b', x: 20, y: 10 }, { id: 'c', x: 30, y: 10, crown: true }
    ],
    edges: edges,
    controls: []
  }, extra || {}));
}
const tstate = (e) => G.makeState(e, { compromised: ['a'] });
const flat = { paceSigma: 0 };

t('same seed gives identical results; different seed differs', () => {
  const a = G.monteCarlo(env, mk(0), { runs: 800, seed: 7 }), b = G.monteCarlo(env, mk(0), { runs: 800, seed: 7 }), c = G.monteCarlo(env, mk(0), { runs: 800, seed: 8 });
  assert.deepStrictEqual([a.p10, a.p50, a.p90, a.by[30]], [b.p10, b.p50, b.p90, b.by[30]]);
  assert.notStrictEqual(a.p50, c.p50);
});

t('percentiles and by-time chances are ordered', () => {
  sample.scenarios.forEach((_, i) => {
    const m = G.monteCarlo(env, mk(i), { runs: 1000 });
    assert.ok(m.p10 <= m.p50 && m.p50 <= m.p90, 'P10<=P50<=P90 in scenario ' + i);
    assert.ok(m.by[15] <= m.by[30] && m.by[30] <= m.by[60] && m.by[60] <= m.by[120] && m.by[120] <= m.pBreach + 1e-9);
    assert.ok(m.hist.counts.reduce((x, y) => x + y, 0) + m.hist.over === Math.round(m.pBreach * m.runs));
  });
});

t('single hop: lognormal median and spread match theory', () => {
  const e = tiny([{ from: 'a', to: 'c', minutes: 20, p: 1, conf: 'med' }]);
  const m = G.monteCarlo(e, tstate(e), Object.assign({ runs: 20000 }, flat));
  near(m.p50, 20, 1, 'median');
  near(m.p90 / m.p50, Math.exp(G.Z90 * G.SIGMA.med), 0.12, 'P90/P50');
  near(m.p10 / m.p50, Math.exp(-G.Z90 * G.SIGMA.med), 0.06, 'P10/P50');
});

t('explicit edge sigma overrides the confidence label', () => {
  const e = tiny([{ from: 'a', to: 'c', minutes: 20, p: 1, conf: 'low', sigma: 0.1 }]);
  const m = G.monteCarlo(e, tstate(e), Object.assign({ runs: 10000 }, flat));
  near(m.p90 / m.p50, Math.exp(G.Z90 * 0.1), 0.05);
});

t('persistent attacker: retries stretch the time by 1/p on average', () => {
  const e = tiny([{ from: 'a', to: 'c', minutes: 10, p: 0.5, sigma: 0.01 }]);
  const m = G.monteCarlo(e, tstate(e), Object.assign({ runs: 20000, persistent: true }, flat));
  assert.strictEqual(m.pBreach, 1);
  near(m.mean, 20, 1, 'mean time with p=0.5');
});

t('single attempt: breach chance equals the hop success probability', () => {
  const e = tiny([{ from: 'a', to: 'c', minutes: 10, p: 0.5 }]);
  const m = G.monteCarlo(e, tstate(e), { runs: 20000, persistent: false });
  near(m.pBreach, 0.5, 0.02);
});

t('single attempt: two independent routes combine as 1-(1-p)(1-q)', () => {
  const e = tiny([{ from: 'a', to: 'c', minutes: 10, p: 0.5 }, { from: 'a', to: 'b', minutes: 5, p: 0.5 }, { from: 'b', to: 'c', minutes: 5, p: 1 }]);
  const m = G.monteCarlo(e, tstate(e), { runs: 20000, persistent: false });
  near(m.pBreach, 0.75, 0.02);
});

t('persistent mode is never less likely to breach than single attempt', () => {
  sample.scenarios.forEach((_, i) => {
    const p = G.monteCarlo(env, mk(i), { runs: 800, persistent: true }), s = G.monteCarlo(env, mk(i), { runs: 800, persistent: false });
    assert.ok(p.pBreach >= s.pBreach - 1e-9);
    assert.ok(s.pBreach < 1, 'single attempt is a lower bound on scenario ' + i);
  });
});

t('wider timing uncertainty widens the interval', () => {
  const a = G.monteCarlo(env, mk(0), { runs: 1500, sigmaScale: 0.5 }), b = G.monteCarlo(env, mk(0), { runs: 1500, sigmaScale: 2 });
  assert.ok(b.p90 - b.p10 > a.p90 - a.p10);
});

t('shared attacker pace widens the interval even when hops are tight', () => {
  const e = tiny([{ from: 'a', to: 'b', minutes: 10, p: 1, sigma: 0.05 }, { from: 'b', to: 'c', minutes: 10, p: 1, sigma: 0.05 }]);
  const tight = G.monteCarlo(e, tstate(e), { runs: 4000, paceSigma: 0 }), loose = G.monteCarlo(e, tstate(e), { runs: 4000, paceSigma: 0.5 });
  assert.ok((loose.p90 - loose.p10) > 3 * (tight.p90 - tight.p10));
});

t('turning controls on delays the whole distribution', () => {
  const off = G.monteCarlo(env, mk(0, s => { Object.keys(s.controls).forEach(k => s.controls[k] = false); }), { runs: 1200 });
  const on = G.monteCarlo(env, mk(0, s => { Object.keys(s.controls).forEach(k => s.controls[k] = true); }), { runs: 1200 });
  assert.ok(on.p50 > off.p50 && on.by[60] < off.by[60]);
});

t('already breached and fully contained states are handled', () => {
  const b = G.monteCarlo(env, mk(0, s => s.compromised.add('db-fin')), { runs: 100 });
  assert.strictEqual(b.status, 'breached'); assert.strictEqual(b.p50, 0); assert.strictEqual(b.by[15], 1);
  const c = G.monteCarlo(env, mk(0, s => env.nodes.filter(n => n.crown).forEach(n => s.removed.add(n.id))), { runs: 100 });
  assert.strictEqual(c.status, 'contained'); assert.strictEqual(c.pBreach, 0); assert.strictEqual(c.p50, null);
});

t('cutting every route to the crown jewels contains it in every run', () => {
  const s = mk(0); env.edges.forEach(e => { if (e.to === 'dc-01') s.blocked.add(e.id); });
  const a = G.analyze(env, s, { k: 0 }), m = G.monteCarlo(env, s, { runs: 300 });
  assert.strictEqual(m.status === 'contained', !a.headline);
});

t('progress on the current hop shortens the remaining time', () => {
  const e = tiny([{ from: 'a', to: 'c', minutes: 30, p: 1, sigma: 0.05 }]);
  const fresh = G.monteCarlo(e, tstate(e), Object.assign({ runs: 2000 }, flat)), half = G.monteCarlo(e, tstate(e), Object.assign({ runs: 2000, hop: { id: 'a>c', elapsed: 15 } }, flat));
  near(fresh.p50 - half.p50, 15, 1.5);
});

t('first-crown shares and edge usage are proper probabilities', () => {
  const m = G.monteCarlo(env, mk(0), { runs: 1000 });
  near(m.crowns.reduce((x, c) => x + c.first, 0), 1, 1e-9);
  Object.values(m.edgeUse).forEach(v => assert.ok(v > 0 && v <= 1));
  assert.ok(m.crowns[0].first >= m.crowns[m.crowns.length - 1].first);
});

t('fastest first-try ETA sits at or below the typical (P50) ETA when hops can fail', () => {
  sample.scenarios.forEach((_, i) => { const m = G.monteCarlo(env, mk(i), { runs: 1500 }); assert.ok(m.deterministic <= m.p50 * 1.05, 'scenario ' + i); });
});

t('tweak scales a hop and leaves other edges alone', () => {
  const e = tiny([{ from: 'a', to: 'b', minutes: 10, p: 0.8 }, { from: 'b', to: 'c', minutes: 10, p: 0.8 }]);
  const s = tstate(e); s.tweak = { edges: { 'a>b': { m: 3, p: 0.5 } } };
  const a = G.analyze(e, s, { k: 1 });
  near(a.minEta, 40, 1e-9); near(a.routes[0].hops[0].p, 0.4, 1e-9); near(a.routes[0].hops[1].p, 0.8, 1e-9);
  assert.strictEqual(G.cloneState(s).tweak.edges['a>b'].m, 3);
});

t('sensitivity ranks attacker pace on top and brackets the base case', () => {
  const r = G.sensitivity(env, mk(0), { runs: 400 });
  assert.ok(r.drivers.length >= 4);
  for (let i = 1; i < r.drivers.length; i++) assert.ok(r.drivers[i - 1].swing >= r.drivers[i].swing);
  const pace = r.drivers.find(d => d.id === 'pace');
  assert.ok(pace, 'pace driver present');
  assert.ok(pace.fast < r.baseValue && r.baseValue < pace.slow);
  r.drivers.forEach(d => assert.ok(d.fast <= d.slow + 1e-9, d.label));
  assert.deepStrictEqual(G.sensitivity(env, mk(0), { runs: 400 }).drivers.map(d => d.id), r.drivers.map(d => d.id));
});

t('sensitivity falls back to a breach-chance metric when breach is unlikely', () => {
  const r = G.sensitivity(env, mk(2), { runs: 400, persistent: false });
  assert.strictEqual(r.metric, 'by60');
  r.drivers.forEach(d => assert.ok(d.fast >= d.slow - 1e-9, d.label));
});

t('explainEdge reports every factor behind a hop', () => {
  const s = mk(0, st => { st.speed = 2; }), hop = G.analyze(env, s, { k: 1 }).routes[0].hops[0];
  const x = G.explainEdge(env, s, hop.id);
  near(x.effMinutes, hop.minutes, 1e-9); near(x.effP, hop.p, 1e-9);
  assert.ok(x.p10 < x.effMinutes && x.effMinutes < x.p90);
  assert.strictEqual(x.speed, 2);
  assert.strictEqual(G.explainEdge(env, s, 'nope'), null);
});

t('runtime is small enough to recompute on every state change', () => {
  const t0 = Date.now(); G.monteCarlo(env, mk(0), { runs: 1500 }); assert.ok(Date.now() - t0 < 400, 'took ' + (Date.now() - t0) + 'ms');
});

console.log('\n' + passed + ' uncertainty tests passed');
