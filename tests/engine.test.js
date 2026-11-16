'use strict';
// Run: node tests/engine.test.js
const assert = require('assert');
const G = require('../js/engine.js');
const sample = require('../js/data.js');

let passed = 0;
function t(name, fn) { fn(); passed++; console.log('  ok  ' + name); }

const env = G.prepare(sample);
const mk = (i, tweak) => { const s = G.makeState(env, sample.scenarios[i]); if (tweak) tweak(s); return s; };

t('sample environment validates', () => assert.deepStrictEqual(G.validate(sample), []));

t('validation catches bad edges and missing crown jewels', () => {
  const bad = { nodes: [{ id: 'a', x: 1, y: 1 }], edges: [{ from: 'a', to: 'zzz', minutes: 1, p: 0.5 }] };
  const errs = G.validate(bad);
  assert.ok(errs.some(e => /unknown "to"/.test(e)));
  assert.ok(errs.some(e => /crown/.test(e)));
});

t('phishing scenario reaches crown jewels with a finite ETA', () => {
  const a = G.analyze(env, mk(0));
  assert.ok(a.headline, 'has headline');
  assert.ok(Number.isFinite(a.minEta) && a.minEta > 0);
  assert.ok(a.routes.length >= 2, 'offers alternative routes');
  assert.strictEqual(a.routes[0].start, 'ws-hr-07');
});

t('routes are sorted by cost and are distinct', () => {
  const a = G.analyze(env, mk(0), { k: 4 });
  for (let i = 1; i < a.routes.length; i++) assert.ok(a.routes[i].cost >= a.routes[i - 1].cost - 1e-9);
  const keys = a.routes.map(r => r.hops.map(h => h.id).join('|'));
  assert.strictEqual(new Set(keys).size, keys.length);
});

t('enabling a control slows the attacker (what-if)', () => {
  const off = G.analyze(env, mk(0, s => { s.controls = Object.fromEntries(Object.keys(s.controls).map(k => [k, false])); }), { k: 0 });
  const on = G.analyze(env, mk(0, s => { s.controls = Object.fromEntries(Object.keys(s.controls).map(k => [k, true])); }), { k: 0 });
  assert.ok(on.minEta > off.minEta, 'ETA grows with all controls on: ' + off.minEta + ' -> ' + on.minEta);
});

t('isolating a node removes routes through it and reroutes', () => {
  const s = mk(0);
  const before = G.analyze(env, s);
  const via = before.routes[0].hops[0].to;
  G.applyAction(s, { kind: 'isolate', id: via });
  const after = G.analyze(env, s);
  const used = after.headline && after.headline.route.hops.some(h => h.from === via || h.to === via);
  assert.ok(!used, 'new route avoids isolated node');
  assert.ok(after.minEta >= before.minEta, 'ETA does not shrink after containment');
});

t('recommendations are positive-scored and ordered', () => {
  const recs = G.recommend(env, mk(0), 8);
  assert.ok(recs.length > 0);
  for (let i = 1; i < recs.length; i++) assert.ok(recs[i].score <= recs[i - 1].score + 1e-9);
  assert.ok(recs.every(r => r.score > 0));
});

t('applying top recommendations repeatedly eventually contains the attacker', () => {
  const s = mk(0);
  for (let i = 0; i < 40; i++) {
    const recs = G.recommend(env, s, 1);
    if (!recs.length) break;
    G.applyAction(s, recs[0]);
  }
  const a = G.analyze(env, s, { k: 0 });
  assert.strictEqual(a.reachable, 0, 'no crown jewel reachable');
});

t('simulation: unmitigated attacker eventually breaches', () => {
  const s = mk(1), sim = G.createSim(s);
  G.tick(env, s, sim, 10000);
  assert.strictEqual(sim.status, 'breach');
  assert.ok(sim.t > 0);
});

t('simulation: cutting the path mid-flight reroutes, containment ends it', () => {
  const s = mk(0), sim = G.createSim(s);
  G.tick(env, s, sim, 1);
  assert.ok(sim.hop, 'attacker mid-hop');
  G.applyAction(s, { kind: 'block', id: sim.hop.adj.id });
  const ev = G.tick(env, s, sim, 0.5);
  assert.ok(ev.some(e => e.type === 'reroute'), 'reroute event emitted');
  const s2 = mk(0), sim2 = G.createSim(s2);
  for (let i = 0; i < 40 && sim2.status === 'running'; i++) {
    const r = G.recommend(env, s2, 1);
    if (!r.length) break;
    G.applyAction(s2, r[0]);
    G.tick(env, s2, sim2, 0.1);
  }
  G.tick(env, s2, sim2, 10);
  assert.strictEqual(sim2.status, 'contained');
});

t('breached crown jewel reports ETA 0', () => {
  const s = mk(0); s.compromised.add('db-fin');
  const a = G.analyze(env, s, { k: 0 });
  assert.strictEqual(a.headline.status, 'breached');
  assert.strictEqual(a.minEta, 0);
});

t('formatter', () => {
  assert.strictEqual(G.fmt(45), '45 min');
  assert.strictEqual(G.fmt(125), '2h 05m');
  assert.strictEqual(G.fmt(Infinity), '∞');
});


const ref = require('../js/reference.js');

t('reference data covers every technique and playbook is well-formed', () => {
  const tids = new Set(sample.edges.map(e => e.tid));
  tids.forEach(id => assert.ok(ref.detect[id], 'detection guidance for ' + id));
  Object.keys(ref.detect).forEach(id => assert.ok(tids.has(id), 'unused detection entry ' + id));
  const ids = new Set();
  ref.playbooks.forEach(pb => pb.steps.forEach(st => { assert.ok(!ids.has(st.id), 'dup step ' + st.id); ids.add(st.id); assert.ok(st.text && st.phase); }));
  sample.scenarios.forEach(sc => assert.ok(ref.playbooks.some(p => p.id === ref.scenarioPlaybook[sc.id]), 'playbook for ' + sc.id));
  sample.edges.forEach(e => assert.ok(ref.tacticOrder.includes(e.tactic), 'known tactic ' + e.tactic));
});

t('adversary speed factor scales ETA linearly', () => {
  const a = mk(0), b = mk(0); b.speed = 0.5;
  const ea = G.analyze(env, a, { k: 0 }).minEta, eb = G.analyze(env, b, { k: 0 }).minEta;
  assert.ok(Math.abs(eb - ea * 0.5) < 1e-6, ea + ' vs ' + eb);
});

t('exposure score is bounded and rises as the attacker gets closer', () => {
  const s = mk(0), e0 = G.exposure(env, s);
  assert.ok(e0 >= 0 && e0 <= 100);
  s.compromised.add('db-fin');
  assert.ok(G.exposure(env, s) > e0);
  const iso = mk(0); sample.edges.forEach(() => {}); iso.removed.add('ws-hr-07');
  assert.strictEqual(G.exposure(env, iso), 0);
});

t('severity maps ETA to levels', () => {
  const breached = mk(0); breached.compromised.add('db-fin');
  assert.strictEqual(G.severity(G.analyze(env, breached, { k: 0 })).level, 'SEV1');
  assert.strictEqual(G.severity(G.analyze(env, mk(2), { k: 0 })).level, 'SEV2');
  const slow = mk(2); slow.speed = 2.5;
  assert.strictEqual(G.severity(G.analyze(env, slow, { k: 0 })).level, 'SEV3');
  const iso = mk(0); iso.removed.add('ws-hr-07');
  assert.strictEqual(G.severity(G.analyze(env, iso, { k: 0 })).level, 'SEV4');
});

t('tactic exposure percentages are valid', () => {
  const te = G.tacticExposure(env, mk(0));
  assert.ok(te.total > 0 && te.tactics.length > 0);
  te.tactics.forEach(x => assert.ok(x.pct > 0 && x.pct <= 100));
});

t('hardening advisor: enabling a missing control never worsens ETA', () => {
  const rows = G.hardening(env, mk(0), sample.scenarios);
  assert.strictEqual(rows.length, env.controls.length);
  rows.filter(r => !r.enabled).forEach(r => assert.ok(r.deltaEta >= -1e-9, r.id + ' ' + r.deltaEta));
  rows.filter(r => r.enabled).forEach(r => assert.ok(r.deltaEta <= 1e-9, r.id));
});

t('projection: guided response beats an unchecked attacker', () => {
  const s = mk(0), sim = G.createSim(s); G.tick(env, s, sim, sample.scenarios[0].dwell);
  const p = G.project(env, s, sim, { lag: 5 });
  assert.strictEqual(p.unmanaged.status, 'breach');
  assert.ok(p.unmanaged.points.length > 2);
  assert.notStrictEqual(p.guided.status, 'breach', 'guided run should not end in breach: ' + p.guided.status);
  assert.ok(p.guided.actions.length > 0);
});

t('projection: slower response lag is never better', () => {
  const s = mk(0), sim = G.createSim(s); G.tick(env, s, sim, sample.scenarios[0].dwell);
  const fast = G.project(env, s, sim, { lag: 1 }), slow = G.project(env, s, sim, { lag: 60 });
  assert.strictEqual(slow.guided.status, 'breach');
  assert.ok(fast.guided.status !== 'breach');
});

t('prepare auto-lays-out nodes that have no coordinates and defaults labels', () => {
  const raw = { nodes: [{ id: 'a', zone: 'Z1' }, { id: 'b', zone: 'Z1' }, { id: 'c', zone: 'Z2', crown: true }], edges: [{ from: 'a', to: 'c', minutes: 5, p: 0.5 }] };
  const e = G.prepare(raw);
  e.nodes.forEach(n => { assert.ok(Number.isFinite(n.x) && Number.isFinite(n.y)); assert.ok(n.label); });
  assert.strictEqual(e.zones.length, 2);
  assert.ok(!('x' in raw.nodes[0]), 'input is not mutated');
});

t('cloneSim copies the in-flight hop', () => {
  const s = mk(1), sim = G.createSim(s); G.tick(env, s, sim, 3);
  const c = G.cloneSim(sim);
  c.hop.remaining = -5;
  assert.notStrictEqual(sim.hop.remaining, -5);
});

t('severity honours a live ETA override', () => {
  const st = mk(2), a = G.analyze(env, st, { k: 1 });
  assert.ok(a.minEta > 15);
  assert.strictEqual(G.severity(a, 10).level, 'SEV1');
  assert.strictEqual(G.severity(a, 45).level, 'SEV2');
  assert.strictEqual(G.severity(a, 90).level, 'SEV3');
});

t('sample incidents agree with the engine (ETA and severity after dwell, default controls)', () => {
  const REF = require('../js/reference.js');
  REF.sampleIncidents.slice(0, 3).forEach(si => {
    const sc = sample.scenarios.find(x => x.id === si.scenarioId), st = G.makeState(env, sc), sim = G.createSim(st);
    if (sc.dwell) G.tick(env, st, sim, sc.dwell);
    const a = G.analyze(env, st, { k: 1 });
    let live = a.minEta; if (sim.hop && a.headline.route.hops[0].id === sim.hop.adj.id) live -= (sim.hop.total - sim.hop.remaining);
    assert.strictEqual(Math.round(live), si.eta, si.title);
    assert.strictEqual(G.severity(a, live).level, si.severity, si.title);
  });
});

t('every playbook step has a CSF code, a role and unique ids', () => {
  const REF = require('../js/reference.js'), seen = new Set();
  REF.playbooks.forEach(pb => pb.steps.forEach(s => {
    assert.ok(/^(ID|RS|RC)\.[A-Z]{2}$/.test(s.code), s.code);
    assert.ok(s.role && s.phase && s.text);
    assert.ok(!seen.has(s.id), 'duplicate ' + s.id); seen.add(s.id);
  }));
});

console.log('\n' + passed + ' tests passed');
