'use strict';
// Run: node tests/validation.test.js
const assert = require('assert');
const G = require('../js/engine.js');
const V = require('../js/validation.js');
const D = require('../js/validation-data.js');
const sample = require('../js/data.js');

let passed = 0;
function t(name, fn) { fn(); passed++; console.log('  ok  ' + name); }

const env = G.prepare(sample);
const st = (speed) => { const s = G.makeState(env, sample.scenarios[0]); if (speed) s.speed = speed; return s; };

t('dataset is well formed and cross-referenced', () => {
  const ids = new Set(D.cases.map(c => c.id));
  assert.strictEqual(ids.size, D.cases.length);
  D.phases.forEach(p => { assert.ok(ids.has(p.caseId), p.id); assert.ok(p.minutes > 0 && Number.isInteger(p.hops) && p.hops >= 1, p.id); assert.ok(p.hopsBasis.length > 20, p.id + ' explains its hop count'); });
  D.cases.concat(D.dwell, D.benchmarks).forEach(x => assert.ok(/^https:\/\//.test(x.url), (x.id || x.name) + ' links to its source'));
  D.dwell.forEach(d => assert.ok(d.minutes > 0 && d.basis && d.label));
  D.benchmarks.forEach(b => assert.ok(b.minutes > 0 && b.reliability && b.kind));
});

t('case milestones are in order and agree with the stated time-to-ransom', () => {
  D.cases.forEach(c => {
    const ts = c.milestones.map(m => m.t).filter(x => x != null);
    for (let i = 1; i < ts.length; i++) assert.ok(ts[i] >= ts[i - 1], c.id + ' milestones ascend');
    if (c.ttr) assert.strictEqual(ts[ts.length - 1], c.ttr, c.id + ' last milestone is the TTR');
  });
});

t('phase durations match the milestones they were derived from', () => {
  const at = (id, re) => D.cases.find(c => c.id === id).milestones.find(m => re.test(m.label)).t;
  const ph = id => D.phases.find(p => p.id === id).minutes;
  assert.strictEqual(ph('p1'), at('ryuk-speed', /domain controllers/) - at('ryuk-speed', /Cobalt Strike/));
  assert.strictEqual(ph('p2'), at('ryuk-speed', /encrypted/) - at('ryuk-speed', /Ryuk deployment/ ) - 0 + (at('ryuk-speed', /Ryuk deployment/) - at('ryuk-speed', /domain controllers/)));
  assert.strictEqual(ph('p3'), D.cases.find(c => c.id === 'ryuk-5h').ttr);
  assert.strictEqual(ph('p4'), at('quantum', /Domain-wide/) - at('quantum', /Hands-on/));
  assert.strictEqual(ph('p6'), at('xinglocker', /Administrative/) - at('xinglocker', /Cobalt Strike beacon downloaded/));
});

t('run is deterministic and returns one result per documented stretch', () => {
  const a = V.run(env, st(), { runs: 2000 }), b = V.run(env, st(), { runs: 2000 });
  assert.strictEqual(a.rows.length, D.phases.length);
  assert.deepStrictEqual(a.rows.map(r => [r.p10, r.p50, r.p90]), b.rows.map(r => [r.p10, r.p50, r.p90]));
  a.rows.forEach(r => assert.ok(r.p10 < r.p50 && r.p50 < r.p90 && r.pit >= 0 && r.pit <= 1));
  assert.ok(a.coverage >= 0 && a.coverage <= 1);
});

t('post-foothold pool excludes initial-access edges', () => {
  const ia = env.edges.filter(e => e.tactic === 'Initial Access').length;
  assert.strictEqual(V.pool(env, st()).length, env.edges.length - ia);
});

t('the check can fail: a tight, retry-free model misses nearly every observation', () => {
  const r = V.run(env, st(), { runs: 2000, persistent: false, sigmaScale: 0.1, paceSigma: 0.01 });
  assert.ok(r.coverage <= 0.34, 'coverage ' + r.coverage);
  assert.strictEqual(r.verdict.level, 'warn');
  assert.ok(r.sharpness < V.run(env, st(), { runs: 2000 }).sharpness, 'tighter model has narrower bands');
});

t('the check can fail: a model ten times too slow or too fast is flagged in the right direction', () => {
  const slowModel = V.run(env, st(10), { runs: 2000 }), fastModel = V.run(env, st(0.1), { runs: 2000 });
  assert.ok(slowModel.faster > slowModel.slower && /faster/.test(slowModel.verdict.headline), slowModel.verdict.headline);
  assert.ok(fastModel.slower > fastModel.faster && /slower/.test(fastModel.verdict.headline), fastModel.verdict.headline);
  assert.ok(slowModel.bias < 0.3 && fastModel.bias > 3);
});

t('a widening suggestion appears for a tight model and not for the default one', () => {
  const tight = V.run(env, st(), { runs: 2000, persistent: false, sigmaScale: 0.1, paceSigma: 0.01 });
  assert.ok(tight.suggest && tight.suggest.scale > 1 && tight.suggest.coverage >= V.TARGET);
  assert.strictEqual(V.run(env, st(), { runs: 2000 }).suggest.scale, 1);
});

t('small samples are labelled anecdotal and wide bands are called out', () => {
  const r = V.run(env, st(), { runs: 2000 });
  assert.strictEqual(r.anecdotal, true);
  assert.ok(r.caveats.some(c => /anecdote/.test(c)));
  assert.ok(r.caveats.some(c => /wide/.test(c)), 'wide-band caveat');
  assert.ok(r.sharpness > 5);
});

t('single-step observations are separated from multi-hop stretches', () => {
  const r = V.run(env, st(), { runs: 2000 });
  assert.strictEqual(r.split.single.n, 2); assert.strictEqual(r.split.multi.n, 4);
  assert.ok(r.split.single.ratio < r.split.multi.ratio);
});

t('time-to-hands-on-keyboard statistics match the cited cases', () => {
  const d = V.dwellStats();
  assert.strictEqual(d.n, 10); assert.strictEqual(d.min, 10); assert.strictEqual(d.max, 1800); assert.strictEqual(d.median, 120);
  assert.strictEqual(d.within240, 0.8); assert.strictEqual(d.overOneDay, 1);
});

console.log('\n' + passed + ' validation tests passed');
