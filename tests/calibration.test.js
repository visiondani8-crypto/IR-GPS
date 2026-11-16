'use strict';
// Run: node tests/calibration.test.js
const assert = require('assert');
const G = require('../js/engine.js');
const C = require('../js/calibration.js');
const sample = require('../js/data.js');

let passed = 0;
function t(name, fn) { fn(); passed++; console.log('  ok  ' + name); }
const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, (msg || '') + ' expected ' + b + ' ± ' + tol + ', got ' + a);
const raw = () => JSON.parse(JSON.stringify(sample));

t('parses CSV with aliases, quotes and units', () => {
  const r = C.parse('Technique;Duration;Result;Case\nT1021.002;6;yes;"red team, march"\nT1003.001;2h;;\nT1021.001;90s;failed;');
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.rows.length, 3);
  assert.deepStrictEqual([r.rows[0].tid, r.rows[0].minutes, r.rows[0].success, r.rows[0].note], ['T1021.002', 6, true, 'red team, march']);
  assert.strictEqual(r.rows[1].minutes, 120);
  assert.strictEqual(r.rows[2].minutes, 1.5); assert.strictEqual(r.rows[2].success, false);
});

t('parses JSON arrays and wrapped objects', () => {
  assert.strictEqual(C.parse('[{"technique":"T1021.002","minutes":5}]').rows.length, 1);
  assert.strictEqual(C.parse('{"observations":[{"from":"a","to":"b","minutes":3,"success":true}]}').rows[0].from, 'a');
});

t('reports bad rows with line numbers and keeps the good ones', () => {
  const r = C.parse('technique,minutes,success\nT1021.002,abc,\n,5,\nT1021.002,7,maybe\nT1021.002,9,true');
  assert.strictEqual(r.rows.length, 1);
  assert.strictEqual(r.errors.length, 3);
  assert.ok(/Line 2/.test(r.errors[0]) && /Line 3/.test(r.errors[1]) && /Line 4/.test(r.errors[2]));
  assert.ok(C.parse('').errors.length && C.parse('hello world').errors.length && C.parse('{bad').errors.length);
});

t('the bundled template parses cleanly', () => assert.deepStrictEqual(C.parse(C.TEMPLATE).errors, []));

t('matching: edge id beats pair beats technique; T1021 covers sub-techniques but not the reverse', () => {
  const env = G.prepare(raw());
  const a = C.assign(env, C.parse('edge,minutes\nws-hr-07>srv-file-01,9').rows);
  assert.deepStrictEqual(Object.keys(a.by), ['ws-hr-07>srv-file-01']);
  const b = C.assign(env, C.parse('from,to,minutes\nws-hr-07,ws-fin-03,9').rows);
  assert.deepStrictEqual(Object.keys(b.by), ['ws-hr-07>ws-fin-03']);
  const c = C.assign(env, C.parse('technique,minutes\nT1021,9').rows), d = C.assign(env, C.parse('technique,minutes\nT1021.002,9').rows);
  assert.ok(Object.keys(c.by).length > Object.keys(d.by).length);
  assert.ok(Object.keys(d.by).every(id => env.edges.find(e => e.from + '>' + e.to === id).tid === 'T1021.002'));
  assert.strictEqual(C.assign(env, C.parse('technique,minutes\nT9999,9').rows).unmatched.length, 1);
});

t('shrinkage: one observation nudges, many dominate, none leaves the prior alone', () => {
  const e = { minutes: 20, p: 0.5, conf: 'low' };
  const none = C.fitEdge(e, []); assert.strictEqual(none.post.minutes, 20);
  const one = C.fitEdge(e, [{ minutes: 5 }]);
  assert.ok(one.post.minutes < 20 && one.post.minutes > 10, 'one point moves it a little: ' + one.post.minutes);
  const many = C.fitEdge(e, Array.from({ length: 40 }, () => ({ minutes: 5 })));
  near(many.post.minutes, 5, 0.9);
});

t('confidence rises with evidence and sigma never drops below the floor', () => {
  const rows = n => Array.from({ length: n }, () => ({ minutes: 10 }));
  const e = { minutes: 10, p: 0.5 };
  assert.deepStrictEqual([1, 3, 8].map(n => C.fitEdge(e, rows(n)).post.conf), ['low', 'med', 'high']);
  assert.ok(C.fitEdge(e, rows(30)).post.sigma >= C.SIGMA_FLOOR - 1e-12);
  assert.ok(C.fitEdge(e, rows(30)).post.sigma < C.fitEdge(e, rows(2)).post.sigma);
});

t('fit recovers a known lognormal from noisy samples', () => {
  const R = G.rng(99), draws = Array.from({ length: 200 }, () => ({ minutes: 12 * Math.exp(0.4 * (Math.sqrt(-2 * Math.log(R() || 1e-9)) * Math.cos(2 * Math.PI * R())) ) }));
  const f = C.fitEdge({ minutes: 30, p: 0.5, conf: 'low' }, draws);
  near(f.post.minutes, 12, 1.2); near(f.post.sigma, 0.4, 0.08);
});

t('success chance is a prior-weighted proportion', () => {
  const f = C.fitEdge({ minutes: 10, p: 0.5 }, [{ success: true }, { success: true }, { success: true }, { success: false }]);
  near(f.post.p, (3 + C.K_PROB * 0.5) / (4 + C.K_PROB), 1e-9);
  assert.strictEqual(C.fitEdge({ minutes: 10, p: 0.5 }, [{ success: false }]).post.minutes, 10);
});

t('apply writes provenance, never mutates its input, and is idempotent on refit', () => {
  const env = raw(), before = JSON.stringify(env);
  const rows = C.parse('technique,minutes,success\nT1021.002,6,true\nT1021.002,8,true\nT1021.002,5,false\nT1021.002,7,true').rows;
  const f1 = C.fit(env, rows), a1 = C.apply(env, f1.fits);
  assert.strictEqual(JSON.stringify(env), before);
  assert.ok(a1.changed >= 1);
  const e = a1.env.edges.find(x => x.tid === 'T1021.002');
  assert.strictEqual(e.source, 'calibrated'); assert.ok(e.n >= 3); assert.ok(e.prior && e.prior.minutes === 15);
  const f2 = C.fit(a1.env, rows), a2 = C.apply(a1.env, f2.fits);
  assert.deepStrictEqual(a2.env.edges.map(x => [x.minutes, x.p, x.sigma, x.conf]), a1.env.edges.map(x => [x.minutes, x.p, x.sigma, x.conf]));
});

t('revert restores the original numbers exactly', () => {
  const env = raw(), rows = C.parse('technique,minutes,success\nT1021,6,true\nT1021,8,true\nT1003,4,false').rows;
  const cal = C.apply(env, C.fit(env, rows).fits);
  assert.notDeepStrictEqual(cal.env.edges, env.edges);
  assert.deepStrictEqual(C.revert(cal.env).env.edges, env.edges);
});

t('revert keeps an explicit prior sigma', () => {
  const env = { nodes: [{ id: 'a' }, { id: 'b', crown: true }], edges: [{ from: 'a', to: 'b', minutes: 10, p: 0.5, sigma: 0.33, tid: 'T1' }] };
  const cal = C.apply(env, C.fit(env, [{ edge: 'a>b', minutes: 9 }]).fits);
  assert.deepStrictEqual(C.revert(cal.env).env.edges, env.edges);
});

t('calibrated environment still validates and tightens the ETA range', () => {
  const env = raw();
  const rows = []; for (let i = 0; i < 12; i++) rows.push({ tid: 'T1021', minutes: 10 + (i % 3) - 1, success: true, from: null, to: null, edge: null, note: '' });
  const cal = C.apply(env, C.fit(env, rows).fits).env;
  assert.deepStrictEqual(G.validate(cal), []);
  const pe = G.prepare(raw()), ce = G.prepare(cal);
  const m0 = G.monteCarlo(pe, G.makeState(pe, sample.scenarios[0]), { runs: 1500 }), m1 = G.monteCarlo(ce, G.makeState(ce, sample.scenarios[0]), { runs: 1500 });
  assert.ok(m1.p90 / m1.p10 < m0.p90 / m0.p10, 'range narrows: ' + (m0.p90 / m0.p10).toFixed(2) + ' -> ' + (m1.p90 / m1.p10).toFixed(2));
});

t('coverage counts calibrated edges and confidence levels', () => {
  const env = raw(), cal = C.apply(env, C.fit(env, C.parse('technique,minutes\nT1021.002,6\nT1021.002,7\nT1021.002,8\nT1021.002,6').rows).fits).env;
  const c = C.coverage(cal);
  assert.strictEqual(c.total, env.edges.length); assert.ok(c.calibrated >= 1 && c.share > 0);
  assert.strictEqual(c.byConf.low + c.byConf.med + c.byConf.high, c.total);
});

console.log('\n' + passed + ' calibration tests passed');
