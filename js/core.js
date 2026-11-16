/* Core: application state, persistence, simulation loop, incidents, notifications.
 * Views read from Core and call its methods; Core emits 'state' (full redraw) and 'tick' (light update). */
(function (root) {
  'use strict';
  var G = root.IRGPS, REF = root.IRG_REF, SAMPLE = root.IRGPS_SAMPLE, UI = root.UI, Cal = root.IRGPSCal, Val = root.IRGPSVal;

  // ---------- storage (localStorage with in-memory fallback) ----------
  var mem = {}, persistent = true;
  function sget(k, def) {
    try { var v = localStorage.getItem('irgps:' + k); if (v != null) { return JSON.parse(v); } return k in mem ? mem[k] : def; }
    catch (e) { persistent = false; return k in mem ? mem[k] : def; }
  }
  function sset(k, v) {
    mem[k] = v;
    try { localStorage.setItem('irgps:' + k, JSON.stringify(v)); } catch (e) { persistent = false; }
  }
  function sdel(k) { delete mem[k]; try { localStorage.removeItem('irgps:' + k); } catch (e) { persistent = false; } }

  var DEFAULTS = { theme: 'dark', jurisdiction: 'uk', owner: 'Daniel', speedProfile: 'ecrime', lag: 5, rangeDays: 30, simSpeed: 4, target: 60, persistent: true, sigmaScale: 1, controls: {} };

  var Core = {
    G: G, REF: REF, UI: UI, sget: sget, sset: sset,
    raw: null, env: null, envRev: 0, st: null, sim: null, scnIdx: 0, log: [], pending: [], timer: null,
    selected: null, routeIdx: 0, analysis: null, recs: [], initial: null, projCache: null,
    incidents: [], settings: {}, notifs: [], linkedId: null, pbChecks: {}, listeners: [], customEnv: false, obs: [], uncCache: null, drvCache: null, valCache: null,
    get persistent() { return persistent; }
  };

  Core.on = function (fn) { Core.listeners.push(fn); };
  Core.emit = function (kind) { Core.listeners.forEach(function (fn) { fn(kind || 'state'); }); };

  // ---------- settings ----------
  Core.setSetting = function (k, v) {
    Core.settings[k] = v; sset('settings', Core.settings);
    if (k === 'theme') Core.applyTheme();
    if (k === 'speedProfile' && Core.st) { Core.st.speed = Core.profileFactor(); Core.projCache = null; Core.refresh(); }
    if (k === 'lag') Core.projCache = null;
    if (k === 'persistent' || k === 'sigmaScale') { Core.uncCache = null; Core.drvCache = null; Core.valCache = null; }
    Core.emit('state');
  };
  Core.applyTheme = function () { document.documentElement.setAttribute('data-theme', Core.settings.theme === 'light' ? 'light' : 'dark'); };
  Core.profileFactor = function () {
    var p = REF.speedProfiles.find(function (x) { return x.id === Core.settings.speedProfile; });
    return p ? p.factor : 1;
  };

  // ---------- environment ----------
  Core.loadEnv = function (raw, persist, keepScenario) {
    var env;
    try { env = G.prepare(raw); }
    catch (e) { UI.toast('Environment rejected: ' + (e.message || 'invalid'), 'err', 6000); return false; }
    Core.raw = JSON.parse(JSON.stringify(raw));
    Core.env = env; Core.envRev++; Core.projCache = null;
    Core.customEnv = raw !== SAMPLE && persist !== false;
    if (!env.scenarios || !env.scenarios.length) {
      var first = env.nodes.find(function (n) { return !n.crown; }) || env.nodes[0];
      env.scenarios = [{ id: 'default', name: 'Default incident', summary: 'Foothold on ' + first.label + '.', compromised: [first.id], dwell: 0 }];
      Core.raw.scenarios = env.scenarios;
    }
    if (persist !== false) { if (raw === SAMPLE) sdel('env'); else sset('env', Core.raw); }
    Core.startScenario(keepScenario ? Math.min(Core.scnIdx, env.scenarios.length - 1) : 0);
    return true;
  };
  Core.updateRaw = function (mutator) {
    var raw = JSON.parse(JSON.stringify(Core.raw)); mutator(raw);
    return Core.loadEnv(raw, true, true);
  };
  Core.resetEnv = function () { Core.loadEnv(SAMPLE, true, false); UI.toast('Sample environment restored.', 'ok'); };

  // ---------- scenario / state ----------
  Core.startScenario = function (i) {
    Core.stop();
    Core.banner = null; // a breach or containment banner belongs to the run that just ended
    var env = Core.env;
    Core.scnIdx = Math.max(0, Math.min(i, env.scenarios.length - 1));
    var scn = env.scenarios[Core.scnIdx];
    Core.st = G.makeState(env, scn);
    Object.keys(Core.settings.controls || {}).forEach(function (id) { if (id in Core.st.controls) Core.st.controls[id] = !!Core.settings.controls[id]; });
    Core.st.speed = Core.profileFactor();
    Core.sim = G.createSim(Core.st);
    Core.log = []; Core.pending = []; Core.selected = null; Core.routeIdx = 0; Core.linkedId = null;
    // The attacker already had `dwell` minutes before the alert. Replay them, then reset the clock so the incident starts at T+00:00.
    if (scn.dwell) {
      G.tick(env, Core.st, Core.sim, scn.dwell).forEach(function (e) {
        if (e.type === 'owned') Core.log.push({ t: e.t - scn.dwell, type: 'owned', text: 'Telemetry confirms ' + e.text.replace('Compromised ', '') });
      });
      Core.sim.t = 0;
    }
    Core.note('you', 'Alert received: ' + scn.summary, 0);
    Core.initial = { st: G.cloneState(Core.st), sim: G.cloneSim(Core.sim) };
    Core.projCache = null;
    Core.refresh(); Core.emit('state');
  };

  Core.note = function (type, text, t) { Core.log.push({ t: t == null ? (Core.sim ? Core.sim.t : 0) : t, type: type, text: text }); };

  Core.refresh = function () {
    Core.analysis = G.analyze(Core.env, Core.st, { k: 3 });
    if (Core.routeIdx >= Core.analysis.routes.length) Core.routeIdx = 0;
    Core.recs = Core.sim.status === 'running' ? G.recommend(Core.env, Core.st, 5) : [];
  };

  Core.liveEta = function () {
    var a = Core.analysis, h = a && a.headline;
    if (!h) return null;
    var eta = h.eta, sim = Core.sim;
    if (sim.hop && h.route && h.route.hops.length && h.route.hops[0].id === sim.hop.adj.id) eta -= (sim.hop.total - sim.hop.remaining);
    return Math.max(0, eta);
  };

  Core.projection = function () {
    var key = [Core.scnIdx, JSON.stringify(Core.st.controls), Core.st.speed, Core.settings.lag, Core.envRev].join('|');
    if (Core.projCache && Core.projCache.key === key) return Core.projCache.val;
    var s = G.cloneState(Core.initial.st); s.controls = Object.assign({}, Core.st.controls); s.speed = Core.st.speed;
    var val = G.project(Core.env, s, G.cloneSim(Core.initial.sim), { lag: Core.settings.lag });
    Core.projCache = { key: key, val: val };
    return val;
  };

  Core.baseline = function () {
    var s = G.cloneState(Core.st);
    Object.keys(s.controls).forEach(function (k) { s.controls[k] = true; });
    var a = G.analyze(Core.env, s, { k: 0 });
    return { eta: a.minEta, exposure: G.exposure(Core.env, s) };
  };

  // ---------- uncertainty ----------
  // Monte Carlo range for the current state. Cached on everything that changes the answer, so views can call it freely.
  function stateKey() {
    var st = Core.st;
    return [Core.envRev, Core.scnIdx, JSON.stringify(st.controls), st.speed, Array.from(st.compromised).sort().join(','), Array.from(st.removed).sort().join(','), Array.from(st.blocked).sort().join(','), Core.settings.persistent !== false, Core.settings.sigmaScale || 1].join('|');
  }
  Core.mcOpts = function () { return { persistent: Core.settings.persistent !== false, sigmaScale: Core.settings.sigmaScale || 1 }; };
  Core.unc = function () {
    var sim = Core.sim, hop = sim && sim.hop && sim.status === 'running' ? { id: sim.hop.adj.id, elapsed: Math.floor(sim.hop.total - sim.hop.remaining) } : null;
    var key = stateKey() + '|' + (hop ? hop.id + ':' + hop.elapsed : '-');
    if (Core.uncCache && Core.uncCache.key === key) return Core.uncCache.val;
    var o = Core.mcOpts(); o.runs = 1500; o.hop = hop;
    var val = G.monteCarlo(Core.env, Core.st, o);
    Core.uncCache = { key: key, val: val };
    return val;
  };
  Core.drivers = function () {
    var key = stateKey();
    if (Core.drvCache && Core.drvCache.key === key) return Core.drvCache.val;
    var o = Core.mcOpts(); o.runs = 400;
    var val = G.sensitivity(Core.env, Core.st, o);
    Core.drvCache = { key: key, val: val };
    return val;
  };
  Core.explain = function (edgeId) { return G.explainEdge(Core.env, Core.st, edgeId, { sigmaScale: Core.settings.sigmaScale || 1 }); };

  // ---------- calibration ----------
  Core.loadObs = function () { var o = sget('obs', []); Core.obs = Array.isArray(o) ? o : []; };
  function saveObs() { sset('obs', Core.obs); }
  Core.calImport = function (text, label) {
    var r = Cal.parse(text);
    if (r.rows.length) {
      r.rows.forEach(function (x) { if (label && !x.note) x.note = label; });
      Core.obs = Core.obs.concat(r.rows); saveObs();
      Core.emit('state');
    }
    return r;
  };
  Core.calFit = function () { return Cal.fit(Core.raw, Core.obs); };
  Core.calApply = function () {
    var fit = Core.calFit();
    if (!fit.fits.length) { UI.toast('No observation matches an edge in this environment.', 'err'); return false; }
    var changed = 0;
    var ok = Core.updateRaw(function (raw) { var res = Cal.apply(raw, fit.fits); raw.edges = res.env.edges; changed = res.changed; });
    if (ok) UI.toast('Calibrated ' + changed + ' step' + (changed === 1 ? '' : 's') + ' from ' + fit.observations + ' observations.', 'ok');
    return ok;
  };
  Core.calRevert = function () {
    var changed = 0;
    var ok = Core.updateRaw(function (raw) { var res = Cal.revert(raw); raw.edges = res.env.edges; changed = res.changed; });
    if (ok) UI.toast(changed ? 'Restored priors on ' + changed + ' step' + (changed === 1 ? '' : 's') + '.' : 'Nothing was calibrated.', 'ok');
    return ok;
  };
  Core.calClear = function () { Core.obs = []; saveObs(); Core.emit('state'); };
  Core.calCoverage = function () { return Cal.coverage(Core.raw); };

  // ---------- validation ----------
  Core.validation = function () {
    var key = [Core.envRev, Core.st.speed, Core.settings.persistent !== false, Core.settings.sigmaScale || 1].join('|');
    if (Core.valCache && Core.valCache.key === key) return Core.valCache.val;
    var o = Core.mcOpts(); o.runs = 3000;
    var base = G.makeState(Core.env, Core.env.scenarios[Core.scnIdx]); base.speed = Core.st.speed;
    var val = Val.run(Core.env, base, o);
    Core.valCache = { key: key, val: val };
    return val;
  };

  Core.setControl = function (id, val) {
    Core.st.controls[id] = !!val;
    Core.settings.controls = Object.assign({}, Core.settings.controls); Core.settings.controls[id] = !!val; sset('settings', Core.settings);
    var c = Core.env.controls.find(function (x) { return x.id === id; });
    Core.note('you', (val ? 'Enabled control: ' : 'Disabled control: ') + (c ? c.label : id));
    Core.projCache = null; Core.refresh(); Core.updateLinked(); Core.emit('state');
  };

  Core.select = function (sel) { Core.selected = sel; Core.emit('state'); };

  // ---------- actions ----------
  Core.describe = function (a) { return a.kind === 'isolate' ? a.verb + ': ' + a.label : 'Block path ' + a.label; };
  Core.actionFromNode = function (id) {
    var n = Core.env.byId[id];
    return { kind: 'isolate', id: id, label: n.label, verb: G.VERBS[n.type] || 'Isolate', impact: n.businessImpact, exec: 3 };
  };
  Core.actionFromEdge = function (id) {
    var e = Core.env.edges.find(function (x) { return x.id === id; });
    return { kind: 'block', id: id, label: Core.env.byId[e.from].label + ' → ' + Core.env.byId[e.to].label, verb: e.remedy || 'Block path', impact: e.impact, exec: 5 };
  };
  Core.execute = function (a) {
    if (!a) return;
    var before = Core.analysis.headline ? Core.liveEta() : null, text = Core.describe(a);
    if (Core.timer && Core.sim.status === 'running') {
      Core.pending.push({ action: a, at: Core.sim.t + a.exec, text: text });
      Core.note('you', 'Dispatched: ' + text + ' (lands in ~' + a.exec + ' min)');
    } else {
      G.applyAction(Core.st, a); Core.note('you', 'Applied: ' + text);
      var after = G.analyze(Core.env, Core.st, { k: 0 });
      Core.banner = after.headline && before != null && after.minEta !== before ? { kind: 'reroute', text: 'Recalculating route… New ETA to ' + after.headline.node.label + ': ' + G.fmt(after.minEta) + ' (was ' + G.fmt(before) + ')', until: Date.now() + 5000 } : null;
    }
    Core.selected = null; Core.projCache = null; Core.refresh(); Core.updateLinked(); Core.emit('state');
  };

  // ---------- simulation loop ----------
  Core.isRunning = function () { return !!Core.timer; };
  Core.play = function () {
    if (Core.sim.status !== 'running' || Core.timer) return;
    Core.banner = null;
    Core.timer = setInterval(Core.step, 100);
    Core.emit('state');
  };
  Core.stop = function () { if (Core.timer) { clearInterval(Core.timer); Core.timer = null; } };
  Core.pause = function () { Core.stop(); Core.emit('state'); };
  Core.toggle = function () { if (Core.timer) Core.pause(); else Core.play(); };

  Core.step = function () {
    var remain = Core.settings.simSpeed * 2 * 0.1, changed = false, guard = 0, sim = Core.sim, env = Core.env;
    while (remain > 1e-9 && sim.status === 'running' && guard++ < 50) {
      var next = Core.pending.length ? Math.min.apply(null, Core.pending.map(function (p) { return p.at; })) - sim.t : Infinity;
      var slice = Math.max(0, Math.min(remain, next));
      if (slice > 0) {
        var t0 = sim.t, ev = G.tick(env, Core.st, sim, slice);
        remain -= Math.max(sim.t - t0, 1e-9);
        ev.forEach(function (e) {
          Core.log.push(e); changed = true;
          if (e.type === 'reroute') { Core.banner = { kind: 'reroute', text: e.text, until: Date.now() + 4000 }; Core.notify('reroute', e.text); }
        });
      }
      var due = Core.pending.filter(function (p) { return p.at <= sim.t + 1e-6; });
      if (due.length) {
        Core.pending = Core.pending.filter(function (p) { return p.at > sim.t + 1e-6; });
        due.forEach(function (p) { G.applyAction(Core.st, p.action); Core.note('you', 'Landed: ' + p.text); });
        changed = true;
      }
    }
    if (sim.status !== 'running') {
      Core.stop();
      var msg = sim.status === 'breach' ? 'Crown jewel breached at ' + clockStr(sim.t) + '. Begin eradication and recovery.' : 'Attacker contained at ' + clockStr(sim.t) + '. No route to any crown jewel remains.';
      Core.banner = { kind: sim.status, text: msg, until: 0 };
      Core.notify(sim.status, msg);
      changed = true;
    }
    if (changed) { Core.projCache = null; Core.refresh(); Core.updateLinked(); Core.emit('sim'); } else Core.emit('tick');
  };

  function clockStr(m) { var s = Math.floor(Math.abs(m) * 60); return 'T' + (m < 0 ? '-' : '+') + UI.pad(Math.floor(s / 60)) + ':' + UI.pad(s % 60); }
  Core.clockStr = clockStr;

  // ---------- notifications ----------
  Core.notify = function (type, text) {
    Core.notifs.unshift({ id: Date.now() + Math.random(), at: Date.now(), type: type, text: text, read: false });
    Core.notifs = Core.notifs.slice(0, 40);
  };
  Core.unread = function () { return Core.notifs.filter(function (n) { return !n.read; }).length; };
  Core.markRead = function () { Core.notifs.forEach(function (n) { n.read = true; }); };

  // ---------- incidents ----------
  function saveIncidents() { sset('incidents', Core.incidents); }
  Core.getIncident = function (id) { return Core.incidents.find(function (i) { return i.id === id; }); };

  Core.snapshot = function () {
    var a = Core.analysis, env = Core.env, st = Core.st;
    var label = function (id) { return env.byId[id] ? env.byId[id].label : id; };
    var edgeLabel = function (id) { var e = env.edges.find(function (x) { return x.id === id; }); return e ? label(e.from) + ' → ' + label(e.to) : id; };
    return {
      eta: a.headline ? (a.headline.status === 'breached' ? 0 : Math.round(Core.liveEta())) : null,
      simStatus: Core.sim.status, simT: Math.round(Core.sim.t * 10) / 10,
      reachable: a.reachable, total: a.destinations.length, exposure: G.exposure(env, st), severity: G.severity(a, Core.liveEta()).level,
      compromised: Array.from(st.compromised).map(label), isolated: Array.from(st.removed).map(label), blocked: Array.from(st.blocked).map(edgeLabel),
      actions: Core.log.filter(function (l) { return l.type === 'you' && /^(Applied|Landed)/.test(l.text); }).map(function (l) { return clockStr(l.t) + ' ' + l.text; }),
      range: (function () { var u = Core.unc(); return u.status === 'at-risk' ? { p10: Math.round(u.p10), p50: Math.round(u.p50), p90: Math.round(u.p90), by60: Math.round(100 * u.by[60]), retries: u.persistent } : null; })(),
      scenario: env.scenarios[Core.scnIdx].name, environment: Core.raw.name || 'custom'
    };
  };

  Core.createIncident = function () {
    var scn = Core.env.scenarios[Core.scnIdx], n = sget('incCounter', 100) + 1; sset('incCounter', n);
    var now = new Date().toISOString(), snap = Core.snapshot();
    var inc = {
      id: 'INC-' + n, title: scn.name, scenarioId: scn.id, severity: snap.severity, status: 'Triage', owner: Core.settings.owner,
      createdAt: now, awareAt: now, playbookId: REF.scenarioPlaybook[scn.id] || REF.playbooks[0].id, notes: '', clockDone: {}, snapshot: snap, sample: false
    };
    Core.incidents.unshift(inc); Core.linkedId = inc.id; Core.updateLinked(); saveIncidents();
    Core.notify('incident', 'Opened ' + inc.id + ': ' + inc.title);
    return inc;
  };
  Core.updateLinked = function () {
    if (!Core.linkedId) return;
    var inc = Core.getIncident(Core.linkedId); if (!inc) { Core.linkedId = null; return; }
    inc.snapshot = Core.snapshot(); inc.severity = inc.snapshot.severity === 'SEV4' ? inc.severity : inc.snapshot.severity;
    if (Core.sim.status === 'contained' && (inc.status === 'Triage' || inc.status === 'Active')) inc.status = 'Contained';
    if (Core.sim.status === 'breach' && (inc.status === 'Triage' || inc.status === 'Active')) inc.status = 'Breached';
    saveIncidents();
  };
  Core.updateIncident = function (id, patch) {
    var inc = Core.getIncident(id); if (!inc) return;
    Object.assign(inc, patch); saveIncidents();
  };
  Core.deleteIncident = function (id) {
    Core.incidents = Core.incidents.filter(function (i) { return i.id !== id; });
    if (Core.linkedId === id) Core.linkedId = null;
    saveIncidents(); Core.emit('state');
  };
  Core.rerun = function (id) {
    var inc = Core.getIncident(id); if (!inc) return false;
    var idx = Core.env.scenarios.findIndex(function (s) { return s.id === inc.scenarioId; });
    if (idx < 0) { UI.toast('That incident\'s scenario is not in the current environment.', 'err'); return false; }
    Core.startScenario(idx); UI.toast('Re-running ' + inc.title + ' in Navigator.', 'ok');
    return true;
  };
  Core.incidentsInRange = function () {
    var d = Core.settings.rangeDays;
    if (!d) return Core.incidents.slice();
    var cut = Date.now() - d * 86400000;
    return Core.incidents.filter(function (i) { return new Date(i.createdAt).getTime() >= cut; });
  };

  // ---------- playbook checks ----------
  Core.checkKey = function (incId, stepId) { return (incId || 'practice') + '|' + stepId; };
  Core.isChecked = function (incId, stepId) { return !!Core.pbChecks[Core.checkKey(incId, stepId)]; };
  Core.toggleCheck = function (incId, stepId) {
    var k = Core.checkKey(incId, stepId);
    if (Core.pbChecks[k]) delete Core.pbChecks[k]; else Core.pbChecks[k] = Date.now();
    sset('pbChecks', Core.pbChecks);
  };
  Core.playbookProgress = function (pb, incId) {
    var done = pb.steps.filter(function (s) { return Core.isChecked(incId, s.id); }).length;
    return { done: done, total: pb.steps.length, pct: Math.round(100 * done / pb.steps.length) };
  };

  // ---------- regulatory clocks ----------
  Core.clocksFor = function () {
    var j = Core.settings.jurisdiction, out = [], seen = {};
    (j === 'both' ? ['uk', 'eu'] : [j]).forEach(function (k) { (REF.clocks[k] || []).forEach(function (c) { if (!seen[c.id]) { seen[c.id] = 1; out.push(c); } }); });
    return out;
  };

  // ---------- reset ----------
  Core.resetAllData = function () {
    ['settings', 'env', 'incidents', 'incCounter', 'pbChecks', 'obs'].forEach(sdel);
    Core.obs = [];
    Core.settings = Object.assign({}, DEFAULTS); Core.applyTheme();
    seedIncidents(); Core.pbChecks = {}; Core.notifs = [];
    Core.loadEnv(SAMPLE, false, false);
  };

  function seedIncidents() {
    Core.incidents = REF.sampleIncidents.map(function (s, i) {
      var d = new Date(Date.now() - s.daysAgo * 86400000).toISOString(), done = {};
      Object.keys(REF.clocks).forEach(function (k) { REF.clocks[k].forEach(function (c) { if (!(i === 0 && c.id === 'uk-gdpr')) done[c.id] = Date.now(); }); });
      return {
        id: 'INC-' + (i + 1), title: s.title, scenarioId: s.scenarioId, severity: s.severity, status: s.status, owner: s.owner,
        createdAt: d, awareAt: d, playbookId: REF.scenarioPlaybook[s.scenarioId] || REF.playbooks[0].id, notes: '', clockDone: done, sample: true,
        snapshot: { eta: s.eta, simStatus: 'contained', simT: s.ttc, reachable: 0, total: 5, exposure: 0, severity: s.severity, compromised: [], isolated: [], blocked: [], actions: [], scenario: s.title, environment: 'Northwind Logistics (sample)' }
      };
    });
    sset('incidents', Core.incidents); sset('incCounter', 100);
  }

  // ---------- init ----------
  Core.init = function () {
    Core.settings = Object.assign({}, DEFAULTS, sget('settings', {}));
    Core.applyTheme();
    var inc = sget('incidents', null);
    if (Array.isArray(inc)) Core.incidents = inc; else seedIncidents();
    Core.pbChecks = sget('pbChecks', {}) || {};
    Core.loadObs();
    var saved = sget('env', null), ok = false;
    if (saved) ok = Core.loadEnv(saved, false, false);
    if (!ok) { sdel('env'); Core.loadEnv(SAMPLE, false, false); }
    else Core.customEnv = true;
  };

  root.Core = Core;
})(typeof self !== 'undefined' ? self : this);
