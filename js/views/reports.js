/* Reports: Markdown incident report, executive summary, CSV exports, environment JSON. Also exposes Reports.* builders. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};

  function csvCell(v) { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  function csv(rows) { return rows.map(function (r) { return r.map(csvCell).join(','); }).join('\n') + '\n'; }
  function label(id) { return Core.env.byId[id] ? Core.env.byId[id].label : id; }
  function deadlines(awareIso) {
    var t0 = new Date(awareIso).getTime();
    return Core.clocksFor().map(function (c) { return { c: c, due: new Date(t0 + c.hours * 3600000) }; });
  }

  var Reports = {
    // Uncertainty section shared by the full report.
    uncMd: function () {
      var u = Core.unc();
      if (u.status !== 'at-risk') return [];
      var sn = Core.drivers(), cov = Core.calCoverage(), L = [];
      var v = function (x) { return sn.metric === 'median' ? G.fmt(x) : Math.round(x * 100) + '% within 60 min'; };
      L.push('## How certain is this ETA', '',
        '- Fastest path, if every step works first time: ' + G.fmt(u.deterministic),
        '- Typical (median of ' + u.runs + ' simulated attacks): ' + G.fmt(u.p50),
        '- Likely range (P10 to P90): ' + G.fmt(u.p10) + ' to ' + G.fmt(u.p90),
        '- Chance a crown jewel falls within 15 / 30 / 60 minutes: ' + [15, 30, 60].map(function (T) { return Math.round(100 * u.by[T]) + '%'; }).join(' / '),
        '- Attacker behaviour assumed: ' + (u.persistent ? 'retries failed steps' : 'one attempt per step (breach chances are lower bounds)'),
        '- Evidence behind the numbers: ' + cov.calibrated + ' of ' + cov.total + ' steps are calibrated from observations; the rest are illustrative priors.');
      if (sn.drivers.length) {
        L.push('', 'Assumptions that move the ETA most (one at a time):');
        sn.drivers.slice(0, 4).forEach(function (d) { L.push('- ' + d.label + ' (' + d.detail.replace(/\.$/, '') + '): ' + d.fastLabel + ' gives ' + v(d.fast) + ', ' + d.slowLabel + ' gives ' + v(d.slow)); });
      }
      L.push('');
      return L;
    },
    // Full report for whatever the Navigator is showing right now.
    incidentMd: function () {
      var env = Core.env, st = Core.st, a = Core.analysis, scn = env.scenarios[Core.scnIdx], sev = G.severity(a, Core.liveEta()), L = [];
      var inc = Core.linkedId ? Core.getIncident(Core.linkedId) : null;
      L.push('# Incident report' + (inc ? ': ' + inc.id : ''), '', '**Scenario:** ' + scn.name, '**Environment:** ' + (Core.raw.name || 'custom'), '**Generated:** ' + new Date().toISOString(),
        '**Severity (from breach ETA):** ' + sev.level + ' ' + sev.label, '**Attacker pace assumption:** ' + (Core.REF.speedProfiles.find(function (p) { return p.id === Core.settings.speedProfile; }) || {}).label, '', '> ' + scn.summary, '');
      L.push('## Status', '- Simulation: ' + Core.sim.status + ' at ' + Core.clockStr(Core.sim.t), '- Crown jewels in reach: ' + a.reachable + ' of ' + a.destinations.length, '- Exposure score: ' + G.exposure(env, st) + '/100',
        '- Fastest ETA: ' + (a.headline ? (a.headline.status === 'breached' ? 'BREACHED (' + a.headline.node.label + ')' : G.fmt(Core.liveEta()) + ' to ' + a.headline.node.label) : 'contained'), '');
      Reports.uncMd().forEach(function (x) { L.push(x); });
      L.push('## Confirmed compromised assets', Array.from(st.compromised).map(function (id) { return '- ' + label(id) + (st.removed.has(id) ? ' (isolated)' : ''); }).join('\n') || '- none', '');
      L.push('## Crown jewels', '', '| Asset | Status | ETA | Route success |', '|---|---|---|---|');
      a.destinations.forEach(function (d) { L.push('| ' + d.node.label + ' | ' + d.status + ' | ' + (d.route ? G.fmt(d.eta) : '-') + ' | ' + (d.route ? Math.round(d.p * 100) + '%' : '-') + ' |'); });
      var acts = Core.log.filter(function (l) { return l.type === 'you' && /^(Applied|Landed|Dispatched)/.test(l.text); });
      L.push('', '## Containment actions', acts.length ? acts.map(function (l) { return '- ' + Core.clockStr(l.t) + ' ' + l.text; }).join('\n') : '- none yet', '');
      L.push('## Predicted attacker routes');
      a.routes.forEach(function (r, i) {
        L.push('', '### ' + (i === 0 ? 'Fastest' : 'Alternative ' + i) + ': ' + G.fmt(r.minutes) + ', ' + Math.round(r.p * 100) + '% success', '', '| # | Move | ATT&CK | How to cut it |', '|---|---|---|---|');
        G.directions(env, r).forEach(function (d) { L.push('| ' + d.n + ' | ' + d.from.label + ' → ' + d.to.label + ' (+' + G.fmt(d.at) + ') | ' + d.tid + ' ' + d.tname + ' | ' + (d.remedy || '') + ' |'); });
      });
      if (Core.recs.length) L.push('', '## Recommended next moves', Core.recs.map(function (x) { return '- ' + x.verb + ': ' + x.label + ' (' + (x.contains ? 'contains' : '+' + G.fmt(x.delta) + ' delay') + ', impact ' + x.impact + '/10)'; }).join('\n'));
      var dl = deadlines(inc ? inc.awareAt : new Date().toISOString());
      L.push('', '## Regulatory clocks (from ' + (inc ? 'awareness time on ' + inc.id : 'now') + ')');
      dl.forEach(function (d) { L.push('- ' + d.c.label + ' (' + d.c.ref + '): by ' + d.due.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' + (d.c.proposed ? ' [proposed duty]' : '')); });
      L.push('', '## Timeline', Core.log.map(function (l) { return '- ' + Core.clockStr(l.t) + ' [' + l.type + '] ' + l.text; }).join('\n'), '');
      L.push('---', 'Generated by IR-GPS. Timings and probabilities are modelled estimates, not measurements, and ranges reflect how little evidence sits behind them. Validate against your own telemetry.');
      return L.join('\n');
    },
    // Report from a stored incident record (uses its saved snapshot).
    incidentMdFor: function (inc) {
      if (inc.id === Core.linkedId) Core.updateLinked();
      var s = inc.snapshot || {}, pb = Core.REF.playbooks.find(function (p) { return p.id === inc.playbookId; }), L = [];
      L.push('# ' + inc.id + ': ' + inc.title, '', '- **Severity:** ' + inc.severity, '- **Status:** ' + inc.status, '- **Owner:** ' + inc.owner, '- **Opened:** ' + new Date(inc.createdAt).toISOString(), '- **Scenario:** ' + (s.scenario || inc.title), '- **Environment:** ' + (s.environment || '-'),
        inc.sample ? '- **Note:** illustrative sample record' : '', '');
      L.push('## Outcome', '- ETA when opened: ' + (s.eta != null ? G.fmt(s.eta) : '-'), '- Simulation result: ' + (s.simStatus || '-') + (s.simT ? ' at ' + G.fmt(s.simT) : ''), '- Crown jewels in reach at last update: ' + (s.reachable != null ? s.reachable + ' of ' + s.total : '-'), '- Exposure at last update: ' + (s.exposure != null ? s.exposure + '/100' : '-'), '');
      if (s.range) L.push('## Uncertainty at last update', '- Likely range: ' + G.fmt(s.range.p10) + ' to ' + G.fmt(s.range.p90) + ' (typical ' + G.fmt(s.range.p50) + ')', '- Chance of breach within 60 minutes: ' + s.range.by60 + '%', '- ' + (s.range.retries ? 'Attacker assumed to retry failed steps' : 'Single attempt per step: breach chances are lower bounds'), '');
      if (s.compromised && s.compromised.length) L.push('## Compromised', s.compromised.map(function (x) { return '- ' + x; }).join('\n'), '');
      if (s.isolated && s.isolated.length) L.push('## Isolated', s.isolated.map(function (x) { return '- ' + x; }).join('\n'), '');
      if (s.blocked && s.blocked.length) L.push('## Blocked paths', s.blocked.map(function (x) { return '- ' + x; }).join('\n'), '');
      if (s.actions && s.actions.length) L.push('## Actions taken', s.actions.map(function (x) { return '- ' + x; }).join('\n'), '');
      if (pb) { var p = Core.playbookProgress(pb, inc.id); L.push('## Playbook', '- ' + pb.name + ': ' + p.done + ' of ' + p.total + ' steps done (' + p.pct + '%)', ''); }
      L.push('## Regulatory deadlines (from ' + new Date(inc.awareAt).toISOString().slice(0, 16).replace('T', ' ') + ' UTC)');
      deadlines(inc.awareAt).forEach(function (d) { L.push('- ' + d.c.label + ' (' + d.c.ref + '): ' + d.due.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' + (inc.clockDone && inc.clockDone[d.c.id] ? ' (done)' : '')); });
      if (inc.notes) L.push('', '## Notes', inc.notes);
      return L.filter(function (x) { return x !== undefined; }).join('\n') + '\n';
    },
    execSummary: function () {
      var a = Core.analysis, env = Core.env, st = Core.st, sev = G.severity(a, Core.liveEta()), scn = env.scenarios[Core.scnIdx], h = a.headline, expo = G.exposure(env, st), proj = Core.projection(), L = [];
      L.push('EXECUTIVE SUMMARY: ' + scn.name, 'Severity ' + sev.level + ' (' + sev.label + ')', '');
      L.push('Situation: ' + scn.summary);
      L.push('Where we stand: ' + (!h ? 'the attacker has no route to any crown jewel. Containment is working.' : h.status === 'breached' ? h.node.label + ' is already breached.' : 'the attacker is predicted to reach ' + h.node.label + ' in about ' + G.fmt(Core.liveEta()) + '. ' + a.reachable + ' of ' + a.destinations.length + ' crown jewels are reachable.'));
      L.push('Exposure score: ' + expo + '/100 (lower is better).');
      (function () { var u = Core.unc(); if (u.status === 'at-risk') L.push('How sure we are: typically ' + G.fmt(u.p50) + ', most likely between ' + G.fmt(u.p10) + ' and ' + G.fmt(u.p90) + '. The fastest case is ' + G.fmt(u.deterministic) + '. ' + Math.round(100 * u.by[60]) + '% chance of a breach within an hour' + (u.persistent ? '.' : ' (lower bound).')); })();
      if (Core.recs.length) { L.push('', 'Recommended next moves:'); Core.recs.slice(0, 3).forEach(function (r, i) { L.push((i + 1) + '. ' + r.verb + ': ' + r.label + (r.contains ? ' (contains the attacker)' : ' (buys ' + G.fmt(r.delta) + ')') + '. Business impact ' + r.impact + '/10.'); }); }
      L.push('', 'If we do nothing: ' + (proj.unmanaged.status === 'breach' ? 'breach in ' + G.fmt(proj.unmanaged.endAt) + '.' : 'no breach projected.') + ' Following guidance after a ' + proj.lag + ' min lag: ' + (proj.guided.status === 'contained' ? 'contained in ' + G.fmt(proj.guided.endAt) + '.' : proj.guided.status === 'breach' ? 'breach at ' + G.fmt(proj.guided.endAt) + '.' : 'stays ahead of the attacker.'));
      var dl = deadlines(new Date().toISOString());
      L.push('', 'Regulatory clocks if this is a notifiable personal-data breach (' + Core.settings.jurisdiction.toUpperCase() + '):');
      dl.forEach(function (d) { L.push('- ' + d.c.label + ': within ' + (d.c.hours >= 48 ? Math.round(d.c.hours / 24) + ' days' : d.c.hours + ' hours') + ' (' + d.c.ref + ')' + (d.c.proposed ? ', proposed' : '')); });
      L.push('', 'Modelled estimates, not measurements.');
      return L.join('\n');
    },
    routesCsv: function () {
      var rows = [['route', 'hop', 'from', 'to', 'attack_id', 'technique', 'tactic', 'minutes', 'cumulative_minutes', 'success_probability', 'hop_p10_min', 'hop_p90_min', 'evidence', 'how_to_cut']];
      Core.analysis.routes.forEach(function (r, i) { G.directions(Core.env, r).forEach(function (d) { rows.push([i === 0 ? 'fastest' : 'alt' + i, d.n, d.from.label, d.to.label, d.tid, d.tname, d.tactic, Math.round(d.minutes * 10) / 10, Math.round(d.at * 10) / 10, d.p.toFixed(2), Math.round(Core.explain(d.edgeId).p10 * 10) / 10, Math.round(Core.explain(d.edgeId).p90 * 10) / 10, Core.explain(d.edgeId).source, d.remedy]); }); });
      return csv(rows);
    },
    timelineCsv: function () { var rows = [['clock', 'type', 'event']]; Core.log.forEach(function (l) { rows.push([Core.clockStr(l.t), l.type, l.text]); }); return csv(rows); },
    incidentsCsv: function (list) {
      var rows = [['id', 'title', 'severity', 'status', 'owner', 'opened', 'eta_at_open_min', 'time_to_contain_min', 'sample']];
      (list || Core.incidents).forEach(function (i) { var s = i.snapshot || {}; rows.push([i.id, i.title, i.severity, i.status, i.owner, i.createdAt, s.eta, s.simStatus === 'contained' ? s.simT : '', i.sample ? 'yes' : 'no']); });
      return csv(rows);
    },
    envJson: function () { return JSON.stringify(Core.raw, null, 2); },
    deliver: function (title, text, name) { UI.textModal(title, text, name); },
    downloadIncident: function (inc) { Reports.deliver(inc.id + ' report', Reports.incidentMdFor(inc), inc.id + '-report.md'); }
  };
  root.Reports = Reports;

  var KINDS = [
    { id: 'incident', title: 'Incident report', sub: 'Markdown. Status, routes, actions, timeline, deadlines.', file: 'ir-gps-report.md', build: Reports.incidentMd },
    { id: 'exec', title: 'Executive summary', sub: 'Plain text for the person who needs one paragraph.', file: 'ir-gps-exec-summary.txt', build: Reports.execSummary },
    { id: 'routes', title: 'Predicted routes (CSV)', sub: 'Every hop of the top routes with ATT&CK ids.', file: 'ir-gps-routes.csv', build: Reports.routesCsv },
    { id: 'timeline', title: 'Timeline (CSV)', sub: 'Every event on the incident clock.', file: 'ir-gps-timeline.csv', build: Reports.timelineCsv },
    { id: 'incidents', title: 'Incident register (CSV)', sub: 'All incidents in the register.', file: 'ir-gps-incidents.csv', build: function () { return Reports.incidentsCsv(); } },
    { id: 'env', title: 'Environment (JSON)', sub: 'Your assets, edges and controls. Re-importable.', file: 'ir-gps-environment.json', build: Reports.envJson }
  ];

  Views.reports = {
    title: 'Reports', kind: 'incident',
    render: function () {
      var cur = KINDS.find(function (k) { return k.id === Views.reports.kind; }) || KINDS[0];
      var list = KINDS.map(function (k) { return '<button class="listbtn' + (k.id === cur.id ? ' on' : '') + '" data-act="rep-kind" data-k="' + k.id + '"><b>' + esc(k.title) + '</b><small class="mut">' + esc(k.sub) + '</small></button>'; }).join('');
      return '<div class="grid g-split"><section class="card"><div class="chead"><h2>Exports</h2></div><div class="stack" style="gap:8px">' + list + '</div></section>' +
        '<section class="card"><div class="chead"><h2>' + esc(cur.title) + '</h2><button class="btn sm" data-act="rep-copy">' + icon('copy') + 'Copy</button><button class="btn sm primary" data-act="rep-download">' + icon('download') + 'Download</button></div>' +
        '<pre class="code" id="rep-pre" style="max-height:68vh">' + esc(cur.build()) + '</pre></section></div>';
    },
    act: function (name, el) {
      var cur = KINDS.find(function (k) { return k.id === Views.reports.kind; }) || KINDS[0];
      if (name === 'rep-kind') { Views.reports.kind = el.getAttribute('data-k'); root.App.render(); return true; }
      if (name === 'rep-copy') { UI.copy(cur.build()).then(function () { UI.toast('Copied.', 'ok'); }, function () { UI.toast('Copy is blocked here. Select the text and copy manually.', 'err'); }); return true; }
      if (name === 'rep-download') { UI.textModal(cur.title, cur.build(), cur.file); return true; }
      return false;
    }
  };
  Views.reports.KINDS = KINDS;
})(typeof self !== 'undefined' ? self : this);
