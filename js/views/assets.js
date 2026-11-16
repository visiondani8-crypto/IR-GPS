/* Assets: edit the environment the engine reasons about. Calibrate times and odds, add assets, paths and scenarios, import/export JSON. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};
  var TYPES = ['gateway', 'workstation', 'server', 'identity', 'cloud', 'data', 'saas'];
  var TACTICS = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact'];
  var $ = function (id) { return document.getElementById(id); };

  function commit(fn, okMsg) {
    var ok = Core.updateRaw(fn);
    if (ok && okMsg) UI.toast(okMsg, 'ok');
    root.App.render();
    return ok;
  }
  function sel(id, opts, val) { return '<select class="select input" id="' + id + '">' + opts.map(function (o) { return '<option value="' + esc(o.v) + '"' + (o.v === val ? ' selected' : '') + '>' + esc(o.t) + '</option>'; }).join('') + '</select>'; }
  function field(label, html) { return '<label style="display:block"><small class="mut">' + label + '</small>' + html + '</label>'; }

  var CONF_ORDER = { low: 0, med: 1, high: 2 };
  function num(x, d) { return (Math.round(x * Math.pow(10, d || 1)) / Math.pow(10, d || 1)).toString(); }
  function calTab() {
    var Cal = root.IRGPSCal, cov = Core.calCoverage(), fit = Core.calFit(), obs = Core.obs.length;
    var kpis = '<div class="grid g3">' +
      '<section class="card kpi"><div class="lbl">Steps backed by your data</div><div class="val">' + cov.calibrated + '<small>of ' + cov.total + '</small></div><div class="foot"><span class="chip ' + (cov.calibrated ? '' : 'amber') + '">' + (cov.calibrated ? Math.round(cov.share * 100) + '% calibrated' : 'all values are priors') + '</span></div></section>' +
      '<section class="card kpi"><div class="lbl">Observations stored</div><div class="val">' + obs + '</div><div class="foot"><span class="chip mut">' + fit.fits.length + ' step' + (fit.fits.length === 1 ? '' : 's') + ' affected</span></div></section>' +
      '<section class="card kpi"><div class="lbl">Confidence mix</div><div class="val" style="font-size:20px">' + cov.byConf.low + ' prior · ' + cov.byConf.med + ' some · ' + cov.byConf.high + ' calibrated</div><div class="foot"><span class="chip mut">sets each step\'s default spread</span></div></section></div>';
    var add = '<section class="card"><div class="chead"><div><h2>Add observations</h2><small class="mut">Timings from red-team runs, purple-team exercises, tabletop injects or past incidents</small></div></div>' +
      '<p class="mut" style="margin-top:0;font-size:13px">One row per attempt. Match a step by <code>technique</code> (T1021 covers every sub-technique), by <code>from</code> + <code>to</code> node ids, or by <code>edge</code> id. Give <code>minutes</code>, <code>success</code> (did it work first time), or both. CSV with a header, or JSON. Everything stays in this browser.</p>' +
      '<textarea class="input obs" id="cal-text" spellcheck="false" placeholder="' + esc(Cal.TEMPLATE) + '" aria-label="Observations"></textarea>' +
      '<div class="row" style="margin-top:10px"><button class="btn primary" data-act="cal-import">' + icon('plus') + 'Add observations</button><button class="btn" data-act="cal-example">Load example</button>' +
      '<label class="btn" style="cursor:pointer">' + icon('upload') + 'From file<input type="file" accept=".csv,.tsv,.txt,.json,text/csv,application/json" data-act="cal-file" class="sr"></label></div></section>';
    var rows = fit.fits.map(function (x) {
      var e = Core.env.byId[x.from], t = Core.env.byId[x.to], pr = x.prior, po = x.post;
      var dm = po.minutes - pr.minutes;
      return '<tr><td><b>' + esc((e ? e.label : x.from) + ' → ' + (t ? t.label : x.to)) + '</b><small class="mut" style="display:block">' + esc(x.tid + ' ' + (x.tname || '')) + (x.shared ? ' · shared technique evidence' : '') + '</small></td>' +
        '<td>' + x.n + ' timing' + (x.n === 1 ? '' : 's') + (x.tries ? '<small class="mut" style="display:block">' + x.wins + ' of ' + x.tries + ' worked</small>' : '') + '</td>' +
        '<td>' + num(pr.minutes) + ' <span class="arrow">→</span> <b>' + num(po.minutes) + '</b> min' + (x.obsMedian ? '<small class="mut" style="display:block">observed median ' + num(x.obsMedian) + '</small>' : '') + '</td>' +
        '<td>' + Math.round(pr.p * 100) + '% <span class="arrow">→</span> <b>' + Math.round(po.p * 100) + '%</b></td>' +
        '<td>' + pr.sigma.toFixed(2) + ' <span class="arrow">→</span> <b>' + po.sigma.toFixed(2) + '</b></td>' +
        '<td>' + root.Unc.confBadge(po.conf) + (CONF_ORDER[po.conf] > CONF_ORDER[pr.conf] ? ' <small class="mut">↑</small>' : '') + '</td></tr>';
    }).join('');
    var un = fit.unmatched.length ? '<p class="mut" style="font-size:12px;margin:10px 0 0">' + fit.unmatched.length + ' observation' + (fit.unmatched.length === 1 ? '' : 's') + ' matched no step here (' + fit.unmatched.slice(0, 3).map(function (r) { return esc(r.edge || (r.from && r.to ? r.from + '>' + r.to : r.tid)); }).join(', ') + (fit.unmatched.length > 3 ? ', …' : '') + '). Check the technique or node ids.</p>' : '';
    var preview = '<section class="card"><div class="chead"><div><h2>What your observations say</h2><small class="mut">Prior → fitted. A few observations nudge a value; many take it over.</small></div>' +
      '<div class="row" style="margin-left:auto"><button class="btn primary sm" data-act="cal-apply"' + (fit.fits.length ? '' : ' disabled') + '>Apply to environment</button><button class="btn sm" data-act="cal-revert"' + (cov.calibrated ? '' : ' disabled') + '>Restore priors</button><button class="btn sm danger" data-act="cal-clear"' + (obs ? '' : ' disabled') + '>Clear observations</button></div></div>' +
      (rows ? '<div class="tablewrap"><table class="t cp"><thead><tr><th>Step</th><th>Evidence</th><th>Minutes</th><th>First-time success</th><th>Spread σ</th><th>Confidence</th></tr></thead><tbody>' + rows + '</tbody></table></div>' + un :
        '<div class="empty">' + (obs ? 'None of the stored observations matches a step in this environment.' : 'No observations yet. Paste some above, or load the example to see how it works.') + '</div>') +
      '<p class="mut" style="font-size:12px;margin:12px 0 0">Method: timings are fitted as lognormal, then pulled toward the prior by ' + Cal.K_TIME + ' pseudo-observations (success by ' + Cal.K_PROB + '), so one data point cannot swing the model. Spread never drops below ' + Cal.SIGMA_FLOOR + '. 3 timings earn "some data", 8 earn "calibrated". Applying restarts the current scenario.</p></section>';
    return kpis + add + preview;
  }

  function importText(text, label) {
    var r = Core.calImport(text, label);
    if (!r.rows.length) { UI.toast(r.errors[0] || 'Nothing to import.', 'err', 6000); return; }
    UI.toast('Added ' + r.rows.length + ' observation' + (r.rows.length === 1 ? '' : 's') + (r.errors.length ? ', skipped ' + r.errors.length + ': ' + r.errors[0] : '') + '.', r.errors.length ? 'info' : 'ok', 6000);
  }

  Views.assets = {
    title: 'Assets', tabs: ['Assets', 'Paths', 'Controls', 'Scenarios', 'Calibration'],
    render: function (tab) {
      var env = Core.env, raw = Core.raw;
      var head = '<div class="grid g4">' + [['Assets', env.nodes.length, 'assets'], ['Attack paths', env.edges.length, 'dashboard'], ['Controls', env.controls.length, 'shield'], ['Scenarios', env.scenarios.length, 'incidents']].map(function (k) {
        return '<section class="card kpi"><div class="lbl">' + k[0] + '</div><div class="val">' + k[1] + '</div></section>'; }).join('') + '</div>';
      var bar = '<section class="card"><div class="row"><div><b>' + esc(raw.name || 'Custom environment') + '</b> ' + (Core.customEnv ? '<span class="chip acc">custom</span>' : '<span class="chip mut">sample</span>') + '<small class="mut" style="display:block">Edits restart the current scenario. The engine runs entirely in your browser.</small></div>' +
        '<div class="row" style="margin-left:auto"><button class="btn sm" data-act="as-json">' + icon('copy') + 'Edit JSON</button><label class="btn sm" style="cursor:pointer">' + icon('upload') + 'Import<input type="file" accept=".json,application/json" data-act="as-file" class="sr"></label><button class="btn sm" data-act="as-export">' + icon('download') + 'Export</button><button class="btn sm danger" data-act="as-reset">Reset to sample</button></div></div></section>';
      var body = '';
      if (tab === 'Paths') {
        body = '<section class="card"><div class="chead"><h2>Attack paths</h2><small>attacker moves, mapped to ATT&amp;CK</small><button class="btn sm primary" data-act="as-add-edge">' + icon('plus') + 'Add path</button></div><div class="tablewrap"><table class="t"><thead><tr><th></th><th>Move</th><th>Technique</th><th>Minutes</th><th>Success</th><th>Evidence</th><th>Controls</th><th></th></tr></thead><tbody>' +
          env.edges.map(function (e, i) {
            return '<tr><td></td><td><b>' + esc(env.byId[e.from].label) + ' → ' + esc(env.byId[e.to].label) + '</b></td><td class="mono">' + esc(e.tid) + '<small class="mut" style="display:block;font-family:inherit">' + esc(e.tname) + '</small></td>' +
              '<td><input class="input num" type="number" min="0.1" step="0.5" data-act="as-edge" data-i="' + i + '" data-f="minutes" value="' + e.minutes + '" aria-label="Minutes"></td>' +
              '<td><input class="input num" type="number" min="0.02" max="1" step="0.05" data-act="as-edge" data-i="' + i + '" data-f="p" value="' + e.p + '" aria-label="Success probability"></td>' +
              '<td>' + root.Unc.confBadge(e.conf, e.source === 'calibrated' ? 'Fitted from ' + e.n + ' observations' : e.source === 'user' ? 'Set by hand' : undefined) + '<small class="mut" style="display:block">' + (e.source === 'calibrated' ? e.n + ' obs' : e.source === 'user' ? 'by hand' : 'prior') + ' · σ ' + G.edgeSigma(e).toFixed(2) + '</small></td>' +
              '<td>' + e.controls.map(function (c) { return '<span class="cc">' + esc(c) + '</span>'; }).join(' ') + '</td><td><div class="row" style="flex-wrap:nowrap"><button class="btn sm ghost" data-act="why" data-id="' + esc(e.id) + '">Why?</button><button class="btn sm ghost" data-act="as-del-edge" data-i="' + i + '" aria-label="Delete path">' + icon('trash') + '</button></div></td></tr>'; }).join('') + '</tbody></table></div></section>';
      } else if (tab === 'Calibration') {
        body = calTab();
      } else if (tab === 'Controls') {
        body = '<section class="card"><div class="chead"><h2>Security controls</h2><small>default state for new scenarios</small></div><div class="tablewrap"><table class="t"><thead><tr><th></th><th>Control</th><th>Mitigates</th><th>Enabled by default</th></tr></thead><tbody>' +
          env.controls.map(function (c, i) { var n = env.edges.filter(function (e) { return e.controls.indexOf(c.id) >= 0; }).length;
            return '<tr><td></td><td><b>' + esc(c.label) + '</b><small class="mut" style="display:block">' + esc(c.desc || '') + '</small></td><td>' + n + ' paths</td><td><label class="switch" style="margin:0"><input type="checkbox" data-act="as-control" data-i="' + i + '"' + (Core.st.controls[c.id] ? ' checked' : '') + ' aria-label="Enable ' + esc(c.label) + '"><i></i></label></td></tr>'; }).join('') + '</tbody></table></div>' +
          '<p class="mut" style="font-size:12px;margin:8px 0 0">Each active control multiplies attacker time by 2.2 and success odds by 0.5 on the paths it is listed against. Add controls in the JSON editor.</p></section>';
      } else if (tab === 'Scenarios') {
        body = '<section class="card"><div class="chead"><h2>Scenarios</h2><small>starting points for a response</small><button class="btn sm primary" data-act="as-add-scn">' + icon('plus') + 'Add scenario</button></div><div class="tablewrap"><table class="t"><thead><tr><th></th><th>Scenario</th><th>Foothold</th><th>Minutes already undetected</th><th></th></tr></thead><tbody>' +
          env.scenarios.map(function (s, i) { return '<tr><td></td><td><b>' + esc(s.name) + '</b><small class="mut" style="display:block">' + esc(s.summary || '') + '</small></td><td>' + s.compromised.map(function (id) { return esc(env.byId[id] ? env.byId[id].label : id); }).join(', ') + '</td>' +
            '<td><input class="input num" type="number" min="0" step="1" data-act="as-scn" data-i="' + i + '" value="' + (s.dwell || 0) + '" aria-label="Dwell minutes"></td><td><button class="btn sm ghost" data-act="as-del-scn" data-i="' + i + '" aria-label="Delete scenario"' + (env.scenarios.length < 2 ? ' disabled' : '') + '>' + icon('trash') + '</button></td></tr>'; }).join('') + '</tbody></table></div></section>';
      } else {
        body = '<section class="card"><div class="chead"><h2>Assets</h2><small>mark crown jewels, set business impact (1–10)</small><button class="btn sm primary" data-act="as-add-node">' + icon('plus') + 'Add asset</button></div><div class="tablewrap"><table class="t"><thead><tr><th></th><th>Asset</th><th>Type</th><th>Zone</th><th>Business impact</th><th>Crown jewel</th><th></th></tr></thead><tbody>' +
          env.nodes.map(function (n, i) { return '<tr><td></td><td><b>' + esc(n.label) + '</b><small class="mut mono" style="display:block">' + esc(n.id) + '</small></td><td>' + esc(n.type) + '</td><td>' + esc(n.zone || '-') + '</td>' +
            '<td><input class="input num" type="number" min="0" max="10" step="1" data-act="as-node" data-i="' + i + '" data-f="businessImpact" value="' + n.businessImpact + '" aria-label="Business impact"></td>' +
            '<td><input type="checkbox" data-act="as-node" data-i="' + i + '" data-f="crown"' + (n.crown ? ' checked' : '') + ' aria-label="Crown jewel"></td><td><button class="btn sm ghost" data-act="as-del-node" data-i="' + i + '" aria-label="Delete asset">' + icon('trash') + '</button></td></tr>'; }).join('') + '</tbody></table></div></section>';
      }
      return head + bar + body;
    },
    act: function (name, el) {
      var i = el.getAttribute && parseInt(el.getAttribute('data-i'), 10), f = el.getAttribute && el.getAttribute('data-f');
      switch (name) {
        case 'as-node': { var v = el.type === 'checkbox' ? el.checked : Math.max(0, Math.min(10, parseFloat(el.value) || 0)); commit(function (r) { if (v === false) delete r.nodes[i][f]; else r.nodes[i][f] = v; }); return true; }
        case 'as-edge': { var n = parseFloat(el.value); commit(function (r) { r.edges[i][f] = n; r.edges[i].source = 'user'; }); return true; }
        case 'as-scn': commit(function (r) { r.scenarios[i].dwell = Math.max(0, parseFloat(el.value) || 0); }); return true;
        case 'as-control': { var on = el.checked, id = Core.env.controls[i].id; Core.settings.controls = Object.assign({}, Core.settings.controls); Core.settings.controls[id] = on; Core.sset('settings', Core.settings); commit(function (r) { r.controls[i].enabled = on; }); return true; }
        case 'as-del-node': {
          var nd = Core.env.nodes[i];
          commit(function (r) { r.edges = r.edges.filter(function (e) { return e.from !== nd.id && e.to !== nd.id; }); r.nodes.splice(i, 1);
            r.scenarios.forEach(function (s) { s.compromised = s.compromised.filter(function (c) { return c !== nd.id; }); }); r.scenarios = r.scenarios.filter(function (s) { return s.compromised.length; }); }, 'Removed ' + nd.label + ' and its paths.'); return true;
        }
        case 'as-del-edge': commit(function (r) { r.edges.splice(i, 1); }, 'Path removed.'); return true;
        case 'as-del-scn': commit(function (r) { r.scenarios.splice(i, 1); }, 'Scenario removed.'); return true;
        case 'go-cal': UI.closeModal(); root.App.tab.assets = 'Calibration'; root.App.go('assets'); return true;
        case 'cal-example': { var ta = document.getElementById('cal-text'); if (ta) ta.value = root.IRGPSCal.TEMPLATE; return true; }
        case 'cal-import': { var tx = document.getElementById('cal-text'); importText(tx ? tx.value : '', 'pasted'); return true; }
        case 'cal-file': { var file = el.files && el.files[0]; if (!file) return true; var fr = new FileReader(); fr.onload = function () { importText(String(fr.result), file.name); }; fr.readAsText(file); el.value = ''; return true; }
        case 'cal-apply': Core.calApply(); root.App.render(); return true;
        case 'cal-revert': Core.calRevert(); root.App.render(); return true;
        case 'cal-clear': Core.calClear(); UI.toast('Observations cleared. Calibrated steps keep their fitted values until you restore priors.', 'ok', 5000); return true;
        case 'as-reset': UI.modal({ title: 'Reset environment?', body: '<p>This replaces your edits with the Northwind sample environment. Incidents are kept.</p>', foot: '<button class="btn" data-act="modal-close">Cancel</button><button class="btn danger" data-act="as-reset-yes">Reset</button>' }); return true;
        case 'as-reset-yes': UI.closeModal(); Core.resetEnv(); root.App.render(); return true;
        case 'as-export': UI.textModal('Environment JSON', JSON.stringify(Core.raw, null, 2), 'ir-gps-environment.json'); return true;
        case 'as-json': UI.modal({ title: 'Edit environment JSON', wide: true, body: '<p class="mut" style="margin-top:0">Nodes need id, x, y (0–1000 by 0–640), and at least one crown jewel. Edges need from, to, minutes and p. Missing coordinates are laid out automatically.</p><textarea class="input" id="as-text" spellcheck="false">' + esc(JSON.stringify(Core.raw, null, 2)) + '</textarea>',
          foot: '<span class="msg" id="as-msg"></span><button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" data-act="as-apply">Apply</button>' }); return true;
        case 'as-apply': {
          var parsed; try { parsed = JSON.parse($('as-text').value); } catch (e) { $('as-msg').textContent = 'Not valid JSON: ' + e.message; $('as-msg').style.color = 'var(--red)'; return true; }
          try { G.prepare(parsed); } catch (e2) { $('as-msg').textContent = e2.message; $('as-msg').style.color = 'var(--red)'; return true; }
          Core.loadEnv(parsed, true, false); UI.closeModal(); UI.toast('Environment applied.', 'ok'); root.App.render(); return true;
        }
        case 'as-file': {
          var file = el.files && el.files[0]; if (!file) return true;
          var rd = new FileReader();
          rd.onload = function () { var obj; try { obj = JSON.parse(rd.result); } catch (e) { UI.toast('That file is not valid JSON.', 'err'); return; } if (Core.loadEnv(obj, true, false)) { UI.toast('Imported ' + file.name + '.', 'ok'); root.App.render(); } };
          rd.onerror = function () { UI.toast('Could not read that file.', 'err'); }; rd.readAsText(file); el.value = ''; return true;
        }
        case 'as-add-node': {
          var zones = (Core.env.zones || []).map(function (z) { return { v: z.name, t: z.name }; });
          UI.modal({ title: 'Add asset', body: '<div class="grid g2">' + field('Name', '<input class="input" id="n-label" placeholder="e.g. Payroll Server">') + field('Id (unique, no spaces)', '<input class="input" id="n-id" placeholder="srv-payroll">') + field('Type', sel('n-type', TYPES.map(function (t) { return { v: t, t: t }; }), 'server')) + field('Zone', sel('n-zone', zones, zones[0] && zones[0].v)) +
            field('Business impact (0–10)', '<input class="input" id="n-imp" type="number" min="0" max="10" value="5">') + '<label class="row" style="padding-top:20px"><input type="checkbox" id="n-crown"> Crown jewel</label></div><div class="msg" id="n-msg" style="color:var(--red);margin-top:8px"></div>',
            foot: '<button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" data-act="as-node-save">Add</button>' }); return true;
        }
        case 'as-node-save': {
          var label = $('n-label').value.trim(), id2 = ($('n-id').value.trim() || label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''));
          if (!label) { $('n-msg').textContent = 'Give the asset a name.'; return true; }
          if (Core.env.byId[id2]) { $('n-msg').textContent = 'That id already exists.'; return true; }
          var zn = $('n-zone').value, z = (Core.env.zones || []).find(function (q) { return q.name === zn; }), sameZone = Core.env.nodes.filter(function (q) { return q.zone === zn; });
          var x = z ? Math.round((z.x0 + z.x1) / 2) : 500, y = Math.min(600, sameZone.reduce(function (m, q) { return Math.max(m, q.y); }, 20) + 90);
          var node = { id: id2, label: label, type: $('n-type').value, zone: zn, x: x, y: y, businessImpact: Math.max(0, Math.min(10, parseFloat($('n-imp').value) || 0)) }; if ($('n-crown').checked) node.crown = true;
          UI.closeModal(); root.App.tab.assets = 'Paths'; commit(function (r) { r.nodes.push(node); }, 'Added ' + label + '. Now connect it with a path.'); return true;
        }
        case 'as-add-edge': {
          var nodes = Core.env.nodes.map(function (n) { return { v: n.id, t: n.label }; });
          UI.modal({ title: 'Add attack path', wide: true, body: '<div class="grid g2">' + field('From', sel('e-from', nodes, nodes[0].v)) + field('To', sel('e-to', nodes, nodes[1] ? nodes[1].v : nodes[0].v)) + field('ATT&CK id', '<input class="input" id="e-tid" placeholder="T1021.002">') + field('Technique name', '<input class="input" id="e-tname" placeholder="SMB/Windows Admin Shares">') +
            field('Tactic', sel('e-tactic', TACTICS.map(function (t) { return { v: t, t: t }; }), 'Lateral Movement')) + field('Minutes for the attacker', '<input class="input" id="e-min" type="number" min="0.5" step="0.5" value="10">') + field('Base success probability (0–1)', '<input class="input" id="e-p" type="number" min="0.05" max="1" step="0.05" value="0.5">') + field('How to cut it', '<input class="input" id="e-remedy" placeholder="Block SMB from workstations">') + '</div>' +
            '<div style="margin-top:10px"><small class="mut">Controls that slow it</small><div class="chips" style="margin-top:6px">' + Core.env.controls.map(function (c) { return '<label class="chip mut" style="cursor:pointer"><input type="checkbox" class="e-ctl" value="' + esc(c.id) + '"> ' + esc(c.label) + '</label>'; }).join('') + '</div></div><div class="msg" id="e-msg" style="color:var(--red);margin-top:8px"></div>',
            foot: '<button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" data-act="as-edge-save">Add</button>' }); return true;
        }
        case 'as-edge-save': {
          var from = $('e-from').value, to = $('e-to').value, tid = $('e-tid').value.trim();
          if (from === to) { $('e-msg').textContent = 'From and to must be different assets.'; return true; }
          if (!tid) { $('e-msg').textContent = 'Add an ATT&CK id (for example T1021.002).'; return true; }
          var edge = { from: from, to: to, tid: tid, tname: $('e-tname').value.trim() || tid, tactic: $('e-tactic').value, minutes: parseFloat($('e-min').value), p: parseFloat($('e-p').value), remedy: $('e-remedy').value.trim() || 'Block this path', controls: Array.prototype.map.call(document.querySelectorAll('.e-ctl:checked'), function (c) { return c.value; }), impact: 2 };
          if (!(edge.minutes > 0) || !(edge.p > 0 && edge.p <= 1)) { $('e-msg').textContent = 'Minutes must be above 0 and probability between 0 and 1.'; return true; }
          UI.closeModal(); commit(function (r) { r.edges.push(edge); }, 'Path added.'); return true;
        }
        case 'as-add-scn': {
          var opts = Core.env.nodes.filter(function (n) { return !n.crown; }).map(function (n) { return { v: n.id, t: n.label }; });
          UI.modal({ title: 'Add scenario', body: '<div class="grid g2">' + field('Name', '<input class="input" id="s-name" placeholder="Ransomware on file server">') + field('Initial foothold', sel('s-foot', opts, opts[0] && opts[0].v)) + field('Minutes already undetected', '<input class="input" id="s-dwell" type="number" min="0" value="10">') + field('Alert summary', '<input class="input" id="s-sum" placeholder="What the alert said">') + '</div><div class="msg" id="s-msg" style="color:var(--red);margin-top:8px"></div>',
            foot: '<button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" data-act="as-scn-save">Add</button>' }); return true;
        }
        case 'as-scn-save': {
          var nm = $('s-name').value.trim(); if (!nm) { $('s-msg').textContent = 'Give the scenario a name.'; return true; }
          var scn = { id: 'scn-' + Date.now().toString(36), name: nm, summary: $('s-sum').value.trim() || nm, compromised: [$('s-foot').value], dwell: Math.max(0, parseFloat($('s-dwell').value) || 0) };
          UI.closeModal(); commit(function (r) { r.scenarios.push(scn); }, 'Scenario added. Pick it in the Navigator.'); return true;
        }
      }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
