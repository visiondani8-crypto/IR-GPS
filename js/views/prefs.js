/* Settings: theme, attacker pace, response lag, jurisdiction, data backup/reset, method and sources. */
(function (root) {
  'use strict';
  var Core = root.Core, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};
  var SOURCES = [
    ['CrowdStrike Global Threat Report (breakout time)', 'https://www.crowdstrike.com/en-us/global-threat-report/'],
    ['Google Mandiant M-Trends (dwell time, hand-off)', 'https://cloud.google.com/security/resources/m-trends'],
    ['IBM Cost of a Data Breach Report', 'https://www.ibm.com/reports/data-breach'],
    ['NIST SP 800-61 Rev. 3, incident response recommendations', 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'],
    ['NIST Cybersecurity Framework 2.0', 'https://www.nist.gov/cyberframework'],
    ['MITRE ATT&CK', 'https://attack.mitre.org/'],
    ['UK ICO: report a personal data breach (72 hours)', 'https://ico.org.uk/for-organisations/report-a-breach/'],
    ['NIS2 Directive, Article 23 (EUR-Lex)', 'https://eur-lex.europa.eu/eli/dir/2022/2555/oj'],
    ['UK Cyber Security and Resilience Bill (proposed)', 'https://www.gov.uk/government/collections/cyber-security-and-resilience-bill']
  ];
  function row(label, hint, ctl) { return '<div class="split" style="padding:12px 0;border-top:1px solid var(--line)"><div><b>' + label + '</b><small class="mut" style="display:block;max-width:520px">' + hint + '</small></div><div>' + ctl + '</div></div>'; }

  Views.prefs = {
    title: 'Settings',
    render: function () {
      var s = Core.settings, REF = Core.REF, prof = REF.speedProfiles.find(function (p) { return p.id === s.speedProfile; });
      var profOpts = REF.speedProfiles.map(function (p) { return '<option value="' + p.id + '"' + (p.id === s.speedProfile ? ' selected' : '') + '>' + esc(p.label) + ' (×' + p.factor + ')</option>'; }).join('');
      var jOpts = [['uk', 'United Kingdom'], ['eu', 'European Union (NIS2 + GDPR)'], ['both', 'UK and EU']].map(function (j) { return '<option value="' + j[0] + '"' + (j[0] === s.jurisdiction ? ' selected' : '') + '>' + j[1] + '</option>'; }).join('');
      return '<div class="grid g2"><section class="card"><div class="chead"><h2>Preferences</h2></div>' +
        row('Dark mode', 'The interface follows this on every screen.', '<label class="switch" style="margin:0"><input type="checkbox" data-act="theme"' + (s.theme !== 'light' ? ' checked' : '') + ' aria-label="Dark mode"><i></i></label>') +
        row('Attacker pace', esc(prof ? prof.note : ''), '<select class="select" data-act="pref" data-k="speedProfile">' + profOpts + '</select>') +
        row('Attacker retries failed steps', 'On: a failed step is retried, which is the cautious assumption. Off: a failed step ends that route, so breach chances become lower bounds.', '<label class="switch" style="margin:0"><input type="checkbox" data-act="pref-bool" data-k="persistent"' + (s.persistent !== false ? ' checked' : '') + ' aria-label="Attacker retries failed steps"><i></i></label>') +
        row('Uncertainty width', 'Scales how widely hop times vary in the ETA range. The Validation screen suggests a value from public cases.', '<select class="select" data-act="pref-num" data-k="sigmaScale">' + [0.5, 0.75, 1, 1.5, 2, 2.5, 3].map(function (w) { return '<option value="' + w + '"' + (Math.abs((s.sigmaScale || 1) - w) < 0.05 ? ' selected' : '') + '>×' + w + (w === 1 ? ' (default)' : '') + '</option>'; }).join('') + '</select>') +
        row('Response lag (minutes)', 'Time from the alert to your first containment action. Used by the Dashboard projection.', '<input class="input num" type="number" min="0" max="60" step="1" data-act="pref" data-k="lag" data-num="1" value="' + s.lag + '">') +
        row('Jurisdiction', 'Which regulatory clocks the Incidents and Reports screens show.', '<select class="select" data-act="pref" data-k="jurisdiction">' + jOpts + '</select>') +
        row('Your name', 'Default owner for new incidents.', '<input class="input" style="width:160px" data-act="pref" data-k="owner" value="' + esc(s.owner) + '">') + '</section>' +
        '<section class="card"><div class="chead"><h2>Your data</h2></div><p style="margin-top:0">' + (Core.persistent ? 'Settings, incidents and your edited environment are saved in this browser only. Nothing is sent anywhere.' : 'This browser blocks local storage here, so changes live in memory and disappear on reload. Export a backup to keep them.') + '</p>' +
        '<div class="row"><button class="btn" data-act="bk-export">' + icon('download') + 'Export backup</button><button class="btn" data-act="bk-import">' + icon('upload') + 'Restore backup</button></div><div class="hr"></div>' +
        '<div class="split"><div><b>Reset everything</b><small class="mut" style="display:block">Clears settings, incidents, checklist progress and environment edits.</small></div><button class="btn danger" data-act="reset-all">' + icon('trash') + 'Reset</button></div></section></div>' +
        '<section class="card"><div class="chead"><h2>How the model works</h2></div><div class="grid g2"><div><p style="margin-top:0">The environment is a directed graph. Each edge is an attacker move with a technique, a time in minutes and a success probability. The engine turns that into a cost (minutes plus a penalty for unlikely moves) and finds the cheapest route from every compromised asset to every crown jewel. The sum of the minutes on that route is the fastest-path ETA, assuming every step works first time.</p>' +
        '<p>The likely range comes from simulating the attack thousands of times: each hop\'s duration varies (lognormal, widest for uncalibrated steps), one shared pace factor makes the whole attacker faster or slower, and failed steps are retried or end the route, depending on the setting above. Typical time is usually later than the fastest path because steps fail and retry.</p>' +
        '<p>Active controls multiply attacker time by 2.2 and success odds by 0.5 on the edges they mitigate. Containment advice is found by simulating every isolation and path block, then scoring the delay gained and crown jewels saved against the business impact of the action.</p></div>' +
        '<div><p style="margin-top:0"><b>Be honest about the limits.</b> The sample timings are illustrative defaults, not measurements of your network, and the ranges are only as good as those inputs. Until you calibrate (Assets, then Calibration) every step is a prior. The Validation screen compares the model with a handful of public intrusions: with so few cases that is a plausibility check, not proof. The regulatory clocks assume a notifiable personal-data breach, and whether yours is notifiable is a legal call.</p><h3>Sources</h3><ul style="margin:0;padding-left:18px">' +
        SOURCES.map(function (x) { return '<li><a href="' + esc(x[1]) + '" target="_blank" rel="noopener">' + esc(x[0]) + '</a></li>'; }).join('') + '</ul></div></div></section>';
    },
    act: function (name, el) {
      switch (name) {
        case 'pref': { var k = el.getAttribute('data-k'), v = el.getAttribute('data-num') ? Math.max(0, Math.min(60, parseFloat(el.value) || 0)) : el.value; Core.setSetting(k, v); UI.toast('Saved.', 'ok', 1500); return true; }
        case 'pref-bool': Core.setSetting(el.getAttribute('data-k'), !!el.checked); UI.toast('Saved.', 'ok', 1500); return true;
        case 'pref-num': Core.setSetting(el.getAttribute('data-k'), parseFloat(el.value) || 1); UI.toast('Saved.', 'ok', 1500); return true;
        case 'bk-export': UI.textModal('Backup (JSON)', JSON.stringify({ app: 'ir-gps', v: 2, settings: Core.settings, incidents: Core.incidents, env: Core.customEnv ? Core.raw : null, pbChecks: Core.pbChecks, observations: Core.obs }, null, 2), 'ir-gps-backup.json'); return true;
        case 'bk-import': UI.modal({ title: 'Restore backup', wide: true, body: '<p class="mut" style="margin-top:0">Paste the JSON from a previous export. This replaces your current settings, incidents and environment.</p><textarea class="input" id="bk-text" spellcheck="false"></textarea>', foot: '<span class="msg" id="bk-msg"></span><button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" data-act="bk-apply">Restore</button>' }); return true;
        case 'bk-apply': {
          var o; try { o = JSON.parse(document.getElementById('bk-text').value); } catch (e) { document.getElementById('bk-msg').textContent = 'Not valid JSON.'; return true; }
          if (!o || o.app !== 'ir-gps') { document.getElementById('bk-msg').textContent = 'That is not an IR-GPS backup.'; return true; }
          if (o.settings) { Core.settings = Object.assign({}, Core.settings, o.settings); Core.sset('settings', Core.settings); Core.applyTheme(); }
          if (Array.isArray(o.incidents)) { Core.incidents = o.incidents; Core.sset('incidents', Core.incidents); }
          if (o.pbChecks) { Core.pbChecks = o.pbChecks; Core.sset('pbChecks', Core.pbChecks); }
          if (Array.isArray(o.observations)) { Core.obs = o.observations; Core.sset('obs', Core.obs); }
          Core.uncCache = Core.drvCache = Core.valCache = null;
          if (o.env) Core.loadEnv(o.env, true, false); else Core.resetEnv();
          UI.closeModal(); UI.toast('Backup restored.', 'ok'); root.App.render(); return true;
        }
        case 'reset-all': UI.modal({ title: 'Reset everything?', body: '<p>This clears all saved settings, incidents, checklist progress and environment edits in this browser. It cannot be undone.</p>', foot: '<button class="btn" data-act="modal-close">Cancel</button><button class="btn danger" data-act="reset-yes">Reset everything</button>' }); return true;
        case 'reset-yes': UI.closeModal(); Core.resetAllData(); UI.toast('Everything was reset.', 'ok'); root.App.render(); return true;
      }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
