/* Incidents: case register with regulatory clocks, playbook link, notes and a snapshot of the Navigator state. */
(function (root) {
  'use strict';
  var Core = root.Core, G = root.IRGPS, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};
  var STATUSES = ['Triage', 'Active', 'Contained', 'Eradicated', 'Recovered', 'Closed', 'Breached'];

  function clocksHtml(inc) {
    var t0 = new Date(inc.awareAt).getTime(), now = Date.now();
    return Core.clocksFor().map(function (c) {
      var due = t0 + c.hours * 3600000, left = due - now, done = inc.clockDone && inc.clockDone[c.id];
      var cls = done ? 'green' : left < 0 ? 'red' : left < 6 * 3600000 ? 'amber' : 'mut';
      return '<div class="clk"><input type="checkbox" data-act="clk-done" data-id="' + esc(inc.id) + '" data-c="' + esc(c.id) + '"' + (done ? ' checked' : '') + ' aria-label="Mark ' + esc(c.label) + ' done">' +
        '<div><b>' + esc(c.label) + '</b>' + (c.proposed ? ' <span class="chip amber">proposed</span>' : '') + '<small class="mut" style="display:block">' + esc(c.ref) + ' · due ' + UI.fmtDateTime(new Date(due).toISOString()) + '</small><small class="mut" style="display:block">' + esc(c.note) + '</small></div>' +
        '<span class="chip ' + cls + ' cd" style="font-size:13px">' + (done ? 'Done' : left < 0 ? 'Overdue ' + UI.fmtCountdown(-left) : UI.fmtCountdown(left)) + '</span></div>';
    }).join('');
  }

  Views.incidents = {
    title: 'Incidents', sel: null, filters: true,
    render: function () {
      var list = Core.filteredIncidents(), all = Core.incidents, inc = Core.getIncident(this.sel) || list[0] || all[0] || null;
      if (inc) this.sel = inc.id;
      var rows = list.map(function (i) {
        return '<button class="listbtn' + (inc && i.id === inc.id ? ' on' : '') + '" data-act="inc-select" data-id="' + esc(i.id) + '"><div class="row" style="justify-content:space-between;flex-wrap:nowrap"><b>' + esc(i.title) + '</b><span class="sev ' + esc(i.severity) + '">' + esc(i.severity) + '</span></div>' +
          '<div class="row" style="justify-content:space-between;flex-wrap:nowrap"><small class="mut">' + esc(i.id) + ' · ' + UI.fmtDate(i.createdAt) + (i.sample ? ' · sample' : '') + '</small>' + UI.status(i.status) + '</div></button>';
      }).join('') || '<div class="empty">No incidents match the filters.</div>';
      var left = '<section class="card"><div class="chead"><h2>Register</h2><small>' + list.length + ' of ' + all.length + '</small><button class="btn sm primary" data-act="inc-new">' + icon('plus') + 'From Navigator</button></div><div class="stack" style="gap:8px">' + rows + '</div></section>';
      if (!inc) return '<div class="grid g-split">' + left + '<section class="card"><div class="empty">No incident selected. Open one from the Navigator to track it here.</div></section></div>';
      var s = inc.snapshot || {}, pb = Core.REF.playbooks.find(function (p) { return p.id === inc.playbookId; }) || Core.REF.playbooks[0], prog = Core.playbookProgress(pb, inc.id);
      var pbOpts = Core.REF.playbooks.map(function (p) { return '<option value="' + esc(p.id) + '"' + (p.id === inc.playbookId ? ' selected' : '') + '>' + esc(p.name) + '</option>'; }).join('');
      var stOpts = STATUSES.map(function (x) { return '<option' + (x === inc.status ? ' selected' : '') + '>' + x + '</option>'; }).join('');
      var sevOpts = ['SEV1', 'SEV2', 'SEV3', 'SEV4'].map(function (x) { return '<option' + (x === inc.severity ? ' selected' : '') + '>' + x + '</option>'; }).join('');
      var kv = function (k, v) { return '<dt>' + k + '</dt><dd>' + v + '</dd>'; };
      var detail = '<div class="stack"><section class="card"><div class="chead"><h2>' + esc(inc.id) + '</h2>' + (inc.id === Core.linkedId ? '<span class="chip acc">linked to Navigator</span>' : '') + '<span class="mut" style="margin-left:auto">' + (Core.persistent ? '' : 'not saved across reloads') + '</span></div>' +
        '<div class="grid g2"><label><small class="mut">Title</small><input class="input" data-act="inc-field" data-f="title" data-id="' + esc(inc.id) + '" value="' + esc(inc.title) + '"></label>' +
        '<label><small class="mut">Owner</small><input class="input" data-act="inc-field" data-f="owner" data-id="' + esc(inc.id) + '" value="' + esc(inc.owner) + '"></label>' +
        '<label><small class="mut">Status</small><select class="select input" data-act="inc-field" data-f="status" data-id="' + esc(inc.id) + '">' + stOpts + '</select></label>' +
        '<label><small class="mut">Severity</small><select class="select input" data-act="inc-field" data-f="severity" data-id="' + esc(inc.id) + '">' + sevOpts + '</select></label>' +
        '<label><small class="mut">Aware of the incident at (starts the clocks)</small><input class="input" type="datetime-local" data-act="inc-aware" data-id="' + esc(inc.id) + '" value="' + UI.toLocalInput(inc.awareAt) + '"></label>' +
        '<label><small class="mut">Playbook</small><select class="select input" data-act="inc-field" data-f="playbookId" data-id="' + esc(inc.id) + '">' + pbOpts + '</select></label></div>' +
        '<div class="hr"></div><div class="row"><button class="btn" data-act="inc-rerun" data-id="' + esc(inc.id) + '">' + icon('rerun') + 'Re-run in Navigator</button><button class="btn" data-act="inc-download" data-id="' + esc(inc.id) + '">' + icon('download') + 'Report</button>' +
        '<button class="btn" data-act="go" data-to="playbooks" data-inc="' + esc(inc.id) + '">' + icon('playbooks') + 'Playbook ' + prog.pct + '%</button><button class="btn danger" data-act="inc-delete" data-id="' + esc(inc.id) + '" style="margin-left:auto">' + icon('trash') + 'Delete</button></div></section>' +
        '<section class="card"><div class="chead"><h2>Regulatory clocks</h2><small>' + (Core.settings.jurisdiction === 'both' ? 'UK and EU' : Core.settings.jurisdiction.toUpperCase()) + ' · change in Settings</small></div><div id="clocks">' + clocksHtml(inc) + '</div>' +
        '<p class="mut" style="font-size:12px;margin:8px 0 0">Deadlines assume this is a notifiable personal-data breach. Whether it is notifiable is a legal judgement for you or counsel. Proposed duties are not yet law.</p></section>' +
        '<section class="card"><div class="chead"><h2>Snapshot</h2><small>last synced from the Navigator</small></div><dl class="kv">' +
        kv('Scenario', esc(s.scenario || '-')) + kv('ETA at that point', s.eta != null ? G.fmt(s.eta) : '-') + kv('Simulation', esc(s.simStatus || '-') + (s.simT ? ' at ' + G.fmt(s.simT) : '')) +
        kv('Crown jewels in reach', s.reachable != null ? s.reachable + ' of ' + s.total : '-') + kv('Exposure', s.exposure != null ? s.exposure + '/100' : '-') +
        kv('Compromised', esc((s.compromised || []).join(', ') || '-')) + kv('Isolated', esc((s.isolated || []).join(', ') || '-')) + kv('Blocked paths', esc((s.blocked || []).join('; ') || '-')) + '</dl></section>' +
        '<section class="card"><div class="chead"><h2>Notes</h2></div><textarea class="input" rows="6" data-act="inc-field" data-f="notes" data-id="' + esc(inc.id) + '" placeholder="Decisions, who was told what and when, open questions…" style="font-family:inherit;font-size:13px">' + esc(inc.notes || '') + '</textarea></section></div>';
      return '<div class="grid g-split">' + left + detail + '</div>';
    },
    pulse: function () { var el = document.getElementById('clocks'), inc = Core.getIncident(this.sel); if (el && inc) el.innerHTML = clocksHtml(inc); },
    act: function (name, el) {
      var id = el.getAttribute && el.getAttribute('data-id');
      switch (name) {
        case 'inc-select': this.sel = id; root.App.render(); return true;
        case 'inc-new': { var i = Core.createIncident(); this.sel = i.id; UI.toast('Opened ' + i.id + ' from the current Navigator state.', 'ok'); Core.emit('state'); return true; }
        case 'inc-field': Core.updateIncident(id, (function (o) { o[el.getAttribute('data-f')] = el.value; return o; })({})); if (el.getAttribute('data-f') !== 'notes') root.App.render(); return true;
        case 'inc-aware': { var d = new Date(el.value); if (!isNaN(d)) { Core.updateIncident(id, { awareAt: d.toISOString() }); root.App.render(); } return true; }
        case 'clk-done': { var inc = Core.getIncident(id), done = Object.assign({}, inc.clockDone); if (el.checked) done[el.getAttribute('data-c')] = Date.now(); else delete done[el.getAttribute('data-c')]; Core.updateIncident(id, { clockDone: done }); this.pulse(); return true; }
        case 'inc-rerun': if (Core.rerun(id)) root.App.go('navigator'); return true;
        case 'inc-download': root.Reports.downloadIncident(Core.getIncident(id)); return true;
        case 'inc-delete': {
          var rec = Core.getIncident(id);
          UI.modal({ title: 'Delete ' + id + '?', body: '<p>' + esc(rec.title) + ' will be removed from the register. This cannot be undone.</p>', foot: '<button class="btn" data-act="modal-close">Cancel</button><button class="btn danger" data-act="inc-delete-yes" data-id="' + esc(id) + '">Delete</button>' });
          return true;
        }
        case 'inc-delete-yes': Core.deleteIncident(id); this.sel = null; UI.closeModal(); UI.toast('Incident deleted.'); return true;
      }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
