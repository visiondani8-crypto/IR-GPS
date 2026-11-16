/* Playbooks: NIST SP 800-61r3 / CSF 2.0 aligned response checklists. Progress is stored per incident. */
(function (root) {
  'use strict';
  var Core = root.Core, UI = root.UI, esc = UI.esc, icon = UI.icon;
  var Views = root.Views = root.Views || {};

  function cur() {
    var pbs = Core.REF.playbooks, v = Views.playbooks;
    if (!v.sel) v.sel = Core.REF.scenarioPlaybook[Core.env.scenarios[Core.scnIdx].id] || pbs[0].id;
    return pbs.find(function (p) { return p.id === v.sel; }) || pbs[0];
  }
  function md(pb, incId) {
    var L = ['# ' + pb.name, '', pb.summary, ''], phase = '';
    pb.steps.forEach(function (s) {
      if (s.phase !== phase) { phase = s.phase; L.push('', '## ' + phase); }
      L.push('- [' + (Core.isChecked(incId, s.id) ? 'x' : ' ') + '] ' + s.text + ' (' + s.role + ', ' + s.code + ')');
    });
    return L.join('\n') + '\n';
  }

  Views.playbooks = {
    title: 'Playbooks', sel: null, inc: null,
    render: function () {
      var pb = cur(), incId = this.inc && Core.getIncident(this.inc) ? this.inc : null, prog = Core.playbookProgress(pb, incId);
      var incOpts = '<option value="">Practice run (no incident)</option>' + Core.incidents.map(function (i) { return '<option value="' + esc(i.id) + '"' + (i.id === incId ? ' selected' : '') + '>' + esc(i.id + ' ' + i.title) + '</option>'; }).join('');
      var list = Core.REF.playbooks.map(function (p) {
        var pr = Core.playbookProgress(p, incId);
        return '<button class="listbtn' + (p.id === pb.id ? ' on' : '') + '" data-act="pb-select" data-id="' + esc(p.id) + '"><b>' + esc(p.name) + '</b><small class="mut">' + esc(p.summary) + '</small><div class="track" style="margin-top:6px"><div class="fill" style="width:' + pr.pct + '%"></div></div><small class="mut">' + pr.done + ' of ' + pr.total + ' steps</small></button>';
      }).join('');
      var phase = '', body = '';
      pb.steps.forEach(function (s) {
        if (s.phase !== phase) { phase = s.phase; body += '<div class="phase">' + esc(phase) + '</div>'; }
        var done = Core.isChecked(incId, s.id);
        body += '<label class="pstep' + (done ? ' done' : '') + '"><input type="checkbox" data-act="pb-check" data-s="' + esc(s.id) + '"' + (done ? ' checked' : '') + '><span class="pt">' + esc(s.text) + '</span><span class="chips"><span class="chip acc">' + esc(s.code) + '</span><span class="chip mut">' + esc(s.role) + '</span></span></label>';
      });
      return '<div class="grid g-split"><section class="card"><div class="chead"><h2>Playbooks</h2></div><div class="stack" style="gap:8px">' + list + '</div>' +
        '<p class="mut" style="font-size:12px;margin:12px 0 0">Steps are tagged with NIST CSF 2.0 Respond and Recover categories, the structure SP 800-61 Rev. 3 now uses. Adapt roles and tools to your organisation.</p></section>' +
        '<section class="card"><div class="chead"><div><h2>' + esc(pb.name) + '</h2><small class="mut">' + prog.done + ' of ' + prog.total + ' steps done</small></div>' +
        '<select class="select" data-act="pb-inc" aria-label="Apply to incident" style="margin-left:auto;max-width:260px">' + incOpts + '</select>' +
        '<button class="btn sm" data-act="pb-copy">' + icon('copy') + 'Copy</button><button class="btn sm" data-act="pb-reset">Reset</button></div>' +
        '<div class="track" style="margin-bottom:6px"><div class="fill green" style="width:' + prog.pct + '%"></div></div>' + body + '</section></div>';
    },
    act: function (name, el) {
      var pb = cur(), incId = this.inc && Core.getIncident(this.inc) ? this.inc : null;
      switch (name) {
        case 'pb-select': this.sel = el.getAttribute('data-id'); root.App.render(); return true;
        case 'pb-inc': this.inc = el.value || null; root.App.render(); return true;
        case 'pb-check': Core.toggleCheck(incId, el.getAttribute('data-s')); root.App.render(); return true;
        case 'pb-copy': UI.copy(md(pb, incId)).then(function () { UI.toast('Checklist copied as Markdown.', 'ok'); }, function () { UI.textModal(pb.name, md(pb, incId), 'playbook.md'); }); return true;
        case 'pb-reset': pb.steps.forEach(function (s) { if (Core.isChecked(incId, s.id)) Core.toggleCheck(incId, s.id); }); root.App.render(); return true;
      }
      return false;
    }
  };
})(typeof self !== 'undefined' ? self : this);
