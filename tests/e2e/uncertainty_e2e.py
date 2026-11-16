# Browser checks for ETA ranges, calibration, and validation. Run: python3 uncertainty_e2e.py file:///.../index.html
import sys, re
from playwright.sync_api import sync_playwright
url = sys.argv[1]
errs = []; fails = []
def check(name, cond, extra=''):
    print(('PASS ' if cond else 'FAIL ') + name + (' | ' + str(extra) if extra != '' and not cond else ''))
    if not cond: fails.append(name)
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={'width':1440,'height':900})
    pg = ctx.new_page()
    pg.on('console', lambda m: errs.append((m.type, m.text)) if m.type in ('error',) else None)
    pg.on('pageerror', lambda e: errs.append(('pageerror', str(e))))
    pg.goto(url); pg.wait_for_timeout(500)
    T = lambda sel: pg.inner_text(sel).lower()  # CSS uppercases some headings, so compare lowercase
    nums = lambda s: [float(x) for x in re.findall(r'\d+(?:\.\d+)?', s)]

    # ---- dashboard
    check('hero KPI shows a likely range', 'likely'.lower() in T('.kpi.hero'), T('.kpi.hero'))
    check('breach-time histogram renders', pg.locator('.histsvg').count() == 1 and pg.locator('.histsvg .hb').count() >= 20)
    check('three breach-chance tiles on dashboard', pg.locator('#view .rc').count() >= 3)
    check('drivers card lists pace first', pg.locator('.torn-row').count() >= 4 and 'Attacker pace' in pg.locator('.torn-row').first.inner_text())
    check('driver bars have both directions', pg.locator('.torn-row .tr').count() >= 4 and pg.locator('.torn-row .tg').count() >= 4)

    # ---- navigator
    pg.click('a[href="#navigator"]'); pg.wait_for_timeout(400)
    check('navigator range block', pg.locator('#uncBox').count() == 1 and 'Likely range'.lower() in T('#uncBox'))
    check('range bar has band, median and fastest marker', pg.locator('#uncBox .band').count() == 1 and pg.locator('#uncBox .med').count() == 1 and pg.locator('#uncBox .fast').count() == 1)
    eta_min = nums(T('#eta'))[0]
    rng = T('#uncBox .rng-head span')
    lo_hi = nums(rng)
    check('range brackets sensibly (P10 <= P90)', len(lo_hi) >= 2 and lo_hi[0] < lo_hi[1], rng)
    check('subline says first-time success', 'works first time'.lower() in T('#etaSub'), T('#etaSub'))
    check('why buttons on every step', pg.locator('.steps [data-act="why"]').count() >= 2)
    pg.click('.steps [data-act="why"] >> nth=0'); pg.wait_for_timeout(200)
    check('why modal explains the number', pg.locator('table.why').count() == 1 and 'Starting estimate'.lower() in T('.mdl') and 'Spread'.lower() in T('.mdl') and 'Evidence'.lower() in T('.mdl'), T('.mdl')[:200])
    check('why modal says prior for sample data', 'illustrative'.lower() in T('.mdl'))
    pg.keyboard.press('Escape')
    # toggling a control moves the range
    before = T('#uncBox .rng-head span')
    pg.click('label.ctl:has-text("Network segmentation") input') if pg.locator('label.ctl:has-text("Network segmentation")').count() else pg.click('label.ctl input >> nth=2')
    pg.wait_for_timeout(300)
    check('toggling a control changes the range', T('#uncBox .rng-head span') != before, before + ' -> ' + T('#uncBox .rng-head span'))
    pg.click('label.ctl input >> nth=2'); pg.wait_for_timeout(200)
    # the red attacker marker sits on the compromised node: it must not swallow clicks on the node's centre
    pg.evaluate("document.querySelector('g[data-id=\"ws-fin-03\"] circle.body').scrollIntoView({block:'center'})"); pg.wait_for_timeout(150)
    cb = pg.locator('g[data-id="ws-fin-03"] circle.body').bounding_box()
    pg.mouse.click(cb['x'] + cb['width'] / 2, cb['y'] + cb['height'] / 2); pg.wait_for_timeout(150)
    check('clicking the exact centre of a node with the attacker marker on it selects it', 'selected: ws-fin-03' in T('#view'), T('#view')[:120])
    pg.mouse.click(cb['x'] + cb['width'] / 2, cb['y'] + cb['height'] / 2); pg.wait_for_timeout(150)
    check('clicking again deselects', 'selected: ws-fin-03' not in T('#view'))
    # live playback: range block stays while the attacker is moving, and gives way to BREACHED at the end
    pg.click('[data-act="speed"][data-v="1"]'); pg.click('[data-act="toggle"]'); pg.wait_for_timeout(700)
    check('range block survives playback', pg.locator('#uncBox').count() == 1 and 'likely range' in T('#uncBox'))
    pg.click('[data-act="toggle"]'); pg.wait_for_timeout(150)
    pg.click('[data-act="speed"][data-v="16"]'); pg.click('[data-act="toggle"]'); pg.wait_for_timeout(2500)
    check('breach replaces the range with BREACHED', 'breached' in T('#eta') and pg.locator('#uncBox').count() == 0, T('#eta'))
    pg.click('[data-act="reset"]'); pg.wait_for_timeout(300)
    check('reset brings the range back', pg.locator('#uncBox').count() == 1)

    # ---- assets: paths evidence + calibration
    pg.click('a[href="#assets"]'); pg.wait_for_timeout(300)
    pg.click('.tab:has-text("Paths")'); pg.wait_for_timeout(200)
    check('paths table has Evidence column', 'Evidence'.lower() in T('table.t thead') and pg.locator('table.t tbody .cf.low').count() >= 20)
    pg.click('.tab:has-text("Calibration")'); pg.wait_for_timeout(200)
    check('calibration starts uncalibrated', '0of'.lower() in T('.kpi').replace(' ', '').replace('\n', '') or 'all values are priors'.lower() in T('#view'))
    check('apply disabled with no observations', pg.locator('[data-act="cal-apply"]').is_disabled())
    pg.fill('#cal-text', 'technique,minutes,success\nT1021.002,5,true\nT1021.002,6,true\nT1021.002,7,true\nT1021.002,5,true\nbogus,x,y')
    pg.click('[data-act="cal-import"]'); pg.wait_for_timeout(300)
    check('import accepted good rows and reported the bad one', 'Added 4'.lower() in T('#toasts') and 'skipped 1'.lower() in T('#toasts'), T('#toasts'))
    check('fit preview lists the affected step', pg.locator('table.t tbody tr').count() >= 1 and 'T1021.002'.lower() in T('#view'))
    check('preview shows prior to fitted', '→'.lower() in T('table.t tbody tr:first-child'))
    pg.click('[data-act="cal-apply"]'); pg.wait_for_timeout(500)
    check('apply reports success', 'Calibrated'.lower() in T('#toasts'), T('#toasts'))
    check('coverage KPI updates', 'calibrated'.lower() in T('#view') and 'all values are priors'.lower() not in T('#view'))
    pg.click('.tab:has-text("Paths")'); pg.wait_for_timeout(200)
    check('calibrated steps show data confidence', pg.locator('table.t tbody .cf.med, table.t tbody .cf.high').count() >= 1 and 'obs'.lower() in T('table.t tbody'))
    pg.click('a[href="#navigator"]'); pg.wait_for_timeout(300)
    check('navigator still renders after calibration', pg.locator('#uncBox').count() == 1)
    pg.click('a[href="#assets"]'); pg.click('.tab:has-text("Calibration")'); pg.wait_for_timeout(200)
    pg.click('[data-act="cal-revert"]'); pg.wait_for_timeout(400)
    check('restore priors works', pg.locator('[data-act="cal-revert"]').is_disabled())
    pg.click('[data-act="cal-clear"]'); pg.wait_for_timeout(200)
    check('clear observations works', 'No observations yet'.lower() in T('#view'))
    pg.click('[data-act="cal-example"]'); check('example loads into the box', 'T1021.002' in pg.input_value('#cal-text'))

    # ---- why -> calibrate shortcut
    pg.click('a[href="#navigator"]'); pg.wait_for_timeout(300)
    pg.click('.steps [data-act="why"] >> nth=0'); pg.wait_for_timeout(150)
    pg.click('[data-act="go-cal"]'); pg.wait_for_timeout(300)
    check('why modal jumps to Calibration', pg.locator('textarea#cal-text').count() == 1 and pg.locator('.mdl').count() == 0)

    # ---- validation screen
    pg.click('button.grp'); pg.wait_for_timeout(100)
    pg.goto(url + '#validation'); pg.wait_for_timeout(900)
    check('validation screen renders', 'Does the model agree'.lower() in T('#view'))
    check('verdict present', pg.locator('.verdict').count() == 1)
    check('six documented stretches', pg.locator('table.t tbody tr').count() == 6, pg.locator('table.t tbody tr').count())
    check('observed markers drawn', pg.locator('.vtrack .obs').count() >= 6)
    check('anecdote caveat shown', 'anecdote'.lower() in T('.caveats').lower())
    check('wide-band caveat shown', 'wide'.lower() in T('.caveats').lower())
    check('report links open in a new tab safely', pg.locator('table.t a[target="_blank"][rel*="noopener"]').count() >= 6)
    check('dwell chart present', pg.locator('.vtrack .obs').count() >= 16)
    pg.click('.tab:has-text("Evidence")'); pg.wait_for_timeout(200)
    check('evidence tab lists cases, stretches, wait times and benchmarks', all(x.lower() in T('#view') for x in ['Ryuk speed run', 'Quantum ransomware', 'Basis for the hop count', 'Time to hands-on-keyboard', 'Vendor benchmarks']))
    check('evidence rows link to sources', pg.locator('#view a[href^="https://"]').count() >= 23)
    check('benchmarks flagged as context', 'not tests'.lower() in T('#view'))

    # ---- settings
    pg.goto(url + '#prefs'); pg.wait_for_timeout(400)
    check('retries toggle present and on', pg.locator('input[data-k="persistent"]').is_checked())
    pg.click('label.switch:has(input[data-k="persistent"])'); pg.wait_for_timeout(200)
    check('retries toggle turns off', not pg.locator('input[data-k="persistent"]').is_checked())
    pg.select_option('select[data-k="sigmaScale"]', '2'); pg.wait_for_timeout(200)
    pg.goto(url + '#navigator'); pg.wait_for_timeout(400)
    check('single-attempt mode explains lower bound', 'lower bound'.lower() in T('#uncBox'), T('#uncBox')[-200:])
    pg.goto(url + '#validation'); pg.wait_for_timeout(700)
    pg.click('.tab:has-text("Model check")'); pg.wait_for_timeout(200)
    check('validation re-runs with new settings', 'Does the model agree'.lower() in T('#view') and 'single attempts'.lower() in T('#view'))
    pg.goto(url + '#prefs'); pg.wait_for_timeout(300)
    pg.click('label.switch:has(input[data-k="persistent"])'); pg.select_option('select[data-k="sigmaScale"]', '1'); pg.wait_for_timeout(200)

    # ---- reports
    pg.goto(url + '#navigator'); pg.wait_for_timeout(400)
    pg.click('[data-act="report"]'); pg.wait_for_timeout(200)
    txt = pg.input_value('#tm-text')
    check('incident report has uncertainty section', '## How certain is this ETA' in txt and 'Likely range (P10 to P90)' in txt and 'Assumptions that move the ETA most' in txt, txt[:300])
    pg.keyboard.press('Escape')
    pg.click('[data-act="new-incident"]'); pg.wait_for_timeout(300)
    rng = pg.evaluate("(function(){var i=Core.incidents[0];return i&&i.snapshot&&i.snapshot.range?i.snapshot.range:null})()")
    check('opened incident stores the range', bool(rng) and rng['p10'] <= rng['p50'] <= rng['p90'], rng)
    inc_md = pg.evaluate("Views.reports ? Reports.incidentMdFor(Core.incidents[0]) : ''")
    check('stored-incident report carries the range', '## Uncertainty at last update' in inc_md, inc_md[:200])
    csvt = pg.evaluate("Reports.routesCsv()")
    check('routes CSV has per-hop range and evidence columns', 'hop_p10_min' in csvt.split('\n')[0] and 'evidence' in csvt.split('\n')[0] and 'prior' in csvt, csvt[:200])
    es = pg.evaluate("Reports.execSummary()")
    check('exec summary says how sure we are', 'How sure we are' in es, es[:300])
    pg.goto(url + '#reports'); pg.wait_for_timeout(300)

    # ---- command palette finds validation
    pg.keyboard.press('Control+k'); pg.fill('#pal-in', 'valid'); pg.wait_for_timeout(150)
    check('palette finds Validation', 'Validation'.lower() in T('#pal-res'))
    pg.keyboard.press('Escape')

    # ---- responsive: new cards do not overflow
    for w in (390, 768, 1024):
        pg.set_viewport_size({'width': w, 'height': 900})
        for route in ('dashboard', 'navigator', 'validation', 'assets'):
            pg.goto(url + '#' + route); pg.wait_for_timeout(350)
            ov = pg.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
            check('no horizontal overflow at %dpx on %s' % (w, route), ov <= 1, ov)
    b.close()
print('CONSOLE ERRORS', errs)
print('FAILS:', fails)
sys.exit(1 if (fails or errs) else 0)
