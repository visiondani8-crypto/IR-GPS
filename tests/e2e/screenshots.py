"""Regenerates docs/screenshots from the real app, so the README images never drift from the UI.

    node scripts/bundle.js          # optional, to use the single-file build
    python3 tests/e2e/screenshots.py file://$PWD/index.html docs/screenshots

Needs: pip install playwright pillow && playwright install chromium
"""
import os, sys
from playwright.sync_api import sync_playwright
from PIL import Image

url = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else 'docs/screenshots'
os.makedirs(out, exist_ok=True)
W, H = 1440, 960
CONTROLS = ('Network segmentation', 'AD tiering', 'Privileged access')


def squeeze(path):
    """Shrink a PNG with an adaptive 256-colour palette. UI screenshots lose nothing visible."""
    im = Image.open(path).convert('RGB')
    im.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(path, optimize=True)


with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_context(viewport={'width': W, 'height': H}, device_scale_factor=1).new_page()
    errs = []
    pg.on('pageerror', lambda e: errs.append(str(e)))

    def shot(name, height=H):
        pg.set_viewport_size({'width': W, 'height': height})
        pg.evaluate("document.querySelectorAll('.toast').forEach(function(t){t.remove()})")
        pg.wait_for_timeout(250)
        pg.screenshot(path=os.path.join(out, name + '.png'))
        pg.set_viewport_size({'width': W, 'height': H})

    def go(route, wait=700):
        pg.goto(url + '#' + route)
        pg.wait_for_timeout(wait)

    go('dashboard'); shot('dashboard', 1280)
    go('navigator'); shot('navigator')

    # What-if: switch three controls on and let the GPS recalculate
    for t in CONTROLS:
        box = pg.locator('label.ctl:has-text("%s") input' % t)
        if not box.is_checked(): box.click(force=True)
    pg.wait_for_timeout(500)
    pg.evaluate("window.scrollTo(0,0);document.querySelectorAll('main,.main,#view').forEach(function(e){e.scrollTop=0})")
    shot('navigator-what-if')
    pg.click('[data-act="reset"]'); pg.wait_for_timeout(400)
    for t in CONTROLS:
        box = pg.locator('label.ctl:has-text("%s") input' % t)
        if box.is_checked(): box.click(force=True)
    pg.click('[data-act="reset"]'); pg.wait_for_timeout(400)

    pg.click('.steps [data-act="why"] >> nth=0'); pg.wait_for_timeout(350); shot('why-this-number'); pg.keyboard.press('Escape')

    go('validation', 900); shot('validation', 1250)

    go('assets', 400); pg.click('.tab:has-text("Calibration")'); pg.wait_for_timeout(300)
    pg.click('[data-act="cal-example"]'); pg.click('[data-act="cal-import"]'); pg.wait_for_timeout(500); shot('calibration')
    pg.click('[data-act="cal-clear"]'); pg.wait_for_timeout(200)

    for route in ('posture', 'hunt', 'playbooks', 'incidents', 'reports'):
        go(route, 600); shot(route)

    go('navigator')
    pg.evaluate("Core.setSetting('theme','light')"); go('navigator'); shot('navigator-light')
    pg.evaluate("Core.setSetting('theme','dark')")

    m = b.new_context(viewport={'width': 390, 'height': 844}, device_scale_factor=2, is_mobile=True).new_page()
    m.goto(url + '#navigator'); m.wait_for_timeout(800)
    m.screenshot(path=os.path.join(out, 'navigator-mobile.png'))
    b.close()

# 1280x640 card for GitHub's social preview (upload it in Settings > Social preview)
hero = Image.open(os.path.join(out, 'navigator.png')).convert('RGB').crop((270, 20, 1430, 600)).resize((1280, 640), Image.LANCZOS)
hero.save(os.path.join(out, 'social-preview.png'))

for f in sorted(os.listdir(out)):
    if f.endswith('.png'): squeeze(os.path.join(out, f))
print('page errors:', errs)
print('wrote', len(os.listdir(out)), 'images to', out)
