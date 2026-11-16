import sys
from playwright.sync_api import sync_playwright
url=sys.argv[1]
with sync_playwright() as p:
    b=p.chromium.launch()
    for w,h in [(1440,900),(1024,800),(390,844)]:
        pg=b.new_page(viewport={'width':w,'height':h}); pg.goto(url); pg.wait_for_timeout(300)
        for v in ['dashboard','navigator','incidents','playbooks','hunt','posture','assets','reports','prefs']:
            pg.evaluate(f"location.hash='{v}'"); pg.wait_for_timeout(150)
            over=pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            if over>0: 
                culprit=pg.evaluate("""()=>{const W=document.documentElement.clientWidth;const out=[];document.querySelectorAll('#view *, #top *, #side *').forEach(e=>{const r=e.getBoundingClientRect();if(r.right>W+2&&r.width>0)out.push(e.tagName+'.'+(e.className&&e.className.baseVal===undefined?e.className:'')+' '+Math.round(r.right))});return out.slice(0,4)}""")
                print(w,v,'OVERFLOW',over,culprit)
        if w==390:
            pg.evaluate("location.hash='dashboard'"); pg.wait_for_timeout(200); pg.screenshot(path='m_dash.png')
            pg.evaluate("location.hash='navigator'"); pg.wait_for_timeout(200); pg.screenshot(path='m_nav.png')
        if w==1440:
            for v in ['dashboard','navigator','prefs','assets']:
                pg.evaluate(f"location.hash='{v}'"); pg.wait_for_timeout(250); pg.screenshot(path=f'd_{v}.png')
        pg.close()
    b.close()
print('done')
