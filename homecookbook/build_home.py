# -*- coding: utf-8 -*-
"""HOME COOKBOOK renderer: recipes/*.json -> HTML -> PDF. Deterministic, no network."""
import json, os, glob, html, base64, io, re, sys
import qrcode
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CAND = os.path.join(REPO, 'cookbook', 'candidates')
sys.path.insert(0, os.path.join(REPO, 'cookbook', 'src'))
try:
    from picks import PICKS
except Exception:
    PICKS = {}
E = html.escape

# Country of origin of each dish (flag + name)
ORIGIN = {
 1:('🇮🇳🇸🇦','Indian / Gulf'), 2:('🇮🇳🇸🇦','Indian / Gulf'), 3:('🇵🇸','Palestine'), 4:('🇵🇸','Palestine'), 5:('🇵🇹🇿🇦','Portuguese / South African style'),
 6:('🇸🇦','Saudi Arabia'), 7:('🇸🇦','Saudi Arabia'), 8:('🇸🇦','Saudi Arabia'), 9:('🇸🇦','Saudi Arabia'), 10:('🇮🇳🇦🇪','Indian / Gulf home style'),
 11:('🇦🇪','Gulf home cooking'), 12:('🇦🇪','United Arab Emirates'), 13:('🇦🇪','United Arab Emirates'), 14:('🇱🇧🇸🇾','Levant'), 15:('🇺🇸🇪🇬','American / Egyptian'),
 16:('🇪🇬','Egypt'), 17:('🇪🇬','Egypt'), 18:('🇪🇬','Egypt'), 19:('🇵🇸','Palestine'), 20:('🇮🇹','Italy'), 21:('🇬🇧','International'),
 22:('🇮🇳🇸🇦','Indian / Gulf'), 23:('🇾🇪🇸🇦','Yemen / Saudi Arabia'),
 'B1':('🇪🇬','Egypt'), 'B2':('🇪🇬','Egypt'), 'B3':('🇸🇦','Gulf'), 'B4':('🇱🇧🇯🇴','Levant'), 'B5':('🇪🇬','Egypt'), 'B6':('🇸🇦','Gulf'), 'B7':('🇪🇬','Egypt'),
 'B8':('🇸🇦','Gulf'), 'B9':('🇨🇾🇱🇧','Cyprus / Levant'), 'B10':('🇸🇦','Gulf'), 'B11':('🇱🇧','Levant'), 'B12':('🇪🇬','Egypt'), 'B13':('🇪🇬','Egypt'), 'B14':('🇸🇦','Gulf'), 'B15':('🇸🇦','Gulf'),
 'S1':('🇱🇧','Lebanon'), 'S2':('🇱🇧','Levant'), 'S3':('🇸🇦','Gulf'), 'S4':('🇱🇧','Lebanon'), 'S5':('🇸🇦','Gulf'), 'S6':('🇬🇷','Greece'), 'S7':('🇺🇸','International'), 'S8':('🇨🇾🇱🇧','Cyprus / Levant'), 'S9':('🇸🇦','Gulf'),
}
SITE_FLAG = {'Sayidaty':'🇸🇦', 'Manal':'🇯🇴', 'Shamlola':'🇪🇬', 'Samira':'🇵🇸', 'Fatafeat':'🇦🇪', 'Custom':'🏠'}
def site_flag(site):
    for k, f in SITE_FLAG.items():
        if k.lower() in (site or '').lower(): return f
    return ''
def origin(rid):
    return ORIGIN.get(rid if isinstance(rid, int) else str(rid), ('', ''))

def load():
    rec = []
    for f in sorted(glob.glob(os.path.join(HERE, 'recipes', '*.json'))):
        rec += json.load(open(f, encoding='utf-8'))
    order = {'Breakfast': 0, 'Salad': 1, 'Main Course': 2}
    def key(r):
        i = r['id']; n = int(re.sub(r'\D', '', str(i)) or 0)
        return (order.get(r['category'], 9), n)
    return sorted(rec, key=key)

def qr(u):
    q = qrcode.QRCode(box_size=5, border=1); q.add_data(u); q.make(fit=True)
    b = io.BytesIO(); q.make_image(fill_color='#1e1810', back_color='white').save(b, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(b.getvalue()).decode()

def photos(r):
    rid = r['id']
    key = rid if isinstance(rid, int) else str(rid)
    files = PICKS.get(key, [])
    out = []
    for f in files:
        if f == 'PEXELS':
            continue
        p = os.path.join(CAND, str(rid), f)
        if os.path.exists(p):
            out.append(os.path.relpath(p, HERE))
    return out[:3]

CSS = """
@page{size:A4;margin:14mm 13mm 16mm}
*{box-sizing:border-box}
body{font-family:Inter,'Segoe UI',Arial,'Noto Color Emoji',sans-serif;color:#1e1810;font-size:10.5px;line-height:1.45;margin:0;background:#fff}
.cover{height:265mm;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;background:#fdfaf4;border:1px solid #e6ddd1;page-break-after:always}
.cover h1{font-size:46px;letter-spacing:.06em;margin:0}
.cover .sub{font-size:16px;color:#c8522a;margin-top:10px;letter-spacing:.2em}
.cover .sub2{font-size:13px;color:#6f6257;margin-top:14px}
.cover .meta{margin-top:60px;font-size:11px;color:#6f6257}
.sec{page-break-before:always}
h1.sec-title{font-size:24px;margin:0 0 4px;color:#1e1810}
.rule{height:3px;width:60px;background:#c8522a;margin:6px 0 14px}
.toc li{display:flex;justify-content:space-between;border-bottom:1px dotted #ddd;padding:3px 0;font-size:11px}
.toc a{color:#1e1810;text-decoration:none}
.toc .ar{color:#6f6257;font-size:10px}
.toc h3{margin:12px 0 4px;color:#c8522a;font-size:12px;letter-spacing:.12em;text-transform:uppercase}
/* recipe */
.recipe{page-break-before:always}
.head{display:flex;justify-content:space-between;gap:12px;border-bottom:3px solid #1e1810;padding-bottom:8px}
.head h1{font-size:24px;margin:0}.flag{font-family:'Noto Color Emoji';font-size:22px}
.ar{font-size:15px;color:#6f6257}
.tags{font-size:9.5px;color:#6f6257;margin-top:2px}
.badge{display:inline-block;background:#2f6b4a;color:#fff;font-weight:700;padding:3px 8px;border-radius:4px;font-size:9.5px;white-space:nowrap}
.info span{display:inline-block;margin-right:10px;font-size:10px}.info b{color:#c8522a}
.note{font-size:9.5px;color:#6f6257}
table.spec{border-collapse:collapse;font-size:9.5px;margin-top:4px}table.spec th{text-align:left;background:#f3ebdd;padding:2px 6px;white-space:nowrap}table.spec td{padding:2px 6px;border-bottom:1px solid #eee}
.photos{display:grid;grid-template-columns:2fr 1fr 1fr;gap:4px;margin-top:8px}.photos img{width:100%;height:52mm;object-fit:cover;border-radius:6px}
.photos.n1{grid-template-columns:1fr}.photos.n2{grid-template-columns:2fr 1fr}
.nophoto{margin-top:8px;height:30mm;border:1.5px dashed #d9cfc3;border-radius:6px;display:flex;align-items:center;justify-content:center;color:#9a8c7c;font-size:10px}
h2{font-size:13px;color:#c8522a;border-bottom:2px solid #c8522a;margin:12px 0 6px}
h3{font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;color:#6f6257;margin:8px 0 4px}
.cols{display:grid;grid-template-columns:42% 1fr;gap:10px}
table.ing{width:100%;border-collapse:collapse;font-size:9.5px}table.ing td{padding:2px 4px;border-bottom:1px solid #eee;vertical-align:top}td.q{text-align:right;white-space:nowrap;font-weight:700}
ol.steps li{margin-bottom:5px}ul.prep li{margin-bottom:3px;font-size:9.5px}
.box{border:1.5px solid #e6ddd1;border-radius:8px;padding:6px 10px;margin-top:8px;break-inside:avoid}.tl{background:#fff8ea;border-color:#f0d9a8}
.qr{display:flex;gap:8px;align-items:center;margin:6px 0}.qr img{width:26mm;height:26mm}.warn{color:#b03030;font-weight:700}
.src{font-size:9px;color:#6f6257;margin-top:8px;border-top:1px solid #eee;padding-top:4px}
.gl dt{font-weight:700;margin-top:4px}.gl dd{margin:0 0 2px 12px}
"""

def recipe_html(r):
    rid = r['id']; anchor = f'r-{rid}'
    ms = r.get('meat_spec')
    spec = ''
    if ms:
        label = 'Lamb' if 'lamb' in (ms.get('cut','')+ms.get('note','')).lower() and 'chicken' not in r['name_en'].lower() else 'Chicken'
        if 'beef' in (ms.get('note','')+ms.get('cut','')).lower(): label='Meat'
        rows = [(f'{label} Type', ms.get('type')), (f'{label} Cut', ms.get('cut')), ('Skin', ms.get('skin')), ('Weight', ms.get('weight')), ('Preparation', ms.get('preparation')), ('Cooking Method', ms.get('cooking_method'))]
        spec = '<table class=spec>' + ''.join(f'<tr><th>{E(k)}</th><td>{E(str(v))}</td></tr>' for k, v in rows if v) + '</table>'
        if not ms.get('source_specified', True) and ms.get('note'):
            spec += f'<div class=note style="max-width:70mm">Suggested cut: {E(ms["note"])}</div>'
    ph = photos(r)
    if ph:
        pho = f'<div class="photos n{len(ph)}">' + ''.join(f'<img src="{E(p)}">' for p in ph) + '</div><div class=note>Real photos of this dish. The finished dish should look like this.</div>'
    else:
        pho = '<div class=nophoto>Final dish photograph: to be added</div>'
    comps = ''
    for c in r['components']:
        ing = ''.join(f'<tr><td>{E(i["item"])}{(" <i>(" + E(i["note"]) + ")</i>") if i.get("note") else ""}</td><td class=q>{E(i["qty"])}</td></tr>' for i in c['ingredients'])
        prep = ''.join(f'<li>{E(p)}</li>' for p in c.get('prep', []))
        steps = ''.join(f'<li>{E(s)}</li>' for s in c['steps'])
        comps += f'<h2>{E(c["title"])}</h2><div class=cols><div><h3>Ingredients (2 adults)</h3><table class=ing>{ing}</table>' + (f'<h3>Preparation before cooking</h3><ul class=prep>{prep}</ul>' if prep else '') + f'</div><div><h3>Cooking instructions</h3><ol class=steps>{steps}</ol></div></div>'
    tl = ''.join(f'<li>{E(x)}</li>' for x in (r.get('timeline') or []))
    mist = ''.join(f'<li>{E(x)}</li>' for x in r.get('mistakes', []))
    serv = ' '.join(E(x) for x in r.get('serving', []))
    safe = ''.join(f'<li>{E(x)}</li>' for x in r.get('safety', []))
    v = r.get('video'); vt = r.get('video_tl')
    vid = ''
    if v and v.get('url'):
        vid += f'<div class=qr><img src="{qr(v["url"])}"><div><b>English video</b> ({E(v.get("priority",""))})<br>{E(v.get("title",""))}<br><small>{E(v.get("channel",""))}{(" · " + E(str(v["duration"]))) if v.get("duration") else ""}</small>{"<br><small class=warn>The video uses chili. The household recipe excludes it.</small>" if v.get("spicy_warning") else ""}<br><small><a href="{E(v["url"])}">{E(v["url"])}</a></small></div></div>'
    else:
        vid += '<div class=note><b>English Cooking Video: Not Available</b></div>'
    if vt and vt.get('url'):
        vid += f'<div class=qr><img src="{qr(vt["url"])}"><div><b>Tagalog video</b><br>{E(vt.get("title",""))}<br><small><a href="{E(vt["url"])}">{E(vt["url"])}</a></small></div></div>'
    s = r['source']
    src = f'<div class=src><b>Original Arabic recipe reference:</b> {site_flag(s.get("site",""))} {E(s.get("site",""))} · Chef: {E(s.get("chef",""))} · {E(s.get("title_ar",""))} · <a href="{E(s.get("url",""))}">{E(s.get("url",""))}</a> · Verification: {E(s.get("verification",""))}<br><b>Adapted:</b> {E(s.get("adapted",""))}' + (f'<br><b>Image source:</b> Wikimedia Commons / video stills (see credits)' if ph else '') + '</div>'
    info = r['info']
    return f'''<section class=recipe id="{anchor}">
<div class=head><div><h1><span class=flag>{origin(rid)[0]}</span> {E(r["name_en"])}</h1><div class=ar>{E(r["name_ar"])}</div>
<div class=tags>Origin: <b>{origin(rid)[0]} {E(origin(rid)[1])}</b> · Cuisine: <b>{E(r["cuisine"])}</b> · Category: <b>{E(r["category"])}</b> · Recipe {E(str(rid))}</div>
<div class=info><span><b>Prep</b> {E(info["prep_time"])}</span><span><b>Cook</b> {E(info["cook_time"])}</span><span><b>Total</b> {E(info["total_time"])}</span><span><b>Servings</b> {E(info["servings"])}</span><span><b>Difficulty</b> {E(info["difficulty"])}</span></div>
<div class=note>Equipment: {E(", ".join(info.get("equipment", [])))}</div></div>
<div><span class=badge>SPICE LEVEL: 0/5 - NO CHILI - NON-SPICY</span>{spec}</div></div>
{pho}
<div class=note style="margin-top:6px"><b>Spice note:</b> {E(r.get("spice_note",""))}</div>
{comps}
{("<div class='box tl'><h3>Cooking timeline</h3><ol>" + tl + "</ol></div>") if tl else ""}
<div class=cols><div class=box><h3>Common mistakes</h3><ul>{mist}</ul></div><div class=box><h3>Serving instructions</h3><p>{serv}</p><h3>Food safety and storage</h3><ul>{safe}</ul></div></div>
<div class=box><h3>Watch the cooking video</h3><p class=note>Scan the QR code to watch the cooking instructions.</p>{vid}</div>
{src}
</section>'''

def front_matter(recs):
    def toc_group(cat, title):
        items = [r for r in recs if r['category'] == cat]
        return f'<h3>{title}</h3><ul class=toc>' + ''.join(f'<li><a href="#r-{r["id"]}">{origin(r["id"])[0]} {E(str(r["id"]))}. {E(r["name_en"])}</a><span class=ar>{E(r["name_ar"])}</span></li>' for r in items) + '</ul>'
    toc = toc_group('Breakfast', 'Breakfast Recipes') + toc_group('Salad', 'Salad Recipes') + toc_group('Main Course', 'Main Course Recipes')
    return f'''
<section class=cover><h1>HOME COOKBOOK</h1><div class=sub>GULF • LEVANTINE • EGYPTIAN CUISINE</div><div class=sub2>Daily Cooking Guide for Household Staff</div><div class=meta>All recipes: 2 adults · Spice level 0/5, no chili · English with Arabic dish names<br>Al Maysari household · Abu Dhabi · 2026</div></section>
<section class=sec><h1 class=sec-title>Table of Contents</h1><div class=rule></div>
<ul class=toc><li><a href="#safety">Kitchen Safety &amp; Hygiene</a></li><li><a href="#measure">Measurement Conversion Guide</a></li><li><a href="#basics">Basic Cooking Techniques</a></li></ul>{toc}
<ul class=toc><li><a href="#glossary">Cooking Terminology Glossary</a></li><li><a href="#sources">Recipe Sources &amp; References</a></li></ul></section>
<section class=sec id=safety><h1 class=sec-title>Kitchen Safety &amp; Hygiene</h1><div class=rule></div>
<h2>House rules</h2><ol class=steps>
<li>No spicy food in this house. No chili, chili flakes, cayenne, hot sauce, harissa or spicy spice mixes. Check labels of ready sauces and spice blends; if it says "hot" or "chili", do not use it.</li>
<li>Keep traditional Arabic flavours: cardamom, cinnamon, turmeric, cumin, coriander, saffron, bay leaf, cloves, black lime, sumac. Black or white pepper only in very small amounts.</li>
<li>Breakfast beans are always in red tomato sauce, never sweet baked beans.</li>
<li>Do not add lemon juice to apples or any fruit.</li>
<li>Check expiry dates before using any product.</li>
<li>If products from the supermarket arrive spoiled, damaged or missing, tell the house owner. Do not throw anything away without asking.</li>
<li>Check delivered products against the invoice or the online order.</li>
<li>Keep raw meat and chicken separate from vegetables and ready food, in the fridge and on the counter.</li>
<li>Use a separate clean board and knife for raw chicken and meat; another for vegetables.</li>
<li>Do not wash raw chicken with water; it spreads bacteria. Pat it dry with kitchen paper.</li>
<li>Cook chicken to 74 C inside (no pink at the bone, juices run clear). Lamb is ready when a fork slides in easily.</li>
<li>Never taste raw meat or chicken to check it.</li>
<li>Wash hands with soap before cooking, after touching raw meat, and after the phone. Clean surfaces before and after.</li>
<li>Leftovers: cool within 1 hour, closed container, fridge up to 3 days, label with the day. Reheat until steaming hot all through. Reheat only once.</li></ol></section>
<section class=sec id=measure><h1 class=sec-title>Measurement Conversion Guide</h1><div class=rule></div>
<table class=ing style="width:60%"><tr><td>1 cup</td><td class=q>250 ml</td></tr><tr><td>1/2 cup</td><td class=q>125 ml</td></tr><tr><td>1/3 cup</td><td class=q>80 ml</td></tr><tr><td>1/4 cup</td><td class=q>60 ml</td></tr><tr><td>1 tbsp (tablespoon)</td><td class=q>15 ml</td></tr><tr><td>1 tsp (teaspoon)</td><td class=q>5 ml</td></tr><tr><td>1 cup basmati rice</td><td class=q>200 g</td></tr><tr><td>1 cup flour</td><td class=q>125 g</td></tr><tr><td>1 cup sugar</td><td class=q>200 g</td></tr><tr><td>1 medium onion</td><td class=q>120 g</td></tr><tr><td>1 medium tomato</td><td class=q>120 to 150 g</td></tr><tr><td>1 large egg</td><td class=q>55 to 60 g</td></tr><tr><td>1 kg</td><td class=q>1000 g</td></tr><tr><td>1 L</td><td class=q>1000 ml</td></tr></table>
<h2>Oven</h2><table class=ing style="width:60%"><tr><td>Low</td><td class=q>160 C</td></tr><tr><td>Medium</td><td class=q>180 C</td></tr><tr><td>Hot</td><td class=q>200 C</td></tr><tr><td>Very hot / grill finish</td><td class=q>220 to 230 C</td></tr></table>
<p class=note>Use the measuring cups and spoons in the drawer. Level the spoon with a knife. Do not guess.</p></section>
<section class=sec id=basics><h1 class=sec-title>Basic Cooking Techniques</h1><div class=rule></div>
<dl class=gl>
<dt>Golden onion</dt><dd>Medium heat, 2 tbsp oil, stir often, 6 to 10 minutes. Soft and light gold is right. Dark brown or black is burnt: throw away and start again.</dd>
<dt>Washing and soaking rice</dt><dd>Cover with cold water, swirl, pour off. Repeat 4 to 5 times until the water is almost clear. Soak 20 to 30 minutes, then drain well.</dd>
<dt>Cooking rice (absorption)</dt><dd>Add the measured liquid, boil 2 minutes, cover with a tight lid, lowest heat, no stirring, no opening, for the time in the recipe. Rest 5 minutes off the heat, then fluff with a fork.</dd>
<dt>Browning meat or chicken</dt><dd>Pat dry. Hot pan, do not crowd, do not move the pieces for the first 2 to 3 minutes so they get colour.</dd>
<dt>Simmer</dt><dd>Small bubbles only, not a rolling boil. Lower the heat until you see a gentle bubble every second.</dd>
<dt>Checking chicken is cooked</dt><dd>Thermometer 74 C at the thickest part, or cut next to the bone: no pink, juices clear.</dd>
<dt>Checking lamb is tender</dt><dd>A fork slides in and the meat separates easily. If it is hard, add a little water and cook longer.</dd>
<dt>Grilling in a pan</dt><dd>Heat the dry pan until very hot (a drop of water dances). Oil the food, not the pan. Do not move it until it releases by itself.</dd>
<dt>Boiling eggs</dt><dd>Eggs in boiling water: 6 min soft, 8 min medium, 10 min hard. Then cold water for 2 minutes.</dd>
<dt>Resting</dt><dd>Let meat, chicken and rice rest 5 to 10 minutes before serving so juices settle.</dd></dl></section>
'''

def back_matter(recs):
    gl = [('Baharat / 7-spice','Arabic mixed spice: allspice, black pepper, cinnamon, cloves, coriander, cumin, nutmeg. Not hot.'),('Bzar','Emirati spice mix for salona and stews.'),('Dum','Steaming rice in a sealed pot on the lowest heat so it finishes in its own steam.'),('Ghee','Clarified butter. Use for frying onions and nuts.'),('Loomi','Dried black lime. Pierce it before adding to the pot.'),('Sumac','Sour red powder used in fattoush and musakhan.'),('Ta\'leya','Garlic fried in ghee with coriander, poured over molokhia.'),('Saffron','Red threads soaked in warm water or rose water for colour and aroma.'),('Al dente','Pasta cooked but still slightly firm in the centre.'),('Blanch','Dip in boiling water 1 to 2 minutes then cold water.'),('Sear','Brown quickly on high heat.'),('Fold','Mix gently with a spatula from the bottom up.'),('Daqoos','Gulf tomato sauce served beside rice. This house makes it without chili.'),('Sahawiq','Yemeni tomato and coriander sauce; this house makes it without chili.')]
    glh = '<dl class=gl>' + ''.join(f'<dt>{E(a)}</dt><dd>{E(b)}</dd>' for a,b in gl) + '</dl>'
    rows = ''.join(f'<tr><td>{E(str(r["id"]))}</td><td>{E(r["name_en"])}</td><td>{site_flag(r["source"].get("site",""))} {E(r["source"].get("site",""))}</td><td>{E(r["source"].get("chef",""))}</td><td style="font-size:8px"><a href="{E(r["source"].get("url",""))}">{E(r["source"].get("url",""))}</a></td><td>{E(r["source"].get("verification",""))[:40]}</td></tr>' for r in recs)
    return f'''<section class=sec id=glossary><h1 class=sec-title>Cooking Terminology Glossary</h1><div class=rule></div>{glh}</section>
<section class=sec id=sources><h1 class=sec-title>Recipe Sources &amp; References</h1><div class=rule></div>
<h2>Approved Arabic sources</h2><table class=ing style="width:70%"><tr><td>🇸🇦 Sayidaty Kitchen</td><td>kitchen.sayidaty.net</td></tr><tr><td>🇯🇴 Manal Alalem</td><td>manalonline.com</td></tr><tr><td>🇪🇬 Shamlola</td><td>shamlola.com</td></tr><tr><td>🇵🇸 Chef Samira Basharat</td><td>kitchen.sayidaty.net/recipes/index/chef/4243</td></tr><tr><td>🏠 Custom Recipe</td><td>household recipes as listed in the brief (Peri-Peri, Cajun, Chicken Mix)</td></tr></table>
<p class=note>Every recipe was rewritten in English from an Arabic source page that was opened and read. Quantities were scaled to 2 adults and all chili removed. Photos: Wikimedia Commons (free licences) and stills from the linked videos; see each recipe.</p>
<table class=ing style="font-size:8.5px"><tr><th>No.</th><th>Dish</th><th>Site</th><th>Chef</th><th>URL</th><th>Verification</th></tr>{rows}</table></section>'''

def build(out_html):
    recs = load()
    body = front_matter(recs) + ''.join(recipe_html(r) for r in recs) + back_matter(recs)
    doc = f'<!doctype html><html><head><meta charset=utf-8><title>HOME COOKBOOK</title><style>{CSS}</style></head><body>{body}</body></html>'
    open(out_html, 'w', encoding='utf-8').write(doc)
    return recs

if __name__ == '__main__':
    out = os.path.join(HERE, 'HOME_COOKBOOK.html')
    recs = build(out)
    print('recipes:', len(recs), 'html:', os.path.getsize(out))
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(); pg = b.new_page()
        pg.goto('file://' + out, wait_until='load', timeout=120000); pg.wait_for_timeout(1000)
        pg.pdf(path=os.path.join(HERE, 'HOME_COOKBOOK_COMPLETE.pdf'), format='A4', print_background=True, prefer_css_page_size=True,
               display_header_footer=True, header_template='<div></div>',
               footer_template='<div style="font-family:Arial;font-size:8px;color:#6f6257;width:100%;padding:0 13mm;display:flex;justify-content:space-between"><span>HOME COOKBOOK · Gulf · Levantine · Egyptian</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>')
        b.close()
    print('pdf done')
