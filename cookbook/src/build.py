# -*- coding: utf-8 -*-
import base64, io, html, sys, os, hashlib
import qrcode
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from recipes import MAINS, SALADS, FRUITS

def qr_b64(url):
    q = qrcode.QRCode(box_size=6, border=1, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(url); q.make(fit=True)
    im = q.make_image(fill_color="#1e1810", back_color="white")
    b = io.BytesIO(); im.save(b, format="PNG")
    return "data:image/png;base64," + base64.b64encode(b.getvalue()).decode()

E = html.escape

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Tajawal:wght@500;700;800&display=swap');
:root{--ink:#1e1810;--muted:#6f6257;--line:#e6ddd1;--accent:#c8522a;--green:#2f6b4a;--gold:#b8862a;--paper:#fff;--cream:#faf6ef}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#ebe6de;color:var(--ink);font-family:Inter,'Segoe UI',Arial,sans-serif;font-size:11.5px;line-height:1.45}
.ar{font-family:Tajawal,'Segoe UI',Arial,sans-serif;direction:rtl}
.page{width:210mm;min-height:297mm;background:var(--paper);margin:10mm auto;padding:14mm 14mm 12mm;position:relative;page-break-after:always;break-after:page;box-shadow:0 2px 14px rgba(0,0,0,.08)}
.page:last-child{page-break-after:auto}
@page{size:A4;margin:0}
@media print{html,body{background:#fff}.page{margin:0;box-shadow:none;width:210mm;height:297mm;overflow:hidden}.no-print{display:none}}

/* cover */
.cover{background:var(--ink);color:#fff;display:flex;flex-direction:column;justify-content:space-between;padding:20mm}
.cover .kicker{letter-spacing:.3em;text-transform:uppercase;font-size:11px;color:#e8a87c}
.cover h1{font-size:46px;font-weight:800;line-height:1.05;margin-top:12px}
.cover h1 span{color:#e8a87c}
.cover .sub{font-size:16px;color:#d9cfc3;margin-top:14px;max-width:120mm}
.cover .ar-title{font-size:30px;margin-top:8px;color:#f5e6d0}
.cover .meta{border-top:1px solid #4a3d31;padding-top:10px;font-size:12px;color:#bfae9c;display:flex;justify-content:space-between}
.cover-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin:16px 0}
.cover-grid img{width:100%;height:46mm;object-fit:cover;border-radius:6px;display:block}

/* generic */
h2.section{font-size:26px;font-weight:800;margin-bottom:4px}
.section-sub{color:var(--muted);font-size:13px;margin-bottom:14px}
.rule{height:3px;background:var(--accent);width:60px;margin:8px 0 14px}
.toc{columns:2;column-gap:10mm;font-size:12px}
.toc li{list-style:none;display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px dotted var(--line);break-inside:avoid}
.toc li b{color:var(--accent);min-width:26px;display:inline-block}
.toc li .ar{color:var(--muted);font-size:11px}
.toc .lang{font-size:9px;border-radius:3px;padding:1px 5px;background:#eef3ee;color:var(--green);font-weight:700;margin-left:6px}
.toc .lang.en{background:#eeeff6;color:#3b4a8a}

/* recipe page */
.rhead{display:flex;gap:6mm;align-items:stretch;margin-bottom:6mm}
.rhead .photo{width:78mm;height:52mm;object-fit:cover;border-radius:8px;flex-shrink:0;background:#eee}
.rhead .ph{width:78mm;height:52mm;border-radius:8px;flex-shrink:0;background:linear-gradient(135deg,#f3e9db,#e8d9c4);display:flex;align-items:center;justify-content:center;font-size:54px}
.rhead .title{flex:1;display:flex;flex-direction:column;justify-content:space-between}
.num{font-size:11px;font-weight:700;color:var(--accent);letter-spacing:.2em}
.rhead h1{font-size:24px;line-height:1.1;font-weight:800;margin:4px 0 2px}
.rhead .ar{font-size:18px;color:var(--muted);font-weight:700;text-align:left;direction:rtl;display:inline-block}
.intro{color:#4a3f36;font-size:11.5px;margin-top:6px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.chip{font-size:10px;font-weight:700;border:1px solid var(--line);border-radius:20px;padding:3px 9px;background:var(--cream)}
.chip.acc{border-color:#efcdbd;background:#fdf1ea;color:var(--accent)}

.cols{display:grid;grid-template-columns:86mm 1fr;gap:7mm}
h3{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);margin-bottom:6px;font-weight:800}
table.ing{width:100%;border-collapse:collapse;font-size:10.5px}
table.ing th{text-align:left;font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:4px 5px;border-bottom:2px solid var(--ink)}
table.ing th.q{text-align:center;width:22mm}
table.ing td{padding:4px 5px;border-bottom:1px solid var(--line);vertical-align:top}
table.ing td.q{text-align:center;font-weight:700;white-space:nowrap}
table.ing td.q.p2{background:#fdf6ee}
ol.steps{padding-left:0;list-style:none;counter-reset:s}
ol.steps li{counter-increment:s;position:relative;padding-left:26px;margin-bottom:7px;font-size:11px}
ol.steps li::before{content:counter(s);position:absolute;left:0;top:0;width:19px;height:19px;border-radius:50%;background:var(--ink);color:#fff;font-size:10px;font-weight:800;display:flex;align-items:center;justify-content:center}
.tl{background:#fff8ea;border:1.5px solid #f0d9a8;border-left:5px solid var(--gold);border-radius:8px;padding:8px 10px;margin-top:8px}
.tl b{display:block;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#8a6412;margin-bottom:4px}
.tl li{margin-left:14px;font-size:10.5px;margin-bottom:2px}
.foot{position:absolute;left:14mm;right:14mm;bottom:8mm;display:flex;justify-content:space-between;align-items:flex-end;border-top:1px solid var(--line);padding-top:6px}
.foot .brand{font-size:9px;color:var(--muted);max-width:46mm;line-height:1.3}
.qr{display:flex;align-items:center;gap:8px}
.qr img{width:24mm;height:24mm;display:block}
.qr .t{font-size:9px;line-height:1.3;max-width:50mm}
.qr .t b{display:block;font-size:10px;color:var(--ink)}
.qr .lang{font-size:9px;font-weight:800;color:#fff;background:var(--green);border-radius:3px;padding:1px 6px;display:inline-block;margin-bottom:3px}
.qr .lang.en{background:#3b4a8a}

/* salads: 2 per page */
.salad{display:grid;grid-template-columns:58mm 1fr 26mm;gap:5mm;padding:5mm 0;border-bottom:1.5px solid var(--line);break-inside:avoid}
.salad:last-of-type{border-bottom:none}
.salad img.photo{width:58mm;height:42mm;object-fit:cover;border-radius:8px}
.salad .ph{width:58mm;height:42mm;border-radius:8px;background:linear-gradient(135deg,#e9f1e6,#d6e6d0);display:flex;align-items:center;justify-content:center;font-size:40px}
.salad h2{font-size:17px;font-weight:800}
.salad .ar{font-size:13px;color:var(--muted);direction:rtl;display:inline-block;margin-left:8px}
.salad table.ing{font-size:9.5px;margin-top:4px}
.salad ol.steps li{font-size:10px;margin-bottom:3px}
.salad .tl{padding:5px 8px;margin-top:5px}
.salad .qrs{display:flex;flex-direction:column;align-items:center;gap:3px;font-size:8.5px;text-align:center}
.salad .qrs img{width:24mm;height:24mm}

/* fruits + rules */
.fruit{display:grid;grid-template-columns:44px 1fr;gap:10px;padding:10px 0;border-bottom:1px solid var(--line);align-items:start}
.fruit .n{width:40px;height:40px;border-radius:50%;background:var(--accent);color:#fff;font-weight:800;font-size:16px;display:flex;align-items:center;justify-content:center}
.fruit h4{font-size:14px;font-weight:800}
.fruit .tlname{color:var(--green);font-size:11px;font-weight:700}
.rules{display:grid;grid-template-columns:1fr 1fr;gap:6mm}
.rule-card{border:1.5px solid var(--line);border-radius:10px;padding:10px 12px;break-inside:avoid}
.rule-card h4{font-size:12px;font-weight:800;margin-bottom:6px;display:flex;gap:6px;align-items:center}
.rule-card li{margin-left:14px;font-size:10.5px;margin-bottom:3px}
.rule-card .tlx{color:#8a6412;font-size:10px;margin-top:4px;font-style:italic}
.danger{background:#fdf1ea;border-color:#efcdbd}
"""

def local_name(url):
    return "img/" + hashlib.md5(url.encode()).hexdigest()[:10] + (".png" if ".png" in url else ".jpg")

def img_src(url):
    if os.environ.get("LOCAL_IMG"):
        return local_name(url)
    return url

def photo(url, emoji, cls="photo"):
    if url:
        return f'<img class="{cls}" src="{E(img_src(url))}" alt="">'
    return f'<div class="ph">{emoji}</div>'

def ing_table(rows, small=False):
    out = ['<table class="ing"><thead><tr><th>Ingredient</th><th class="q">1 person</th><th class="q">2 persons</th></tr></thead><tbody>']
    for n,a,b in rows:
        out.append(f'<tr><td>{E(n)}</td><td class="q">{E(a)}</td><td class="q p2">{E(b)}</td></tr>')
    out.append('</tbody></table>')
    return ''.join(out)

def steps_list(steps):
    return '<ol class="steps">' + ''.join(f'<li>{E(s)}</li>' for s in steps) + '</ol>'

def tl_box(items):
    return '<div class="tl"><b>Mahalagang paalala (Tagalog)</b><ul>' + ''.join(f'<li>{E(x)}</li>' for x in items) + '</ul></div>'

def qr_block(url, title, lang, label="Scan to watch the cooking video"):
    cls = 'en' if lang.lower().startswith('en') else ''
    return f'''<div class="qr"><img src="{qr_b64(url)}" alt="QR"><div class="t"><span class="lang {cls}">{E(lang)}</span><b>{E(label)}</b>{E(title)}</div></div>'''

def recipe_page(r, total):
    lang = r["video_lang"]
    chips = f'<span class="chip">⏱ {E(r["time"])}</span><span class="chip">Level: {E(r["difficulty"])}</span>'
    extra = ''
    if r.get('video2'):
        extra = f'<div class="qr" style="margin-left:10px"><img src="{qr_b64(r["video2"])}" alt="QR"><div class="t"><span class="lang">Extra</span><b>Second video</b>{E(r["video2_title"])}</div></div>'
    return f'''
<section class="page">
  <div class="rhead">
    {photo(r["img"], r["emoji"])}
    <div class="title">
      <div>
        <div class="num">RECIPE {r["id"]:02d} / {total}</div>
        <h1>{E(r["name"])}</h1>
        <span class="ar">{E(r["ar"])}</span>
        <p class="intro">{E(r["intro"])}</p>
      </div>
      <div class="chips">{chips}</div>
    </div>
  </div>
  <div class="cols">
    <div>
      <h3>Ingredients</h3>
      {ing_table(r["ingredients"])}
    </div>
    <div>
      <h3>Method</h3>
      {steps_list(r["steps"])}
      {tl_box(r["tl"])}
    </div>
  </div>
  <div class="foot">
    <div class="brand">Al Maysari Family Cookbook · Mohamed &amp; Einas · 2026</div>
    <div style="display:flex">{qr_block(r["video"], r["video_title"], lang)}{extra}</div>
  </div>
</section>'''

def salad_block(s):
    lang = s["video_lang"]
    cls = 'en' if lang.lower().startswith('en') else ''
    return f'''
<div class="salad">
  <div>{photo(s["img"], s["emoji"])}</div>
  <div>
    <h2>{E(s["name"])} <span class="ar">{E(s["ar"])}</span></h2>
    <div class="chips" style="margin:4px 0 4px"><span class="chip">⏱ {E(s["time"])}</span></div>
    {ing_table(s["ingredients"])}
    {steps_list(s["steps"])}
    {tl_box(s["tl"])}
  </div>
  <div class="qrs"><img src="{qr_b64(s["video"])}" alt="QR"><span class="lang {cls}" style="font-size:8.5px;font-weight:800;color:#fff;background:{'#3b4a8a' if cls else '#2f6b4a'};border-radius:3px;padding:1px 6px">{E(lang)}</span><span>{E(s["video_title"])}</span></div>
</div>'''

def build():
    total = len(MAINS)
    cover_imgs = [img_src(MAINS[i]["img"]) for i in (0,5,6,2,22,10)]
    parts = []
    parts.append(f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Al Maysari Family Cookbook</title><style>{CSS}</style></head><body>
<section class="page cover">
  <div>
    <div class="kicker">Family Cookbook · Cooking Guide</div>
    <h1>Al Maysari<br><span>Family Kitchen</span></h1>
    <div class="ar-title ar" style="text-align:left;direction:rtl;display:inline-block">دليل الطبخ لعائلة الميسري</div>
    <p class="sub">{total} main dishes, {len(SALADS)} salads and {len(FRUITS)} fruit preparations. Every recipe has exact quantities for 1 or 2 persons, step-by-step method, Tagalog reminders and a QR code to a cooking video.</p>
  </div>
  <div class="cover-grid">{''.join(f'<img src="{E(u)}" alt="">' for u in cover_imgs)}</div>
  <div class="meta"><span>Prepared for the household helper · English + Tagalog</span><span>Abu Dhabi · October 2026</span></div>
</section>''')

    # Rules page
    parts.append('''
<section class="page">
  <h2 class="section">House Rules of the Kitchen</h2>
  <div class="section-sub">Read this page first. These rules apply to every recipe. · <span class="ar">قواعد المطبخ</span></div>
  <div class="rule">
  </div>
  <div class="rules">
    <div class="rule-card danger"><h4>⚠️ Einas (Madam) – ALWAYS</h4><ul>
      <li>NO spicy food. No chili, no hot sauce, no "medium". Mild only.</li>
      <li>NO regular milk or cream. Use OAT milk or lactose-free milk/cheese only.</li>
      <li>NO beans / legumes (lobia, chickpeas, lentils, foul).</li>
      <li>NO seafood or fish.</li>
      <li>Chicken is her meat. Lamb or beef dishes: cook her a chicken version or a salad with grilled chicken.</li>
      <li>She is pregnant: food must be fully cooked (no pink chicken, no runny eggs), fresh, and clean.</li></ul>
      <div class="tlx">Tagalog: Walang maanghang, walang regular na gatas, walang beans, walang isda. Manok lang. Lutong-luto lahat.</div></div>
    <div class="rule-card"><h4>👨‍💼 Mohamed (Sir)</h4><ul>
      <li>All cuisines. Chicken, lamb and beef.</li>
      <li>Does NOT eat: foul (fava beans), mujaddara, seafood.</li>
      <li>Likes: fresh juice, fresh fruit. No bread with breakfast.</li>
      <li>Spice level: mild to medium. Chili sauce on the side, never mixed in.</li></ul></div>
    <div class="rule-card"><h4>📏 Quantities</h4><ul>
      <li>Every table has two columns: 1 person and 2 persons. Use the column that was requested that day.</li>
      <li>1 cup = 250 ml. 1 tbsp = 15 ml. 1 tsp = 5 ml. Use the measuring cups and spoons in the drawer, not a random glass.</li>
      <li>Rice: always wash 3 times until the water is clear, then soak 20-30 min.</li>
      <li>Dinner portions are half of lunch portions unless told otherwise.</li></ul>
      <div class="tlx">Gamitin ang measuring cup at kutsara. Huwag tantiyahin.</div></div>
    <div class="rule-card"><h4>🔥 Cooking basics</h4><ul>
      <li>Onion "golden": medium heat 8-12 min, stir often. Brown = good. Black = throw away and start again.</li>
      <li>Chicken is cooked when juices run CLEAR and no pink near the bone (74 °C).</li>
      <li>Lamb is ready only when a fork goes in easily. If hard, cook longer with a little water.</li>
      <li>Rice: after adding water, boil 2 min, then cover and LOWEST heat, no stirring, no opening.</li>
      <li>Taste the food before serving. Salt is added in small steps.</li></ul>
      <div class="tlx">Tikman bago ihain. Asin paunti-unti.</div></div>
    <div class="rule-card"><h4>🧼 Hygiene &amp; safety</h4><ul>
      <li>Wash hands before cooking and after touching raw chicken or meat.</li>
      <li>Separate board and knife for raw meat and for vegetables.</li>
      <li>Cool food before closing any lunch box. Sauces in a separate small box.</li>
      <li>Leftovers: into the fridge within 1 hour, in a closed container, labelled with the day.</li></ul></div>
    <div class="rule-card"><h4>📱 Videos (QR codes)</h4><ul>
      <li>Every recipe has a QR code at the bottom. Open the camera on the phone, point at the code, tap the link.</li>
      <li>Green label = Tagalog video. Blue label = English video.</li>
      <li>Watch the video ONCE fully before cooking the dish for the first time. Then follow the written recipe in this book for quantities.</li>
      <li>If something is unclear, ask BEFORE cooking, not after.</li></ul>
      <div class="tlx">Panoorin ang video nang buo bago magluto sa unang beses. Magtanong bago, hindi pagkatapos.</div></div>
  </div>
</section>''')

    # TOC
    toc = '<ul class="toc">'
    for r in MAINS:
        cls = 'en' if r["video_lang"].lower().startswith('en') else ''
        toc += f'<li><span><b>{r["id"]:02d}</b>{E(r["name"])}<span class="lang {cls}">{E(r["video_lang"][:2].upper())}</span></span><span class="ar">{E(r["ar"])}</span></li>'
    toc += '</ul><h3 style="margin-top:14px">Salads</h3><ul class="toc">'
    for s in SALADS:
        cls = 'en' if s["video_lang"].lower().startswith('en') else ''
        toc += f'<li><span><b>{E(s["id"])}</b>{E(s["name"])}<span class="lang {cls}">{E(s["video_lang"][:2].upper())}</span></span><span class="ar">{E(s["ar"])}</span></li>'
    toc += '</ul>'
    parts.append(f'''<section class="page"><h2 class="section">Contents</h2><div class="section-sub">{total} main dishes · {len(SALADS)} salads · {len(FRUITS)} night fruit preparations</div><div class="rule"></div><h3>Main dishes</h3>{toc}
    <h3 style="margin-top:14px">Night fruit preparation</h3><p style="font-size:11px;color:#4a3f36">See the last page: five fruit combinations, three kinds each, prepared the night before.</p></section>''')

    for r in MAINS:
        parts.append(recipe_page(r, total))

    # Salads: 2 per page
    parts.append('<section class="page"><h2 class="section">Salads</h2><div class="section-sub">Fresh, cut right before serving. Dressing always separate for lunch boxes. · <span class="ar">السلطات</span></div><div class="rule"></div>')
    for i, s in enumerate(SALADS):
        if i and i % 2 == 0:
            parts.append('</section><section class="page">')
        parts.append(salad_block(s))
    parts.append('</section>')

    # Fruits page
    fr = ''.join(f'<div class="fruit"><div class="n">{i+1}</div><div><h4>{E(a)}</h4><div class="tlname">{E(b)}</div><div style="font-size:11px;margin-top:3px">{E(c)}</div></div></div>' for i,(a,b,c) in enumerate(FRUITS))
    parts.append(f'''<section class="page"><h2 class="section">Night Fruit Preparation</h2><div class="section-sub">Every night, prepare 3 kinds of fruit for the next day. Rotate the combinations below. · <span class="ar">تحضير الفواكه ليلاً</span></div><div class="rule"></div>
    {fr}
    <div class="tl" style="margin-top:14px"><b>Mahalagang paalala (Tagalog)</b><ul>
      <li>Hugasan lahat ng prutas. Alisin ang buto. Pantay-pantay ang hiwa.</li>
      <li>Mansanas, peras at saging: hiwain sa umaga o lagyan ng lemon para hindi umitim.</li>
      <li>Ilagay sa saradong lalagyan sa ref. Hiwalay na lalagyan bawat tao.</li>
      <li>Pakwan at melon: alisin lahat ng buto.</li></ul></div>
    <div class="foot"><div class="brand">Al Maysari Family Cookbook · Mohamed &amp; Einas · 2026</div><div class="brand">End of book</div></div>
    </section>''')

    parts.append('</body></html>')
    out = '\n'.join(parts)
    with open(os.path.join(HERE,'index.html'), 'w', encoding='utf-8') as f:
        f.write(out)
    print('written', len(out), 'chars')
    urls = sorted({r["img"] for r in MAINS + SALADS if r.get("img")})
    with open(os.path.join(HERE,'images.txt'),'w') as f:
        for u in urls: f.write(local_name(u) + ' ' + u + '\n')

if __name__ == '__main__':
    build()
