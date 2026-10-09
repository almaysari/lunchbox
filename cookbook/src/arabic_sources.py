# -*- coding: utf-8 -*-
"""Runs inside GitHub Actions (open internet).
For each recipe, search the preferred Arabic site via its own site search or Bing,
fetch candidate recipe pages, extract title / ingredients / steps / main image / video, and save
cookbook/sources/<id>.json + raw html. The parent session then reads the JSON to write recipes.
"""
import json, os, re, sys, time, urllib.parse, html as htmlmod
import requests
from bs4 import BeautifulSoup

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'sources')
os.makedirs(OUT, exist_ok=True)
S = requests.Session()
S.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
                  'Accept-Language': 'ar,en;q=0.8'})

# id -> (english name, arabic search terms list, preferred site key)
SITES = {
 'sayidaty': 'kitchen.sayidaty.net',
 'manal': 'manalonline.com',
 'shamlola': 'shamlola.com',
 'basharat': 'kitchen.sayidaty.net',
}
RECIPES = [
 # breakfast
 ('B1','Pasolla',['فاصوليا بيضاء معلبة بالصلصة','فاصوليا بالصلصة للفطور','فاصوليا حمراء معلبة بالطماطم'],'shamlola'),
 ('B2','Fried Egg',['بيض مقلي','بيض عيون'],'shamlola'),
 ('B3','Boiled Egg',['بيض مسلوق','طريقة سلق البيض'],'shamlola'),
 ('B4','Chicken Liver',['كبدة دجاج','كبدة الدجاج بالبصل'],'manal'),
 ('B5','Chickpeas',['حمص بالطحينة','حمص مسلوق بالكمون','بليلة حمص'],'manal'),
 ('B6','Sandwich Pizza',['بيتزا التوست','ساندويتش بيتزا','بيتزا الخبز'],'sayidaty'),
 ('B7','Potato',['بطاطا حارة','بطاطا حرة','بطاطس حارة شامية'],'shamlola'),
 ('B8','Feta Cheese Sandwich',['ساندويتش جبنة بيضاء','ساندويتش جبنة فيتا'],'sayidaty'),
 ('B9','Fried Halloumi',['حلوم مقلي','جبنة حلوم مقلية'],'sayidaty'),
 ('B10','Sunny-Side-Up Egg',['بيض عيون','بيض مقلي عيون'],'shamlola'),
 ('B11','Halloumi Sandwich',['ساندويتش حلوم','ساندويتش جبنة حلوم مشوية'],'sayidaty'),
 ('B12','Egg Omelette',['عجة البيض','أومليت','اومليت بيض'],'shamlola'),
 ('B13','Shakshuka Egg',['شكشوكة','بيض بالطماطم'],'shamlola'),
 ('B14','Chicken Mix',['سلطة دجاج بالمايونيز','ساندويتش دجاج بالمايونيز'],'sayidaty'),
 ('B15','Boiled Egg with Chicken Mix',['سلطة دجاج بالمايونيز','بيض مسلوق بالدجاج'],'sayidaty'),
 # salads
 ('S1','Fattoush Salad',['فتوش','سلطة فتوش'],'sayidaty'),
 ('S2','Walnut Salad',['سلطة الجوز','سلطة بالجوز والتفاح'],'sayidaty'),
 ('S3','Corn Salad',['سلطة الذرة'],'sayidaty'),
 ('S4','Borgol Salad',['سلطة برغل','تبولة'],'manal'),
 ('S5','Green Mix Salad',['سلطة خضراء','سلطة خضراء مشكلة'],'sayidaty'),
 ('S6','Greek Salad',['سلطة يونانية'],'sayidaty'),
 ('S7','Caesar Salad',['سلطة سيزر','سلطة سيزر بالدجاج'],'sayidaty'),
 ('S8','Halloumi Salad',['سلطة حلوم','سلطة الحلوم المشوي'],'sayidaty'),
 ('S9','Jer-Jer Salad',['سلطة جرجير','سلطة الجرجير'],'manal'),
 # mains
 ('M1','Chicken Biryani',['برياني دجاج','برياني الدجاج'],'manal'),
 ('M2','Lamb Biryani',['برياني لحم','برياني اللحم'],'manal'),
 ('M3','Chicken Maqluba',['مقلوبة دجاج','مقلوبة الدجاج'],'manal'),
 ('M4','Lamb Maqluba',['مقلوبة لحم','مقلوبة اللحم بالباذنجان'],'manal'),
 ('M5','Yellow Rice with Peri-Peri Chicken',['أرز أصفر','رز أصفر بالكركم'],'sayidaty'),
 ('M6','Lamb Kabsa',['كبسة لحم','كبسة اللحم السعودية'],'sayidaty'),
 ('M7','Chicken Kabsa',['كبسة دجاج','كبسة الدجاج السعودية'],'sayidaty'),
 ('M8','Chicken Bukhari',['رز بخاري بالدجاج','بخاري دجاج'],'sayidaty'),
 ('M9','Lamb Bukhari',['رز بخاري باللحم','بخاري لحم'],'sayidaty'),
 ('M10','Chicken Curry with Boiled Egg',['كاري دجاج','دجاج بالكاري'],'manal'),
 ('M11','Chicken with Vegetables in Oven',['دجاج بالخضار بالفرن','صينية دجاج بالخضار'],'manal'),
 ('M12','Chicken Salona',['صالونة دجاج','صالونة الدجاج'],'sayidaty'),
 ('M13','Lamb Salona',['صالونة لحم','صالونة اللحم'],'sayidaty'),
 ('M14','Mashi Malfouf',['محشي ملفوف','ملفوف محشي'],'manal'),
 ('M15','Cajun Chicken with Lobia and White Rice',['لوبيا بالصلصة','فاصوليا لوبيا بالطماطم','أرز أبيض'],'sayidaty'),
 ('M16','Grilled Chicken with Molokhia and White Rice',['ملوخية بالدجاج','ملوخية مصرية'],'shamlola'),
 ('M17','Okra with Lamb and White Rice',['بامية باللحم','بامية باللحمة'],'shamlola'),
 ('M18','Fried Chicken with Okra and White Rice',['بامية بالدجاج','دجاج مقلي'],'shamlola'),
 ('M19','Musakhan Chicken with White Rice in Oven',['مسخن دجاج','مسخن فلسطيني'],'basharat'),
 ('M20','Spaghetti with Meatballs',['سباغيتي بكرات اللحم','مكرونة بكرات اللحم'],'sayidaty'),
 ('M21','Mashed Potato with Grilled Chicken',['بطاطس مهروسة','دجاج مشوي بالفرن'],'sayidaty'),
 ('M22','Chicken Spinach with White Rice',['سبانخ بالدجاج','سبانخ مطبوخة بالدجاج'],'shamlola'),
 ('M23','Mahdbi Chicken with Rice',['مظبي دجاج','دجاج مظبي'],'sayidaty'),
]

def bing(q, site, n=8):
    url = 'https://www.bing.com/search?' + urllib.parse.urlencode({'q': f'{q} site:{site}', 'setlang': 'ar'})
    try:
        r = S.get(url, timeout=40)
        soup = BeautifulSoup(r.text, 'html.parser')
        links = []
        for a in soup.select('li.b_algo h2 a'):
            h = a.get('href', '')
            if site in h and h not in links:
                links.append(h)
        return links[:n]
    except Exception as e:
        print('  bing fail', q, e); return []

def ddg(q, site, n=8):
    url = 'https://html.duckduckgo.com/html/?' + urllib.parse.urlencode({'q': f'{q} site:{site}'})
    try:
        r = S.get(url, timeout=40)
        soup = BeautifulSoup(r.text, 'html.parser')
        links = []
        for a in soup.select('a.result__a'):
            h = a.get('href', '')
            m = re.search(r'uddg=([^&]+)', h)
            if m: h = urllib.parse.unquote(m.group(1))
            if site in h and h not in links:
                links.append(h)
        return links[:n]
    except Exception as e:
        print('  ddg fail', q, e); return []

def site_search(q, site):
    links = []
    try:
        if site == 'kitchen.sayidaty.net':
            r = S.get('https://kitchen.sayidaty.net/recipes/search?' + urllib.parse.urlencode({'q': q}), timeout=40)
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.select('a[href*="/recipes/"]'):
                h = a.get('href', '')
                if not h.startswith('http'): h = 'https://kitchen.sayidaty.net' + h
                if re.search(r'/recipes/\d+', h) and h not in links: links.append(h)
        elif site == 'manalonline.com':
            r = S.get('https://www.manalonline.com/?' + urllib.parse.urlencode({'s': q}), timeout=40)
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.select('a[href*="manalonline.com/recipes/"]'):
                h = a.get('href', '')
                if h not in links: links.append(h)
        elif site == 'shamlola.com':
            r = S.get('https://www.shamlola.com/search?' + urllib.parse.urlencode({'q': q}), timeout=40)
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.select('a[href*="/recipes/"]'):
                h = a.get('href', '')
                if not h.startswith('http'): h = 'https://www.shamlola.com' + h
                if h not in links: links.append(h)
    except Exception as e:
        print('  site search fail', site, q, e)
    return links[:8]

def extract(url):
    r = S.get(url, timeout=60); r.raise_for_status()
    soup = BeautifulSoup(r.text, 'html.parser')
    data = {'url': url, 'status': r.status_code}
    # JSON-LD recipe
    for sc in soup.find_all('script', type='application/ld+json'):
        try:
            j = json.loads(sc.string or '')
        except Exception:
            continue
        objs = j if isinstance(j, list) else [j]
        for o in objs:
            if isinstance(o, dict) and '@graph' in o: objs.extend(o['@graph'])
        for o in objs:
            if isinstance(o, dict) and (o.get('@type') == 'Recipe' or 'Recipe' in str(o.get('@type'))):
                data['jsonld'] = {k: o.get(k) for k in ('name','author','image','recipeIngredient','recipeInstructions','recipeYield','prepTime','cookTime','totalTime','video','description')}
                break
    data['title'] = (soup.title.string if soup.title else '').strip()
    og = soup.find('meta', property='og:image')
    data['og_image'] = og.get('content') if og else None
    # heuristic text blocks
    txt = soup.get_text('\n')
    txt = re.sub(r'\n{3,}', '\n\n', txt)
    data['text_excerpt'] = txt[:6000]
    # video
    vids = []
    for f in soup.find_all('iframe'):
        s = f.get('src', '')
        if 'youtube' in s or 'youtu.be' in s: vids.append(s)
    for a in soup.find_all('a', href=True):
        if 'youtube.com/watch' in a['href'] or 'youtu.be/' in a['href']: vids.append(a['href'])
    data['videos'] = list(dict.fromkeys(vids))[:5]
    return data

def main():
    only = os.environ.get('ONLY')
    for rid, name, terms, pref in RECIPES:
        if only and rid not in only.split(','): continue
        outp = os.path.join(OUT, f'{rid}.json')
        if os.path.exists(outp) and not os.environ.get('FORCE'):
            continue
        site = SITES[pref]
        found = []
        seen = set()
        for t in terms:
            for fn in (site_search, bing, ddg):
                for u in fn(t, site):
                    if u in seen: continue
                    seen.add(u)
                    if pref == 'basharat' and '/chef/4243' not in u:
                        pass
                    found.append(u)
                    if len(found) >= 6: break
                if len(found) >= 6: break
                time.sleep(1.0)
            if len(found) >= 6: break
        results = []
        for u in found[:6]:
            try:
                results.append(extract(u)); print(rid, 'ok', u)
            except Exception as e:
                print(rid, 'fail', u, e)
            time.sleep(1.5)
        json.dump({'id': rid, 'name': name, 'preferred': pref, 'terms': terms, 'results': results},
                  open(outp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(rid, name, len(results), 'pages')

if __name__ == '__main__':
    main()
