# -*- coding: utf-8 -*-
"""Runs inside GitHub Actions (full internet). Downloads candidate photos per dish:
- Wikimedia Commons search results (real photos of the dish)
- YouTube thumbnails of the recipe videos (shows the result of the video the helper will watch)
Writes cookbook/candidates/<id>/NN.jpg and cookbook/candidates/index.json
"""
import json, os, re, sys, urllib.parse, urllib.request, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from recipes import MAINS, SALADS

OUT = os.path.join(HERE, '..', 'candidates')
UA = {'User-Agent': 'AlMaysariCookbook/1.0 (family cookbook; contact: github almaysari)'}

# Commons search terms per recipe id (several queries, results merged)
TERMS = {
 1: ['Chicken biryani', 'Biryani'], 2: ['Mutton biryani', 'Lamb biryani', 'Biryani'],
 3: ['Maqluba', 'Maqlooba', 'Makloubeh'], 4: ['Maqluba', 'Makloubeh'],
 5: ['Peri-peri chicken', 'Piri piri chicken', 'Yellow rice chicken'],
 6: ['Kabsa', 'Kabsa lamb', 'Machboos'], 7: ['Kabsa chicken', 'Kabsa', 'Machboos chicken'],
 8: ['Bukhari rice', 'Ruz Bukhari', 'Kabuli pulao chicken'], 9: ['Bukhari rice', 'Ruz Bukhari', 'Kabuli palaw'],
 10: ['Chicken curry egg', 'Egg curry', 'Chicken curry'], 11: ['Roast chicken vegetables', 'Roasted chicken tray'],
 12: ['Saloona', 'Salona', 'Chicken stew tomato'], 13: ['Saloona', 'Lamb stew Arabic', 'Marag'],
 14: ['Malfouf mahshi', 'Stuffed cabbage rolls', 'Mahshi'], 15: ['Lubia', 'Black-eyed pea stew', 'Cajun chicken'],
 16: ['Mulukhiyah', 'Molokhia', 'Molokhia chicken'], 17: ['Bamia', 'Okra stew', 'Bamia lamb'],
 18: ['Bamia', 'Okra stew chicken', 'Fried chicken plate'], 19: ['Musakhan'],
 20: ['Spaghetti meatballs'], 21: ['Mashed potatoes chicken', 'Grilled chicken breast plate'],
 22: ['Palak chicken', 'Saag chicken', 'Chicken spinach'], 23: ['Mandi', 'Madhbi', 'Chicken mandi'],
 'S1': ['Fattoush'], 'S2': ['Walnut salad', 'Apple walnut salad'], 'S3': ['Corn salad'],
 'S4': ['Tabbouleh'], 'S5': ['Green salad', 'Garden salad'], 'S6': ['Greek salad', 'Horiatiki'],
 'S7': ['Caesar salad chicken', 'Caesar salad'], 'S8': ['Halloumi salad'], 'S9': ['Arugula salad', 'Rocket salad', 'Jarjeer'],
}

def commons_search(term, limit=10):
    q = urllib.parse.urlencode({
        'action': 'query', 'format': 'json', 'generator': 'search',
        'gsrsearch': f'{term} filetype:bitmap', 'gsrnamespace': 6, 'gsrlimit': limit,
        'prop': 'imageinfo', 'iiprop': 'url|size|mime|extmetadata', 'iiurlwidth': 900,
    })
    url = 'https://commons.wikimedia.org/w/api.php?' + q
    data = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.load(r)
            break
        except Exception as e:
            print('  retry', attempt, term, e); time.sleep(3 * (attempt + 1))
    if data is None:
        return []
    out = []
    for p in (data.get('query', {}).get('pages', {}) or {}).values():
        ii = (p.get('imageinfo') or [{}])[0]
        if not ii or ii.get('mime') not in ('image/jpeg', 'image/png'):
            continue
        if ii.get('width', 0) < 500 or ii.get('height', 0) < 350:
            continue
        meta = ii.get('extmetadata', {})
        out.append({
            'title': p.get('title'), 'thumb': ii.get('thumburl') or ii.get('url'),
            'page': ii.get('descriptionurl'), 'w': ii.get('width'), 'h': ii.get('height'),
            'license': (meta.get('LicenseShortName') or {}).get('value', ''),
            'author': re.sub('<[^>]+>', '', (meta.get('Artist') or {}).get('value', ''))[:80],
        })
    return out

def yt_id(url):
    m = re.search(r'v=([A-Za-z0-9_-]{11})', url or '')
    return m.group(1) if m else None

def fetch(url, path):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=60) as r, open(path, 'wb') as f:
            f.write(r.read())
        return os.path.getsize(path) > 3000
    except Exception as e:
        print('  fail', url, e)
        return False

def main():
    os.makedirs(OUT, exist_ok=True)
    index = {}
    old = {}
    try:
        old = json.load(open(os.path.join(OUT, 'index.json'), encoding='utf-8'))
    except Exception:
        pass
    for r in MAINS + SALADS:
        rid = r['id']
        if os.environ.get('ONLY_MISSING') and len(old.get(str(rid), {}).get('cands', [])) >= 4:
            index[str(rid)] = old[str(rid)]; continue
        d = os.path.join(OUT, str(rid)); os.makedirs(d, exist_ok=True)
        cands = []
        # 1) video thumbnails
        for key in ('video', 'video2'):
            vid = yt_id(r.get(key))
            if not vid: continue
            for name in ('maxresdefault', 'sddefault', 'hqdefault'):
                u = f'https://img.youtube.com/vi/{vid}/{name}.jpg'
                p = os.path.join(d, f'yt_{key}.jpg')
                if fetch(u, p):
                    cands.append({'file': f'yt_{key}.jpg', 'src': 'youtube', 'page': r.get(key), 'title': r.get(key+'_title', r.get('video_title'))})
                    break
        # 2) Commons
        seen = set(); n = 0
        for term in TERMS.get(rid, [r['name']]):
            try:
                res = commons_search(term)
            except Exception as e:
                print('  search fail', term, e); res = []
            for it in res:
                if it['title'] in seen or n >= 14: continue
                seen.add(it['title'])
                p = os.path.join(d, f'c{n:02d}.jpg')
                if fetch(it['thumb'], p):
                    cands.append({'file': f'c{n:02d}.jpg', 'src': 'commons', **it})
                    n += 1
            time.sleep(2.5)
        index[str(rid)] = {'name': r['name'], 'cands': cands}
        print(rid, r['name'], len(cands), 'candidates')
    with open(os.path.join(OUT, 'index.json'), 'w', encoding='utf-8') as f:
        json.dump(index, f, ensure_ascii=False, indent=1)

if __name__ == '__main__':
    main()
