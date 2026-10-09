# Download the final-dish photo from each recipe's Arabic source page (og:image / JSON-LD image),
# trying larger variants for Sayidaty, plus inline step photos for step-by-step pages.
# Saves to ../images/src/<id>.jpg and ../images/src/<id>_step<N>.jpg, with ../images/src/index.json
import os, sys, json, re, time, requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from book import ALL
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'images', 'src'); os.makedirs(OUT, exist_ok=True)
S = requests.Session()
S.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36', 'Referer': 'https://kitchen.sayidaty.net/'})
index = {}

def variants(u):
    vs = [u]
    if 'sayidaty' in u:
        vs = [re.sub(r'_w\d+_h\d+', '', u), u.replace('/small/', '/large/'), u.replace('/small/', '/'), u]
    if 'manalonline' in u:
        vs = [u.replace('/crops/g16x9/', '/'), u]
    return list(dict.fromkeys(vs))

def get_img(u):
    for v in variants(u):
        try:
            r = S.get(v, timeout=60)
            if r.status_code == 200 and r.headers.get('content-type', '').startswith('image') and len(r.content) > 8000:
                return v, r.content
        except Exception:
            pass
    return None, None

def page_images(url):
    try:
        r = S.get(url, timeout=60)
    except Exception:
        return []
    imgs = re.findall(r'<img[^>]+(?:data-src|src)="([^"]+)"', r.text)
    keep = []
    for i in imgs:
        if 'uploads' in i and ('w750' in i or 'w1000' in i or 'node_gallery' in i or 'large' in i):
            keep.append(i)
    return list(dict.fromkeys(keep))[:8]

for r in ALL:
    rid = r['id']; src = r['source']
    entry = {'page': src['url'], 'image_url': src['image'], 'site': src['site']}
    used, data = get_img(src['image'])
    if data:
        open(os.path.join(OUT, rid + '.jpg'), 'wb').write(data)
        entry['saved'] = rid + '.jpg'; entry['used_url'] = used; entry['bytes'] = len(data)
    else:
        entry['saved'] = None
    if 'sayidaty' in src['url'] and 'خطوة' in src['url']:
        steps = []
        for n, iu in enumerate(page_images(src['url']), 1):
            u2, d2 = get_img(iu)
            if d2:
                fn = f'{rid}_step{n}.jpg'; open(os.path.join(OUT, fn), 'wb').write(d2); steps.append({'file': fn, 'url': u2})
        entry['steps'] = steps
    index[rid] = entry
    print(rid, entry.get('saved'), entry.get('bytes'))
    time.sleep(0.8)
json.dump(index, open(os.path.join(OUT, 'index.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('done')
