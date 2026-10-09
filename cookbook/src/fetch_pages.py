# Fetch the exact candidate pages in fetch_list.json and extract recipe data.
# Writes ../sources/pages/<id>.json  (list of extracted candidates per recipe id)
import json, os, time, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arabic_sources import extract, S

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'sources', 'pages'); os.makedirs(OUT, exist_ok=True)
LIST = json.load(open(os.path.join(HERE, 'fetch_list.json'), encoding='utf-8'))
only = os.environ.get('ONLY', '')
only = [x.strip() for x in only.split(',') if x.strip()]
force = os.environ.get('FORCE')

def author_from_html(url):
    """Sayidaty pages carry chef links /recipes/index/chef/<id>."""
    try:
        r = S.get(url, timeout=60)
    except Exception:
        return None
    m = re.findall(r'href="(https?://kitchen\.sayidaty\.net/recipes/index/chef/(\d+))"[^>]*>([^<]{1,80})<', r.text)
    if m:
        return {'chef_url': m[0][0], 'chef_id': m[0][1], 'chef_name': m[0][2].strip()}
    return None

for rid, urls in LIST.items():
    if only and rid not in only: continue
    outp = os.path.join(OUT, rid + '.json')
    if os.path.exists(outp) and not force:
        print('skip', rid); continue
    res = []
    for u in urls:
        try:
            d = extract(u)
            if 'sayidaty' in u:
                d['chef'] = author_from_html(u)
            d['ok'] = True
        except Exception as e:
            d = {'url': u, 'ok': False, 'error': str(e)}
        res.append(d)
        print(rid, u, 'ok' if d.get('ok') else 'FAIL', (d.get('jsonld') or {}).get('name'))
        time.sleep(1.0)
    json.dump(res, open(outp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('done')
