# Search YouTube (results page HTML -> ytInitialData) for English cooking videos per recipe,
# verify each candidate with oEmbed, and save ../sources/videos/<id>.json
import requests, json, re, os, sys, time, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'sources', 'videos'); os.makedirs(OUT, exist_ok=True)
S = requests.Session()
S.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
                  'Accept-Language': 'en-US,en;q=0.9'})
S.cookies.set('CONSENT', 'YES+1', domain='.youtube.com')
S.cookies.set('SOCS', 'CAI', domain='.youtube.com')

QUERIES = json.load(open(os.path.join(HERE, 'yt_queries.json'), encoding='utf-8'))
only = [x for x in os.environ.get('ONLY', '').split(',') if x]

def walk(o, acc):
    if isinstance(o, dict):
        if 'videoRenderer' in o:
            v = o['videoRenderer']
            try:
                acc.append({
                    'videoId': v['videoId'],
                    'title': ''.join(r.get('text', '') for r in v.get('title', {}).get('runs', [])),
                    'channel': ''.join(r.get('text', '') for r in v.get('ownerText', {}).get('runs', [])),
                    'length': v.get('lengthText', {}).get('simpleText', ''),
                    'views': v.get('viewCountText', {}).get('simpleText', ''),
                    'published': v.get('publishedTimeText', {}).get('simpleText', ''),
                })
            except Exception:
                pass
        for x in o.values(): walk(x, acc)
    elif isinstance(o, list):
        for x in o: walk(x, acc)

def search(q):
    u = 'https://www.youtube.com/results?search_query=' + urllib.parse.quote(q) + '&sp=EgIQAQ%253D%253D'  # videos only
    r = S.get(u, timeout=60)
    m = re.search(r'var ytInitialData = (\{.*?\});</script>', r.text, re.S)
    if not m:
        m = re.search(r'ytInitialData"?\]?\s*=\s*(\{.*?\});', r.text, re.S)
    if not m:
        return []
    try:
        data = json.loads(m.group(1))
    except Exception:
        return []
    acc = []; walk(data, acc)
    return acc[:12]

def oembed(vid):
    try:
        r = S.get('https://www.youtube.com/oembed', params={'url': f'https://www.youtube.com/watch?v={vid}', 'format': 'json'}, timeout=30)
        if r.status_code == 200:
            j = r.json(); return {'ok': True, 'title': j.get('title'), 'author': j.get('author_name'), 'thumb': j.get('thumbnail_url')}
        return {'ok': False, 'status': r.status_code}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

for rid, qs in QUERIES.items():
    if only and rid not in only: continue
    res = {'queries': qs, 'candidates': []}
    seen = set()
    for q in qs:
        try:
            for c in search(q):
                if c['videoId'] in seen: continue
                seen.add(c['videoId']); c['query'] = q
                res['candidates'].append(c)
        except Exception as e:
            res.setdefault('errors', []).append(f'{q}: {e}')
        time.sleep(1.5)
    # verify top candidates
    for c in res['candidates'][:25]:
        c['oembed'] = oembed(c['videoId']); time.sleep(0.3)
    json.dump(res, open(os.path.join(OUT, rid + '.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(rid, len(res['candidates']), 'candidates')
print('done')
