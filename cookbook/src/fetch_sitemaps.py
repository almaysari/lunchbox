import requests, os, re, gzip, io, json, time
from bs4 import BeautifulSoup
S = requests.Session()
S.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'})
OUT = '../sources/sitemaps'; os.makedirs(OUT, exist_ok=True)

def get(u):
    r = S.get(u, timeout=60); r.raise_for_status()
    b = r.content
    if u.endswith('.gz') or b[:2] == b'\x1f\x8b':
        b = gzip.decompress(b)
    return b.decode('utf-8', 'ignore')

def crawl(root, name, limit=60):
    urls = set(); todo = [root]; seen = set(); n = 0
    while todo and n < limit:
        u = todo.pop(0)
        if u in seen: continue
        seen.add(u); n += 1
        try:
            x = get(u)
        except Exception as e:
            print('  fail', u, e); continue
        locs = re.findall(r'<loc>\s*([^<]+?)\s*</loc>', x)
        if '<sitemapindex' in x:
            todo.extend(locs)
        else:
            urls.update(locs)
        print(name, u, 'locs', len(locs), 'total', len(urls))
        time.sleep(0.5)
    open(os.path.join(OUT, name + '.txt'), 'w', encoding='utf-8').write('\n'.join(sorted(urls)))
    return urls

for name, roots in {
 'sayidaty': ['https://kitchen.sayidaty.net/sitemap.xml', 'https://kitchen.sayidaty.net/sitemap_index.xml', 'https://kitchen.sayidaty.net/robots.txt'],
 'manal': ['https://www.manalonline.com/sitemap.xml', 'https://www.manalonline.com/sitemap_index.xml', 'https://www.manalonline.com/wp-sitemap.xml', 'https://www.manalonline.com/robots.txt'],
 'shamlola': ['https://www.shamlola.com/sitemap.xml', 'https://www.shamlola.com/sitemap_index.xml', 'https://www.shamlola.com/robots.txt'],
}.items():
    for root in roots:
        try:
            x = get(root)
        except Exception as e:
            print(name, root, 'fail', e); continue
        if root.endswith('robots.txt'):
            sm = re.findall(r'(?i)sitemap:\s*(\S+)', x)
            print(name, 'robots sitemaps', sm)
            for s in sm: crawl(s, name + '_' + re.sub(r'\W+', '_', s.split('/')[-1])[:30])
        else:
            crawl(root, name + '_' + re.sub(r'\W+', '_', root.split('/')[-1])[:30])
