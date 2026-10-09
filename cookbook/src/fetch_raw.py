# Fetch raw HTML of listing/search pages and save, so the parent session can inspect link patterns offline.
import requests, os, json, urllib.parse, time
S = requests.Session()
S.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36','Accept-Language':'ar,en;q=0.8'})
OUT = '../sources/raw'; os.makedirs(OUT, exist_ok=True)
pages = {
 'sayidaty_search_kabsa': 'https://kitchen.sayidaty.net/recipes/search?q=' + urllib.parse.quote('كبسة دجاج'),
 'sayidaty_chef_4243': 'https://kitchen.sayidaty.net/recipes/index/chef/4243',
 'manal_search_biryani': 'https://www.manalonline.com/?s=' + urllib.parse.quote('برياني'),
 'manal_recipes': 'https://www.manalonline.com/recipes/',
 'shamlola_recipes': 'https://www.shamlola.com/recipes',
 'shamlola_search2': 'https://www.shamlola.com/search/' + urllib.parse.quote('ملوخية'),
 'shamlola_search3': 'https://www.shamlola.com/recipes?search=' + urllib.parse.quote('ملوخية'),
 'shamlola_search4': 'https://www.shamlola.com/recipes/search/' + urllib.parse.quote('ملوخية'),
}
meta = {}
for k, u in pages.items():
    try:
        r = S.get(u, timeout=60)
        open(os.path.join(OUT, k + '.html'), 'w', encoding='utf-8').write(r.text)
        meta[k] = {'status': r.status_code, 'final': r.url, 'len': len(r.text)}
    except Exception as e:
        meta[k] = {'error': str(e)}
    time.sleep(1)
json.dump(meta, open(os.path.join(OUT, '_meta.json'), 'w'), indent=1)
print(json.dumps(meta, indent=1))
