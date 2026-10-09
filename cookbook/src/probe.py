import requests, re, json, sys
from bs4 import BeautifulSoup
S = requests.Session()
S.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36','Accept-Language':'ar,en;q=0.8'})
out = {}
tests = {
 'sayidaty_home': 'https://kitchen.sayidaty.net/',
 'sayidaty_search': 'https://kitchen.sayidaty.net/recipes/search?q=%D9%83%D8%A8%D8%B3%D8%A9',
 'sayidaty_chef': 'https://kitchen.sayidaty.net/recipes/index/chef/4243',
 'manal_home': 'https://www.manalonline.com/recipes/',
 'manal_search': 'https://www.manalonline.com/?s=%D8%A8%D8%B1%D9%8A%D8%A7%D9%86%D9%8A',
 'shamlola_home': 'https://www.shamlola.com/recipes',
 'shamlola_search': 'https://www.shamlola.com/search?q=%D9%85%D9%84%D9%88%D8%AE%D9%8A%D8%A9',
 'bing': 'https://www.bing.com/search?q=%D9%83%D8%A8%D8%B3%D8%A9+site%3Akitchen.sayidaty.net',
 'ddg': 'https://html.duckduckgo.com/html/?q=%D9%83%D8%A8%D8%B3%D8%A9+site%3Akitchen.sayidaty.net',
}
for k, u in tests.items():
    try:
        r = S.get(u, timeout=40, allow_redirects=True)
        soup = BeautifulSoup(r.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        rec = [l for l in links if l and ('/recipes/' in l or 'recipe' in l)][:8]
        out[k] = {'status': r.status_code, 'final': r.url, 'len': len(r.text), 'title': (soup.title.string or '')[:80] if soup.title else '', 'recipe_links': rec}
    except Exception as e:
        out[k] = {'error': str(e)}
print(json.dumps(out, ensure_ascii=False, indent=1))
json.dump(out, open('../sources/_probe.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
