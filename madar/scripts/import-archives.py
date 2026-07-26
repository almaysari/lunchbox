#!/usr/bin/env python3
"""One-command bulk archive importer for Madar (stdlib only, no dependencies).

Usage:
    python3 scripts/import-archives.py ~/Downloads/zoho-exports [--url http://localhost:3000] [--yes]

What it does, end to end:
  1. Logs into Madar (email + hidden password prompt) on YOUR machine.
  2. Reads the shared-mailbox intake list from the running platform.
  3. Proposes a filename -> mailbox binding for every *.zip in the folder
     (exact address variants, or an unambiguous local part) and shows the
     full mapping for ONE confirmation — nothing is ever guessed silently.
  4. Uploads and imports every file sequentially, prints per-file results,
     then re-checks the intake board and prints the per-mailbox states.
Re-running is always safe: duplicates are blocked by the canonical model.
"""
import argparse
import getpass
import json
import pathlib
import re
import sys
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar

def api(opener, base, path, data=None, headers=None, raw=False):
    req = urllib.request.Request(base + path, data=data, headers=headers or {})
    try:
        with opener.open(req, timeout=3600) as r:
            body = r.read()
            return r.status, (body if raw else json.loads(body or b'{}'))
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body or b'{}')
        except Exception:
            return e.code, {'error': body.decode('utf-8', 'replace')[:300]}

def guess_mailbox(filename, mailboxes):
    n = filename.lower()
    for m in mailboxes:
        addr = m['address'].lower()
        variants = [addr, addr.replace('@', '_').replace('.', '_'),
                    addr.replace('@', '-').replace('.', '-'), addr.replace('@', '_at_')]
        if any(v in n for v in variants):
            return m['mailboxId']
    locals_map = {}
    for m in mailboxes:
        locals_map.setdefault(m['address'].lower().split('@')[0], []).append(m['mailboxId'])
    for lp, ids in locals_map.items():
        if len(ids) == 1 and re.search(r'(^|[^a-z0-9])' + re.escape(lp) + r'([^a-z0-9]|$)', n):
            return ids[0]
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('folder', help='folder containing the downloaded eDiscovery ZIP parts')
    ap.add_argument('--url', default='http://localhost:3000', help='Madar base URL')
    ap.add_argument('--yes', action='store_true', help='skip the mapping confirmation prompt')
    args = ap.parse_args()

    folder = pathlib.Path(args.folder).expanduser()
    zips = sorted(p for p in folder.glob('*.zip') if p.is_file())
    if not zips:
        sys.exit(f'لا توجد ملفات .zip في {folder}')

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    email = input('بريد أدمن مدار: ').strip()
    password = getpass.getpass('كلمة المرور (لن تظهر): ')
    status, login = api(opener, args.url, '/api/auth/login',
                        data=json.dumps({'email': email, 'password': password}).encode(),
                        headers={'Content-Type': 'application/json'})
    if status != 200:
        sys.exit(f'فشل تسجيل الدخول ({status}): {login.get("error", "")}')
    if login.get('mustChangePassword'):
        sys.exit('هذا الحساب مطالب بتغيير كلمة المرور أولًا — غيّرها من الواجهة ثم أعد التشغيل.')
    csrf = login['csrf']

    status, intake = api(opener, args.url, '/api/mail/archive-intake')
    if status != 200:
        sys.exit(f'تعذر جلب قائمة الصناديق ({status}) — تأكد أن الحساب يملك دور إدارة البريد.')
    boxes = intake['mailboxes']
    by_id = {m['mailboxId']: m['address'] for m in boxes}

    plan, unmatched = [], []
    for z in zips:
        mid = guess_mailbox(z.name, boxes)
        (plan if mid else unmatched).append((z, mid))
    print('\nخريطة الربط المقترحة (من أسماء الملفات):')
    for z, mid in plan:
        print(f'  {z.name}  ->  {by_id[mid]}')
    for z, _ in unmatched:
        print(f'  {z.name}  ->  ✗ لم يُتعرف — سيُتخطى (أعد تسميته ليتضمن عنوان الصندوق ثم أعد التشغيل)')
    if not plan:
        sys.exit('لا ملف واحد قابل للربط — أعد تسمية الملفات لتتضمن عناوين الصناديق.')
    if not args.yes and input('\nتأكيد الاستيراد بهذه الخريطة؟ [y/N]: ').strip().lower() != 'y':
        sys.exit('أُلغي — لم يُستورد شيء.')

    totals = {'imported': 0, 'attachments': 0, 'duplicates': 0}
    failures = []
    for i, (z, mid) in enumerate(plan, 1):
        data = z.read_bytes()
        print(f'[{i}/{len(plan)}] {z.name} -> {by_id[mid]} ({len(data)/1048576:.1f}MB)...', flush=True)
        status, res = api(opener, args.url, f'/api/mail/mailboxes/{mid}/import-archive', data=data,
                          headers={'Content-Type': 'application/zip', 'X-CSRF-Token': csrf,
                                   'X-File-Name': urllib.parse.quote(z.name)})
        if status == 200:
            for k in totals:
                totals[k] += res.get(k, 0)
            print(f'    ✓ {res["imported"]} رسالة، {res["attachments"]} مرفق، تكرارات مُنعت: {res["duplicates"]}')
        else:
            failures.append((z.name, res.get('error', f'HTTP {status}')))
            print(f'    ✗ فشل: {res.get("error", status)}')

    status, board = api(opener, args.url, '/api/mail/archive-intake')
    print('\n===== حالة الصناديق بعد الاستيراد =====')
    for m in board['mailboxes']:
        print(f'  {m["state"]:<10} {m["address"]}  (رسائل: {m["imported"]}, مرفقات: {m["attachments"]})')
    s = board['summary']
    print(f'\nالإجمالي: مكتمل {s["completed"]}/{s["total"]} — بانتظار {s["pending"]} — فاشل {s["failed"]}')
    print(f'هذه الدفعة: {totals["imported"]} رسالة، {totals["attachments"]} مرفق، تكرارات مُنعت: {totals["duplicates"]}')
    if failures:
        print('\nملفات فشلت (إعادة تشغيل الأمر آمنة — لا ازدواج):')
        for name, err in failures:
            print(f'  ✗ {name}: {err}')
        sys.exit(1)
    if unmatched:
        sys.exit(2)

if __name__ == '__main__':
    main()
