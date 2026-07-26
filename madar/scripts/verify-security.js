#!/usr/bin/env node
// verify:security — repository hygiene gate (runs locally and in CI):
//  * prohibited files must not be tracked: node_modules, .env, *.sqlite/db,
//    data dirs, attachments, dumps
//  * no obvious secret material in tracked files (best-effort pattern pass;
//    the full-history scan is done by gitleaks in CI)
//  * .env.example must not contain ready-to-use credentials
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

let failed = false;
const fail = msg => { console.error('FAIL:', msg); failed = true; };

const tracked = execFileSync('git', ['ls-files'], { cwd: path.join(__dirname, '..'), encoding: 'utf8' })
  .split('\n').filter(Boolean);

const PROHIBITED = [
  /(^|\/)node_modules\//, /(^|\/)\.env$/, /\.(sqlite3?|db)$/i,
  /(^|\/)data(-demo)?\//, /(^|\/)attachments\//, /\.(dump|pst)$/i, /\.eml$/i,
];
for (const f of tracked) {
  for (const re of PROHIBITED) if (re.test(f)) fail(`prohibited file tracked: ${f}`);
}

const SECRET_RE = /(client_secret|refresh_token|api[_-]?key|password)["'\s:=]+["'][A-Za-z0-9+/_-]{24,}["']/i;
for (const f of tracked) {
  if (!/\.(js|json|yml|yaml|md|sql|html)$/.test(f)) continue;
  const text = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  for (const [i, line] of text.split('\n').entries()) {
    if (SECRET_RE.test(line) && !/CHANGE_ME|example|randomBytes|test|mock|demo|REDACTED|EXCLUDED|placeholder/i.test(line)) {
      fail(`possible secret in ${f}:${i + 1}`);
    }
  }
}

const envExample = fs.readFileSync(path.join(__dirname, '..', '.env.example'), 'utf8');
for (const line of envExample.split('\n')) {
  const m = line.match(/^([A-Z0-9_]+)=(.+)$/);
  if (!m) continue;
  const [, key, value] = m;
  if (/(PASSWORD|SECRET|KEY|TOKEN)/.test(key) && value && !/CHANGE_ME|^$/.test(value) && !key.startsWith('#')) {
    // values must be empty or explicit placeholders — never usable credentials
    if (!/^(CHANGE_ME.*|)$/.test(value)) fail(`.env.example ships a usable-looking value for ${key}`);
  }
}

if (failed) process.exit(1);
console.log(`verify:security OK — ${tracked.length} tracked files clean (pattern pass; gitleaks covers full history in CI)`);
