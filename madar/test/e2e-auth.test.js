// End-to-end auth lifecycle over REAL HTTP against the real server process:
// fresh install → no bootstrap admin exists → create-admin → first login →
// forced password change → second login. Proves login is served exclusively
// from the PostgreSQL users table.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn, execFileSync } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');

const BASE_TEST_URL = process.env.TEST_DATABASE_URL || 'postgresql://madar:madar_dev@localhost:5432/madar_test';
const E2E_URL = BASE_TEST_URL.replace(/\/[^/]+$/, '/madar_e2e');
const PORT = 3400 + Math.floor(Math.random() * 500);
const ROOT = path.join(__dirname, '..');
const ENV = {
  ...process.env,
  MODE: 'live', PORT: String(PORT), BASE_URL: `http://localhost:${PORT}`,
  DATABASE_URL: E2E_URL,
  MADAR_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'),
  MADAR_SESSION_SECRET: crypto.randomBytes(32).toString('hex'),
  MADAR_CSRF_SECRET: crypto.randomBytes(32).toString('hex'),
  MADAR_ATTACH_DIR: require('fs').mkdtempSync(path.join(require('os').tmpdir(), 'e2e-att-')),
};

let serverProc, jar = '';
const http = async (method, p, body, extraHeaders = {}) => {
  const res = await fetch(`http://localhost:${PORT}${p}`, {
    method, headers: { 'Content-Type': 'application/json', cookie: jar, ...extraHeaders },
    body: body ? JSON.stringify(body) : undefined, redirect: 'manual',
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) jar = setCookie.split(';')[0];
  let json = null; try { json = await res.json(); } catch {}
  return { status: res.status, json };
};

before(async () => {
  const { Pool } = require('pg');
  const adminPool = new Pool({ connectionString: BASE_TEST_URL });
  await adminPool.query('CREATE DATABASE madar_e2e').catch(() => {});
  await adminPool.end();
  const e2ePool = new Pool({ connectionString: E2E_URL });
  await e2ePool.query('DROP SCHEMA public CASCADE'); await e2ePool.query('CREATE SCHEMA public');
  await e2ePool.end();
  execFileSync('node', [path.join(ROOT, 'scripts', 'migrate.js')], { env: ENV });
  serverProc = spawn('node', [path.join(ROOT, 'server.js')], { env: ENV, stdio: 'ignore' });
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(`http://localhost:${PORT}/health/ready`); if (r.ok) return; } catch {}
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error('server did not become ready');
});

test('fresh install: zero users, no bootstrap admin, login impossible', async () => {
  const st = await http('GET', '/api/auth/setup-status');
  assert.deepStrictEqual(st.json, { hasUsers: false });
  const bad = await http('POST', '/api/auth/login', { email: 'admin@local', password: 'anything-long-123' });
  assert.strictEqual(bad.status, 401); // no bootstrap identity exists anywhere
});

test('create-admin (users table) → first login → forced change → relogin', async () => {
  execFileSync('node', [path.join(ROOT, 'scripts', 'create-admin.js')], {
    env: { ...ENV, MADAR_ADMIN_EMAIL: 'owner@e2e.test', MADAR_ADMIN_NAME: 'Owner', MADAR_ADMIN_PASSWORD: 'initial-pass-123456' },
  });
  assert.deepStrictEqual((await http('GET', '/api/auth/setup-status')).json, { hasUsers: true });

  const login1 = await http('POST', '/api/auth/login', { email: 'owner@e2e.test', password: 'initial-pass-123456' });
  assert.strictEqual(login1.status, 200);
  assert.strictEqual(login1.json.mustChangePassword, true);
  assert.ok(login1.json.roles.includes('platform_admin'));
  const csrf = login1.json.csrf;

  // gated until the password is changed
  const gated = await http('GET', '/api/mail/mailboxes');
  assert.strictEqual(gated.status, 428);

  const change = await http('POST', '/api/auth/change-password',
    { current_password: 'initial-pass-123456', new_password: 'permanent-pass-654321' }, { 'X-CSRF-Token': csrf });
  assert.strictEqual(change.status, 200);

  // all sessions revoked → old cookie is dead
  const me = await http('GET', '/api/auth/me');
  assert.strictEqual(me.json, null);

  // second login with the NEW password: flag cleared, platform works
  const login2 = await http('POST', '/api/auth/login', { email: 'owner@e2e.test', password: 'permanent-pass-654321' });
  assert.strictEqual(login2.status, 200);
  assert.strictEqual(login2.json.mustChangePassword, false);
  const boxes = await http('GET', '/api/mail/mailboxes');
  assert.strictEqual(boxes.status, 200); // admin metadata access via role
  // old password no longer works
  const old = await http('POST', '/api/auth/login', { email: 'owner@e2e.test', password: 'initial-pass-123456' });
  assert.strictEqual(old.status, 401);
});

after(() => { serverProc?.kill('SIGKILL'); });
