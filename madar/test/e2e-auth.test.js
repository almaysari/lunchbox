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

// Grants lifecycle over the REAL endpoint (production shape from Gate 2):
// a zoho:member_copy occurrence in a shared mailbox is invisible to the admin
// until an explicit grant; POST /api/admin/grants exposes it IMMEDIATELY (no
// restart, no cache), writes an audit row per change, and the grant is visible
// in the admin users listing; revoke hides it again. This is the API path the
// UI checkbox calls — fakeCall-based tests can't reach server.js, so the
// audit-per-change guarantee is proven HERE (pg.test.js's vacuous n>=0 check
// was a hole).
test('grants: explicit + audited + immediate over /api/admin/grants (shared member-copy message)', async () => {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: E2E_URL });
  const q = (t, p) => pool.query(t, p).then(r => r.rows);

  // seed: shared mailbox + routed folder + one member-copy message (the exact
  // production shape captured in Gate 2)
  const [mb] = await q(`INSERT INTO mailboxes (address, display_name, detected_type, strategy, status)
    VALUES ('finance-e2e@exoticcolors.org','Finance E2E','shared_mailbox','none','ready') RETURNING id`);
  const [f] = await q(`INSERT INTO folders (mailbox_id, provider_folder_id, name, folder_type)
    VALUES ($1,'live:routed','Live (وارد موجّه)','inbox') RETURNING id`, [mb.id]);
  const [c] = await q(`INSERT INTO canonical_messages (dedup_hash, from_address, to_addresses, subject, snippet, sent_at)
    VALUES ('e2e-grant-proof','client@example.com','finance-e2e@exoticcolors.org','E2E-GRANT-PROOF','s', now()) RETURNING id`);
  await q(`INSERT INTO message_occurrences (canonical_message_id, mailbox_id, folder_id, provider, provider_message_id, received_at)
    VALUES ($1,$2,$3,'zoho:member_copy','e2e-grant-1', now())`, [c.id, mb.id, f.id]);

  const login = await http('POST', '/api/auth/login', { email: 'owner@e2e.test', password: 'permanent-pass-654321' });
  assert.strictEqual(login.status, 200);
  const csrf = login.json.csrf;
  const meRow = await q(`SELECT id FROM users WHERE email='owner@e2e.test'`);
  const adminId = Number(meRow[0].id);

  // BEFORE any grant: admin role gives metadata, NEVER content — the shared
  // mailbox is outside the readable set (404 anti-enumeration), list is empty
  const before1 = await http('GET', `/api/mail/messages?mailbox_id=${mb.id}`);
  assert.strictEqual(before1.status, 404);
  const beforeAll = await http('GET', '/api/mail/messages?q=E2E-GRANT-PROOF');
  assert.deepStrictEqual(beforeAll.json, []);
  const audit0 = (await q(`SELECT COUNT(*)::int n FROM audit_log WHERE action='admin.grant.set'`))[0].n;

  // EXPLICIT grant via the real endpoint (what the UI checkbox calls)
  const grant = await http('POST', '/api/admin/grants',
    { user_id: adminId, mailbox_id: Number(mb.id), flags: { can_view_messages: true } }, { 'X-CSRF-Token': csrf });
  assert.strictEqual(grant.status, 200);

  // AUDITED: exactly one new admin.grant.set row, naming actor + target
  const audit1 = await q(`SELECT user_id, target FROM audit_log WHERE action='admin.grant.set' ORDER BY id DESC LIMIT 1`);
  assert.strictEqual((await q(`SELECT COUNT(*)::int n FROM audit_log WHERE action='admin.grant.set'`))[0].n, audit0 + 1);
  assert.strictEqual(Number(audit1[0].user_id), adminId);
  assert.ok(String(audit1[0].target).includes(`mailbox:${mb.id}`));

  // IMMEDIATE: the stored member-copy message is served right away
  const after1 = await http('GET', `/api/mail/messages?mailbox_id=${mb.id}`);
  assert.strictEqual(after1.status, 200);
  assert.ok(after1.json.some(r => r.subject === 'E2E-GRANT-PROOF'), 'granted read exposes the stored message immediately');

  // VISIBLE: the users listing shows the grant
  const users = await http('GET', '/api/admin/users');
  const meListed = users.json.find(u => u.id === adminId);
  assert.ok(meListed.grants.some(g => Number(g.mailbox_id) === Number(mb.id) && g.can_view_messages),
    'grant is visible in the admin users listing');

  // REVOKE: audited too, and the content disappears again
  const revoke = await http('POST', '/api/admin/grants',
    { user_id: adminId, mailbox_id: Number(mb.id) }, { 'X-CSRF-Token': csrf });
  assert.strictEqual(revoke.status, 200);
  assert.strictEqual((await q(`SELECT COUNT(*)::int n FROM audit_log WHERE action='admin.grant.set'`))[0].n, audit0 + 2);
  assert.strictEqual((await http('GET', `/api/mail/messages?mailbox_id=${mb.id}`)).status, 404);

  await pool.end();
});

// Accounting integration layer over REAL HTTP: machine keys (no session, no
// CSRF), per-key mailbox scope, cursor-based unread semantics, full message
// fidelity, admin-managed + audited lifecycle. Madar is the abstraction —
// consumers never touch Zoho.
test('integration API: scoped machine keys expose shared mailboxes with unread cursors, full fidelity, and audited lifecycle', async () => {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: E2E_URL });
  const q = (t, p) => pool.query(t, p).then(r => r.rows);
  const [mb] = await q(`SELECT id FROM mailboxes WHERE address='finance-e2e@exoticcolors.org'`);
  const [other] = await q(`INSERT INTO mailboxes (address, display_name, detected_type, strategy, status)
    VALUES ('billing-e2e@exoticcolors.org','Billing E2E','shared_mailbox','none','ready') RETURNING id`);

  const login = await http('POST', '/api/auth/login', { email: 'owner@e2e.test', password: 'permanent-pass-654321' });
  const csrf = login.json.csrf;

  // EXPLICIT scope at key creation = the machine-access grant, audited
  const created = await http('POST', '/api/admin/integration-keys',
    { name: 'accounting-system', mailbox_ids: [Number(mb.id)] }, { 'X-CSRF-Token': csrf });
  assert.strictEqual(created.status, 200);
  const secret = created.json.secret;
  assert.ok(/^mik_[0-9a-f]{40}$/.test(secret), 'secret issued once, mik_ prefixed');
  assert.ok((await q(`SELECT 1 FROM audit_log WHERE action='admin.integration_key.create'`)).length >= 1);
  // the secret is never stored — only its hash + display prefix
  assert.strictEqual((await q(`SELECT COUNT(*)::int n FROM integration_keys WHERE key_hash=$1`, [secret]))[0].n, 0);

  const api = (method, p, body, headers = {}) => http(method, p, body, { 'X-Api-Key': secret, ...headers });

  // auth gate: missing/garbage keys are 401
  assert.strictEqual((await http('GET', '/api/integration/v1/mailboxes')).status, 401);
  assert.strictEqual((await http('GET', '/api/integration/v1/mailboxes', null, { 'X-Api-Key': 'mik_' + '0'.repeat(40) })).status, 401);

  // stable mailbox ids, scoped listing only
  const boxes = await api('GET', '/api/integration/v1/mailboxes');
  assert.strictEqual(boxes.status, 200);
  assert.deepStrictEqual(boxes.json.map(b => b.address), ['finance-e2e@exoticcolors.org']);
  assert.strictEqual(Number(boxes.json[0].id), Number(mb.id));

  // out-of-scope mailbox is indistinguishable from nonexistent
  assert.strictEqual((await api('GET', `/api/integration/v1/mailboxes/${other.id}/messages`)).status, 404);

  // unread (fresh consumer: cursor 0) → the stored member-copy message, full fidelity
  const first = await api('GET', `/api/integration/v1/mailboxes/${mb.id}/messages`);
  assert.strictEqual(first.status, 200);
  assert.strictEqual(first.json.messages.length, 1);
  const msg = first.json.messages[0];
  assert.strictEqual(msg.providerMessageId, 'e2e-grant-1');
  assert.strictEqual(msg.provider, 'zoho:member_copy');
  assert.strictEqual(msg.subject, 'E2E-GRANT-PROOF');
  assert.strictEqual(msg.from.address, 'client@example.com');
  assert.ok(String(msg.to).includes('finance-e2e@exoticcolors.org'));
  assert.ok(!Number.isNaN(Date.parse(msg.sentAt)) && !Number.isNaN(Date.parse(msg.receivedAt)));
  assert.ok(Number(msg.occurrenceId) > 0 && Number(msg.canonicalId) > 0);
  assert.strictEqual(msg.folder, 'Live (وارد موجّه)');
  assert.ok(first.json.nextCursor >= msg.occurrenceId);

  // acknowledge → unread drains to empty (per-consumer cursor, monotonic)
  const ack = await api('POST', `/api/integration/v1/mailboxes/${mb.id}/cursor`, { last_occurrence_id: first.json.nextCursor });
  assert.strictEqual(ack.status, 200);
  assert.deepStrictEqual((await api('GET', `/api/integration/v1/mailboxes/${mb.id}/messages`)).json.messages, []);

  // a NEW message arrives → only IT is unread; after_id=0 replays full history
  const [c2] = await q(`INSERT INTO canonical_messages (dedup_hash, from_address, to_addresses, subject, snippet, sent_at)
    VALUES ('e2e-int-2','vendor@example.com','finance-e2e@exoticcolors.org','INVOICE-42','s', now()) RETURNING id`);
  const [f2] = await q(`SELECT folder_id FROM message_occurrences o JOIN mailboxes m ON m.id=o.mailbox_id WHERE m.id=$1 LIMIT 1`, [mb.id]);
  await q(`INSERT INTO message_occurrences (canonical_message_id, mailbox_id, folder_id, provider, provider_message_id, received_at)
    VALUES ($1,$2,$3,'zoho:member_copy','e2e-int-2', now())`, [c2.id, mb.id, f2.folder_id]);
  const second = await api('GET', `/api/integration/v1/mailboxes/${mb.id}/messages`);
  assert.deepStrictEqual(second.json.messages.map(x => x.subject), ['INVOICE-42']);
  const replay = await api('GET', `/api/integration/v1/mailboxes/${mb.id}/messages?after_id=0`);
  assert.deepStrictEqual(replay.json.messages.map(x => x.subject), ['E2E-GRANT-PROOF', 'INVOICE-42']);
  // duplicate prevention at the interface: each canonical exactly once
  const canonicals = replay.json.messages.map(x => Number(x.canonicalId));
  assert.strictEqual(new Set(canonicals).size, canonicals.length);

  // cursor never moves backwards (accidental replays cannot lose position)
  await api('POST', `/api/integration/v1/mailboxes/${mb.id}/cursor`, { last_occurrence_id: 1 });
  assert.deepStrictEqual((await api('GET', `/api/integration/v1/mailboxes/${mb.id}/messages`)).json.messages.map(x => x.subject),
    ['INVOICE-42'], 'monotonic cursor: a lower ack does not rewind unread');

  // admin visibility without secrets; revoke is audited and kills the key
  const listing = await http('GET', '/api/admin/integration-keys');
  const row = listing.json.find(k => k.name === 'accounting-system');
  assert.ok(row && row.prefix && !('secret' in row) && !('key_hash' in row));
  const revoke = await http('POST', '/api/admin/integration-keys/revoke', { key_id: row.id }, { 'X-CSRF-Token': csrf });
  assert.strictEqual(revoke.status, 200);
  assert.strictEqual((await api('GET', '/api/integration/v1/mailboxes')).status, 401);
  assert.ok((await q(`SELECT 1 FROM audit_log WHERE action='admin.integration_key.revoke'`)).length >= 1);

  await pool.end();
});

after(() => { serverProc?.kill('SIGKILL'); });
