// PostgreSQL integration test suite — runs against a real PostgreSQL server.
// Requires: TEST_DATABASE_URL (or postgresql://madar:madar_dev@localhost:5432/madar_test)
// Run: npm test
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');

const DB_URL = process.env.TEST_DATABASE_URL || 'postgresql://madar:madar_dev@localhost:5432/madar_test';
process.env.DATABASE_URL = DB_URL;
process.env.MADAR_MAX_RPM = '100000';
const ENC_KEY = crypto.randomBytes(32).toString('hex');
const SESS_KEY = crypto.randomBytes(32).toString('hex');

const cryptoCore = require('../core/crypto');
cryptoCore.init(ENC_KEY, SESS_KEY);
const db = require('../core/db');
const auth = require('../core/auth');
const { sanitizeDetails } = require('../core/audit');
const { LocalStorage } = require('../core/storage');
const { ZohoClient, READ_SCOPES } = require('../modules/mail/zoho-client');
const detection = require('../modules/mail/detection');
const sync = require('../modules/mail/sync');
const routes = require('../modules/mail/routes');
const { startMockZoho } = require('./mock-zoho');

const MIGRATE = path.join(__dirname, '..', 'scripts', 'migrate.js');
const runMigrate = () => execFileSync('node', [MIGRATE], { env: { ...process.env, DATABASE_URL: DB_URL }, encoding: 'utf8' });

let mockPort, connId, byAddress = {}, adminUser, memberUser;

// minimal fake req/res to exercise route handlers directly
function fakeCall(method, pathname, { user, body = {}, search = '' } = {}) {
  return new Promise((resolve) => {
    const req = { method, headers: {} };
    const res = {
      writeHead: (status, headers) => { res._status = status; res._headers = headers; },
      end: (data) => resolve({ status: res._status, body: data, headers: res._headers, streamed: false }),
    };
    const url = new URL('http://x' + pathname + search);
    const send = (status, payload) => { resolve({ status, body: payload }); return true; };
    const requireAdmin = () => {
      if (user.role === 'admin') return true;
      send(403, { error: 'admin only' });
      return false;
    };
    routes.handle(req, res, url, user, body, { send, requireAdmin, baseUrl: 'http://localhost:3000' })
      .then(handled => { if (handled === false) resolve({ status: 404, body: { error: 'unhandled' } }); })
      .catch(err => resolve({ status: 500, body: { error: String(err.message) } }));
  });
}

before(async () => {
  // 1) all migrations from an EMPTY database
  await db.q('DROP SCHEMA public CASCADE'); await db.q('CREATE SCHEMA public');
  const out1 = runMigrate();
  assert.match(out1, /applied: 001_init\.sql/);
  // 2) re-running migrations is a no-op, no errors
  const out2 = runMigrate();
  assert.match(out2, /up to date/);

  process.env.MADAR_ATTACH_DIR = require('fs').mkdtempSync(path.join(require('os').tmpdir(), 'madar-att-'));

  mockPort = await startMockZoho(0);
  const base = `http://127.0.0.1:${mockPort}`;
  const r = await db.one(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
      client_secret_enc, refresh_token_enc, scopes, status)
    VALUES ('zoho','Test Org',$1,$1,'test-client',$2,$3,$4,'connected') RETURNING id`,
    [base, cryptoCore.encrypt('super-secret-client-secret'), cryptoCore.encrypt('mock-refresh-token'), READ_SCOPES]);
  connId = Number(r.id);
});

test('users, roles and login work; password hashing is scrypt-tagged', async () => {
  const adminId = await auth.createUser({ email: 'admin@corp.test', name: 'Admin', password: 'a-strong-password-123', role: 'admin' });
  const memberId = await auth.createUser({ email: 'member@corp.test', name: 'Member', password: 'another-strong-pass-1', role: 'member' });
  adminUser = { id: adminId, email: 'admin@corp.test', role: 'admin' };
  memberUser = { id: memberId, email: 'member@corp.test', role: 'member' };
  const login = await auth.login('admin@corp.test', 'a-strong-password-123');
  assert.ok(login && login.token.length === 64);
  assert.strictEqual(await auth.login('admin@corp.test', 'wrong-password-xxxx'), null);
  const stored = (await db.one('SELECT password_hash FROM users WHERE id = $1', [adminId])).password_hash;
  assert.match(stored, /^scrypt\$32768\$/);
  await assert.rejects(() => auth.createUser({ email: 'x@x.test', password: 'short', role: 'member' }), /12 characters/);
});

test('session cookies are HMAC-signed; tampering invalidates them', async () => {
  const login = await auth.login('admin@corp.test', 'a-strong-password-123');
  const cookie = cryptoCore.signSession(login.token);
  assert.strictEqual(cryptoCore.verifySessionCookie(cookie), login.token);
  assert.strictEqual(cryptoCore.verifySessionCookie(cookie.slice(0, -2) + 'ff'), null);
  assert.strictEqual(cryptoCore.verifySessionCookie(login.token), null); // unsigned token rejected
});

test('connection secrets are AES-256-GCM encrypted at rest and decrypt correctly', async () => {
  const row = await db.one('SELECT client_secret_enc, refresh_token_enc FROM connections WHERE id = $1', [connId]);
  assert.ok(row.client_secret_enc.startsWith('v1:'));
  assert.ok(!row.client_secret_enc.includes('super-secret-client-secret'));
  assert.strictEqual(cryptoCore.decrypt(row.client_secret_enc), 'super-secret-client-secret');
});

test('connections API never exposes encrypted secrets or plaintext', async () => {
  const r = await fakeCall('GET', '/api/mail/connections', { user: adminUser });
  assert.strictEqual(r.status, 200);
  const text = JSON.stringify(r.body);
  assert.ok(!text.includes('client_secret_enc') && !text.includes('refresh_token_enc'));
  assert.ok(!text.includes('super-secret-client-secret') && !text.includes('mock-refresh-token'));
});

test('mock discovery creates the 20 fixture shared mailboxes without duplication', async () => {
  const zoho = await ZohoClient.forConnection(connId);
  const discovery = await detection.discoverOrganization(zoho);
  for (const mb of discovery.mailboxes) {
    const caps = await detection.probeCapabilities(zoho, mb);
    const choice = detection.chooseStrategy(mb, caps);
    const id = await detection.upsertMailbox(connId, mb, caps, choice);
    byAddress[mb.address] = { id, mb, caps, choice };
  }
  const shared = await db.one("SELECT COUNT(*)::int AS n FROM mailboxes WHERE detected_type = 'shared_mailbox'");
  assert.strictEqual(shared.n, 20);
  // re-run: no duplicates (unique constraints + alias table)
  for (const mb of discovery.mailboxes) {
    const caps = await detection.probeCapabilities(zoho, mb);
    await detection.upsertMailbox(connId, mb, caps, detection.chooseStrategy(mb, caps));
  }
  assert.strictEqual((await db.one('SELECT COUNT(*)::int AS n FROM mailboxes')).n, 21);
});

test('alias uniqueness: aliases resolve to the owning mailbox and cannot become mailboxes', async () => {
  const info = byAddress['info@exoticcolors.org'];
  const alias = await db.one('SELECT mailbox_id FROM mailbox_aliases WHERE address = $1', ['contact@exoticcolors.org']);
  assert.strictEqual(Number(alias.mailbox_id), info.id);
  assert.strictEqual((await db.one("SELECT COUNT(*)::int AS n FROM mailboxes WHERE address = 'contact@exoticcolors.org'")).n, 0);
});

test('detection evidence is sanitized: no tokens or secrets stored', async () => {
  const rep = await db.one('SELECT report::text AS t FROM detection_reports ORDER BY id DESC LIMIT 1');
  assert.ok(!rep.t.includes('mock-access-token') && !rep.t.includes('Zoho-oauthtoken'));
  assert.match(sanitizeDetails('refresh_token: abcdef1234567890'), /\[REDACTED\]/);
});

test('mailbox grants: member sees only granted mailboxes; cross-user access denied', async () => {
  const info = byAddress['info@exoticcolors.org'];
  const hr = byAddress['hr@exoticcolors.org'];
  await auth.setGrant(memberUser.id, info.id, 'read');
  assert.deepStrictEqual(await auth.readableMailboxIds(memberUser), [info.id]);
  assert.strictEqual(await auth.canReadMailbox(memberUser, hr.id), false);
  const denied = await fakeCall('GET', `/api/mail/mailboxes/${hr.id}`, { user: memberUser });
  assert.strictEqual(denied.status, 403);
});

test('pilot sync requires pilot + explicit start; supports partial run, resume and dedup', async () => {
  const info = byAddress['info@exoticcolors.org'];
  await assert.rejects(() => sync.syncMailbox(info.id), /not pilot-selected/);
  await db.q('UPDATE mailboxes SET is_pilot = TRUE WHERE id = $1', [info.id]);
  await assert.rejects(() => sync.syncMailbox(info.id), /not explicitly started/);
  await db.q('UPDATE mailboxes SET sync_enabled = TRUE WHERE id = $1', [info.id]);

  // partial run (1 backfill page): 100 newest + 100 backfill = 200 of 250
  const s1 = await sync.syncMailbox(info.id, { maxPages: 1 });
  assert.strictEqual(s1.newMessages, 200);
  const st = await db.one('SELECT * FROM sync_state WHERE mailbox_id = $1 AND backfill_done = FALSE', [info.id]);
  assert.ok(st, 'cursor persisted for resume');
  assert.strictEqual(Number(st.next_start), 201);

  // resume completes the remaining 50, and a further run imports 0 (dedup)
  const s2 = await sync.syncMailbox(info.id, { maxPages: 5 });
  assert.strictEqual(s2.newMessages, 50);
  assert.ok(s2.attachments > 0);
  const s3 = await sync.syncMailbox(info.id, { maxPages: 5 });
  assert.strictEqual(s3.newMessages, 0);
  assert.strictEqual((await db.one('SELECT COUNT(*)::int AS n FROM messages WHERE mailbox_id = $1', [info.id])).n, 250);
});

test('sync state survives a simulated process restart (new pool, same DB)', async () => {
  const info = byAddress['info@exoticcolors.org'];
  await db.closeDb(); // simulate process exit: pool gone, state must live in PG
  const st = await db.one('SELECT backfill_done FROM sync_state WHERE mailbox_id = $1 LIMIT 1', [info.id]);
  assert.strictEqual(st.backfill_done, true);
});

test('cancellation stops a running sync and persists a resumable state', async () => {
  const admin2 = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot = TRUE, sync_enabled = TRUE WHERE id = $1', [admin2.id]);
  sync.cancelSync(admin2.id); // flag set before the run: first checkpoint throws
  await assert.rejects(() => sync.syncMailbox(admin2.id, { maxPages: 5 }), /cancelled/);
  const mb = await db.one('SELECT status, status_detail FROM mailboxes WHERE id = $1', [admin2.id]);
  assert.strictEqual(mb.status, 'ready');
  assert.match(mb.status_detail, /cancelled/i);
  const s = await sync.syncMailbox(admin2.id, { maxPages: 5 }); // resume works after cancel
  assert.ok(s.newMessages > 0);
});

test('attachment storage: unguessable keys, traversal blocked, size limit, sha256, no public path', async () => {
  const store = new LocalStorage(require('fs').mkdtempSync(path.join(require('os').tmpdir(), 'att-')), { maxBytes: 1024 });
  const { key, sha256 } = store.put(Buffer.from('hello'));
  assert.match(key, /^[0-9a-f]{48}$/);
  assert.strictEqual(sha256, crypto.createHash('sha256').update('hello').digest('hex'));
  assert.throws(() => store._resolve('../../etc/passwd'), /Invalid storage key/);
  assert.throws(() => store.put(Buffer.alloc(2048)), /size limit/);
  const dbAtt = await db.one('SELECT storage_key FROM attachments LIMIT 1');
  assert.ok(dbAtt && !dbAtt.storage_key.includes('/') && !dbAtt.storage_key.includes('public'));
});

test('attachment download is authorization-gated per mailbox', async () => {
  const att = await db.one(`SELECT a.id, msg.mailbox_id FROM attachments a JOIN messages msg ON msg.id = a.message_id
    WHERE msg.mailbox_id = $1 LIMIT 1`, [byAddress['info@exoticcolors.org'].id]);
  assert.ok(att, 'an attachment exists from the pilot sync');
  const okRes = await new Promise(resolve => {
    const { Writable } = require('stream');
    const res = new Writable({ write(c, e, cb) { cb(); } });
    res.writeHead = (s) => { res._s = s; };
    res.on('finish', () => resolve({ status: res._s, streamed: true }));
    routes.handle({ method: 'GET', headers: {} }, res, new URL(`http://x/api/mail/attachments/${att.id}`), memberUser, {}, {
      send: (status, body) => { resolve({ status, body }); return true; },
      requireAdmin: () => true, baseUrl: '',
    });
  });
  assert.strictEqual(okRes.status, 200); // member HAS a grant on info@
  // revoke → denied
  await auth.setGrant(memberUser.id, byAddress['info@exoticcolors.org'].id, null);
  const denied = await fakeCall('GET', `/api/mail/attachments/${att.id}`, { user: memberUser });
  assert.strictEqual(denied.status, 403);
});

test('FTS search works and is scoped to permitted mailboxes', async () => {
  const admin = adminUser;
  const r = await fakeCall('GET', '/api/mail/messages', { user: admin, search: '?q=Demo+message' });
  assert.strictEqual(r.status, 200);
  assert.ok(r.body.length > 0);
  const none = await fakeCall('GET', '/api/mail/messages', { user: memberUser, search: '?q=Demo' });
  assert.deepStrictEqual(none.body, []); // grants revoked in previous test
});

test('moderation queue stays separate from archive; Invalid Account ID evidence recorded', async () => {
  const hr = byAddress['hr@exoticcolors.org'];
  assert.strictEqual(hr.caps.messages, false);
  assert.strictEqual(byAddress['sms@exoticcolors.org'].caps.moderationQueueReadable, true);
  assert.strictEqual(byAddress['sms@exoticcolors.org'].choice.strategy, 'ediscovery_import');
  const ev = hr.caps.evidence['folders.groupIdAsAccountId'];
  assert.strictEqual(ev.status, 400);
  assert.match(JSON.stringify(ev.body), /Invalid Account ID/);
});

test('health check reflects database availability', async () => {
  assert.strictEqual(await db.healthy(), true);
  const { Pool } = require('pg');
  const bad = new Pool({ connectionString: 'postgresql://madar:madar_dev@localhost:59999/nope', connectionTimeoutMillis: 800 });
  await assert.rejects(() => bad.query('SELECT 1'));
  await bad.end();
});

after(async () => { await db.closeDb(); });
