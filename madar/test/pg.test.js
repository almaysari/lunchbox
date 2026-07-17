// PostgreSQL integration test suite — real PostgreSQL, full security model.
// Run: npm test  (TEST_DATABASE_URL or postgresql://madar:madar_dev@localhost:5432/madar_test)
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');

const DB_URL = process.env.TEST_DATABASE_URL || 'postgresql://madar:madar_dev@localhost:5432/madar_test';
process.env.DATABASE_URL = DB_URL;
process.env.MADAR_MAX_RPM = '100000';
const KEY_V1 = crypto.randomBytes(32).toString('hex');
const KEY_V2 = crypto.randomBytes(32).toString('hex');
const SESS_KEY = crypto.randomBytes(32).toString('hex');
const CSRF_KEY = crypto.randomBytes(32).toString('hex');

const cryptoCore = require('../core/crypto');
cryptoCore.init({ 1: KEY_V1 }, SESS_KEY, CSRF_KEY);
const db = require('../core/db');
const auth = require('../core/auth');
const { sanitizeDetails } = require('../core/audit');
const { LocalStorage, detectMime, sanitizeFilename } = require('../core/storage');
const { ZohoClient, READ_SCOPES } = require('../modules/mail/zoho-client');
const detection = require('../modules/mail/detection');
const sync = require('../modules/mail/sync');
const routes = require('../modules/mail/routes');
const { startMockZoho } = require('./mock-zoho');

const MIGRATE = path.join(__dirname, '..', 'scripts', 'migrate.js');
const runMigrate = () => execFileSync('node', [MIGRATE], { env: { ...process.env, DATABASE_URL: DB_URL }, encoding: 'utf8' });

let mockPort, connId, byAddress = {}, adminUser, memberUser, auditorUser;

function fakeCall(method, pathname, { user, body = {}, search = '', reqHeaders = {} } = {}) {
  return new Promise((resolve) => {
    const { Writable } = require('stream');
    const res = new Writable({ write(c, e, cb) { cb(); } });
    res.writeHead = (s, h) => { res._s = s; res._h = h; };
    res.on('finish', () => resolve({ status: res._s, headers: res._h, streamed: true }));
    res.end = res.end.bind(res);
    const url = new URL('http://x' + pathname + search);
    const send = (status, payload) => { resolve({ status, body: payload }); return true; };
    routes.handle({ method, headers: reqHeaders }, res, url, user, body, { send, baseUrl: 'http://localhost:3000' })
      .then(handled => { if (handled === false) resolve({ status: 404, body: { error: 'unhandled' } }); })
      .catch(err => resolve({ status: 500, body: { error: String(err.message) } }));
  });
}

before(async () => {
  await db.q('DROP SCHEMA public CASCADE'); await db.q('CREATE SCHEMA public');
  const out1 = runMigrate();
  assert.match(out1, /applied: 001_init\.sql/);
  assert.match(out1, /applied: 002_rbac_canonical_security\.sql/);
  assert.match(runMigrate(), /up to date/); // idempotent re-run

  process.env.MADAR_ATTACH_DIR = require('fs').mkdtempSync(path.join(require('os').tmpdir(), 'madar-att-'));
  mockPort = await startMockZoho(0);
  const base = `http://127.0.0.1:${mockPort}`;
  const r = await db.one(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
      client_secret_enc, refresh_token_enc, scopes, status, encryption_key_version)
    VALUES ('zoho','Test Org',$1,$1,'test-client',$2,$3,$4,'connected',1) RETURNING id`,
    [base, cryptoCore.encrypt('super-secret-client-secret'), cryptoCore.encrypt('mock-refresh-token'), READ_SCOPES]);
  connId = Number(r.id);
});

// ---------- schema / migrations ----------
test('schema: all required tables exist', async () => {
  const rows = await db.all(`SELECT table_name FROM information_schema.tables WHERE table_schema='public'`);
  const names = new Set(rows.map(r => r.table_name));
  for (const t of ['schema_migrations', 'users', 'roles', 'user_roles', 'sessions', 'connections', 'mailboxes',
    'mailbox_aliases', 'detection_reports', 'folders', 'canonical_messages', 'message_occurrences',
    'attachments', 'mailbox_grants', 'sync_jobs', 'sync_state', 'labels', 'message_labels', 'audit_log', 'oauth_states']) {
    assert.ok(names.has(t), 'missing table: ' + t);
  }
});

// ---------- RBAC ----------
test('RBAC: roles are real tables; users carry no role column', async () => {
  const roleNames = (await db.all('SELECT name FROM roles ORDER BY id')).map(r => r.name);
  assert.deepStrictEqual(roleNames, ['platform_admin', 'security_admin', 'mail_admin', 'auditor', 'member']);
  const cols = await db.all(`SELECT column_name FROM information_schema.columns WHERE table_name='users'`);
  assert.ok(!cols.some(c => c.column_name === 'role'));

  const adminId = await auth.createUser({ email: 'admin@corp.test', name: 'Admin', password: 'a-strong-password-123', roles: ['platform_admin'] });
  const memberId = await auth.createUser({ email: 'member@corp.test', name: 'Member', password: 'another-strong-pass-1', roles: ['member'] });
  const auditorId = await auth.createUser({ email: 'auditor@corp.test', name: 'Auditor', password: 'auditor-strong-pass-1', roles: ['auditor'] });
  adminUser = { id: adminId, email: 'admin@corp.test', roles: ['platform_admin'] };
  memberUser = { id: memberId, email: 'member@corp.test', roles: ['member'] };
  auditorUser = { id: auditorId, email: 'auditor@corp.test', roles: ['auditor'] };
  assert.ok(auth.isPlatformAdmin(adminUser) && auth.isMailAdmin(adminUser) && auth.isAuditor(adminUser));
  assert.ok(!auth.isMailAdmin(memberUser) && !auth.isAuditor(memberUser));
  assert.ok(auth.isAuditor(auditorUser) && !auth.isMailAdmin(auditorUser));
});

// ---------- auth security ----------
test('auth: login, scrypt format, lockout after repeated failures', async () => {
  const ok = await auth.login('admin@corp.test', 'a-strong-password-123');
  assert.ok(ok && ok.token);
  const stored = (await db.one('SELECT password_hash FROM users WHERE id = $1', [adminUser.id])).password_hash;
  assert.match(stored, /^scrypt\$32768\$/);
  // 5 failures → locked (DB-backed, restart-safe)
  for (let i = 0; i < 5; i++) {
    assert.strictEqual(await auth.login('victim@corp.test', 'wrong-password-xxxx'), null);
    await db.q("INSERT INTO audit_log (action, target) VALUES ('auth.login.failed','victim@corp.test')");
  }
  const locked = await auth.login('victim@corp.test', 'whatever-password-1');
  assert.deepStrictEqual(locked, { locked: true });
});

test('auth: session rotation and revocation', async () => {
  const login = await auth.login('admin@corp.test', 'a-strong-password-123');
  // age the session beyond the rotation threshold
  await db.q("UPDATE sessions SET created_at = now() - interval '2 hours' WHERE token = $1", [login.token]);
  const r = await auth.userForToken(login.token);
  assert.ok(r.user && r.rotatedToken && r.rotatedToken !== login.token);
  assert.strictEqual((await auth.userForToken(login.token)).user, null); // old token revoked
  assert.ok((await auth.userForToken(r.rotatedToken)).user);
  await auth.revokeAllSessions(adminUser.id);
  assert.strictEqual((await auth.userForToken(r.rotatedToken)).user, null);
});

test('auth: CSRF tokens verify and reject tampering; password reset revokes sessions', async () => {
  const t = 'a'.repeat(64);
  const c = cryptoCore.csrfTokenFor(t);
  assert.ok(cryptoCore.verifyCsrf(t, c));
  assert.ok(!cryptoCore.verifyCsrf(t, c.slice(0, -2) + 'ff'));
  assert.ok(!cryptoCore.verifyCsrf('b'.repeat(64), c));
  const login = await auth.login('member@corp.test', 'another-strong-pass-1');
  await auth.resetPassword(memberUser.id, 'brand-new-strong-pass-2');
  assert.strictEqual((await auth.userForToken(login.token)).user, null);
  assert.ok(await auth.login('member@corp.test', 'brand-new-strong-pass-2'));
});

// ---------- encryption ----------
test('encryption: versioned at rest, key rotation via reencrypt, API leaks nothing', async () => {
  const row = await db.one('SELECT client_secret_enc, encryption_key_version FROM connections WHERE id = $1', [connId]);
  assert.match(row.client_secret_enc, /^k1:/);
  assert.strictEqual(row.encryption_key_version, 1);
  assert.strictEqual(cryptoCore.decrypt(row.client_secret_enc), 'super-secret-client-secret');
  // rotate: add key v2, re-encrypt, old ciphertext still readable, new writes use v2
  cryptoCore.init({ 1: KEY_V1, 2: KEY_V2 }, SESS_KEY, CSRF_KEY);
  assert.strictEqual(cryptoCore.currentKeyVersion(), 2);
  const rotated = cryptoCore.reencrypt(row.client_secret_enc);
  assert.match(rotated, /^k2:/);
  assert.strictEqual(cryptoCore.decrypt(rotated), 'super-secret-client-secret');
  const api = await fakeCall('GET', '/api/mail/connections', { user: adminUser });
  const text = JSON.stringify(api.body);
  assert.ok(!text.includes('_enc') && !text.includes('super-secret-client-secret') && !text.includes('mock-refresh-token'));
});

// ---------- OAuth state ----------
test('oauth_states: hashed at rest, one-time use, expiry enforced', async () => {
  const r = await fakeCall('GET', `/api/mail/connections/${connId}/authorize-url`, { user: adminUser });
  assert.strictEqual(r.status, 200);
  const state = new URL(r.body.url).searchParams.get('state');
  assert.ok(state && state.length === 64);
  const row = await db.one('SELECT * FROM oauth_states ORDER BY expires_at DESC LIMIT 1');
  assert.notStrictEqual(row.state_hash, state); // plaintext never stored
  assert.strictEqual(row.state_hash, cryptoCore.sha256(Buffer.from(state)));
  // consume once
  const cb1 = await fakeCall('GET', '/oauth/callback', { user: adminUser, search: `?code=fake-code&state=${state}` });
  assert.ok(cb1.status === 302 || cb1.streamed);
  // replay rejected
  const cb2 = await fakeCall('GET', '/oauth/callback', { user: adminUser, search: `?code=fake-code&state=${state}` });
  assert.strictEqual(cb2.status, 403);
  // expired state rejected
  const r2 = await fakeCall('GET', `/api/mail/connections/${connId}/authorize-url`, { user: adminUser });
  const state2 = new URL(r2.body.url).searchParams.get('state');
  await db.q("UPDATE oauth_states SET expires_at = now() - interval '1 minute' WHERE state_hash = $1", [cryptoCore.sha256(Buffer.from(state2))]);
  const cb3 = await fakeCall('GET', '/oauth/callback', { user: adminUser, search: `?code=fake-code&state=${state2}` });
  assert.strictEqual(cb3.status, 403);
});

// ---------- discovery ----------
test('discovery: 20 fixture shared mailboxes, no duplicates, alias uniqueness', async () => {
  const zoho = await ZohoClient.forConnection(connId);
  const discovery = await detection.discoverOrganization(zoho);
  for (const mb of discovery.mailboxes) {
    const caps = await detection.probeCapabilities(zoho, mb);
    const choice = detection.chooseStrategy(mb, caps);
    const id = await detection.upsertMailbox(connId, mb, caps, choice);
    byAddress[mb.address] = { id, mb, caps, choice };
  }
  assert.strictEqual((await db.one("SELECT COUNT(*)::int n FROM mailboxes WHERE detected_type='shared_mailbox'")).n, 20);
  for (const mb of discovery.mailboxes) {
    const caps = await detection.probeCapabilities(zoho, mb);
    await detection.upsertMailbox(connId, mb, caps, detection.chooseStrategy(mb, caps));
  }
  assert.strictEqual((await db.one('SELECT COUNT(*)::int n FROM mailboxes')).n, 21);
  const alias = await db.one("SELECT mailbox_id FROM mailbox_aliases WHERE address='contact@exoticcolors.org'");
  assert.strictEqual(Number(alias.mailbox_id), byAddress['info@exoticcolors.org'].id);
});

// ---------- canonical + occurrences ----------
test('canonical model: same message in two mailboxes = 1 canonical, 2 occurrences (nothing lost)', async () => {
  const info = byAddress['info@exoticcolors.org'];
  const hr = byAddress['hr@exoticcolors.org'];
  const fInfo = await sync.upsertFolder(info.id, { providerFolderId: 't-inbox', name: 'Inbox', type: 'inbox' });
  const fHr = await sync.upsertFolder(hr.id, { providerFolderId: 't-inbox', name: 'Inbox', type: 'inbox' });
  const msg = { providerMessageId: 'x-100', rfcMessageId: '<x-100@corp>', from: 'a@b.c', fromName: 'A',
    subject: 'Shared thread', snippet: 'hello', receivedAt: Date.now(), direction: 'in' };
  const r1 = await sync.insertMessage(info.id, fInfo, msg);
  const r2 = await sync.insertMessage(hr.id, fHr, { ...msg, providerMessageId: 'y-200' });
  assert.strictEqual(r1.canonicalId, r2.canonicalId);       // one canonical
  assert.ok(r1.occurrenceId && r2.occurrenceId);            // two occurrences
  assert.ok(r1.isNewCanonical && !r2.isNewCanonical);
  // duplicate occurrence in the same folder is rejected, occurrence count stays 2
  const r3 = await sync.insertMessage(hr.id, fHr, { ...msg, providerMessageId: 'y-200' });
  assert.strictEqual(r3.occurrenceId, null);
  const n = await db.one('SELECT COUNT(*)::int n FROM message_occurrences WHERE canonical_message_id = $1', [r1.canonicalId]);
  assert.strictEqual(n.n, 2);
});

// ---------- sync jobs ----------
test('sync jobs: gating, progress, pause blocks parallel start, cancel, resume, dedup', async () => {
  const info = byAddress['info@exoticcolors.org'];
  await assert.rejects(() => sync.syncMailbox(info.id), /not pilot-selected/);
  await db.q('UPDATE mailboxes SET is_pilot=TRUE WHERE id=$1', [info.id]);
  await assert.rejects(() => sync.syncMailbox(info.id), /not explicitly started/);
  await db.q('UPDATE mailboxes SET sync_enabled=TRUE WHERE id=$1', [info.id]);

  const s1 = await sync.syncMailbox(info.id, { maxPages: 1 });          // partial: 200/250
  assert.strictEqual(s1.newOccurrences, 200);
  let job = await db.one('SELECT * FROM sync_jobs WHERE id = $1', [s1.jobId]);
  assert.strictEqual(job.status, 'completed');
  assert.ok(job.imported >= 200 && job.discovered >= 200);

  // pause MID-RUN: start a run, flip the live job to paused, engine stops at a checkpoint
  const delayMs = ms => new Promise(r => setTimeout(r, ms));
  const admin2 = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin2.id]);
  const running = sync.syncMailbox(admin2.id, { maxPages: 5 });
  running.catch(() => {}); // asserted below
  let liveJob = null;
  for (let i = 0; i < 500 && !liveJob; i++) {
    liveJob = await db.one("SELECT id FROM sync_jobs WHERE mailbox_id=$1 AND status='running'", [admin2.id]);
    if (!liveJob) await delayMs(2);
  }
  assert.ok(liveJob, 'live job appeared');
  await sync.setJobControl(Number(liveJob.id), 'paused');
  await assert.rejects(() => running, /paused/);
  // while paused, a parallel start reuses the SAME job (no duplicate active job)
  assert.strictEqual(await sync.createJob(admin2.id, null), Number(liveJob.id));
  // resume completes the run (createJob reuses the paused job directly)
  const resumed = await sync.syncMailbox(admin2.id, { maxPages: 5 });
  assert.ok(resumed.newOccurrences >= 0);
  const finalJob = await db.one('SELECT status FROM sync_jobs WHERE id=$1', [liveJob.id]);
  assert.strictEqual(finalJob.status, 'completed');

  const s2 = await sync.syncMailbox(info.id, { maxPages: 5 });          // resume backfill
  assert.strictEqual(s2.newOccurrences, 50);
  const s3 = await sync.syncMailbox(info.id, { maxPages: 5 });          // idempotent
  assert.strictEqual(s3.newOccurrences, 0);
  // 250 synced + 1 manual occurrence from the canonical-model test
  assert.strictEqual((await db.one('SELECT COUNT(*)::int n FROM message_occurrences WHERE mailbox_id=$1', [info.id])).n, 251);

  // cancel MID-RUN on a fresh mailbox state: cancelled job finishes as cancelled
  await db.q('DELETE FROM sync_state WHERE mailbox_id=$1', [admin2.id]);
  await db.q('DELETE FROM message_occurrences WHERE mailbox_id=$1', [admin2.id]);
  const running2 = sync.syncMailbox(admin2.id, { maxPages: 5 });
  running2.catch(() => {});
  let liveJob2 = null;
  for (let i = 0; i < 500 && !liveJob2; i++) {
    liveJob2 = await db.one("SELECT id FROM sync_jobs WHERE mailbox_id=$1 AND status='running'", [admin2.id]);
    if (!liveJob2) await delayMs(2);
  }
  assert.ok(liveJob2, 'second live job appeared');
  await sync.setJobControl(Number(liveJob2.id), 'cancelled');
  await assert.rejects(() => running2, /cancelled/);
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [liveJob2.id])).status, 'cancelled');
});

// ---------- attachments ----------
test('attachments: MIME detected from bytes, provider MIME distrusted, quarantine on mismatch', async () => {
  assert.strictEqual(detectMime(Buffer.from('%PDF-1.4 test')), 'application/pdf');
  assert.strictEqual(detectMime(Buffer.from([0x50, 0x4b, 3, 4, 0, 0, 0, 0])), 'application/zip');
  assert.strictEqual(sanitizeFilename('../../etc/passwd'), 'passwd');
  const info = byAddress['info@exoticcolors.org'];
  const cm = await db.one('SELECT canonical_message_id AS id FROM message_occurrences WHERE mailbox_id=$1 LIMIT 1', [info.id]);
  // provider claims image/png but bytes are a PDF → quarantined
  await sync.storeAttachment(Number(cm.id), 'p1', 'evil.png', 'image/png', Buffer.from('%PDF-1.4 malicious'));
  const att = await db.one(`SELECT * FROM attachments WHERE canonical_message_id=$1 AND original_filename='evil.png'`, [cm.id]);
  assert.strictEqual(att.detected_mime_type, 'application/pdf');
  assert.strictEqual(att.provider_mime_type, 'image/png');
  assert.strictEqual(att.quarantine_status, 'quarantined');
  // quarantined download denied even with grants
  await auth.setGrant(memberUser.id, info.id, { can_view_messages: true, can_view_attachments: true, can_download_attachments: true });
  const denied = await fakeCall('GET', `/api/mail/attachments/${att.id}`, { user: memberUser });
  assert.strictEqual(denied.status, 423);
});

test('attachments: view/download flags enforced separately; safe headers; Range works', async () => {
  const info = byAddress['info@exoticcolors.org'];
  const att = await db.one(`SELECT a.* FROM attachments a JOIN message_occurrences o ON o.canonical_message_id=a.canonical_message_id
    WHERE o.mailbox_id=$1 AND a.quarantine_status='clean' LIMIT 1`, [info.id]);
  assert.ok(att, 'clean attachment exists from pilot sync');
  // member: view only
  await auth.setGrant(memberUser.id, info.id, { can_view_messages: true, can_view_attachments: true });
  const view = await fakeCall('GET', `/api/mail/attachments/${att.id}`, { user: memberUser });
  assert.strictEqual(view.status, 200);
  assert.strictEqual(view.headers['X-Content-Type-Options'], 'nosniff');
  assert.match(view.headers['Content-Security-Policy'], /sandbox/);
  assert.match(view.headers['Content-Disposition'], /^inline/);
  const dl = await fakeCall('GET', `/api/mail/attachments/${att.id}`, { user: memberUser, search: '?download=1' });
  assert.strictEqual(dl.status, 403); // download flag not granted
  const range = await fakeCall('GET', `/api/mail/attachments/${att.id}`, { user: adminUser, reqHeaders: { range: 'bytes=0-9' } });
  assert.strictEqual(range.status, 206);
  assert.match(String(range.headers['Content-Range']), /^bytes 0-9\//);
});

test('storage contract: putObject/getObject/deleteObject/exists/metadata/signedUrl', async () => {
  const store = new LocalStorage(require('fs').mkdtempSync(path.join(require('os').tmpdir(), 'att-')), { maxBytes: 1024 });
  const { key, sha256: h, size } = store.putObject(Buffer.from('hello'));
  assert.match(key, /^[0-9a-f]{48}$/);
  assert.strictEqual(size, 5);
  assert.strictEqual(h, crypto.createHash('sha256').update('hello').digest('hex'));
  assert.ok(store.exists(key));
  assert.strictEqual(store.metadata(key).size, 5);
  assert.strictEqual(store.signedUrl(key, 60), null);
  assert.throws(() => store.putObject(Buffer.alloc(2048)), /size limit/);
  assert.throws(() => store._resolve('../../etc/passwd'), /Invalid storage key/);
  store.deleteObject(key);
  assert.ok(!store.exists(key));
});

// ---------- search security ----------
test('search: permissions live inside the SQL — no results/counts/snippets leak', async () => {
  await auth.setGrant(memberUser.id, byAddress['info@exoticcolors.org'].id, null); // revoke everything
  const r = await fakeCall('GET', '/api/mail/messages', { user: memberUser, search: '?q=Demo' });
  assert.deepStrictEqual(r.body, []); // zero rows, zero counts, zero snippets
  const admin = await fakeCall('GET', '/api/mail/messages', { user: adminUser, search: '?q=Demo' });
  assert.ok(admin.body.length > 0);
  // direct occurrence access denied
  const denied = await fakeCall('GET', `/api/mail/occurrences/${admin.body[0].occurrence_id}`, { user: memberUser });
  assert.strictEqual(denied.status, 403);
});

// ---------- audit ----------
test('audit: central redaction; no subjects/bodies/tokens stored by sync & message reads', async () => {
  assert.match(sanitizeDetails('refresh_token: abcdef1234567890'), /\[REDACTED\]/);
  assert.match(sanitizeDetails({ password: 'supersecretvalue123' }), /\[REDACTED\]/);
  const rows = await db.all(`SELECT details, target FROM audit_log WHERE action IN ('mail.sync','mail.message.read')`);
  for (const r of rows) {
    assert.ok(!r.details.includes('Demo message'), 'subject leaked into audit');
    assert.ok(!/mock-access-token|Zoho-oauthtoken/.test(r.details + r.target));
  }
});

test('detection evidence sanitized: no tokens in stored reports', async () => {
  const rep = await db.one('SELECT report::text t FROM detection_reports ORDER BY id DESC LIMIT 1');
  assert.ok(!rep.t.includes('mock-access-token') && !rep.t.includes('Zoho-oauthtoken'));
});

// ---------- health ----------
test('health reflects database availability', async () => {
  assert.strictEqual(await db.healthy(), true);
});

after(async () => { await db.closeDb(); });
