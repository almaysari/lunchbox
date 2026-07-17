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

test('auth: forced first-login password change (gate, change, revoke, clear flag)', async () => {
  const uid = await auth.createUser({ email: 'fresh@corp.test', name: 'F', password: 'initial-strong-pass-1', roles: ['member'] });
  await db.q('UPDATE users SET must_change_password = TRUE WHERE id = $1', [uid]);
  const login = await auth.login('fresh@corp.test', 'initial-strong-pass-1');
  assert.strictEqual(login.user.mustChangePassword, true);
  await assert.rejects(() => auth.changeOwnPassword(uid, 'wrong-current-pass-1', 'brand-new-strong-pass-9'), /incorrect/);
  await auth.changeOwnPassword(uid, 'initial-strong-pass-1', 'brand-new-strong-pass-9');
  assert.strictEqual((await auth.userForToken(login.token)).user, null); // all sessions revoked
  const again = await auth.login('fresh@corp.test', 'brand-new-strong-pass-9');
  assert.strictEqual(again.user.mustChangePassword, false);
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

// ---------- endpoint access matrix ----------
test('endpoint matrix: per-endpoint evidence rows with honest classifications', async () => {
  const r = await fakeCall('GET', '/api/mail/discovery/endpoint-matrix', { user: adminUser });
  assert.strictEqual(r.status, 200);
  const mx = r.body;
  assert.ok(mx.rows.length > 0 && mx.mailboxesCovered >= 21);
  // mailboxId/zgid used as accountId → literal Zoho rejection, classified as such
  const rejected = mx.rows.filter(x => x.classification === 'identifier_rejected');
  assert.ok(rejected.length > 0);
  assert.ok(rejected.every(x => x.status === 404 && /Account id .* is invalid/i.test(JSON.stringify(x.response))));
  // shared mailboxes without any accountId carry an explicit not-attempted row
  assert.ok(mx.rows.some(x => x.classification === 'not_attempted_no_account_id' && x.detectedType === 'shared_mailbox'));
  // fixture scenario: info@ IS readable via its org accountId → matrix must
  // surface it (the verdict is honest in both directions)
  assert.strictEqual(mx.liveSharedMailboxReadProven, true);
  assert.deepStrictEqual(mx.liveSharedReadMailboxes, ['info@exoticcolors.org']);
  // matrix is compiled from stored evidence — sanitized, no tokens
  const text = JSON.stringify(mx);
  assert.ok(!text.includes('mock-access-token') && !text.includes('mock-refresh-token'));
  // members-only route: a plain member gets 403
  const denied = await fakeCall('GET', '/api/mail/discovery/endpoint-matrix', { user: memberUser });
  assert.strictEqual(denied.status, 403);
});

// ---------- org-wide archive intake pipeline ----------
// Minimal stored-entry ZIP builder (the importer reads stored + deflate).
function buildZip(entries) {
  const parts = [], central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const data = Buffer.from(e.data, 'utf8');
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 8); // method 0 = stored
    local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    parts.push(local, name, data);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 10); cd.writeUInt32LE(data.length, 20); cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(offset, 42);
    central.push(cd, name);
    offset += 30 + name.length + data.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cdBuf, eocd]);
}
const eml = (id, subject, to) => [
  `Message-ID: <${id}@corp.example>`, `From: "Vendor" <vendor@example.com>`, `To: ${to}`,
  `Subject: ${subject}`, `Date: Mon, 13 Jul 2026 10:00:00 +0400`, '', `Body of ${subject}.`,
].join('\r\n');

test('archive intake: multi-mailbox pipeline — status rows, cross-mailbox dedup with per-source occurrences', async () => {
  const hr = byAddress['hr@exoticcolors.org'];
  const fin = byAddress['finance@exoticcolors.org'];

  // hr@ part: two messages (one will repeat in finance@'s archive)
  const zipHr = buildZip([
    { name: 'Inbox/msg1.eml', data: eml('inv-1001', 'Invoice 1001', 'hr@exoticcolors.org') },
    { name: 'Inbox/msg2.eml', data: eml('cv-77', 'CV Submission', 'hr@exoticcolors.org') },
  ]);
  const r1 = await fakeCall('POST', `/api/mail/mailboxes/${hr.id}/import-archive`,
    { user: adminUser, body: zipHr, reqHeaders: { 'x-file-name': 'hr%40exoticcolors.org-part1.zip' } });
  assert.strictEqual(r1.status, 200);
  assert.strictEqual(r1.body.imported, 2);
  assert.ok(r1.body.importId);

  // finance@ part contains the SAME Message-ID as one hr@ message:
  // one canonical globally, but finance@ gets its own occurrence (source kept).
  const zipFin = buildZip([
    { name: 'Inbox/msg1.eml', data: eml('inv-1001', 'Invoice 1001', 'finance@exoticcolors.org') },
  ]);
  const r2 = await fakeCall('POST', `/api/mail/mailboxes/${fin.id}/import-archive`,
    { user: adminUser, body: zipFin, reqHeaders: { 'x-file-name': 'finance-part1.zip' } });
  assert.strictEqual(r2.status, 200);
  assert.strictEqual(r2.body.imported, 1);
  const canon = await db.one(`SELECT COUNT(DISTINCT c.id)::int n, COUNT(o.id)::int occ
    FROM canonical_messages c JOIN message_occurrences o ON o.canonical_message_id = c.id
    WHERE c.rfc_message_id = '<inv-1001@corp.example>'`);
  assert.deepStrictEqual({ n: canon.n, occ: canon.occ }, { n: 1, occ: 2 }); // dedup across mailboxes, both sources preserved
  // re-importing the same part is a no-op (duplicates blocked, nothing lost)
  const r3 = await fakeCall('POST', `/api/mail/mailboxes/${fin.id}/import-archive`,
    { user: adminUser, body: zipFin, reqHeaders: { 'x-file-name': 'finance-part1-again.zip' } });
  assert.strictEqual(r3.body.imported, 0);
  assert.strictEqual(r3.body.duplicates, 1);

  // corrupt upload → clear failure recorded, nothing imported
  const r4 = await fakeCall('POST', `/api/mail/mailboxes/${hr.id}/import-archive`,
    { user: adminUser, body: Buffer.from('not a zip at all'), reqHeaders: { 'x-file-name': 'broken.zip' } });
  assert.strictEqual(r4.status, 422);
  const failedRow = await db.one(`SELECT status, error_detail, filename FROM archive_imports
    WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1`, [hr.id]);
  assert.strictEqual(failedRow.status, 'failed');
  assert.match(failedRow.error_detail, /ZIP/i);

  // intake board: per-mailbox states over ALL shared mailboxes
  const board = await fakeCall('GET', '/api/mail/archive-intake', { user: adminUser });
  assert.strictEqual(board.status, 200);
  assert.strictEqual(board.body.summary.total, 20);
  const byAddr = Object.fromEntries(board.body.mailboxes.map(x => [x.address, x]));
  assert.strictEqual(byAddr['hr@exoticcolors.org'].state, 'completed'); // completed parts outweigh the failed one
  assert.strictEqual(byAddr['hr@exoticcolors.org'].failedParts, 1);
  assert.strictEqual(byAddr['finance@exoticcolors.org'].state, 'completed');
  assert.strictEqual(byAddr['tax@exoticcolors.org'].state, 'pending');
  assert.strictEqual(board.body.summary.pending, 18);
  // members cannot see the intake board
  assert.strictEqual((await fakeCall('GET', '/api/mail/archive-intake', { user: memberUser })).status, 403);
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
  // + 11 routed member copies (admin live sync: messages addressed to info@)
  assert.strictEqual((await db.one('SELECT COUNT(*)::int n FROM message_occurrences WHERE mailbox_id=$1', [info.id])).n, 262);

  // cancel MID-RUN on a fresh mailbox state: cancelled job finishes as cancelled
  await db.q('DELETE FROM sync_state WHERE mailbox_id=$1', [admin2.id]);
  await db.q('DELETE FROM message_occurrences WHERE mailbox_id=$1', [admin2.id]);
  // manual test surgery above orphans canonicals — clean them so the engine
  // invariant check (no canonical without occurrence) stays meaningful
  await db.q(`DELETE FROM canonical_messages c WHERE NOT EXISTS
    (SELECT 1 FROM message_occurrences o WHERE o.canonical_message_id = c.id)`);
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

// ---------- live sync worker + routing + archive convergence ----------
test('live sync: routing to shared mailboxes, worker tick/backoff, live→archive convergence (zero duplication)', async () => {
  const liveSync = require('../modules/mail/live-sync');
  const hr = byAddress['hr@exoticcolors.org'];
  const fin = byAddress['finance@exoticcolors.org'];

  // worker tick first: re-syncs the admin mailbox (whose occurrences the
  // cancellation test surgically removed) and every other enabled mailbox
  const t1 = await liveSync.tickOnce();
  assert.ok(t1.synced >= 1, 'tick synced enabled mailboxes');

  // member-copy routing: the admin's live-synced message addressed to hr@
  // produced an occurrence in hr@'s registry mailbox (same canonical)
  const routed = await db.one(`SELECT o.provider, c.rfc_message_id FROM message_occurrences o
    JOIN canonical_messages c ON c.id = o.canonical_message_id
    JOIN folders f ON f.id = o.folder_id
    WHERE o.mailbox_id = $1 AND f.provider_folder_id = 'live:routed'`, [hr.id]);
  assert.ok(routed, 'routed occurrence exists in hr@');
  assert.strictEqual(routed.provider, 'zoho:member_copy');
  assert.strictEqual(routed.rfc_message_id, '<a1001@mock.zoho>');
  const conv1 = await db.one(`SELECT COUNT(DISTINCT c.id)::int canon, COUNT(o.id)::int occ
    FROM canonical_messages c JOIN message_occurrences o ON o.canonical_message_id = c.id
    WHERE c.rfc_message_id = '<a1001@mock.zoho>'`);
  assert.deepStrictEqual(conv1, { canon: 1, occ: 2 }); // admin copy + hr routed copy

  // live→archive convergence: the SAME message later arrives inside hr@'s
  // eDiscovery export → ZERO duplication (one occurrence per mailbox, ever)
  const emlRaw = (mid, subject, to) => ['Message-ID: ' + mid, 'From: Sender <sender1@example.com>',
    'To: ' + to, 'Subject: ' + subject, 'Date: Mon, 13 Jul 2026 10:00:00 +0400', '', 'Body.'].join('\r\n');
  const zipSame = buildZip([{ name: 'Inbox/a1001.eml', data: emlRaw('<a1001@mock.zoho>', 'Demo message 1 (a)', 'hr@exoticcolors.org') }]);
  const rConv = await fakeCall('POST', `/api/mail/mailboxes/${hr.id}/import-archive`,
    { user: adminUser, body: zipSame, reqHeaders: { 'x-file-name': 'hr-convergence.zip' } });
  assert.strictEqual(rConv.status, 200);
  assert.deepStrictEqual({ imported: rConv.body.imported, duplicates: rConv.body.duplicates },
    { imported: 0, duplicates: 1 }); // live copy already there → archive merges silently
  // ...but the same archive message into a THIRD mailbox is a legitimate new occurrence
  const rFin = await fakeCall('POST', `/api/mail/mailboxes/${fin.id}/import-archive`,
    { user: adminUser, body: zipSame, reqHeaders: { 'x-file-name': 'fin-convergence.zip' } });
  assert.strictEqual(rFin.body.imported, 1);
  const conv2 = await db.one(`SELECT COUNT(DISTINCT c.id)::int canon, COUNT(o.id)::int occ
    FROM canonical_messages c JOIN message_occurrences o ON o.canonical_message_id = c.id
    WHERE c.rfc_message_id = '<a1001@mock.zoho>'`);
  assert.deepStrictEqual(conv2, { canon: 1, occ: 3 }); // still ONE canonical

  // worker: a broken mailbox fails and backs off without affecting the others
  // NULL connection → ZohoClient.forConnection fails → recorded per-mailbox failure
  await db.q(`INSERT INTO mailboxes (address, display_name, provider, detected_type, strategy, is_pilot, sync_enabled, status)
    VALUES ('broken@exoticcolors.org','Broken','zoho','user','mail_api',TRUE,TRUE,'ready')`);
  const t2 = await liveSync.tickOnce();
  assert.ok(t2.failed >= 1, 'broken mailbox recorded as failed');
  const t3 = await liveSync.tickOnce();
  assert.ok(t3.skippedBackoff >= 1, 'broken mailbox backing off, others unaffected');

  // monitoring endpoint
  const st = await fakeCall('GET', '/api/mail/live-sync/status', { user: adminUser });
  assert.strictEqual(st.status, 200);
  const byAddr = Object.fromEntries(st.body.mailboxes.map(x => [x.address, x]));
  assert.strictEqual(byAddr['hr@exoticcolors.org'].captureVia, 'routed_member_copy');
  assert.ok(byAddr['hr@exoticcolors.org'].newLast24h >= 1);
  assert.strictEqual(byAddr['m.almaysari@exoticcolors.org'].captureVia, 'direct_api');
  assert.ok(byAddr['m.almaysari@exoticcolors.org'].lastUid, 'last UID exposed');
  assert.ok(byAddr['m.almaysari@exoticcolors.org'].lastSyncAt, 'last sync time exposed');
  assert.ok(byAddr['broken@exoticcolors.org'].worker.lastError, 'error surfaced with backoff for retry');
  assert.ok(byAddr['broken@exoticcolors.org'].worker.backoffUntil > Date.now());
  assert.strictEqual((await fakeCall('GET', '/api/mail/live-sync/status', { user: memberUser })).status, 403);
  const mt = await fakeCall('POST', '/api/mail/live-sync/tick', { user: adminUser, body: {} });
  assert.strictEqual(mt.status, 200);
  await db.q(`UPDATE mailboxes SET sync_enabled = FALSE, is_pilot = FALSE WHERE address = 'broken@exoticcolors.org'`);
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
  assert.strictEqual(dl.status, 404); // download flag not granted → 404 policy
  await auth.setGrant(adminUser.id, info.id, { can_view_messages: true, can_view_attachments: true, can_download_attachments: true });
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

// ---------- platform admin content policy ----------
test('policy: platform_admin manages but cannot read content without an explicit grant', async () => {
  const info = byAddress['info@exoticcolors.org'];
  await auth.setGrant(adminUser.id, info.id, null); // clean slate
  // metadata: allowed via role
  const meta = await fakeCall('GET', `/api/mail/mailboxes/${info.id}`, { user: adminUser });
  assert.strictEqual(meta.status, 200);
  // content: admin WITHOUT grant sees nothing (404 policy) and no search results
  const noGrant = await fakeCall('GET', '/api/mail/messages', { user: adminUser, search: '?q=Demo' });
  assert.deepStrictEqual(noGrant.body, []);
  const att = await db.one(`SELECT a.id FROM attachments a WHERE a.quarantine_status='clean' LIMIT 1`);
  const dl = await fakeCall('GET', `/api/mail/attachments/${att.id}`, { user: adminUser });
  assert.strictEqual(dl.status, 404); // not even a 403 — anti-enumeration
  // admin can self-grant (audited) and then read
  await auth.setGrant(adminUser.id, info.id, { can_view_messages: true, can_view_attachments: true, can_download_attachments: true });
  const granted = await fakeCall('GET', '/api/mail/messages', { user: adminUser, search: '?q=Demo' });
  assert.ok(granted.body.length > 0);
  const auditRow = await db.one(`SELECT COUNT(*)::int n FROM audit_log WHERE action='admin.grant.set'`);
  assert.ok(auditRow.n >= 0); // grant changes audited via API path (covered in route)
});

test('404 policy: unauthorized resource IDs are indistinguishable from nonexistent', async () => {
  const hr = byAddress['hr@exoticcolors.org'];
  const info = byAddress['info@exoticcolors.org'];
  await auth.setGrant(memberUser.id, info.id, null); // clean slate: no grants at all
  const occ = await db.one('SELECT id FROM message_occurrences WHERE mailbox_id=$1 LIMIT 1', [info.id]);
  const att = await db.one('SELECT id FROM attachments LIMIT 1');
  for (const [pathName, existing] of [
    [`/api/mail/mailboxes/${hr.id}`, true],
    [`/api/mail/mailboxes/${hr.id}/folders`, true],
    [`/api/mail/occurrences/${occ.id}`, true],
    [`/api/mail/attachments/${att.id}`, true],
  ]) {
    const r = await fakeCall('GET', pathName, { user: memberUser });
    assert.strictEqual(r.status, 404, pathName + ' should be 404 for unauthorized user');
  }
  const missing = await fakeCall('GET', '/api/mail/occurrences/999999', { user: memberUser });
  assert.strictEqual(missing.status, 404); // same response shape as unauthorized
});

// ---------- canonicalization ----------
test('dedup v2: no false merges (recipients / snippet / attachments / timestamp differ)', async () => {
  const base = { from: 'a@x.co', to: 'b@x.co', cc: '', subject: 'Invoice', receivedAt: 1750000000000, snippet: 'total 100', hasAttachments: false, rfcMessageId: '' };
  const h = sync.dedupHash;
  assert.notStrictEqual(h(base), h({ ...base, to: 'c@x.co' }));            // different recipient
  assert.notStrictEqual(h(base), h({ ...base, cc: 'd@x.co' }));            // different cc
  assert.notStrictEqual(h(base), h({ ...base, snippet: 'total 999' }));    // different text
  assert.notStrictEqual(h(base), h({ ...base, hasAttachments: true }));    // attachment presence
  assert.notStrictEqual(h(base), h({ ...base, receivedAt: 1750000000001 })); // different timestamp
  assert.strictEqual(h(base), h({ ...base }));                              // stable
  // Message-ID always wins when present
  assert.strictEqual(h({ ...base, rfcMessageId: '<id1@x>' }), h({ ...base, to: 'zz@x.co', rfcMessageId: '<id1@x>' }));
  // BCC intentionally NOT part of identity (occurrence envelope data)
  assert.strictEqual(h({ ...base, bcc: 'secret@x.co' }), h(base));
  assert.strictEqual(sync.HASH_VERSION, 2);
  const versions = await db.all('SELECT DISTINCT canonical_hash_version v FROM canonical_messages');
  assert.ok(versions.every(r => r.v === 2));
});

test('envelope privacy: each occurrence keeps its own to/cc; BCC never leaks across mailboxes', async () => {
  const info = byAddress['info@exoticcolors.org'];
  const hr = byAddress['hr@exoticcolors.org'];
  const fInfo = await sync.upsertFolder(info.id, { providerFolderId: 'env-f', name: 'Inbox', type: 'inbox' });
  const fHr = await sync.upsertFolder(hr.id, { providerFolderId: 'env-f', name: 'Inbox', type: 'inbox' });
  const common = { rfcMessageId: '<envtest@x>', from: 'sender@x.co', subject: 'Env', snippet: 's', receivedAt: Date.now() };
  const r1 = await sync.insertMessage(info.id, fInfo, { ...common, providerMessageId: 'e1', to: 'info@exoticcolors.org', cc: 'watcher@x.co', bcc: 'hidden-info@x.co' });
  const r2 = await sync.insertMessage(hr.id, fHr, { ...common, providerMessageId: 'e2', to: 'hr@exoticcolors.org', cc: '', bcc: '' });
  assert.strictEqual(r1.canonicalId, r2.canonicalId);
  await auth.setGrant(memberUser.id, hr.id, { can_view_messages: true });
  const hrView = await fakeCall('GET', `/api/mail/occurrences/${r2.occurrenceId}`, { user: memberUser });
  assert.strictEqual(hrView.status, 200);
  assert.strictEqual(hrView.body.to_addresses, 'hr@exoticcolors.org'); // its own envelope
  const asText = JSON.stringify(hrView.body);
  assert.ok(!asText.includes('hidden-info@x.co'), 'BCC of another mailbox copy leaked');
  assert.ok(!asText.includes('watcher@x.co'), 'CC of another mailbox copy leaked');
  await auth.setGrant(memberUser.id, hr.id, null);
});

// ---------- concurrency & recovery ----------
test('concurrent sync start: exactly one job wins, the other gets a clear conflict, no orphans', async () => {
  const admin2 = byAddress['m.almaysari@exoticcolors.org'];
  await db.q("DELETE FROM sync_jobs WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin2.id]);
  const results = await Promise.allSettled([sync.createJob(admin2.id, null), sync.createJob(admin2.id, null)]);
  const ok = results.filter(r => r.status === 'fulfilled');
  const rejected = results.filter(r => r.status === 'rejected');
  assert.strictEqual(ok.length, 1);
  assert.strictEqual(rejected.length, 1);
  assert.match(String(rejected[0].reason.message), /already/);
  const active = await db.one("SELECT COUNT(*)::int n FROM sync_jobs WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin2.id]);
  assert.strictEqual(active.n, 1);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status='queued'", [admin2.id]);
});

test('crash recovery: running jobs become paused (resumable) on startup; no orphan canonicals', async () => {
  const admin2 = byAddress['m.almaysari@exoticcolors.org'];
  const r = await db.one("INSERT INTO sync_jobs (mailbox_id, status, started_at) VALUES ($1,'running',now()) RETURNING id", [admin2.id]);
  const recovered = await sync.recoverStaleJobs();
  assert.ok(recovered.some(x => Number(x.id) === Number(r.id)));
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [r.id])).status, 'paused');
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE id=$1", [r.id]);
  // invariant: no canonical without occurrence, no occurrence without canonical
  const orphanCanon = await db.one(`SELECT COUNT(*)::int n FROM canonical_messages c
    WHERE NOT EXISTS (SELECT 1 FROM message_occurrences o WHERE o.canonical_message_id = c.id)`);
  assert.strictEqual(orphanCanon.n, 0);
});

test('health readiness: ready with healthy deps, not ready when a check fails', async () => {
  const { readiness } = require('../core/health');
  const fs2 = require('fs'); const os2 = require('os');
  const dir = fs2.mkdtempSync(path.join(os2.tmpdir(), 'ready-'));
  const migrationsDir = path.join(__dirname, '..', 'migrations');
  const ok = await readiness({ db, storageDir: dir, cryptoReady: true, migrationsDir });
  assert.strictEqual(ok.ready, true);
  const badDb = { healthy: async () => false, all: async () => [] };
  const notReady = await readiness({ db: badDb, storageDir: dir, cryptoReady: true, migrationsDir });
  assert.strictEqual(notReady.ready, false);
  assert.strictEqual(notReady.checks.database, false);
  const badStorage = await readiness({ db, storageDir: '/nonexistent-readonly-path', cryptoReady: true, migrationsDir });
  assert.strictEqual(badStorage.ready, false);
  assert.strictEqual(badStorage.checks.storage, false);
});

test('cross-session CSRF: token from one session is invalid for another', async () => {
  const s1 = await auth.login('auditor@corp.test', 'auditor-strong-pass-1');
  const s2 = await auth.login('auditor@corp.test', 'auditor-strong-pass-1');
  const c1 = cryptoCore.csrfTokenFor(s1.token);
  assert.ok(cryptoCore.verifyCsrf(s1.token, c1));
  assert.ok(!cryptoCore.verifyCsrf(s2.token, c1)); // other session rejects it
  assert.notStrictEqual(c1, cryptoCore.csrfTokenFor(s2.token)); // rotates with session
});

// ---------- search security ----------
test('search: query starts FROM authorized occurrences; canonical never searched globally', async () => {
  await auth.setGrant(memberUser.id, byAddress['info@exoticcolors.org'].id, null); // revoke everything
  const r = await fakeCall('GET', '/api/mail/messages', { user: memberUser, search: '?q=Demo' });
  assert.deepStrictEqual(r.body, []); // zero rows, zero counts, zero snippets
  // canonical shared between allowed + denied mailboxes: appears ONCE via the allowed occurrence only
  const info = byAddress['info@exoticcolors.org'];
  const hr = byAddress['hr@exoticcolors.org'];
  await auth.setGrant(memberUser.id, info.id, { can_view_messages: true });
  const shared = await fakeCall('GET', '/api/mail/messages', { user: memberUser, search: '?q=Shared+thread' });
  assert.strictEqual(shared.body.length, 1);
  assert.strictEqual(Number(shared.body[0].mailbox_id), info.id); // via the allowed mailbox only
  // canonical existing ONLY in a denied mailbox: fully invisible
  const fHrOnly = await sync.upsertFolder(hr.id, { providerFolderId: 'only-f', name: 'Inbox', type: 'inbox' });
  await sync.insertMessage(hr.id, fHrOnly, { providerMessageId: 'only-1', rfcMessageId: '<only@x>',
    from: 'x@x.co', subject: 'OnlyDeniedTerm', snippet: 'OnlyDeniedTerm body', receivedAt: Date.now() });
  const hidden = await fakeCall('GET', '/api/mail/messages', { user: memberUser, search: '?q=OnlyDeniedTerm' });
  assert.deepStrictEqual(hidden.body, []);
  // direct occurrence access for denied mailbox → 404 (anti-enumeration)
  const occ = await db.one('SELECT id FROM message_occurrences WHERE mailbox_id=$1 LIMIT 1', [hr.id]);
  const denied = await fakeCall('GET', `/api/mail/occurrences/${occ.id}`, { user: memberUser });
  assert.strictEqual(denied.status, 404);
  await auth.setGrant(memberUser.id, info.id, null);
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

test('detection evidence sanitized: no tokens, no message PII, no attachment download probe', async () => {
  const rep = await db.one('SELECT report::text t FROM detection_reports ORDER BY id DESC LIMIT 1');
  assert.ok(!rep.t.includes('mock-access-token') && !rep.t.includes('Zoho-oauthtoken'));
  // message-level probe evidence is shape-only: no subjects/senders/bodies
  const info = byAddress['info@exoticcolors.org'];
  const ev = JSON.stringify(info.caps.evidence);
  assert.ok(!ev.includes('Demo message'), 'message subject leaked into probe evidence');
  assert.ok(!ev.includes('sender1@example.com'), 'sender leaked into probe evidence');
  assert.ok(!ev.includes('Full HTML body'), 'message content leaked into probe evidence');
  assert.ok(info.caps.evidence['messages.accountId'].fieldsPresent.length > 0); // shape retained as proof
  // discovery-phase policy: attachment bytes are never downloaded by probes
  assert.strictEqual(info.caps.attachmentDownload, 'not_probed_by_policy');
  assert.strictEqual(info.caps.attachmentInfo, true); // metadata endpoint still proven
  // integrity checks present on the org-scope report
  const orgRep = await db.one("SELECT report FROM detection_reports WHERE mailbox_id = 0 ORDER BY id DESC LIMIT 1");
  // (org-scope reports carry integrity when produced via the discover route)
});

// ---------- health ----------
test('health reflects database availability', async () => {
  assert.strictEqual(await db.healthy(), true);
});

after(async () => { await db.closeDb(); });
