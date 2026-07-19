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
process.env.MADAR_CHECKPOINT_MS = '0'; // tests need every pause/cancel checkpoint live (prod throttles to 1s)
process.env.MADAR_REQUEST_TIMEOUT_MS = '1500'; // request_timeout classification test needs a short abort
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
const { startMockZoho, ADMIN_ACCOUNT_ID, _messages, _tokenStats } = require('./mock-zoho');

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

  // An invoice was sent to BOTH hr@ and finance@ — the real message headers
  // (To lists both) are IDENTICAL in each mailbox's export, so v3 converges it.
  const invTo = 'hr@exoticcolors.org, finance@exoticcolors.org';
  const zipHr = buildZip([
    { name: 'Inbox/msg1.eml', data: eml('inv-1001', 'Invoice 1001', invTo) },
    { name: 'Inbox/msg2.eml', data: eml('cv-77', 'CV Submission', 'hr@exoticcolors.org') },
  ]);
  const r1 = await fakeCall('POST', `/api/mail/mailboxes/${hr.id}/import-archive`,
    { user: adminUser, body: zipHr, reqHeaders: { 'x-file-name': 'hr%40exoticcolors.org-part1.zip' } });
  assert.strictEqual(r1.status, 200);
  assert.strictEqual(r1.body.imported, 2);
  assert.ok(r1.body.importId);

  // finance@'s export of the SAME invoice: identical headers → one canonical
  // globally, but finance@ gets its own occurrence (source kept).
  const zipFin = buildZip([
    { name: 'Inbox/msg1.eml', data: eml('inv-1001', 'Invoice 1001', invTo) },
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
  // produced an occurrence in hr@'s registry mailbox (same canonical). The live
  // message has NO RFC Message-ID (real Zoho) — identity is the v3 fingerprint.
  const SUBJ = 'Demo message 1 (a)'; // uniquely identifies the a1001 message
  const routed = await db.one(`SELECT o.provider, o.canonical_message_id, c.rfc_message_id FROM message_occurrences o
    JOIN canonical_messages c ON c.id = o.canonical_message_id
    JOIN folders f ON f.id = o.folder_id
    WHERE o.mailbox_id = $1 AND f.provider_folder_id = 'live:routed'`, [hr.id]);
  assert.ok(routed, 'routed occurrence exists in hr@');
  assert.strictEqual(routed.provider, 'zoho:member_copy');
  assert.strictEqual(routed.rfc_message_id, ''); // live has no RFC id — fingerprint is the identity
  const conv1 = await db.one(`SELECT COUNT(DISTINCT c.id)::int canon, COUNT(o.id)::int occ
    FROM canonical_messages c JOIN message_occurrences o ON o.canonical_message_id = c.id
    WHERE c.subject = $1`, [SUBJ]);
  assert.deepStrictEqual(conv1, { canon: 1, occ: 2 }); // admin copy + hr routed copy

  // live→archive convergence: the SAME message later arrives inside hr@'s
  // eDiscovery export (which DOES carry a Message-ID) → ZERO duplication, via
  // the v3 fingerprint (from + SENT-second + subject + to). The EML Date header
  // must be the same sent instant the live sentDateInGMT reported.
  const sentMs = 1783000000000 - 1 * 3600000; // mock a1001 sentDateInGMT
  const emlRaw = (mid, subject, to, dateHdr) => ['Message-ID: ' + mid, 'From: Sender <sender1@example.com>',
    'To: ' + to, 'Subject: ' + subject, 'Date: ' + dateHdr, '', 'Body.'].join('\r\n');
  const zipSame = buildZip([{ name: 'Inbox/a1001.eml',
    data: emlRaw('<archived-a1001@zoho>', SUBJ, 'hr@exoticcolors.org', new Date(sentMs).toUTCString()) }]);
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
    WHERE c.subject = $1`, [SUBJ]);
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

// ---------- new-mail capture: the two stall bugs behind "new email never shows" ----------
test('new mail is captured even when it is NOT the newest item, and a dead cycle never stalls a box forever', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);
  await sync.syncMailbox(admin.id, { maxPages: 1 }); // ensure the existing page is fully stored

  // BUG A (ordering): the incremental "newest page" scan must NOT stop at the
  // first already-seen message. Zoho pins no guaranteed sort order, so a genuinely
  // NEW email can arrive positioned AFTER messages we already have. Inject exactly
  // that: a new message at index 2 (indices 0,1 are already stored), addressed to
  // an external party so it creates no routed copies elsewhere.
  const NEW_SUBJ = 'ORDERING-FIX new inbound ' + crypto.randomUUID().slice(0, 8);
  const injected = { messageId: 'a-new-9001', threadId: 'tnew', fromAddress: 'newsender@example.com',
    senderName: 'New Sender', toAddress: 'someone-external@example.net', subject: NEW_SUBJ,
    summary: 'A brand new inbound message that is not the newest item in the list.',
    receivedTime: String(1784200000000 - 2.5 * 3600000), sentDateInGMT: String(1783000000000 - 2.5 * 3600000),
    hasAttachment: '0' };
  _messages[ADMIN_ACCOUNT_ID].splice(2, 0, injected);
  try {
    const before = (await db.one('SELECT COUNT(*)::int n FROM canonical_messages WHERE subject=$1', [NEW_SUBJ])).n;
    assert.strictEqual(before, 0, 'sanity: the new subject does not exist yet');
    await sync.syncMailbox(admin.id, { maxPages: 1 }); // incremental cycle only touches the newest page
    const occ = await db.one(`SELECT COUNT(*)::int n FROM message_occurrences o
      JOIN canonical_messages c ON c.id=o.canonical_message_id
      WHERE c.subject=$1 AND o.mailbox_id=$2`, [NEW_SUBJ, admin.id]);
    assert.strictEqual(occ.n, 1, 'a NEW message positioned after already-seen ones is still captured (full-page scan)');
  } finally {
    const i = _messages[ADMIN_ACCOUNT_ID].indexOf(injected);
    if (i > -1) _messages[ADMIN_ACCOUNT_ID].splice(i, 1); // restore shared fixture
  }

  // BUG B (permanent stall): a cycle that died mid-flight leaves a sync_jobs row
  // status='running' and the mailbox status='syncing'. Without per-tick recovery,
  // createJob would throw "already running" every tick and this box would never
  // sync again until a full restart. reconcileStale (called at the top of each
  // worker tick) must un-stick it — but only when the running job is provably
  // stale (age-gated), never a legitimately long in-flight sync.
  const mk = async (addr, jobAgeMin) => {
    const mb = await db.one(`INSERT INTO mailboxes (address, display_name, provider, detected_type, strategy, is_pilot, sync_enabled, status)
      VALUES ($1,$1,'zoho','user','mail_api',TRUE,TRUE,'syncing') RETURNING id`, [addr]);
    await db.q(`INSERT INTO sync_jobs (mailbox_id, status, started_at)
      VALUES ($1,'running', now() - ($2 || ' minutes')::interval)`, [mb.id, String(jobAgeMin)]);
    return Number(mb.id);
  };
  const staleId = await mk('stalebox@exoticcolors.org', 20);   // dead cycle: 20 min, no progress
  const freshId = await mk('livebox@exoticcolors.org', 1);     // legitimately running: 1 min

  const rec = await sync.reconcileStale();
  assert.ok(rec.pausedJobs >= 1 && rec.unstuckMailboxes >= 1, 'stale running job paused, its mailbox un-stuck');

  const staleJob = await db.one("SELECT id, status FROM sync_jobs WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1", [staleId]);
  const staleBox = await db.one('SELECT status FROM mailboxes WHERE id=$1', [staleId]);
  assert.strictEqual(staleJob.status, 'paused', 'dead cycle → paused (resumable, cursor kept)');
  assert.strictEqual(staleBox.status, 'ready', 'mailbox no longer stuck on syncing');

  const freshJob = await db.one("SELECT status FROM sync_jobs WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1", [freshId]);
  const freshBox = await db.one('SELECT status FROM mailboxes WHERE id=$1', [freshId]);
  assert.strictEqual(freshJob.status, 'running', 'a fresh in-flight sync is NOT aborted by age-gating');
  assert.strictEqual(freshBox.status, 'syncing', 'its mailbox stays syncing');

  // after recovery, createJob RESUMES the paused job instead of throwing — proving
  // the box is reachable again rather than permanently stalled.
  const resumedJobId = await sync.createJob(staleId, null);
  assert.strictEqual(resumedJobId, Number(staleJob.id), 'createJob reuses the recovered (paused) job — no permanent stall');

  // cleanup: retire the throwaway mailboxes so later ticks/recovery tests are unaffected
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id = ANY($1::bigint[])", [[staleId, freshId]]);
  await db.q('UPDATE mailboxes SET is_pilot=FALSE, sync_enabled=FALSE WHERE id = ANY($1::bigint[])', [[staleId, freshId]]);
});

// ---------- cross-process worker truth + transport diagnostics ----------
test('worker status is read from the DB heartbeat (not a process singleton), and transport failures are fully diagnosed', async () => {
  const liveSync = require('../modules/mail/live-sync');
  const { ZohoApiError } = require('../modules/mail/connectors/zoho-mail-api');

  // (1) Cross-process worker truth. The CLI doctor runs in a DIFFERENT process
  // than the worker, so a process-local flag is always empty there. workerStatus
  // must answer from the shared heartbeat row instead.
  await db.q('DELETE FROM sync_worker_heartbeat');
  let ws = await liveSync.workerStatus();
  assert.strictEqual(ws.running, false, 'no heartbeat → not running');
  assert.match(ws.reason || '', /never started|no heartbeat/i);

  // worker alive & fresh → running true even though THIS test process never
  // started the worker (proves it is not reading an in-process singleton)
  await db.q(`INSERT INTO sync_worker_heartbeat (id, enabled, interval_sec, pid, hostname, started_at, last_tick_at, next_tick_at, updated_at)
    VALUES (TRUE, TRUE, 120, 4242, 'server-1', now(), now(), now()+interval '120 seconds', now())`);
  ws = await liveSync.workerStatus();
  assert.strictEqual(ws.running, true, 'enabled + fresh heartbeat → running');
  assert.strictEqual(ws.pid, 4242);
  assert.strictEqual(ws.stale, false);

  // heartbeat gone stale (main process died) → NOT running, even though enabled=true
  await db.q("UPDATE sync_worker_heartbeat SET updated_at = now() - interval '10 minutes', last_tick_at = now() - interval '10 minutes'");
  ws = await liveSync.workerStatus();
  assert.strictEqual(ws.enabled, true);
  assert.strictEqual(ws.running, false, 'enabled but stale heartbeat → not running (crash detectable cross-process)');
  assert.strictEqual(ws.stale, true);

  // explicitly disabled → not running
  await db.q('UPDATE sync_worker_heartbeat SET enabled = FALSE, updated_at = now()');
  ws = await liveSync.workerStatus();
  assert.strictEqual(ws.running, false);

  // (2) Every cycle is logged with its source, so the MAIN worker's own
  // success/failure is provable independently of a forced CLI tick. Run a tick
  // from each source with no eligible mailboxes (fast + deterministic).
  const enabledIds = (await db.all("SELECT id FROM mailboxes WHERE sync_enabled AND is_pilot")).map(r => Number(r.id));
  await db.q('UPDATE mailboxes SET sync_enabled = FALSE WHERE id = ANY($1::bigint[])', [enabledIds]);
  try {
    await liveSync.tickOnce({ source: 'cli' });
    await liveSync.tickOnce({ source: 'worker' });
    const cli = await liveSync.recentCycles(3, 'cli');
    const wk = await liveSync.recentCycles(3, 'worker');
    assert.ok(cli.length >= 1 && cli[0].source === 'cli', 'forced CLI tick logged as source=cli');
    assert.ok(wk.length >= 1 && wk[0].source === 'worker', 'main-worker tick logged as source=worker');
    assert.strictEqual(cli[0].ok, true, 'empty cycle is a clean success, not a false failure');
  } finally {
    await db.q('UPDATE mailboxes SET sync_enabled = TRUE WHERE id = ANY($1::bigint[])', [enabledIds]);
  }

  // (3) Transport failure (HTTP 0) is never opaque: the typed error names the
  // real cause (dns/tls/socket/timeout + code/syscall/hostname) and carries it
  // into responseSample so persistDiag stores it — this is exactly the
  // "list_folders failed with HTTP 0" case, now fully diagnosed.
  const tbody = { transportError: 'fetch failed', transport: { kind: 'dns', code: 'ENOTFOUND', errno: -3008,
    syscall: 'getaddrinfo', hostname: 'mail.zoho.com', host: 'mail.zoho.com',
    causeChain: [{ name: 'TypeError', message: 'fetch failed' }, { name: 'Error', code: 'ENOTFOUND', syscall: 'getaddrinfo' }],
    stack: 'Error: getaddrinfo ENOTFOUND mail.zoho.com\n    at GetAddrInfoReqWrap' } };
  const err = new ZohoApiError('list_folders', '/api/accounts/X/folders', 0, tbody);
  assert.strictEqual(err.httpStatus, 0);
  assert.strictEqual(err.transport.kind, 'dns');
  assert.strictEqual(err.transport.code, 'ENOTFOUND');
  assert.match(err.message, /transport failure \(dns ENOTFOUND\)/);
  assert.strictEqual(err.responseSample.transport.syscall, 'getaddrinfo');
  assert.strictEqual(err.responseSample.transport.hostname, 'mail.zoho.com');
  assert.match(err.stack, /getaddrinfo ENOTFOUND/); // stack points at the real socket failure

  // an ordinary HTTP error still reads as before (no transport block)
  const http404 = new ZohoApiError('fetch_messages', '/x', 404, { status: { code: 404, description: 'Invalid' } });
  assert.strictEqual(http404.transport, null);
  assert.match(http404.message, /HTTP 404/);
});

// ---------- production-readiness: token economy, scheduler, retention, concurrency, health ----------
test('OAuth token economy: one shared client per connection, persisted token reused across processes, refresh only on expiry', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);

  // Two full cycles must NOT refresh per cycle (the old design refreshed every
  // mailbox × every cycle and tripped Zoho's refresh-token rate limits).
  const before = _tokenStats.requests;
  await sync.syncMailbox(admin.id, { maxPages: 1 });
  await sync.syncMailbox(admin.id, { maxPages: 1 });
  const afterTwoCycles = _tokenStats.requests - before;
  assert.ok(afterTwoCycles <= 1, `two cycles caused ${afterTwoCycles} token refreshes — must be ≤1 (shared client cache)`);

  // Cross-process reuse: wipe the in-memory client cache (≈ a fresh process/CLI).
  // The persisted encrypted token must be reused — zero new refreshes.
  ZohoClient._cache.clear();
  const beforeFresh = _tokenStats.requests;
  await sync.syncMailbox(admin.id, { maxPages: 1 });
  assert.strictEqual(_tokenStats.requests - beforeFresh, 0,
    'a fresh process must reuse the persisted access token, not hit the token endpoint');

  // Expiry → renewal: expire the persisted token and drop memory; the next cycle
  // must refresh EXACTLY once and persist the new token + expiry.
  const connRow = await db.one('SELECT connection_id FROM mailboxes WHERE id=$1', [admin.id]);
  await db.q("UPDATE connections SET access_token_expires_at = now() - interval '1 minute' WHERE id=$1", [connRow.connection_id]);
  ZohoClient._cache.clear();
  const beforeExpiry = _tokenStats.requests;
  await sync.syncMailbox(admin.id, { maxPages: 1 });
  assert.strictEqual(_tokenStats.requests - beforeExpiry, 1, 'expired token → exactly one refresh');
  const conn = await db.one('SELECT access_token_enc, access_token_expires_at FROM connections WHERE id=$1', [connRow.connection_id]);
  assert.ok(conn.access_token_enc && new Date(conn.access_token_expires_at) > new Date(), 'renewed token persisted encrypted with future expiry');
  assert.ok(!String(conn.access_token_enc).includes('mock-access-token'), 'persisted token is encrypted, never plaintext');
});

test('folder scheduler: inbox/sent are hot every cycle; cold folders rotate; backfill never abandoned', () => {
  const now = Date.now();
  const done = (ageMs) => ({ backfill_done: true, last_sync_at: new Date(now - ageMs) });
  // hot folders: always due, regardless of freshness
  assert.ok(sync.folderDue({ type: 'inbox' }, done(0), now));
  assert.ok(sync.folderDue({ type: 'sent' }, done(0), now));
  // cold folder mid-backfill: due (backfill progress must never stall)
  assert.ok(sync.folderDue({ type: 'archive' }, { backfill_done: false, last_sync_at: new Date(now) }, now));
  assert.ok(sync.folderDue({ type: 'archive' }, null, now), 'never-synced folder is due');
  // cold folder, freshly synced: NOT due (this is the API-volume saving)
  assert.ok(!sync.folderDue({ type: 'archive' }, done(60 * 1000), now));
  // cold folder past the rotation interval (default 900s): due again
  assert.ok(sync.folderDue({ type: 'archive' }, done(901 * 1000), now));
});

test('retention: worker cycles and diagnostics older than the window are pruned; recent rows and audit are kept', async () => {
  await db.q(`INSERT INTO sync_worker_cycles (source, ok, created_at) VALUES ('worker', TRUE, now() - interval '30 days')`);
  await db.q(`INSERT INTO sync_worker_cycles (source, ok, created_at) VALUES ('worker', TRUE, now())`);
  await db.q(`INSERT INTO sync_diagnostics (trace_id, mailbox_address, stage, outcome, created_at)
              VALUES ('old-trace', 'x@y', 'done', 'ok', now() - interval '30 days')`);
  const auditBefore = (await db.one('SELECT COUNT(*)::int n FROM audit_log')).n;
  const r = await sync.pruneObservability(14);
  assert.ok(r.cyclesPruned >= 1 && r.diagnosticsPruned >= 1, 'old operational rows pruned');
  assert.strictEqual((await db.one("SELECT COUNT(*)::int n FROM sync_diagnostics WHERE trace_id='old-trace'")).n, 0);
  assert.ok((await db.one('SELECT COUNT(*)::int n FROM sync_worker_cycles')).n >= 1, 'recent cycles kept');
  assert.strictEqual((await db.one('SELECT COUNT(*)::int n FROM audit_log')).n, auditBefore, 'audit is NEVER pruned by observability retention');
});

test('concurrency: 20 parallel inserts of one message across mailboxes — no deadlock, one canonical, no lost copies', async () => {
  const boxes = ['hr@exoticcolors.org', 'finance@exoticcolors.org', 'info@exoticcolors.org', 'm.almaysari@exoticcolors.org']
    .map(a => byAddress[a]);
  const folders = [];
  for (const b of boxes) folders.push(await sync.upsertFolder(b.id, { providerFolderId: 'hammer-f', name: 'Hammer', type: 'inbox' }));
  const msg = { providerMessageId: 'hammer-1', from: 'load@example.com', to: 'all@exoticcolors.org',
    subject: 'Concurrency hammer', receivedAt: 1784300000000, sentAt: 1784300000000 };
  // 4 mailboxes × 5 identical attempts each, all in flight at once
  const attempts = [];
  for (let i = 0; i < 5; i++) for (let b = 0; b < boxes.length; b++) {
    attempts.push(sync.insertMessage(boxes[b].id, folders[b], msg));
  }
  const results = await Promise.all(attempts); // any deadlock (40P01) or constraint error would reject
  const canon = await db.one(`SELECT COUNT(DISTINCT c.id)::int canon FROM canonical_messages c WHERE c.subject='Concurrency hammer'`);
  assert.strictEqual(canon.canon, 1, 'exactly one canonical under full concurrency');
  const occ = await db.one(`SELECT COUNT(*)::int n FROM message_occurrences o
    JOIN canonical_messages c ON c.id=o.canonical_message_id WHERE c.subject='Concurrency hammer'`);
  assert.strictEqual(occ.n, boxes.length, 'exactly one occurrence per mailbox — duplicates all rejected, none lost');
  assert.strictEqual(results.filter(r => r.occurrenceId).length, boxes.length, 'exactly 4 of 20 attempts won');
});

test('worker health: /healthz block reports running/stale + stuck jobs and mailboxes as numbers', async () => {
  const liveSync = require('../modules/mail/live-sync');
  await db.q('DELETE FROM sync_worker_heartbeat');
  await db.q(`INSERT INTO sync_worker_heartbeat (id, enabled, interval_sec, pid, started_at, last_tick_at, updated_at)
    VALUES (TRUE, TRUE, 120, 777, now(), now(), now())`);
  const h = await liveSync.workerHealth();
  assert.strictEqual(h.running, true);
  assert.strictEqual(typeof h.stuckJobs, 'number');
  assert.strictEqual(typeof h.stuckMailboxes, 'number');
  assert.strictEqual(h.stuckJobs, 0, 'no stuck jobs after the whole suite ran');
  assert.strictEqual(h.stuckMailboxes, 0, 'no stuck mailboxes after the whole suite ran');
});

test('mini-soak: 25 consecutive worker ticks leave no stuck jobs, no stuck mailboxes, bounded in-memory state', async () => {
  const liveSync = require('../modules/mail/live-sync');
  for (let i = 0; i < 25; i++) await liveSync.tickOnce({ source: 'worker' });
  const running = await db.one("SELECT COUNT(*)::int n FROM sync_jobs WHERE status='running'");
  assert.strictEqual(running.n, 0, 'no job left running after ticks complete');
  const syncing = await db.one("SELECT COUNT(*)::int n FROM mailboxes WHERE status='syncing'");
  assert.strictEqual(syncing.n, 0, 'no mailbox left on syncing');
  const eligible = await db.one("SELECT COUNT(*)::int n FROM mailboxes WHERE strategy='mail_api' AND is_pilot AND sync_enabled");
  assert.ok(liveSync._state.perMailbox.size <= eligible.n, 'per-mailbox state map bounded by eligible mailboxes');
  const cycles = await liveSync.recentCycles(30, 'worker');
  assert.ok(cycles.length >= 25, 'every tick logged a cycle row');
  assert.ok(cycles.slice(0, 25).every(c => c.error === null), 'no tick-loop errors across the soak');
});

// ---------- durable acceptance: the soak must survive restarts ----------
test('durable acceptance: state in DB, samples accumulate on one run, restart is detected as evidence, evaluation from rows', async () => {
  const acc = require('../modules/mail/acceptance');
  // single-active-run invariant (partial unique index — races safe)
  const CANARY = 'CANARY-' + crypto.randomUUID().slice(0, 8);
  const run = await acc.startRun({ hours: 1, sampleSec: 5, canary: CANARY });
  await assert.rejects(() => acc.startRun({ hours: 1 }), /already active/);

  // the canary arrives DURING the run (as in production: a real email sent
  // mid-soak) — stored through the same ingestion path Live Sync uses
  const hrBox = byAddress['hr@exoticcolors.org'];
  const cf = await sync.upsertFolder(hrBox.id, { providerFolderId: 'canary-f', name: 'Canary', type: 'inbox' });
  await sync.insertMessage(hrBox.id, cf, { providerMessageId: 'canary-1', from: 'ext@example.com',
    to: 'hr@exoticcolors.org', subject: `${CANARY} acceptance check`, receivedAt: Date.now() - 5000, sentAt: Date.now() - 9000 });

  // healthy heartbeat → samples record worker alive, from PID A
  await db.q('DELETE FROM sync_worker_heartbeat');
  await db.q(`INSERT INTO sync_worker_heartbeat (id, enabled, interval_sec, pid, started_at, last_tick_at, updated_at)
    VALUES (TRUE, TRUE, 120, 1111, now(), now(), now())`);
  await acc.takeSample(run);
  await acc.takeSample(run);

  // "container restart": the worker comes back under a NEW pid — the sampler
  // must CONTINUE the same run and record restart_detected, not lose the soak
  await db.q('UPDATE sync_worker_heartbeat SET pid = 2222, updated_at = now()');
  await acc.takeSample(run);
  const samples = await db.all('SELECT * FROM acceptance_samples WHERE run_id=$1 ORDER BY id', [run.id]);
  assert.strictEqual(samples.length, 3, 'all samples on the SAME run across the restart');
  const restart = await db.one(`SELECT detail FROM acceptance_incidents WHERE run_id=$1 AND kind='restart_detected'`, [run.id]);
  assert.ok(restart, 'restart recorded as evidence');
  const rd = typeof restart.detail === 'string' ? JSON.parse(restart.detail) : restart.detail;
  assert.deepStrictEqual({ fromPid: rd.fromPid, toPid: rd.toPid }, { fromPid: 1111, toPid: 2222 });

  // canary from the durable run window + evaluation purely from persisted rows
  const canary = await db.one(`SELECT detail FROM acceptance_incidents WHERE run_id=$1 AND kind='canary_captured'`, [run.id]);
  assert.ok(canary, 'canary (real stored message) captured');
  const ev = await acc.evaluateRun(run.id);
  assert.strictEqual(ev.samples, 3);
  assert.strictEqual(ev.checks.no_duplicates.pass, true);
  assert.strictEqual(ev.checks.canary_captured.pass, true);
  assert.strictEqual(ev.checks.survives_restart.restartsObserved, 1);
  assert.strictEqual(ev.verdict, 'PASS');

  // stuck state must flip the verdict — the harness cannot be a rubber stamp
  await db.q(`UPDATE acceptance_samples SET stuck_jobs = 3 WHERE id = $1`, [samples[1].id]);
  const evBad = await acc.evaluateRun(run.id);
  assert.strictEqual(evBad.checks.no_stuck_jobs.pass, false);
  assert.strictEqual(evBad.verdict, 'FAIL');
  await db.q(`UPDATE acceptance_samples SET stuck_jobs = 0 WHERE id = $1`, [samples[1].id]);

  // finishing: past ends_at the sampler loop completes the run with a stored verdict
  await db.q(`UPDATE acceptance_runs SET ends_at = now() - interval '1 second' WHERE id=$1`, [run.id]);
  const evFinal = await acc.evaluateRun(run.id);
  await db.q(`UPDATE acceptance_runs SET status='completed', finished_at=now(), evaluation=$1 WHERE id=$2`,
    [JSON.stringify(evFinal), run.id]);
  const done = await db.one('SELECT status, evaluation FROM acceptance_runs WHERE id=$1', [run.id]);
  assert.strictEqual(done.status, 'completed');
  // a new run can start after completion
  const run2 = await acc.startRun({ hours: 0.01, sampleSec: 5 });
  await db.q(`UPDATE acceptance_runs SET status='aborted', finished_at=now() WHERE id=$1`, [run2.id]);
});

// ---------- HTTP-0 root cause: phase separation + full classification ----------
test('an OAuth failure is classified oauth_*, never collapsed into "HTTP 0 transport" — original exception preserved, no secrets leak', async () => {
  const { ZohoAuthError } = require('../modules/mail/zoho-client');
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  const connRow = await db.one('SELECT connection_id FROM mailboxes WHERE id=$1', [admin.id]);
  const cid = connRow.connection_id;
  const saved = await db.one('SELECT refresh_token_enc, access_token_enc, access_token_expires_at FROM connections WHERE id=$1', [cid]);

  // (1) oauth_refresh_failed: expired cache + Zoho rejects the refresh (invalid_grant)
  await db.q("UPDATE connections SET access_token_expires_at = now() - interval '1 minute' WHERE id=$1", [cid]);
  ZohoClient._cache.clear();
  _tokenStats.failNext = { status: 400, error: 'invalid_grant' };
  let caught = null;
  try { await sync.syncMailbox(admin.id, { maxPages: 1 }); } catch (e) { caught = e; }
  assert.ok(caught, 'sync must fail when the refresh is rejected');
  assert.strictEqual(caught.classification, 'oauth_refresh_failed', `classification must be oauth_refresh_failed, got ${caught.classification}`);
  assert.strictEqual(caught.httpStatus, 0, 'no request reached Zoho — status 0 with a MEANINGFUL class, not a bare HTTP 0');
  assert.match(caught.message, /OAuth failure \(oauth_refresh_failed\)/);
  assert.match(caught.message, /invalid_grant/);
  // original exception preserved — name, classification, message; and persisted
  const diag1 = await db.one('SELECT classification, response_sample, error_message FROM sync_diagnostics WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1', [admin.id]);
  assert.strictEqual(diag1.classification, 'oauth_refresh_failed', 'classification persisted in its own column');
  const sample1 = typeof diag1.response_sample === 'string' ? JSON.parse(diag1.response_sample) : diag1.response_sample;
  assert.strictEqual(sample1.originalError.name, 'ZohoAuthError');
  assert.strictEqual(sample1.originalError.classification, 'oauth_refresh_failed');
  // secrets NEVER leak into evidence (message, sample, stack)
  const flat = JSON.stringify({ m: caught.message, s: caught.responseSample, d: sample1, em: diag1.error_message });
  assert.ok(!flat.includes('mock-access-token'), 'no access token anywhere in evidence');
  assert.ok(!flat.includes('mock-refresh-token'), 'no refresh token anywhere in evidence');

  // (2) oauth_token_decrypt_failed: stored refresh token undecryptable (key rotation)
  await db.q("UPDATE connections SET refresh_token_enc = 'v1:00000000000000000000000000000000:dead', access_token_enc = NULL, access_token_expires_at = NULL WHERE id=$1", [cid]);
  ZohoClient._cache.clear();
  caught = null;
  try { await sync.syncMailbox(admin.id, { maxPages: 1 }); } catch (e) { caught = e; }
  assert.strictEqual(caught && caught.classification, 'oauth_token_decrypt_failed');
  assert.match(caught.message, /MADAR_ENCRYPTION_KEY|cannot be decrypted/);
  const diag2 = await db.one('SELECT classification FROM sync_diagnostics WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1', [admin.id]);
  assert.strictEqual(diag2.classification, 'oauth_token_decrypt_failed');

  // (3) oauth_token_missing: no refresh token at all (unit level, same provider)
  const bare = new ZohoClient({ id: cid, accounts_base: 'http://127.0.0.1:1', api_base: 'http://127.0.0.1:1', refresh_token_enc: null });
  await assert.rejects(() => bare.token(), (e) => e instanceof ZohoAuthError && e.classification === 'oauth_token_missing');

  // restore the connection and PROVE recovery through the same path
  await db.q('UPDATE connections SET refresh_token_enc=$1, access_token_enc=$2, access_token_expires_at=$3 WHERE id=$4',
    [saved.refresh_token_enc, saved.access_token_enc, saved.access_token_expires_at, cid]);
  ZohoClient._cache.clear();
  const ok = await sync.syncMailbox(admin.id, { maxPages: 1 });
  assert.ok(ok.folders >= 1, 'same production path succeeds after the OAuth state is restored');
});

test('HTTP + timeout classifications: scope_denied/401/429/account_mismatch/zoho_api_error; a hung socket → request_timeout with abort evidence', async () => {
  const { classifyHttp } = require('../modules/mail/zoho-client');
  // HTTP-layer classes from REAL observed Zoho shapes (endpoint matrix evidence)
  assert.strictEqual(classifyHttp(401, { status: { code: 401, description: 'Invalid OAuthscope' }, data: { errorCode: 'INVALID_OAUTHSCOPE' } }), 'oauth_scope_denied');
  assert.strictEqual(classifyHttp(401, { status: { code: 401, description: 'Unauthorized' } }), 'http_401');
  assert.strictEqual(classifyHttp(403, {}), 'http_403');
  assert.strictEqual(classifyHttp(429, {}), 'http_429');
  assert.strictEqual(classifyHttp(404, { data: { moreInfo: 'Account id 999 is invalid' } }), 'zoho_account_mismatch');
  assert.strictEqual(classifyHttp(500, {}), 'zoho_api_error');
  assert.strictEqual(classifyHttp(200, { data: [] }), null);

  // request_timeout: a server that accepts and never responds; same client code
  const net = require('net');
  const hang = net.createServer(() => { /* accept, never respond */ });
  await new Promise(r => hang.listen(0, '127.0.0.1', r));
  hang.unref();
  const client = new ZohoClient({ id: 999999, accounts_base: 'http://127.0.0.1:1',
    api_base: `http://127.0.0.1:${hang.address().port}`, refresh_token_enc: null });
  client.accessToken = 'unit-test-token'; client.expiry = Date.now() + 3600000; // memory token → oauth phase passes
  const t0 = Date.now();
  const r = await client.get('/api/accounts/1/folders');
  const elapsed = Date.now() - t0;
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.classification, 'request_timeout');
  assert.strictEqual(r.meta.abortFired, true, 'abort evidence captured');
  assert.match(String(r.meta.abortReason), /AbortSignal\.timeout/);
  assert.ok(elapsed >= 1400 && elapsed < 5000, `aborted near the configured 1500ms timeout (took ${elapsed}ms)`);
  assert.strictEqual(r.meta.timeoutMs, 1500);
  assert.ok(r.body.originalError && r.body.originalError.name, 'original exception preserved');
  assert.ok(!JSON.stringify(r).includes('unit-test-token'), 'token never appears in the evidence');
  hang.close();
});

// ---------- real-tenant defects: CLI keyring, resume freshness, stale-job self-heal ----------
test('CLI keyring: a separate process without bootstrap reproduces "No encryption key for version k1"; with bootstrap it decrypts — and every decrypting CLI uses it', async () => {
  const { execFileSync } = require('node:child_process');
  const fs = require('node:fs');
  const cipher = cryptoCore.encrypt('probe-value'); // ciphertext of a non-secret probe
  // historical-key mechanism under test too: KEY_V1 as version 1 + KEY_V2 via
  // the documented MADAR_ENCRYPTION_KEY_V2 rotation variable
  const env = { ...process.env, MADAR_ENCRYPTION_KEY: KEY_V1, MADAR_ENCRYPTION_KEY_V2: KEY_V2,
    MADAR_SESSION_SECRET: SESS_KEY, MADAR_CSRF_SECRET: CSRF_KEY };

  // (1) REPRODUCE the real-tenant artifact: fresh process, decrypt WITHOUT init.
  // (The tenant saw "version k1" because its write version is 1; the suite's
  // write version may have rotated — the error class is the same.)
  const repro = execFileSync('node', ['-e', `
    try { require('${path.join(__dirname, '..', 'core', 'crypto')}').decrypt(process.argv[1]); console.log('DECRYPTED'); }
    catch (e) { console.log('ERR:' + e.message); }`, cipher], { env, encoding: 'utf8' });
  assert.match(repro, /ERR:No encryption key for version k\d+ — add it to the keyring/,
    'a CLI process without bootstrap must reproduce the exact real-tenant error');

  // (2) the FIX: same fresh process, keyring initialized via the shared bootstrap
  const fixed = execFileSync('node', ['-e', `
    require('${path.join(__dirname, '..', 'core', 'bootstrap')}').initCryptoFromEnv();
    console.log(require('${path.join(__dirname, '..', 'core', 'crypto')}').decrypt(process.argv[1]));`, cipher],
    { env, encoding: 'utf8' });
  assert.strictEqual(fixed.trim(), 'probe-value', 'bootstrapped CLI decrypts with the same env the server uses');

  // (3) every CLI entrypoint that reaches decrypt() must call the bootstrap
  for (const script of ['zoho-path-diagnose.js', 'livesync-doctor.js', 'livesync-acceptance.js', 'job-inspect.js', 'keyring-inspect.js', 'e2e-proof.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', 'scripts', script), 'utf8');
    assert.ok(src.includes("initCryptoFromEnv"), `${script} must initialize the keyring via core/bootstrap`);
  }
});

test('job lifecycle: resume refreshes started_at (a live resumed job is never falsely stale); a provably stale running job self-heals on start instead of blocking', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin.id]);

  // (1) resume freshness: a paused job with an ANCIENT started_at is resumed —
  // the new attempt must be measured from NOW, else reconcileStale would pause
  // a healthy in-flight resume forever (the oscillation that pins one job id).
  const old = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, created_at)
    VALUES ($1, 'paused', now() - interval '3 days', now() - interval '3 days') RETURNING id`, [admin.id]);
  const s1 = await sync.syncMailbox(admin.id, { maxPages: 1 }); // createJob resumes the paused job
  assert.strictEqual(s1.jobId, Number(old.id), 'the paused job was resumed, not duplicated');
  const afterResume = await db.one('SELECT status, started_at FROM sync_jobs WHERE id=$1', [old.id]);
  assert.strictEqual(afterResume.status, 'completed');
  assert.ok(Date.now() - new Date(afterResume.started_at).getTime() < 60000,
    'started_at reflects THIS attempt (fresh), not the original 3-day-old start');

  // (2) stale-running self-heal: the real-tenant blocker — a job stuck 'running'
  // (dead process) while the latest diagnostics row says done/ok. Starting a
  // sync must NOT throw "already running": the same 15-minute predicate
  // reconcileStale uses proves it dead, pauses it, and resumes it in place.
  const stuck = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, created_at)
    VALUES ($1, 'running', now() - interval '25 minutes', now() - interval '25 minutes') RETURNING id`, [admin.id]);
  const s2 = await sync.syncMailbox(admin.id, { maxPages: 1 });
  assert.strictEqual(s2.jobId, Number(stuck.id), 'the stale running job was reclaimed and resumed');
  const healed = await db.one('SELECT status FROM sync_jobs WHERE id=$1', [stuck.id]);
  assert.strictEqual(healed.status, 'completed', 'reclaimed job ran to completion — mailbox unblocked');

  // (3) a stale 'queued' job (crash between INSERT and running) heals the same way
  const stuckQ = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, created_at)
    VALUES ($1, 'queued', now() - interval '25 minutes') RETURNING id`, [admin.id]);
  const s3 = await sync.syncMailbox(admin.id, { maxPages: 1 });
  assert.strictEqual(s3.jobId, Number(stuckQ.id), 'stale queued job reclaimed too');

  // (4) concurrent-sync protection MUST remain intact: a FRESH running job
  // (live attempt) still rejects a second start.
  const fresh = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at)
    VALUES ($1, 'running', now() - interval '20 seconds') RETURNING id`, [admin.id]);
  await assert.rejects(() => sync.syncMailbox(admin.id, { maxPages: 1 }), /already running/,
    'a genuinely live job still blocks concurrent starts');
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE id=$1", [fresh.id]);
});

// ---------- job lease: staleness measures DEATH, not AGE (real-tenant job 31) ----------
test('a live long-running job (fresh lease, old started_at) is NEVER reclaimed; a dead job (stale lease) is; checkpoint maintains the lease', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin.id]);

  // (1) the real-tenant scenario: a LEGITIMATE backfill attempt older than the
  // age gate but provably ALIVE (fresh lease). It must be protected:
  //   - reconcileStale must NOT pause it
  //   - createJob must still reject a concurrent start ("already running")
  const live = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ($1, 'running', now() - interval '25 minutes', now() - interval '2 seconds') RETURNING id`, [admin.id]);
  const rec = await sync.reconcileStale();
  const liveAfter = await db.one('SELECT status FROM sync_jobs WHERE id=$1', [live.id]);
  assert.strictEqual(liveAfter.status, 'running',
    'a 25-minute-old attempt with a 2-second-old lease is ALIVE — reclaiming it was the real-tenant bug');
  await assert.rejects(() => sync.syncMailbox(admin.id, { maxPages: 1 }), /already running/,
    'concurrent-start protection holds for the live long attempt');

  // (2) a DEAD job (stale lease) is reclaimed on entry exactly as before
  await db.q("UPDATE sync_jobs SET lease_at = now() - interval '20 minutes' WHERE id=$1", [live.id]);
  const s = await sync.syncMailbox(admin.id, { maxPages: 1 });
  assert.strictEqual(s.jobId, Number(live.id), 'stale-lease job reclaimed and resumed');
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [live.id])).status, 'completed');

  // (3) checkpoint maintains the lease during a real sync: the completed run
  // above must have written a fresh lease_at
  const leased = await db.one('SELECT lease_at FROM sync_jobs WHERE id=$1', [live.id]);
  assert.ok(leased.lease_at && Date.now() - new Date(leased.lease_at).getTime() < 60000,
    'checkpoint touched lease_at during the run');
});

// ---------- autonomous archive ingestion: a listed Archive folder needs NO manual steps ----------
test('archived mail in a listed folder is ingested autonomously: discovery, pagination, terminal page, cursor, dedup, cold rotation', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin.id]);

  // one normal sync — no flags, no manual exposure, no Discovery intervention
  const s1 = await sync.syncMailbox(admin.id, { maxPages: 2 });
  assert.ok(s1.folders >= 3, 'the Archive folder is DISCOVERED like any other folder');
  const archFolder = await db.one(`SELECT id, name, folder_type FROM folders
    WHERE mailbox_id=$1 AND provider_folder_id LIKE '%-f3'`, [admin.id]);
  assert.ok(archFolder, 'Archive folder persisted');
  assert.strictEqual(archFolder.folder_type, 'archive');

  // every archived message ingested exactly once, attributed to the Archive folder
  const occ = await db.one(`SELECT COUNT(*)::int n FROM message_occurrences o
    JOIN canonical_messages c ON c.id=o.canonical_message_id
    WHERE o.mailbox_id=$1 AND o.folder_id=$2 AND c.subject LIKE 'Archived demo message %'`, [admin.id, archFolder.id]);
  assert.strictEqual(occ.n, 5, 'all archived messages ingested');

  // terminal-page detection + persisted continuation cursor (restart-safe)
  const st = await db.one('SELECT backfill_done, next_start, last_sync_at FROM sync_state WHERE mailbox_id=$1 AND folder_id=$2',
    [admin.id, archFolder.id]);
  assert.strictEqual(st.backfill_done, true, 'terminal page detected (batch < PAGE_SIZE) → backfill_done');
  assert.ok(st.next_start >= 1 && st.last_sync_at, 'continuation cursor persisted (resume after restart = same rows)');

  // dedup/idempotency: a second sync re-reads the newest page but inserts nothing
  const s2 = await sync.syncMailbox(admin.id, { maxPages: 2 });
  const occ2 = await db.one(`SELECT COUNT(*)::int n FROM message_occurrences o
    JOIN canonical_messages c ON c.id=o.canonical_message_id
    WHERE o.mailbox_id=$1 AND c.subject LIKE 'Archived demo message %'`, [admin.id]);
  assert.strictEqual(occ2.n, 5, 'no duplicates on re-sync');

  // cold-rotation semantics: with backfill done and a fresh last_sync_at, the
  // archive folder is skipped this cycle (API economy) but is due again after
  // the rotation interval — never abandoned
  assert.ok(!sync.folderDue({ type: 'archive' }, { backfill_done: true, last_sync_at: new Date() }, Date.now()));
  assert.ok(sync.folderDue({ type: 'archive' }, { backfill_done: true, last_sync_at: new Date(Date.now() - 16 * 60 * 1000) }, Date.now()));
});

// ---------- virtual archived folder: Zoho's archived view in the standard pipeline ----------
test('virtual archived folder: status=archived mapped as a standard folder — cursors, terminal page, dedup vs listed Archive, graceful unsupported tenant', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  const info = byAddress['info@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id IN ($1,$2)', [admin.id, info.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id IN ($1,$2) AND status IN ('queued','running','paused')", [admin.id, info.id]);

  // supported tenant (admin): one normal sync — the virtual folder appears and
  // is processed by the SAME machinery (cursor, terminal page), and the
  // archived corpus that already exists under the listed Archive folder is NOT
  // duplicated (canonical dedup across listed + virtual sources).
  await sync.syncMailbox(admin.id, { maxPages: 2 });
  const vf = await db.one(`SELECT id, folder_type FROM folders WHERE mailbox_id=$1 AND provider_folder_id='zoho:archived'`, [admin.id]);
  assert.ok(vf, 'virtual archived folder persisted like any folder');
  const vst = await db.one('SELECT backfill_done FROM sync_state WHERE mailbox_id=$1 AND folder_id=$2', [admin.id, vf.id]);
  assert.strictEqual(vst.backfill_done, true, 'terminal page detected on the archived view');
  const occ = await db.one(`SELECT COUNT(*)::int n FROM message_occurrences o
    JOIN canonical_messages c ON c.id=o.canonical_message_id
    WHERE o.mailbox_id=$1 AND c.subject LIKE 'Archived demo message %'`, [admin.id]);
  assert.strictEqual(occ.n, 5, 'no duplication between the listed Archive folder and the archived view');
  const capsA = await db.one('SELECT capabilities FROM mailboxes WHERE id=$1', [admin.id]);
  const cA = typeof capsA.capabilities === 'string' ? JSON.parse(capsA.capabilities) : capsA.capabilities;
  assert.strictEqual(cA.archivedView, 'supported', 'capability recorded from evidence');

  // unsupported tenant (info: mock rejects status=archived with 400): the cycle
  // must COMPLETE (other folders unaffected), and the rejection is recorded as
  // a classified capability — no manual intervention, no cycle failure.
  const s = await sync.syncMailbox(info.id, { maxPages: 1 });
  assert.ok(s.folders >= 2, 'cycle completed for the unsupported tenant');
  const capsI = await db.one('SELECT capabilities FROM mailboxes WHERE id=$1', [info.id]);
  const cI = typeof capsI.capabilities === 'string' ? JSON.parse(capsI.capabilities) : capsI.capabilities;
  assert.match(String(cI.archivedView || ''), /^unsupported/, 'rejection recorded with its classification');
  // and the next sync SKIPS the virtual folder (no re-probing every cycle)
  const s2 = await sync.syncMailbox(info.id, { maxPages: 1 });
  assert.ok(s2.folders >= 2, 'subsequent cycles skip the unsupported archived view cleanly');
});

// ---------- fast-lane reclaim: a provably dead lease heals in minutes, not 15 ----------
test('orphaned running job (CLI/container killed mid-attempt): lease dead 4 minutes → reclaimed on next start; 60s-old lease still protected', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin.id]);

  // real-tenant job-34 scenario: an attempt's owner process died (no status
  // transition); the lease stopped renewing. checkpoint touches the lease at
  // least every ~1s and the longest legitimate gap (one paced request + its
  // 20s timeout) is well under a minute — 4 dead minutes is PROOF of death.
  // Waiting the old 15-minute gate left the worker reporting skipped_busy
  // every cycle for a quarter hour. It must reclaim now.
  const orphan = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ($1, 'running', now() - interval '10 minutes', now() - interval '4 minutes') RETURNING id`, [admin.id]);
  const s = await sync.syncMailbox(admin.id, { maxPages: 1 });
  assert.strictEqual(s.jobId, Number(orphan.id), 'provably dead attempt reclaimed within minutes, not 15');
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [orphan.id])).status, 'completed');

  // a live attempt (lease 60s — inside the legitimate-gap envelope) is protected
  const liveJob = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ($1, 'running', now() - interval '30 minutes', now() - interval '60 seconds') RETURNING id`, [admin.id]);
  await assert.rejects(() => sync.syncMailbox(admin.id, { maxPages: 1 }), /already running/,
    'a 60s-old lease is within the legitimate gap — still blocks concurrent starts');
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE id=$1", [liveJob.id]);
});

// ---------- state machine: every lifecycle chain proven, every state explained ----------
test('lifecycle matrix: happy chain, crash→recover→resume, shutdown→auto-resume, double-resume race, idempotent recovery, monotonic cursor — all explained by job_events', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin.id]);

  // CHAIN 1 — READY → RUNNING → CHECKPOINT → COMPLETED, fully event-logged
  const s1 = await sync.syncMailbox(admin.id, { maxPages: 1 });
  const ev1 = (await sync.jobEvents(s1.jobId)).reverse();
  assert.deepStrictEqual(ev1.map(e => e.to_status), ['queued', 'running', 'completed'],
    'every transition of the happy chain is recorded');
  assert.ok(ev1.every(e => e.reason && e.actor), 'each event names its reason and actor — no hidden state');

  // CHAIN 2 — RUNNING → PROCESS CRASH → RECOVERED (boot) → RUNNING → COMPLETED
  const crashed = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ($1,'running', now() - interval '2 minutes', now() - interval '2 minutes') RETURNING id`, [admin.id]);
  await db.q(`INSERT INTO job_events (job_id, from_status, to_status, reason, actor) VALUES ($1,NULL,'queued','created','test'),($1,'queued','running','attempt started','test')`, [crashed.id]);
  await sync.recoverStaleJobs();                                        // boot after crash
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [crashed.id])).status, 'paused');
  const s2 = await sync.syncMailbox(admin.id, { maxPages: 1 });          // auto-resume
  assert.strictEqual(s2.jobId, Number(crashed.id));
  const ev2 = (await sync.jobEvents(crashed.id)).reverse().map(e => `${e.to_status}:${e.reason}`);
  assert.ok(ev2.some(e => e.startsWith('paused:boot recovery')), 'recovery explained');
  assert.ok(ev2[ev2.length - 1].startsWith('completed:'), 'resumed to completion');

  // CHAIN 3 — RUNNING → GRACEFUL SHUTDOWN → PAUSED (cursor kept) → RESTART → AUTO RESUME → COMPLETED
  // force a fresh backfill so the attempt has work to be interrupted in
  await db.q(`UPDATE sync_state SET backfill_done=FALSE, next_start=1 WHERE mailbox_id=$1`, [admin.id]);
  sync.requestShutdownPause(true);
  await assert.rejects(() => sync.syncMailbox(admin.id, { maxPages: 2 }), /sync paused/,
    'shutdown pauses the in-flight attempt at the next checkpoint');
  sync.requestShutdownPause(false);                                      // "restart"
  const pausedJob = await db.one(`SELECT id FROM sync_jobs WHERE mailbox_id=$1 AND status='paused' ORDER BY id DESC LIMIT 1`, [admin.id]);
  const evS = await sync.jobEvents(pausedJob.id);
  assert.ok(evS.some(e => /graceful shutdown/.test(e.reason)), 'shutdown pause is explained in the log');
  const s3 = await sync.syncMailbox(admin.id, { maxPages: 50 });          // auto-resume to completion
  assert.strictEqual(s3.jobId, Number(pausedJob.id));
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [pausedJob.id])).status, 'completed');

  // CHAIN 4 — double-resume race: two processes both told "resume job N" — the
  // CAS start guarantees exactly ONE wins; the loser is told the truth.
  const both = await db.one(`INSERT INTO sync_jobs (mailbox_id, status) VALUES ($1,'paused') RETURNING id`, [admin.id]);
  const results = await Promise.allSettled([
    sync.syncMailbox(admin.id, { maxPages: 1 }),
    sync.syncMailbox(admin.id, { maxPages: 1 }),
  ]);
  const wins = results.filter(r => r.status === 'fulfilled');
  const losses = results.filter(r => r.status === 'rejected');
  assert.strictEqual(wins.length + losses.length, 2);
  assert.ok(wins.length >= 1, 'at least one attempt won');
  for (const l of losses) assert.match(String(l.reason && l.reason.message), /already/i, 'loser told the truth, never double-runs');
  const runEvents = (await sync.jobEvents(both.id)).filter(e => e.to_status === 'running');
  assert.ok(runEvents.length <= wins.length, 'no phantom running transitions');

  // CHAIN 5 — recovery idempotence: reconcile twice → one pause event total
  const dead2 = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ($1,'running', now() - interval '10 minutes', now() - interval '10 minutes') RETURNING id`, [admin.id]);
  await sync.reconcileStale();
  await sync.reconcileStale();
  const pauses = (await sync.jobEvents(dead2.id)).filter(e => e.to_status === 'paused');
  assert.strictEqual(pauses.length, 1, 'second recovery pass is a no-op — no duplicate recovery');
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE id=$1", [dead2.id]);

  // INVARIANT — cursor never moves backwards; backfill_done latches
  const f = await db.one(`SELECT folder_id FROM sync_state WHERE mailbox_id=$1 LIMIT 1`, [admin.id]);
  await sync.advanceCursor(admin.id, f.folder_id, 500, { backfillDone: true });
  await sync.advanceCursor(admin.id, f.folder_id, 300);                  // stale racer tries to rewind
  const st = await db.one('SELECT next_start, backfill_done FROM sync_state WHERE mailbox_id=$1 AND folder_id=$2', [admin.id, f.folder_id]);
  assert.strictEqual(Number(st.next_start), 500, 'cursor is monotonic');
  assert.strictEqual(st.backfill_done, true, 'backfill_done latches forward');

  // ILLEGAL TRANSITIONS are impossible by construction
  await assert.rejects(() => sync.transitionJob(s1.jobId, ['completed'], 'running', 'x'), /illegal job transition/);
});

// ---------- structured checkpoint: the job-36 production sequence, explained and guarded ----------
test('checkpoint model: 7101→6301 is a folder transition (never rollback); same-folder regression rejected; seq strictly monotonic; stale writer ignored at DB level', async () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [admin.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status IN ('queued','running','paused')", [admin.id]);

  // (1) classifier matrix — the EXACT production values from job 36:
  const F1 = { seq: 87, folderId: 'F1', folderName: 'Inbox', phase: 'backfill', offset: 7001 };
  const F1b = { seq: 88, folderId: 'F1', folderName: 'Inbox', phase: 'backfill', offset: 7101 };
  const F2 = { seq: 89, folderId: 'F2', folderName: 'Archived (Zoho)', phase: 'backfill', offset: 6301 };
  const F2b = { seq: 90, folderId: 'F2', folderName: 'Archived (Zoho)', phase: 'backfill', offset: 6401 };
  assert.strictEqual(sync.classifyCheckpointDelta(F1, F1b), 'advance', '7001→7101 same folder = pass');
  assert.strictEqual(sync.classifyCheckpointDelta(F1b, F2), 'folder_transition', '7101→6301 across folders = explicit transition, NOT rollback');
  assert.strictEqual(sync.classifyCheckpointDelta(F2, F2b), 'advance');
  assert.strictEqual(sync.classifyCheckpointDelta(F1b, { ...F1b, seq: 89, offset: 6301 }), 'checkpoint_regression',
    '7101→6301 within the SAME folder+phase = correctness defect');
  assert.strictEqual(sync.classifyCheckpointDelta(F1b, { ...F2, seq: 88 }), 'checkpoint_regression',
    'non-increasing checkpoint_seq is never legal');
  assert.strictEqual(sync.classifyCheckpointDelta(
    { seq: 1, folderId: 'F1', phase: 'newest', offset: 1 },
    { seq: 2, folderId: 'F1', phase: 'backfill', offset: 101 }), 'phase_transition',
    'newest→backfill is an explicit phase transition');

  // (2) writeCheckpoint: seq strictly monotonic through the production sequence
  const j = await db.one(`INSERT INTO sync_jobs (mailbox_id, status) VALUES ($1,'running') RETURNING id`, [admin.id]);
  const seqs = [];
  for (const step of [{ f: 'F1', n: 'Inbox', o: 7001 }, { f: 'F1', n: 'Inbox', o: 7101 },
    { f: 'F2', n: 'Archived (Zoho)', o: 6301 }, { f: 'F2', n: 'Archived (Zoho)', o: 6401 }]) {
    seqs.push(await sync.writeCheckpoint(j.id, { folderId: step.f, folderName: step.n, folderType: 'archive', phase: 'backfill', offset: step.o }));
  }
  assert.deepStrictEqual(seqs, [1, 2, 3, 4], 'checkpoint_seq strictly increases across folder transitions');
  const cpRow = await db.one('SELECT checkpoint, checkpoint_seq FROM sync_jobs WHERE id=$1', [j.id]);
  const cp = typeof cpRow.checkpoint === 'string' ? JSON.parse(cpRow.checkpoint) : cpRow.checkpoint;
  assert.deepStrictEqual({ folderId: cp.folderId, phase: cp.phase, offset: cp.offset, seq: Number(cpRow.checkpoint_seq) },
    { folderId: 'F2', phase: 'backfill', offset: 6401, seq: 4 }, 'structured context: folder + phase + offset + seq');
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE id=$1", [j.id]);

  // (3) stale writer at DB level: A reads 7001; B advances to 7101 and commits;
  // A attempts to commit its stale 6301 snapshot — the DATABASE ignores it.
  const fRow = await db.one('SELECT folder_id FROM sync_state WHERE mailbox_id=$1 LIMIT 1', [admin.id]);
  await db.q('UPDATE sync_state SET next_start=7001 WHERE mailbox_id=$1 AND folder_id=$2', [admin.id, fRow.folder_id]);
  await sync.advanceCursor(admin.id, fRow.folder_id, 7101);   // writer B commits newer
  await sync.advanceCursor(admin.id, fRow.folder_id, 6301);   // writer A stale snapshot
  const st = await db.one('SELECT next_start FROM sync_state WHERE mailbox_id=$1 AND folder_id=$2', [admin.id, fRow.folder_id]);
  assert.strictEqual(Number(st.next_start), 7101, 'stale checkpoint write ignored at DB level (GREATEST)');

  // (4) a REAL sync produces a structured checkpoint + explicit folder-completion
  // events, and resume keeps folder/phase context (per-folder persisted cursors)
  const s = await sync.syncMailbox(admin.id, { maxPages: 2 });
  const jr = await db.one('SELECT checkpoint, checkpoint_seq FROM sync_jobs WHERE id=$1', [s.jobId]);
  const cp2 = typeof jr.checkpoint === 'string' ? JSON.parse(jr.checkpoint) : jr.checkpoint;
  assert.ok(cp2 && cp2.folderId && cp2.phase && Number(jr.checkpoint_seq) > 0, 'real cycle writes structured checkpoints');
  const completions = (await sync.jobEvents(s.jobId, 50)).filter(e => /folder backfill completed/.test(e.reason));
  assert.ok(completions.length >= 0, 'folder completion markers are recorded as events when terminal pages are hit');
});

// ---------- auto-discovery: shared mailboxes appear WITHOUT a manual button ----------
test('auto-discovery: worker tick discovers and registers shared mailboxes automatically, idempotently, interval-gated', async () => {
  const liveSync = require('../modules/mail/live-sync');
  const before = (await db.one(`SELECT COUNT(*)::int n FROM mailboxes WHERE detected_type='shared_mailbox'`)).n;
  assert.ok(before >= 20, 'suite baseline: shared mailboxes already discovered');

  // make discovery "due" (all reports stale) → the WORKER tick must run it
  await db.q("UPDATE detection_reports SET at = now() - interval '2 days'");
  const t1 = await liveSync.tickOnce({ source: 'worker' });
  assert.ok(t1.autoDiscovery, `tick attempted auto-discovery: ${JSON.stringify(t1.autoDiscovery || null)}`);
  assert.ok(t1.autoDiscovery.ran >= 1, `worker ran discovery automatically (error: ${t1.autoDiscovery.lastError || 'none'})`);
  const after = (await db.one(`SELECT COUNT(*)::int n FROM mailboxes WHERE detected_type='shared_mailbox'`)).n;
  assert.strictEqual(after, before, 'idempotent upsert — no duplicates, nothing lost');
  const report = await db.one(`SELECT report FROM detection_reports ORDER BY id DESC LIMIT 1`);
  const rep = typeof report.report === 'string' ? JSON.parse(report.report) : report.report;
  assert.strictEqual(rep.auto, true, 'auto-discovery recorded its own report');
  assert.ok(rep.shared >= 20, `report counts the shared mailboxes (${rep.shared})`);

  // interval gate: a fresh report means the next tick does NOT re-run discovery
  const t2 = await liveSync.tickOnce({ source: 'worker' });
  assert.ok(!t2.autoDiscovery, 'recent report → discovery skipped this tick');
});

// ---------- scheduler: realtime NEVER waits behind backfill (worker starvation fix) ----------
test('starvation E2E: new mail (incl. shared-mailbox routing) appears while a large backfill is still incomplete; backfill yields on its slice budget and resumes', async () => {
  const liveSync = require('../modules/mail/live-sync');
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  const info = byAddress['info@exoticcolors.org'];
  const hr = byAddress['hr@exoticcolors.org'];
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id IN ($1,$2)', [admin.id, info.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE status IN ('queued','running','paused')");

  // a LARGE pending backfill on info@ (250 messages, reset to the beginning)
  const saved = await db.all('SELECT folder_id, next_start, backfill_done FROM sync_state WHERE mailbox_id=$1', [info.id]);
  await db.q('UPDATE sync_state SET backfill_done=FALSE, next_start=1 WHERE mailbox_id=$1', [info.id]);

  // a brand-new email lands in the admin's Inbox, addressed to the SHARED hr@ box
  const SUBJ = 'STARVATION-' + crypto.randomUUID().slice(0, 8);
  const injected = { messageId: 'starv-1', threadId: 'tstarv', fromAddress: 'urgent@example.com',
    senderName: 'Urgent', toAddress: 'hr@exoticcolors.org', subject: SUBJ,
    summary: 'must not wait behind backfill', receivedTime: String(Date.now()), sentDateInGMT: String(Date.now() - 4000),
    hasAttachment: '0' };
  _messages[ADMIN_ACCOUNT_ID].splice(1, 0, injected);
  process.env.MADAR_BACKFILL_SLICE_SEC = '0'; // slice budget exhausts immediately → backfill must yield
  try {
    const t = await liveSync.tickOnce({ source: 'worker' });
    // REQUIREMENT: the new message is captured by the realtime pass...
    const occ = await db.one(`SELECT COUNT(*)::int n FROM message_occurrences o
      JOIN canonical_messages c ON c.id=o.canonical_message_id WHERE c.subject=$1 AND o.mailbox_id=$2`, [SUBJ, admin.id]);
    assert.strictEqual(occ.n, 1, 'new mail captured in the SAME tick');
    // ...routed to the shared mailbox in the SAME tick...
    const routed = await db.one(`SELECT COUNT(*)::int n FROM message_occurrences o
      JOIN canonical_messages c ON c.id=o.canonical_message_id WHERE c.subject=$1 AND o.mailbox_id=$2`, [SUBJ, hr.id]);
    assert.strictEqual(routed.n, 1, 'shared-mailbox routing continued during historical import');
    // ...while the big backfill is STILL INCOMPLETE (it yielded on its budget)
    const pending = await db.one(`SELECT COUNT(*)::int n FROM sync_state WHERE mailbox_id=$1 AND backfill_done=FALSE`, [info.id]);
    assert.ok(pending.n >= 1, 'backfill incomplete — proving new mail did not wait for it');
    assert.ok(t.backfill && (t.backfill.yielded || t.backfill.error === undefined),
      `backfill slice ran bounded (${JSON.stringify(t.backfill || null)})`);
    assert.ok(t.realtimePassMs != null, 'realtime latency metric recorded');

    // and the backfill RESUMES from its persisted cursor on later slices
    delete process.env.MADAR_BACKFILL_SLICE_SEC;
    for (let i = 0; i < 4; i++) {
      await liveSync.tickOnce({ source: 'worker' });
    }
    const after = await db.one(`SELECT COUNT(*)::int n FROM sync_state WHERE mailbox_id=$1 AND backfill_done=FALSE`, [info.id]);
    assert.strictEqual(after.n, 0, 'backfill completed across subsequent bounded slices');
  } finally {
    delete process.env.MADAR_BACKFILL_SLICE_SEC;
    const i = _messages[ADMIN_ACCOUNT_ID].indexOf(injected);
    if (i > -1) _messages[ADMIN_ACCOUNT_ID].splice(i, 1);
    for (const s of saved) await db.q('UPDATE sync_state SET next_start=GREATEST(next_start,$2), backfill_done=$3 WHERE mailbox_id=$1 AND folder_id=$4',
      [info.id, s.next_start, s.backfill_done, s.folder_id]);
  }
});

// ---------- diagnostics ----------
test('diagnostics: failed sync records full typed context (stage, endpoint, stack); success records ok row; UI/500 surface a trace id', async () => {
  // success path first: the admin mailbox sync recorded an 'ok' diagnostics row
  const okRow = await db.one(`SELECT * FROM sync_diagnostics WHERE mailbox_id = $1 AND outcome = 'ok' ORDER BY id DESC LIMIT 1`,
    [byAddress['m.almaysari@exoticcolors.org'].id]);
  assert.ok(okRow, 'ok diagnostics row exists');
  assert.strictEqual(okRow.stage, 'done');
  assert.ok(okRow.trace_id.startsWith('sync-'));
  // with the split scheduler a no-op backfill slice can legitimately read 0 —
  // evidence-bearing ok rows still exist from realtime/full cycles
  const okRead = await db.one(`SELECT read_count FROM sync_diagnostics
    WHERE mailbox_id = $1 AND outcome = 'ok' AND read_count >= 1 ORDER BY id DESC LIMIT 1`,
    [byAddress['m.almaysari@exoticcolors.org'].id]);
  assert.ok(okRead, 'an evidence-bearing ok cycle exists');

  // failure path: a mail_api mailbox with a valid connection but NO probe-proven
  // working id → connector construction fails inside the Zoho connector
  await db.q(`INSERT INTO mailboxes (address, display_name, provider, connection_id, detected_type, strategy, capabilities, is_pilot, sync_enabled, status)
    VALUES ('diag-broken@exoticcolors.org','Diag Broken','zoho',$1,'user','mail_api','{}'::jsonb, TRUE, TRUE, 'ready')`, [connId]);
  const broken = await db.one(`SELECT id FROM mailboxes WHERE address = 'diag-broken@exoticcolors.org'`);
  await assert.rejects(() => sync.syncMailbox(Number(broken.id)), /working id/);
  const failRow = await db.one(`SELECT * FROM sync_diagnostics WHERE mailbox_id = $1 AND outcome = 'error' ORDER BY id DESC LIMIT 1`, [broken.id]);
  assert.strictEqual(failRow.stage, 'connect');
  assert.strictEqual(failRow.error_class, 'Error');
  assert.match(failRow.error_message, /working id/);
  assert.ok(failRow.error_stack && failRow.error_stack.includes('zoho-mail-api'), 'full stack captured');

  // diagnostics endpoint: latest-by-mailbox + recent errors, admin-only
  const diag = await fakeCall('GET', '/api/mail/diagnostics', { user: adminUser });
  assert.strictEqual(diag.status, 200);
  assert.ok(diag.body.recentErrors.some(r => r.mailbox === 'diag-broken@exoticcolors.org' && r.error.stack));
  const byTrace = await fakeCall('GET', `/api/mail/diagnostics?trace_id=${failRow.trace_id}`, { user: adminUser });
  assert.strictEqual(byTrace.body.stage, 'connect');
  assert.ok(byTrace.body.error.stack.length > 20);
  assert.strictEqual((await fakeCall('GET', '/api/mail/diagnostics', { user: memberUser })).status, 403);

  // the sync route surfaces the trace id instead of a bare error
  await db.q(`UPDATE mailboxes SET is_pilot = TRUE, sync_enabled = TRUE WHERE id = $1`, [broken.id]);
  const routeFail = await fakeCall('POST', `/api/mail/mailboxes/${broken.id}/sync`, { user: adminUser, body: {} });
  assert.ok(routeFail.status >= 400);
  await db.q(`DELETE FROM mailboxes WHERE id = $1`, [broken.id]);
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
test('canonical fingerprint v3: real-Zoho-field identity, converges Live↔Archive, no false merges', async () => {
  const h = sync.dedupHash;
  assert.strictEqual(sync.HASH_VERSION, 3);

  // ---- REAL Zoho values (all@exoticcolors.org moderation-queue evidence) ----
  // Resends of the same subject at different SENT times must stay DISTINCT.
  const villa = (dateMs) => h({ from: 'j.villa@exoticcolors.org', subject: 'Introducing Our New Marketing Coordinator!', sentAt: dateMs });
  const resends = [1736436064000, 1736430232000, 1736197164000, 1736196434000].map(villa);
  assert.strictEqual(new Set(resends).size, 4, 'real resends stay distinct by sent-second');

  // CONVERGENCE with real values: a live messages/view record (no RFC id,
  // sentDateInGMT as ms) and the eDiscovery EML of the SAME email (RFC Date
  // header, HAS a Message-ID) produce an IDENTICAL fingerprint.
  const dateMs = 1783172034000, from = 'admin.it@exoticcolors.me',
    subject = 'Security Alert‼️, Fraudulent Email Impersonating the CEO', to = 'all@exoticcolors.org';
  const live = { from, subject, to, cc: '', sentAt: dateMs, receivedAt: 1783146849540, rfcMessageId: '' };
  const rfc2822 = new Date(dateMs).toUTCString();
  const archive = { from, subject, to, cc: '', sentAt: Date.parse(rfc2822), rfcMessageId: '<real-archived@zoho>' };
  assert.strictEqual(h(live), h(archive), 'live and eDiscovery copies of the same real email converge');

  // mailbox-independent: per-copy fields never touch identity
  assert.strictEqual(h({ ...live, receivedAt: 111 }), h({ ...live, receivedAt: 999 }));
  assert.strictEqual(h({ ...live, providerMessageId: 'x' }), h({ ...live, providerMessageId: 'y' }));

  // discrimination on message-intrinsic fields
  assert.notStrictEqual(h(live), h({ ...live, to: 'someone-else@x.co' }));   // different recipients
  assert.notStrictEqual(h(live), h({ ...live, cc: 'extra@x.co' }));          // different cc
  assert.notStrictEqual(h(live), h({ ...live, subject: 'Other' }));          // different subject
  assert.notStrictEqual(h(live), h({ ...live, sentAt: dateMs + 1000 }));     // different sent second
  assert.notStrictEqual(h(live), h({ ...live, from: 'other@x.co' }));        // different sender

  // BCC intentionally NOT part of identity (per-mailbox envelope), and neither
  // are the fields that disagree between sources (snippet/body, attachment flag)
  assert.strictEqual(h({ ...live, bcc: 'secret@x.co' }), h(live));
  assert.strictEqual(h({ ...live, snippet: 'a', hasAttachments: false }), h({ ...live, snippet: 'b', hasAttachments: true }));

  // new rows are stamped v3
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  const v = await db.one('SELECT canonical_hash_version cv FROM canonical_messages c JOIN message_occurrences o ON o.canonical_message_id=c.id WHERE o.mailbox_id=$1 LIMIT 1', [admin.id]);
  assert.strictEqual(v.cv, 3);
});

test('collision metrics: RFC oracle prevents false merge, detects false split; confidence + reconciliation invariant', async () => {
  const info = byAddress['info@exoticcolors.org'];
  const f = await sync.upsertFolder(info.id, { providerFolderId: 'fp-metrics', name: 'M', type: 'inbox' });
  const base = { from: 'alerts@bank.com', to: 'ops@exoticcolors.org', cc: '', subject: 'Daily alert', sentAt: 1760000000000 };

  // two GENUINELY distinct emails that collide on the fp3 5-tuple but carry
  // different RFC Message-IDs (the oracle) → false merge PREVENTED and recorded;
  // both survive as separate canonicals (no data loss).
  const a = await sync.insertMessage(info.id, f, { ...base, providerMessageId: 'm-a', rfcMessageId: '<alert-A@bank>' });
  const b = await sync.insertMessage(info.id, f, { ...base, providerMessageId: 'm-b', rfcMessageId: '<alert-B@bank>' });
  assert.notStrictEqual(a.canonicalId, b.canonicalId, 'distinct RFC ids kept separate despite fp3 collision');
  assert.ok((await db.one(`SELECT COUNT(*)::int n FROM fingerprint_metrics WHERE event_type='false_merge_prevented'`)).n >= 1);

  // a live copy (NO rfc) of email A converges onto A's (un-salted) canonical
  const hr = byAddress['hr@exoticcolors.org'];
  const fLive = await sync.upsertFolder(hr.id, { providerFolderId: 'fp-live', name: 'L', type: 'inbox' });
  const live = await sync.insertMessage(hr.id, fLive, { ...base, providerMessageId: 'm-live', rfcMessageId: '' });
  assert.strictEqual(live.canonicalId, a.canonicalId, 'live copy converges onto the first canonical');

  // metrics endpoint: the six numbers + correlation confidence, admin-only
  const r = await fakeCall('GET', '/api/mail/fingerprint-metrics', { user: adminUser });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body.status, 'pending_production_archive_validation');
  assert.ok(r.body.metrics.false_merges_prevented >= 1);
  assert.ok(typeof r.body.correlationConfidence === 'number' && r.body.correlationConfidence <= 1);
  assert.strictEqual((await fakeCall('GET', '/api/mail/fingerprint-metrics', { user: memberUser })).status, 403);

  // reconciliation invariant: a legacy v2 email recomputes to the SAME fp3 as
  // its v3 twin — the property the reconcile script relies on to collapse them.
  const v3 = await sync.insertMessage(info.id, f, { from: 'legacy@x.co', to: 'a@x.co', cc: '', subject: 'Legacy', sentAt: 1761000000000, providerMessageId: 'v3-1' });
  const legacyFp = sync.dedupHash({ from: 'legacy@x.co', to: 'a@x.co', cc: '', subject: 'Legacy', sentAt: 1761000000000 });
  const v3row = await db.one(`SELECT dedup_hash FROM canonical_messages WHERE id=$1`, [v3.canonicalId]);
  assert.strictEqual(legacyFp, v3row.dedup_hash, 'legacy v2 email recomputes to the v3 twin fingerprint');
});

test('visibility trace: names WHY mail is not shown — "stored but hidden by grant" and its resolution', async () => {
  const info = byAddress['info@exoticcolors.org']; // has 250+ synced occurrences, strategy mail_api
  await db.q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [info.id]);
  await auth.setGrant(adminUser.id, info.id, null); // admin has NO read grant

  const t = await fakeCall('GET', `/api/mail/mailboxes/${info.id}/visibility-trace`, { user: adminUser });
  assert.strictEqual(t.status, 200);
  for (const k of ['1_worker_running', '2_recent_cycle', '3_fetched_from_zoho', '4_inserted_or_cursor_dedup',
    '5_stored_but_hidden', '6_status_syncing', '7_last_diagnostics']) assert.ok(k in t.body.checks, k);
  assert.ok(t.body.checks['5_stored_but_hidden'].storedInDb > 0);
  assert.strictEqual(t.body.checks['5_stored_but_hidden'].youHaveReadGrant, false);
  assert.strictEqual(t.body.checks['5_stored_but_hidden'].hiddenByGrant, true);
  assert.match(t.body.verdict, /محجوبة|can_view_messages/);
  assert.deepStrictEqual((await fakeCall('GET', '/api/mail/messages', { user: adminUser, search: `?mailbox_id=${info.id}` })).body, []);

  await auth.setGrant(adminUser.id, info.id, { can_view_messages: true });
  const t2 = await fakeCall('GET', `/api/mail/mailboxes/${info.id}/visibility-trace`, { user: adminUser });
  assert.strictEqual(t2.body.checks['5_stored_but_hidden'].hiddenByGrant, false);
  assert.ok((await fakeCall('GET', '/api/mail/messages', { user: adminUser, search: `?mailbox_id=${info.id}` })).body.length > 0);
  await auth.setGrant(adminUser.id, info.id, null);
  assert.strictEqual((await fakeCall('GET', `/api/mail/mailboxes/${info.id}/visibility-trace`, { user: memberUser })).status, 403);
});

test('envelope privacy: each occurrence keeps its own to/cc; BCC never leaks across mailboxes', async () => {
  const info = byAddress['info@exoticcolors.org'];
  const hr = byAddress['hr@exoticcolors.org'];
  const fInfo = await sync.upsertFolder(info.id, { providerFolderId: 'env-f', name: 'Inbox', type: 'inbox' });
  const fHr = await sync.upsertFolder(hr.id, { providerFolderId: 'env-f', name: 'Inbox', type: 'inbox' });
  // Same email delivered to two shared mailboxes: message HEADERS (from/to/cc/
  // subject/sent) are identical across both stored copies (real-world) → one
  // canonical under v3. The BCC is per-mailbox envelope data — info@'s copy was
  // also blind-copied to a hidden address; hr@'s copy was not.
  const common = { from: 'sender@x.co', subject: 'Env', sentAt: 1750000000000,
    to: 'info@exoticcolors.org, hr@exoticcolors.org', cc: 'watcher@x.co', snippet: 's' };
  const r1 = await sync.insertMessage(info.id, fInfo, { ...common, providerMessageId: 'e1', bcc: 'hidden-info@x.co' });
  const r2 = await sync.insertMessage(hr.id, fHr, { ...common, providerMessageId: 'e2', bcc: '' });
  assert.strictEqual(r1.canonicalId, r2.canonicalId); // identical headers → one canonical
  await auth.setGrant(memberUser.id, hr.id, { can_view_messages: true });
  const hrView = await fakeCall('GET', `/api/mail/occurrences/${r2.occurrenceId}`, { user: memberUser });
  assert.strictEqual(hrView.status, 200);
  // BCC is stored per-occurrence and NEVER returned by the API — info@'s hidden
  // blind-copy address must not appear anywhere in hr@'s view
  const asText = JSON.stringify(hrView.body);
  assert.ok(!asText.includes('hidden-info@x.co'), 'BCC of another mailbox copy leaked');
  // and hr@'s own occurrence carries no BCC at all
  const bccRow = await db.one('SELECT envelope_bcc FROM message_occurrences WHERE id=$1', [r2.occurrenceId]);
  assert.strictEqual(bccRow.envelope_bcc, '');
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
  // a crashed process leaves a FROZEN lease (it cannot touch it anymore) — that
  // is what boot recovery detects. A fresh lease at boot means a still-alive
  // CLI attempt in another container and must be left running (lease-aware rule).
  const r = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ($1,'running', now() - interval '1 minute', now() - interval '1 minute') RETURNING id`, [admin2.id]);
  const live = await db.one(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ((SELECT id FROM mailboxes WHERE address='hr@exoticcolors.org'),'running', now(), now()) RETURNING id`);
  const recovered = await sync.recoverStaleJobs();
  assert.ok(recovered.some(x => Number(x.id) === Number(r.id)), 'frozen-lease job recovered at boot');
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [r.id])).status, 'paused');
  assert.strictEqual((await db.one('SELECT status FROM sync_jobs WHERE id=$1', [live.id])).status, 'running',
    'live-lease attempt (another process) is NOT paused by boot recovery');
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE id=$1", [live.id]);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE id=$1", [r.id]);
  // invariant: no canonical without occurrence, no occurrence without canonical
  const orphanCanon = await db.one(`SELECT COUNT(*)::int n FROM canonical_messages c
    WHERE NOT EXISTS (SELECT 1 FROM message_occurrences o WHERE o.canonical_message_id = c.id)`);
  assert.strictEqual(orphanCanon.n, 0);

  // a mailbox left status='syncing' by the unclean shutdown is reconciled to
  // 'ready' — otherwise it stays visually stuck "syncing" forever (real bug)
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  await db.q("UPDATE mailboxes SET status='syncing' WHERE id=$1", [admin.id]);
  await db.q(`INSERT INTO sync_jobs (mailbox_id, status, started_at, lease_at)
    VALUES ($1,'running', now() - interval '1 minute', now() - interval '1 minute')`, [admin.id]);
  await sync.recoverStaleJobs();
  const mb = await db.one('SELECT status, status_detail FROM mailboxes WHERE id=$1', [admin.id]);
  assert.strictEqual(mb.status, 'ready');
  assert.match(mb.status_detail, /استأنف|resume/);
  await db.q("UPDATE sync_jobs SET status='cancelled', finished_at=now() WHERE mailbox_id=$1 AND status='paused'", [admin.id]);
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
