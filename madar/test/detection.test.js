// Detection + discovery + sync test suite against the mock Zoho API.
// Run: node --experimental-sqlite --test test/
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.MADAR_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'madar-test-'));
process.env.MADAR_MAX_RPM = '100000'; // no throttling against the local mock

const cryptoCore = require('../core/crypto');
cryptoCore.init('test-secret');
const { getDb } = require('../core/db');
const { encrypt } = require('../core/crypto');
const { ZohoClient, READ_SCOPES } = require('../modules/mail/zoho-client');
const detection = require('../modules/mail/detection');
const { syncMailbox, importArchiveZip } = require('../modules/mail/sync');
const { startMockZoho } = require('./mock-zoho');

const baseline = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'expected-mailboxes.json'), 'utf8'));

let mockServer, mockPort, connId, zoho, discovery, byAddress = {};

before(async () => {
  mockPort = await startMockZoho(0);
  const db = getDb();
  const base = `http://127.0.0.1:${mockPort}`;
  const r = db.prepare(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
      client_secret_enc, refresh_token_enc, scopes, status, created_at)
    VALUES ('zoho','Test Org',?,?,'test-client',?,?,?,'connected',?)`)
    .run(base, base, encrypt('s'), encrypt('mock-refresh-token'), READ_SCOPES, Date.now());
  connId = Number(r.lastInsertRowid);
  zoho = ZohoClient.forConnection(connId);

  discovery = await detection.discoverOrganization(zoho);
  for (const mb of discovery.mailboxes) {
    const caps = await detection.probeCapabilities(zoho, mb);
    const choice = detection.chooseStrategy(mb, caps);
    const id = detection.upsertMailbox(connId, mb, caps, choice);
    byAddress[mb.address] = { id, mb, caps, choice };
  }
});

test('discovers all 20 shared mailboxes from the org groups API', () => {
  const shared = discovery.mailboxes.filter(m => m.detectedType === 'shared_mailbox');
  assert.strictEqual(shared.length, 20);
  const cmp = detection.compareWithBaseline(shared, baseline);
  assert.strictEqual(cmp.expectedCount, 20);
  assert.strictEqual(cmp.matched.length, 20);
  assert.deepStrictEqual(cmp.missing, []);
});

test('shared mailboxes appear in Groups but NOT in /api/accounts', () => {
  const accountsBody = discovery.evidence.accounts.body;
  const accountEmails = JSON.stringify(accountsBody.data);
  assert.ok(!accountEmails.includes('hr@exoticcolors.org'));
  assert.strictEqual(byAddress['hr@exoticcolors.org'].mb.detectedType, 'shared_mailbox');
});

test('mailbox on a second domain (logistics@thetaurus.world) is discovered', () => {
  assert.ok(byAddress['logistics@thetaurus.world']);
  assert.strictEqual(byAddress['logistics@thetaurus.world'].mb.detectedType, 'shared_mailbox');
});

test('aliases (+N) are captured and stored', () => {
  const info = byAddress['info@exoticcolors.org'];
  assert.deepStrictEqual(info.mb.aliases.sort(), ['contact@exoticcolors.org', 'welcome@exoticcolors.org']);
  const rows = getDb().prepare('SELECT address FROM mailbox_aliases WHERE mailbox_id=?').all(info.id);
  assert.strictEqual(rows.length, 2);
});

test('access levels: everyone / organization_members / only_moderators', () => {
  assert.strictEqual(byAddress['hr@exoticcolors.org'].mb.accessLevel, 'everyone');
  assert.strictEqual(byAddress['sms@exoticcolors.org'].mb.accessLevel, 'organization_members');
  assert.strictEqual(byAddress['referral@exoticcolors.org'].mb.accessLevel, 'organization_members');
  assert.strictEqual(byAddress['scan@exoticcolors.org'].mb.accessLevel, 'only_moderators');
});

test('moderation queues are read as metadata (sms=4, e-commerce=1) and never as archive', () => {
  assert.strictEqual(byAddress['sms@exoticcolors.org'].mb.moderationCount, 4);
  assert.strictEqual(byAddress['e-commerce@exoticcolors.org'].mb.moderationCount, 1);
  const smsCaps = byAddress['sms@exoticcolors.org'].caps;
  assert.strictEqual(smsCaps.moderationQueueReadable, true);
  assert.strictEqual(smsCaps.messages, false); // moderation ≠ mailbox read
  assert.strictEqual(byAddress['sms@exoticcolors.org'].choice.strategy, 'ediscovery_import');
});

test('group id without account id → metadata only, literal Invalid Account ID evidence', () => {
  const hr = byAddress['hr@exoticcolors.org'];
  assert.strictEqual(hr.mb.providerAccountId, null);
  assert.ok(hr.mb.providerGroupId);
  const ev = hr.caps.evidence['folders.groupIdAsAccountId'];
  assert.strictEqual(ev.status, 400);
  assert.match(JSON.stringify(ev.body), /Invalid Account ID/);
  assert.strictEqual(hr.choice.status, 'no_live_api');
  assert.match(hr.choice.detail, /eDiscovery/);
});

test('shared mailbox WITH an org-level accountId gets live message read (info@)', () => {
  const info = byAddress['info@exoticcolors.org'];
  assert.strictEqual(info.mb.providerAccountId, '5001000777');
  assert.strictEqual(info.caps.messages, true);
  assert.strictEqual(info.choice.strategy, 'mail_api');
});

test('normal user mailbox is classified user with full read', () => {
  const admin = byAddress['m.almaysari@exoticcolors.org'];
  assert.strictEqual(admin.mb.detectedType, 'user');
  assert.strictEqual(admin.caps.messages, true);
  assert.strictEqual(admin.choice.strategy, 'mail_api');
});

test('members and moderators are extracted', () => {
  const hr = byAddress['hr@exoticcolors.org'];
  assert.ok(hr.mb.members.some(x => x.email === 'staff1@exoticcolors.org'));
  assert.deepStrictEqual(hr.mb.moderators, ['m.almaysari@exoticcolors.org']);
});

test('re-running discovery does not duplicate mailboxes; aliases never become mailboxes', async () => {
  const dbCount = () => getDb().prepare('SELECT COUNT(*) n FROM mailboxes').get().n;
  const beforeCount = dbCount();
  const again = await detection.discoverOrganization(zoho);
  for (const mb of again.mailboxes) {
    const caps = await detection.probeCapabilities(zoho, mb);
    detection.upsertMailbox(connId, mb, caps, detection.chooseStrategy(mb, caps));
  }
  assert.strictEqual(dbCount(), beforeCount);
  // Alias address resolves to the existing info@ mailbox, never a new row.
  const alias = getDb().prepare('SELECT mailbox_id FROM mailbox_aliases WHERE address=?').get('contact@exoticcolors.org');
  assert.strictEqual(alias.mailbox_id, byAddress['info@exoticcolors.org'].id);
  assert.strictEqual(getDb().prepare('SELECT COUNT(*) n FROM mailboxes WHERE address=?').get('contact@exoticcolors.org').n, 0);
});

test('pilot sync is read-only, imports messages + attachments, and never duplicates', async () => {
  const info = byAddress['info@exoticcolors.org'];
  await assert.rejects(() => syncMailbox(info.id), /not pilot-selected/); // refuses before pilot selection
  getDb().prepare('UPDATE mailboxes SET is_pilot=1 WHERE id=?').run(info.id);
  const s1 = await syncMailbox(info.id, { maxPages: 5 });
  assert.ok(s1.newMessages >= 25, `expected >=25, got ${s1.newMessages}`);
  assert.ok(s1.attachments > 0);
  const s2 = await syncMailbox(info.id, { maxPages: 5 });
  assert.strictEqual(s2.newMessages, 0); // dedup: full re-run imports nothing
});

test('eDiscovery ZIP import parses EML, dedupes, and labels folders as archive', () => {
  const eml = (id, subject) => Buffer.from(
    `Message-ID: <${id}@export.zoho>\r\nFrom: "Applicant" <applicant@example.com>\r\nTo: hr@exoticcolors.org\r\n` +
    `Subject: ${subject}\r\nDate: Mon, 01 Jun 2026 10:00:00 +0400\r\nContent-Type: multipart/mixed; boundary="B1"\r\n\r\n` +
    `--B1\r\nContent-Type: text/plain\r\n\r\nPlease find my CV attached.\r\n` +
    `--B1\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename="cv.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n` +
    Buffer.from('%PDF-1.4 fake').toString('base64') + `\r\n--B1--\r\n`);
  // minimal stored-method ZIP with two EML files (Inbox + Sent)
  const files = [['Inbox/msg1.eml', eml('e1', 'Application 1')], ['Sent/msg2.eml', eml('e2', 'Reply 1')]];
  const zip = buildStoredZip(files);
  const hr = byAddress['hr@exoticcolors.org'];
  const r1 = importArchiveZip(hr.id, zip, null);
  assert.strictEqual(r1.imported, 2);
  assert.strictEqual(r1.attachments, 2);
  const r2 = importArchiveZip(hr.id, zip, null);
  assert.strictEqual(r2.imported, 0);
  assert.strictEqual(r2.duplicates, 2);
  const folders = getDb().prepare('SELECT name, folder_type FROM folders WHERE mailbox_id=?').all(hr.id);
  assert.ok(folders.some(f => f.folder_type === 'sent'));
});

function buildStoredZip(files) {
  const chunks = []; const central = []; let offset = 0;
  const crc32 = buf => { // standard CRC-32
    let c, table = buildStoredZip._t || (buildStoredZip._t = Array.from({ length: 256 }, (_, n) => {
      c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; return c >>> 0;
    }));
    let crc = 0xFFFFFFFF;
    for (const b of buf) crc = table[(crc ^ b) & 0xFF] ^ (crc >>> 8);
    return (crc ^ 0xFFFFFFFF) >>> 0;
  };
  for (const [name, data] of files) {
    const nameBuf = Buffer.from(name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 8);
    lh.writeUInt32LE(crc32(data), 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    chunks.push(lh, nameBuf, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0, 10);
    ch.writeUInt32LE(crc32(data), 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28); ch.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([ch, nameBuf]));
    offset += 30 + nameBuf.length + data.length;
  }
  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...chunks, centralBuf, eocd]);
}

after(() => { mockServer?.close?.(); });
