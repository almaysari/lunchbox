// Demo-mode seed: creates the demo organization connection pointing at the
// in-process mock Zoho API and runs a first discovery, so the UI opens with
// the full company picture already visible.
const { getDb } = require('../core/db');
const { encrypt } = require('../core/crypto');
const { READ_SCOPES, ZohoClient } = require('../modules/mail/zoho-client');
const detection = require('../modules/mail/detection');

async function seedDemoConnection(mockBase) {
  const db = getDb();
  let conn = db.prepare("SELECT * FROM connections WHERE label = 'Demo Zoho Organization'").get();
  if (!conn) {
    const r = db.prepare(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
        client_secret_enc, refresh_token_enc, scopes, status, created_at)
      VALUES ('zoho', 'Demo Zoho Organization', ?, ?, 'demo-client', ?, ?, ?, 'connected', ?)`)
      .run(mockBase, mockBase, encrypt('demo-secret'), encrypt('mock-refresh-token'), READ_SCOPES, Date.now());
    conn = db.prepare('SELECT * FROM connections WHERE id = ?').get(Number(r.lastInsertRowid));
  } else {
    // The mock port changes on every start.
    db.prepare('UPDATE connections SET accounts_base = ?, api_base = ? WHERE id = ?').run(mockBase, mockBase, conn.id);
    conn.accounts_base = mockBase; conn.api_base = mockBase;
  }

  if (!db.prepare('SELECT COUNT(*) n FROM mailboxes').get().n) {
    const zoho = new ZohoClient(conn);
    const discovery = await detection.discoverOrganization(zoho);
    for (const mb of discovery.mailboxes) {
      const caps = await detection.probeCapabilities(zoho, mb);
      const choice = detection.chooseStrategy(mb, caps);
      detection.upsertMailbox(conn.id, mb, caps, choice);
    }
    db.prepare('INSERT INTO detection_reports (mailbox_id, at, report) VALUES (0, ?, ?)').run(Date.now(), JSON.stringify({
      scope: 'organization',
      evidence: discovery.evidence,
      comparison: detection.compareWithBaseline(
        discovery.mailboxes.filter(x => x.detectedType === 'shared_mailbox'),
        require('./fixtures/expected-mailboxes.json')),
    }));
  }
  return conn.id;
}

module.exports = { seedDemoConnection };
