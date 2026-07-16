// Demo-mode seed (PostgreSQL): creates the demo organization connection
// pointing at the in-process mock Zoho API and runs a first Mock Discovery.
// Demo must always use a dedicated demo database (DATABASE_URL), never live.
const { q, one } = require('../core/db');
const { encrypt } = require('../core/crypto');
const { READ_SCOPES, ZohoClient } = require('../modules/mail/zoho-client');
const detection = require('../modules/mail/detection');

async function seedDemoConnection(mockBase) {
  let conn = await one("SELECT * FROM connections WHERE label = 'Demo Zoho Organization'");
  if (!conn) {
    const r = await one(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
        client_secret_enc, refresh_token_enc, scopes, status)
      VALUES ('zoho', 'Demo Zoho Organization', $1, $1, 'demo-client', $2, $3, $4, 'connected') RETURNING id`,
      [mockBase, encrypt('demo-secret'), encrypt('mock-refresh-token'), READ_SCOPES]);
    conn = await one('SELECT * FROM connections WHERE id = $1', [r.id]);
  } else {
    await q('UPDATE connections SET accounts_base = $1, api_base = $1 WHERE id = $2', [mockBase, conn.id]);
    conn.accounts_base = mockBase; conn.api_base = mockBase;
  }

  const count = await one('SELECT COUNT(*)::int AS n FROM mailboxes');
  if (!count.n) {
    const zoho = new ZohoClient(conn);
    const discovery = await detection.discoverOrganization(zoho);
    for (const mb of discovery.mailboxes) {
      const caps = await detection.probeCapabilities(zoho, mb);
      const choice = detection.chooseStrategy(mb, caps);
      await detection.upsertMailbox(Number(conn.id), mb, caps, choice);
    }
    await q('INSERT INTO detection_reports (mailbox_id, report) VALUES (0, $1)', [JSON.stringify({
      scope: 'organization',
      evidence: discovery.evidence,
      comparison: detection.compareWithBaseline(
        discovery.mailboxes.filter(x => x.detectedType === 'shared_mailbox'),
        require('./fixtures/expected-mailboxes.json')),
    })]);
  }
  return Number(conn.id);
}

module.exports = { seedDemoConnection };
