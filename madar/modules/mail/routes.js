// Mail module REST API.
const fs = require('fs');
const path = require('path');
const { getDb, ATTACH_DIR } = require('../../core/db');
const { encrypt } = require('../../core/crypto');
const { audit } = require('../../core/audit');
const auth = require('../../core/auth');
const { ZohoClient, READ_SCOPES } = require('./zoho-client');
const detection = require('./detection');
const { syncMailbox, importArchiveZip } = require('./sync');

// Expected-mailboxes baseline: validation reference ONLY (never a data source).
// Admin can replace it at data/expected-mailboxes.json; the repo fixture is the default.
function loadBaseline() {
  for (const p of [
    path.join(__dirname, '..', '..', 'data', 'expected-mailboxes.json'),
    path.join(__dirname, '..', '..', 'test', 'fixtures', 'expected-mailboxes.json'),
  ]) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { /* next */ }
  }
  return [];
}

function mailboxRow(m) {
  return {
    id: m.id, address: m.address, displayName: m.display_name, provider: m.provider,
    connectionId: m.connection_id, detectedType: m.detected_type, strategy: m.strategy,
    accessLevel: m.access_level, moderationCount: m.moderation_count,
    members: JSON.parse(m.members || '[]'), moderators: JSON.parse(m.moderators || '[]'),
    capabilities: JSON.parse(m.capabilities || '{}'),
    isPilot: Boolean(m.is_pilot), status: m.status, statusDetail: m.status_detail,
    providerAccountId: m.provider_account_id, providerGroupId: m.provider_group_id,
    aliases: getDb().prepare('SELECT address FROM mailbox_aliases WHERE mailbox_id=?').all(m.id).map(r => r.address),
  };
}

async function handle(req, res, url, user, body, helpers) {
  const { send, requireAdmin } = helpers;
  const db = getDb();
  const p = url.pathname;

  // ---------- connections (organization-owned, admin only) ----------
  if (p === '/api/mail/connections' && req.method === 'GET') {
    if (!requireAdmin()) return true;
    const rows = db.prepare('SELECT id, provider, label, accounts_base, api_base, client_id, scopes, status, status_detail, created_at, (refresh_token_enc IS NOT NULL) AS authorized FROM connections').all();
    return send(200, rows);
  }
  if (p === '/api/mail/connections' && req.method === 'POST') {
    if (!requireAdmin()) return true;
    const { label, client_id, client_secret, accounts_base, api_base } = body;
    if (!client_id || !client_secret) return send(400, { error: 'client_id and client_secret are required' });
    const r = db.prepare(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id, client_secret_enc, scopes, created_by, created_at)
      VALUES ('zoho',?,?,?,?,?,?,?,?)`)
      .run(label || 'Zoho Organization', accounts_base || 'https://accounts.zoho.com', api_base || 'https://mail.zoho.com',
        client_id, encrypt(client_secret), READ_SCOPES, user.id, Date.now());
    audit(user.id, 'mail.connection.create', label || client_id);
    return send(200, { id: Number(r.lastInsertRowid) });
  }
  let m;
  if ((m = p.match(/^\/api\/mail\/connections\/(\d+)\/authorize-url$/)) && req.method === 'GET') {
    if (!requireAdmin()) return true;
    const zoho = ZohoClient.forConnection(Number(m[1]));
    const redirect = helpers.baseUrl + '/oauth/callback';
    return send(200, { url: zoho.authorizeUrl(redirect) + '&state=' + m[1], redirectUri: redirect });
  }
  if (p === '/oauth/callback' && req.method === 'GET') {
    const code = url.searchParams.get('code');
    const connId = Number(url.searchParams.get('state'));
    if (!code || !connId) return send(400, 'Missing code/state', 'text/plain');
    const zoho = ZohoClient.forConnection(connId);
    await zoho.exchangeCode(code, helpers.baseUrl + '/oauth/callback');
    audit(user && user.id, 'mail.connection.authorized', String(connId));
    res.writeHead(302, { Location: '/?connected=1' });
    res.end();
    return true;
  }

  // ---------- organization-wide discovery ----------
  if (p === '/api/mail/discover' && req.method === 'POST') {
    if (!requireAdmin()) return true;
    const connId = Number(body.connection_id);
    const zoho = ZohoClient.forConnection(connId);
    const discovery = await detection.discoverOrganization(zoho);
    const results = [];
    for (const mb of discovery.mailboxes) {
      const caps = await detection.probeCapabilities(zoho, mb);
      const choice = detection.chooseStrategy(mb, caps);
      const id = detection.upsertMailbox(connId, mb, caps, choice);
      results.push({ id, address: mb.address, detectedType: mb.detectedType, strategy: choice.strategy, status: choice.status });
    }
    const baseline = loadBaseline();
    const comparison = detection.compareWithBaseline(
      discovery.mailboxes.filter(x => x.detectedType === 'shared_mailbox'),
      baseline.filter(b => (b.type || 'shared_mailbox') === 'shared_mailbox'));
    db.prepare('INSERT INTO detection_reports (mailbox_id, at, report) VALUES (0, ?, ?)')
      .run(Date.now(), JSON.stringify({ scope: 'organization', evidence: discovery.evidence, comparison }));
    audit(user.id, 'mail.discover', 'connection:' + connId, comparison);
    return send(200, { results, comparison, evidence: discovery.evidence });
  }
  if (p === '/api/mail/discovery-status' && req.method === 'GET') {
    if (!requireAdmin()) return true;
    const last = db.prepare('SELECT * FROM detection_reports WHERE mailbox_id = 0 ORDER BY id DESC LIMIT 1').get();
    return send(200, last ? { at: last.at, ...JSON.parse(last.report) } : { comparison: null });
  }

  // ---------- mailboxes ----------
  if (p === '/api/mail/mailboxes' && req.method === 'GET') {
    const ids = new Set(auth.readableMailboxIds(user));
    const rows = db.prepare('SELECT * FROM mailboxes ORDER BY address').all()
      .filter(r => user.role === 'admin' || ids.has(r.id));
    return send(200, rows.map(mailboxRow));
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)$/)) && req.method === 'GET') {
    const row = db.prepare('SELECT * FROM mailboxes WHERE id=?').get(Number(m[1]));
    if (!row) return send(404, { error: 'not found' });
    if (!auth.canReadMailbox(user, row.id)) return send(403, { error: 'forbidden' });
    const report = db.prepare('SELECT at, report FROM detection_reports WHERE mailbox_id=? ORDER BY id DESC LIMIT 1').get(row.id);
    return send(200, { ...mailboxRow(row), lastDetection: report ? { at: report.at, ...JSON.parse(report.report) } : null });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/pilot$/)) && req.method === 'POST') {
    if (!requireAdmin()) return true;
    db.prepare('UPDATE mailboxes SET is_pilot=? WHERE id=?').run(body.on ? 1 : 0, Number(m[1]));
    audit(user.id, 'mail.pilot.' + (body.on ? 'on' : 'off'), 'mailbox:' + m[1]);
    return send(200, { ok: true });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/sync$/)) && req.method === 'POST') {
    if (!requireAdmin()) return true;
    // Explicit admin action — this is the ONLY thing that enables scheduled
    // incremental sync afterwards. Discovery never triggers sync by itself.
    db.prepare('UPDATE mailboxes SET sync_enabled=1 WHERE id=?').run(Number(m[1]));
    audit(user.id, 'mail.pilot_sync.start', 'mailbox:' + m[1]);
    const summary = await syncMailbox(Number(m[1]));
    return send(200, summary);
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/import-archive$/)) && req.method === 'POST') {
    if (!requireAdmin()) return true;
    if (!Buffer.isBuffer(body) || !body.length) return send(400, { error: 'upload the eDiscovery/Backup export ZIP as the raw request body (Content-Type: application/zip)' });
    const summary = importArchiveZip(Number(m[1]), body, user.id);
    return send(200, summary);
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/folders$/)) && req.method === 'GET') {
    const id = Number(m[1]);
    if (!auth.canReadMailbox(user, id)) return send(403, { error: 'forbidden' });
    return send(200, db.prepare('SELECT id, name, folder_type FROM folders WHERE mailbox_id=? ORDER BY name').all(id));
  }

  // ---------- messages / search / attachments ----------
  if (p === '/api/mail/messages' && req.method === 'GET') {
    const allowed = auth.readableMailboxIds(user);
    if (!allowed.length) return send(200, []);
    const mailboxId = url.searchParams.get('mailbox_id') ? Number(url.searchParams.get('mailbox_id')) : null;
    if (mailboxId && !allowed.includes(mailboxId)) return send(403, { error: 'forbidden' });
    const folderId = url.searchParams.get('folder_id') ? Number(url.searchParams.get('folder_id')) : null;
    const q = (url.searchParams.get('q') || '').trim();
    const scope = mailboxId ? [mailboxId] : allowed;
    const ph = scope.map(() => '?').join(',');
    let rows;
    if (q) {
      // FTS across all permitted mailboxes, or one selected mailbox.
      rows = db.prepare(`SELECT msg.* FROM messages_fts f JOIN messages msg ON msg.id = f.rowid
        WHERE messages_fts MATCH ? AND msg.mailbox_id IN (${ph}) ${folderId ? 'AND msg.folder_id = ?' : ''}
        ORDER BY msg.received_at DESC LIMIT 100`)
        .all(q.replace(/['"*]/g, ' '), ...scope, ...(folderId ? [folderId] : []));
    } else {
      rows = db.prepare(`SELECT * FROM messages WHERE mailbox_id IN (${ph}) ${folderId ? 'AND folder_id = ?' : ''}
        ORDER BY received_at DESC LIMIT 100`).all(...scope, ...(folderId ? [folderId] : []));
    }
    return send(200, rows.map(r => ({ ...r, body_html: undefined })));
  }
  if ((m = p.match(/^\/api\/mail\/messages\/(\d+)$/)) && req.method === 'GET') {
    const row = db.prepare('SELECT * FROM messages WHERE id=?').get(Number(m[1]));
    if (!row) return send(404, { error: 'not found' });
    if (!auth.canReadMailbox(user, row.mailbox_id)) return send(403, { error: 'forbidden' });
    audit(user.id, 'mail.message.read', 'message:' + row.id);
    const atts = db.prepare('SELECT id, name, size, mime FROM attachments WHERE message_id=?').all(row.id);
    return send(200, { ...row, attachments: atts });
  }
  if ((m = p.match(/^\/api\/mail\/attachments\/(\d+)$/)) && req.method === 'GET') {
    const att = db.prepare(`SELECT a.*, msg.mailbox_id FROM attachments a JOIN messages msg ON msg.id=a.message_id WHERE a.id=?`).get(Number(m[1]));
    if (!att) return send(404, { error: 'not found' });
    if (!auth.canReadMailbox(user, att.mailbox_id)) return send(403, { error: 'forbidden' });
    audit(user.id, 'mail.attachment.read', att.name);
    const full = path.join(ATTACH_DIR, path.basename(att.file_path));
    if (!fs.existsSync(full)) return send(404, { error: 'file missing' });
    res.writeHead(200, { 'Content-Type': att.mime || 'application/octet-stream', 'Content-Disposition': `inline; filename="${encodeURIComponent(att.name)}"` });
    fs.createReadStream(full).pipe(res);
    return true;
  }

  // ---------- labels ----------
  if (p === '/api/mail/labels' && req.method === 'GET') {
    return send(200, db.prepare('SELECT * FROM labels ORDER BY name').all());
  }
  if (p === '/api/mail/labels' && req.method === 'POST') {
    if (!requireAdmin()) return true;
    const r = db.prepare('INSERT INTO labels (name, color) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET color=excluded.color')
      .run(body.name, body.color || '#2545d3');
    return send(200, { id: Number(r.lastInsertRowid) });
  }
  if ((m = p.match(/^\/api\/mail\/messages\/(\d+)\/labels$/)) && req.method === 'POST') {
    const row = db.prepare('SELECT mailbox_id FROM messages WHERE id=?').get(Number(m[1]));
    if (!row || !auth.canReadMailbox(user, row.mailbox_id)) return send(403, { error: 'forbidden' });
    if (body.add) db.prepare('INSERT OR IGNORE INTO message_labels (message_id, label_id) VALUES (?,?)').run(Number(m[1]), Number(body.add));
    if (body.remove) db.prepare('DELETE FROM message_labels WHERE message_id=? AND label_id=?').run(Number(m[1]), Number(body.remove));
    return send(200, { ok: true });
  }

  return false; // not handled
}

module.exports = { handle };
