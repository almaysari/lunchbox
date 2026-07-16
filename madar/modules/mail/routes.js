// Mail module REST API (PostgreSQL, async).
const fs = require('fs');
const path = require('path');
const { q, one, all } = require('../../core/db');
const { encrypt } = require('../../core/crypto');
const { getStorage } = require('../../core/storage');
const { audit } = require('../../core/audit');
const auth = require('../../core/auth');
const { ZohoClient, READ_SCOPES } = require('./zoho-client');
const detection = require('./detection');
const { syncMailbox, importArchiveZip, cancelSync } = require('./sync');

// Expected-mailboxes baseline: validation reference ONLY (never a data source).
function loadBaseline() {
  for (const p of [
    path.join(__dirname, '..', '..', 'data', 'expected-mailboxes.json'),
    path.join(__dirname, '..', '..', 'test', 'fixtures', 'expected-mailboxes.json'),
  ]) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { /* next */ }
  }
  return [];
}

const jsonCol = v => typeof v === 'string' ? JSON.parse(v || 'null') : (v ?? null);

async function mailboxRow(m) {
  return {
    id: Number(m.id), address: m.address, displayName: m.display_name, provider: m.provider,
    connectionId: m.connection_id && Number(m.connection_id), detectedType: m.detected_type, strategy: m.strategy,
    accessLevel: m.access_level, moderationCount: m.moderation_count,
    members: jsonCol(m.members) || [], moderators: jsonCol(m.moderators) || [],
    capabilities: jsonCol(m.capabilities) || {},
    isPilot: Boolean(m.is_pilot), syncEnabled: Boolean(m.sync_enabled),
    status: m.status, statusDetail: m.status_detail,
    providerAccountId: m.provider_account_id, providerGroupId: m.provider_group_id,
    aliases: (await all('SELECT address FROM mailbox_aliases WHERE mailbox_id = $1', [m.id])).map(r => r.address),
  };
}

async function handle(req, res, url, user, body, helpers) {
  const { send, requireAdmin } = helpers;
  const p = url.pathname;
  let m;

  // ---------- connections (organization-owned, admin only) ----------
  if (p === '/api/mail/connections' && req.method === 'GET') {
    if (!requireAdmin()) return true;
    return send(200, await all(`SELECT id, provider, label, accounts_base, api_base, client_id, scopes, status,
      status_detail, created_at, (refresh_token_enc IS NOT NULL) AS authorized FROM connections ORDER BY id`));
  }
  if (p === '/api/mail/connections' && req.method === 'POST') {
    if (!requireAdmin()) return true;
    const { label, client_id, client_secret, accounts_base, api_base } = body;
    if (!client_id || !client_secret) return send(400, { error: 'client_id and client_secret are required' });
    const r = await one(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id, client_secret_enc, scopes, created_by)
      VALUES ('zoho',$1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [label || 'Zoho Organization', accounts_base || 'https://accounts.zoho.com', api_base || 'https://mail.zoho.com',
        client_id, encrypt(client_secret), READ_SCOPES, user.id]);
    await audit(user.id, 'mail.connection.create', label || client_id);
    return send(200, { id: Number(r.id) });
  }
  if ((m = p.match(/^\/api\/mail\/connections\/(\d+)\/authorize-url$/)) && req.method === 'GET') {
    if (!requireAdmin()) return true;
    const zoho = await ZohoClient.forConnection(Number(m[1]));
    const redirect = helpers.baseUrl + '/oauth/callback';
    return send(200, { url: zoho.authorizeUrl(redirect) + '&state=' + m[1], redirectUri: redirect });
  }
  if (p === '/oauth/callback' && req.method === 'GET') {
    const code = url.searchParams.get('code');
    const connId = Number(url.searchParams.get('state'));
    if (!code || !connId) return send(400, 'Missing code/state', 'text/plain');
    const zoho = await ZohoClient.forConnection(connId);
    await zoho.exchangeCode(code, helpers.baseUrl + '/oauth/callback');
    await audit(user && user.id, 'mail.connection.authorized', String(connId));
    res.writeHead(302, { Location: '/?connected=1' });
    res.end();
    return true;
  }

  // ---------- organization-wide discovery ----------
  if (p === '/api/mail/discover' && req.method === 'POST') {
    if (!requireAdmin()) return true;
    const connId = Number(body.connection_id);
    const zoho = await ZohoClient.forConnection(connId);
    const discovery = await detection.discoverOrganization(zoho);
    const results = [];
    for (const mb of discovery.mailboxes) {
      const caps = await detection.probeCapabilities(zoho, mb);
      const choice = detection.chooseStrategy(mb, caps);
      const id = await detection.upsertMailbox(connId, mb, caps, choice);
      results.push({ id, address: mb.address, detectedType: mb.detectedType, strategy: choice.strategy, status: choice.status });
    }
    const baseline = loadBaseline();
    const comparison = detection.compareWithBaseline(
      discovery.mailboxes.filter(x => x.detectedType === 'shared_mailbox'),
      baseline.filter(b => (b.type || 'shared_mailbox') === 'shared_mailbox'));
    await q('INSERT INTO detection_reports (mailbox_id, report) VALUES (0, $1)',
      [JSON.stringify({ scope: 'organization', evidence: discovery.evidence, comparison })]);
    await audit(user.id, 'mail.discover', 'connection:' + connId, comparison);
    return send(200, { results, comparison, evidence: discovery.evidence });
  }
  if (p === '/api/mail/discovery-status' && req.method === 'GET') {
    if (!requireAdmin()) return true;
    const last = await one('SELECT * FROM detection_reports WHERE mailbox_id = 0 ORDER BY id DESC LIMIT 1');
    return send(200, last ? { at: new Date(last.at).getTime(), ...jsonCol(last.report) } : { comparison: null });
  }

  // ---------- mailboxes ----------
  if (p === '/api/mail/mailboxes' && req.method === 'GET') {
    const ids = new Set(await auth.readableMailboxIds(user));
    const rows = (await all('SELECT * FROM mailboxes ORDER BY address')).filter(r => user.role === 'admin' || ids.has(Number(r.id)));
    return send(200, await Promise.all(rows.map(mailboxRow)));
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)$/)) && req.method === 'GET') {
    const row = await one('SELECT * FROM mailboxes WHERE id = $1', [Number(m[1])]);
    if (!row) return send(404, { error: 'not found' });
    if (!(await auth.canReadMailbox(user, Number(row.id)))) return send(403, { error: 'forbidden' });
    const report = await one('SELECT at, report FROM detection_reports WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1', [row.id]);
    return send(200, {
      ...(await mailboxRow(row)),
      lastDetection: report ? { at: new Date(report.at).getTime(), ...jsonCol(report.report) } : null,
    });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/pilot$/)) && req.method === 'POST') {
    if (!requireAdmin()) return true;
    await q('UPDATE mailboxes SET is_pilot = $1 WHERE id = $2', [Boolean(body.on), Number(m[1])]);
    await audit(user.id, 'mail.pilot.' + (body.on ? 'on' : 'off'), 'mailbox:' + m[1]);
    return send(200, { ok: true });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/sync$/)) && req.method === 'POST') {
    if (!requireAdmin()) return true;
    // Explicit admin action — the only thing that enables scheduled sync later.
    await q('UPDATE mailboxes SET sync_enabled = TRUE WHERE id = $1', [Number(m[1])]);
    await audit(user.id, 'mail.pilot_sync.start', 'mailbox:' + m[1]);
    return send(200, await syncMailbox(Number(m[1])));
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/sync\/cancel$/)) && req.method === 'POST') {
    if (!requireAdmin()) return true;
    cancelSync(Number(m[1]));
    await audit(user.id, 'mail.pilot_sync.cancel', 'mailbox:' + m[1]);
    return send(200, { ok: true });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/import-archive$/)) && req.method === 'POST') {
    if (!requireAdmin()) return true;
    if (!Buffer.isBuffer(body) || !body.length) return send(400, { error: 'upload the eDiscovery/Backup export ZIP as the raw request body (Content-Type: application/zip)' });
    return send(200, await importArchiveZip(Number(m[1]), body, user.id));
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/folders$/)) && req.method === 'GET') {
    const id = Number(m[1]);
    if (!(await auth.canReadMailbox(user, id))) return send(403, { error: 'forbidden' });
    return send(200, await all('SELECT id, name, folder_type FROM folders WHERE mailbox_id = $1 ORDER BY name', [id]));
  }

  // ---------- messages / search / attachments ----------
  if (p === '/api/mail/messages' && req.method === 'GET') {
    const allowed = await auth.readableMailboxIds(user);
    if (!allowed.length) return send(200, []);
    const mailboxId = url.searchParams.get('mailbox_id') ? Number(url.searchParams.get('mailbox_id')) : null;
    if (mailboxId && !allowed.includes(mailboxId)) return send(403, { error: 'forbidden' });
    const folderId = url.searchParams.get('folder_id') ? Number(url.searchParams.get('folder_id')) : null;
    const qtext = (url.searchParams.get('q') || '').trim();
    const scope = mailboxId ? [mailboxId] : allowed;
    const params = [scope];
    let where = 'mailbox_id = ANY($1)';
    if (folderId) { params.push(folderId); where += ` AND folder_id = $${params.length}`; }
    if (qtext) { params.push(qtext.split(/\s+/).join(' & ')); where += ` AND fts @@ to_tsquery('simple', $${params.length})`; }
    const rows = await all(`SELECT id, mailbox_id, folder_id, provider_message_id, from_address, from_name,
      subject, snippet, received_at, direction, has_attachments
      FROM messages WHERE ${where} ORDER BY received_at DESC LIMIT 100`, params);
    return send(200, rows.map(r => ({ ...r, received_at: new Date(r.received_at).getTime() })));
  }
  if ((m = p.match(/^\/api\/mail\/messages\/(\d+)$/)) && req.method === 'GET') {
    const row = await one('SELECT * FROM messages WHERE id = $1', [Number(m[1])]);
    if (!row) return send(404, { error: 'not found' });
    if (!(await auth.canReadMailbox(user, Number(row.mailbox_id)))) return send(403, { error: 'forbidden' });
    await audit(user.id, 'mail.message.read', 'message:' + row.id);
    const atts = await all('SELECT id, name, size, mime FROM attachments WHERE message_id = $1', [row.id]);
    return send(200, { ...row, fts: undefined, received_at: new Date(row.received_at).getTime(), attachments: atts });
  }
  if ((m = p.match(/^\/api\/mail\/attachments\/(\d+)$/)) && req.method === 'GET') {
    const att = await one(`SELECT a.*, msg.mailbox_id FROM attachments a JOIN messages msg ON msg.id = a.message_id WHERE a.id = $1`, [Number(m[1])]);
    if (!att) return send(404, { error: 'not found' });
    if (!(await auth.canReadMailbox(user, Number(att.mailbox_id)))) return send(403, { error: 'forbidden' });
    await audit(user.id, 'mail.attachment.read', att.name);
    const storage = getStorage();
    if (!storage.exists(att.storage_key)) return send(404, { error: 'file missing' });
    res.writeHead(200, { 'Content-Type': att.mime || 'application/octet-stream', 'Content-Disposition': `inline; filename="${encodeURIComponent(att.name)}"` });
    storage.getStream(att.storage_key).pipe(res);
    return true;
  }

  // ---------- labels ----------
  if (p === '/api/mail/labels' && req.method === 'GET') {
    return send(200, await all('SELECT * FROM labels ORDER BY name'));
  }
  if (p === '/api/mail/labels' && req.method === 'POST') {
    if (!requireAdmin()) return true;
    const r = await one(`INSERT INTO labels (name, color) VALUES ($1,$2)
      ON CONFLICT (name) DO UPDATE SET color = EXCLUDED.color RETURNING id`, [body.name, body.color || '#2545d3']);
    return send(200, { id: Number(r.id) });
  }
  if ((m = p.match(/^\/api\/mail\/messages\/(\d+)\/labels$/)) && req.method === 'POST') {
    const row = await one('SELECT mailbox_id FROM messages WHERE id = $1', [Number(m[1])]);
    if (!row || !(await auth.canReadMailbox(user, Number(row.mailbox_id)))) return send(403, { error: 'forbidden' });
    if (body.add) await q('INSERT INTO message_labels (message_id, label_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [Number(m[1]), Number(body.add)]);
    if (body.remove) await q('DELETE FROM message_labels WHERE message_id = $1 AND label_id = $2', [Number(m[1]), Number(body.remove)]);
    return send(200, { ok: true });
  }

  return false; // not handled
}

module.exports = { handle };
