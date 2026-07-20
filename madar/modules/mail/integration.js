// Accounting integration layer — Madar as the stable abstraction over shared
// mailboxes. External systems (accounting consuming finance@/billing@/tax@)
// never touch Zoho: they poll THIS interface with a machine key.
//
// Contract:
//   * stable ids: mailbox id and occurrence id are DB identities — they never
//     change or get reused; canonicalId dedupes across mailboxes.
//   * unread semantics: each (key, mailbox) has a durable monotonic cursor;
//     GET messages without after_id returns everything past the cursor, the
//     consumer acknowledges with POST cursor. after_id=0 replays full history.
//   * fidelity: provider message id, RFC id (when known), sender, recipients,
//     both timestamps, folder, attachments metadata + bytes.
//   * no duplicates: schema + provider-identity guard ensure one occurrence
//     per canonical per mailbox; the cursor makes delivery exactly-once per
//     consumer position.
//   * auth: sha256-hashed keys (secret shown once at creation), per-key
//     mailbox scope decided by an admin (audited) — machine access is as
//     explicit as human grants. Out-of-scope = 404 (anti-enumeration).
const crypto = require('crypto');
const { all, one, q } = require('../../core/db');
const { getStorage } = require('../../core/storage');

const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- key lifecycle (called from admin routes; audited there) ----------
async function createKey({ name, mailboxIds, createdBy = null }) {
  if (!name || !Array.isArray(mailboxIds) || mailboxIds.length === 0) {
    throw new Error('name and a non-empty mailbox_ids list are required');
  }
  const secret = 'mik_' + crypto.randomBytes(20).toString('hex');
  const row = await one(`INSERT INTO integration_keys (name, key_hash, key_prefix, created_by)
    VALUES ($1,$2,$3,$4) RETURNING id`, [String(name), sha256hex(secret), secret.slice(0, 12) + '…', createdBy]);
  for (const mid of mailboxIds) {
    const mb = await one('SELECT id FROM mailboxes WHERE id=$1', [Number(mid)]);
    if (!mb) throw new Error(`mailbox ${mid} not found`);
    await q('INSERT INTO integration_key_mailboxes (key_id, mailbox_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [row.id, Number(mid)]);
  }
  return { id: Number(row.id), secret }; // secret leaves this function exactly once
}

async function revokeKey(keyId) {
  return one(`UPDATE integration_keys SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL RETURNING id`, [Number(keyId)]);
}

// Rotation: SAME key identity — mailbox scope and per-mailbox cursors survive
// (no replay storm for the consumer), the old secret dies atomically with the
// hash swap. Returns the new secret exactly once.
async function rotateKey(keyId) {
  const secret = 'mik_' + crypto.randomBytes(20).toString('hex');
  const r = await one(`UPDATE integration_keys SET key_hash=$2, key_prefix=$3
    WHERE id=$1 AND revoked_at IS NULL RETURNING id`,
  [Number(keyId), sha256hex(secret), secret.slice(0, 12) + '…']);
  return r ? { id: Number(r.id), secret } : null;
}

async function listKeys() {
  return (await all(`SELECT k.id, k.name, k.key_prefix AS prefix, k.created_at, k.revoked_at, k.last_used_at,
      COALESCE(json_agg(json_build_object('id', m.id, 'address', m.address)) FILTER (WHERE m.id IS NOT NULL), '[]') AS mailboxes
    FROM integration_keys k
    LEFT JOIN integration_key_mailboxes km ON km.key_id = k.id
    LEFT JOIN mailboxes m ON m.id = km.mailbox_id
    GROUP BY k.id ORDER BY k.id`)).map(r => ({ ...r, id: Number(r.id) }));
}

async function verifyKey(secret) {
  if (!secret || typeof secret !== 'string') return null;
  const key = await one(`SELECT id, name FROM integration_keys WHERE key_hash=$1 AND revoked_at IS NULL`, [sha256hex(secret)]);
  if (key) await q('UPDATE integration_keys SET last_used_at=now() WHERE id=$1', [key.id]);
  return key;
}

// ---------- scoped reads ----------
async function inScope(keyId, mailboxId) {
  return Boolean(await one('SELECT 1 FROM integration_key_mailboxes WHERE key_id=$1 AND mailbox_id=$2', [keyId, mailboxId]));
}

async function scopedMailboxes(keyId) {
  return (await all(`SELECT m.id, m.address, m.display_name, m.detected_type
    FROM integration_key_mailboxes km JOIN mailboxes m ON m.id = km.mailbox_id
    WHERE km.key_id = $1 ORDER BY m.id`, [keyId]))
    .map(m => ({ id: Number(m.id), address: m.address, displayName: m.display_name,
      type: m.detected_type === 'shared_mailbox' ? 'shared' : m.detected_type }));
}

async function listMessages(keyId, mailboxId, { afterId = null, limit = 100 } = {}) {
  let cursor = afterId;
  if (cursor == null) {
    const c = await one('SELECT last_occurrence_id FROM integration_cursors WHERE key_id=$1 AND mailbox_id=$2', [keyId, mailboxId]);
    cursor = c ? Number(c.last_occurrence_id) : 0;
  }
  const lim = Math.max(1, Math.min(500, Number(limit) || 100));
  const rows = await all(`SELECT o.id AS occurrence_id, o.canonical_message_id,
      o.direction, o.received_at, o.envelope_to, o.envelope_cc, f.name AS folder,
      c.rfc_message_id, c.thread_id, c.from_address, c.from_name, c.to_addresses, c.cc_addresses,
      c.subject, c.snippet, c.sent_at, c.has_attachments
    FROM message_occurrences o
    JOIN canonical_messages c ON c.id = o.canonical_message_id
    LEFT JOIN folders f ON f.id = o.folder_id
    WHERE o.mailbox_id = $1 AND o.id > $2
    ORDER BY o.id LIMIT ${lim}`, [mailboxId, cursor]);

  const canonIds = [...new Set(rows.map(r => Number(r.canonical_message_id)))];
  const attRows = canonIds.length
    ? await all(`SELECT id, canonical_message_id, sanitized_filename AS name, size,
          detected_mime_type AS mime, quarantine_status FROM attachments WHERE canonical_message_id = ANY($1)`, [canonIds])
    : [];
  const attsByCanon = new Map();
  for (const a of attRows) {
    const k = Number(a.canonical_message_id);
    if (!attsByCanon.has(k)) attsByCanon.set(k, []);
    attsByCanon.get(k).push({ id: Number(a.id), name: a.name, size: Number(a.size),
      mime: a.mime, quarantined: a.quarantine_status === 'quarantined' });
  }

  // External identity contract: messageId (Madar canonical) is the PRIMARY
  // identity; occurrenceId is the delivery-position id the cursor speaks.
  // Provider ids and the member-copy mechanism are Madar internals — they
  // never cross this boundary (Madar is the source of truth, not Zoho).
  const messages = rows.map(r => ({
    messageId: Number(r.canonical_message_id),
    occurrenceId: Number(r.occurrence_id),
    rfcMessageId: r.rfc_message_id || null,
    threadId: r.thread_id || null,
    direction: r.direction,
    subject: r.subject,
    snippet: r.snippet,
    from: { address: r.from_address, name: r.from_name },
    to: r.envelope_to || r.to_addresses,
    cc: r.envelope_cc || r.cc_addresses,
    sentAt: new Date(r.sent_at).toISOString(),
    receivedAt: new Date(r.received_at).toISOString(),
    folder: r.folder,
    hasAttachments: Boolean(r.has_attachments),
    attachments: attsByCanon.get(Number(r.canonical_message_id)) || [],
  }));
  return { mailboxId: Number(mailboxId), cursorUsed: Number(cursor),
    nextCursor: messages.length ? messages[messages.length - 1].occurrenceId : Number(cursor),
    count: messages.length, messages };
}

// Monotonic per-consumer acknowledgement — an accidental lower ack can never
// rewind the consumer's position (GREATEST, same pattern as sync cursors).
async function setCursor(keyId, mailboxId, lastOccurrenceId) {
  const r = await one(`INSERT INTO integration_cursors (key_id, mailbox_id, last_occurrence_id, updated_at)
    VALUES ($1,$2,$3,now())
    ON CONFLICT (key_id, mailbox_id) DO UPDATE
      SET last_occurrence_id = GREATEST(integration_cursors.last_occurrence_id, EXCLUDED.last_occurrence_id),
          updated_at = now()
    RETURNING last_occurrence_id`, [keyId, mailboxId, Math.max(0, Number(lastOccurrenceId) || 0)]);
  return Number(r.last_occurrence_id);
}

// ---------- HTTP surface (machine path: key auth, no session, no CSRF) ----------
// Every access is audited with the consumer identity (key id — never the
// secret), the mailbox, the message range, and the action. Auth failures are
// audited too (without the attempted credential).
async function handle(req, res, url, send, readBody) {
  const { audit } = require('../../core/audit');
  const p = url.pathname;
  const bearer = (String(req.headers.authorization || '').match(/^Bearer\s+(\S+)$/) || [])[1];
  const key = await verifyKey(String(req.headers['x-api-key'] || bearer || ''));
  if (!key) {
    await audit(null, 'integration.auth_failed', p); // the attempted secret is never logged
    return send(401, { error: 'invalid or missing API key' });
  }
  let m;

  if (p === '/api/integration/v1/mailboxes' && req.method === 'GET') {
    const boxes = await scopedMailboxes(key.id);
    await audit(null, 'integration.mailboxes.list', `key:${key.id}`, { count: boxes.length });
    return send(200, boxes);
  }
  if ((m = p.match(/^\/api\/integration\/v1\/mailboxes\/(\d+)\/messages$/)) && req.method === 'GET') {
    const mailboxId = Number(m[1]);
    if (!(await inScope(key.id, mailboxId))) return send(404, { error: 'not found' });
    const afterParam = url.searchParams.get('after_id');
    const out = await listMessages(key.id, mailboxId, {
      afterId: afterParam != null ? Number(afterParam) : null,
      limit: url.searchParams.get('limit'),
    });
    await audit(null, 'integration.messages.read', `key:${key.id} mailbox:${mailboxId}`, {
      count: out.count, cursorUsed: out.cursorUsed,
      firstOccurrenceId: out.messages[0] ? out.messages[0].occurrenceId : null,
      lastOccurrenceId: out.messages.length ? out.messages[out.messages.length - 1].occurrenceId : null,
    });
    return send(200, out);
  }
  if ((m = p.match(/^\/api\/integration\/v1\/mailboxes\/(\d+)\/cursor$/)) && req.method === 'POST') {
    const mailboxId = Number(m[1]);
    if (!(await inScope(key.id, mailboxId))) return send(404, { error: 'not found' });
    const body = await readBody(req);
    const v = Number(body && body.last_occurrence_id);
    if (!Number.isFinite(v) || v < 0) return send(400, { error: 'last_occurrence_id (non-negative number) required' });
    const cur = await setCursor(key.id, mailboxId, v);
    await audit(null, 'integration.cursor.set', `key:${key.id} mailbox:${mailboxId}`, { lastOccurrenceId: cur });
    return send(200, { ok: true, lastOccurrenceId: cur });
  }
  if ((m = p.match(/^\/api\/integration\/v1\/attachments\/(\d+)$/)) && req.method === 'GET') {
    const att = await one('SELECT * FROM attachments WHERE id=$1', [Number(m[1])]);
    // scope: the attachment's canonical must have an occurrence in a mailbox
    // this key covers — otherwise indistinguishable from nonexistent
    const scoped = att && await one(`SELECT 1 FROM message_occurrences o
      JOIN integration_key_mailboxes km ON km.mailbox_id = o.mailbox_id AND km.key_id = $2
      WHERE o.canonical_message_id = $1 LIMIT 1`, [att.canonical_message_id, key.id]);
    if (!scoped) return send(404, { error: 'not found' });
    if (att.quarantine_status === 'quarantined') {
      return send(423, { error: 'attachment quarantined (declared type does not match detected content)' });
    }
    const storage = getStorage();
    if (!storage.exists(att.storage_key)) return send(404, { error: 'file missing' });
    await audit(null, 'integration.attachment.download', `key:${key.id} attachment:${att.id}`,
      { canonicalMessageId: Number(att.canonical_message_id) });
    res.writeHead(200, {
      'Content-Type': att.detected_mime_type || 'application/octet-stream', // detected, never provider-claimed
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Content-Disposition': `attachment; filename="${att.sanitized_filename}"`,
      'Cache-Control': 'private, no-store',
      'Content-Length': Number(att.size),
    });
    storage.getObject(att.storage_key).pipe(res);
    return true;
  }
  return send(404, { error: 'not found' });
}

module.exports = { createKey, revokeKey, rotateKey, listKeys, verifyKey, inScope, scopedMailboxes, listMessages, setCursor, handle };
