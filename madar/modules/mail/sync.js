// Ingestion pipeline — READ-ONLY, PostgreSQL-backed.
// Runs ONLY for pilot mailboxes whose sync was explicitly started by an admin.
// Resume-safe: the backfill cursor persists in sync_state, so a crash or
// restart continues where it stopped. Cancellable mid-run via cancelSync().
const { q, one, all } = require('../../core/db');
const { getStorage } = require('../../core/storage');
const { sha256 } = require('../../core/crypto');
const { audit } = require('../../core/audit');
const { ZohoClient } = require('./zoho-client');
const { ZohoMailApiConnector } = require('./connectors/zoho-mail-api');
const { messagesFromExportZip } = require('./connectors/ediscovery-import');

const MAX_RPM = Number(process.env.MADAR_MAX_RPM || 25); // stay under Zoho's documented ~30 req/min
const PAGE_SIZE = 100;
const delay = ms => new Promise(r => setTimeout(r, ms));
const budgetDelay = () => delay(Math.ceil(60000 / MAX_RPM));

const cancelFlags = new Map(); // mailboxId -> true
function cancelSync(mailboxId) { cancelFlags.set(Number(mailboxId), true); }
function checkCancel(mailboxId) {
  if (cancelFlags.get(Number(mailboxId))) {
    cancelFlags.delete(Number(mailboxId));
    const err = new Error('Sync cancelled by admin');
    err.cancelled = true;
    throw err;
  }
}

function dedupHash(m) {
  const key = m.rfcMessageId
    ? 'rfc:' + m.rfcMessageId.trim()
    : 'fp:' + [m.from, m.subject, m.receivedAt].join('|');
  return sha256(Buffer.from(key));
}

async function upsertFolder(mailboxId, f) {
  const r = await one(`INSERT INTO folders (mailbox_id, provider_folder_id, name, folder_type) VALUES ($1,$2,$3,$4)
    ON CONFLICT (mailbox_id, provider_folder_id) DO UPDATE SET name = EXCLUDED.name, folder_type = EXCLUDED.folder_type
    RETURNING id`, [mailboxId, f.providerFolderId, f.name, f.type || '']);
  return Number(r.id);
}

// Returns inserted message id, or null on duplicate (unique constraints).
async function insertMessage(mailboxId, folderId, m) {
  const r = await one(`INSERT INTO messages (mailbox_id, folder_id, provider_message_id, rfc_message_id,
      dedup_hash, thread_id, from_address, from_name, to_addresses, cc_addresses, subject, snippet,
      body_html, received_at, direction, has_attachments)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
    ON CONFLICT DO NOTHING RETURNING id`,
    [mailboxId, folderId, m.providerMessageId, m.rfcMessageId || '', dedupHash(m), m.threadId || '',
      m.from || '', m.fromName || '', m.to || '', m.cc || '', m.subject || '', m.snippet || '',
      m.bodyHtml || null, new Date(Number(m.receivedAt) || Date.now()), m.direction || 'in', Boolean(m.hasAttachments)]);
  return r ? Number(r.id) : null;
}

async function storeAttachment(messageId, name, mime, buf) {
  const { key, sha256: hash, size } = getStorage().put(buf);
  await q('INSERT INTO attachments (message_id, name, size, mime, storage_key, sha256) VALUES ($1,$2,$3,$4,$5,$6)',
    [messageId, name, size, mime || '', key, hash]);
}

async function connectorFor(mailbox) {
  if (mailbox.strategy !== 'mail_api') {
    throw new Error(`Mailbox ${mailbox.address} has no live-sync strategy (strategy=${mailbox.strategy}).`);
  }
  const zoho = await ZohoClient.forConnection(mailbox.connection_id);
  return new ZohoMailApiConnector(zoho, mailbox);
}

async function syncMailbox(mailboxId, { maxPages = 5 } = {}) {
  const mailbox = await one('SELECT * FROM mailboxes WHERE id = $1', [mailboxId]);
  if (!mailbox) throw new Error('mailbox not found');
  if (!mailbox.is_pilot) throw new Error('sync refused: mailbox is not pilot-selected');
  if (!mailbox.sync_enabled) throw new Error('sync refused: not explicitly started by an admin');
  const connector = await connectorFor(mailbox);
  const summary = { mailbox: mailbox.address, folders: 0, newMessages: 0, attachments: 0, pagesUsed: 0 };

  await q("UPDATE mailboxes SET status='syncing' WHERE id=$1", [mailboxId]);
  try {
    const folders = await connector.listFolders(); await budgetDelay();
    for (const f of folders) {
      checkCancel(mailboxId);
      const folderId = await upsertFolder(mailboxId, f);
      summary.folders++;
      await q('INSERT INTO sync_state (mailbox_id, folder_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [mailboxId, folderId]);
      const state = await one('SELECT * FROM sync_state WHERE mailbox_id=$1 AND folder_id=$2', [mailboxId, folderId]);

      // 1) Incremental: newest page first — stop at first already-known message.
      const newest = await connector.listMessages(f, { start: 1, limit: PAGE_SIZE }); await budgetDelay();
      summary.pagesUsed++;
      for (const m of newest) {
        checkCancel(mailboxId);
        const inserted = await ingestOne(connector, f, mailboxId, folderId, m, summary);
        if (!inserted) break;
      }

      // 2) Backfill: resume from the persisted cursor.
      if (!state.backfill_done) {
        let start = Math.max(Number(state.next_start) || 1, 1 + PAGE_SIZE);
        let pages = 0;
        while (pages < maxPages) {
          checkCancel(mailboxId);
          const batch = await connector.listMessages(f, { start, limit: PAGE_SIZE }); await budgetDelay();
          summary.pagesUsed++; pages++;
          for (const m of batch) {
            checkCancel(mailboxId);
            await ingestOne(connector, f, mailboxId, folderId, m, summary);
          }
          if (batch.length < PAGE_SIZE) {
            await q('UPDATE sync_state SET backfill_done=TRUE, next_start=$1, last_sync_at=now() WHERE mailbox_id=$2 AND folder_id=$3',
              [start + batch.length, mailboxId, folderId]);
            break;
          }
          start += PAGE_SIZE;
          await q('UPDATE sync_state SET next_start=$1, last_sync_at=now() WHERE mailbox_id=$2 AND folder_id=$3',
            [start, mailboxId, folderId]);
        }
      }
      await q("UPDATE sync_state SET last_sync_at=now(), last_error='' WHERE mailbox_id=$1 AND folder_id=$2", [mailboxId, folderId]);
    }
    await q("UPDATE mailboxes SET status='ready', status_detail='' WHERE id=$1", [mailboxId]);
  } catch (err) {
    const status = err.cancelled ? 'ready' : 'error';
    const detail = err.cancelled ? 'Last sync cancelled by admin — cursor persisted, resume any time.' : String(err.message || err);
    await q('UPDATE mailboxes SET status=$1, status_detail=$2 WHERE id=$3', [status, detail, mailboxId]);
    throw err;
  }
  await audit(null, 'mail.sync', mailbox.address, summary);
  return summary;
}

async function ingestOne(connector, folder, mailboxId, folderId, m, summary) {
  const rowId = await insertMessage(mailboxId, folderId, m);
  if (!rowId) return false;
  summary.newMessages++;
  const body = await connector.getBody(folder, m.providerMessageId); await budgetDelay();
  if (body) await q('UPDATE messages SET body_html=$1 WHERE id=$2', [body, rowId]);
  if (m.hasAttachments) {
    const atts = await connector.listAttachments(folder, m.providerMessageId); await budgetDelay();
    for (const a of atts) {
      try {
        const buf = await connector.downloadAttachment(folder, m.providerMessageId, a.providerAttachmentId); await budgetDelay();
        await storeAttachment(rowId, a.name, a.mime, buf);
        summary.attachments++;
      } catch (e) {
        await audit(null, 'mail.attachment.error', m.providerMessageId, String(e.message || e));
      }
    }
  }
  return true;
}

// Official archive import (eDiscovery/Backup ZIP) — archive import, never live sync.
async function importArchiveZip(mailboxId, zipBuffer, userId) {
  const mailbox = await one('SELECT * FROM mailboxes WHERE id = $1', [mailboxId]);
  if (!mailbox) throw new Error('mailbox not found');
  const summary = { mailbox: mailbox.address, imported: 0, duplicates: 0, attachments: 0, folders: new Set() };

  for (const msg of messagesFromExportZip(zipBuffer)) {
    const folderName = msg.sourceFolder || (msg.direction === 'out' ? 'Sent (archive)' : 'Inbox (archive)');
    const folderId = await upsertFolder(mailboxId, {
      providerFolderId: 'archive:' + folderName, name: folderName,
      type: msg.direction === 'out' ? 'sent' : 'archive',
    });
    summary.folders.add(folderName);
    const rowId = await insertMessage(mailboxId, folderId, msg);
    if (!rowId) { summary.duplicates++; continue; }
    summary.imported++;
    for (const a of msg.attachments || []) {
      await storeAttachment(rowId, a.name, a.mime, a.data);
      summary.attachments++;
    }
  }
  summary.folders = [...summary.folders];
  await audit(userId, 'mail.archive_import', mailbox.address, summary);
  return summary;
}

module.exports = { syncMailbox, importArchiveZip, insertMessage, upsertFolder, dedupHash, cancelSync };
