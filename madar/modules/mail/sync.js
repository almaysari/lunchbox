// Ingestion pipeline — READ-ONLY.
// Runs ONLY for pilot-selected mailboxes (is_pilot=1). Never modifies,
// moves, deletes or marks anything on the provider side.
const fs = require('fs');
const path = require('path');
const { getDb, ATTACH_DIR } = require('../../core/db');
const { sha256 } = require('../../core/crypto');
const { audit } = require('../../core/audit');
const { ZohoClient } = require('./zoho-client');
const { ZohoMailApiConnector } = require('./connectors/zoho-mail-api');
const { messagesFromExportZip } = require('./connectors/ediscovery-import');

const MAX_RPM = Number(process.env.MADAR_MAX_RPM || 25); // stay under Zoho's documented ~30 req/min
const PAGE_SIZE = 100;
const delay = ms => new Promise(r => setTimeout(r, ms));
const budgetDelay = () => delay(Math.ceil(60000 / MAX_RPM));

function dedupHash(m) {
  // Platform-wide duplicate guard: RFC Message-ID when present, otherwise a
  // stable fingerprint. Catches the same mail arriving via different sources.
  const key = m.rfcMessageId
    ? 'rfc:' + m.rfcMessageId.trim()
    : 'fp:' + [m.from, m.subject, m.receivedAt].join('|');
  return sha256(Buffer.from(key));
}

function upsertFolder(mailboxId, f) {
  const db = getDb();
  db.prepare(`INSERT INTO folders (mailbox_id, provider_folder_id, name, folder_type) VALUES (?,?,?,?)
              ON CONFLICT(mailbox_id, provider_folder_id) DO UPDATE SET name=excluded.name, folder_type=excluded.folder_type`)
    .run(mailboxId, f.providerFolderId, f.name, f.type || '');
  return db.prepare('SELECT id FROM folders WHERE mailbox_id=? AND provider_folder_id=?')
    .get(mailboxId, f.providerFolderId).id;
}

// Returns inserted message row id, or null when it was a duplicate.
function insertMessage(mailboxId, folderId, m) {
  const db = getDb();
  const hash = dedupHash(m);
  const dupe = db.prepare('SELECT id FROM messages WHERE mailbox_id=? AND (provider_message_id=? OR dedup_hash=?)')
    .get(mailboxId, m.providerMessageId, hash);
  if (dupe) return null;
  const r = db.prepare(`INSERT INTO messages (mailbox_id, folder_id, provider_message_id, rfc_message_id,
      dedup_hash, thread_id, from_address, from_name, to_addresses, cc_addresses, subject, snippet,
      body_html, received_at, direction, has_attachments)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(mailboxId, folderId, m.providerMessageId, m.rfcMessageId || '', hash, m.threadId || '',
      m.from || '', m.fromName || '', m.to || '', m.cc || '', m.subject || '', m.snippet || '',
      m.bodyHtml || null, m.receivedAt, m.direction || 'in', m.hasAttachments ? 1 : 0);
  return Number(r.lastInsertRowid);
}

function storeAttachment(messageId, name, mime, buf) {
  const db = getDb();
  const hash = sha256(buf);
  const safe = String(name).replace(/[^\w.؀-ۿ-]+/g, '_').slice(0, 100);
  const file = `${messageId}-${hash.slice(0, 8)}-${safe}`;
  fs.writeFileSync(path.join(ATTACH_DIR, file), buf);
  db.prepare('INSERT INTO attachments (message_id, name, size, mime, file_path, sha256) VALUES (?,?,?,?,?,?)')
    .run(messageId, name, buf.length, mime || '', file, hash);
}

function connectorFor(mailbox) {
  if (mailbox.strategy !== 'mail_api') {
    throw new Error(`Mailbox ${mailbox.address} has no live-sync strategy (strategy=${mailbox.strategy}).`);
  }
  const zoho = ZohoClient.forConnection(mailbox.connection_id);
  return new ZohoMailApiConnector(zoho, mailbox);
}

// One sync pass for a pilot mailbox: continues backfill from the stored
// cursor AND picks up new messages (page 1 re-scan).
async function syncMailbox(mailboxId, { maxPages = 5 } = {}) {
  const db = getDb();
  const mailbox = db.prepare('SELECT * FROM mailboxes WHERE id=?').get(mailboxId);
  if (!mailbox) throw new Error('mailbox not found');
  if (!mailbox.is_pilot) throw new Error('sync refused: mailbox is not pilot-selected');
  const connector = connectorFor(mailbox);
  const summary = { mailbox: mailbox.address, folders: 0, newMessages: 0, attachments: 0, pagesUsed: 0 };

  db.prepare("UPDATE mailboxes SET status='syncing' WHERE id=?").run(mailboxId);
  try {
    const folders = await connector.listFolders(); await budgetDelay();
    for (const f of folders) {
      const folderId = upsertFolder(mailboxId, f);
      summary.folders++;
      db.prepare(`INSERT INTO sync_state (mailbox_id, folder_id) VALUES (?,?)
                  ON CONFLICT(mailbox_id, folder_id) DO NOTHING`).run(mailboxId, folderId);
      const state = db.prepare('SELECT * FROM sync_state WHERE mailbox_id=? AND folder_id=?').get(mailboxId, folderId);

      // 1) Incremental: newest page first — stop at first already-known message.
      const newest = await connector.listMessages(f, { start: 1, limit: PAGE_SIZE }); await budgetDelay();
      summary.pagesUsed++;
      for (const m of newest) {
        const inserted = await ingestOne(connector, f, mailboxId, folderId, m, summary);
        if (!inserted) break; // reached known territory
      }

      // 2) Backfill: continue from stored cursor until exhausted or page budget spent.
      if (!state.backfill_done) {
        let start = Math.max(Number(state.next_start) || 1, 1 + PAGE_SIZE); // page 1 handled above
        let pages = 0;
        while (pages < maxPages) {
          const batch = await connector.listMessages(f, { start, limit: PAGE_SIZE }); await budgetDelay();
          summary.pagesUsed++; pages++;
          for (const m of batch) await ingestOne(connector, f, mailboxId, folderId, m, summary);
          if (batch.length < PAGE_SIZE) {
            db.prepare('UPDATE sync_state SET backfill_done=1, next_start=?, last_sync_at=? WHERE mailbox_id=? AND folder_id=?')
              .run(start + batch.length, Date.now(), mailboxId, folderId);
            break;
          }
          start += PAGE_SIZE;
          db.prepare('UPDATE sync_state SET next_start=?, last_sync_at=? WHERE mailbox_id=? AND folder_id=?')
            .run(start, Date.now(), mailboxId, folderId);
        }
      }
      db.prepare("UPDATE sync_state SET last_sync_at=?, last_error='' WHERE mailbox_id=? AND folder_id=?")
        .run(Date.now(), mailboxId, folderId);
    }
    db.prepare("UPDATE mailboxes SET status='ready', status_detail='' WHERE id=?").run(mailboxId);
  } catch (err) {
    db.prepare("UPDATE mailboxes SET status='error', status_detail=? WHERE id=?").run(String(err.message || err), mailboxId);
    throw err;
  }
  audit(null, 'mail.sync', mailbox.address, summary);
  return summary;
}

async function ingestOne(connector, folder, mailboxId, folderId, m, summary) {
  const rowId = insertMessage(mailboxId, folderId, m);
  if (!rowId) return false;
  summary.newMessages++;
  const body = await connector.getBody(folder, m.providerMessageId); await budgetDelay();
  if (body) getDb().prepare('UPDATE messages SET body_html=? WHERE id=?').run(body, rowId);
  if (m.hasAttachments) {
    const atts = await connector.listAttachments(folder, m.providerMessageId); await budgetDelay();
    for (const a of atts) {
      try {
        const buf = await connector.downloadAttachment(folder, m.providerMessageId, a.providerAttachmentId); await budgetDelay();
        storeAttachment(rowId, a.name, a.mime, buf);
        summary.attachments++;
      } catch (e) {
        audit(null, 'mail.attachment.error', m.providerMessageId, String(e.message || e));
      }
    }
  }
  return true;
}

// Official archive import for shared mailboxes (eDiscovery/Backup ZIP).
// Clearly an ARCHIVE IMPORT — never presented as live sync.
function importArchiveZip(mailboxId, zipBuffer, userId) {
  const db = getDb();
  const mailbox = db.prepare('SELECT * FROM mailboxes WHERE id=?').get(mailboxId);
  if (!mailbox) throw new Error('mailbox not found');
  const summary = { mailbox: mailbox.address, imported: 0, duplicates: 0, attachments: 0, folders: new Set() };

  for (const msg of messagesFromExportZip(zipBuffer)) {
    const folderName = msg.sourceFolder || (msg.direction === 'out' ? 'Sent (archive)' : 'Inbox (archive)');
    const folderId = upsertFolder(mailboxId, { providerFolderId: 'archive:' + folderName, name: folderName, type: msg.direction === 'out' ? 'sent' : 'archive' });
    summary.folders.add(folderName);
    const rowId = insertMessage(mailboxId, folderId, msg);
    if (!rowId) { summary.duplicates++; continue; }
    summary.imported++;
    for (const a of msg.attachments || []) {
      storeAttachment(rowId, a.name, a.mime, a.data);
      summary.attachments++;
    }
  }
  summary.folders = [...summary.folders];
  audit(userId, 'mail.archive_import', mailbox.address, summary);
  return summary;
}

module.exports = { syncMailbox, importArchiveZip, insertMessage, upsertFolder, dedupHash };
