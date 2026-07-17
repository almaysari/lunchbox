// Ingestion pipeline — READ-ONLY, PostgreSQL-backed, canonical-message model.
// A message appearing in several mailboxes/folders becomes ONE canonical
// message with an occurrence per (mailbox, folder) — nothing is ever lost.
// Every run is a sync_jobs row: start / pause / resume / cancel / progress,
// all restart-safe (control state lives in PostgreSQL, not process memory).
const { q, one } = require('../../core/db');
const { getStorage, detectMime, sanitizeFilename } = require('../../core/storage');
const { sha256 } = require('../../core/crypto');
const { audit } = require('../../core/audit');
const { ZohoClient } = require('./zoho-client');
const { ZohoMailApiConnector } = require('./connectors/zoho-mail-api');
const { messagesFromExportZip } = require('./connectors/ediscovery-import');

const MAX_RPM = Number(process.env.MADAR_MAX_RPM || 25);
const PAGE_SIZE = 100;
const delay = ms => new Promise(r => setTimeout(r, ms));
const budgetDelay = () => delay(Math.ceil(60000 / MAX_RPM));

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

// Insert canonical (once platform-wide) + occurrence (once per mailbox/folder).
// Returns { canonicalId, occurrenceId|null } — occurrenceId null = duplicate occurrence.
async function insertMessage(mailboxId, folderId, m, provider = 'zoho') {
  const hash = dedupHash(m);
  let canonical = await one(`INSERT INTO canonical_messages (dedup_hash, rfc_message_id, thread_id, from_address,
      from_name, to_addresses, cc_addresses, subject, snippet, body_html, sent_at, has_attachments)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    ON CONFLICT (dedup_hash) DO NOTHING RETURNING id`,
    [hash, m.rfcMessageId || '', m.threadId || '', m.from || '', m.fromName || '', m.to || '', m.cc || '',
      m.subject || '', m.snippet || '', m.bodyHtml || null, new Date(Number(m.receivedAt) || Date.now()),
      Boolean(m.hasAttachments)]);
  const isNewCanonical = Boolean(canonical);
  if (!canonical) canonical = await one('SELECT id FROM canonical_messages WHERE dedup_hash = $1', [hash]);

  const occ = await one(`INSERT INTO message_occurrences (canonical_message_id, mailbox_id, folder_id, provider,
      provider_message_id, direction, received_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING id`,
    [canonical.id, mailboxId, folderId, provider, m.providerMessageId, m.direction || 'in',
      new Date(Number(m.receivedAt) || Date.now())]);

  return { canonicalId: Number(canonical.id), occurrenceId: occ ? Number(occ.id) : null, isNewCanonical };
}

// Attachments hang off the canonical message; MIME is detected from bytes,
// never trusted from the provider. Mismatch → quarantined.
async function storeAttachment(canonicalId, providerAttachmentId, name, providerMime, buf) {
  const dupe = await one('SELECT id FROM attachments WHERE canonical_message_id=$1 AND sha256=$2 AND original_filename=$3',
    [canonicalId, sha256(buf), name]);
  if (dupe) return false;
  const { key, sha256: hash, size } = getStorage().putObject(buf);
  const detected = detectMime(buf);
  const claimed = String(providerMime || '').split(';')[0].trim().toLowerCase();
  // quarantine when the provider claims something materially different
  const compatible = !claimed || claimed === detected ||
    (detected === 'application/zip' && /officedocument|zip/.test(claimed)) ||
    (detected === 'text/plain' && claimed.startsWith('text/'));
  await q(`INSERT INTO attachments (canonical_message_id, provider_attachment_id, original_filename,
      sanitized_filename, size, provider_mime_type, detected_mime_type, quarantine_status, storage_key, sha256)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [canonicalId, providerAttachmentId || '', name, sanitizeFilename(name), size,
      claimed, detected, compatible ? 'clean' : 'quarantined', key, hash]);
  return true;
}

// ---- sync jobs ----
async function createJob(mailboxId, userId) {
  const active = await one(`SELECT id, status FROM sync_jobs WHERE mailbox_id = $1 AND status IN ('queued','running','paused')`, [mailboxId]);
  if (active) {
    if (active.status === 'paused') return Number(active.id); // resume reuses the paused job
    throw new Error(`A sync job is already ${active.status} for this mailbox (job ${active.id}).`);
  }
  const r = await one('INSERT INTO sync_jobs (mailbox_id, requested_by) VALUES ($1,$2) RETURNING id', [mailboxId, userId || null]);
  return Number(r.id);
}

async function setJobControl(jobId, status) { // 'paused' | 'cancelled' (admin action)
  const job = await one('SELECT * FROM sync_jobs WHERE id = $1', [jobId]);
  if (!job) throw new Error('job not found');
  if (!['queued', 'running', 'paused'].includes(job.status)) throw new Error(`job is already ${job.status}`);
  await q('UPDATE sync_jobs SET status = $1 WHERE id = $2', [status, jobId]);
}

async function jobControlState(jobId) {
  const row = await one('SELECT status FROM sync_jobs WHERE id = $1', [jobId]);
  return row && row.status;
}

class JobStopped extends Error {
  constructor(kind) { super('sync ' + kind); this.kind = kind; }
}

async function checkpoint(jobId) {
  const s = await jobControlState(jobId);
  if (s === 'paused') throw new JobStopped('paused');
  if (s === 'cancelled') throw new JobStopped('cancelled');
}

async function connectorFor(mailbox) {
  if (mailbox.strategy !== 'mail_api') {
    throw new Error(`Mailbox ${mailbox.address} has no live-sync strategy (strategy=${mailbox.strategy}).`);
  }
  const zoho = await ZohoClient.forConnection(mailbox.connection_id);
  return new ZohoMailApiConnector(zoho, mailbox);
}

async function syncMailbox(mailboxId, { maxPages = 5, userId = null } = {}) {
  const mailbox = await one('SELECT * FROM mailboxes WHERE id = $1', [mailboxId]);
  if (!mailbox) throw new Error('mailbox not found');
  if (!mailbox.is_pilot) throw new Error('sync refused: mailbox is not pilot-selected');
  if (!mailbox.sync_enabled) throw new Error('sync refused: not explicitly started by an admin');
  const connector = await connectorFor(mailbox);
  const jobId = await createJob(mailboxId, userId);
  await q("UPDATE sync_jobs SET status='running', started_at = COALESCE(started_at, now()) WHERE id = $1", [jobId]);
  await q("UPDATE mailboxes SET status='syncing' WHERE id=$1", [mailboxId]);
  const summary = { jobId, mailbox: mailbox.address, folders: 0, newMessages: 0, newOccurrences: 0, attachments: 0, skipped: 0 };

  try {
    const folders = await connector.listFolders(); await budgetDelay();
    for (const f of folders) {
      await checkpoint(jobId);
      const folderId = await upsertFolder(mailboxId, f);
      summary.folders++;
      await q('UPDATE sync_jobs SET current_folder_id = $1 WHERE id = $2', [folderId, jobId]);
      await q('INSERT INTO sync_state (mailbox_id, folder_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [mailboxId, folderId]);
      const state = await one('SELECT * FROM sync_state WHERE mailbox_id=$1 AND folder_id=$2', [mailboxId, folderId]);

      // incremental newest page
      const newest = await connector.listMessages(f, { start: 1, limit: PAGE_SIZE }); await budgetDelay();
      await q('UPDATE sync_jobs SET discovered = discovered + $1 WHERE id = $2', [newest.length, jobId]);
      for (const msg of newest) {
        await checkpoint(jobId);
        const fresh = await ingestOne(connector, f, mailboxId, folderId, msg, summary, jobId);
        if (!fresh) break;
      }

      // backfill from persisted cursor
      if (!state.backfill_done) {
        let start = Math.max(Number(state.next_start) || 1, 1 + PAGE_SIZE);
        let pages = 0;
        while (pages < maxPages) {
          await checkpoint(jobId);
          const batch = await connector.listMessages(f, { start, limit: PAGE_SIZE }); await budgetDelay();
          pages++;
          await q('UPDATE sync_jobs SET discovered = discovered + $1, current_cursor = $2 WHERE id = $3', [batch.length, start, jobId]);
          for (const msg of batch) {
            await checkpoint(jobId);
            await ingestOne(connector, f, mailboxId, folderId, msg, summary, jobId);
          }
          if (batch.length < PAGE_SIZE) {
            await q('UPDATE sync_state SET backfill_done=TRUE, next_start=$1, last_sync_at=now() WHERE mailbox_id=$2 AND folder_id=$3',
              [start + batch.length, mailboxId, folderId]);
            break;
          }
          start += PAGE_SIZE;
          await q('UPDATE sync_state SET next_start=$1, last_sync_at=now() WHERE mailbox_id=$2 AND folder_id=$3', [start, mailboxId, folderId]);
        }
      }
      await q("UPDATE sync_state SET last_sync_at=now(), last_error='' WHERE mailbox_id=$1 AND folder_id=$2", [mailboxId, folderId]);
    }
    await q("UPDATE sync_jobs SET status='completed', finished_at=now() WHERE id=$1", [jobId]);
    await q("UPDATE mailboxes SET status='ready', status_detail='' WHERE id=$1", [mailboxId]);
  } catch (err) {
    if (err instanceof JobStopped) {
      // status was already set by the control action; cursor is persisted → resumable
      if (err.kind === 'cancelled') await q('UPDATE sync_jobs SET finished_at=now() WHERE id=$1', [jobId]);
      await q("UPDATE mailboxes SET status='ready', status_detail=$1 WHERE id=$2",
        [`Last sync ${err.kind} — cursor persisted, resume any time.`, mailboxId]);
    } else {
      await q("UPDATE sync_jobs SET status='failed', error_detail=$1, errors = errors + 1, finished_at=now() WHERE id=$2",
        [String(err.message || err), jobId]);
      await q("UPDATE mailboxes SET status='error', status_detail=$1 WHERE id=$2", [String(err.message || err), mailboxId]);
    }
    throw err;
  }
  await audit(userId, 'mail.sync', mailbox.address, summary);
  return summary;
}

async function ingestOne(connector, folder, mailboxId, folderId, msg, summary, jobId) {
  const { canonicalId, occurrenceId, isNewCanonical } = await insertMessage(mailboxId, folderId, msg);
  if (!occurrenceId) {
    summary.skipped++;
    await q('UPDATE sync_jobs SET skipped = skipped + 1 WHERE id = $1', [jobId]);
    return false;
  }
  summary.newOccurrences++;
  await q('UPDATE sync_jobs SET imported = imported + 1 WHERE id = $1', [jobId]);
  if (!isNewCanonical) return true; // body/attachments already captured for this canonical

  summary.newMessages++;
  const body = await connector.getBody(folder, msg.providerMessageId); await budgetDelay();
  if (body) await q('UPDATE canonical_messages SET body_html=$1 WHERE id=$2', [body, canonicalId]);
  if (msg.hasAttachments) {
    const atts = await connector.listAttachments(folder, msg.providerMessageId); await budgetDelay();
    for (const a of atts) {
      try {
        const buf = await connector.downloadAttachment(folder, msg.providerMessageId, a.providerAttachmentId); await budgetDelay();
        if (await storeAttachment(canonicalId, a.providerAttachmentId, a.name, a.mime, buf)) summary.attachments++;
      } catch (e) {
        await q('UPDATE sync_jobs SET errors = errors + 1 WHERE id = $1', [jobId]);
        await audit(null, 'mail.attachment.error', msg.providerMessageId, String(e.message || e));
      }
    }
  }
  return true;
}

// Official archive import (eDiscovery/Backup ZIP) — archive import, never live sync.
async function importArchiveZip(mailboxId, zipBuffer, userId) {
  const mailbox = await one('SELECT * FROM mailboxes WHERE id = $1', [mailboxId]);
  if (!mailbox) throw new Error('mailbox not found');
  const summary = { mailbox: mailbox.address, imported: 0, duplicates: 0, attachments: 0, quarantined: 0, folders: new Set() };

  for (const msg of messagesFromExportZip(zipBuffer)) {
    const folderName = msg.sourceFolder || (msg.direction === 'out' ? 'Sent (archive)' : 'Inbox (archive)');
    const folderId = await upsertFolder(mailboxId, {
      providerFolderId: 'archive:' + folderName, name: folderName,
      type: msg.direction === 'out' ? 'sent' : 'archive',
    });
    summary.folders.add(folderName);
    const { canonicalId, occurrenceId, isNewCanonical } = await insertMessage(mailboxId, folderId, msg, 'ediscovery');
    if (!occurrenceId) { summary.duplicates++; continue; }
    summary.imported++;
    if (isNewCanonical) {
      for (const a of msg.attachments || []) {
        if (await storeAttachment(canonicalId, '', a.name, a.mime, a.data)) summary.attachments++;
      }
    }
  }
  summary.folders = [...summary.folders];
  await audit(userId, 'mail.archive_import', mailbox.address, summary);
  return summary;
}

module.exports = { syncMailbox, importArchiveZip, insertMessage, upsertFolder, dedupHash, storeAttachment, createJob, setJobControl };
