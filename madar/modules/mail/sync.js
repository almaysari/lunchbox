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

// ---- diagnostics: one persisted row per sync cycle, full typed context ----
let _traceSeq = 0;
function newTraceId() {
  _traceSeq = (_traceSeq + 1) % 1e6;
  return 'sync-' + Date.now().toString(36) + '-' + _traceSeq.toString(36);
}
// A live per-cycle scratchpad the sync loop updates as it advances, so even a
// hard crash leaves the last-reached stage + counts + endpoint recorded.
function newDiag(mailbox) {
  return {
    traceId: newTraceId(), mailboxId: mailbox.id, mailboxAddress: mailbox.address,
    stage: 'load_state', endpoint: null, httpStatus: null, responseSample: null,
    read: 0, inserted: 0, skipped: 0, routed: 0, routingContext: null,
  };
}
async function persistDiag(diag, err) {
  const base = [diag.traceId, diag.mailboxId, diag.mailboxAddress, diag.stage,
    diag.endpoint, diag.httpStatus, diag.responseSample ? JSON.stringify(diag.responseSample) : null,
    diag.read, diag.inserted, diag.skipped, diag.routed];
  if (!err) {
    await q(`INSERT INTO sync_diagnostics (trace_id, mailbox_id, mailbox_address, stage, endpoint,
      http_status, response_sample, read_count, inserted_count, skipped_count, routed_count, outcome)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'ok')`, base);
    return diag.traceId;
  }
  // Typed extraction: Zoho HTTP context, or pg SQL context, or routing context.
  const isPg = err.code && /^\d/.test(String(err.code)) && err.severity;
  await q(`INSERT INTO sync_diagnostics (trace_id, mailbox_id, mailbox_address, stage, endpoint,
    http_status, response_sample, read_count, inserted_count, skipped_count, routed_count,
    outcome, error_class, error_message, error_stack, sql_state, constraint_name, routing_context)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'error',$12,$13,$14,$15,$16,$17)`,
    [...base.slice(0, 4),
      err.endpoint || diag.endpoint, err.httpStatus || diag.httpStatus,
      err.responseSample ? JSON.stringify(err.responseSample) : (diag.responseSample ? JSON.stringify(diag.responseSample) : null),
      diag.read, diag.inserted, diag.skipped, diag.routed,
      err.name || 'Error', String(err.message || err).slice(0, 1000),
      String(err.stack || '').slice(0, 6000),
      isPg ? String(err.code) : null, isPg ? (err.constraint || null) : null,
      diag.routingContext ? JSON.stringify(diag.routingContext) : null]);
  return diag.traceId;
}

const MAX_RPM = Number(process.env.MADAR_MAX_RPM || 25);
const PAGE_SIZE = 100;
const delay = ms => new Promise(r => setTimeout(r, ms));
const budgetDelay = () => delay(Math.ceil(60000 / MAX_RPM));

// Canonicalization algorithm v3 (stored per-row as canonical_hash_version).
//
// WHY NOT RFC Message-ID as the key: Zoho's live messages/view returns NO RFC
// Message-ID field (proven from the real tenant's response — fields are
// fromAddress/sender/subject/sentDateInGMT/receivedTime/… only). The eDiscovery
// EML archive DOES carry a Message-ID. Keying on Message-ID would therefore make
// the SAME email arrive as two different canonicals (live copy vs archive copy),
// i.e. a duplicate. So the canonical key must be computable IDENTICALLY from
// both sources, using only message-intrinsic, copy-stable fields.
//
// fp3 = sha256( from-emails | SENT-second | subject | to-emails | cc-emails )
//   * SENT time (sentDateInGMT / the EML Date: header) — NOT receivedTime, which
//     differs per recipient mailbox. Rounded to the second (RFC2822 precision).
//   * from/to/cc reduced to sorted unique email addresses (angle-brackets,
//     display names and ordering removed).
//   * DELIBERATELY EXCLUDED: Zoho messageId (per-copy), receivedTime (per-copy),
//     size (varies per copy via Received: headers), snippet/body and the
//     has-attachment flag (a live 'summary' vs a parsed archive body, or an
//     inline vs attachment, can disagree between the two sources and would break
//     convergence). BCC stays occurrence-only (per-mailbox), never identity.
// rfcMessageId is still STORED (forensics) but is not the identity.
// Proven against REAL Zoho values (moderation-queue evidence): distinct sends of
// the same subject stay distinct (different sent-second); a live record and an
// eDiscovery EML of the same email produce an identical fp3 across mailboxes.
// Old v2 rows keep their version and are never re-merged retroactively.
const HASH_VERSION = 3;

// ---- unified normalization (single source of truth for identity + validator) ----
// subject: lowercase + collapse all whitespace + trim.
const _normSubject = s => String(s || '').toLowerCase().replace(/\s+/g, ' ').trim();
// address list -> sorted, de-duplicated, lowercased set of bare email addresses:
//   * display names removed (only the addr-spec is matched)
//   * any separator (comma / semicolon / space / newline) handled — we extract,
//     not split — so ";" vs ", " never changes the result
//   * duplicates removed, order canonicalized by sort
const _emailSet = s => {
  const m = String(s || '').toLowerCase().match(/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/g) || [];
  return [...new Set(m)].sort().join(',');
};
// SENT time -> epoch SECONDS, timezone-normalized:
//   * numeric or all-digit string => treated as epoch ms as-is (already GMT).
//   * otherwise Date.parse: RFC2822 / ISO carry an explicit offset, so the
//     result is absolute UTC — DST is inherent (the offset already reflects it).
//   * missing / invalid => 0 (the caller flags the message as time-unlinkable).
//   * floor to the second (RFC2822 Date: headers have no sub-second precision).
function _sentEpochSec(m) {
  const v = (m.sentAt != null && m.sentAt !== '') ? m.sentAt : m.receivedAt;
  let ms;
  if (typeof v === 'number') ms = v;
  else if (/^\d{10,}$/.test(String(v || '').trim())) ms = Number(v);
  else ms = Date.parse(v); // absolute UTC from the embedded offset
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
}
// The normalized identity tuple — exposed so the production validator computes
// fp3 EXACTLY as ingestion does (no drift between proof and prod).
function normalizeForFingerprint(m) {
  return { from: _emailSet(m.from), sentSec: _sentEpochSec(m), subject: _normSubject(m.subject),
    to: _emailSet(m.to), cc: _emailSet(m.cc), timeUnlinkable: _sentEpochSec(m) === 0 };
}
function dedupHash(m) {
  const n = normalizeForFingerprint(m);
  return sha256(Buffer.from(['v3', n.from, n.sentSec, n.subject, n.to, n.cc].join('|')));
}
async function recordMetric(client, ev) {
  await client.query(`INSERT INTO fingerprint_metrics (event_type, fp3, rfc_incoming, rfc_existing,
    canonical_a, canonical_b, mailbox_id, detail) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [ev.event_type, ev.fp3 || null, ev.rfc_incoming || null, ev.rfc_existing || null,
      ev.canonical_a || null, ev.canonical_b || null, ev.mailbox_id || null, ev.detail || null]);
}

async function upsertFolder(mailboxId, f) {
  const r = await one(`INSERT INTO folders (mailbox_id, provider_folder_id, name, folder_type) VALUES ($1,$2,$3,$4)
    ON CONFLICT (mailbox_id, provider_folder_id) DO UPDATE SET name = EXCLUDED.name, folder_type = EXCLUDED.folder_type
    RETURNING id`, [mailboxId, f.providerFolderId, f.name, f.type || '']);
  return Number(r.id);
}

// Insert canonical (once platform-wide) + occurrence (once per mailbox/folder),
// atomically: a duplicate occurrence rolls back a just-created canonical, so
// no canonical can ever exist without at least one occurrence.
// Envelope fields (to/cc/bcc as THIS mailbox saw them) live on the occurrence.
async function insertMessage(mailboxId, folderId, m, provider = 'zoho') {
  let hash = dedupHash(m);
  const rfc = (m.rfcMessageId || '').trim();
  const norm = normalizeForFingerprint(m);
  const { tx } = require('../../core/db');
  return tx(async (client) => {
    // Forensic oracle (RFC Message-ID, when the archive provides one):
    //   * A canonical already at THIS fp3 but carrying a DIFFERENT non-empty RFC
    //     Message-ID => two genuinely distinct emails collided on fp3. Prevent
    //     the false merge (data loss) by salting the key with the RFC id, and
    //     record the event. (Live copies carry no RFC id, so this never fires on
    //     the live path — convergence is preserved.)
    //   * A DIFFERENT canonical already carries the SAME RFC id => fp3 split one
    //     email into two (false split). Record it (reconciliation handles merge).
    if (rfc) {
      const clash = (await client.query(
        `SELECT id, rfc_message_id FROM canonical_messages WHERE dedup_hash = $1`, [hash])).rows[0];
      if (clash && clash.rfc_message_id && clash.rfc_message_id !== rfc) {
        await recordMetric(client, { event_type: 'false_merge_prevented', fp3: hash,
          rfc_incoming: rfc, rfc_existing: clash.rfc_message_id, canonical_a: Number(clash.id),
          mailbox_id: mailboxId, detail: 'distinct RFC Message-IDs collided on fp3 — salted to keep separate' });
        hash = sha256(Buffer.from(hash + '|rfc:' + rfc)); // deterministic disambiguation
      }
      const split = (await client.query(
        `SELECT id, dedup_hash FROM canonical_messages WHERE rfc_message_id = $1 AND dedup_hash <> $2 LIMIT 1`,
        [rfc, hash])).rows[0];
      if (split) {
        await recordMetric(client, { event_type: 'false_split_detected', fp3: hash,
          rfc_incoming: rfc, rfc_existing: rfc, canonical_a: Number(split.id),
          mailbox_id: mailboxId, detail: 'same RFC Message-ID under two fingerprints — candidate for reconciliation' });
      }
    }
    if (norm.timeUnlinkable) {
      await recordMetric(client, { event_type: 'time_unlinkable', fp3: hash, rfc_incoming: rfc || null,
        mailbox_id: mailboxId, detail: 'no valid sent/received time — weak temporal key' });
    }

    let canonical = (await client.query(`INSERT INTO canonical_messages (dedup_hash, canonical_hash_version,
        rfc_message_id, thread_id, from_address, from_name, to_addresses, cc_addresses, subject, snippet,
        body_html, sent_at, has_attachments)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (dedup_hash) DO NOTHING RETURNING id`,
      [hash, HASH_VERSION, rfc, m.threadId || '', m.from || '', m.fromName || '',
        m.to || '', m.cc || '', m.subject || '', m.snippet || '', m.bodyHtml || null,
        new Date(Number(m.receivedAt) || Date.now()), Boolean(m.hasAttachments)])).rows[0];
    const isNewCanonical = Boolean(canonical);
    if (!canonical) canonical = (await client.query('SELECT id FROM canonical_messages WHERE dedup_hash = $1', [hash])).rows[0];

    const occ = (await client.query(`INSERT INTO message_occurrences (canonical_message_id, mailbox_id, folder_id,
        provider, provider_message_id, direction, received_at, envelope_to, envelope_cc, envelope_bcc)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING RETURNING id`,
      [canonical.id, mailboxId, folderId, provider, m.providerMessageId, m.direction || 'in',
        new Date(Number(m.receivedAt) || Date.now()), m.to || '', m.cc || '', m.bcc || ''])).rows[0];

    if (!occ && isNewCanonical) throw Object.assign(new Error('rollback-orphan'), { _rollbackOrphan: true, canonicalId: Number(canonical.id) });
    if (!occ) await recordMetric(client, { event_type: 'duplicate_prevented', fp3: hash, rfc_incoming: rfc || null,
      canonical_a: Number(canonical.id), mailbox_id: mailboxId, detail: 'occurrence already present in this mailbox' });
    return { canonicalId: Number(canonical.id), occurrenceId: occ ? Number(occ.id) : null, isNewCanonical };
  }).catch(err => {
    if (err._rollbackOrphan) return { canonicalId: err.canonicalId, occurrenceId: null, isNewCanonical: false };
    throw err;
  });
}

// Attachments hang off the canonical message; MIME is detected from bytes,
// never trusted from the provider. Mismatch → quarantined.
// If the DB insert fails after the file was written, the object is deleted —
// no partial attachments survive a pause/cancel/crash.
async function storeAttachment(canonicalId, providerAttachmentId, name, providerMime, buf) {
  const dupe = await one('SELECT id FROM attachments WHERE canonical_message_id=$1 AND sha256=$2 AND original_filename=$3',
    [canonicalId, sha256(buf), name]);
  if (dupe) return false;
  const { key, sha256: hash, size } = getStorage().putObject(buf);
  try {
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
  } catch (err) {
    getStorage().deleteObject(key); // no orphan objects on DB failure
    throw err;
  }
}

// ---- sync jobs ----
async function createJob(mailboxId, userId) {
  const active = await one(`SELECT id, status FROM sync_jobs WHERE mailbox_id = $1 AND status IN ('queued','running','paused')`, [mailboxId]);
  if (active) {
    if (active.status === 'paused') return Number(active.id); // resume reuses the paused job
    throw new Error(`A sync job is already ${active.status} for this mailbox (job ${active.id}).`);
  }
  try {
    // idx_sync_jobs_one_active (partial unique index) is the real guard:
    // two concurrent starts race here and exactly one INSERT wins.
    const r = await one('INSERT INTO sync_jobs (mailbox_id, requested_by) VALUES ($1,$2) RETURNING id', [mailboxId, userId || null]);
    return Number(r.id);
  } catch (err) {
    if (String(err.code) === '23505') throw new Error('A sync job is already active for this mailbox (concurrent start rejected).');
    throw err;
  }
}

// Crash recovery: jobs left 'running' by a dead process become 'paused'
// (cursor is persisted → safely resumable). Called at server startup.
// Decision documented in docs/DECISIONS.md: paused, not failed/queued, so an
// operator explicitly resumes and nothing restarts unattended.
// ALSO reconciles the mailbox row: a mailbox left status='syncing' by the same
// unclean shutdown would otherwise stay visually stuck forever (observed in
// production) — reset it to 'ready' with a resumable note.
async function recoverStaleJobs() {
  const { all } = require('../../core/db');
  const rows = await all(
    `UPDATE sync_jobs SET status='paused', error_detail='recovered after unclean shutdown'
     WHERE status='running' RETURNING id, mailbox_id`);
  const reconciled = await all(
    `UPDATE mailboxes SET status='ready',
        status_detail='المزامنة توقفت بإعادة تشغيل غير نظيفة — المؤشر محفوظ، استأنف في أي وقت'
     WHERE status='syncing' RETURNING id`);
  if (reconciled.length) console.log && console.log(`[madar] reconciled ${reconciled.length} mailbox(es) stuck in 'syncing' → ready`);
  return rows;
}

// Per-tick staleness reconciliation for the live worker. recoverStaleJobs runs
// only at boot; but a cycle can die mid-flight AFTER boot (killed worker, OOM,
// an unhandled path) leaving a sync_jobs row status='running'. On the next tick
// createJob would then throw "already running", the worker marks the mailbox
// skippedBusy, and it is NEVER synced again until a full restart. That is a
// silent per-mailbox stall — the worker keeps ticking, this box just stops
// receiving new mail. Here we age-gate: a 'running' job with no progress for
// staleMin minutes is provably dead (a real 2-page sync finishes in seconds),
// so we pause it (cursor is persisted → createJob resumes it) and un-stick the
// mailbox. Age-gating means a legitimately long manual sync is never aborted.
async function reconcileStale(staleMin = 15) {
  const { all } = require('../../core/db');
  const paused = await all(
    `UPDATE sync_jobs SET status='paused', error_detail='auto-recovered: running with no progress > ${staleMin}m (worker un-stall)'
     WHERE status='running' AND COALESCE(started_at, created_at) < now() - interval '${staleMin} minutes'
     RETURNING id, mailbox_id`);
  const unstuck = await all(
    `UPDATE mailboxes m SET status='ready',
        status_detail='دورة سابقة توقّفت — المؤشر محفوظ، ستُستأنف تلقائيًا في الدورة القادمة'
     WHERE status='syncing'
       AND NOT EXISTS (SELECT 1 FROM sync_jobs j WHERE j.mailbox_id=m.id AND j.status='running'
                       AND COALESCE(j.started_at, j.created_at) >= now() - interval '${staleMin} minutes')
     RETURNING id`);
  return { pausedJobs: paused.length, unstuckMailboxes: unstuck.length };
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

// Address -> shared-mailbox routing map (primary addresses + aliases).
// Live capture for shared mailboxes: Zoho exposes no message API for groups
// (proven, DECISIONS.md), but group mail delivered to a synced MEMBER account
// is API-readable there — any synced message addressed to a registered shared
// mailbox also gets an occurrence in that mailbox (same canonical, source kept).
async function sharedAddressMap() {
  const { all } = require('../../core/db');
  const map = new Map();
  for (const r of await all(`SELECT id, address FROM mailboxes WHERE detected_type = 'shared_mailbox'`)) {
    map.set(r.address.toLowerCase(), Number(r.id));
  }
  for (const r of await all(`SELECT a.address, a.mailbox_id FROM mailbox_aliases a
                             JOIN mailboxes m ON m.id = a.mailbox_id WHERE m.detected_type = 'shared_mailbox'`)) {
    if (!map.has(r.address.toLowerCase())) map.set(r.address.toLowerCase(), Number(r.mailbox_id));
  }
  return { map, folderCache: new Map() };
}

async function routeToSharedMailboxes(msg, sourceMailboxId, routing, summary, diag = null) {
  if (!routing) return;
  const recipients = new Set((String(msg.to || '') + ' ' + String(msg.cc || ''))
    .toLowerCase().match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g) || []);
  for (const addr of recipients) {
    const targetId = routing.map.get(addr);
    if (!targetId || targetId === sourceMailboxId) continue;
    if (diag) diag.routingContext = { messageId: msg.providerMessageId, rfcMessageId: msg.rfcMessageId || null,
      sourceMailbox: sourceMailboxId, target: addr, decision: 'route_member_copy' };
    let folderId = routing.folderCache.get(targetId);
    if (!folderId) {
      folderId = await upsertFolder(targetId, { providerFolderId: 'live:routed', name: 'Live (وارد موجّه)', type: 'inbox' });
      routing.folderCache.set(targetId, folderId);
    }
    const { occurrenceId } = await insertMessage(targetId, folderId, msg, 'zoho:member_copy');
    if (occurrenceId) { summary.routed++; if (diag) diag.routed++; }
  }
}

async function syncMailbox(mailboxId, { maxPages = 5, userId = null } = {}) {
  const mailbox = await one('SELECT * FROM mailboxes WHERE id = $1', [mailboxId]);
  if (!mailbox) throw new Error('mailbox not found');
  if (!mailbox.is_pilot) throw new Error('sync refused: mailbox is not pilot-selected');
  if (!mailbox.sync_enabled) throw new Error('sync refused: not explicitly started by an admin');
  // Connector construction can fail (e.g. no probe-proven working id, missing
  // connection) — record it as a diagnostics row too, at the 'connect' stage.
  let connector;
  try {
    connector = await connectorFor(mailbox);
  } catch (err) {
    const d = newDiag(mailbox); d.stage = 'connect';
    err.traceId = await persistDiag(d, err).catch(() => d.traceId); err.stage = 'connect';
    throw err;
  }
  const jobId = await createJob(mailboxId, userId);
  await q("UPDATE sync_jobs SET status='running', started_at = COALESCE(started_at, now()) WHERE id = $1", [jobId]);
  await q("UPDATE mailboxes SET status='syncing' WHERE id=$1", [mailboxId]);
  const routing = await sharedAddressMap();
  const diag = newDiag(mailbox);
  const summary = { jobId, mailbox: mailbox.address, traceId: diag.traceId, folders: 0, newMessages: 0, newOccurrences: 0, attachments: 0, skipped: 0, routed: 0 };

  try {
    diag.stage = 'list_folders';
    diag.endpoint = `/api/accounts/${connector.id}/folders`;
    const folders = await connector.listFolders(); await budgetDelay();
    for (const f of folders) {
      await checkpoint(jobId);
      const folderId = await upsertFolder(mailboxId, f);
      summary.folders++;
      await q('UPDATE sync_jobs SET current_folder_id = $1 WHERE id = $2', [folderId, jobId]);
      await q('INSERT INTO sync_state (mailbox_id, folder_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [mailboxId, folderId]);
      const state = await one('SELECT * FROM sync_state WHERE mailbox_id=$1 AND folder_id=$2', [mailboxId, folderId]);

      // incremental newest page — scan the ENTIRE page, never stop at the first
      // already-seen message. The Zoho Mail messages/view endpoint pins no
      // guaranteed sort order (its default is undocumented and can interleave),
      // so a break-on-first-duplicate would silently drop a NEW email that
      // happens to sit after an already-stored one. Re-scanning one page of
      // PAGE_SIZE every tick is cheap (dedup is a single ON CONFLICT DO NOTHING)
      // and GUARANTEES any new message within the newest window is ingested,
      // independent of ordering. This is the fix for "worker runs but new mail
      // never appears": correctness no longer depends on the provider's sort.
      diag.stage = 'fetch_messages';
      diag.endpoint = connector.lastEndpoint;
      const newest = await connector.listMessages(f, { start: 1, limit: PAGE_SIZE }); await budgetDelay();
      diag.read += newest.length;
      diag.responseSample = { fields: newest[0] ? Object.keys(newest[0]).sort() : [], count: newest.length };
      await q('UPDATE sync_jobs SET discovered = discovered + $1 WHERE id = $2', [newest.length, jobId]);
      for (const msg of newest) {
        await checkpoint(jobId);
        await ingestOne(connector, f, mailboxId, folderId, msg, summary, jobId, routing, diag);
      }

      // backfill from persisted cursor
      if (!state.backfill_done) {
        let start = Math.max(Number(state.next_start) || 1, 1 + PAGE_SIZE);
        let pages = 0;
        while (pages < maxPages) {
          await checkpoint(jobId);
          diag.stage = 'fetch_messages'; diag.endpoint = connector.lastEndpoint;
          const batch = await connector.listMessages(f, { start, limit: PAGE_SIZE }); await budgetDelay();
          diag.read += batch.length;
          pages++;
          await q('UPDATE sync_jobs SET discovered = discovered + $1, current_cursor = $2 WHERE id = $3', [batch.length, start, jobId]);
          for (const msg of batch) {
            await checkpoint(jobId);
            await ingestOne(connector, f, mailboxId, folderId, msg, summary, jobId, routing, diag);
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
    diag.stage = 'done';
    await persistDiag(diag, null);
    await q("UPDATE sync_jobs SET status='completed', finished_at=now() WHERE id=$1", [jobId]);
    await q("UPDATE mailboxes SET status='ready', status_detail='' WHERE id=$1", [mailboxId]);
  } catch (err) {
    if (err instanceof JobStopped) {
      // status was already set by the control action; cursor is persisted → resumable
      if (err.kind === 'cancelled') await q('UPDATE sync_jobs SET finished_at=now() WHERE id=$1', [jobId]);
      await q("UPDATE mailboxes SET status='ready', status_detail=$1 WHERE id=$2",
        [`Last sync ${err.kind} — cursor persisted, resume any time.`, mailboxId]);
    } else {
      // Persist the FULL typed diagnostic (stage, endpoint, HTTP/SQL/routing,
      // complete stack) and put a traceable id on the job + mailbox status.
      const traceId = await persistDiag(diag, err).catch(() => diag.traceId);
      const shortMsg = `[${diag.stage}] ${String(err.message || err)}`.slice(0, 380) + ` (trace ${traceId})`;
      await q("UPDATE sync_jobs SET status='failed', error_detail=$1, errors = errors + 1, finished_at=now() WHERE id=$2",
        [shortMsg, jobId]);
      await q("UPDATE mailboxes SET status='error', status_detail=$1 WHERE id=$2", [shortMsg, mailboxId]);
      err.traceId = traceId; err.stage = diag.stage;
    }
    throw err;
  }
  await audit(userId, 'mail.sync', mailbox.address, summary);
  return summary;
}

async function ingestOne(connector, folder, mailboxId, folderId, msg, summary, jobId, routing = null, diag = null) {
  if (diag) diag.stage = 'db_tx';
  const { canonicalId, occurrenceId, isNewCanonical } = await insertMessage(mailboxId, folderId, msg);
  if (!occurrenceId) {
    summary.skipped++;
    if (diag) diag.skipped++;
    await q('UPDATE sync_jobs SET skipped = skipped + 1 WHERE id = $1', [jobId]);
    return false;
  }
  if (diag) { diag.stage = 'routing'; diag.inserted++; }
  await routeToSharedMailboxes(msg, mailboxId, routing, summary, diag);
  summary.newOccurrences++;
  await q('UPDATE sync_jobs SET imported = imported + 1 WHERE id = $1', [jobId]);
  if (!isNewCanonical) return true; // body/attachments already captured for this canonical

  summary.newMessages++;
  if (diag) diag.stage = 'body';
  const body = await connector.getBody(folder, msg.providerMessageId); await budgetDelay();
  if (body) await q('UPDATE canonical_messages SET body_html=$1 WHERE id=$2', [body, canonicalId]);
  if (msg.hasAttachments) {
    if (diag) diag.stage = 'attachments';
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

// Recorded variant used by the org-wide intake pipeline: every uploaded ZIP
// part gets a status row (pending -> importing -> completed | failed), so the
// admin sees per-mailbox intake state across all shared mailboxes.
async function importArchiveRecorded(mailboxId, zipBuffer, userId, filename = '') {
  const row = await one(
    `INSERT INTO archive_imports (mailbox_id, filename, size_bytes, status, uploaded_by)
     VALUES ($1, $2, $3, 'importing', $4) RETURNING id`,
    [mailboxId, String(filename).slice(0, 300), zipBuffer.length, userId]);
  try {
    const summary = await importArchiveZip(mailboxId, zipBuffer, userId);
    await q(`UPDATE archive_imports SET status = 'completed', totals = $1, finished_at = now() WHERE id = $2`,
      [JSON.stringify(summary), row.id]);
    return { importId: Number(row.id), ...summary };
  } catch (e) {
    await q(`UPDATE archive_imports SET status = 'failed', error_detail = $1, finished_at = now() WHERE id = $2`,
      [String(e.message).slice(0, 500), row.id]);
    throw e;
  }
}

module.exports = { syncMailbox, importArchiveZip, importArchiveRecorded, insertMessage, upsertFolder, dedupHash, normalizeForFingerprint, HASH_VERSION, storeAttachment, createJob, setJobControl, recoverStaleJobs, reconcileStale, persistDiag, newDiag };
