// Collector-mailbox organization — the production hardening layer over the
// ingestion gateway (madar.capture@...). Design contract (owner-mandated):
//
//   * ORIGINAL shared mailboxes are the system of record — the collector only
//     holds mirrored copies; nothing here ever touches any other mailbox.
//   * The collector is ingestion-only: after Madar processes a message, the
//     organizer MOVES the Zoho copy out of Inbox into Processed-<category> /
//     Unknown / Failed, so the Inbox stays clean (new + pending work only).
//   * All state is in the collector_ingest ledger (migration 020): restart-,
//     crash- and duplicate-safe. The organizer is a bounded, idempotent pass.
//   * Writes need write scopes on the COLLECTOR connection only. A tenant (or
//     scope) rejecting the write surface is capability-recorded
//     (collectorWrites: unsupported:*) and organization DEGRADES GRACEFULLY:
//     ingestion, routing and search continue untouched, monitoring reports
//     the backlog loudly.
//   * Retry policy: retryable failures stay in the Zoho Inbox, which the
//     realtime pass re-scans every tick — a retry costs nothing and a late
//     success is idempotent (dedup). After MAX_ATTEMPTS the row is promoted to
//     'failed' and the copy is moved to Failed/. The 'Retry' folder is the
//     MANUAL requeue surface: it is scanned like the Inbox, so an operator
//     dragging a message there re-runs it through the exact same pipeline.
const { one, all, q } = require('../../core/db');

const MAX_ATTEMPTS = () => Math.max(1, Number(process.env.MADAR_COLLECTOR_MAX_ATTEMPTS) || 5);
const ORG_FOLDERS = { failed: 'Failed', unknown: 'Unknown', retry: 'Retry' };
const PROCESSED_PREFIX = 'Processed-';
// organization folders are OUTPUTS — never scanned as ingest sources
const ORGANIZED_RE = /^(Processed-|Failed$|Unknown$)/;

function collectorAddresses() {
  return String(process.env.MADAR_COLLECTOR_ADDRESSES || '')
    .toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
}
function isCollectorAddress(address) {
  return collectorAddresses().includes(String(address || '').toLowerCase());
}
// deterministic category from the FIRST routed shared address: local part,
// lowercase (finance@… -> Processed-finance). Address-derived, never display
// names — stable across renames.
function categoryFor(routedTo) {
  const first = (routedTo || [])[0];
  return first ? String(first).split('@')[0].toLowerCase() : '';
}
const RETRYABLE = new Set(['request_timeout', 'request_aborted', 'http_429', 'http_500', 'http_502',
  'http_503', 'http_504', 'unknown_transport_error', 'oauth_refresh_failed']);
function isRetryable(classification, httpStatus) {
  if (classification && RETRYABLE.has(classification)) return true;
  return Number(httpStatus) === 429 || Number(httpStatus) >= 500;
}

// Ledger upsert — called from the sync loop for EVERY collector-inbox message
// outcome (success, unroutable, failure). Idempotent per provider message; a
// later success overrides an earlier retrying state; attempts accumulate.
async function recordOutcome({ mailboxId, providerMessageId, receivedAt = null, occurrenceId = null,
  routedTo = [], error = null, errorStack = null, classification = null, httpStatus = null }) {
  let state, target;
  if (error) {
    const retryable = isRetryable(classification, httpStatus);
    state = retryable ? 'retrying' : 'failed';
    target = retryable ? '' : ORG_FOLDERS.failed;
    const row = await one(`INSERT INTO collector_ingest (mailbox_id, provider_message_id, occurrence_id,
        state, routed_to, category, error, error_stack, retryable, received_at, target_folder, move_state)
      VALUES ($1,$2,$3,$4,'','',$5,$6,$7,$8,$9,$10)
      ON CONFLICT (mailbox_id, provider_message_id) DO UPDATE SET
        attempts = collector_ingest.attempts + 1,
        error = EXCLUDED.error, error_stack = EXCLUDED.error_stack, retryable = EXCLUDED.retryable,
        -- terminal states are never demoted by a later transient failure
        state = CASE WHEN collector_ingest.state IN ('processed','unknown','failed') THEN collector_ingest.state
                     WHEN EXCLUDED.state = 'failed' THEN 'failed'
                     WHEN collector_ingest.attempts + 1 >= $11 THEN 'failed'
                     ELSE 'retrying' END
      RETURNING state, attempts`,
    [mailboxId, providerMessageId, occurrenceId, state, String(error).slice(0, 2000),
      errorStack ? String(errorStack).slice(0, 8000) : null, state === 'retrying',
      receivedAt ? new Date(receivedAt) : null, target,
      state === 'retrying' ? 'skipped' : 'pending', MAX_ATTEMPTS()]);
    // promotion to failed needs its move target set
    if (row && row.state === 'failed') {
      await q(`UPDATE collector_ingest SET target_folder=$3, move_state='pending'
        WHERE mailbox_id=$1 AND provider_message_id=$2 AND move_state='skipped'`,
      [mailboxId, providerMessageId, ORG_FOLDERS.failed]);
    }
    return;
  }
  state = routedTo.length ? 'processed' : 'unknown';
  target = routedTo.length ? PROCESSED_PREFIX + categoryFor(routedTo) : ORG_FOLDERS.unknown;
  await q(`INSERT INTO collector_ingest (mailbox_id, provider_message_id, occurrence_id, state,
      routed_to, category, received_at, processed_at, target_folder, move_state)
    VALUES ($1,$2,$3,$4,$5,$6,$7,now(),$8,'pending')
    ON CONFLICT (mailbox_id, provider_message_id) DO UPDATE SET
      -- an idempotent RE-SCAN with no routing info must never demote a
      -- processed row to unknown (the original routing verdict stands)
      state = CASE WHEN collector_ingest.state='processed' AND EXCLUDED.state='unknown'
                   THEN 'processed' ELSE EXCLUDED.state END,
      routed_to = CASE WHEN collector_ingest.state='processed' AND EXCLUDED.state='unknown'
                       THEN collector_ingest.routed_to ELSE EXCLUDED.routed_to END,
      category = CASE WHEN collector_ingest.state='processed' AND EXCLUDED.state='unknown'
                      THEN collector_ingest.category ELSE EXCLUDED.category END,
      target_folder = CASE WHEN collector_ingest.state='processed' AND EXCLUDED.state='unknown'
                           THEN collector_ingest.target_folder ELSE EXCLUDED.target_folder END,
      occurrence_id = COALESCE(EXCLUDED.occurrence_id, collector_ingest.occurrence_id),
      processed_at = COALESCE(collector_ingest.processed_at, EXCLUDED.processed_at),
      move_state = CASE WHEN collector_ingest.move_state = 'done' THEN 'done' ELSE 'pending' END,
      error = NULL, error_stack = NULL`,
  [mailboxId, providerMessageId, occurrenceId, state, routedTo.join(','), categoryFor(routedTo),
    receivedAt ? new Date(receivedAt) : null, target]);
}

// Bounded, idempotent organizer pass: ensure target folders exist on Zoho and
// move processed/unknown/failed copies out of the Inbox. Batched per folder;
// respects a time budget so it can run inside the worker tick without ever
// delaying the realtime pass (it runs AFTER it).
async function organizePass({ budgetMs = 15000, batch = 50 } = {}) {
  const t0 = Date.now();
  const out = { mailboxes: 0, moved: 0, foldersCreated: 0, unsupported: 0, errors: 0 };
  const addrs = collectorAddresses();
  if (!addrs.length) return out;
  const boxes = await all(`SELECT * FROM mailboxes WHERE lower(address) = ANY($1)
    AND strategy='mail_api' AND is_pilot AND sync_enabled`, [addrs]);

  for (const box of boxes) {
    if (Date.now() - t0 > budgetMs) break;
    out.mailboxes++;
    const caps = typeof box.capabilities === 'string' ? JSON.parse(box.capabilities || '{}') : (box.capabilities || {});
    if (String(caps.collectorWrites || '').startsWith('unsupported')) { out.unsupported++; continue; }
    const pending = await all(`SELECT id, provider_message_id, target_folder FROM collector_ingest
      WHERE mailbox_id=$1 AND move_state='pending' AND target_folder <> '' ORDER BY id LIMIT $2`, [box.id, batch]);
    if (!pending.length) continue;

    const { ZohoClient } = require('./zoho-client');
    const { ZohoMailApiConnector } = require('./connectors/zoho-mail-api');
    let zoho, accountId;
    try {
      zoho = await ZohoClient.cachedForConnection(box.connection_id);
      accountId = new ZohoMailApiConnector(zoho, box).id;
    } catch { out.errors++; continue; }

    const folderIds = caps.collectorFolders || {}; // name -> zoho folder id (persisted cache)
    const recordUnsupported = async (status) => {
      caps.collectorWrites = 'unsupported:http_' + status;
      await q('UPDATE mailboxes SET capabilities=$1 WHERE id=$2', [JSON.stringify({ ...caps }), box.id]);
      await q(`UPDATE collector_ingest SET move_state='unsupported' WHERE mailbox_id=$1 AND move_state='pending'`, [box.id]);
      out.unsupported++;
    };

    const byFolder = new Map();
    for (const r of pending) {
      if (!byFolder.has(r.target_folder)) byFolder.set(r.target_folder, []);
      byFolder.get(r.target_folder).push(r);
    }
    let capsDirty = false, stop = false;
    for (const [folderName, rows] of byFolder) {
      if (stop || Date.now() - t0 > budgetMs) break;
      // ensure the target folder exists (cached id first, create on miss)
      if (!folderIds[folderName]) {
        const cr = await zoho.createFolder(accountId, folderName);
        if (cr.status === 200 || cr.status === 201) {
          const d = (cr.body && cr.body.data) || {};
          if (d.folderId) { folderIds[folderName] = String(d.folderId); out.foldersCreated++; capsDirty = true; }
        } else if (cr.status >= 400 && cr.status < 500) { await recordUnsupported(cr.status); stop = true; break; }
        else { out.errors++; continue; } // transport/5xx: retry next pass
        if (!folderIds[folderName]) { out.errors++; continue; }
      }
      const mv = await zoho.moveMessages(accountId, folderIds[folderName], rows.map(r => r.provider_message_id));
      if (mv.status === 200) {
        await q(`UPDATE collector_ingest SET move_state='done', moved_at=now() WHERE id = ANY($1)`,
          [rows.map(r => r.id)]);
        out.moved += rows.length;
        // evidence-record the working write surface once (monitoring shows
        // 'supported' instead of a forever-'untested')
        if (caps.collectorWrites !== 'supported') { caps.collectorWrites = 'supported'; capsDirty = true; }
      } else if (mv.status >= 400 && mv.status < 500) { await recordUnsupported(mv.status); stop = true; }
      else { out.errors++; } // transient: stays pending for the next pass
    }
    if (capsDirty && !stop) {
      caps.collectorFolders = folderIds;
      await q('UPDATE mailboxes SET capabilities=$1 WHERE id=$2', [JSON.stringify(caps), box.id]);
    }
  }
  out.elapsedMs = Date.now() - t0;
  return out;
}

// Monitoring — everything the operator asked for, from the ledger alone.
async function status() {
  const addrs = collectorAddresses();
  if (!addrs.length) return { enabled: false };
  const boxes = await all(`SELECT id, address, capabilities FROM mailboxes WHERE lower(address)=ANY($1)`, [addrs]);
  const perMailbox = [];
  for (const b of boxes) {
    const counts = Object.fromEntries((await all(`SELECT state, COUNT(*)::int n
      FROM collector_ingest WHERE mailbox_id=$1 GROUP BY state`, [b.id])).map(r => [r.state, r.n]));
    const moves = Object.fromEntries((await all(`SELECT move_state, COUNT(*)::int n
      FROM collector_ingest WHERE mailbox_id=$1 GROUP BY move_state`, [b.id])).map(r => [r.move_state, r.n]));
    const lat = await one(`SELECT ROUND(AVG(EXTRACT(EPOCH FROM (processed_at - received_at))))::int avg_sec
      FROM collector_ingest WHERE mailbox_id=$1 AND processed_at IS NOT NULL AND received_at IS NOT NULL
        AND processed_at > now() - interval '24 hours'`, [b.id]);
    const oldest = await one(`SELECT ROUND(EXTRACT(EPOCH FROM (now() - MIN(received_at))))::int age_sec
      FROM collector_ingest WHERE mailbox_id=$1 AND state='retrying'`, [b.id]);
    const caps = typeof b.capabilities === 'string' ? JSON.parse(b.capabilities || '{}') : (b.capabilities || {});
    perMailbox.push({
      address: b.address,
      processed: counts.processed || 0, unknown: counts.unknown || 0,
      retrying: counts.retrying || 0, failed: counts.failed || 0,
      inboxPendingApprox: (counts.retrying || 0) + (moves.pending || 0),
      movesPending: moves.pending || 0, movesDone: moves.done || 0,
      movesUnsupported: moves.unsupported || 0,
      avgProcessingLatencySec: lat ? lat.avg_sec : null,
      oldestUnprocessedAgeSec: oldest ? oldest.age_sec : null,
      writeCapability: caps.collectorWrites || 'untested',
    });
  }
  return { enabled: true, mailboxes: perMailbox };
}

// Pre-create the WHOLE organization tree up front (owner mandate: the
// structure is visible in the collector before the first message lands).
// The organizer only creates folders it is about to move into — it never
// creates 'Retry' (a manual requeue surface, not a move target) and creates
// Processed-<cat> lazily. Idempotent: the live folder list seeds the id cache
// first, because re-creating an existing name is a 4xx on real tenants and
// the caps cache can be lost to a discovery re-run — without the seed, a
// harmless re-run would falsely record the write surface as unsupported.
async function ensureFolders() {
  const out = { mailboxes: [] };
  const addrs = collectorAddresses();
  if (!addrs.length) return out;
  const shared = await all(`SELECT address FROM mailboxes WHERE detected_type='shared_mailbox'
    AND NOT (lower(address) = ANY($1)) ORDER BY address`, [addrs]);
  const wanted = [...Object.values(ORG_FOLDERS),
    ...shared.map(r => PROCESSED_PREFIX + String(r.address).split('@')[0].toLowerCase())];
  const boxes = await all(`SELECT * FROM mailboxes WHERE lower(address) = ANY($1)
    AND strategy='mail_api' AND is_pilot AND sync_enabled`, [addrs]);
  for (const box of boxes) {
    const caps = typeof box.capabilities === 'string' ? JSON.parse(box.capabilities || '{}') : (box.capabilities || {});
    const rep = { address: box.address, ensured: [], created: [], errors: [], unsupported: null };
    out.mailboxes.push(rep);
    if (String(caps.collectorWrites || '').startsWith('unsupported')) { rep.unsupported = caps.collectorWrites; continue; }
    const { ZohoClient } = require('./zoho-client');
    const { ZohoMailApiConnector } = require('./connectors/zoho-mail-api');
    let zoho, accountId;
    try {
      zoho = await ZohoClient.cachedForConnection(box.connection_id);
      accountId = new ZohoMailApiConnector(zoho, box).id;
    } catch (e) { rep.errors.push('client:' + (e.message || 'unknown')); continue; }
    const folderIds = caps.collectorFolders || {};
    let dirty = false;
    const lf = await zoho.getFolders(accountId);
    if (lf.status === 200 && Array.isArray(lf.body && lf.body.data)) {
      for (const f of lf.body.data) {
        if (f && f.folderName && f.folderId && wanted.includes(f.folderName) && !folderIds[f.folderName]) {
          folderIds[f.folderName] = String(f.folderId); dirty = true;
        }
      }
    }
    for (const name of wanted) {
      if (folderIds[name]) { rep.ensured.push(name); continue; }
      const cr = await zoho.createFolder(accountId, name);
      if (cr.status === 200 || cr.status === 201) {
        const d = (cr.body && cr.body.data) || {};
        if (d.folderId) { folderIds[name] = String(d.folderId); rep.created.push(name); rep.ensured.push(name); dirty = true; }
        else rep.errors.push(name + ':no_folder_id');
      } else if (cr.status >= 400 && cr.status < 500) {
        caps.collectorWrites = 'unsupported:http_' + cr.status; rep.unsupported = caps.collectorWrites; dirty = true; break;
      } else rep.errors.push(name + ':http_' + cr.status); // transport/5xx: next run retries
    }
    if (dirty) {
      caps.collectorFolders = folderIds;
      await q('UPDATE mailboxes SET capabilities=$1 WHERE id=$2', [JSON.stringify(caps), box.id]);
    }
  }
  return out;
}

module.exports = { collectorAddresses, isCollectorAddress, categoryFor, isRetryable,
  recordOutcome, organizePass, ensureFolders, status, ORGANIZED_RE, ORG_FOLDERS, PROCESSED_PREFIX };
