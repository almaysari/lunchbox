// Live Sync background worker — smart polling, no overlap, per-mailbox backoff.
//
// Zoho offers no push/webhook for mailbox changes in the documented Mail API,
// so this polls (default every 120s, MADAR_LIVE_SYNC_INTERVAL_SEC) every
// mailbox an admin has explicitly enabled (is_pilot + sync_enabled) whose
// strategy is mail_api. Rate limits are respected by the connector's own
// per-request budget (~MADAR_MAX_RPM). Failures back off exponentially
// (interval × 2^n, capped at 30 min) per mailbox without blocking the others.
//
// Shared mailboxes have NO live message API (proven — DECISIONS.md): their
// live capture happens via routing inside syncMailbox — any synced message
// addressed to a registered shared mailbox also lands there (same canonical).
const os = require('os');
const { all, one, q } = require('../../core/db');
const { syncMailbox, reconcileStale, pruneObservability } = require('./sync');
const { audit } = require('../../core/audit');

const INTERVAL_MS = Math.max(30, Number(process.env.MADAR_LIVE_SYNC_INTERVAL_SEC) || 120) * 1000;
const MAX_BACKOFF_MS = 30 * 60 * 1000;
const PID = process.pid;
const HOST = os.hostname();

const state = {
  enabled: false,
  intervalMs: INTERVAL_MS,
  ticking: false,
  lastTickAt: null,
  nextTickAt: null,
  timer: null,
  perMailbox: new Map(), // id -> { backoffMs, backoffUntil, lastError, lastOkAt, lastSummary }
};

// ---- cross-process heartbeat (DB-backed; the single source of truth) ----
// The worker runs inside the main server process, so its in-memory `state` is
// invisible to any OTHER process (the CLI doctor, a health probe). Persisting the
// heartbeat means "is the worker running?" is answered from the database, which
// every process shares — fixing the false "worker is OFF" the CLI reported.
async function writeHeartbeat(patch) {
  const cols = Object.keys(patch);                 // fixed internal names, never user input
  const params = cols.map(c => patch[c]);
  const insCols = cols.join(', ');
  const insVals = cols.map((_, i) => `$${i + 1}`).join(', ');
  const updSet = cols.map((c, i) => `${c}=$${i + 1}`).concat('updated_at=now()').join(', ');
  await q(`INSERT INTO sync_worker_heartbeat (id, ${insCols}) VALUES (TRUE, ${insVals})
           ON CONFLICT (id) DO UPDATE SET ${updSet}`, params);
}
async function readHeartbeat() { return one('SELECT * FROM sync_worker_heartbeat WHERE id = TRUE'); }
async function logCycle(row) {
  try {
    await q(`INSERT INTO sync_worker_cycles (source, pid, ok, synced, failed, skipped_busy, skipped_backoff,
             recovered, duration_ms, result, error)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [row.source, PID, row.ok, row.synced || 0, row.failed || 0, row.skippedBusy || 0, row.skippedBackoff || 0,
        row.recovered || 0, row.durationMs || null, JSON.stringify(row.result || {}), row.error || null]);
  } catch { /* logging must never break the worker */ }
}

async function eligibleMailboxes() {
  return all(`SELECT id, address FROM mailboxes
              WHERE strategy = 'mail_api' AND is_pilot = TRUE AND sync_enabled = TRUE
              ORDER BY id`);
}

async function tickOnce({ source = 'worker' } = {}) {
  if (state.ticking) return { skipped: 'tick already running' };
  state.ticking = true;
  state.lastTickAt = Date.now();
  const startedMs = state.lastTickAt;
  const result = { synced: 0, skippedBackoff: 0, skippedBusy: 0, failed: 0, recovered: 0, perMailbox: [] };
  // Heartbeat: only the WORKER lifecycle owns enabled/pid/started_at. A tick from
  // any source refreshes last_tick_at/ticking so freshness is observable, but the
  // cycle log's `source` is what proves who ran it.
  if (source === 'worker') await writeHeartbeat({ ticking: true, last_tick_at: new Date(startedMs) }).catch(() => {});
  let loopError = null;
  try {
    // Un-stall before syncing: a dead-process 'running' job would otherwise make
    // createJob throw "already running" and this mailbox would be skipped every
    // tick, forever, with no new mail — until a full restart. Age-gated so a
    // legitimately long manual sync is never touched.
    try {
      const rec = await reconcileStale();
      result.recovered = rec.pausedJobs + rec.unstuckMailboxes;
      if (result.recovered) state.lastRecovery = { at: Date.now(), ...rec };
    } catch { /* reconciliation must never kill the tick */ }
    // Retention pruning ~every 6h (worker cycles + diagnostics older than
    // MADAR_RETENTION_DAYS) — required for multi-day unattended runs.
    if (source === 'worker' && Date.now() - (state.lastPruneAt || 0) > 6 * 3600 * 1000) {
      state.lastPruneAt = Date.now();
      try { state.lastPrune = { at: state.lastPruneAt, ...(await pruneObservability()) }; }
      catch { /* pruning must never kill the tick */ }
    }
    const eligible = await eligibleMailboxes();
    // Drop per-mailbox worker state for boxes no longer eligible (disabled or
    // deleted) — otherwise the map and its stale backoff entries grow forever.
    const eligibleIds = new Set(eligible.map(m => Number(m.id)));
    for (const id of state.perMailbox.keys()) if (!eligibleIds.has(id)) state.perMailbox.delete(id);
    for (const mb of eligible) {
      const id = Number(mb.id);
      const s = state.perMailbox.get(id) || { backoffMs: 0, backoffUntil: 0, lastError: null, lastOkAt: null, lastSummary: null };
      if (s.backoffUntil > Date.now()) { result.skippedBackoff++; result.perMailbox.push({ id, address: mb.address, outcome: 'backoff' }); state.perMailbox.set(id, s); continue; }
      try {
        // incremental: newest page per folder + bounded backfill continuation
        s.lastSummary = await syncMailbox(id, { maxPages: 2 });
        s.lastOkAt = Date.now(); s.lastError = null; s.backoffMs = 0; s.backoffUntil = 0;
        result.synced++;
        result.perMailbox.push({ id, address: mb.address, outcome: 'synced',
          newOccurrences: s.lastSummary && s.lastSummary.newOccurrences, traceId: s.lastSummary && s.lastSummary.traceId });
      } catch (e) {
        const msg = String(e.message || e);
        if (/already (active|running|queued|paused)/.test(msg)) { result.skippedBusy++; result.perMailbox.push({ id, address: mb.address, outcome: 'busy' }); }
        else {
          s.lastError = msg;
          s.backoffMs = Math.min(s.backoffMs ? s.backoffMs * 2 : state.intervalMs, MAX_BACKOFF_MS);
          s.backoffUntil = Date.now() + s.backoffMs;
          result.failed++;
          // Carry the typed transport/HTTP context into the cycle log so a main
          // worker failure is provable without opening every diagnostics row.
          result.perMailbox.push({ id, address: mb.address, outcome: 'failed', error: msg.slice(0, 300),
            errorClass: e.name || 'Error', stage: e.stage || null, traceId: e.traceId || null,
            httpStatus: e.httpStatus != null ? e.httpStatus : null,
            transport: e.transport ? { kind: e.transport.kind, code: e.transport.code, syscall: e.transport.syscall,
              hostname: e.transport.hostname, errno: e.transport.errno } : null });
          await audit(null, 'mail.livesync.error', mb.address, msg.slice(0, 300));
        }
      }
      state.perMailbox.set(id, s);
    }
  } catch (e) {
    loopError = String(e && e.message || e);
  } finally {
    state.ticking = false;
    const durationMs = Date.now() - startedMs;
    // Every cycle is logged — main worker OR forced CLI tick — so success/failure
    // of the real background loop is provable independently of a manual --force.
    await logCycle({ source, ok: !loopError && result.failed === 0, synced: result.synced, failed: result.failed,
      skippedBusy: result.skippedBusy, skippedBackoff: result.skippedBackoff, recovered: result.recovered,
      durationMs, result, error: loopError });
    if (source === 'worker') {
      await writeHeartbeat({ ticking: false, last_tick_at: new Date(startedMs),
        next_tick_at: state.enabled ? new Date(Date.now() + state.intervalMs) : null,
        last_result: JSON.stringify({ ...result, durationMs, error: loopError }) }).catch(() => {});
    }
  }
  if (loopError) result.error = loopError;
  return result;
}

function schedule() {
  state.nextTickAt = Date.now() + state.intervalMs;
  state.timer = setTimeout(async () => {
    try { await tickOnce({ source: 'worker' }); } catch { /* tick errors are per-mailbox; never kill the loop */ }
    if (state.enabled) schedule();
  }, state.intervalMs);
  if (state.timer.unref) state.timer.unref(); // never keep a dying process alive
}

function startLiveSync() {
  if (process.env.MADAR_LIVE_SYNC === 'off' || state.enabled) return false;
  state.enabled = true;
  schedule();
  // Publish the heartbeat so OTHER processes (CLI doctor, health checks) can see
  // the worker is alive. Fire-and-forget: a DB hiccup must not stop the worker.
  writeHeartbeat({ enabled: true, interval_sec: Math.round(state.intervalMs / 1000), pid: PID, hostname: HOST,
    started_at: new Date(), next_tick_at: new Date(Date.now() + state.intervalMs), ticking: false }).catch(() => {});
  return true;
}

function stopLiveSync() {
  state.enabled = false;
  if (state.timer) clearTimeout(state.timer);
  state.nextTickAt = null;
  writeHeartbeat({ enabled: false, next_tick_at: null, ticking: false }).catch(() => {});
}

// The authoritative "is the worker running?" — read from the shared DB heartbeat,
// NOT a process-local variable. Running == the worker published enabled=true AND
// the heartbeat is fresh (a crashed main process leaves a stale row → not running).
async function workerStatus() {
  const hb = await readHeartbeat();
  if (!hb) return { running: false, enabled: false, source: 'heartbeat', reason: 'no heartbeat row — worker never started against this database' };
  const intervalMs = (hb.interval_sec || 120) * 1000;
  const updatedMs = hb.updated_at ? new Date(hb.updated_at).getTime() : 0;
  const ageMs = Date.now() - updatedMs;
  const stale = ageMs > intervalMs * 2 + 60000; // two missed ticks + slack
  return {
    running: Boolean(hb.enabled) && !stale,
    enabled: Boolean(hb.enabled),
    stale, source: 'heartbeat', pid: hb.pid, hostname: hb.hostname,
    intervalSec: hb.interval_sec,
    startedAt: hb.started_at ? new Date(hb.started_at).getTime() : null,
    lastTickAt: hb.last_tick_at ? new Date(hb.last_tick_at).getTime() : null,
    nextTickAt: hb.next_tick_at ? new Date(hb.next_tick_at).getTime() : null,
    ticking: Boolean(hb.ticking),
    updatedAt: updatedMs || null, ageSec: updatedMs ? Math.round(ageMs / 1000) : null,
    lastResult: hb.last_result || null,
  };
}

// Compact worker health for /healthz: worker liveness (from the heartbeat) plus
// stuck-state detection — numbers only, no addresses/PII. "Stuck" here matches
// reconcileStale's age gate, so a nonzero value means recovery is overdue.
async function workerHealth() {
  const ws = await workerStatus();
  const stuckJobs = await one(
    `SELECT COUNT(*)::int n FROM sync_jobs WHERE status='running'
     AND COALESCE(started_at, created_at) < now() - interval '15 minutes'`);
  const stuckBoxes = await one(
    `SELECT COUNT(*)::int n FROM mailboxes m WHERE m.status='syncing'
     AND NOT EXISTS (SELECT 1 FROM sync_jobs j WHERE j.mailbox_id=m.id AND j.status='running'
                     AND COALESCE(j.started_at, j.created_at) >= now() - interval '15 minutes')`);
  return { running: ws.running, enabled: ws.enabled, stale: Boolean(ws.stale),
    lastTickAt: ws.lastTickAt || null, stuckJobs: stuckJobs.n, stuckMailboxes: stuckBoxes.n };
}

async function recentCycles(limit = 10, source = null) {
  const rows = source
    ? await all(`SELECT * FROM sync_worker_cycles WHERE source=$1 ORDER BY id DESC LIMIT $2`, [source, limit])
    : await all(`SELECT * FROM sync_worker_cycles ORDER BY id DESC LIMIT $1`, [limit]);
  return rows.map(r => ({ id: Number(r.id), source: r.source, pid: r.pid, ok: r.ok, synced: r.synced,
    failed: r.failed, skippedBusy: r.skipped_busy, skippedBackoff: r.skipped_backoff, recovered: r.recovered,
    durationMs: r.duration_ms, error: r.error, result: r.result, at: new Date(r.created_at).getTime() }));
}

async function liveStatus() {
  const boxes = await all(`SELECT m.id, m.address, m.display_name, m.detected_type, m.strategy,
      m.is_pilot, m.sync_enabled, m.status, m.status_detail
    FROM mailboxes m WHERE m.strategy = 'mail_api' OR m.detected_type = 'shared_mailbox'
    ORDER BY m.detected_type DESC, m.address`);
  const rows = [];
  for (const b of boxes) {
    const id = Number(b.id);
    const last = await one(`SELECT MAX(received_at) AS last_at FROM message_occurrences WHERE mailbox_id = $1`, [id]);
    const lastOcc = await one(`SELECT provider_message_id, received_at FROM message_occurrences
                               WHERE mailbox_id = $1 ORDER BY received_at DESC, id DESC LIMIT 1`, [id]);
    const day = await one(`SELECT COUNT(*)::int n FROM message_occurrences
                           WHERE mailbox_id = $1 AND created_at > now() - interval '24 hours'`, [id]);
    const st = await one(`SELECT MAX(last_sync_at) AS last_sync FROM sync_state WHERE mailbox_id = $1`, [id]);
    const lastJob = await one(`SELECT status, error_detail, finished_at FROM sync_jobs
                               WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1`, [id]);
    const mem = state.perMailbox.get(id) || {};
    rows.push({
      mailboxId: id, address: b.address, displayName: b.display_name,
      detectedType: b.detected_type, strategy: b.strategy,
      liveEligible: b.strategy === 'mail_api',
      captureVia: b.strategy === 'mail_api' ? 'direct_api'
        : b.detected_type === 'shared_mailbox' ? 'routed_member_copy' : 'none',
      syncEnabled: Boolean(b.sync_enabled), isPilot: Boolean(b.is_pilot),
      lastSyncAt: st && st.last_sync ? new Date(st.last_sync).getTime() : null,
      lastMessageAt: last && last.last_at ? new Date(last.last_at).getTime() : null,
      lastUid: lastOcc ? lastOcc.provider_message_id : null,
      newLast24h: day.n,
      lastJob: lastJob ? { status: lastJob.status, error: lastJob.error_detail || null,
        finishedAt: lastJob.finished_at ? new Date(lastJob.finished_at).getTime() : null } : null,
      worker: { lastOkAt: mem.lastOkAt || null, lastError: mem.lastError || null,
        backoffUntil: mem.backoffUntil || null },
    });
  }
  // Worker status comes from the DB heartbeat (cross-process truth), with the
  // in-process view alongside for this process's own diagnostics.
  const ws = await workerStatus();
  return {
    worker: {
      running: ws.running, enabled: ws.enabled, stale: ws.stale, source: ws.source,
      pid: ws.pid, hostname: ws.hostname, intervalSec: ws.intervalSec,
      startedAt: ws.startedAt, lastTickAt: ws.lastTickAt, nextTickAt: ws.nextTickAt,
      ticking: ws.ticking, updatedAt: ws.updatedAt, ageSec: ws.ageSec, reason: ws.reason || null,
      thisProcess: { enabled: state.enabled, pid: PID, isWorkerHost: state.enabled },
    },
    recentCycles: await recentCycles(8),
    mailboxes: rows,
  };
}

module.exports = { startLiveSync, stopLiveSync, tickOnce, liveStatus,
  workerStatus, workerHealth, recentCycles, readHeartbeat, _state: state };
