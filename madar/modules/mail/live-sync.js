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
const { all, one } = require('../../core/db');
const { syncMailbox } = require('./sync');
const { audit } = require('../../core/audit');

const INTERVAL_MS = Math.max(30, Number(process.env.MADAR_LIVE_SYNC_INTERVAL_SEC) || 120) * 1000;
const MAX_BACKOFF_MS = 30 * 60 * 1000;

const state = {
  enabled: false,
  intervalMs: INTERVAL_MS,
  ticking: false,
  lastTickAt: null,
  nextTickAt: null,
  timer: null,
  perMailbox: new Map(), // id -> { backoffMs, backoffUntil, lastError, lastOkAt, lastSummary }
};

async function eligibleMailboxes() {
  return all(`SELECT id, address FROM mailboxes
              WHERE strategy = 'mail_api' AND is_pilot = TRUE AND sync_enabled = TRUE
              ORDER BY id`);
}

async function tickOnce() {
  if (state.ticking) return { skipped: 'tick already running' };
  state.ticking = true;
  state.lastTickAt = Date.now();
  const result = { synced: 0, skippedBackoff: 0, skippedBusy: 0, failed: 0 };
  try {
    for (const mb of await eligibleMailboxes()) {
      const id = Number(mb.id);
      const s = state.perMailbox.get(id) || { backoffMs: 0, backoffUntil: 0, lastError: null, lastOkAt: null, lastSummary: null };
      if (s.backoffUntil > Date.now()) { result.skippedBackoff++; state.perMailbox.set(id, s); continue; }
      try {
        // incremental: newest page per folder + bounded backfill continuation
        s.lastSummary = await syncMailbox(id, { maxPages: 2 });
        s.lastOkAt = Date.now(); s.lastError = null; s.backoffMs = 0; s.backoffUntil = 0;
        result.synced++;
      } catch (e) {
        const msg = String(e.message || e);
        if (/already (active|running|queued|paused)/.test(msg)) { result.skippedBusy++; }
        else {
          s.lastError = msg;
          s.backoffMs = Math.min(s.backoffMs ? s.backoffMs * 2 : state.intervalMs, MAX_BACKOFF_MS);
          s.backoffUntil = Date.now() + s.backoffMs;
          result.failed++;
          await audit(null, 'mail.livesync.error', mb.address, msg.slice(0, 300));
        }
      }
      state.perMailbox.set(id, s);
    }
  } finally {
    state.ticking = false;
  }
  return result;
}

function schedule() {
  state.nextTickAt = Date.now() + state.intervalMs;
  state.timer = setTimeout(async () => {
    try { await tickOnce(); } catch { /* tick errors are per-mailbox; never kill the loop */ }
    if (state.enabled) schedule();
  }, state.intervalMs);
  if (state.timer.unref) state.timer.unref(); // never keep a dying process alive
}

function startLiveSync() {
  if (process.env.MADAR_LIVE_SYNC === 'off' || state.enabled) return false;
  state.enabled = true;
  schedule();
  return true;
}

function stopLiveSync() {
  state.enabled = false;
  if (state.timer) clearTimeout(state.timer);
  state.nextTickAt = null;
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
  return {
    worker: {
      enabled: state.enabled, intervalSec: state.intervalMs / 1000,
      lastTickAt: state.lastTickAt, nextTickAt: state.nextTickAt, ticking: state.ticking,
    },
    mailboxes: rows,
  };
}

module.exports = { startLiveSync, stopLiveSync, tickOnce, liveStatus, _state: state };
