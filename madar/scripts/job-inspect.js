#!/usr/bin/env node
// Read-only sync-job lifecycle forensics — answers, from the LIVE database:
// is this job actively running, completed-but-mislocked, or stale-dead? Why has
// recovery (boot recoverStaleJobs / per-tick reconcileStale / on-start reclaim)
// fired or not fired? Who might be holding it (advisory locks, idle-in-tx)?
//
// Prints ids, statuses, timestamps, age math and lock metadata ONLY — no message
// content, no secrets, no tokens. Changes nothing.
//
// Usage (inside the app container):
//   node scripts/job-inspect.js --job 30
//   node scripts/job-inspect.js --mailbox m.almaysari@exoticcolors.org
require('../core/bootstrap').initCryptoFromEnv(); // consistency: all CLIs bootstrap alike
const { all, one, closeDb } = require('../core/db');

function arg(name) { const i = process.argv.indexOf(name); return i > -1 ? process.argv[i + 1] : null; }

async function main() {
  const jobId = arg('--job') ? Number(arg('--job')) : null;
  const addr = arg('--mailbox') ? String(arg('--mailbox')).toLowerCase() : null;
  let job = null;
  if (jobId) job = await one('SELECT * FROM sync_jobs WHERE id=$1', [jobId]);
  else if (addr) job = await one(`SELECT j.* FROM sync_jobs j JOIN mailboxes m ON m.id=j.mailbox_id
    WHERE lower(m.address)=$1 ORDER BY j.id DESC LIMIT 1`, [addr]);
  if (!job) { console.error('job not found (use --job N or --mailbox address)'); process.exit(1); }

  const mb = await one('SELECT id, address, status, status_detail, is_pilot, sync_enabled FROM mailboxes WHERE id=$1', [job.mailbox_id]);
  const hb = await one('SELECT * FROM sync_worker_heartbeat WHERE id=TRUE');
  const cycles = await all(`SELECT id, source, pid, ok, synced, failed, skipped_busy, recovered, created_at
    FROM sync_worker_cycles ORDER BY id DESC LIMIT 5`);
  const diags = await all(`SELECT trace_id, stage, outcome, classification, read_count, inserted_count, created_at
    FROM sync_diagnostics WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 5`, [job.mailbox_id]);
  const others = await all(`SELECT id, status, started_at, finished_at FROM sync_jobs
    WHERE mailbox_id=$1 AND id <> $2 ORDER BY id DESC LIMIT 5`, [job.mailbox_id, job.id]);

  // lock forensics: madar advisory locks (classid 0x4d41) + idle-in-transaction
  const advisory = await all(`SELECT l.pid, l.classid, l.objid, l.granted, a.state,
      a.application_name, now() - a.state_change AS in_state_for
    FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
    WHERE l.locktype = 'advisory'`);
  const idleTx = await all(`SELECT pid, state, application_name, now() - state_change AS in_state_for,
      LEFT(query, 60) AS last_query
    FROM pg_stat_activity WHERE state = 'idle in transaction'`);

  const startMs = job.started_at ? new Date(job.started_at).getTime() : (job.created_at ? new Date(job.created_at).getTime() : 0);
  const attemptAgeSec = startMs ? Math.round((Date.now() - startMs) / 1000) : null;
  // liveness = LEASE age (checkpoint touches lease_at ≤1s apart while alive);
  // attempt age is informational only — a live long backfill is legitimate
  const leaseMs = job.lease_at ? new Date(job.lease_at).getTime() : startMs;
  const leaseAgeSec = leaseMs ? Math.round((Date.now() - leaseMs) / 1000) : null;
  const STALE_SEC = Math.max(60, Number(process.env.MADAR_JOB_STALE_SEC) || 180);
  const wouldReclaim = job.status === 'running' && leaseAgeSec != null && leaseAgeSec > STALE_SEC;

  const verdict =
    job.status !== 'running' ? `job is '${job.status}' — not holding the mailbox` :
    wouldReclaim ? `STALE-DEAD: running but lease heartbeat is ${leaseAgeSec}s old (> ${STALE_SEC}s) — createJob/reconcileStale will reclaim it on the next start/tick` :
    `LIVE ATTEMPT: running with a ${leaseAgeSec}s-old lease heartbeat (attempt age ${attemptAgeSec}s — long attempts are legitimate) — the concurrent-start rejection is CORRECT protection right now`;

  console.log(JSON.stringify({
    job: { id: Number(job.id), mailboxId: Number(job.mailbox_id), status: job.status,
      createdAt: job.created_at, startedAt: job.started_at, finishedAt: job.finished_at,
      leaseAt: job.lease_at || null, leaseAgeSec,
      attemptAgeSec, discovered: job.discovered, imported: job.imported, skipped: job.skipped,
      errors: job.errors, errorDetail: job.error_detail, currentCursor: job.current_cursor },
    mailbox: mb ? { address: mb.address, status: mb.status, statusDetail: mb.status_detail,
      isPilot: mb.is_pilot, syncEnabled: mb.sync_enabled } : null,
    workerHeartbeat: hb ? { enabled: hb.enabled, pid: hb.pid, lastTickAt: hb.last_tick_at,
      updatedAt: hb.updated_at, ageSec: Math.round((Date.now() - new Date(hb.updated_at).getTime()) / 1000) } : null,
    recentWorkerCycles: cycles,
    recentDiagnostics: diags,
    otherRecentJobs: others,
    advisoryLocks: advisory,
    idleInTransaction: idleTx,
    stalenessPredicate: { basis: 'lease heartbeat (death), not attempt age', staleAfterSec: STALE_SEC,
      leaseAgeSec, attemptAgeSec, wouldReclaimNow: wouldReclaim },
    verdict,
  }, null, 2));
  await closeDb();
}

main().catch(async e => { console.error('job-inspect failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
