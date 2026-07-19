// Durable production-acceptance sampler — runs INSIDE the Docker-supervised
// server process, with ALL state in PostgreSQL (migration 011).
//
// Design (postgres-pro + docker skills):
//   * the run definition, every sample, every incident: rows, not process memory
//   * the sampler is a supervised loop in the main process — a container restart
//     kills it AND brings it back; on boot it finds the still-'active' run and
//     resumes sampling the SAME run, recording `restart_detected` (pid change)
//     as first-class evidence instead of losing the soak
//   * exactly one active run (partial unique index) — start/abort are races-safe
//   * evaluation reads only persisted rows, so it can run any time, from any
//     process, even mid-soak
//
// The operator CLI (scripts/livesync-acceptance.js) is now a thin controller:
// start / status / report / abort — it never holds soak state itself.
const fs = require('fs');
const { all, one, q } = require('../../core/db');
const { JOB_STALE_SEC } = require('./sync'); // stuck = dead lease, same gate system-wide

const state = { timer: null, running: false, lastSampleAt: null, lastRunId: null };

async function activeRun() {
  return one(`SELECT * FROM acceptance_runs WHERE status = 'active' LIMIT 1`);
}

async function startRun({ hours, sampleSec = 60, canary = null, userId = null }) {
  const h = Math.max(0.01, Number(hours));
  const s = Math.max(5, Math.floor(Number(sampleSec) || 60));
  try {
    // make_interval's hours parameter is int — fractional hours go through secs.
    // hours passed twice ($1 NUMERIC column, $5 double precision interval) so pg
    // never has to deduce one parameter as two types.
    const r = await one(`INSERT INTO acceptance_runs (planned_hours, sample_sec, canary, ends_at, created_by)
      VALUES ($1, $2, $3, now() + make_interval(secs => $5), $4) RETURNING *`,
      [h, s, canary, userId, h * 3600]);
    return r;
  } catch (err) {
    if (String(err.code) === '23505') throw new Error('an acceptance run is already active — finish or abort it first');
    throw err;
  }
}

async function abortRun() {
  return one(`UPDATE acceptance_runs SET status='aborted', finished_at=now()
              WHERE status='active' RETURNING id`);
}

function rssOfPid(pid) {
  try {
    const m = fs.readFileSync(`/proc/${pid}/status`, 'utf8').match(/VmRSS:\s+(\d+)\s*kB/);
    return m ? Number(m[1]) * 1024 : null;
  } catch { return null; }
}

async function takeSample(run) {
  const hb = await one('SELECT * FROM sync_worker_heartbeat WHERE id = TRUE');
  const intervalMs = ((hb && hb.interval_sec) || 120) * 1000;
  const ageMs = hb && hb.updated_at ? Date.now() - new Date(hb.updated_at).getTime() : Infinity;
  const stale = ageMs > intervalMs * 2 + 60000;
  const alive = Boolean(hb && hb.enabled && !stale);
  const stuckJobs = (await one(`SELECT COUNT(*)::int n FROM sync_jobs WHERE status='running'
    AND COALESCE(lease_at, started_at, created_at) < now() - make_interval(secs => ${JOB_STALE_SEC})`)).n;
  const stuckBoxes = (await one(`SELECT COUNT(*)::int n FROM mailboxes m WHERE m.status='syncing'
    AND NOT EXISTS (SELECT 1 FROM sync_jobs j WHERE j.mailbox_id=m.id AND j.status='running'
                    AND COALESCE(j.lease_at, j.started_at, j.created_at) >= now() - make_interval(secs => ${JOB_STALE_SEC}))`)).n;
  const occ = (await one('SELECT COUNT(*)::bigint n FROM message_occurrences')).n;
  const dupOcc = (await one(`SELECT COUNT(*)::int n FROM (
    SELECT 1 FROM message_occurrences GROUP BY mailbox_id, provider, provider_message_id HAVING COUNT(*) > 1) d`)).n;
  const dupCanon = (await one(`SELECT COUNT(*)::int n FROM (
    SELECT 1 FROM canonical_messages GROUP BY dedup_hash HAVING COUNT(*) > 1) d`)).n;
  const transport = await all(`SELECT COALESCE(response_sample::jsonb -> 'transport' ->> 'kind',
      'http_' || COALESCE(http_status::text, '?')) AS kind, COUNT(*)::int n
    FROM sync_diagnostics WHERE outcome='error' AND created_at > now() - make_interval(secs => $1)
    GROUP BY 1`, [run.sample_sec]);
  const transportObj = Object.fromEntries(transport.map(t => [t.kind, t.n]));
  const pid = hb ? hb.pid : null;
  const rss = pid ? rssOfPid(pid) : null;

  // restart evidence: worker pid changed since the previous sample of this run
  const prev = await one(`SELECT worker_pid FROM acceptance_samples WHERE run_id=$1 ORDER BY id DESC LIMIT 1`, [run.id]);
  if (prev && prev.worker_pid && pid && Number(prev.worker_pid) !== Number(pid)) {
    await q(`INSERT INTO acceptance_incidents (run_id, kind, detail) VALUES ($1, 'restart_detected', $2)`,
      [run.id, JSON.stringify({ fromPid: Number(prev.worker_pid), toPid: Number(pid) })]);
  }

  await q(`INSERT INTO acceptance_samples (run_id, worker_alive, heartbeat_age_sec, worker_pid, stuck_jobs,
      stuck_mailboxes, occurrences_total, duplicate_occurrences, duplicate_canonicals, transport_errors, rss_bytes)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [run.id, alive, Number.isFinite(ageMs) ? Math.round(ageMs / 1000) : null, pid, stuckJobs, stuckBoxes,
      occ, dupOcc, dupCanon, JSON.stringify(transportObj), rss]);

  const inc = (kind, detail) => q(`INSERT INTO acceptance_incidents (run_id, kind, detail) VALUES ($1,$2,$3)`,
    [run.id, kind, JSON.stringify(detail)]);
  if (!alive) await inc('worker_stale', { ageSec: Math.round(ageMs / 1000) });
  if (stuckJobs) await inc('stuck_job', { count: stuckJobs });
  if (stuckBoxes) await inc('stuck_mailbox', { count: stuckBoxes });
  if (dupOcc || dupCanon) await inc('duplicate_detected', { dupOcc, dupCanon });

  if (run.canary) {
    const seen = await one(`SELECT 1 FROM acceptance_incidents WHERE run_id=$1 AND kind='canary_captured' LIMIT 1`, [run.id]);
    if (!seen) {
      const hit = await one(`SELECT o.created_at, o.received_at, m.address,
          (SELECT COUNT(DISTINCT c2.id)::int FROM canonical_messages c2 WHERE c2.subject ILIKE '%' || $1 || '%') AS canonicals
        FROM canonical_messages c
        JOIN message_occurrences o ON o.canonical_message_id = c.id
        JOIN mailboxes m ON m.id = o.mailbox_id
        WHERE c.subject ILIKE '%' || $1 || '%' AND o.created_at >= $2 ORDER BY o.id LIMIT 1`,
        [run.canary, run.started_at]);
      if (hit) await inc('canary_captured', {
        mailbox: hit.address, canonicals: hit.canonicals, duplicateFree: hit.canonicals === 1,
        captureLatencySec: Math.round((new Date(hit.created_at) - new Date(hit.received_at)) / 1000),
      });
    }
  }
}

// Evaluation reads ONLY persisted rows — callable any time, from any process.
async function evaluateRun(runId) {
  const run = await one('SELECT * FROM acceptance_runs WHERE id=$1', [runId]);
  if (!run) throw new Error('run not found');
  const S = await all('SELECT * FROM acceptance_samples WHERE run_id=$1 ORDER BY id', [runId]);
  const I = await all('SELECT * FROM acceptance_incidents WHERE run_id=$1 ORDER BY id', [runId]);
  const restarts = I.filter(i => i.kind === 'restart_detected').length;
  const canaryInc = I.find(i => i.kind === 'canary_captured');
  const canary = canaryInc ? (typeof canaryInc.detail === 'string' ? JSON.parse(canaryInc.detail) : canaryInc.detail) : null;

  const perHour = Math.max(1, Math.floor(3600 / run.sample_sec));
  const rssSamples = S.filter(s => s.rss_bytes);
  const avg = a => a.length ? a.reduce((x, s) => x + Number(s.rss_bytes), 0) / a.length : null;
  const rss0 = avg(rssSamples.slice(0, perHour)), rss1 = avg(rssSamples.slice(-perHour));
  const memGrowth = rss0 && rss1 ? (rss1 - rss0) / rss0 : null;

  const kinds = {};
  for (const s of S) {
    const t = typeof s.transport_errors === 'string' ? JSON.parse(s.transport_errors || '{}') : (s.transport_errors || {});
    for (const [k, n] of Object.entries(t)) kinds[k] = (kinds[k] || 0) + Number(n);
  }
  const staleSamples = S.filter(s => !s.worker_alive).length;
  const checks = {
    worker_uptime: { pass: staleSamples === 0, staleSamples, totalSamples: S.length },
    survives_restart: restarts > 0
      ? { pass: staleSamples === 0, restartsObserved: restarts, note: 'restarts occurred and sampling continued on the same run' }
      : { pass: null, note: 'no restart occurred during the soak (not exercised)' },
    no_stuck_jobs: { pass: S.every(s => s.stuck_jobs === 0) },
    no_stuck_mailboxes: { pass: S.every(s => s.stuck_mailboxes === 0) },
    no_duplicates: { pass: S.every(s => s.duplicate_occurrences === 0 && s.duplicate_canonicals === 0) },
    memory_stable: { pass: memGrowth === null ? null : memGrowth < 0.25, growthRatio: memGrowth,
      note: memGrowth === null ? 'RSS unavailable from sampler process' : undefined },
    transport_health: { pass: Object.keys(kinds).length === 0, errorsByKind: kinds },
    canary_captured: run.canary
      ? { pass: Boolean(canary && canary.duplicateFree), result: canary }
      : { pass: null, note: 'no canary configured for this run' },
  };
  const hardFailures = Object.values(checks).filter(c => c.pass === false).length;
  return { runId: Number(runId), status: run.status, startedAt: run.started_at, endsAt: run.ends_at,
    samples: S.length, incidents: I.length, checks, hardFailures,
    verdict: hardFailures === 0 ? 'PASS' : 'FAIL' };
}

// Supervised sampler loop — started at server boot; picks up whatever run is
// active NOW or becomes active later (start/restart both land here).
function startAcceptanceSampler() {
  if (state.running) return false;
  state.running = true;
  const loop = async () => {
    try {
      const run = await activeRun();
      if (run) {
        state.lastRunId = Number(run.id);
        if (new Date(run.ends_at).getTime() <= Date.now()) {
          const ev = await evaluateRun(run.id);
          await q(`UPDATE acceptance_runs SET status='completed', finished_at=now(), evaluation=$1 WHERE id=$2`,
            [JSON.stringify(ev), run.id]);
          console.log(`[madar] acceptance run ${run.id} completed: ${ev.verdict}`);
        } else {
          await takeSample(run);
          state.lastSampleAt = Date.now();
        }
      }
    } catch (e) {
      // the sampler itself must never die silently — record and continue
      try {
        const run = await activeRun();
        if (run) await q(`INSERT INTO acceptance_incidents (run_id, kind, detail) VALUES ($1,'sampler_error',$2)`,
          [run.id, JSON.stringify({ error: String(e.message || e) })]);
      } catch { /* db down — next iteration retries */ }
    }
    if (!state.running) return;
    const run = await activeRun().catch(() => null);
    const delayMs = (run ? run.sample_sec : 30) * 1000;
    state.timer = setTimeout(loop, delayMs);
    if (state.timer.unref) state.timer.unref();
  };
  loop();
  return true;
}

function stopAcceptanceSampler() {
  state.running = false;
  if (state.timer) clearTimeout(state.timer);
}

module.exports = { startRun, abortRun, activeRun, takeSample, evaluateRun,
  startAcceptanceSampler, stopAcceptanceSampler, _state: state };
