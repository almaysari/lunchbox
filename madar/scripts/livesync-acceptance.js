#!/usr/bin/env node
// Production-acceptance controller — thin CLI over DURABLE PostgreSQL state.
//
// The soak itself runs inside the Docker-supervised SERVER process
// (modules/mail/acceptance.js): this CLI only starts/inspects/finishes runs, so
// a container restart never kills the soak — the server resumes the same run on
// boot and the restart is recorded as evidence (`restart_detected`).
//
// Usage (inside the app container):
//   node scripts/livesync-acceptance.js start --hours 72 --canary "ACCEPT-7f3a"
//   node scripts/livesync-acceptance.js status
//   node scripts/livesync-acceptance.js report [--out data/acceptance-report.json]
//   node scripts/livesync-acceptance.js abort
//
// `report` works any time (mid-soak too) — it reads only persisted rows.
// Output contains counts/timings/classifications only: no message content,
// no tokens.
require('../core/bootstrap').initCryptoFromEnv(); // same keyring init as the server — CLI must never diverge
const fs = require('fs');
const path = require('path');
const { closeDb, one } = require('../core/db');
const acc = require('../modules/mail/acceptance');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

async function main() {
  const cmd = process.argv[2];
  if (cmd === 'start') {
    const run = await acc.startRun({
      hours: Number(arg('--hours', 72)),
      sampleSec: Number(arg('--sample-sec', 60)),
      canary: typeof arg('--canary') === 'string' ? arg('--canary') : null,
    });
    console.log(`started acceptance run ${run.id}: ${run.planned_hours}h, sample every ${run.sample_sec}s` +
      (run.canary ? ', canary set' : ''));
    console.log('the SERVER process samples it (survives restarts). Check with: status / report');
  } else if (cmd === 'status') {
    const run = await acc.activeRun();
    if (!run) {
      const last = await one(`SELECT id, status, finished_at, evaluation->>'verdict' AS verdict
        FROM acceptance_runs ORDER BY id DESC LIMIT 1`);
      console.log(last ? `no active run; last run ${last.id}: ${last.status}${last.verdict ? ' ' + last.verdict : ''}` : 'no runs yet');
    } else {
      const n = await one('SELECT COUNT(*)::int n, MAX(at) latest FROM acceptance_samples WHERE run_id=$1', [run.id]);
      const inc = await one('SELECT COUNT(*)::int n FROM acceptance_incidents WHERE run_id=$1', [run.id]);
      console.log(`run ${run.id} active: ${n.n} samples (latest ${n.latest || '—'}), ${inc.n} incidents, ends ${new Date(run.ends_at).toISOString()}`);
      if (n.n === 0) console.log('WARNING: zero samples — is the server process running with the sampler?');
    }
  } else if (cmd === 'report') {
    const run = await one(`SELECT id FROM acceptance_runs ORDER BY id DESC LIMIT 1`);
    if (!run) { console.log('no runs'); process.exitCode = 1; }
    else {
      const ev = await acc.evaluateRun(run.id);
      const out = String(arg('--out', path.join(__dirname, '..', 'data', 'acceptance-report.json')));
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, JSON.stringify(ev, null, 2));
      console.log(`run ${ev.runId} (${ev.status}): ${ev.verdict} — ${ev.samples} samples, ${ev.incidents} incidents`);
      for (const [k, v] of Object.entries(ev.checks)) {
        console.log(`  ${v.pass === true ? 'PASS' : v.pass === false ? 'FAIL' : 'N/A '} ${k}${v.note ? ' — ' + v.note : ''}`);
      }
      console.log('full evidence: ' + out);
      process.exitCode = ev.verdict === 'PASS' ? 0 : 1;
    }
  } else if (cmd === 'abort') {
    const r = await acc.abortRun();
    console.log(r ? `aborted run ${r.id}` : 'no active run');
  } else {
    console.error('usage: livesync-acceptance.js start|status|report|abort [--hours N] [--sample-sec N] [--canary text] [--out path]');
    process.exitCode = 2;
  }
  await closeDb();
}

main().catch(async e => { console.error('acceptance CLI failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
