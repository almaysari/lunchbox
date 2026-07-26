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
    // --canary with no text used to silently mean NO canary (check ends N/A).
    // A bare flag now generates a subject — the operator must actually SEND an
    // email with it during the soak, so it is printed loudly.
    const canaryArg = arg('--canary');
    const canary = typeof canaryArg === 'string' ? canaryArg
      : canaryArg === true ? 'SOAK-' + require('crypto').randomUUID().slice(0, 8).toUpperCase() : null;
    const run = await acc.startRun({
      hours: Number(arg('--hours', 72)),
      sampleSec: Number(arg('--sample-sec', 60)),
      canary,
    });
    console.log(`started acceptance run ${run.id}: ${run.planned_hours}h, sample every ${run.sample_sec}s` +
      (run.canary ? `, canary subject: "${run.canary}"` : ', NO canary (canary check will be N/A)'));
    if (run.canary) console.log(`ACTION REQUIRED: during the soak, send a real email whose subject contains "${run.canary}" to a synced (or shared) mailbox — that is the routing-continues evidence.`);
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
      // incident KINDS inline — diagnosing must never depend on the report
      // file being writable (and canary_captured here is GOOD news, not a fault)
      if (inc.n > 0) {
        const kinds = await require('../core/db').all(
          `SELECT kind, COUNT(*)::int n, MAX(at) latest FROM acceptance_incidents WHERE run_id=$1 GROUP BY kind ORDER BY kind`, [run.id]);
        for (const k of kinds) console.log(`  incident ${k.kind}: ${k.n}x (latest ${new Date(k.latest).toISOString()})`);
        const last = await one(`SELECT kind, detail, at FROM acceptance_incidents WHERE run_id=$1 ORDER BY id DESC LIMIT 1`, [run.id]);
        console.log(`  latest detail: ${typeof last.detail === 'string' ? last.detail : JSON.stringify(last.detail)}`);
      }
    }
  } else if (cmd === 'report') {
    const run = await one(`SELECT id FROM acceptance_runs ORDER BY id DESC LIMIT 1`);
    if (!run) { console.log('no runs'); process.exitCode = 1; }
    else {
      const ev = await acc.evaluateRun(run.id);
      // console FIRST — the verdict must never be lost to an unwritable path
      // (in the container /app is root-owned while the process runs as node:
      // the old data/-first default crashed before printing anything)
      console.log(`run ${ev.runId} (${ev.status}): ${ev.verdict} — ${ev.samples} samples, ${ev.incidents} incidents`);
      for (const [k, v] of Object.entries(ev.checks)) {
        console.log(`  ${v.pass === true ? 'PASS' : v.pass === false ? 'FAIL' : 'N/A '} ${k}${v.note ? ' — ' + v.note : ''}` +
          (v.pass === false && v.errorsByKind ? ' ' + JSON.stringify(v.errorsByKind) : ''));
      }
      const candidates = arg('--out') && typeof arg('--out') === 'string' ? [String(arg('--out'))] : [
        process.env.MADAR_DATA_DIR ? path.join(process.env.MADAR_DATA_DIR, 'acceptance-report.json') : null,
        '/var/lib/madar/acceptance-report.json',                        // writable in the official container
        path.join(__dirname, '..', 'data', 'acceptance-report.json'),   // bare-metal runs
      ].filter(Boolean);
      let written = null, writeErr = null;
      for (const out of candidates) {
        try { fs.mkdirSync(path.dirname(out), { recursive: true }); fs.writeFileSync(out, JSON.stringify(ev, null, 2)); written = out; break; }
        catch (e) { writeErr = e.message; }
      }
      console.log(written ? 'full evidence: ' + written
        : `WARNING: could not write the evidence file (${writeErr}) — verdict above is complete; pass --out <path> for a copy`);
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
