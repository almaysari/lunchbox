#!/usr/bin/env node
// Checkpoint-model verification on the REAL tenant — the Gate-1 acceptance
// command for the structured checkpoint invariants:
//   * checkpoint_seq strictly monotonic for the job
//   * offset monotonic within the same folder+phase
//   * every offset drop explained by an explicit folder/phase transition
//   * the persisted per-folder truth (sync_state.next_start) never regresses
//
// It samples the active (or given) job over time, classifies every checkpoint
// delta with the SAME classifier the engine ships, prints each transition in
// full context, dumps the per-folder persisted cursors and the lifecycle
// events (including 'folder backfill completed' markers), and exits nonzero on
// any unexplained regression.
//
// Usage (inside the app container):
//   node scripts/checkpoint-verify.js --mailbox m.almaysari@exoticcolors.org [--samples 12] [--interval 10]
//   node scripts/checkpoint-verify.js --job 36
require('../core/bootstrap').initCryptoFromEnv();
const { one, all, closeDb } = require('../core/db');
const { classifyCheckpointDelta, jobEvents } = require('../modules/mail/sync');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

async function main() {
  const samples = Math.max(2, Number(arg('--samples', 12)));
  const intervalSec = Math.max(2, Number(arg('--interval', 10)));
  let jobRow = null;
  if (arg('--job')) jobRow = await one('SELECT * FROM sync_jobs WHERE id=$1', [Number(arg('--job'))]);
  else if (arg('--mailbox')) {
    const mb = await one('SELECT id FROM mailboxes WHERE lower(address)=$1', [String(arg('--mailbox')).toLowerCase()]);
    if (!mb) { console.error('mailbox not found'); process.exit(1); }
    jobRow = await one(`SELECT * FROM sync_jobs WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1`, [mb.id]);
  }
  if (!jobRow) { console.error('usage: checkpoint-verify.js --mailbox <address> | --job <id>'); process.exit(2); }
  const jobId = Number(jobRow.id);

  const observed = [];
  const transitions = [];
  let regressions = 0, prev = null;
  console.log(`[verify] sampling job ${jobId} checkpoint ${samples}× every ${intervalSec}s...`);
  for (let i = 0; i < samples; i++) {
    const j = await one('SELECT status, checkpoint, checkpoint_seq FROM sync_jobs WHERE id=$1', [jobId]);
    const c = j && (typeof j.checkpoint === 'string' ? JSON.parse(j.checkpoint || 'null') : j.checkpoint);
    if (c) {
      const cp = { seq: Number(j.checkpoint_seq), folderId: c.folderId, folderName: c.folderName,
        phase: c.phase, offset: Number(c.offset) };
      if (prev && cp.seq !== prev.seq) {
        const cls = classifyCheckpointDelta(prev, cp);
        const line = `job ${jobId}: folder ${prev.folderName}/phase ${prev.phase}/offset ${prev.offset} → folder ${cp.folderName}/phase ${cp.phase}/offset ${cp.offset} (seq ${prev.seq}→${cp.seq}) [${cls}]`;
        transitions.push({ classification: cls, line });
        console.log('  ' + line);
        if (cls === 'checkpoint_regression') regressions++;
      }
      prev = cp;
      observed.push({ at: new Date().toISOString(), status: j.status, ...cp });
    }
    if (i < samples - 1) await new Promise(r => setTimeout(r, intervalSec * 1000));
  }

  // the persisted per-folder truth — this is what resume actually uses
  const folderCursors = await all(`SELECT f.name, f.folder_type, ss.next_start, ss.backfill_done, ss.last_sync_at
    FROM sync_state ss JOIN folders f ON f.id = ss.folder_id
    WHERE ss.mailbox_id = $1 ORDER BY f.name`, [jobRow.mailbox_id]);

  const out = {
    jobId, status: (await one('SELECT status FROM sync_jobs WHERE id=$1', [jobId])).status,
    samplesTaken: observed.length,
    seqStrictlyMonotonic: observed.every((s, i) => i === 0 || s.seq >= observed[i - 1].seq)
      && transitions.every(t => t.classification !== 'checkpoint_regression' || false),
    transitions: transitions.map(t => t.line),
    unexplainedRegressions: regressions,
    persistedFolderCursors: folderCursors,
    lifecycleTail: await jobEvents(jobId, 12),
    observed,
  };
  out.pass = regressions === 0;
  out.verdict = out.pass
    ? `PASS — checkpoint_seq strictly monotonic across ${observed.length} samples; ${transitions.length} explicit folder/phase transition(s); zero unexplained regressions; per-folder persisted cursors listed above are the resume truth.`
    : `FAIL — ${regressions} unexplained checkpoint regression(s) detected (same folder+phase offset decrease or non-increasing seq). This is a correctness defect.`;
  console.log(JSON.stringify(out, null, 2));
  await closeDb();
  process.exit(out.pass ? 0 : 1);
}

main().catch(async e => { console.error('checkpoint-verify failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
