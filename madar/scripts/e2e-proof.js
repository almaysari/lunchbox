#!/usr/bin/env node
// E2E production proof — Gate 2/3 evidence collector, run on the REAL tenant.
//
//   Gate 2: send a uniquely-titled email to a synced mailbox, then:
//     docker compose exec app node scripts/e2e-proof.js <mailbox> --subject "E2E-7k2x" --watch 900
//   It waits for Live Sync to capture the message and prints the full timeline:
//     sentAt → receivedAt → storedAt (fetched+persisted) → visibleNow
//   plus the occurrence count (MUST be exactly 1) and the capturing trace.
//
//   Gate 3: after `docker compose restart app`, re-run WITHOUT --watch:
//     docker compose exec app node scripts/e2e-proof.js <mailbox> --subject "E2E-7k2x"
//   Same message, still exactly ONE occurrence (restart caused no duplicate,
//   no loss), worker heartbeat alive again, and any interrupted job resumed —
//   the verdict says PASS/FAIL for the restart gate.
//
// Evidence only — prints the canary subject (operator-chosen), ids, timestamps,
// counts. No bodies, no other subjects, no tokens.
require('../core/bootstrap').initCryptoFromEnv();
const { one, all, closeDb } = require('../core/db');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

async function snapshot(mailboxId, subject) {
  const rows = await all(`SELECT c.id AS canonical_id, c.subject, c.sent_at,
      o.id AS occurrence_id, o.received_at, o.created_at AS stored_at, o.provider, f.name AS folder
    FROM canonical_messages c
    JOIN message_occurrences o ON o.canonical_message_id = c.id
    LEFT JOIN folders f ON f.id = o.folder_id
    WHERE o.mailbox_id = $1 AND c.subject ILIKE '%' || $2 || '%'
    ORDER BY o.id`, [mailboxId, subject]);
  return rows;
}

async function main() {
  const address = (process.argv[2] || '').toLowerCase();
  const subject = arg('--subject');
  if (!address || typeof subject !== 'string' || !subject) {
    console.error('usage: e2e-proof.js <mailbox-address> --subject "E2E-xxxx" [--watch seconds]');
    process.exit(2);
  }
  const watchSec = Number(arg('--watch', 0)) || 0;
  const mb = await one('SELECT id, address FROM mailboxes WHERE lower(address)=$1', [address]);
  if (!mb) { console.error('mailbox not found'); process.exit(1); }

  const t0 = Date.now();
  let rows = await snapshot(mb.id, subject);
  if (!rows.length && watchSec > 0) {
    console.log(`[watch] waiting up to ${watchSec}s for a message titled ~"${subject}" to be captured by Live Sync...`);
    const deadline = Date.now() + watchSec * 1000;
    while (!rows.length && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 10000));
      rows = await snapshot(mb.id, subject);
      if (!rows.length && (Date.now() - t0) % 60000 < 10000) {
        const hb = await one('SELECT enabled, updated_at FROM sync_worker_heartbeat WHERE id=TRUE');
        const age = hb ? Math.round((Date.now() - new Date(hb.updated_at)) / 1000) : null;
        // honesty: enabled with an old heartbeat is NOT "alive" — say STALE loudly
        const label = !hb ? 'missing' : !hb.enabled ? 'OFF' : age < 300 ? 'alive' : `STALE (heartbeat frozen)`;
        console.log(`[watch] not yet — worker ${label}, heartbeat ${age != null ? age + 's ago' : 'n/a'}` +
          (label.startsWith('STALE') ? ' — the server may be running OLD code or stuck; pull latest + rebuild, then job-inspect' : ''));
      }
    }
  }
  if (!rows.length) {
    console.log(JSON.stringify({ gate: 'e2e', pass: false,
      reason: `no message matching "${subject}" captured${watchSec ? ` within ${watchSec}s` : ' (yet)'} — check live-sync status / doctor` }, null, 2));
    await closeDb(); process.exit(1);
  }

  // visibility: the message is served by the authorized read path (grants) —
  // count how many granted readers can see it right now
  const readers = await one(`SELECT COUNT(*)::int n FROM mailbox_grants WHERE mailbox_id=$1 AND can_view_messages`, [mb.id]);
  const occCount = rows.length;
  const first = rows[0];
  const canonTwins = await one(`SELECT COUNT(DISTINCT id)::int n FROM canonical_messages WHERE subject ILIKE '%' || $1 || '%'`, [subject]);

  // restart-gate context: worker heartbeat + last boot-recovery/resume events
  const hb = await one('SELECT enabled, pid, updated_at FROM sync_worker_heartbeat WHERE id=TRUE');
  const hbAge = hb ? Math.round((Date.now() - new Date(hb.updated_at)) / 1000) : null;
  const recentEvents = await all(`SELECT e.job_id, e.to_status, e.reason, e.at FROM job_events e
    JOIN sync_jobs j ON j.id = e.job_id WHERE j.mailbox_id = $1 ORDER BY e.id DESC LIMIT 8`, [mb.id]);
  const stuck = await one(`SELECT COUNT(*)::int n FROM sync_jobs WHERE mailbox_id=$1 AND status='running'
    AND COALESCE(lease_at, started_at, created_at) < now() - interval '180 seconds'`, [mb.id]);

  const sentAt = first.sent_at ? new Date(first.sent_at) : null;
  const storedAt = new Date(first.stored_at);
  const receivedAt = new Date(first.received_at);
  const out = {
    gate: 'e2e',
    mailbox: mb.address,
    subjectProbe: subject,
    timeline: {
      sentAt: sentAt ? sentAt.toISOString() : null,
      receivedAt: receivedAt.toISOString(),
      storedAt: storedAt.toISOString(),                       // fetched from Zoho + persisted (same transaction)
      captureLatencySec: Math.round((storedAt - receivedAt) / 1000),
      visibleNow: readers.n > 0,
      grantedReaders: readers.n,
      note: readers.n === 0 ? 'stored but no reader holds can_view_messages — grant read in the UI to see it' : undefined,
    },
    occurrences: occCount,
    canonicals: canonTwins.n,
    exactlyOneOccurrence: occCount === 1 && canonTwins.n === 1,
    capture: { occurrenceId: Number(first.occurrence_id), canonicalId: Number(first.canonical_id),
      provider: first.provider, folder: first.folder },
    workerAfter: { alive: Boolean(hb && hb.enabled && hbAge < 300), heartbeatAgeSec: hbAge, pid: hb ? hb.pid : null },
    stuckJobsNow: stuck.n,
    recentLifecycle: recentEvents,
  };
  out.pass = out.exactlyOneOccurrence && out.workerAfter.alive && stuck.n === 0;
  out.verdict = out.pass
    ? `PASS — captured exactly once (${out.timeline.captureLatencySec}s after receipt), worker alive, no stuck jobs${readers.n === 0 ? ' (grant read to view in UI)' : ''}`
    : !out.exactlyOneOccurrence ? `FAIL — expected exactly 1 occurrence/canonical, found ${occCount}/${canonTwins.n}`
      : !out.workerAfter.alive ? 'FAIL — worker heartbeat not alive'
        : `FAIL — ${stuck.n} stuck job(s) present`;
  console.log(JSON.stringify(out, null, 2));
  await closeDb();
  process.exit(out.pass ? 0 : 1);
}

main().catch(async e => { console.error('e2e-proof failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
