#!/usr/bin/env node
// Live email-activity report for an acceptance soak window — READ-ONLY.
//
//   docker compose exec app node scripts/soak-activity.js            # active (or latest) run
//   docker compose exec app node scripts/soak-activity.js --run 6
//
// Answers, from the run's start to now: captures (total/new canonicals),
// breakdown by mailbox type and by folder class (incl. the virtual Archived
// view and routed copies), real-mail-vs-canary, routing to shared mailboxes,
// duplicate evidence (detector counts + guard meters), failed sync attempts
// (classified), and per-mailbox sync freshness.
//
// Sanitization (content policy applies to operators too): NO message subjects
// or bodies of real mail — sender DOMAINS, tenant mailbox addresses, folders,
// timestamps, counts. The canary subject is operator-chosen and may appear.
require('../core/bootstrap').initCryptoFromEnv();
const { one, all, closeDb } = require('../core/db');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

async function main() {
  const runId = arg('--run');
  const run = runId
    ? await one('SELECT * FROM acceptance_runs WHERE id=$1', [Number(runId)])
    : (await one(`SELECT * FROM acceptance_runs WHERE status='active' LIMIT 1`)
       || await one('SELECT * FROM acceptance_runs ORDER BY id DESC LIMIT 1'));
  if (!run) { console.error('no acceptance runs found'); process.exit(1); }
  const since = run.started_at;

  // 1) captures since the run started
  const totals = await one(`SELECT COUNT(*)::int occurrences,
      COUNT(DISTINCT canonical_message_id)::int canonicals
    FROM message_occurrences WHERE created_at >= $1`, [since]);

  // 2) breakdown: mailbox type + folder class
  const byType = await all(`SELECT
      CASE WHEN m.detected_type='shared_mailbox' THEN 'shared' ELSE m.detected_type END AS mailbox_type,
      COUNT(*)::int n
    FROM message_occurrences o JOIN mailboxes m ON m.id=o.mailbox_id
    WHERE o.created_at >= $1 GROUP BY 1 ORDER BY n DESC`, [since]);
  const byFolderClass = await all(`SELECT
      CASE WHEN f.provider_folder_id='zoho:archived' THEN 'Archived (Zoho) virtual view'
           WHEN f.provider_folder_id='live:routed' THEN 'routed member-copy (shared inbox)'
           ELSE lower(COALESCE(NULLIF(f.folder_type,''),'other')) END AS folder_class,
      COUNT(*)::int n
    FROM message_occurrences o LEFT JOIN folders f ON f.id=o.folder_id
    WHERE o.created_at >= $1 GROUP BY 1 ORDER BY n DESC`, [since]);

  // 3) real mail vs canary (subjects of real mail are NEVER printed)
  const canary = run.canary || null;
  const realVsCanary = await one(`SELECT
      COUNT(DISTINCT c.id) FILTER (WHERE $2::text IS NOT NULL AND c.subject ILIKE '%' || $2 || '%')::int canary_canonicals,
      COUNT(DISTINCT c.id) FILTER (WHERE $2::text IS NULL OR c.subject NOT ILIKE '%' || $2 || '%')::int real_canonicals
    FROM canonical_messages c JOIN message_occurrences o ON o.canonical_message_id=c.id
    WHERE o.created_at >= $1`, [since, canary]);
  const topSenders = await all(`SELECT lower(split_part(c.from_address,'@',2)) AS sender_domain,
      COUNT(DISTINCT c.id)::int messages
    FROM canonical_messages c JOIN message_occurrences o ON o.canonical_message_id=c.id
    WHERE o.created_at >= $1 AND ($2::text IS NULL OR c.subject NOT ILIKE '%' || $2 || '%')
    GROUP BY 1 ORDER BY messages DESC, 1 LIMIT 8`, [since, canary]);
  // sanitized examples: domain + mailbox + folder + time + attachments flag
  const examples = await all(`SELECT lower(split_part(c.from_address,'@',2)) AS sender_domain,
      m.address AS mailbox, COALESCE(f.name,'?') AS folder,
      o.received_at, c.has_attachments
    FROM message_occurrences o
    JOIN canonical_messages c ON c.id=o.canonical_message_id
    JOIN mailboxes m ON m.id=o.mailbox_id
    LEFT JOIN folders f ON f.id=o.folder_id
    WHERE o.created_at >= $1 AND ($2::text IS NULL OR c.subject NOT ILIKE '%' || $2 || '%')
    ORDER BY o.id DESC LIMIT 5`, [since, canary]);

  // 4) routed to shared mailboxes during the window
  const routed = await all(`SELECT m.address AS shared_mailbox, COUNT(*)::int n
    FROM message_occurrences o JOIN mailboxes m ON m.id=o.mailbox_id
    WHERE o.created_at >= $1 AND o.provider='zoho:member_copy'
    GROUP BY 1 ORDER BY n DESC`, [since]);

  // 5) duplicate evidence: detector incidents + live invariant + guard meters
  const dupIncidents = await one(`SELECT COUNT(*)::int n FROM acceptance_incidents
    WHERE run_id=$1 AND kind='duplicate_detected'`, [run.id]);
  const liveDupGroups = await one(`SELECT COUNT(*)::int n FROM (
    SELECT 1 FROM message_occurrences GROUP BY mailbox_id, provider, provider_message_id HAVING COUNT(*) > 1) d`);
  const guardMeters = await all(`SELECT event_type, COUNT(*)::int n FROM fingerprint_metrics
    WHERE created_at >= $1 GROUP BY 1 ORDER BY 1`, [since]).catch(() => []);

  // 6) failed sync attempts in the window, classified
  const failures = await all(`SELECT COALESCE(NULLIF(classification,''),'unclassified') AS classification,
      COUNT(*)::int n, MAX(created_at) AS latest
    FROM sync_diagnostics WHERE outcome='error' AND created_at >= $1
    GROUP BY 1 ORDER BY n DESC`, [since]);
  const failedJobs = await one(`SELECT COUNT(*)::int n FROM sync_jobs
    WHERE status='failed' AND created_at >= $1`, [since]);

  // 7) per-mailbox sync freshness + window activity
  const perMailbox = await all(`SELECT m.address, m.status,
      CASE WHEN m.detected_type='shared_mailbox' THEN 'shared' ELSE m.detected_type END AS type,
      (SELECT MAX(s.last_sync_at) FROM sync_state s WHERE s.mailbox_id=m.id) AS last_sync_at,
      (SELECT COUNT(*)::int FROM message_occurrences o WHERE o.mailbox_id=m.id AND o.created_at >= $1) AS captured_in_window
    FROM mailboxes m
    WHERE m.sync_enabled OR m.detected_type='shared_mailbox'
    ORDER BY captured_in_window DESC, m.address LIMIT 40`, [since]);
  const hb = await one('SELECT enabled, updated_at FROM sync_worker_heartbeat WHERE id=TRUE');

  const out = {
    run: { id: Number(run.id), status: run.status, startedAt: new Date(run.started_at).toISOString(),
      endsAt: new Date(run.ends_at).toISOString(), canarySubject: canary },
    window: { from: new Date(since).toISOString(), to: new Date().toISOString() },
    q1_capturedSinceStart: totals,
    q2_breakdown: { byMailboxType: byType, byFolderClass },
    q3_realMail: { realCanonicals: realVsCanary.real_canonicals, canaryCanonicals: realVsCanary.canary_canonicals,
      topSenderDomains: topSenders,
      sanitizedExamples: examples.map(e => ({ from: '<redacted>@' + e.sender_domain, mailbox: e.mailbox,
        folder: e.folder, receivedAt: new Date(e.received_at).toISOString(), hasAttachments: e.has_attachments })),
      note: 'subjects/bodies of real mail are content — never printed by CLI; read them in the UI under your grant' },
    q4_routedToShared: routed,
    q5_duplicates: { detectorIncidentsThisRun: dupIncidents.n, liveDuplicateGroupsNow: liveDupGroups.n,
      guardMetersInWindow: guardMeters },
    q6_failedSyncs: { classified: failures, failedJobs: failedJobs.n },
    q7_mailboxes: { worker: { enabled: Boolean(hb && hb.enabled),
      heartbeatAgeSec: hb ? Math.round((Date.now() - new Date(hb.updated_at)) / 1000) : null },
    perMailbox: perMailbox.map(r => ({ ...r,
      last_sync_at: r.last_sync_at ? new Date(r.last_sync_at).toISOString() : null })) },
  };
  console.log(JSON.stringify(out, null, 2));
  await closeDb();
  process.exit(0);
}

main().catch(async e => { console.error('soak-activity failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
