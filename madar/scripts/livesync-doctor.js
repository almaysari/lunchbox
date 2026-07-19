#!/usr/bin/env node
// Live Sync doctor — runs the SEVEN visibility checks against the REAL running
// tenant (the live Postgres this container is wired to), forces one real sync
// tick, and proves — end to end — whether a message actually reaches the
// authenticated reader's API. No screen access, no assumptions: every answer is
// read from the live database and the live Zoho fetch.
//
// Run inside the running app container so it shares the same DB + env:
//   docker compose exec app node scripts/livesync-doctor.js <mailbox-address> [--as you@company.com] [--force] [--grant]
//
//   <mailbox-address>   e.g. m.almaysari@exoticcolors.org  (the box you expect mail in)
//   --as <email>        evaluate the grant/visibility checks AS this user
//                       (defaults to the mailbox owner if they are a Madar user,
//                        else the first platform_admin)
//   --force             force one real sync tick NOW (fetch from Zoho) before reporting
//   --grant             if the reader lacks can_view_messages, grant it (audited),
//                        then re-check — proves the fix rather than describing it
//
// Prints a JSON evidence block + a one-line decisive verdict. Contains NO message
// bodies/subjects and NO tokens.

const { all, one, q, closeDb } = require('../core/db');
const auth = require('../core/auth');
const live = require('../modules/mail/live-sync');

function arg(name) {
  const i = process.argv.indexOf(name);
  return i > -1 ? (process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[i + 1] : true) : null;
}

async function main() {
  const address = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2].toLowerCase() : null;
  if (!address) {
    console.error('usage: node scripts/livesync-doctor.js <mailbox-address> [--as email] [--force] [--grant]');
    process.exit(2);
  }
  const asEmail = typeof arg('--as') === 'string' ? arg('--as').toLowerCase() : null;
  const doForce = Boolean(arg('--force'));
  const doGrant = Boolean(arg('--grant'));

  const mb = await one('SELECT * FROM mailboxes WHERE lower(address) = $1', [address]);
  if (!mb) { console.error(`mailbox not found: ${address}`); process.exit(1); }
  const id = Number(mb.id);

  // Reader identity: whose eyes are we testing visibility through?
  let reader = null;
  if (asEmail) reader = await one('SELECT * FROM users WHERE lower(email) = $1', [asEmail]);
  if (!reader) reader = await one('SELECT * FROM users WHERE lower(email) = $1', [address]); // mailbox owner, if a user
  if (!reader) reader = await one(
    `SELECT u.* FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id
     WHERE r.name='platform_admin' ORDER BY u.id LIMIT 1`);
  if (!reader) { console.error('no reader user could be resolved (pass --as email)'); process.exit(1); }

  const out = { mailbox: mb.address, mailboxId: id, strategy: mb.strategy, isPilot: mb.is_pilot,
    syncEnabled: mb.sync_enabled, detectedType: mb.detected_type, reader: reader.email, checks: {} };

  // ---- Worker status from the SHARED DB heartbeat (not this CLI process) ----
  // This is THE fix for the false "worker is OFF": the CLI is a different process
  // than the main server that runs the worker, so a process-local singleton is
  // always empty here. The heartbeat is written by the worker to the database.
  const ws = await live.workerStatus();
  out.worker = ws;

  // Main-worker vs forced-CLI cycles — proves the background loop's own
  // success/failure independently of any --force we run below.
  out.mainWorkerCycles = await live.recentCycles(5, 'worker');
  out.cliCycles = await live.recentCycles(3, 'cli');

  // ---- Optional: force a REAL sync tick now (fetch from Zoho), tagged 'cli' ----
  if (doForce) {
    try { out.forcedTick = await live.tickOnce({ source: 'cli' }); }
    catch (e) { out.forcedTick = { error: String(e.message || e), stack: e.stack }; }
  }

  // ---- The seven checks (all from the live DB) ----
  const lastDiag = await one('SELECT * FROM sync_diagnostics WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1', [id]);
  const lastJob = await one(`SELECT id,status,error_detail,started_at,finished_at,discovered,imported,skipped
                             FROM sync_jobs WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1`, [id]);
  const cursors = await all(`SELECT f.name, ss.backfill_done, ss.next_start, ss.last_sync_at, ss.last_error
                             FROM sync_state ss LEFT JOIN folders f ON f.id=ss.folder_id WHERE ss.mailbox_id=$1`, [id]);
  const occTotal = await one('SELECT COUNT(*)::int n FROM message_occurrences WHERE mailbox_id=$1', [id]);
  const occ24 = await one(`SELECT COUNT(*)::int n FROM message_occurrences WHERE mailbox_id=$1
                           AND created_at > now() - interval '24 hours'`, [id]);
  const dup = await one(`SELECT COUNT(*)::int n FROM fingerprint_metrics
                         WHERE mailbox_id=$1 AND event_type='duplicate_prevented'`, [id]);
  const myGrant = await one('SELECT can_view_messages FROM mailbox_grants WHERE user_id=$1 AND mailbox_id=$2', [reader.id, id]);
  const anyReaders = await one('SELECT COUNT(*)::int n FROM mailbox_grants WHERE mailbox_id=$1 AND can_view_messages', [id]);
  let inReadable = (await auth.readableMailboxIds(reader)).includes(id);

  out.checks['1_worker_running'] = { ok: ws.running, running: ws.running, enabled: ws.enabled, stale: ws.stale,
    source: ws.source, pid: ws.pid, hostname: ws.hostname, intervalSec: ws.intervalSec,
    startedAt: ws.startedAt, lastTickAt: ws.lastTickAt, nextTickAt: ws.nextTickAt, ageSec: ws.ageSec,
    reason: ws.reason || null };
  out.checks['2_recent_cycle'] = { ok: Boolean(lastDiag),
    lastCycleAt: lastDiag ? new Date(lastDiag.created_at).getTime() : null,
    lastJobStatus: lastJob ? lastJob.status : null };
  // response_sample carries the full phase-separated diagnosis (classification,
  // preserved original error, oauth evidence, transport detail, request meta)
  const diagSample = lastDiag && lastDiag.response_sample
    ? (typeof lastDiag.response_sample === 'string' ? JSON.parse(lastDiag.response_sample) : lastDiag.response_sample) : null;
  out.checks['3_fetched_from_zoho'] = { ok: Boolean(lastDiag && lastDiag.read_count > 0),
    read: lastDiag ? lastDiag.read_count : 0, endpoint: lastDiag ? lastDiag.endpoint : null,
    httpStatus: lastDiag ? lastDiag.http_status : null,
    classification: (lastDiag && lastDiag.classification) || (diagSample && diagSample.classification) || null,
    transport: diagSample && diagSample.transport ? diagSample.transport : null,
    oauth: diagSample && diagSample.oauth ? diagSample.oauth : null };

  // token cache metadata via the persisted state Live Sync itself uses (no
  // secrets: presence booleans + expiry only; fingerprints come from
  // zoho-path-diagnose which exercises the live provider)
  const connMeta = await one(`SELECT c.id, c.status, c.api_base,
      (c.refresh_token_enc IS NOT NULL) AS has_refresh_token,
      (c.access_token_enc IS NOT NULL) AS has_cached_access_token,
      c.access_token_expires_at
    FROM connections c WHERE c.id = $1`, [mb.connection_id]);
  out.tokenMetadata = connMeta ? {
    connectionId: Number(connMeta.id), connectionStatus: connMeta.status,
    dataCenterHost: (() => { try { return new URL(connMeta.api_base).host; } catch { return connMeta.api_base; } })(),
    source: 'postgres_cache', hasRefreshToken: connMeta.has_refresh_token,
    hasCachedAccessToken: connMeta.has_cached_access_token,
    accessTokenExpiresAt: connMeta.access_token_expires_at ? new Date(connMeta.access_token_expires_at).getTime() : null,
    accessTokenRemainingSec: connMeta.access_token_expires_at
      ? Math.round((new Date(connMeta.access_token_expires_at).getTime() - Date.now()) / 1000) : null,
  } : null;
  out.checks['4_inserted_or_cursor_dedup'] = { inserted: lastDiag ? lastDiag.inserted_count : 0,
    skipped: lastDiag ? lastDiag.skipped_count : 0, duplicatesPrevented: dup.n,
    cursors: cursors.map(c => ({ folder: c.name, backfillDone: c.backfill_done, nextStart: c.next_start,
      lastSyncAt: c.last_sync_at ? new Date(c.last_sync_at).getTime() : null, lastError: c.last_error })) };
  out.checks['5_stored_but_hidden'] = { storedInDb: occTotal.n, storedLast24h: occ24.n,
    readerHasGrant: Boolean(myGrant && myGrant.can_view_messages), mailboxInReadableSet: inReadable,
    anyReadersGranted: anyReaders.n, hiddenByGrant: occTotal.n > 0 && !inReadable };
  out.checks['6_status_syncing'] = { status: mb.status, statusDetail: mb.status_detail, stuck: mb.status === 'syncing' };
  out.checks['7_last_diagnostics'] = lastDiag ? { traceId: lastDiag.trace_id, stage: lastDiag.stage,
    outcome: lastDiag.outcome, classification: lastDiag.classification || null,
    read: lastDiag.read_count, inserted: lastDiag.inserted_count,
    skipped: lastDiag.skipped_count, routed: lastDiag.routed_count,
    error: lastDiag.outcome === 'error' ? { class: lastDiag.error_class, message: lastDiag.error_message,
      classification: lastDiag.classification || (diagSample && diagSample.classification) || null,
      sqlState: lastDiag.sql_state, constraint: lastDiag.constraint_name,
      originalError: diagSample && diagSample.originalError ? diagSample.originalError : null,
      transport: diagSample && diagSample.transport ? diagSample.transport : null,
      oauth: diagSample && diagSample.oauth ? diagSample.oauth : null,
      requestMeta: diagSample && diagSample.requestMeta ? diagSample.requestMeta : null,
      stack: lastDiag.error_stack ? String(lastDiag.error_stack).split('\n').slice(0, 6).join('\n') : null } : null } : null;

  // ---- Optional: prove the fix — grant read, then re-check ----
  if (doGrant && !(myGrant && myGrant.can_view_messages)) {
    await auth.setGrant(reader.id, id, { can_view_messages: true, can_view_attachments: true });
    inReadable = (await auth.readableMailboxIds(reader)).includes(id);
    out.grantApplied = { user: reader.email, mailboxInReadableSetNow: inReadable };
    out.checks['5_stored_but_hidden'].mailboxInReadableSet = inReadable;
    out.checks['5_stored_but_hidden'].hiddenByGrant = occTotal.n > 0 && !inReadable;
  }

  // ---- The decisive proof: does a real message reach the reader's API? ----
  // Mirror the exact authorization the message-list route uses: read starts FROM
  // the reader's readable occurrences, never the global canonical table.
  const readable = await auth.readableMailboxIds(reader);
  let visibleToReader = 0, latest = null;
  if (readable.includes(id)) {
    const vr = await one(`SELECT COUNT(*)::int n FROM message_occurrences WHERE mailbox_id = ANY($1::bigint[])
                          AND mailbox_id=$2`, [readable, id]);
    visibleToReader = vr.n;
    const l = await one(`SELECT received_at, created_at FROM message_occurrences WHERE mailbox_id=$2
                         AND mailbox_id = ANY($1::bigint[]) ORDER BY received_at DESC, id DESC LIMIT 1`, [readable, id]);
    latest = l ? { receivedAt: new Date(l.received_at).getTime(), storedAt: new Date(l.created_at).getTime() } : null;
  }
  out.proof = { messagesVisibleToReader: visibleToReader, latestVisible: latest,
    provenReachesUi: visibleToReader > 0 };

  // ---- Decisive verdict — first failing gate, in causal order ----
  const c = out.checks; let verdict;
  if (mb.strategy !== 'mail_api')
    verdict = `NOT a live-read box (strategy=${mb.strategy}) — mail arrives via routing/archive only, no direct Zoho fetch.`;
  else if (!mb.is_pilot || !mb.sync_enabled)
    verdict = 'Sync not enabled — enable Pilot then start Pilot Sync. The worker never touches a box not explicitly started.';
  else if (c['5_stored_but_hidden'].hiddenByGrant)
    verdict = `STORED BUT HIDDEN: ${occTotal.n} messages in DB, but reader ${reader.email} lacks can_view_messages on this box. Grant read (re-run with --grant) — the privacy policy blocks admins without an explicit grant.`;
  else if (!ws.running)
    verdict = ws.stale
      ? `Live worker NOT RESPONDING: last heartbeat ${ws.ageSec}s ago (> 2 intervals) — the main server process may be down; restart it.`
      : 'Live worker is OFF (MADAR_LIVE_SYNC=off or never started) — turn it on.';
  else if (lastDiag && lastDiag.outcome === 'error') {
    const e7 = c['7_last_diagnostics'] && c['7_last_diagnostics'].error;
    const cls = (e7 && e7.classification) || lastDiag.classification;
    const t = e7 && e7.transport;
    if (cls && cls.startsWith('oauth_'))
      verdict = `Last cycle FAILED at stage "${lastDiag.stage}" — ${cls.toUpperCase()}: ${lastDiag.error_message}. This is an OAUTH failure (no request reached Zoho) — NOT network. Trace ${lastDiag.trace_id}; run zoho-path-diagnose for Test A/B evidence.`;
    else if (cls === 'request_timeout')
      verdict = `Last cycle FAILED at stage "${lastDiag.stage}" — REQUEST TIMEOUT (AbortSignal fired). Trace ${lastDiag.trace_id}; see check 7 requestMeta for elapsed vs configured timeout.`;
    else if (t)
      verdict = `Last cycle FAILED at stage "${lastDiag.stage}" — TRANSPORT ${t.kind}${t.code ? ' (' + t.code + ')' : ''} to ${t.hostname || t.host || '?'}${t.syscall ? ' syscall=' + t.syscall : ''}. Network problem reaching Zoho — trace ${lastDiag.trace_id}. See check 7 for the full cause chain.`;
    else
      verdict = `Last cycle FAILED at stage "${lastDiag.stage}" — ${cls || 'HTTP ' + lastDiag.http_status}, trace ${lastDiag.trace_id}. See check 7.`;
  }
  else if (mb.status === 'syncing')
    verdict = 'Mailbox stuck on "syncing" — a dead cycle left it; the worker now auto-recovers age-gated. Re-run with --force.';
  else if (!lastDiag)
    verdict = 'No sync cycle has run yet for this box — run with --force or wait for the next tick.';
  else if (occTotal.n === 0 && lastDiag.read_count > 0)
    verdict = 'Zoho returned messages but none were inserted — inspect inserted/skipped/dedup in check 4.';
  else if (lastDiag.read_count === 0)
    verdict = 'Sync is healthy but Zoho returned no mail last cycle (no new inbound, or cursor at the top).';
  else if (out.proof.provenReachesUi)
    verdict = `HEALTHY — ${visibleToReader} message(s) are visible to ${reader.email}; a real message reaches the UI.`;
  else
    verdict = 'All gates pass but nothing is visible to the reader — unexpected; inspect the evidence block.';
  out.verdict = verdict;

  console.log(JSON.stringify(out, null, 2));
  console.log('\nVERDICT: ' + verdict);
  await closeDb();
}

main().catch(async e => { console.error('doctor failed:', e); try { await closeDb(); } catch {} process.exit(1); });
