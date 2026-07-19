#!/usr/bin/env node
// Test A / Test B — application-level root-cause diagnosis for the list_folders
// "HTTP 0" symptom, run INSIDE the app container against the REAL tenant.
//
//   Test A  calls list_folders through the EXACT production stack:
//           ZohoClient.cachedForConnection (PostgreSQL token cache + advisory-
//           locked refresh) → ZohoMailApiConnector.listFolders — the same
//           client, headers, timeout, abort and error parser Live Sync uses.
//   Test B  triggers the REAL Live Sync path (sync.syncMailbox) and reads the
//           persisted diagnostics row it produced.
//
// It prints a comparison and the decisive interpretation:
//   A fails                → OAuth acquisition / persisted token state / scopes /
//                            account id / data-center (see A's classification)
//   A passes, B fails      → the Live Sync wrapper (see B's classification)
//   both pass              → earlier failure was stale code/token state or
//                            intermittent — use --repeat N to hunt intermittence
//
// Sanitized by construction: token appears ONLY as a sha256 12-char fingerprint;
// headers are redacted; bodies pass the secret scrubber. Read-only except that
// Test B is the real sync path (it ingests new mail exactly as production does).
//
// Usage:
//   docker compose exec app node scripts/zoho-path-diagnose.js <mailbox-address> [--repeat N] [--skip-b] [--wait-sec N (default 300)]
// Keyring bootstrap FIRST — without it this CLI decrypted with an EMPTY keyring
// and every tenant saw the artifact "No encryption key for version k1" (the
// server was healthy all along). Same init path as server.js.
require('../core/bootstrap').initCryptoFromEnv();
const { one, closeDb } = require('../core/db');
const { ZohoClient } = require('../modules/mail/zoho-client');
const { ZohoMailApiConnector } = require('../modules/mail/connectors/zoho-mail-api');

function fail(msg) { console.error(msg); process.exit(2); }

function evidenceFromError(e) {
  return {
    classification: e.classification || 'application_exception',
    phase: e.phase || null,
    message: String(e.message || e).slice(0, 300),
    httpStatus: e.httpStatus != null ? e.httpStatus : null,
    originalError: e.originalError || null,
    transport: e.transport ? { kind: e.transport.kind, code: e.transport.code, syscall: e.transport.syscall,
      hostname: e.transport.hostname } : null,
    requestMeta: e.requestMeta ? { host: e.requestMeta.host, timeoutMs: e.requestMeta.timeoutMs,
      elapsedMs: e.requestMeta.elapsedMs, abortFired: e.requestMeta.abortFired, abortReason: e.requestMeta.abortReason } : null,
    oauth: e.oauth || null,
    responseSample: e.responseSample || null,
  };
}

async function testA(mailbox) {
  const out = { name: 'A_production_token_provider_direct' };
  const t0 = Date.now();
  try {
    const zoho = await ZohoClient.cachedForConnection(mailbox.connection_id); // THE production provider
    const connector = new ZohoMailApiConnector(zoho, mailbox);
    out.accountId = connector.id;
    out.dataCenterHost = new URL(zoho.conn.api_base).host;
    const folders = await connector.listFolders();
    out.elapsedMs = Date.now() - t0;
    out.tokenEvidence = zoho.lastTokenEvidence || null; // fingerprint/source/expiry only
    // structural validation — a "success" with a wrong shape is not a success
    const structural = Array.isArray(folders) && folders.length > 0 &&
      folders.every(f => f.providerFolderId && typeof f.name === 'string');
    out.result = { ok: true, folders: folders.length,
      structurallyValid: structural,
      sample: folders.slice(0, 3).map(f => ({ name: f.name, type: f.type })) };
    out.classification = structural ? 'ok' : 'malformed_response';
  } catch (e) {
    out.elapsedMs = Date.now() - t0;
    out.result = { ok: false };
    out.error = evidenceFromError(e);
    out.classification = out.error.classification;
    try { out.tokenEvidence = (await ZohoClient.cachedForConnection(mailbox.connection_id)).lastTokenEvidence || null; } catch { /* keep null */ }
  }
  return out;
}

// A LIVE worker owning the mailbox is healthy concurrency protection, not a
// diagnostic failure. Test B therefore WAITS for the active attempt to finish
// (polling job state + lease, collecting progress evidence), then executes the
// real path itself. If the attempt outlives the wait budget, it reports
// attached-evidence: the worker IS the real Live Sync path, and its advancing
// cursor + fresh lease are authentic proof it is executing right now.
async function waitForMailboxFree(mailboxId, waitSec, out) {
  const deadline = Date.now() + waitSec * 1000;
  let first = null, last = null, polls = 0;
  while (Date.now() < deadline) {
    const j = await one(`SELECT id, status, started_at, lease_at, current_cursor, imported, discovered
      FROM sync_jobs WHERE mailbox_id=$1 AND status IN ('queued','running') ORDER BY id DESC LIMIT 1`, [mailboxId]);
    if (!j) return { free: true, polls, observed: last };
    polls++;
    const snap = { jobId: Number(j.id), status: j.status, cursor: j.current_cursor,
      imported: j.imported, discovered: j.discovered,
      leaseAgeSec: j.lease_at ? Math.round((Date.now() - new Date(j.lease_at).getTime()) / 1000) : null };
    if (!first) first = snap;
    last = snap;
    if (polls === 1 || polls % 6 === 0) { // progress line every ~30s — never block silently
      console.log(`  [wait] job ${snap.jobId} ${snap.status}: lease ${snap.leaseAgeSec}s, cursor ${snap.cursor}, imported ${snap.imported}`);
    }
    await new Promise(r => setTimeout(r, 5000));
  }
  return { free: false, polls, first, observed: last,
    progressAdvanced: Boolean(first && last && (last.cursor !== first.cursor
      || last.imported !== first.imported || last.discovered !== first.discovered)),
    leaseAlive: Boolean(last && last.leaseAgeSec != null && last.leaseAgeSec < 120) };
}

async function testB(mailbox, waitSec = 300) {
  const out = { name: 'B_live_sync_real_path' };
  const sync = require('../modules/mail/sync');
  const t0 = Date.now();
  const wait = await waitForMailboxFree(Number(mailbox.id), waitSec, out);
  out.waitedForActiveWorker = { waitedSec: Math.round((Date.now() - t0) / 1000), polls: wait.polls };
  if (!wait.free) {
    // attached evidence: the WORKER is executing the real path right now
    out.result = { ok: wait.progressAdvanced || wait.leaseAlive, mode: 'attached_to_live_worker',
      job: wait.observed, firstSample: wait.first,
      progressAdvanced: wait.progressAdvanced, leaseAlive: wait.leaseAlive };
    out.classification = (wait.progressAdvanced || wait.leaseAlive) ? 'live_worker_active' : 'stuck_job_suspected';
    out.elapsedMs = Date.now() - t0;
  } else {
    try {
      const summary = await sync.syncMailbox(Number(mailbox.id), { maxPages: 1 });
      out.result = { ok: true, mode: 'direct', traceId: summary.traceId, folders: summary.folders,
        newOccurrences: summary.newOccurrences, skipped: summary.skipped };
      out.classification = 'ok';
    } catch (e) {
      out.result = { ok: false, traceId: e.traceId || null, stage: e.stage || null };
      out.error = evidenceFromError(e);
      out.classification = out.error.classification;
    }
    out.elapsedMs = Date.now() - t0;
  }
  // the persisted diagnostics row is the durable truth for this cycle
  const diag = await one(`SELECT trace_id, stage, outcome, classification, http_status, endpoint,
      error_class, error_message, read_count, inserted_count, skipped_count
    FROM sync_diagnostics WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1`, [mailbox.id]);
  out.persistedDiagnostics = diag ? { traceId: diag.trace_id, stage: diag.stage, outcome: diag.outcome,
    classification: diag.classification, httpStatus: diag.http_status, endpoint: diag.endpoint,
    errorClass: diag.error_class, error: diag.error_message,
    read: diag.read_count, inserted: diag.inserted_count, skipped: diag.skipped_count } : null;
  const zoho = await ZohoClient.cachedForConnection(mailbox.connection_id).catch(() => null);
  out.tokenEvidence = zoho && zoho.lastTokenEvidence ? zoho.lastTokenEvidence : null;
  return out;
}

async function main() {
  const address = (process.argv[2] || '').toLowerCase();
  if (!address || address.startsWith('--')) fail('usage: zoho-path-diagnose.js <mailbox-address> [--repeat N] [--skip-b] [--wait-sec N (default 300)]');
  const repIdx = process.argv.indexOf('--repeat');
  const repeats = repIdx > -1 ? Math.max(1, Number(process.argv[repIdx + 1]) || 1) : 1;
  const skipB = process.argv.includes('--skip-b');
  const waitIdx = process.argv.indexOf('--wait-sec');
  const waitSec = waitIdx > -1 ? Math.max(0, Number(process.argv[waitIdx + 1]) || 0) : 300;

  const mailbox = await one('SELECT * FROM mailboxes WHERE lower(address) = $1', [address]);
  if (!mailbox) fail('mailbox not found: ' + address);
  if (mailbox.strategy !== 'mail_api') fail(`mailbox strategy is ${mailbox.strategy} — no live path to diagnose`);

  const runs = [];
  for (let i = 1; i <= repeats; i++) {
    const a = await testA(mailbox);
    const b = skipB ? null : await testB(mailbox, waitSec);
    runs.push({ attempt: i, at: new Date().toISOString(), testA: a, testB: b });
    const aTag = `${a.classification}${a.result.ok ? ` (${a.result.folders} folders)` : ''}`;
    console.log(`attempt ${i}/${repeats}: A=${aTag}` + (b ? `  B=${b.classification}` : ''));
  }

  // comparison of the last attempt (full JSON below carries all attempts)
  const last = runs[runs.length - 1];
  const cmp = {
    tokenFingerprint: { A: last.testA.tokenEvidence && last.testA.tokenEvidence.fingerprint,
      B: last.testB && last.testB.tokenEvidence && last.testB.tokenEvidence.fingerprint },
    tokenSource: { A: last.testA.tokenEvidence && last.testA.tokenEvidence.source,
      B: last.testB && last.testB.tokenEvidence && last.testB.tokenEvidence.source },
    tokenExpiresAt: { A: last.testA.tokenEvidence && last.testA.tokenEvidence.expiresAt,
      B: last.testB && last.testB.tokenEvidence && last.testB.tokenEvidence.expiresAt },
    accountId: last.testA.accountId,
    dataCenterHost: last.testA.dataCenterHost,
    classification: { A: last.testA.classification, B: last.testB ? last.testB.classification : 'skipped' },
  };

  const aOk = last.testA.classification === 'ok';
  const bPass = (b) => !b || b.classification === 'ok' || b.classification === 'live_worker_active';
  const bOk = bPass(last.testB);
  const failures = runs.filter(r => r.testA.classification !== 'ok' || !bPass(r.testB));
  const attached = runs.filter(r => r.testB && r.testB.classification === 'live_worker_active').length;
  let interpretation;
  if (!aOk) interpretation = `TEST A FAILED (${last.testA.classification}) — the defect is in OAuth acquisition / persisted token state / scopes / account id / data-center selection. Fix per the classification above; Live Sync is NOT the culprit.`;
  else if (!bOk) interpretation = `TEST A PASSED but TEST B FAILED (${last.testB.classification}) — the defect is inside the Live Sync wrapper (lifecycle/concurrency/error mapping). See persistedDiagnostics.`;
  else if (failures.length) interpretation = `INTERMITTENT: ${failures.length}/${runs.length} attempts failed — every classified failure is preserved below; do NOT call it fixed on one success.`;
  else if (attached === runs.length && attached > 0) interpretation = `LIVE WORKER OWNS THE MAILBOX (all ${attached} attempts): the REAL Live Sync path is executing right now — advancing cursor + fresh lease are the proof (see result.job). This is healthy during backfill; rerun after it completes (or raise --wait-sec) for a direct-execution traceId.`;
  else interpretation = `BOTH PASS (${runs.length}×) — the earlier HTTP 0 came from stale code (pre-instrumentation), stale token state, or a transient failure that no longer reproduces. Re-run livesync-doctor; keep --repeat monitoring before trusting.`;

  console.log('\n=== interpretation ===\n' + interpretation);
  console.log('\n=== comparison (last attempt) ===\n' + JSON.stringify(cmp, null, 2));
  console.log('\n=== full sanitized evidence ===\n' + JSON.stringify({ mailbox: mailbox.address, repeats, runs }, null, 2));
  await closeDb();
  process.exit(aOk && bOk && !failures.length ? 0 : 1);
}

main().catch(async e => { console.error('diagnose failed:', e && e.stack || e); try { await closeDb(); } catch {} process.exit(2); });
