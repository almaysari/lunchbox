// Mail module REST API (PostgreSQL, canonical-message model, RBAC).
//
// Direct-resource privacy policy (anti-enumeration): a user without
// permission on a specific resource ID (mailbox / canonical / occurrence /
// attachment / detection report) receives 404 — indistinguishable from a
// nonexistent ID. Role-gated ADMIN endpoints return 403 (the endpoint's
// existence is public knowledge, no resource ID is probed).
const fs = require('fs');
const path = require('path');
const { q, one, all } = require('../../core/db');
const { encrypt, sha256, randomToken } = require('../../core/crypto');
const { getStorage } = require('../../core/storage');
const { audit } = require('../../core/audit');
const auth = require('../../core/auth');
const { ZohoClient, READ_SCOPES } = require('./zoho-client');
const detection = require('./detection');
const { syncMailbox, importArchiveRecorded, setJobControl } = require('./sync');

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

// Expected-mailboxes baseline: validation reference ONLY (never a data source).
function loadBaseline() {
  for (const p of [
    path.join(__dirname, '..', '..', 'data', 'expected-mailboxes.json'),
    path.join(__dirname, '..', '..', 'test', 'fixtures', 'expected-mailboxes.json'),
  ]) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { /* next */ }
  }
  return [];
}

const jsonCol = v => typeof v === 'string' ? JSON.parse(v || 'null') : (v ?? null);

function diagRow(r) {
  return {
    traceId: r.trace_id, mailboxId: r.mailbox_id ? Number(r.mailbox_id) : null, mailbox: r.mailbox_address,
    stage: r.stage, endpoint: r.endpoint, httpStatus: r.http_status,
    responseSample: jsonCol(r.response_sample),
    read: r.read_count, inserted: r.inserted_count, skipped: r.skipped_count, routed: r.routed_count,
    outcome: r.outcome,
    error: r.outcome === 'error' ? {
      class: r.error_class, message: r.error_message, stack: r.error_stack,
      sqlState: r.sql_state, constraint: r.constraint_name, routing: jsonCol(r.routing_context),
    } : null,
    at: new Date(r.created_at).getTime(),
  };
}

async function mailboxRow(m) {
  return {
    id: Number(m.id), address: m.address, displayName: m.display_name, provider: m.provider,
    connectionId: m.connection_id && Number(m.connection_id), detectedType: m.detected_type, strategy: m.strategy,
    accessLevel: m.access_level, moderationCount: m.moderation_count,
    members: jsonCol(m.members) || [], moderators: jsonCol(m.moderators) || [],
    capabilities: jsonCol(m.capabilities) || {},
    isPilot: Boolean(m.is_pilot), syncEnabled: Boolean(m.sync_enabled),
    status: m.status, statusDetail: m.status_detail,
    providerAccountId: m.provider_account_id, providerGroupId: m.provider_group_id,
    aliases: (await all('SELECT address FROM mailbox_aliases WHERE mailbox_id = $1', [m.id])).map(r => r.address),
  };
}

async function handle(req, res, url, user, body, helpers) {
  const { send } = helpers;
  const p = url.pathname;
  let m;
  const requireMailAdmin = () => {
    if (auth.isMailAdmin(user)) return true;
    send(403, { error: 'mail admin role required' });
    return false;
  };
  const requireSecurityAdmin = () => {
    if (auth.isSecurityAdmin(user)) return true;
    send(403, { error: 'security admin role required' });
    return false;
  };

  // ---------- connections (organization-owned) ----------
  if (p === '/api/mail/connections' && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    return send(200, await all(`SELECT id, provider, label, accounts_base, api_base, client_id, scopes, status,
      status_detail, created_at, encryption_key_version, (refresh_token_enc IS NOT NULL) AS authorized
      FROM connections ORDER BY id`));
  }
  if (p === '/api/mail/connections' && req.method === 'POST') {
    if (!requireSecurityAdmin()) return true;
    const { label, client_id, client_secret, accounts_base, api_base } = body;
    if (!client_id || !client_secret) return send(400, { error: 'client_id and client_secret are required' });
    const { currentKeyVersion } = require('../../core/crypto');
    const r = await one(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
      client_secret_enc, scopes, created_by, encryption_key_version)
      VALUES ('zoho',$1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [label || 'Zoho Organization', accounts_base || 'https://accounts.zoho.com', api_base || 'https://mail.zoho.com',
        client_id, encrypt(client_secret), READ_SCOPES, user.id, currentKeyVersion()]);
    await audit(user.id, 'mail.connection.create', label || client_id);
    return send(200, { id: Number(r.id) });
  }

  // ---------- OAuth: state is random, hashed at rest, one-time, expiring ----------
  if ((m = p.match(/^\/api\/mail\/connections\/(\d+)\/authorize-url$/)) && req.method === 'GET') {
    if (!requireSecurityAdmin()) return true;
    const zoho = await ZohoClient.forConnection(Number(m[1]));
    const state = randomToken();
    await q('INSERT INTO oauth_states (state_hash, connection_id, created_by, expires_at) VALUES ($1,$2,$3,$4)',
      [sha256(Buffer.from(state)), Number(m[1]), user.id, new Date(Date.now() + OAUTH_STATE_TTL_MS)]);
    const redirect = helpers.baseUrl + '/oauth/callback';
    return send(200, { url: zoho.authorizeUrl(redirect) + '&state=' + state, redirectUri: redirect });
  }
  if (p === '/oauth/callback' && req.method === 'GET') {
    const code = url.searchParams.get('code');   // never logged, never stored
    const state = url.searchParams.get('state') || '';
    if (!code || !state) return send(400, 'Missing code/state', 'text/plain');
    // one-time consumption: only an unused, unexpired state row matches
    const row = await one(`UPDATE oauth_states SET used_at = now()
      WHERE state_hash = $1 AND used_at IS NULL AND expires_at > now()
      RETURNING connection_id`, [sha256(Buffer.from(state))]);
    if (!row) {
      await audit(user && user.id, 'mail.oauth.state_rejected', 'invalid/expired/reused state');
      return send(403, 'Invalid, expired or already-used OAuth state', 'text/plain');
    }
    const zoho = await ZohoClient.forConnection(Number(row.connection_id));
    await zoho.exchangeCode(code, helpers.baseUrl + '/oauth/callback');
    await audit(user && user.id, 'mail.connection.authorized', 'connection:' + row.connection_id);
    res.writeHead(302, { Location: '/?connected=1' });
    res.end();
    return true;
  }

  // ---------- organization-wide discovery ----------
  if (p === '/api/mail/discover' && req.method === 'POST') {
    if (!requireMailAdmin()) return true;
    const connId = Number(body.connection_id);
    const zoho = await ZohoClient.forConnection(connId);
    const discovery = await detection.discoverOrganization(zoho);
    const results = [];
    for (const mb of discovery.mailboxes) {
      const caps = await detection.probeCapabilities(zoho, mb);
      const choice = detection.chooseStrategy(mb, caps);
      const id = await detection.upsertMailbox(connId, mb, caps, choice);
      results.push({ id, address: mb.address, detectedType: mb.detectedType, strategy: choice.strategy, status: choice.status });
    }
    const baseline = loadBaseline();
    const comparison = detection.compareWithBaseline(
      discovery.mailboxes.filter(x => x.detectedType === 'shared_mailbox'),
      baseline.filter(b => (b.type || 'shared_mailbox') === 'shared_mailbox'));
    // record WHICH Zoho account authorized this connection (admin verification)
    const authorizedAs = (((discovery.evidence.accounts || {}).body || {}).data || [])
      .map(a => a.mailboxAddress || a.primaryEmailAddress).filter(Boolean).join(', ');
    if (authorizedAs) await q('UPDATE connections SET status_detail = $1 WHERE id = $2', ['authorized as: ' + authorizedAs, connId]);
    await q('INSERT INTO detection_reports (mailbox_id, report) VALUES (0, $1)',
      [JSON.stringify({ scope: 'organization', evidence: discovery.evidence, comparison, integrity: discovery.integrity, authorizedAs })]);
    await audit(user.id, 'mail.discover', 'connection:' + connId, comparison);
    return send(200, { results, comparison, integrity: discovery.integrity, authorizedAs, evidence: discovery.evidence });
  }
  if (p === '/api/mail/discovery-status' && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    const last = await one('SELECT * FROM detection_reports WHERE mailbox_id = 0 ORDER BY id DESC LIMIT 1');
    return send(200, last ? { at: new Date(last.at).getTime(), ...jsonCol(last.report) } : { comparison: null });
  }
  // Per-endpoint access matrix, compiled from the STORED probe evidence of the
  // latest detection report per mailbox. No Zoho call is made here.
  if (p === '/api/mail/discovery/endpoint-matrix' && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    const boxes = await all('SELECT id, address, detected_type FROM mailboxes ORDER BY address');
    const reportRows = [];
    for (const b of boxes) {
      const rep = await one('SELECT at, report FROM detection_reports WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1', [b.id]);
      if (rep) reportRows.push({ address: b.address, detectedType: b.detected_type, at: new Date(rep.at).getTime(), report: jsonCol(rep.report) });
    }
    const matrix = detection.endpointMatrix(reportRows);
    return send(200, { ...matrix, mailboxesCovered: reportRows.length, reportDates: reportRows.map(r => r.at) });
  }

  // ---------- mailboxes ----------
  if (p === '/api/mail/mailboxes' && req.method === 'GET') {
    const ids = new Set(await auth.readableMailboxIds(user));
    const rows = (await all('SELECT * FROM mailboxes ORDER BY address')).filter(r => auth.isMailAdmin(user) || ids.has(Number(r.id)));
    return send(200, await Promise.all(rows.map(mailboxRow)));
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)$/)) && req.method === 'GET') {
    const row = await one('SELECT * FROM mailboxes WHERE id = $1', [Number(m[1])]);
    if (!row) return send(404, { error: 'not found' });
    // metadata + evidence: admin roles OR granted users; others get 404 (anti-enumeration)
    if (!auth.isMailAdmin(user) && !(await auth.canReadMailbox(user, Number(row.id)))) return send(404, { error: 'not found' });
    const report = await one('SELECT at, report FROM detection_reports WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 1', [row.id]);
    return send(200, {
      ...(await mailboxRow(row)),
      lastDetection: report ? { at: new Date(report.at).getTime(), ...jsonCol(report.report) } : null,
    });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/pilot$/)) && req.method === 'POST') {
    if (!requireMailAdmin()) return true;
    await q('UPDATE mailboxes SET is_pilot = $1 WHERE id = $2', [Boolean(body.on), Number(m[1])]);
    await audit(user.id, 'mail.pilot.' + (body.on ? 'on' : 'off'), 'mailbox:' + m[1]);
    return send(200, { ok: true });
  }

  // ---------- live sync monitoring ----------
  if (p === '/api/mail/live-sync/status' && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    return send(200, await require('./live-sync').liveStatus());
  }
  if (p === '/api/mail/live-sync/tick' && req.method === 'POST') {
    if (!requireMailAdmin()) return true; // manual "sync now" across all enabled mailboxes
    const r = await require('./live-sync').tickOnce();
    await audit(user.id, 'mail.livesync.manual_tick', '', r);
    return send(200, r);
  }
  // Diagnostics: last cycle per mailbox with full typed context (stage,
  // endpoint, HTTP/SQL/routing, complete stack). Optional ?mailbox_id / ?trace_id.
  if (p === '/api/mail/diagnostics' && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    const traceId = url.searchParams.get('trace_id');
    if (traceId) {
      const row = await one('SELECT * FROM sync_diagnostics WHERE trace_id = $1 ORDER BY id DESC LIMIT 1', [traceId]);
      return send(200, row ? diagRow(row) : { error: 'trace not found' });
    }
    const mid = Number(url.searchParams.get('mailbox_id')) || null;
    const latest = await all(`SELECT DISTINCT ON (mailbox_id) * FROM sync_diagnostics
      ${mid ? 'WHERE mailbox_id = $1' : ''} ORDER BY mailbox_id, id DESC`, mid ? [mid] : []);
    const recentErrors = await all(`SELECT * FROM sync_diagnostics WHERE outcome = 'error'
      ${mid ? 'AND mailbox_id = $1' : ''} ORDER BY id DESC LIMIT 20`, mid ? [mid] : []);
    return send(200, { latestByMailbox: latest.map(diagRow), recentErrors: recentErrors.map(diagRow) });
  }

  // ---------- "why don't I see mail for this mailbox?" — 7-point trace ----------
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/visibility-trace$/)) && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    const id = Number(m[1]);
    const mb = await one('SELECT * FROM mailboxes WHERE id=$1', [id]);
    if (!mb) return send(404, { error: 'not found' });
    // Worker status from the shared DB heartbeat — NOT this process's singleton.
    // (The old ._state read wrongly said "OFF" whenever the reader ran in a
    // different process than the worker, e.g. the CLI doctor.)
    const ws = await require('./live-sync').workerStatus();
    const lastDiag = await one(`SELECT * FROM sync_diagnostics WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1`, [id]);
    const lastJob = await one(`SELECT id, status, error_detail, started_at, finished_at, discovered, imported, skipped FROM sync_jobs WHERE mailbox_id=$1 ORDER BY id DESC LIMIT 1`, [id]);
    const cursors = await all(`SELECT ss.folder_id, f.name, ss.backfill_done, ss.next_start, ss.last_sync_at, ss.last_error
      FROM sync_state ss LEFT JOIN folders f ON f.id=ss.folder_id WHERE ss.mailbox_id=$1`, [id]);
    const occTotal = await one('SELECT COUNT(*)::int n FROM message_occurrences WHERE mailbox_id=$1', [id]);
    const occ24 = await one(`SELECT COUNT(*)::int n FROM message_occurrences WHERE mailbox_id=$1 AND created_at > now() - interval '24 hours'`, [id]);
    const dup = await one(`SELECT COUNT(*)::int n FROM fingerprint_metrics WHERE mailbox_id=$1 AND event_type='duplicate_prevented'`, [id]);
    const myGrant = await one(`SELECT can_view_messages FROM mailbox_grants WHERE user_id=$1 AND mailbox_id=$2`, [user.id, id]);
    const anyReaders = await one(`SELECT COUNT(*)::int n FROM mailbox_grants WHERE mailbox_id=$1 AND can_view_messages`, [id]);
    const inMyReadable = (await auth.readableMailboxIds(user)).includes(id);

    const checks = {
      '1_worker_running': { ok: ws.running, enabled: ws.enabled, running: ws.running, stale: ws.stale,
        source: ws.source, pid: ws.pid, hostname: ws.hostname, intervalSec: ws.intervalSec,
        lastTickAt: ws.lastTickAt, nextTickAt: ws.nextTickAt, ageSec: ws.ageSec, reason: ws.reason || null },
      '2_recent_cycle': { ok: Boolean(lastDiag), lastCycleAt: lastDiag ? new Date(lastDiag.created_at).getTime() : null,
        lastJobStatus: lastJob ? lastJob.status : null },
      '3_fetched_from_zoho': { ok: Boolean(lastDiag && lastDiag.read_count > 0), read: lastDiag ? lastDiag.read_count : 0,
        lastEndpoint: lastDiag ? lastDiag.endpoint : null, httpStatus: lastDiag ? lastDiag.http_status : null },
      '4_inserted_or_cursor_dedup': { inserted: lastDiag ? lastDiag.inserted_count : 0, skipped: lastDiag ? lastDiag.skipped_count : 0,
        duplicatesPrevented: dup.n, cursors: cursors.map(c => ({ folder: c.name, backfillDone: c.backfill_done,
          nextStart: c.next_start, lastSyncAt: c.last_sync_at ? new Date(c.last_sync_at).getTime() : null, lastError: c.last_error })) },
      '5_stored_but_hidden': { storedInDb: occTotal.n, storedLast24h: occ24.n,
        youHaveReadGrant: Boolean(myGrant && myGrant.can_view_messages), mailboxInYourReadableSet: inMyReadable,
        anyReadersGranted: anyReaders.n,
        hiddenByGrant: occTotal.n > 0 && !inMyReadable },
      '6_status_syncing': { status: mb.status, statusDetail: mb.status_detail, stuck: mb.status === 'syncing' },
      '7_last_diagnostics': lastDiag ? {
        traceId: lastDiag.trace_id, stage: lastDiag.stage, outcome: lastDiag.outcome,
        read: lastDiag.read_count, inserted: lastDiag.inserted_count, skipped: lastDiag.skipped_count, routed: lastDiag.routed_count,
        error: lastDiag.outcome === 'error' ? { class: lastDiag.error_class, message: lastDiag.error_message,
          stack: lastDiag.error_stack, sqlState: lastDiag.sql_state, constraint: lastDiag.constraint_name } : null,
      } : null,
    };

    // decisive verdict — the FIRST failing gate, in causal order
    let verdict;
    if (mb.strategy !== 'mail_api') verdict = 'هذا الصندوق ليس مسار قراءة حية (strategy≠mail_api) — بريده يأتي عبر التوجيه أو الأرشيف فقط.';
    else if (!mb.is_pilot || !mb.sync_enabled) verdict = 'المزامنة غير مفعّلة: فعّل Pilot ثم اضغط «بدء Pilot Sync» — الـworker لا يلمس صندوقًا لم يُفعّل صراحةً.';
    // A grant block on ALREADY-stored mail is decisive and masks every worker/cycle
    // gate below it: no amount of worker-running reveals mail you can't read. So if
    // messages exist in the DB but aren't in your readable set, that IS the reason.
    else if (occTotal.n > 0 && !inMyReadable) verdict = `الرسائل محفوظة (${occTotal.n} في القاعدة) لكنها محجوبة عنك: لا تملك صلاحية can_view_messages على هذا الصندوق. امنح نفسك (أو القارئ المقصود) القراءة من «المستخدمون والصلاحيات» — سياسة الخصوصية تمنع الأدمن من قراءة المحتوى دون منح صريح.`;
    else if (!ws.running) verdict = ws.stale
      ? `عامل المزامنة الحية غير مستجيب: آخر نبضة قبل ${ws.ageSec}s (أكبر من دورتين) — العملية الرئيسية قد تكون متوقفة، أعد تشغيلها.`
      : 'عامل المزامنة الحية متوقف (MADAR_LIVE_SYNC=off أو لم يبدأ) — شغّله.';
    else if (lastDiag && lastDiag.outcome === 'error') verdict = `آخر دورة فشلت في مرحلة «${lastDiag.stage}» — افتح التشخيص (trace ${lastDiag.trace_id}).`;
    else if (mb.status === 'syncing') verdict = 'الصندوق عالق على syncing — أعد التشغيل ليُصحَّح تلقائيًا، أو استأنف Pilot.';
    else if (!lastDiag) verdict = 'لا توجد أي دورة مزامنة بعد — اضغط «مزامنة الآن» أو انتظر الدورة التالية.';
    else if (occTotal.n === 0 && lastDiag.read_count > 0) verdict = 'Zoho أعاد رسائل لكن لم تُدرَج — راجع عدّادات inserted/skipped وdedup أدناه.';
    else if (lastDiag.read_count === 0) verdict = 'المزامنة تعمل لكن Zoho لم يُعِد رسائل جديدة في آخر دورة (لا وارد جديد، أو المؤشر عند القمة).';
    else verdict = 'كل الفحوص سليمة والرسائل مرئية لك — إن كنت لا تراها في الواجهة فحدّث الصفحة أو اختر الصندوق من القائمة.';

    return send(200, { mailbox: mb.address, strategy: mb.strategy, isPilot: mb.is_pilot, syncEnabled: mb.sync_enabled,
      verdict, checks });
  }

  // ---------- canonical-identity collision metrics + fp3 validation ----------
  if (p === '/api/mail/fingerprint-metrics' && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    const counts = await all(`SELECT event_type, COUNT(*)::int n FROM fingerprint_metrics GROUP BY event_type`);
    const byType = Object.fromEntries(counts.map(r => [r.event_type, r.n]));
    const recent = await all(`SELECT event_type, fp3, rfc_incoming, rfc_existing, canonical_a, canonical_b,
      mailbox_id, detail, created_at FROM fingerprint_metrics ORDER BY id DESC LIMIT 50`);
    const tot = await one(`SELECT COUNT(*)::int canon FROM canonical_messages`);
    const occ = await one(`SELECT COUNT(*)::int occ FROM message_occurrences`);
    const dupPrevented = byType.duplicate_prevented || 0;
    const falseMerge = byType.false_merge_prevented || 0;
    const falseSplit = byType.false_split_detected || 0;
    // correlation confidence: of all cross-source links fp3 established, the
    // fraction with no forensic contradiction (no false merge/split).
    const linked = (tot.canon || 0) + falseMerge; // canonicals + prevented over-merges
    const confidence = linked ? Number((1 - (falseMerge + falseSplit) / linked).toFixed(6)) : 1;
    return send(200, {
      status: 'pending_production_archive_validation',
      canonicals: tot.canon, occurrences: occ.occ,
      metrics: { fp3_collisions: falseMerge, false_merges_prevented: falseMerge,
        false_splits_detected: falseSplit, duplicates_prevented: dupPrevented,
        time_unlinkable: byType.time_unlinkable || 0 },
      correlationConfidence: confidence,
      recent: recent.map(r => ({ ...r, created_at: new Date(r.created_at).getTime() })),
    });
  }

  // ---------- sync jobs: start / pause / resume / cancel / progress ----------
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/sync$/)) && req.method === 'POST') {
    if (!requireMailAdmin()) return true;
    await q('UPDATE mailboxes SET sync_enabled = TRUE WHERE id = $1', [Number(m[1])]);
    await audit(user.id, 'mail.pilot_sync.start', 'mailbox:' + m[1]);
    // a paused job is resumed automatically (createJob reuses it)
    try {
      return send(200, await syncMailbox(Number(m[1]), { userId: user.id }));
    } catch (err) {
      // never a bare error — return the sync-cycle trace id + stage so the
      // operator can open the full diagnostics row
      return send(422, { error: String(err.message || err), errorClass: err.name || 'Error',
        traceId: err.traceId, stage: err.stage });
    }
  }
  if ((m = p.match(/^\/api\/mail\/sync-jobs\/(\d+)\/(pause|cancel)$/)) && req.method === 'POST') {
    if (!requireMailAdmin()) return true;
    await setJobControl(Number(m[1]), m[2] === 'pause' ? 'paused' : 'cancelled', user.id);
    await audit(user.id, 'mail.sync_job.' + m[2], 'job:' + m[1]);
    return send(200, { ok: true });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/sync-jobs$/)) && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    return send(200, await all(`SELECT id, status, discovered, imported, skipped, errors, current_cursor,
      current_folder_id, error_detail, started_at, finished_at, created_at
      FROM sync_jobs WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 10`, [Number(m[1])]));
  }

  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/import-archive$/)) && req.method === 'POST') {
    if (!requireMailAdmin()) return true;
    if (!Buffer.isBuffer(body) || !body.length) return send(400, { error: 'upload the eDiscovery/Backup export ZIP as the raw request body (Content-Type: application/zip)' });
    const filename = decodeURIComponent(String(req.headers['x-file-name'] || ''));
    try {
      return send(200, await importArchiveRecorded(Number(m[1]), body, user.id, filename));
    } catch (e) {
      return send(422, { error: 'فشل استيراد الأرشيف: ' + e.message });
    }
  }
  // Org-wide intake board: every shared mailbox with its archive-import state.
  // Pending = no import yet; otherwise the latest row's status + totals.
  if (p === '/api/mail/archive-intake' && req.method === 'GET') {
    if (!requireMailAdmin()) return true;
    const boxes = await all(`SELECT id, address, display_name, detected_type, strategy FROM mailboxes
                             WHERE detected_type = 'shared_mailbox' ORDER BY address`);
    const rows = [];
    for (const b of boxes) {
      const imports = await all(
        `SELECT id, filename, size_bytes, status, totals, error_detail, created_at, finished_at
         FROM archive_imports WHERE mailbox_id = $1 ORDER BY id DESC LIMIT 5`, [b.id]);
      const agg = await one(
        `SELECT COALESCE(SUM((totals->>'imported')::int),0)::int AS imported,
                COALESCE(SUM((totals->>'attachments')::int),0)::int AS attachments,
                COUNT(*) FILTER (WHERE status = 'completed')::int AS completed_parts,
                COUNT(*) FILTER (WHERE status = 'failed')::int AS failed_parts,
                COUNT(*) FILTER (WHERE status = 'importing')::int AS importing_parts
         FROM archive_imports WHERE mailbox_id = $1`, [b.id]);
      const state = agg.importing_parts > 0 ? 'importing'
        : agg.failed_parts > 0 && agg.completed_parts === 0 ? 'failed'
        : agg.completed_parts > 0 ? 'completed' : 'pending';
      rows.push({
        mailboxId: Number(b.id), address: b.address, displayName: b.display_name,
        state, imported: agg.imported, attachments: agg.attachments,
        completedParts: agg.completed_parts, failedParts: agg.failed_parts,
        imports: imports.map(r => ({
          id: Number(r.id), filename: r.filename, sizeBytes: Number(r.size_bytes), status: r.status,
          totals: jsonCol(r.totals), error: r.error_detail || null,
          at: new Date(r.created_at).getTime(),
          finishedAt: r.finished_at ? new Date(r.finished_at).getTime() : null,
        })),
      });
    }
    const summary = {
      total: rows.length,
      completed: rows.filter(r => r.state === 'completed').length,
      importing: rows.filter(r => r.state === 'importing').length,
      failed: rows.filter(r => r.state === 'failed').length,
      pending: rows.filter(r => r.state === 'pending').length,
    };
    return send(200, { summary, mailboxes: rows });
  }
  if ((m = p.match(/^\/api\/mail\/mailboxes\/(\d+)\/folders$/)) && req.method === 'GET') {
    const id = Number(m[1]);
    if (!(await auth.canReadMailbox(user, id))) return send(404, { error: 'not found' });
    return send(200, await all('SELECT id, name, folder_type FROM folders WHERE mailbox_id = $1 ORDER BY name', [id]));
  }

  // ---------- messages: occurrences joined to canonical; permissions INSIDE the SQL ----------
  if (p === '/api/mail/messages' && req.method === 'GET') {
    const allowed = await auth.readableMailboxIds(user);
    const mailboxId = url.searchParams.get('mailbox_id') ? Number(url.searchParams.get('mailbox_id')) : null;
    // an unauthorized mailbox_id is 404 for EVERY caller — a zero-grant user
    // must get the same answer as a partially-granted one (anti-enumeration
    // consistency; the old empty-grants shortcut answered 200 [] here)
    if (mailboxId && !allowed.includes(mailboxId)) return send(404, { error: 'not found' });
    if (!allowed.length) return send(200, []);
    const folderId = url.searchParams.get('folder_id') ? Number(url.searchParams.get('folder_id')) : null;
    const qtext = (url.searchParams.get('q') || '').trim();
    const scope = mailboxId ? [mailboxId] : allowed;
    const params = [scope];
    let where = 'o.mailbox_id = ANY($1)';
    if (folderId) { params.push(folderId); where += ` AND o.folder_id = $${params.length}`; }
    if (qtext) { params.push(qtext.split(/\s+/).join(' & ')); where += ` AND c.fts @@ to_tsquery('simple', $${params.length})`; }
    const rows = await all(`SELECT o.id AS occurrence_id, o.mailbox_id, o.folder_id, o.direction, o.received_at,
        c.id AS canonical_id, c.from_address, c.from_name, c.subject, c.snippet, c.has_attachments
      FROM message_occurrences o JOIN canonical_messages c ON c.id = o.canonical_message_id
      WHERE ${where} ORDER BY o.received_at DESC LIMIT 100`, params);
    return send(200, rows.map(r => ({ ...r, received_at: new Date(r.received_at).getTime() })));
  }
  if ((m = p.match(/^\/api\/mail\/occurrences\/(\d+)$/)) && req.method === 'GET') {
    const row = await one(`SELECT o.*, c.* , o.id AS occurrence_id, c.id AS canonical_id
      FROM message_occurrences o JOIN canonical_messages c ON c.id = o.canonical_message_id WHERE o.id = $1`, [Number(m[1])]);
    if (!row) return send(404, { error: 'not found' });
    if (!(await auth.canReadMailbox(user, Number(row.mailbox_id)))) return send(404, { error: 'not found' });
    await audit(user.id, 'mail.message.read', 'occurrence:' + row.occurrence_id);
    const canSeeAtt = await auth.mailboxPermission(user, Number(row.mailbox_id), 'can_view_attachments');
    const atts = canSeeAtt
      ? await all('SELECT id, sanitized_filename AS name, size, detected_mime_type AS mime, quarantine_status FROM attachments WHERE canonical_message_id = $1', [row.canonical_id])
      : [];
    const occurrences = await all(`SELECT o2.id, o2.mailbox_id, mb.address, f.name AS folder
      FROM message_occurrences o2 JOIN mailboxes mb ON mb.id = o2.mailbox_id LEFT JOIN folders f ON f.id = o2.folder_id
      WHERE o2.canonical_message_id = $1`, [row.canonical_id]);
    return send(200, {
      occurrenceId: Number(row.occurrence_id), canonicalId: Number(row.canonical_id),
      mailboxId: Number(row.mailbox_id), direction: row.direction,
      from_address: row.from_address, from_name: row.from_name,
      // envelope privacy: recipients as THIS mailbox's copy saw them —
      // never another occurrence's envelope (BCC etc. stay per-occurrence)
      to_addresses: row.envelope_to,
      cc_addresses: row.envelope_cc,
      subject: row.subject, snippet: row.snippet, body_html: row.body_html,
      received_at: new Date(row.received_at).getTime(), attachments: atts,
      // occurrences shown only where the user can read that mailbox
      appearsIn: (await Promise.all(occurrences.map(async o =>
        (await auth.canReadMailbox(user, Number(o.mailbox_id))) ? { address: o.address, folder: o.folder } : null)))
        .filter(Boolean),
    });
  }

  // ---------- attachments: view/download split, safe headers, quarantine, Range ----------
  if ((m = p.match(/^\/api\/mail\/attachments\/(\d+)$/)) && req.method === 'GET') {
    const att = await one(`SELECT a.*, o.mailbox_id FROM attachments a
      JOIN message_occurrences o ON o.canonical_message_id = a.canonical_message_id
      WHERE a.id = $1 LIMIT 1`, [Number(m[1])]);
    if (!att) return send(404, { error: 'not found' });
    // ANY readable occurrence's mailbox grants access — but the flag must match the action.
    const occRows = await all('SELECT DISTINCT mailbox_id FROM message_occurrences WHERE canonical_message_id = $1', [att.canonical_message_id]);
    const wantDownload = url.searchParams.get('download') === '1';
    const flag = wantDownload ? 'can_download_attachments' : 'can_view_attachments';
    let permitted = false;
    for (const o of occRows) if (await auth.mailboxPermission(user, Number(o.mailbox_id), flag)) { permitted = true; break; }
    if (!permitted) return send(404, { error: 'not found' });
    if (att.quarantine_status === 'quarantined' && !auth.isSecurityAdmin(user)) {
      return send(423, { error: 'attachment quarantined (declared type does not match detected content)' });
    }
    await audit(user.id, wantDownload ? 'mail.attachment.download' : 'mail.attachment.view', 'attachment:' + att.id);
    const storage = getStorage();
    if (!storage.exists(att.storage_key)) return send(404, { error: 'file missing' });

    const headers = {
      'Content-Type': att.detected_mime_type || 'application/octet-stream', // detected, never provider-claimed
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Content-Disposition': `${wantDownload ? 'attachment' : 'inline'}; filename="${att.sanitized_filename}"`,
      'Cache-Control': 'private, no-store',
      'Accept-Ranges': 'bytes',
    };
    // Range support (PDF viewers request byte ranges)
    const range = String(req.headers.range || '').match(/^bytes=(\d+)-(\d*)$/);
    if (range) {
      const start = Number(range[1]);
      const end = range[2] ? Math.min(Number(range[2]), Number(att.size) - 1) : Number(att.size) - 1;
      if (start >= Number(att.size)) { res.writeHead(416, { 'Content-Range': `bytes */${att.size}` }); res.end(); return true; }
      res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${att.size}`, 'Content-Length': end - start + 1 });
      storage.getObject(att.storage_key, { start, end }).pipe(res);
    } else {
      res.writeHead(200, { ...headers, 'Content-Length': Number(att.size) });
      storage.getObject(att.storage_key).pipe(res);
    }
    return true;
  }

  // ---------- labels ----------
  if (p === '/api/mail/labels' && req.method === 'GET') {
    return send(200, await all('SELECT * FROM labels ORDER BY name'));
  }
  if (p === '/api/mail/labels' && req.method === 'POST') {
    if (!requireMailAdmin()) return true;
    const r = await one(`INSERT INTO labels (name, color) VALUES ($1,$2)
      ON CONFLICT (name) DO UPDATE SET color = EXCLUDED.color RETURNING id`, [body.name, body.color || '#2545d3']);
    return send(200, { id: Number(r.id) });
  }
  if ((m = p.match(/^\/api\/mail\/canonical\/(\d+)\/labels$/)) && req.method === 'POST') {
    const occ = await all('SELECT DISTINCT mailbox_id FROM message_occurrences WHERE canonical_message_id = $1', [Number(m[1])]);
    let permitted = false;
    for (const o of occ) if (await auth.mailboxPermission(user, Number(o.mailbox_id), 'can_manage_labels')) { permitted = true; break; }
    if (!permitted) return send(404, { error: 'not found' });
    if (body.add) await q('INSERT INTO message_labels (canonical_message_id, label_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [Number(m[1]), Number(body.add)]);
    if (body.remove) await q('DELETE FROM message_labels WHERE canonical_message_id = $1 AND label_id = $2', [Number(m[1]), Number(body.remove)]);
    return send(200, { ok: true });
  }

  return false; // not handled
}

module.exports = { handle };
