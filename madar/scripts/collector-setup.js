#!/usr/bin/env node
// Collector-mailbox go-live in two phases — compresses the operator's part to
// one consent click in the browser profile that holds the collector's Zoho
// session (no Madar session needed there: the callback is state-guarded).
//
//   PHASE 1 — mint the connection + authorize URL:
//     docker compose exec app node scripts/collector-setup.js init
//   → prints ONE URL. Open it in the collector profile, approve. That's the
//     only human step.
//
//   PHASE 2 — after approving:
//     docker compose exec app node scripts/collector-setup.js finish --address madar.capture@exoticcolors.org
//   → waits for the connection to turn connected, runs discovery, registers
//     the collector mailbox, enables pilot+sync, runs one realtime cycle, and
//     prints the readiness verdict.
//
// Credentials are CLONED from the existing connected connection inside the
// database (client_secret stays encrypted — nothing is printed or decrypted
// here). Idempotent: re-running init reuses a pending 'Madar Capture'
// connection; finish can run any number of times.
require('../core/bootstrap').initCryptoFromEnv();
const { one, all, q, closeDb } = require('../core/db');
const { randomToken, sha256 } = require('../core/crypto');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}
const LABEL = 'Madar Capture';

async function init() {
  const src = await one(`SELECT * FROM connections WHERE status='connected' ORDER BY id LIMIT 1`);
  if (!src) { console.error('no connected source connection to clone credentials from'); process.exit(1); }
  let conn = await one(`SELECT id, status FROM connections WHERE label=$1 ORDER BY id DESC LIMIT 1`, [LABEL]);
  if (conn && conn.status === 'connected') {
    console.log(`connection ${conn.id} ("${LABEL}") is ALREADY connected — go straight to: collector-setup.js finish`);
    return;
  }
  if (!conn) {
    conn = await one(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
        client_secret_enc, scopes, created_by, encryption_key_version, status)
      SELECT provider, $2, accounts_base, api_base, client_id, client_secret_enc, scopes, created_by,
        encryption_key_version, 'pending' FROM connections WHERE id=$1 RETURNING id, status`, [src.id, LABEL]);
    console.log(`created connection ${conn.id} ("${LABEL}") — credentials cloned encrypted from connection ${src.id}`);
  } else {
    console.log(`reusing pending connection ${conn.id} ("${LABEL}")`);
  }
  const { ZohoClient } = require('../modules/mail/zoho-client');
  const zoho = await ZohoClient.forConnection(Number(conn.id));
  const state = randomToken();
  await q(`INSERT INTO oauth_states (state_hash, connection_id, created_by, expires_at)
           VALUES ($1,$2,NULL,$3)`, [sha256(Buffer.from(state)), conn.id, new Date(Date.now() + 10 * 60 * 1000)]);
  const redirect = (process.env.BASE_URL || 'http://localhost:3000') + '/oauth/callback';
  console.log('\nACTION (the only human step):');
  console.log('open this URL in the browser profile where the COLLECTOR account is signed in, and approve:');
  console.log('\n' + zoho.authorizeUrl(redirect) + '&state=' + state + '\n');
  console.log('(valid 10 minutes, single use — no Madar login needed in that profile)');
  console.log('then run:  docker compose exec app node scripts/collector-setup.js finish --address <collector-address>');
}

async function finish() {
  const address = String(arg('--address', '')).toLowerCase();
  if (!address) { console.error('--address <collector-address> is required'); process.exit(2); }
  const waitSec = Number(arg('--wait-sec', 300)) || 300;
  const deadline = Date.now() + waitSec * 1000;
  let conn = null;
  while (Date.now() < deadline) {
    conn = await one(`SELECT id, status FROM connections WHERE label=$1 ORDER BY id DESC LIMIT 1`, [LABEL]);
    if (conn && conn.status === 'connected') break;
    console.log(`[wait] connection "${LABEL}" is ${conn ? conn.status : 'missing'} — approve the authorize URL, checking again in 10s...`);
    await new Promise(r => setTimeout(r, 10000));
  }
  if (!conn || conn.status !== 'connected') {
    console.error(`connection never turned connected within ${waitSec}s — re-run init for a fresh URL`); process.exit(1);
  }

  console.log(`[discover] running discovery on connection ${conn.id}...`);
  const { ZohoClient } = require('../modules/mail/zoho-client');
  const detection = require('../modules/mail/detection');
  const zoho = await ZohoClient.cachedForConnection(conn.id);
  const discovery = await detection.discoverOrganization(zoho);
  let registered = 0, errors = 0;
  for (const mb of discovery.mailboxes) {
    try {
      const caps = await detection.probeCapabilities(zoho, mb);
      const choice = detection.chooseStrategy(mb, caps);
      await detection.upsertMailbox(conn.id, mb, caps, choice);
      registered++;
    } catch { errors++; }
  }
  console.log(`[discover] ${registered} mailbox(es) registered/updated (${errors} contained error(s))`);

  const box = await one('SELECT * FROM mailboxes WHERE lower(address)=$1', [address]);
  if (!box) { console.error(`collector mailbox ${address} not found after discovery — check the address / the approved account`); process.exit(1); }
  const caps = typeof box.capabilities === 'string' ? JSON.parse(box.capabilities || '{}') : (box.capabilities || {});
  if (box.strategy !== 'mail_api' || !caps.workingId) {
    console.error(`collector mailbox found but NOT live-readable (strategy=${box.strategy}) — the approved Zoho session was probably not the collector account`); process.exit(1);
  }
  await q('UPDATE mailboxes SET is_pilot=TRUE, sync_enabled=TRUE WHERE id=$1', [box.id]);

  console.log('[sync] first realtime cycle...');
  const sync = require('../modules/mail/sync');
  let firstCycle = null;
  try { firstCycle = await sync.syncMailbox(Number(box.id), { mode: 'full', maxPages: 2 }); }
  catch (e) { firstCycle = { error: e.message, traceId: e.traceId || null }; }

  const collectorEnv = String(process.env.MADAR_COLLECTOR_ADDRESSES || '').toLowerCase();
  const warnings = [];
  if (!collectorEnv.split(',').map(s => s.trim()).includes(address)) {
    warnings.push(`MADAR_COLLECTOR_ADDRESSES does not include ${address} — envelope (Delivered-To) routing fallback is OFF until you add it to .env and rebuild`);
  }
  const hb = await one('SELECT enabled, updated_at FROM sync_worker_heartbeat WHERE id=TRUE');
  const out = {
    connectionId: Number(conn.id), mailboxId: Number(box.id), address,
    liveReadable: true, workingId: caps.workingId,
    firstCycle, warnings,
    worker: { enabled: Boolean(hb && hb.enabled),
      heartbeatAgeSec: hb ? Math.round((Date.now() - new Date(hb.updated_at)) / 1000) : null },
    verdict: firstCycle && !firstCycle.error
      ? 'COLLECTOR LIVE — the worker now owns it every tick; next: group memberships in Zoho Admin, then the ai@ pilot e2e-proof.'
      : 'connection + registration OK, but the first cycle errored — run livesync-doctor.js / job-inspect.js with the trace above.',
  };
  console.log('\n' + JSON.stringify(out, null, 2));
}

// PHASE 3 (optional, owner decision): folder organization inside the collector
// needs WRITE scopes — on the COLLECTOR connection ONLY (the admin connection
// stays read-only). This mints a re-consent URL showing the expanded scopes;
// nothing changes until the owner approves that screen.
async function grantWrite() {
  const conn = await one(`SELECT id, scopes FROM connections WHERE label=$1 ORDER BY id DESC LIMIT 1`, [LABEL]);
  if (!conn) { console.error('no "Madar Capture" connection — run init first'); process.exit(1); }
  const WRITE_SCOPES = ['ZohoMail.folders.ALL', 'ZohoMail.messages.ALL'];
  const scopes = [...new Set(String(conn.scopes || '').split(',').map(s => s.trim()).filter(Boolean)
    .concat(WRITE_SCOPES))].join(',');
  await q('UPDATE connections SET scopes=$2 WHERE id=$1', [conn.id, scopes]);
  const { ZohoClient } = require('../modules/mail/zoho-client');
  const zoho = await ZohoClient.forConnection(Number(conn.id));
  const state = randomToken();
  await q(`INSERT INTO oauth_states (state_hash, connection_id, created_by, expires_at)
           VALUES ($1,$2,NULL,$3)`, [sha256(Buffer.from(state)), conn.id, new Date(Date.now() + 10 * 60 * 1000)]);
  const redirect = (process.env.BASE_URL || 'http://localhost:3000') + '/oauth/callback';
  console.log('write scopes staged on the COLLECTOR connection only (admin connection untouched).');
  console.log('ACTION: approve the expanded consent in the collector browser profile:');
  console.log('\n' + zoho.authorizeUrl(redirect) + '&state=' + state + '\n');
  console.log('after approving, the organizer starts moving processed mail on the next worker tick.');
  console.log('If the write surface is rejected by the tenant, it is capability-recorded and');
  console.log('ingestion continues unchanged (organization deferred, reported in live-sync status).');
}

(async () => {
  const cmd = process.argv[2];
  if (cmd === 'init') await init();
  else if (cmd === 'finish') await finish();
  else if (cmd === 'grant-write') await grantWrite();
  else { console.error('usage: collector-setup.js init | finish --address <collector-address> [--wait-sec N] | grant-write'); process.exit(2); }
  await closeDb();
  process.exit(0);
})().catch(async e => { console.error('collector-setup failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
