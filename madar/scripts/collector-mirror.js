#!/usr/bin/env node
// "Mirrors" — make the collector address a member of every shared Zoho group,
// so each group's mail gets a mirrored copy delivered into the collector.
//
//   plan (default, READ-ONLY):
//     docker compose exec app node scripts/collector-mirror.js plan
//   → live membership matrix per shared group: already_mirrored / missing /
//     unreadable. No writes, ever.
//
//   grant (one consent, owner-approved):
//     docker compose exec app node scripts/collector-mirror.js grant
//   → clones the admin connection's credentials (encrypted, nothing printed)
//     into a dedicated 'Madar Groups Admin' connection whose scope is the
//     GROUPS scope alone, and prints ONE authorize URL. Approve it in the
//     browser profile where the ORG ADMIN is signed in. The existing admin
//     connection is never upgraded — it stays read-only.
//
//   apply [--only a@x,b@y]:
//     docker compose exec app node scripts/collector-mirror.js apply
//   → add-only membership writes through the dedicated connection, each one
//     verified by a live re-read and audited. A group's rejection is
//     classified and reported; the rest still apply. Idempotent.
//
// Membership is necessary but NOT sufficient for delivery — group settings
// decide whether members receive copies. The authoritative proof remains the
// e2e capture probe (scripts/e2e-proof.js) per group.
require('../core/bootstrap').initCryptoFromEnv();
const { one, q, closeDb } = require('../core/db');
const { randomToken, sha256 } = require('../core/crypto');
const mirror = require('../modules/mail/mirror');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

async function plan() {
  const p = await mirror.planMirror();
  console.log(JSON.stringify(p, null, 2));
  const missing = p.groups.filter(g => g.state === 'missing').length;
  const unreadable = p.groups.filter(g => g.state === 'unreadable').length;
  console.log(`\n${p.groups.length} shared group(s): ${p.groups.length - missing - unreadable} already mirrored, ${missing} missing, ${unreadable} unreadable`);
  if (missing) console.log('next: collector-mirror.js grant (once), then collector-mirror.js apply');
}

async function grant() {
  const src = await one(`SELECT id FROM connections WHERE status='connected'
    AND label NOT IN ('Madar Capture', $1) ORDER BY id LIMIT 1`, [mirror.GROUPS_ADMIN_LABEL]);
  if (!src) { console.error('no connected admin connection to clone credentials from'); process.exit(1); }
  let conn = await one(`SELECT id, status FROM connections WHERE label=$1 ORDER BY id DESC LIMIT 1`, [mirror.GROUPS_ADMIN_LABEL]);
  if (conn && conn.status === 'connected') {
    console.log(`connection ${conn.id} ("${mirror.GROUPS_ADMIN_LABEL}") is ALREADY connected — go straight to: collector-mirror.js apply`);
    return;
  }
  if (!conn) {
    conn = await one(`INSERT INTO connections (provider, label, accounts_base, api_base, client_id,
        client_secret_enc, scopes, created_by, encryption_key_version, status)
      SELECT provider, $2, accounts_base, api_base, client_id, client_secret_enc, $3, created_by,
        encryption_key_version, 'pending' FROM connections WHERE id=$1 RETURNING id, status`,
      [src.id, mirror.GROUPS_ADMIN_LABEL, mirror.GROUPS_WRITE_SCOPE]);
    console.log(`created connection ${conn.id} ("${mirror.GROUPS_ADMIN_LABEL}") — credentials cloned encrypted from connection ${src.id}; scope: ${mirror.GROUPS_WRITE_SCOPE} ONLY`);
  } else {
    await q('UPDATE connections SET scopes=$2 WHERE id=$1', [conn.id, mirror.GROUPS_WRITE_SCOPE]);
    console.log(`reusing pending connection ${conn.id} ("${mirror.GROUPS_ADMIN_LABEL}")`);
  }
  const { ZohoClient } = require('../modules/mail/zoho-client');
  const zoho = await ZohoClient.forConnection(Number(conn.id));
  const state = randomToken();
  await q(`INSERT INTO oauth_states (state_hash, connection_id, created_by, expires_at)
           VALUES ($1,$2,NULL,$3)`, [sha256(Buffer.from(state)), conn.id, new Date(Date.now() + 10 * 60 * 1000)]);
  const redirect = (process.env.BASE_URL || 'http://localhost:3000') + '/oauth/callback';
  console.log('\nACTION (the only human step):');
  console.log('open this URL in the browser profile where the ORG ADMIN is signed in, and approve:');
  console.log('\n' + zoho.authorizeUrl(redirect) + '&state=' + state + '\n');
  console.log('(valid 10 minutes, single use — the admin read connection is untouched)');
  console.log('then run:  docker compose exec app node scripts/collector-mirror.js apply');
}

async function apply() {
  const onlyArg = arg('--only');
  const only = onlyArg && onlyArg !== true
    ? String(onlyArg).toLowerCase().split(',').map(s => s.trim()).filter(Boolean) : null;
  const res = await mirror.applyMirror({ only });
  console.log(JSON.stringify(res, null, 2));
  const bad = res.applied.filter(r => r.verdict !== 'mirrored');
  console.log(`\n${res.applied.length} write(s): ${res.applied.length - bad.length} mirrored, ${bad.length} not confirmed`);
  console.log('delivery proof per group: scripts/e2e-proof.js (membership alone is not delivery)');
}

(async () => {
  const cmd = process.argv[2] || 'plan';
  if (cmd === 'plan') await plan();
  else if (cmd === 'grant') await grant();
  else if (cmd === 'apply') await apply();
  else { console.error('usage: collector-mirror.js [plan] | grant | apply [--only a@x,b@y]'); process.exit(2); }
  await closeDb();
  process.exit(0);
})().catch(async e => { console.error('collector-mirror failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
