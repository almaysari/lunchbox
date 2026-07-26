#!/usr/bin/env node
// Shared-mailbox discovery verification — the EXACT production discovery path
// (discoverOrganization → probeCapabilities → chooseStrategy) run as a report,
// per mailbox, in the operator's required format:
//
//   finance@exoticcolors.org
//   type: shared
//   discovered: true
//   accountId: xxxx | none
//   folders: 12 | 0
//   messages_access: true/false
//   reason: <exact classified reason when unavailable>
//   capture: direct_api | routed_member_copy + archive(eDiscovery) | ...
//
// It also lists every account the token can see (own accounts + org accounts +
// groups with pagination and the zoid fallback) so "does /api/accounts return
// shared mailboxes / do they have their own accountId" is answered from THIS
// tenant's live responses, not assumptions.
//
// --persist  additionally upserts the results into the registry (identical to
//            pressing "discover" in the UI). Default is read-only reporting.
//
// Sanitized: addresses, ids, types, statuses, field names — no message content,
// no tokens.
require('../core/bootstrap').initCryptoFromEnv();
const { one, all, closeDb } = require('../core/db');
const { ZohoClient } = require('../modules/mail/zoho-client');
const detection = require('../modules/mail/detection');

async function main() {
  const persist = process.argv.includes('--persist');
  // --mailbox <address>: PILOT mode — probe exactly one mailbox (small shared
  // box first, before touching the big ones). Read-only unless --persist.
  const mbArg = process.argv.indexOf('--mailbox');
  const onlyAddress = mbArg > -1 ? String(process.argv[mbArg + 1] || '').toLowerCase() : null;
  const connArg = process.argv.indexOf('--connection');
  const conn = connArg > -1 ? await one('SELECT id FROM connections WHERE id=$1', [Number(process.argv[connArg + 1])])
    : await one(`SELECT id FROM connections WHERE status='connected' ORDER BY id LIMIT 1`);
  if (!conn) { console.error('no connected Zoho connection'); process.exit(1); }
  const zoho = await ZohoClient.cachedForConnection(conn.id);

  console.log('[discovery] running the production discovery path (accounts + org accounts + paginated groups)...');
  const discovery = await detection.discoverOrganization(zoho);
  const ev = discovery.evidence || {};
  const ownAccounts = (((ev.accounts || {}).body || {}).data || []);
  const totals = {
    tokenVisibleAccounts: ownAccounts.length,
    orgAccounts: Array.isArray((((ev.orgAccounts || {}).body || {}).data)) ? ev.orgAccounts.body.data.length : null,
    groupsDiscovered: discovery.mailboxes.filter(m => m.detectedType === 'shared_mailbox').length,
    userMailboxes: discovery.mailboxes.filter(m => m.detectedType !== 'shared_mailbox').length,
  };

  const targets = onlyAddress
    ? discovery.mailboxes.filter(m => m.address.toLowerCase() === onlyAddress)
    : discovery.mailboxes;
  if (onlyAddress && !targets.length) {
    console.error(`mailbox ${onlyAddress} not found in live discovery (check the address)`);
    process.exit(1);
  }
  const rows = [];
  for (const mb of targets) {
    const caps = await detection.probeCapabilities(zoho, mb);
    const choice = detection.chooseStrategy(mb, caps);
    let registeredId = null;
    if (persist) registeredId = await detection.upsertMailbox(conn.id, mb, caps, choice);
    const registered = registeredId || (await one('SELECT id FROM mailboxes WHERE lower(address)=lower($1)', [mb.address]) || {}).id || null;
    // what Madar has ACTUALLY stored for this mailbox — answers "does it hold
    // messages, and did they come via member-copy routing or another path?"
    let stored = { total: 0, byFolder: [] };
    if (registered) {
      const byFolder = await all(`SELECT COALESCE(f.name,'?') AS folder, o.provider, COUNT(*)::int n,
          MIN(o.received_at) AS oldest, MAX(o.received_at) AS newest
        FROM message_occurrences o LEFT JOIN folders f ON f.id = o.folder_id
        WHERE o.mailbox_id = $1 GROUP BY 1, 2 ORDER BY n DESC`, [registered]);
      stored = {
        total: byFolder.reduce((s, r) => s + r.n, 0),
        byFolder: byFolder.map(r => ({ folder: r.folder, via: r.provider, count: r.n,
          oldest: r.oldest ? new Date(r.oldest).toISOString().slice(0, 10) : null,
          newest: r.newest ? new Date(r.newest).toISOString().slice(0, 10) : null })),
      };
    }
    // exact reason when live message access is unavailable — from the probe's
    // classified evidence, never assumed
    let reason = null;
    if (!caps.messages) {
      const denials = Object.entries(caps.evidence || {})
        .filter(([k, e]) => e && e.status && e.status !== 200)
        .map(([k, e]) => `${k}: HTTP ${e.status}${e.classification ? ' (' + e.classification + ')' : ''}${e.description ? ' — ' + String(e.description).slice(0, 80) : ''}`);
      reason = denials.length ? denials.join(' | ')
        : 'no candidate id (group has no accountId — Zoho groups are not accounts)';
    }
    rows.push({
      address: mb.address,
      type: mb.detectedType === 'shared_mailbox' ? 'shared' : 'user',
      discovered: true,
      registeredInDiscoveryPage: Boolean(registered),
      accountId: caps.workingId || mb.providerAccountId || null,
      idKind: caps.workingIdKind || (mb.providerGroupId ? 'groupId(no account)' : null),
      folders: caps.folderCount || 0,
      folders_access: Boolean(caps.folders),
      messages_access: Boolean(caps.messages),
      strategy: choice.strategy,
      capture: choice.strategy === 'mail_api' ? 'direct_api (Option A)'
        : mb.detectedType === 'shared_mailbox' ? 'routed_member_copy live (Option B) + eDiscovery archive (Option C)'
          : 'none',
      reason,
      stored,
    });
    console.log(`\n${mb.address}\n  type: ${rows[rows.length - 1].type}\n  discovered: true\n  accountId: ${rows[rows.length - 1].accountId || 'none'}\n  folders: ${rows[rows.length - 1].folders}\n  messages_access: ${rows[rows.length - 1].messages_access}` +
      (reason ? `\n  reason: ${reason.slice(0, 200)}` : '') + `\n  capture: ${rows[rows.length - 1].capture}` +
      `\n  stored_in_madar: ${stored.total}` +
      (stored.byFolder.length ? stored.byFolder.map(f =>
        `\n    - ${f.folder} (via ${f.via}): ${f.count} [${f.oldest} → ${f.newest}]`).join('') : ''));
  }

  const shared = rows.filter(r => r.type === 'shared');
  const out = {
    connectionId: Number(conn.id), persisted: persist, totals,
    sharedMailboxes: shared.length,
    sharedWithDirectApi: shared.filter(r => r.messages_access).length,
    sharedViaMemberCopyAndArchive: shared.filter(r => !r.messages_access).length,
    rows,
    architecture: {
      optionA_direct_api: 'only for mailboxes with a probe-proven working accountId (user mailboxes; rare shared ones that are real accounts)',
      optionB_member_copy: 'IMPLEMENTED — any synced member message addressed to a registered shared mailbox lands there live (same canonical, provider zoho:member_copy)',
      optionC_admin_ediscovery: 'IMPLEMENTED — archive intake pipeline (multi-ZIP, cross-mailbox dedup, status board)',
    },
    verdict: shared.length > 0
      ? `DISCOVERED ${shared.length} shared mailbox(es) automatically${persist ? ' and registered them in the Discovery page' : ' (re-run with --persist to register without the UI button)'} — ${shared.filter(r => r.messages_access).length} with direct API, ${shared.filter(r => !r.messages_access).length} via member-copy live + eDiscovery archive (each with its exact classified reason above).`
      : 'NO shared mailboxes discovered — inspect totals/evidence (groups endpoint may be denied for this token; see reasons).',
  };
  console.log('\n' + JSON.stringify({ ...out, rows: undefined }, null, 2));
  console.log('\nfull rows:\n' + JSON.stringify(rows, null, 2));
  await closeDb();
  // pilot mode: completing the single-mailbox report IS success
  process.exit(onlyAddress ? 0 : (shared.length > 0 ? 0 : 1));
}

main().catch(async e => { console.error('discovery-verify failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
