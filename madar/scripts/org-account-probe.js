#!/usr/bin/env node
// Org-account readability probe — READ-ONLY evidence for the question:
// «can the current admin OAuth token read OTHER org members' mailboxes
// directly?» (the tenant exposes ~89 org accounts to this token).
//
//   docker compose exec app node scripts/org-account-probe.js              # sample of 5
//   docker compose exec app node scripts/org-account-probe.js --limit 20
//   docker compose exec app node scripts/org-account-probe.js --all
//   docker compose exec app node scripts/org-account-probe.js --account someone@exoticcolors.org
//
// If READABLE: every employee mailbox is a live-sync candidate → shared
// mailboxes get org-wide member-copy coverage (all members' inboxes become
// capture surface, not just one).
// If DENIED: the classified rejection is printed per account — the bridge is
// then Zoho-side (member delivery / collector account / licensed conversion).
//
// Sanitized: addresses + ids + HTTP statuses + counts. NO subjects, NO bodies,
// NO message metadata beyond a count.
require('../core/bootstrap').initCryptoFromEnv();
const { one, closeDb } = require('../core/db');
const { ZohoClient } = require('../modules/mail/zoho-client');
const detection = require('../modules/mail/detection');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

async function main() {
  const conn = await one(`SELECT id FROM connections WHERE status='connected' ORDER BY id LIMIT 1`);
  if (!conn) { console.error('no connected Zoho connection'); process.exit(1); }
  const zoho = await ZohoClient.cachedForConnection(conn.id);

  console.log('[probe] resolving org accounts through the production discovery path...');
  const discovery = await detection.discoverOrganization(zoho);
  const ev = discovery.evidence || {};
  const orgAccounts = (((ev.orgAccounts || {}).body || {}).data || []);
  const ownAddresses = new Set((((ev.accounts || {}).body || {}).data || [])
    .flatMap(a => [a.mailboxAddress, a.primaryEmailAddress].filter(Boolean).map(s => s.toLowerCase())));

  const onlyAddr = typeof arg('--account') === 'string' ? String(arg('--account')).toLowerCase() : null;
  const all = process.argv.includes('--all');
  const limit = all ? Infinity : Math.max(1, Number(arg('--limit', 5)) || 5);

  let candidates = orgAccounts
    .map(a => ({ address: (a.mailboxAddress || a.primaryEmailAddress || '').toLowerCase(),
      accountId: a.accountId ? String(a.accountId) : null }))
    .filter(a => a.address && a.accountId && !ownAddresses.has(a.address));
  if (onlyAddr) candidates = candidates.filter(a => a.address === onlyAddr);
  const skippedForSample = Math.max(0, candidates.length - (Number.isFinite(limit) ? limit : candidates.length));
  candidates = candidates.slice(0, Number.isFinite(limit) ? limit : candidates.length);
  if (!candidates.length) { console.error('no matching org accounts (or none beyond your own)'); process.exit(1); }

  const rows = [];
  for (const c of candidates) {
    const row = { address: c.address, accountId: c.accountId,
      folders: null, messages: null, readable: false, reason: null };
    try {
      const f = await zoho.getFolders(c.accountId);
      row.folders = { status: f.status, count: Array.isArray(f.body && f.body.data) ? f.body.data.length : 0 };
      if (f.status === 200 && row.folders.count) {
        const firstFolder = String(f.body.data[0].folderId);
        const m = await zoho.listMessages(c.accountId, firstFolder, { start: 1, limit: 5 });
        row.messages = { status: m.status, sampleCount: Array.isArray(m.body && m.body.data) ? m.body.data.length : 0 };
        row.readable = m.status === 200;
        if (!row.readable) row.reason = `messages: HTTP ${m.status}` +
          ((m.body && m.body.status && m.body.status.description) ? ' — ' + String(m.body.status.description).slice(0, 100) : '');
      } else {
        row.reason = `folders: HTTP ${f.status}` +
          ((f.body && f.body.status && f.body.status.description) ? ' — ' + String(f.body.status.description).slice(0, 100) : '');
      }
    } catch (err) {
      row.reason = err.classification || err.message || String(err);
    }
    rows.push(row);
    console.log(`  ${row.address} [${row.accountId}] → ${row.readable ? 'READABLE'
      : 'denied (' + (row.reason || '?') + ')'}`);
  }

  const readable = rows.filter(r => r.readable).length;
  const out = {
    connectionId: Number(conn.id),
    orgAccountsVisible: orgAccounts.length,
    probed: rows.length,
    skippedForSample,
    readable,
    denied: rows.length - readable,
    rows,
    verdict: readable === rows.length
      ? `READABLE — the admin token reads other org mailboxes directly: every employee mailbox is a live-sync candidate, giving shared mailboxes ORG-WIDE member-copy coverage.`
      : readable > 0
        ? `MIXED (${readable}/${rows.length}) — some org accounts are readable; inspect per-account reasons above.`
        : `DENIED — this token cannot read other members' mail (privacy-correct default). Bridge options: Zoho member-delivery / collector account membership / licensed conversion of key shared boxes; eDiscovery covers history.`,
  };
  console.log('\n' + JSON.stringify({ ...out, rows: undefined }, null, 2));
  console.log('\nfull rows:\n' + JSON.stringify(rows, null, 2));
  await closeDb();
  process.exit(0);
}

main().catch(async e => { console.error('org-account-probe failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
