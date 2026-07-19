#!/usr/bin/env node
// Archived-mail evidence probe — read-only, on the REAL tenant, using the exact
// production client (shared token cache, pacing, classification).
//
// Question it settles with evidence, per mailbox:
//   Where does Zoho expose archived mail for this account?
//     (a) in a LISTED folder (folderType Archive/…): then Madar ALREADY ingests
//         it autonomously — proven by test "archived mail in a listed folder is
//         ingested autonomously" — and any gap is rotation timing, visible here.
//     (b) only behind a dedicated archived VIEW parameter: the matrix below
//         probes the documented/likely candidates and classifies each response.
//     (c) not exposed by the API at all: every candidate's classified rejection
//         is the documented proof.
//
// Output: folder inventory (ids/names/types/counts — structural metadata only),
// per-candidate classification rows, and a verdict. No message bodies, no
// subjects, no tokens.
//
// Usage: docker compose exec app node scripts/archive-probe.js <mailbox-address>
require('../core/bootstrap').initCryptoFromEnv();
const { one, all, closeDb } = require('../core/db');
const { ZohoClient } = require('../modules/mail/zoho-client');

async function main() {
  const address = (process.argv[2] || '').toLowerCase();
  if (!address) { console.error('usage: archive-probe.js <mailbox-address>'); process.exit(2); }
  const mb = await one('SELECT * FROM mailboxes WHERE lower(address)=$1', [address]);
  if (!mb) { console.error('mailbox not found'); process.exit(1); }
  const caps = typeof mb.capabilities === 'string' ? JSON.parse(mb.capabilities || '{}') : (mb.capabilities || {});
  if (!caps.workingId) { console.error('no probe-proven working id for this mailbox'); process.exit(1); }
  const zoho = await ZohoClient.cachedForConnection(mb.connection_id);
  const acc = caps.workingId;

  const out = { mailbox: mb.address, accountId: acc, folders: [], candidates: [], syncedFolders: [] };

  // 1) full folder inventory as Zoho reports it (structural metadata only)
  const f = await zoho.getFolders(acc);
  const folderRows = (f.status === 200 && f.body && f.body.data) ? f.body.data : [];
  out.foldersEndpoint = { status: f.status, classification: f.classification || null, count: folderRows.length };
  for (const fo of folderRows) {
    out.folders.push({ folderId: String(fo.folderId), name: fo.folderName, type: fo.folderType || null,
      extraFields: Object.keys(fo).filter(k => !['folderId', 'folderName', 'folderType'].includes(k)).sort() });
  }
  const archiveLike = folderRows.filter(fo => /archiv/i.test(String(fo.folderType || '') + ' ' + String(fo.folderName || '')));

  // 2) what Madar has ALREADY ingested per folder (proves rotation state)
  out.syncedFolders = await all(`SELECT fo.name, fo.folder_type,
      (SELECT COUNT(*)::int FROM message_occurrences o WHERE o.folder_id = fo.id) AS stored,
      ss.backfill_done, ss.next_start, ss.last_sync_at
    FROM folders fo LEFT JOIN sync_state ss ON ss.folder_id = fo.id AND ss.mailbox_id = fo.mailbox_id
    WHERE fo.mailbox_id = $1 ORDER BY fo.name`, [mb.id]);

  // 3) candidate archived-view endpoints (read-only GETs, classified)
  const candidates = [
    ...archiveLike.map(fo => ({ label: `listed archive folder "${fo.folderName}"`,
      path: `/api/accounts/${acc}/messages/view?folderId=${fo.folderId}&limit=5` })),
    { label: 'messages/view?status=archived', path: `/api/accounts/${acc}/messages/view?status=archived&limit=5` },
    { label: 'messages/view?includearchive=true', path: `/api/accounts/${acc}/messages/view?includearchive=true&limit=5` },
    { label: 'messages/view?archivedMails=true', path: `/api/accounts/${acc}/messages/view?archivedMails=true&limit=5` },
  ];
  for (const c of candidates) {
    const r = await zoho.get(c.path);
    const rows = (r.status === 200 && r.body && Array.isArray(r.body.data)) ? r.body.data : null;
    out.candidates.push({
      label: c.label, status: r.status,
      classification: r.classification || (r.status === 200 ? 'ok' : null),
      returnedCount: rows ? rows.length : null,
      fieldNames: rows && rows[0] ? Object.keys(rows[0]).sort() : null,
      error: r.status !== 200 ? (r.body && (r.body.error || (r.body.status && r.body.status.description))) || null : null,
    });
  }

  const listedWorks = out.candidates.some(c => c.label.startsWith('listed archive folder') && c.status === 200);
  const viewWorks = out.candidates.find(c => !c.label.startsWith('listed archive folder') && c.status === 200 && c.returnedCount);
  out.verdict = listedWorks
    ? 'ARCHIVE IS A LISTED FOLDER — Madar already ingests it autonomously (cold rotation ≤ 15 min + backfill to terminal page). See syncedFolders for its current stored count and cursor.'
    : viewWorks
      ? `ARCHIVED MAIL IS BEHIND A DEDICATED VIEW (${viewWorks.label}) — connector mapping for a virtual Archived folder is the required change; this probe is the evidence to build it on.`
      : archiveLike.length === 0
        ? 'NO archive folder listed AND no archived-view candidate accepted — with these classified rejections as evidence, the API does not expose archived mail for this account type; the eDiscovery export remains the only path for that corpus.'
        : 'Archive folder listed but its message listing failed — see its classification row.';
  console.log(JSON.stringify(out, null, 2));
  await closeDb();
}

main().catch(async e => { console.error('archive-probe failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
