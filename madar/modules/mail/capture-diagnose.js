// Shared-mailbox capture diagnosis — names the EXACT broken link in the
// member-copy chain, from evidence (DB reads + live Zoho hot-folder reads).
//
// The chain for a shared mailbox with no direct API access:
//   (1) Zoho delivers group mail into MEMBER accounts
//   (2) the realtime pass ingests it from a SYNCED member's hot folder
//   (3) header routing (to/cc) adds the shared-mailbox occurrence
// A Gate-2 "no capture in N seconds" verdict means one specific link failed.
// Guessing which is forbidden — this module reads the evidence for each link
// and classifies. classifyCapture is pure (unit-testable); collectEvidence
// does the I/O. Read-only: no writes, no message bodies; output carries only
// the operator-chosen canary subject and tenant addresses needed for the
// routing verdict.
const { one, all } = require('../../core/db');
const { recipientAddresses, sharedAddressMap } = require('./sync');
const { ZohoClient } = require('./zoho-client');
const { ZohoMailApiConnector } = require('./connectors/zoho-mail-api');

const CLASSIFICATIONS = {
  shared_not_registered: {
    engineDefect: true,
    meaning: 'The shared mailbox is not in the registry, so the router has no target for it.',
    nextAction: 'Run discovery (worker auto-discovery or shared-mailbox-discovery-verify.js --persist), then re-test.',
  },
  captured: {
    engineDefect: false,
    meaning: 'The canary has an occurrence in the shared mailbox — the chain works.',
    nextAction: 'Re-run e2e-proof.js for the formal gate verdict.',
  },
  stored_in_member_not_routed: {
    engineDefect: true,
    meaning: 'A member copy IS stored with the shared address in to/cc, but no shared occurrence exists — the router failed.',
    nextAction: 'Engine bug: inspect routeToSharedMailboxes with the printed canonical id.',
  },
  member_copy_headers_lack_shared_address: {
    engineDefect: false,
    meaning: 'A member copy exists but its to/cc headers do not carry the shared address (BCC/envelope-style delivery) — header-based routing cannot see it BY DESIGN.',
    nextAction: 'Send the canary with the shared address in To or CC (not BCC), or from a synced member (the Sent copy routes). Header-invisible delivery needs the eDiscovery archive path.',
  },
  on_zoho_not_stored: {
    engineDefect: true,
    meaning: 'The canary is visible in a synced member hot folder on Zoho, arrived BEFORE that folder’s last scan, and is still not stored — the realtime scan missed it.',
    nextAction: 'Engine bug: inspect the member mailbox sync (job-inspect + sync_diagnostics for the scan window).',
  },
  scan_pending: {
    engineDefect: false,
    meaning: 'The canary is on Zoho in a synced member hot folder with routable headers, but arrived after the last scan — the next realtime tick should capture it.',
    nextAction: 'Wait one sync interval and re-run; if it stays scan_pending, check worker heartbeat/cycles.',
  },
  no_capture_surface: {
    engineDefect: false,
    meaning: 'No member of this shared mailbox is a synced (pilot + enabled, mail_api) mailbox — there is nowhere to capture a live copy from.',
    nextAction: 'Enable sync for at least one member mailbox of this group.',
  },
  no_member_copy_on_zoho: {
    engineDefect: false,
    meaning: 'The canary is not visible on Zoho in ANY synced member hot folder — Zoho never delivered a member copy (group delivery settings), or the message was not sent.',
    nextAction: 'Verify the email was actually sent; check the Zoho group’s delivery setting (members must receive copies), or send from/to a synced member account.',
  },
};

function verdict(classification, extra = {}) {
  const c = CLASSIFICATIONS[classification];
  return { classification, engineDefect: c.engineDefect, meaning: c.meaning, nextAction: c.nextAction, ...extra };
}

// Pure — evidence in, named verdict out. Priority order matters: a stored
// member copy explains more than a live Zoho hit, which explains more than
// absence. See CLASSIFICATIONS for what each one means and what to do next.
function classifyCapture(ev) {
  if (!ev.sharedRegistered) return verdict('shared_not_registered');
  if ((ev.storedInShared || 0) > 0) return verdict('captured');
  const stored = ev.storedInMembers || [];
  if (stored.some(h => h.headersMatch)) return verdict('stored_in_member_not_routed');
  if (stored.length) return verdict('member_copy_headers_lack_shared_address');
  const hits = ev.zohoHits || [];
  const routable = hits.filter(h => h.headersMatch);
  if (routable.some(h => h.receivedBeforeLastScan)) return verdict('on_zoho_not_stored');
  if (routable.length) return verdict('scan_pending');
  if (hits.length) return verdict('member_copy_headers_lack_shared_address');
  if (!(ev.syncedMembers || []).length) return verdict('no_capture_surface');
  return verdict('no_member_copy_on_zoho');
}

// I/O: gather every link's evidence for one shared address + canary subject.
async function collectEvidence(sharedAddress, subject) {
  const shared = await one(
    `SELECT id, address, detected_type, strategy, members FROM mailboxes WHERE lower(address)=lower($1)`,
    [sharedAddress]);
  const sharedRegistered = Boolean(shared && shared.detected_type === 'shared_mailbox');
  const ev = {
    sharedAddress: sharedAddress.toLowerCase(), subject, sharedRegistered,
    sharedMailboxId: shared ? Number(shared.id) : null,
    routedAddresses: [], members: [], syncedMembers: [],
    storedInShared: 0, storedInMembers: [], zohoHits: [], probeErrors: [],
  };
  if (!sharedRegistered) return ev;

  // (3) routing target set — the PRODUCTION map (primary + aliases), so the
  // diagnostic matches exactly what the router would match
  const routing = await sharedAddressMap();
  ev.routedAddresses = [...routing.map.entries()]
    .filter(([, id]) => id === ev.sharedMailboxId).map(([a]) => a);
  const routedSet = new Set(ev.routedAddresses);
  const headersMatch = (to, cc) =>
    [...recipientAddresses({ to, cc })].some(a => routedSet.has(a));

  // stored occurrences of the canary ANYWHERE (shared + member copies)
  const storedRows = await all(
    `SELECT o.mailbox_id, m.address, f.name AS folder, o.provider,
            c.id AS canonical_id, c.to_addresses, c.cc_addresses
       FROM canonical_messages c
       JOIN message_occurrences o ON o.canonical_message_id = c.id
       JOIN mailboxes m ON m.id = o.mailbox_id
       LEFT JOIN folders f ON f.id = o.folder_id
      WHERE c.subject ILIKE '%' || $1 || '%'`, [subject]);
  ev.storedInShared = storedRows.filter(r => Number(r.mailbox_id) === ev.sharedMailboxId).length;
  ev.storedInMembers = storedRows
    .filter(r => Number(r.mailbox_id) !== ev.sharedMailboxId)
    .map(r => ({ mailboxId: Number(r.mailbox_id), address: r.address, folder: r.folder,
      provider: r.provider, canonicalId: Number(r.canonical_id),
      headersMatch: headersMatch(r.to_addresses, r.cc_addresses) }));

  // (2) capture surface: synced members of this group
  const members = Array.isArray(shared.members) ? shared.members
    : JSON.parse(shared.members || '[]');
  ev.members = members.map(m => m.email).filter(Boolean);
  const probeList = ev.members.length
    ? await all(`SELECT * FROM mailboxes WHERE lower(address) = ANY($1)
                   AND strategy='mail_api' AND is_pilot AND sync_enabled`, [ev.members.map(a => a.toLowerCase())])
    // membership unknown (e.g. groups API returned no member list): every synced
    // mailbox is a potential capture surface — probe them all rather than guess
    : await all(`SELECT * FROM mailboxes WHERE strategy='mail_api' AND is_pilot AND sync_enabled`);
  ev.syncedMembers = probeList.map(m => ({ mailboxId: Number(m.id), address: m.address }));

  // (1) live Zoho truth: is the canary in a synced member's hot folder RIGHT NOW?
  for (const mb of probeList) {
    try {
      const zoho = await ZohoClient.cachedForConnection(mb.connection_id);
      const connector = new ZohoMailApiConnector(zoho, mb);
      const hot = await all(
        `SELECT f.id, f.provider_folder_id, f.name, f.folder_type, s.last_sync_at
           FROM folders f LEFT JOIN sync_state s ON s.folder_id = f.id AND s.mailbox_id = f.mailbox_id
          WHERE f.mailbox_id = $1 AND lower(f.folder_type) IN ('inbox','sent')`, [mb.id]);
      for (const f of hot) {
        const page = await connector.listMessages(
          { providerFolderId: f.provider_folder_id, name: f.name, type: f.folder_type }, { start: 1, limit: 100 });
        for (const msg of page) {
          if (!String(msg.subject || '').toLowerCase().includes(subject.toLowerCase())) continue;
          const lastScan = f.last_sync_at ? new Date(f.last_sync_at).getTime() : null;
          ev.zohoHits.push({
            memberAddress: mb.address, folder: f.name, folderType: f.folder_type,
            to: msg.to, cc: msg.cc, receivedAt: new Date(msg.receivedAt).toISOString(),
            headersMatch: headersMatch(msg.to, msg.cc),
            hotFolderLastScanAt: lastScan ? new Date(lastScan).toISOString() : null,
            receivedBeforeLastScan: Boolean(lastScan && msg.receivedAt < lastScan),
          });
        }
      }
    } catch (err) {
      // contained: one member's probe failure must not sink the diagnosis —
      // record it (an unreachable member is itself evidence)
      ev.probeErrors.push({ address: mb.address,
        error: err.classification || err.message || String(err) });
    }
  }
  return ev;
}

module.exports = { classifyCapture, collectEvidence, CLASSIFICATIONS };
