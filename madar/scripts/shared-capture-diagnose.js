#!/usr/bin/env node
// Gate-2 failure analyzer — run on the REAL tenant when e2e-proof reports
// "no message captured":
//
//   docker compose exec app node scripts/shared-capture-diagnose.js \
//     finance@exoticcolors.org --subject "E2E-SHARED-REALTIME-..."
//
// It walks the member-copy chain link by link and prints ONE verdict naming
// the broken link, with evidence:
//   captured                              → chain works, re-run e2e-proof
//   scan_pending                          → on Zoho, next tick should take it
//   on_zoho_not_stored                    → ENGINE DEFECT (realtime scan)
//   stored_in_member_not_routed           → ENGINE DEFECT (router)
//   member_copy_headers_lack_shared_address → delivery shape (BCC/envelope) —
//                                           resend with the shared address in To/CC
//   no_member_copy_on_zoho                → Zoho never delivered a member copy
//   no_capture_surface                    → no synced member mailbox exists
//   shared_not_registered                 → discovery/registry problem
//
// Exit codes: 0 captured · 2 engine defect · 1 external cause (delivery/config).
// Read-only. Output holds only the canary subject + tenant addresses.
require('../core/bootstrap').initCryptoFromEnv();
const { one, closeDb } = require('../core/db');
const { collectEvidence, classifyCapture } = require('../modules/mail/capture-diagnose');

function arg(name, dflt = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return dflt;
  const v = process.argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}

async function main() {
  const address = (process.argv[2] || '').toLowerCase();
  const subject = arg('--subject');
  if (!address || typeof subject !== 'string' || !subject) {
    console.error('usage: shared-capture-diagnose.js <shared-address> --subject "E2E-xxxx"');
    process.exit(2);
  }

  console.log(`[diagnose] walking the member-copy chain for ${address}, canary ~"${subject}"...`);
  const ev = await collectEvidence(address, subject);
  const v = classifyCapture(ev);

  const hb = await one('SELECT enabled, updated_at FROM sync_worker_heartbeat WHERE id=TRUE');
  const hbAge = hb ? Math.round((Date.now() - new Date(hb.updated_at)) / 1000) : null;
  const out = {
    tool: 'shared-capture-diagnose',
    sharedMailbox: ev.sharedAddress,
    subjectProbe: subject,
    verdict: v.classification,
    engineDefect: v.engineDefect,
    meaning: v.meaning,
    nextAction: v.nextAction,
    evidence: {
      sharedRegistered: ev.sharedRegistered,
      routedAddresses: ev.routedAddresses,
      groupMembers: ev.members,
      syncedMembers: ev.syncedMembers,
      storedInShared: ev.storedInShared,
      storedInMembers: ev.storedInMembers,
      zohoHotFolderHits: ev.zohoHits,
      probeErrors: ev.probeErrors,
      worker: { enabled: Boolean(hb && hb.enabled), heartbeatAgeSec: hbAge },
    },
  };
  console.log(JSON.stringify(out, null, 2));
  await closeDb();
  process.exit(v.classification === 'captured' ? 0 : v.engineDefect ? 2 : 1);
}

main().catch(async e => { console.error('shared-capture-diagnose failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
