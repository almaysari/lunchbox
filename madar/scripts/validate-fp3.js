// Production validation of Canonical Identity v3 — Live vs Archive.
//
//   node scripts/validate-fp3.js <folder-with-eDiscovery-zips>
//
// Closes the v3 architectural decision ONLY when it PASSES on real Zoho live
// data (already synced into this DB) AND a real eDiscovery archive. It computes,
// over the intersection of the two sources, the exact six numbers the decision
// requires, using the RFC Message-ID carried by the archive EMLs as an
// INDEPENDENT forensic oracle (fp3 is never used to judge itself).
const fs = require('fs');
const path = require('path');
const { all } = require('../core/db');
const { dedupHash, normalizeForFingerprint } = require('../modules/mail/sync');
const { messagesFromExportZip } = require('../modules/mail/connectors/ediscovery-import');

const MIN_MESSAGES = Number(process.env.FP3_MIN || 100);

async function main() {
  const dir = process.argv[2];
  if (!dir) { console.error('usage: node scripts/validate-fp3.js <folder-with-zips>'); process.exit(2); }
  const zips = fs.readdirSync(dir).filter(f => f.toLowerCase().endsWith('.zip')).map(f => path.join(dir, f));
  if (!zips.length) { console.error('no .zip files in', dir); process.exit(2); }

  // ---- archive side: parse every EML, compute fp3 + keep the RFC oracle ----
  const archive = []; // {rfc, fp3, from, subject, sentSec}
  for (const z of zips) {
    for (const msg of messagesFromExportZip(fs.readFileSync(z))) {
      const n = normalizeForFingerprint(msg);
      archive.push({ rfc: (msg.rfcMessageId || '').trim(), fp3: dedupHash(msg),
        from: n.from, subject: n.subject, sentSec: n.sentSec, timeUnlinkable: n.timeUnlinkable });
    }
  }

  // ---- ORACLE CHECK 1 (within archive): fp3 vs RFC Message-ID ----
  // false merge: one fp3 covers >1 distinct RFC id. false split: one RFC id maps to >1 fp3.
  const withRfc = archive.filter(a => a.rfc);
  const fpToRfc = new Map(), rfcToFp = new Map();
  for (const a of withRfc) {
    (fpToRfc.get(a.fp3) || fpToRfc.set(a.fp3, new Set()).get(a.fp3)).add(a.rfc);
    (rfcToFp.get(a.rfc) || rfcToFp.set(a.rfc, new Set()).get(a.rfc)).add(a.fp3);
  }
  const falseMerges = [...fpToRfc.entries()].filter(([, s]) => s.size > 1);
  const falseSplits = [...rfcToFp.entries()].filter(([, s]) => s.size > 1);

  // ---- live side: fingerprints already stored (dedup_hash of v3 canonicals) ----
  const liveRows = await all(`SELECT dedup_hash FROM canonical_messages WHERE canonical_hash_version = 3`);
  const liveFps = new Set(liveRows.map(r => r.dedup_hash));

  // ---- convergence: archive messages whose fp3 exists among live canonicals ----
  const matched = archive.filter(a => liveFps.has(a.fp3));
  const unmatched = archive.filter(a => !liveFps.has(a.fp3));
  const unlinkable = archive.filter(a => a.timeUnlinkable || (!a.from && !a.subject));

  // in-system metrics (recorded live at ingestion)
  const m = Object.fromEntries((await all(
    `SELECT event_type, COUNT(*)::int n FROM fingerprint_metrics GROUP BY event_type`))
    .map(r => [r.event_type, r.n]));

  const report = {
    generatedFor: 'Canonical Identity v3 production closure',
    archiveMessages: archive.length,
    archiveWithRfcOracle: withRfc.length,
    liveV3Canonicals: liveFps.size,
    matched_by_fp3: matched.length,
    unmatched: unmatched.length,
    false_merges: falseMerges.length,      // fp3 quality on real content (oracle)
    false_splits: falseSplits.length,
    duplicates_prevented: m.duplicate_prevented || 0,
    unlinkable: unlinkable.length,
    fingerprint_metrics_in_system: m,
    correlation_confidence: withRfc.length
      ? Number((1 - (falseMerges.length + falseSplits.length) / new Set(withRfc.map(a => a.rfc)).size).toFixed(6))
      : null,
  };
  const pass = archive.length >= MIN_MESSAGES && matched.length >= MIN_MESSAGES
    && falseMerges.length === 0 && falseSplits.length === 0;
  report.threshold = { minMessages: MIN_MESSAGES };
  report.verdict = pass ? 'PASS — v3 may be closed' : 'NOT YET — see counts / raise coverage';

  console.log(JSON.stringify(report, null, 2));
  if (falseMerges.length) console.error('FALSE MERGE fp3s:', falseMerges.slice(0, 10).map(([fp]) => fp.slice(0, 12)));
  if (falseSplits.length) console.error('FALSE SPLIT rfcs:', falseSplits.slice(0, 10).map(([rfc]) => rfc));
  process.exit(pass ? 0 : 1);
}
main().catch(e => { console.error(e.stack || e.message); process.exit(3); });
