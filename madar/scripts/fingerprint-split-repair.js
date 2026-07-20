#!/usr/bin/env node
// Heals fingerprint splits: the same provider message stored under TWO
// canonicals in one mailbox (minted by the virtual Archived view's field
// drift before the insertMessage provider-identity guard existed).
//
//   docker compose exec app node scripts/fingerprint-split-repair.js            # dry-run report
//   docker compose exec app node scripts/fingerprint-split-repair.js --apply    # merge
//
// Merge keeps the OLDEST occurrence's canonical, salvages unique attachments +
// missing bodies onto it, removes the split-off occurrence rows, and deletes
// split-off canonicals only when nothing else references them. Idempotent —
// re-running after a successful --apply reports 0 groups. The field-drift
// census in the output names WHICH fingerprint anchor differed (evidence).
// Output: ids/counts/flags only — no subjects, no bodies, no addresses beyond
// the mailbox's own id.
require('../core/bootstrap').initCryptoFromEnv();
const { closeDb } = require('../core/db');
const { repairSplits } = require('../modules/mail/split-repair');

async function main() {
  const apply = process.argv.includes('--apply');
  console.log(`[split-repair] ${apply ? 'APPLYING merge' : 'dry-run (pass --apply to merge)'}...`);
  const out = await repairSplits({ apply });
  console.log(JSON.stringify(out, null, 2));
  if (!apply && out.groups > 0) console.log(`\n${out.groups} split group(s) found — re-run with --apply to merge them.`);
  if (apply) console.log(`\nmerged. Re-run without --apply to verify it now reports 0 groups.`);
  await closeDb();
  process.exit(0);
}

main().catch(async e => { console.error('split-repair failed:', e.message || e); try { await closeDb(); } catch {} process.exit(2); });
