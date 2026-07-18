// fp2 -> fp3 reconciliation: eliminate the risk that legacy v2 canonicals and
// new v3 canonicals of the SAME email coexist as duplicates forever.
//
//   node scripts/reconcile-hash-versions.js            # dry-run (report only)
//   node scripts/reconcile-hash-versions.js --apply    # perform the merge
//
// Strategy (idempotent, no data loss):
//   For every v2 canonical, recompute its fp3 from its stored fields. If a v3
//   canonical already has that fp3, the two are the same email split across the
//   version boundary: re-point the v2 canonical's occurrences and attachments
//   onto the v3 canonical (occurrence unique keys make this dedup-safe), then
//   delete the now-empty v2 canonical. If no v3 twin exists, upgrade the v2 row
//   in place to v3 (recomputed dedup_hash + version=3) so future v3 ingestion
//   converges onto it. Either way, after this runs there is exactly one
//   canonical per email regardless of which version first ingested it.
const { all, one, q, tx } = require('../core/db');
const { dedupHash } = require('../modules/mail/sync');

async function main() {
  const apply = process.argv.includes('--apply');
  const v2 = await all(`SELECT id, dedup_hash, rfc_message_id, from_address, from_name, to_addresses,
    cc_addresses, subject, snippet, sent_at, has_attachments FROM canonical_messages WHERE canonical_hash_version = 2`);
  const report = { v2Canonicals: v2.length, mergedIntoV3: 0, upgradedInPlace: 0, hashCollisionsSkipped: 0, apply };

  for (const c of v2) {
    // reconstruct the message shape v3's dedupHash expects (SENT time drives it)
    const shape = { from: c.from_address, to: c.to_addresses, cc: c.cc_addresses,
      subject: c.subject, sentAt: c.sent_at ? new Date(c.sent_at).getTime() : undefined,
      receivedAt: c.sent_at ? new Date(c.sent_at).getTime() : undefined, rfcMessageId: c.rfc_message_id };
    const newHash = dedupHash(shape);
    const twin = await one(`SELECT id FROM canonical_messages WHERE dedup_hash = $1 AND canonical_hash_version = 3`, [newHash]);

    if (twin && Number(twin.id) !== Number(c.id)) {
      report.mergedIntoV3++;
      if (apply) {
        await tx(async (client) => {
          // occurrences: move those that don't collide; drop exact duplicates
          await client.query(`UPDATE message_occurrences o SET canonical_message_id = $1
            WHERE o.canonical_message_id = $2 AND NOT EXISTS (
              SELECT 1 FROM message_occurrences x WHERE x.canonical_message_id = $1
                AND x.mailbox_id = o.mailbox_id)`, [twin.id, c.id]);
          await client.query(`DELETE FROM message_occurrences WHERE canonical_message_id = $1`, [c.id]);
          await client.query(`UPDATE attachments a SET canonical_message_id = $1
            WHERE a.canonical_message_id = $2 AND NOT EXISTS (
              SELECT 1 FROM attachments y WHERE y.canonical_message_id = $1
                AND y.sha256 = a.sha256 AND y.original_filename = a.original_filename)`, [twin.id, c.id]);
          await client.query(`DELETE FROM attachments WHERE canonical_message_id = $1`, [c.id]);
          await client.query(`DELETE FROM canonical_messages WHERE id = $1`, [c.id]);
        });
      }
    } else if (!twin) {
      // no v3 twin — upgrade in place unless the new hash already belongs to a
      // different v2 row (rare); then leave it and report for manual review.
      const busy = await one(`SELECT id FROM canonical_messages WHERE dedup_hash = $1 AND id <> $2`, [newHash, c.id]);
      if (busy) { report.hashCollisionsSkipped++; continue; }
      report.upgradedInPlace++;
      if (apply) await q(`UPDATE canonical_messages SET dedup_hash = $1, canonical_hash_version = 3 WHERE id = $2`, [newHash, c.id]);
    }
  }
  console.log(JSON.stringify(report, null, 2));
  if (!apply) console.log('\n(dry-run — re-run with --apply to perform the reconciliation)');
}
main().catch(e => { console.error(e.stack || e.message); process.exit(1); });
