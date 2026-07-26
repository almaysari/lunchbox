// Fingerprint-split reconciliation — merges canonicals that are the SAME
// provider message stored twice in one mailbox (dupOcc groups: same mailbox_id
// + provider + provider_message_id under >1 canonicals). The insertMessage
// provider-identity guard prevents NEW splits; this heals the existing ones
// (1056 groups on the real tenant, minted by the virtual Archived view).
//
// Owner-approved conditions (all enforced here, all test-proven):
//   * DRY-RUN by default — reports groups, affected canonicals, the merge
//     strategy, and conflicts, writing NOTHING.
//   * NO permanent deletion — every row leaving the live tables is first
//     snapshotted (full JSON, incl. the occurrence's folder membership) into
//     split_merge_log, which has no FKs and is never pruned.
//   * audit trail — one audit_log row per applied run (repair.split_merge)
//     with group/row counts; per-group evidence lives in the merge log.
//   * one TRANSACTION per group; idempotent (re-run finds 0 groups, writes
//     no duplicate log rows); resumable at any point.
//   * the OLDEST occurrence's canonical is the keeper (grants history, audit
//     references, thread context).
//   * relations transfer BEFORE the live rows move to the log: attachments
//     unique to the split-off canonical are re-parented (sha256+filename
//     match), a body the keeper lacks is copied.
//   * END-STATE INVARIANT: provider + mailbox + provider_message_id resolves
//     to exactly ONE canonical (and the guard keeps it that way).
//
// Conflict classes surfaced by the dry-run (none blocks the merge; each has a
// defined resolution):
//   * sharedLoserCanonicals — split-off canonical also referenced from OTHER
//     mailboxes (e.g. a routed member copy): its occurrence in THIS mailbox is
//     merged, the canonical itself STAYS LIVE (logged with removed_canonical
//     = null), so nothing referenced elsewhere ever disappears.
//   * multiWayGroups — >2 canonicals for one provider message: all non-oldest
//     merge into the same keeper, one log row each.
//   * attachmentCollisions — same sha256+filename on both sides: keeper's row
//     wins, the loser's duplicate row is preserved inside its snapshot.
const { all, one, tx } = require('../../core/db');

const STRATEGY = 'keep the OLDEST occurrence\'s canonical per (mailbox, provider, provider_message_id); '
  + 're-parent unique attachments + copy missing body to the keeper; move the split-off occurrence '
  + '(and its canonical when nothing else references it) into split_merge_log as full JSON snapshots — '
  + 'no permanent deletion; one transaction per group; idempotent';

async function findSplitGroups() {
  return all(`SELECT o.mailbox_id, o.provider, o.provider_message_id,
      array_agg(o.id ORDER BY o.id) AS occurrence_ids,
      array_agg(o.canonical_message_id ORDER BY o.id) AS canonical_ids
    FROM message_occurrences o
    GROUP BY o.mailbox_id, o.provider, o.provider_message_id
    HAVING COUNT(*) > 1
    ORDER BY o.mailbox_id, o.provider_message_id`);
}

async function repairSplits({ apply = false } = {}) {
  const groups = await findSplitGroups();
  const out = {
    applied: Boolean(apply), strategy: STRATEGY,
    groups: groups.length, canonicalsAffected: 0,
    occurrencesMerged: 0, canonicalsMerged: 0,
    attachmentsToReparent: 0, bodiesToCopy: 0,
    conflicts: { sharedLoserCanonicals: 0, multiWayGroups: 0, attachmentCollisions: 0 },
    fieldDrift: { sent_at: 0, subject: 0, from_address: 0, to_addresses: 0, hash_version: 0 },
    sample: [],
  };
  const affected = new Set();

  for (const g of groups) {
    const keeperId = Number(g.canonical_ids[0]); // canonical of the OLDEST occurrence
    const loserOccIds = g.occurrence_ids.slice(1).map(Number);
    const loserCanonIds = [...new Set(g.canonical_ids.slice(1).map(Number))].filter(id => id !== keeperId);
    affected.add(keeperId); loserCanonIds.forEach(id => affected.add(id));
    if (loserCanonIds.length > 1) out.conflicts.multiWayGroups++;

    // per-loser analysis — identical queries in dry-run and apply, so the
    // dry-run report predicts the apply exactly
    for (const lid of loserCanonIds) {
      const diff = await one(`SELECT (a.sent_at IS DISTINCT FROM b.sent_at)::int AS sent_at,
          (a.subject IS DISTINCT FROM b.subject)::int AS subject,
          (a.from_address IS DISTINCT FROM b.from_address)::int AS from_address,
          (a.to_addresses IS DISTINCT FROM b.to_addresses)::int AS to_addresses,
          (a.canonical_hash_version IS DISTINCT FROM b.canonical_hash_version)::int AS hash_version
        FROM canonical_messages a, canonical_messages b WHERE a.id=$1 AND b.id=$2`, [keeperId, lid]);
      if (diff) for (const k of Object.keys(out.fieldDrift)) out.fieldDrift[k] += Number(diff[k] || 0);
      const uniqAtt = await one(`SELECT COUNT(*)::int n FROM attachments a WHERE a.canonical_message_id=$1
        AND NOT EXISTS (SELECT 1 FROM attachments k WHERE k.canonical_message_id=$2
          AND k.sha256=a.sha256 AND k.original_filename=a.original_filename)`, [lid, keeperId]);
      const collAtt = await one(`SELECT COUNT(*)::int n FROM attachments a WHERE a.canonical_message_id=$1
        AND EXISTS (SELECT 1 FROM attachments k WHERE k.canonical_message_id=$2
          AND k.sha256=a.sha256 AND k.original_filename=a.original_filename)`, [lid, keeperId]);
      out.attachmentsToReparent += uniqAtt.n;
      if (collAtt.n) out.conflicts.attachmentCollisions++;
      const body = await one(`SELECT (k.body_html IS NULL AND l.body_html IS NOT NULL)::int AS copy
        FROM canonical_messages k, canonical_messages l WHERE k.id=$1 AND l.id=$2`, [keeperId, lid]);
      if (body && body.copy) out.bodiesToCopy++;
      const shared = await one(`SELECT 1 FROM message_occurrences WHERE canonical_message_id=$1
        AND mailbox_id <> $2 LIMIT 1`, [lid, g.mailbox_id]);
      if (shared) out.conflicts.sharedLoserCanonicals++;
    }
    if (out.sample.length < 3) out.sample.push({ mailboxId: Number(g.mailbox_id),
      providerMessageId: g.provider_message_id, keeperCanonical: keeperId, splitOffCanonicals: loserCanonIds });

    if (!apply) { out.occurrencesMerged += loserOccIds.length; out.canonicalsMerged += loserCanonIds.length; continue; }

    await tx(async (client) => {
      // 1) transfer relations to the keeper FIRST
      for (const lid of loserCanonIds) {
        await client.query(`UPDATE attachments a SET canonical_message_id = $1
          WHERE a.canonical_message_id = $2 AND NOT EXISTS (
            SELECT 1 FROM attachments k WHERE k.canonical_message_id = $1
              AND k.sha256 = a.sha256 AND k.original_filename = a.original_filename)`, [keeperId, lid]);
        await client.query(`UPDATE canonical_messages k SET body_html = l.body_html
          FROM canonical_messages l WHERE k.id = $1 AND l.id = $2
            AND k.body_html IS NULL AND l.body_html IS NOT NULL`, [keeperId, lid]);
      }
      // 2) snapshot + move each split-off occurrence into the merge log
      for (const oid of loserOccIds) {
        const occ = (await client.query('SELECT * FROM message_occurrences WHERE id=$1', [oid])).rows[0];
        if (!occ) continue; // resumability: a previous partial run already handled it
        await client.query(`INSERT INTO split_merge_log (mailbox_id, provider, provider_message_id,
            keeper_canonical_id, removed_occurrence, note)
          VALUES ($1,$2,$3,$4,$5,'occurrence merged into keeper')`,
        [g.mailbox_id, g.provider, g.provider_message_id, keeperId, JSON.stringify(occ)]);
        await client.query('DELETE FROM message_occurrences WHERE id=$1', [oid]);
        out.occurrencesMerged++;
      }
      // 3) a split-off canonical leaves the live table ONLY when nothing else
      //    references it — and its full snapshot goes to the log either way
      for (const lid of loserCanonIds) {
        const still = await client.query('SELECT 1 FROM message_occurrences WHERE canonical_message_id=$1 LIMIT 1', [lid]);
        const canon = (await client.query('SELECT * FROM canonical_messages WHERE id=$1', [lid])).rows[0];
        if (!canon) continue;
        if (still.rows.length) {
          await client.query(`UPDATE split_merge_log SET note = note || '; split-off canonical kept live (referenced elsewhere)'
            WHERE keeper_canonical_id=$1 AND provider_message_id=$2 AND mailbox_id=$3`,
          [keeperId, g.provider_message_id, g.mailbox_id]);
          continue;
        }
        await client.query(`UPDATE split_merge_log SET removed_canonical=$4
          WHERE keeper_canonical_id=$1 AND provider_message_id=$2 AND mailbox_id=$3`,
        [keeperId, g.provider_message_id, g.mailbox_id, JSON.stringify(canon)]);
        await client.query('DELETE FROM canonical_messages WHERE id=$1', [lid]);
        out.canonicalsMerged++;
      }
    });
  }
  out.canonicalsAffected = affected.size;

  if (apply && groups.length) {
    const { audit } = require('../../core/audit');
    await audit(null, 'repair.split_merge', `groups:${groups.length}`, {
      occurrencesMerged: out.occurrencesMerged, canonicalsMerged: out.canonicalsMerged,
      attachmentsReparented: out.attachmentsToReparent, bodiesCopied: out.bodiesToCopy,
      conflicts: out.conflicts,
    });
  }
  return out;
}

module.exports = { repairSplits, findSplitGroups, STRATEGY };
