// Fingerprint-split repair — merges canonicals that are the SAME provider
// message stored twice in one mailbox (dupOcc groups: same mailbox_id +
// provider + provider_message_id under >1 canonicals). This is the damage the
// insertMessage provider-identity guard now prevents; this module heals what
// already happened (1056 groups on the real tenant, minted by the virtual
// Archived view's field drift).
//
// Merge policy, per group, one transaction each (idempotent, resumable):
//   * KEEP the canonical of the OLDEST occurrence (original ingest — it holds
//     grants history, audit references, thread context).
//   * Salvage before delete: attachments unique to the split-off canonical are
//     re-parented to the keeper (matched by sha256+filename); a body the keeper
//     lacks is copied over.
//   * DELETE the split-off occurrence rows, then the split-off canonical ONLY
//     if nothing else references it (member-copy occurrences in other mailboxes
//     keep it alive — reported, not touched).
//   * Field-drift census (which fingerprint anchor differed) is reported as
//     evidence for the root cause — timestamps/flags only, no content.
//
// Dry-run by default; { apply: true } executes.
const { all, one, tx } = require('../../core/db');

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
  const out = { applied: Boolean(apply), groups: groups.length, occurrencesRemoved: 0,
    canonicalsRemoved: 0, canonicalsKeptShared: 0, attachmentsReparented: 0, bodiesCopied: 0,
    fieldDrift: { sent_at: 0, subject: 0, from_address: 0, to_addresses: 0 },
    sample: [] };

  for (const g of groups) {
    const keeperId = Number(g.canonical_ids[0]); // canonical of the OLDEST occurrence
    const loserOccIds = g.occurrence_ids.slice(1).map(Number);
    const loserCanonIds = [...new Set(g.canonical_ids.slice(1).map(Number))].filter(id => id !== keeperId);

    // drift census (evidence for the root cause) — computed in dry-run too
    for (const lid of loserCanonIds) {
      const diff = await one(`SELECT (a.sent_at IS DISTINCT FROM b.sent_at)::int AS sent_at,
          (a.subject IS DISTINCT FROM b.subject)::int AS subject,
          (a.from_address IS DISTINCT FROM b.from_address)::int AS from_address,
          (a.to_addresses IS DISTINCT FROM b.to_addresses)::int AS to_addresses
        FROM canonical_messages a, canonical_messages b WHERE a.id=$1 AND b.id=$2`, [keeperId, lid]);
      if (diff) for (const k of Object.keys(out.fieldDrift)) out.fieldDrift[k] += Number(diff[k] || 0);
    }
    if (out.sample.length < 3) out.sample.push({ mailboxId: Number(g.mailbox_id),
      providerMessageId: g.provider_message_id, keeperCanonical: keeperId, splitOffCanonicals: loserCanonIds });
    if (!apply) { out.occurrencesRemoved += loserOccIds.length; out.canonicalsRemoved += loserCanonIds.length; continue; }

    await tx(async (client) => {
      for (const lid of loserCanonIds) {
        // salvage: attachments the keeper does not have, and a missing body
        const rep = await client.query(`UPDATE attachments a SET canonical_message_id = $1
          WHERE a.canonical_message_id = $2 AND NOT EXISTS (
            SELECT 1 FROM attachments k WHERE k.canonical_message_id = $1
              AND k.sha256 = a.sha256 AND k.original_filename = a.original_filename)`, [keeperId, lid]);
        out.attachmentsReparented += rep.rowCount;
        const body = await client.query(`UPDATE canonical_messages k SET body_html = l.body_html
          FROM canonical_messages l WHERE k.id = $1 AND l.id = $2
            AND k.body_html IS NULL AND l.body_html IS NOT NULL`, [keeperId, lid]);
        out.bodiesCopied += body.rowCount;
      }
      const del = await client.query(`DELETE FROM message_occurrences WHERE id = ANY($1)`, [loserOccIds]);
      out.occurrencesRemoved += del.rowCount;
      for (const lid of loserCanonIds) {
        const still = await client.query(`SELECT 1 FROM message_occurrences WHERE canonical_message_id = $1 LIMIT 1`, [lid]);
        if (still.rows.length) { out.canonicalsKeptShared++; continue; } // alive elsewhere (e.g. member copy)
        await client.query(`DELETE FROM canonical_messages WHERE id = $1`, [lid]); // CASCADE: attachments leftovers
        out.canonicalsRemoved++;
      }
    });
  }
  return out;
}

module.exports = { repairSplits, findSplitGroups };
