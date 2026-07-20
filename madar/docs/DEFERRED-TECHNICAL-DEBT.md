# Madar — Deferred Technical Debt

Items identified during E2E validation (2026-07-20), reviewed and **deferred by owner decision**.
Neither blocks the current milestone. Neither was introduced by the validation.

> **Note on detail level.** This document is published in a public repository. Mailbox
> identities, folder names, record identifiers and production data volumes are deliberately
> generalized.

**Standing directive for both items — no production data changes:**

- Do **not** run `scripts/reconcile-hash-versions.js --apply`
- Do **not** run any historical data migration
- Do **not** run any duplicate cleanup on production

---

## DEBT-1 — Acceptance soak duplicate-key check is incorrect

**Type:** validator logic defect. **Severity:** low (reporting only). **Status:** deferred.

`modules/mail/acceptance.js` computes `duplicate_occurrences` by grouping
`message_occurrences` on `(mailbox_id, provider, provider_message_id)`.

The database enforces `UNIQUE (mailbox_id, folder_id, provider_message_id)`. Grouping with
`folder_id` included yields **0** duplicate groups; without it, a large non-zero count.

**Effect:** the acceptance run reports a spurious `FAIL no_duplicates`, one incident per sample.
Live capture is not duplicating — the count held constant while total occurrences grew.

**Resolution:** fix the **validator logic only** in a future task. No data changes. The genuine
underlying condition (DEBT-2) must remain visible under some check — do not simply relax the
assertion to make the soak green.

---

## DEBT-2 — Historical v2/v3 canonical hash inconsistency

**Type:** historical data migration issue. **Severity:** medium (historical records only).
**Status:** deferred, pending a separately approved migration design.

A set of emails exists as two canonical records each — one `canonical_hash_version=2`, one
`version=3` — split between an active folder and an archive folder. Both hash versions coexist in
the dataset.

Verified same-email evidence on a sample pair: identical subject hash, identical sender hash,
identical `sent_at`; recomputing fp3 over both yields the same value while their stored hashes
differ.

**The shipped remediation is itself defective.** `scripts/reconcile-hash-versions.js` dry-run
reports **zero merges**, slating every v2 row for in-place upgrade instead. It compares fp3
recomputed from stored fields against *stored* `dedup_hash` values, which are not comparable:
**0 of 300** sampled v3 rows reproduce their own stored hash, and **300 of 300** have HTML-escaped
stored fields.

**Risk if `--apply` were run as-is:** merges nothing; rewrites every v2 row's `dedup_hash` (a
UNIQUE column) to values inconsistent with live ingestion; future copies of the same email would
fail to converge onto the upgraded rows, likely creating *more* duplicates.

**Resolution:** requires a separate, approved migration design — fix the comparison basis
(recompute both sides, or normalize fields before hashing), add a test over a known v2/v3 twin
pair, confirm the dry run reports merges rather than in-place upgrades, and only then seek
approval to apply. Live capture correctness is unaffected in the meantime.
