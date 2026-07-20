# Madar — E2E Validation Status

**Milestone status: E2E VALIDATION COMPLETE — accepted PASS, 2026-07-20.**

Live sync validation status is PASS. Permissions are unchanged. The two findings in section 6
were reviewed and **deferred** as technical debt — see
[DEFERRED-TECHNICAL-DEBT.md](DEFERRED-TECHNICAL-DEBT.md). Standing directive: no historical data
migration, no duplicate cleanup on production, and `reconcile-hash-versions.js --apply` must not
be run.

**Scope:** email capture and synchronization validation only. No mailbox administration, no
access changes to any sensitive mailbox.
**Method:** read-only inspection plus the project's own shipped validation scripts.

> **Note on detail level.** This document is published in a public repository. Mailbox
> identities, folder names, record identifiers and production data volumes are deliberately
> generalized. Operators can reproduce every figure by running the commands below against the
> live system.

---

## 1. Final E2E status

**Verdict: PASS** on the capture and synchronization path.

Command (established project gate):

```
docker compose exec app node scripts/e2e-proof.js <mailbox-address> --subject "<canary-subject>"
```

| Criterion | Result |
|---|---|
| `visibleNow` | `true` |
| `grantedReaders` | ≥ 1 |
| `exactlyOneOccurrence` | `true` |
| `occurrences` / `canonicals` | `1` / `1` |
| Occurrence + canonical id | Stable and identical across repeated runs (no duplicate created) |
| `workerAfter.alive` | `true` |
| `stuckJobsNow` | `0` |
| Verdict | `PASS — captured exactly once, worker alive, no stuck jobs` |

## 2. Validated mailbox path

| Field | Value |
|---|---|
| Target | A single individual user mailbox. **Not** a shared, finance, or otherwise sensitive mailbox. |
| Why this one | It is the **only** mailbox in the fleet with `sync_enabled=true` / `status=ready`. Every other mailbox is `no_live_api` and cannot produce a real capture. |
| Reader identity | An existing platform user holding a pre-existing grant on that mailbox. |
| Grant | `can_view_messages`, `can_view_attachments` — **pre-existing**, granted two days before this validation. |
| Audit record | The grant has a corresponding `admin.grant.set` row in `audit_log`. |

No grant was created, altered, or revoked during this validation. No sensitive shared mailbox was
accessed, and none had its permissions modified.

## 3. Capture latency

| Metric | Value |
|---|---|
| **Observed capture latency** | **71 seconds** (receipt → stored) |

Single observation from one canary. Not a statistical distribution — do not quote it as a
guaranteed SLA.

## 4. Worker status

| Check | Result |
|---|---|
| Worker alive | Yes |
| Heartbeat age | Well inside the stale threshold on every sample |
| Stuck jobs | 0 |
| Stuck mailboxes | 0 |
| Job lifecycle | Realtime and backfill cycles completed cleanly; next cycle running |
| Memory | Stable across all soak samples |
| Transport health | No transport errors recorded |

## 5. Deduplication and canonical integrity

`scripts/verify-canonical-fingerprint.js` — **all 5 properties PASS** (HASH_VERSION 3):

1. Real resends stay distinct
2. Distinct messages produce distinct fingerprints
3. Live vs eDiscovery EML converge to the same fp3
4. Mailbox-independent: the same email in two mailboxes shares one canonical
5. Re-import idempotency stable

Enforced at the database level:

- `UNIQUE (mailbox_id, folder_id, provider_message_id)`
- `UNIQUE (mailbox_id, folder_id, canonical_message_id)`
- `UNIQUE (mailbox_id, canonical_message_id)`
- `UNIQUE (dedup_hash)` on `canonical_messages`

No two canonicals share a `dedup_hash` (`duplicate_canonicals = 0` in every soak sample).

---

## 6. Known limitations

### 6.1 Acceptance soak reports `FAIL no_duplicates` — cause identified, not live duplication

The acceptance soak reports a non-zero `duplicate_occurrences` and an overall FAIL. Findings:

- The count stayed **constant** across every sample while total occurrences grew. New captures
  are **not** producing duplicates.
- The check groups by `(mailbox_id, provider, provider_message_id)`. Adding `folder_id` — which
  is what the database actually enforces — yields **0** duplicate groups.
- All affected groups are confined to the single live-syncing mailbox.

**Assessment:** the acceptance check's uniqueness key does not match the storage model's key. It
is a check-side inconsistency, not evidence of duplicate processing.

### 6.2 Root cause: the fp2/fp3 version boundary

Each affected group is one `canonical_hash_version=2` canonical plus one `version=3` canonical of
the same email, split between an active folder and an archive folder. Both versions coexist in
the dataset.

Verified on a sample pair: identical subject hash, identical sender hash, identical `sent_at` to
the millisecond, and recomputing fp3 over both rows produces the **same** hash. They are the same
email.

### 6.3 DEFECT — `scripts/reconcile-hash-versions.js` will not fix 6.2, and applying it is risky

Dry-run reports **zero merges** (`mergedIntoV3: 0`) with every v2 row instead slated for in-place
upgrade — despite a large number of genuine v2/v3 twins existing.

Cause: the script recomputes fp3 from a v2 canonical's **stored** fields and looks for a v3
canonical whose **stored** `dedup_hash` equals it. Those are not comparable:

- **0 of 300** sampled v3 canonicals reproduce their own stored hash from their stored fields.
- **300 of 300** have HTML-escaped stored fields (e.g. `&quot;Display Name&quot;&lt;user@example.com&gt;`).

Confirmed fact: stored fields are HTML-escaped at persist time while the hash was computed at
ingestion, so recomputation from storage never reproduces a stored hash. (That escaping is the
mechanism is an inference from the evidence, but the non-reproducibility itself is measured.)

Consequence of running `--apply`:

1. It merges nothing — the duplicate pairs remain.
2. It rewrites every v2 row's `dedup_hash` to a recomputed-from-storage value in a **UNIQUE**
   column.
3. Those rewritten hashes are inconsistent with how live ingestion computes hashes, so future
   copies of the same email would **fail** to converge onto the upgraded rows — likely creating
   *more* duplicates.

**Recommendation: do not run `reconcile-hash-versions.js --apply`.** The fix is to compare
recomputed-to-recomputed (or normalize fields before hashing) so both sides use the same basis.
Not actioned here — out of validation scope, and it is a data migration requiring approval.

### 6.4 Coverage limitations

- **Only one mailbox in the fleet live-syncs.** E2E capture is proven for exactly one mailbox and
  one provider path; the derived member-copy path is observed but not independently proven
  end-to-end.
- **No dedicated test fixture exists.** Validation runs against a real mailbox. A synthetic test
  mailbox is not usable until it has live sync, otherwise a proof there would require fabricated
  rows.
- **`survives_restart` is N/A** — no restart occurred during the soak, so resilience is unexercised.
- **`canary_captured` is N/A** for this soak run — no canary was configured for it.
- Capture latency rests on a single observation.

## 7. Summary

| Area | Status |
|---|---|
| Message capture | PASS |
| Synchronization lifecycle | PASS |
| Real-time updates | PASS (71 s observed) |
| Canonical handling | PASS |
| Deduplication (live path) | PASS |
| User visibility model | PASS — enforced server-side |
| Worker health / stuck jobs | PASS |
| Historical fp2/fp3 duplicate backlog | **DEFERRED** — DEBT-2; remediation script defective (6.3) |
| Acceptance check key correctness | **DEFERRED** — DEBT-1; omits `folder_id` (6.1) |

The live capture and synchronization path is validated. The two deferred items are pre-existing
data/tooling issues affecting historical records; neither was introduced by this validation and
neither affects live capture correctness. Both are tracked in
[DEFERRED-TECHNICAL-DEBT.md](DEFERRED-TECHNICAL-DEBT.md) and are out of scope for this milestone.
