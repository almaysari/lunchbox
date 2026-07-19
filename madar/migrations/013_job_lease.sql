-- Job liveness lease. Real-tenant evidence (job 31): a LEGITIMATE long backfill
-- cycle (1844 discovered, 175 bodies imported at the paced 25 req/min) exceeds
-- 15 minutes by nature, and the age-based staleness predicate then "reclaimed"
-- it mid-flight with the factually false message "no progress > 15m" — progress
-- was real (cursor 6101). Staleness must measure DEATH (no heartbeat), not AGE.
-- checkpoint() — already called at least once per second during any live
-- attempt — now touches lease_at; the reclaim predicates read the lease. A live
-- hour-long attempt is never interrupted; a dead one is reclaimed exactly as
-- before (lease_at falls back to started_at for pre-lease rows).
ALTER TABLE sync_jobs ADD COLUMN lease_at TIMESTAMPTZ;
