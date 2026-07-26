-- Structured checkpoint (production Gate-1 finding, job 36).
--
-- sync_jobs.current_cursor was a SCALAR display of the CURRENT folder's page
-- offset while the true, resume-authoritative checkpoints are per-(mailbox,
-- folder) rows in sync_state.next_start (GREATEST-guarded, monotonic). The
-- scalar legitimately "drops" whenever the backfill loop enters the next
-- folder (production evidence: 7001,7101 = folder A's two pages at maxPages=2,
-- then 6301,6401 = folder B resuming from ITS persisted cursor) — but the
-- diagnostic surfaced it as a global cursor and even called the run healthy.
-- A scalar named "cursor" is insufficient and misleading. Replaced with:
--   checkpoint      JSONB  {folderId, folderName, folderType, phase(newest|backfill),
--                           offset, traceId, updatedAt}
--   checkpoint_seq  BIGINT strictly monotonic per job (server-side +1 on every
--                          write — a stale writer cannot decrease it)
-- Invariants: checkpoint_seq strictly increases; offset is monotonic only
-- WITHIN the same folder+phase; folder/phase changes are explicit transitions
-- (folder-backfill completion is also recorded in job_events).
ALTER TABLE sync_jobs ADD COLUMN checkpoint JSONB;
ALTER TABLE sync_jobs ADD COLUMN checkpoint_seq BIGINT NOT NULL DEFAULT 0;
