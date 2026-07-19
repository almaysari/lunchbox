-- Job state machine event log — the architectural fix for the whole class of
-- lifecycle bugs (zombie resurrection, ambiguous paused, double-resume races,
-- unexplainable states). Until now, job status transitions were raw UPDATEs
-- scattered across seven call sites with no legality check, no compare-and-swap
-- and no record of WHO moved a job WHY. Every transition now goes through ONE
-- guarded function (sync.transitionJob) that (a) validates the transition
-- against an explicit legal map, (b) performs it as a CAS
-- (WHERE status = ANY(expected) RETURNING), so two processes can never both win
-- a resume, and (c) appends a row here. "Why is this job running/paused/
-- skipped/recovered/failed?" is answered by reading this log — no hidden state,
-- no guessing.
CREATE TABLE job_events (
  id          BIGSERIAL PRIMARY KEY,
  job_id      BIGINT NOT NULL REFERENCES sync_jobs(id) ON DELETE CASCADE,
  from_status TEXT,                       -- NULL for creation
  to_status   TEXT NOT NULL,
  reason      TEXT NOT NULL,              -- human-readable cause ('attempt started', 'lease silent > 180s (dead attempt) reclaimed', 'graceful shutdown', ...)
  actor       TEXT NOT NULL,              -- '<label>:<pid>' — worker/cli/boot/admin/reconcile
  at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_job_events_job ON job_events(job_id, id);
