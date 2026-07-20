-- Owner condition on split reconciliation: NO permanent deletion. Every row a
-- merge removes from the live tables is snapshotted here first — complete JSON
-- (occurrence incl. its folder membership; canonical incl. dedup_hash/subject/
-- body pointer fields) so any merge is reconstructible. Append-only evidence:
-- no FKs (the log must survive its sources), never pruned (like audit_log).
CREATE TABLE split_merge_log (
  id                  BIGSERIAL PRIMARY KEY,
  at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  mailbox_id          BIGINT NOT NULL,
  provider            TEXT NOT NULL,
  provider_message_id TEXT NOT NULL,
  keeper_canonical_id BIGINT NOT NULL,
  removed_occurrence  JSONB NOT NULL,
  removed_canonical   JSONB,            -- NULL when the canonical stayed live (referenced elsewhere)
  note                TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_split_merge_provider ON split_merge_log (mailbox_id, provider, provider_message_id);
