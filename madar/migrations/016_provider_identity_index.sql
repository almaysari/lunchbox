-- Provider-identity lookup: insertMessage's guard resolves every ingest by
-- (mailbox, provider, provider_message_id) before touching canonicals. The
-- existing unique indexes lead with (mailbox_id, folder_id, ...) and cannot
-- serve this. NOT unique: pre-repair data legitimately holds split groups
-- (>1 rows per key) until scripts/fingerprint-split-repair.js --apply runs.
CREATE INDEX IF NOT EXISTS idx_occ_provider_identity
  ON message_occurrences (mailbox_id, provider, provider_message_id);
