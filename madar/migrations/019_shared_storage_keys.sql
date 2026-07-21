-- Content-addressed attachment storage: identical bytes map to ONE object,
-- so multiple attachments rows legitimately SHARE a storage_key (same invoice
-- forwarded through three threads = one object on disk). The implicit UNIQUE
-- on storage_key contradicts that by design — replaced with a plain index
-- (needed by the failure-path "is this key still referenced?" check and any
-- future garbage collection).
ALTER TABLE attachments DROP CONSTRAINT IF EXISTS attachments_storage_key_key;
CREATE INDEX IF NOT EXISTS idx_attachments_storage_key ON attachments (storage_key);
