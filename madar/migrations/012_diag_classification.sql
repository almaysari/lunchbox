-- Application-level failure classification, persisted per sync cycle.
-- Network transport was PROVEN healthy on the real tenant while list_folders
-- still reported "HTTP 0" — because the old client caught the OAuth phase and
-- the fetch phase in one block and stamped every throw as transport. Each
-- diagnostics row now carries the precise classification (oauth_token_missing,
-- oauth_token_decrypt_failed, oauth_refresh_failed, oauth_scope_denied,
-- zoho_account_mismatch, request_timeout, request_aborted, http_401/403/429,
-- zoho_api_error, malformed_response, application_exception,
-- unknown_transport_error) so the doctor and the operator see the real failure
-- class, and the original sanitized exception is preserved in response_sample.
ALTER TABLE sync_diagnostics ADD COLUMN classification TEXT;
CREATE INDEX idx_sync_diag_classification ON sync_diagnostics(classification) WHERE classification IS NOT NULL;
