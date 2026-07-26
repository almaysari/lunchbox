-- OAuth access-token cache (encrypted at rest), shared across processes.
--
-- Architectural defect this fixes: every sync cycle built a FRESH ZohoClient per
-- mailbox, whose access token lived only in that instance's memory — so every
-- mailbox × every cycle hit Zoho's token endpoint for a refresh. Zoho hard-limits
-- refresh-token usage; at a 120s interval with several mailboxes this trips the
-- limit and produces intermittent auth/transport failures that look random.
-- Persisting the (encrypted) access token with its expiry means ONE refresh per
-- connection per ~hour, shared by the server worker, the CLI doctor, and any
-- future process — and it survives restarts.
ALTER TABLE connections ADD COLUMN access_token_enc TEXT;
ALTER TABLE connections ADD COLUMN access_token_expires_at TIMESTAMPTZ;
