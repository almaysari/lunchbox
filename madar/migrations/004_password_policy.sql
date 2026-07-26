-- First-login password policy: initial (operator-created) credentials must be
-- changed before any other API call is allowed.
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
