-- BitosX outbox payload size, recovery-code uniqueness scope, and housekeeping indexes (migration 0008).
--
-- 1. email_outbox.payload_ciphertext VARBINARY(512) -> VARBINARY(4096). The payload is the JSON of
--    (version, account id, token, expiry, recipient). The validator allows a 320-character address and
--    the default JSON encoder writes each non-ASCII character as a 6-byte \uXXXX escape, so the worst case
--    is about 2.1 KB; GCM ciphertext has the plaintext's length. 512 bytes failed such a registration.
-- 2. Recovery-code verifiers are unique per ACCOUNT, not globally: the HMAC has no account binding, so two
--    accounts drawing the same code (about 2^49.5 possibilities) made confirm/regenerate fail. Every lookup
--    already filters on account_id.
-- 3. Indexes for the bounded, batched deletes of the housekeeping service and of the outbox retention
--    (which previously scanned the whole table every poll).
ALTER TABLE email_outbox
    MODIFY COLUMN payload_ciphertext VARBINARY(4096) NULL,
    ADD INDEX ix_outbox_created_at (created_at);

ALTER TABLE account_recovery_codes
    ADD CONSTRAINT ux_arc_account_code_hash UNIQUE (account_id, code_hash),
    DROP INDEX ux_arc_code_hash;

ALTER TABLE email_verification_challenges
    ADD INDEX ix_evc_expires_at (expires_at);

ALTER TABLE mfa_challenges
    ADD INDEX ix_mfa_expires_at (expires_at);

ALTER TABLE sessions
    ADD INDEX ix_sessions_revoked_at (revoked_at),
    ADD INDEX ix_sessions_absolute_expires_at (absolute_expires_at),
    ADD INDEX ix_sessions_last_seen_at (last_seen_at);
