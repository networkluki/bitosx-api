-- BitosX password reset (migration 0004).
--
-- Password-reset challenges reuse email_verification_challenges and the transactional email outbox
-- (same HMAC verifier, TTL, single-use, invalidation and delivery machinery), distinguished by a
-- `purpose` column so a token issued for one purpose can never be consumed for another:
--   email_verification : activates an unverified account and sets its first password
--   password_reset     : replaces the password of a verified account and revokes its sessions
--
-- Account deletion needs no schema: every account-owned row (challenges, outbox rows via their
-- challenge, sessions, refresh tokens via their session, vault_blobs) already cascades from accounts.
--
-- Zero-knowledge boundary unchanged: a reset changes only the ACCOUNT password hash. The vault
-- envelope stays ciphertext under the master password, which the server never has.
ALTER TABLE email_verification_challenges
    ADD COLUMN purpose VARCHAR(32) NOT NULL DEFAULT 'email_verification' AFTER account_id;

CREATE INDEX ix_evc_account_purpose
    ON email_verification_challenges (account_id, purpose);
