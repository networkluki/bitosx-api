-- BitosX account registration + email verification schema (migration 0002).
--
-- Note: migration 0001 comments email_verification_challenges.token_hash as
-- "SHA-256". The registration subsystem stores HMAC-SHA256(EmailVerificationPepper,
-- token) there instead (still 32 bytes, so VARBINARY(32) is unchanged). 0001 is
-- applied+immutable and is intentionally NOT rewritten; this is the clarification.
--
-- Zero-knowledge boundary unchanged: no vault master password, Vault Key, vault
-- secret, or vault TOTP is stored anywhere. Account secrets are stored only as
-- hashes; the verification token exists in the outbox only as AES-256-GCM
-- ciphertext, erased on delivery/expiry.

-- ---------------------------------------------------------------------------
-- Distinguish "consumed" (actually verified) from "invalidated" (replaced by a
-- newer challenge on resend). Active := consumed_at IS NULL AND invalidated_at
-- IS NULL AND expires_at > now.
-- ---------------------------------------------------------------------------
ALTER TABLE email_verification_challenges
    ADD COLUMN invalidated_at DATETIME(6) NULL AFTER consumed_at;

-- Enables lookup of a challenge by its token verifier and guarantees collision
-- safety / idempotent inserts.
CREATE UNIQUE INDEX ux_evc_token_hash
    ON email_verification_challenges (token_hash);

-- ---------------------------------------------------------------------------
-- Transactional email outbox. Delivery happens out-of-band (never in the HTTP
-- request path). The verification token lives here only as AES-256-GCM
-- ciphertext (payload_nonce/ciphertext/tag), authenticated against
-- (id, payload_version, message_type, recipient_email); it is zeroed on
-- terminal state.
-- ---------------------------------------------------------------------------
CREATE TABLE email_outbox (
    id                 CHAR(36)          NOT NULL,
    challenge_id       CHAR(36)          NOT NULL,        -- links to the verification challenge
    message_type       VARCHAR(64)       NOT NULL,
    recipient_email    VARCHAR(320)      NOT NULL,
    payload_version    TINYINT UNSIGNED  NOT NULL,
    payload_nonce      VARBINARY(12)     NULL,           -- zeroed on terminal state
    payload_ciphertext VARBINARY(512)    NULL,           -- zeroed on terminal state
    payload_tag        VARBINARY(16)     NULL,           -- zeroed on terminal state
    created_at         DATETIME(6)       NOT NULL,
    available_at       DATETIME(6)       NOT NULL,        -- earliest next attempt (backoff)
    attempt_count      INT               NOT NULL DEFAULT 0,
    last_attempt_at    DATETIME(6)       NULL,
    sent_at            DATETIME(6)       NULL,            -- success marker
    failed_at          DATETIME(6)       NULL,            -- terminal-failure/expiry marker
    locked_until       DATETIME(6)       NULL,            -- worker lease
    locked_by          VARCHAR(64)       NULL,
    CONSTRAINT pk_email_outbox PRIMARY KEY (id),
    CONSTRAINT fk_outbox_challenge FOREIGN KEY (challenge_id)
        REFERENCES email_verification_challenges (id) ON DELETE CASCADE,
    INDEX ix_outbox_due (sent_at, failed_at, available_at, locked_until),
    INDEX ix_outbox_challenge (challenge_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
