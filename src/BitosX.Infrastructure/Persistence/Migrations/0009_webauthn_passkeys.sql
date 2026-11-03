-- BitosX passkeys (WebAuthn), migration 0009.
--
-- Passkeys are added on top of TOTP, never instead of it, and authenticate the ACCOUNT only: the vault stays
-- ciphertext under the master password, which the server never has (zero-knowledge boundary unchanged).
--
-- accounts.webauthn_user_handle: the account's WebAuthn user handle (user.id), 32 random bytes assigned when the
--   account first starts a passkey registration and kept for the account's lifetime. Never the account id or the
--   email, so an authenticator learns nothing about the account from it. Unique: a passwordless sign-in resolves the
--   account from it (together with the credential id).
-- webauthn_credentials: one row per registered passkey. public_key is the COSE public key (nothing secret is stored);
--   credential_id is at most 1023 bytes (WebAuthn §7.1) and unique across all accounts; sign_count is the last
--   signature counter seen (a counter that does not increase is refused as a clone signal); user_handle is the
--   account's handle at registration; aaguid, backup_eligible and backed_up are as the authenticator reported them.
--   Deleting the account deletes its passkeys (cascade).
-- webauthn_challenges: server-side ceremonies, single use (consumed_at), 5 minutes. purpose binds a challenge to
--   what it was issued for: 'register' (bound to the account and to an opaque registration id), 'mfa' (bound to an
--   MFA challenge, hence to its account; one live ceremony per MFA challenge) or 'passwordless' (bound to an opaque
--   assertion id). handle_hash is the SHA-256 of the registration/assertion id, never the id. challenge is the raw
--   random challenge: the WebAuthn library verifies a response against the original bytes, and it is not a secret
--   (the client receives it in the options). Housekeeping deletes expired rows.
--
-- Identifiers are CHAR(36) like every other id in this schema; the collation is the schema's.
ALTER TABLE accounts
    ADD COLUMN webauthn_user_handle BINARY(32) NULL,
    ADD CONSTRAINT ux_accounts_webauthn_user_handle UNIQUE (webauthn_user_handle);

CREATE TABLE webauthn_credentials (
    id              CHAR(36)          NOT NULL,
    account_id      CHAR(36)          NOT NULL,
    credential_id   VARBINARY(1023)   NOT NULL,
    public_key      VARBINARY(2048)   NOT NULL,
    sign_count      BIGINT UNSIGNED   NOT NULL,
    user_handle     BINARY(32)        NOT NULL,
    name            VARCHAR(64)       NOT NULL,
    aaguid          BINARY(16)        NOT NULL,
    backup_eligible TINYINT(1)        NOT NULL,
    backed_up       TINYINT(1)        NOT NULL,
    transports      VARCHAR(255)      NULL,
    created_at      DATETIME(6)       NOT NULL,
    last_used_at    DATETIME(6)       NULL,
    CONSTRAINT pk_webauthn_credentials PRIMARY KEY (id),
    CONSTRAINT ux_wc_credential_id UNIQUE (credential_id),
    CONSTRAINT fk_wc_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE,
    INDEX ix_wc_account_id (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE webauthn_challenges (
    id               CHAR(36)       NOT NULL,
    purpose          VARCHAR(16)    NOT NULL,
    handle_hash      BINARY(32)     NULL,     -- SHA-256 of the registration/assertion id; never the id
    account_id       CHAR(36)       NULL,
    mfa_challenge_id CHAR(36)       NULL,
    challenge        VARBINARY(64)  NOT NULL,
    created_at       DATETIME(6)    NOT NULL,
    expires_at       DATETIME(6)    NOT NULL,
    consumed_at      DATETIME(6)    NULL,
    CONSTRAINT pk_webauthn_challenges PRIMARY KEY (id),
    CONSTRAINT ux_wch_handle_hash UNIQUE (handle_hash),
    CONSTRAINT ux_wch_mfa_challenge UNIQUE (mfa_challenge_id),
    CONSTRAINT ck_wch_purpose CHECK (purpose IN ('register', 'mfa', 'passwordless')),
    CONSTRAINT fk_wch_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE,
    CONSTRAINT fk_wch_mfa_challenge FOREIGN KEY (mfa_challenge_id)
        REFERENCES mfa_challenges (id) ON DELETE CASCADE,
    INDEX ix_wch_account_id (account_id),
    INDEX ix_wch_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
