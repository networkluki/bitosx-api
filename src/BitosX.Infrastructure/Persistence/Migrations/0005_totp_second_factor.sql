-- BitosX TOTP second factor (migration 0005).
--
-- account_totp holds one encrypted TOTP secret per account (AES-256-GCM under Security:TotpKey, AAD
-- bound to the account id), pending until the first valid code sets confirmed_at. last_used_step is
-- the replay guard: a code is accepted once, and never one for an older step.
-- account_recovery_codes holds keyed verifiers (HMAC-SHA256) of single-use recovery codes.
-- mfa_challenges are the short-lived second-step tokens issued when the password was accepted; only the
-- SHA-256 verifier is stored, plus a fingerprint of the password hash that was verified.
--
-- Zero-knowledge boundary unchanged: the second factor protects the ACCOUNT sign-in. The vault stays
-- ciphertext under the master password, which the server never has.
CREATE TABLE account_totp (
    account_id        CHAR(36)          NOT NULL,
    secret_version    TINYINT UNSIGNED  NOT NULL,
    secret_nonce      VARBINARY(12)     NOT NULL,
    secret_ciphertext VARBINARY(64)     NOT NULL,
    secret_tag        VARBINARY(16)     NOT NULL,
    created_at        DATETIME(6)       NOT NULL,
    confirmed_at      DATETIME(6)       NULL,
    last_used_step    BIGINT            NULL,
    CONSTRAINT pk_account_totp PRIMARY KEY (account_id),
    CONSTRAINT fk_account_totp_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE account_recovery_codes (
    id          CHAR(36)      NOT NULL,
    account_id  CHAR(36)      NOT NULL,
    code_hash   VARBINARY(32) NOT NULL,     -- HMAC-SHA256 verifier; never the code
    created_at  DATETIME(6)   NOT NULL,
    used_at     DATETIME(6)   NULL,
    CONSTRAINT pk_account_recovery_codes PRIMARY KEY (id),
    CONSTRAINT ux_arc_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_arc_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE,
    INDEX ix_arc_account_id (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE mfa_challenges (
    id                        CHAR(36)      NOT NULL,
    account_id                CHAR(36)      NOT NULL,
    token_hash                VARBINARY(32) NOT NULL, -- SHA-256 of the opaque token; never the token
    password_hash_fingerprint VARBINARY(32) NOT NULL, -- SHA-256 of the PHC verified in step one
    user_agent                VARCHAR(255)  NULL,
    created_at                DATETIME(6)   NOT NULL,
    expires_at                DATETIME(6)   NOT NULL,
    consumed_at               DATETIME(6)   NULL,
    attempt_count             INT           NOT NULL DEFAULT 0,
    CONSTRAINT pk_mfa_challenges PRIMARY KEY (id),
    CONSTRAINT ux_mfa_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_mfa_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE,
    INDEX ix_mfa_account_id (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
