-- BitosX Persistence Foundation — initial account schema.
--
-- Zero-knowledge boundary: NO column here stores vault master passwords, vault
-- keys, vault secrets, vault TOTP secrets, or any vault plaintext. All account
-- secrets (password, tokens, OTP codes) are stored only as hashes, never as
-- plaintext. All timestamps are UTC DATETIME(6).

-- ---------------------------------------------------------------------------
-- accounts
-- ---------------------------------------------------------------------------
CREATE TABLE accounts (
    id                 CHAR(36)      NOT NULL,
    email              VARCHAR(320)  NOT NULL,
    normalized_email   VARCHAR(320)  NOT NULL,
    email_verified_at  DATETIME(6)   NULL,
    phone_e164         VARCHAR(16)   NULL,
    phone_verified_at  DATETIME(6)   NULL,
    password_hash      VARCHAR(255)  NULL,
    created_at         DATETIME(6)   NOT NULL,
    updated_at         DATETIME(6)   NOT NULL,
    disabled_at        DATETIME(6)   NULL,
    CONSTRAINT pk_accounts PRIMARY KEY (id),
    CONSTRAINT ux_accounts_normalized_email UNIQUE (normalized_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- email_verification_challenges
-- ---------------------------------------------------------------------------
CREATE TABLE email_verification_challenges (
    id            CHAR(36)      NOT NULL,
    account_id    CHAR(36)      NOT NULL,
    token_hash    VARBINARY(32) NOT NULL,     -- SHA-256 of token; never plaintext
    created_at    DATETIME(6)   NOT NULL,
    expires_at    DATETIME(6)   NOT NULL,
    consumed_at   DATETIME(6)   NULL,          -- single-use marker
    attempt_count INT           NOT NULL DEFAULT 0,
    CONSTRAINT pk_email_verification_challenges PRIMARY KEY (id),
    CONSTRAINT fk_evc_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE,
    INDEX ix_evc_account_id (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- phone_verification_challenges
-- ---------------------------------------------------------------------------
CREATE TABLE phone_verification_challenges (
    id                 CHAR(36)      NOT NULL,
    account_id         CHAR(36)      NOT NULL,
    pending_phone_e164 VARCHAR(16)   NOT NULL, -- pending until verified; not on account yet
    code_hash          VARBINARY(32) NOT NULL, -- HMAC-SHA256 of OTP; never plaintext
    created_at         DATETIME(6)   NOT NULL,
    expires_at         DATETIME(6)   NOT NULL, -- TTL policy: 10 minutes
    consumed_at        DATETIME(6)   NULL,      -- single-use marker
    attempt_count      INT           NOT NULL DEFAULT 0,
    max_attempts       INT           NOT NULL DEFAULT 5,
    CONSTRAINT pk_phone_verification_challenges PRIMARY KEY (id),
    CONSTRAINT fk_pvc_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE,
    INDEX ix_pvc_account_id (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- sessions
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id                  CHAR(36)     NOT NULL,
    account_id          CHAR(36)     NOT NULL,
    created_at          DATETIME(6)  NOT NULL,
    last_seen_at        DATETIME(6)  NOT NULL, -- idle-lifetime tracking (30 days)
    absolute_expires_at DATETIME(6)  NOT NULL, -- absolute-lifetime cap (90 days)
    revoked_at          DATETIME(6)  NULL,
    user_agent          VARCHAR(255) NULL,
    CONSTRAINT pk_sessions PRIMARY KEY (id),
    CONSTRAINT fk_sessions_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE,
    INDEX ix_sessions_account_id (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- refresh_tokens
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id                   CHAR(36)      NOT NULL,
    session_id           CHAR(36)      NOT NULL,
    token_hash           VARBINARY(32) NOT NULL, -- SHA-256 of 256-bit opaque token; never plaintext
    created_at           DATETIME(6)   NOT NULL,
    expires_at           DATETIME(6)   NOT NULL,
    consumed_at          DATETIME(6)   NULL,       -- rotation marker (reuse detection)
    revoked_at           DATETIME(6)   NULL,
    replaced_by_token_id CHAR(36)      NULL,       -- rotation chain
    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT ux_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_session FOREIGN KEY (session_id)
        REFERENCES sessions (id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_tokens_replaced_by FOREIGN KEY (replaced_by_token_id)
        REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    INDEX ix_refresh_tokens_session_id (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
