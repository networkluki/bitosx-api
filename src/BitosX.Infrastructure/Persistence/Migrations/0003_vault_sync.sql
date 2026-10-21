-- BitosX encrypted-envelope sync (migration 0003).
--
-- One row per account: the desktop vault file exactly as the client uploaded it. The envelope is
-- ciphertext under a key derived from the master password on the device; the server stores and
-- returns the bytes and never has, and never needs, anything that could decrypt them. The
-- fingerprint is SHA-256 over those bytes — a public value the client uses to tell whether its
-- file matches the server's copy. Revisions are compare-and-set: a client names the revision it
-- last saw, and the row changes only if that is still the current one.
--
-- Zero-knowledge boundary unchanged: no master password, no vault key, no plaintext, no item.
CREATE TABLE vault_blobs (
    account_id   CHAR(36)      NOT NULL,
    revision     BIGINT        NOT NULL,          -- 1, 2, 3, ...; the client's base revision + 1
    size_bytes   INT           NOT NULL,
    fingerprint  VARBINARY(32) NOT NULL,          -- SHA-256 of the envelope bytes (public)
    envelope     MEDIUMBLOB    NOT NULL,          -- the encrypted vault, opaque to the server (<= 16 MiB)
    created_at   DATETIME(6)   NOT NULL,
    updated_at   DATETIME(6)   NOT NULL,
    CONSTRAINT pk_vault_blobs PRIMARY KEY (account_id),
    CONSTRAINT fk_vault_blobs_account FOREIGN KEY (account_id)
        REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
