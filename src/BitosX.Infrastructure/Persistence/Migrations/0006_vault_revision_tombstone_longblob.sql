-- BitosX encrypted-envelope sync: revisions never restart, 16 MiB really fits (migration 0006).
--
-- 1. envelope becomes LONGBLOB. MEDIUMBLOB holds at most 16,777,215 bytes, one byte less than the
--    16 MiB (16,777,216 bytes) the API and the desktop client accept.
-- 2. envelope and fingerprint become nullable. DELETE /v1/sync/envelope no longer removes the row: it
--    clears the envelope and keeps the revision as a tombstone, so the next upload continues at the
--    previous revision + 1 and a device that recorded an old revision can never mistake a new lineage
--    for the one it saw. A row with envelope IS NULL means "nothing stored" (the API answers 404).
--    The row still disappears with the account (ON DELETE CASCADE).
--
-- Zero-knowledge boundary unchanged: the envelope stays ciphertext under a key the server never has.
ALTER TABLE vault_blobs
    MODIFY COLUMN envelope    LONGBLOB      NULL,
    MODIFY COLUMN fingerprint VARBINARY(32) NULL;
