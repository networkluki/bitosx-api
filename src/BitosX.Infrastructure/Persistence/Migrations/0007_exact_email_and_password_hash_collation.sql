-- BitosX exact comparison of account identity and password hashes (migration 0007).
--
-- The accounts table was created with utf8mb4_0900_ai_ci, which ignores case, ACCENTS and WIDTH. The
-- application normalizes an email with Trim().ToUpperInvariant() and keys its per-email rate limits on the
-- exact normalized string, but the database compared under that collation, so 'JOSÉ@…', 'JOSE@…' and the
-- full-width 'ＪＯＳＥ@…' were one row for uniqueness and lookup while being three keys for the limiter
-- (bypassing the per-email login limit, and letting a look-alike address squat a registration). The PHC
-- password hash is case-sensitive Base64, yet "password_hash = @expected" re-checks ignored letter case.
--
-- Both columns become utf8mb4_bin: equality is byte-for-byte, exactly what the application compares.
-- Existing rows cannot collide (uniqueness under the looser collation implies uniqueness under the binary
-- one), so the unique index on normalized_email is rebuilt without conflicts.
ALTER TABLE accounts
    MODIFY COLUMN normalized_email VARCHAR(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    MODIFY COLUMN password_hash    VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL;
