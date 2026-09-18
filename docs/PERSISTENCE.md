# BitosX API — Persistence

Status: **Persistence Foundation.** Schema and data-access plumbing exist; no
account/auth behavior (registration, login, token issuance, email/SMS) is
implemented yet.

## Engine and data-access stack

- **Database engine:** MariaDB 11.8 (LTS), local only.
- **Driver:** `MySqlConnector` (ADO.NET) — full MariaDB support, native .NET 10.
- **Mapping:** `Dapper` (snake_case ↔ PascalCase via `MatchNamesWithUnderscores`).
- **Migrations:** versioned `.sql` scripts embedded in `BitosX.Infrastructure`,
  applied in filename order by `SqlMigrationRunner`, tracked in a
  `schema_migrations` table (idempotent).

> **Why not EF Core?** As of this milestone there is no stable, production-
> suitable EF Core 10-compatible **MariaDB** provider (Pomelo is EF Core 9 only;
> Oracle's EF Core 10 provider targets MySQL, not MariaDB). We deliberately use
> MySqlConnector + Dapper to stay on .NET 10 / EF Core 10 with no downgrade and
> no pre-release dependencies. Re-evaluate if Pomelo ships EF Core 10.

## Database boundaries and ownership

- Dedicated database: **`bitosx`** (dev) and an isolated **`bitosx_test`** used
  only by integration tests.
- Dedicated least-privilege application user: **`bitosx_app`@`127.0.0.1`**
  (TCP loopback). Not `root`, and not any legacy/vault user.
- Grants are scoped **only** to `bitosx.*` and `bitosx_test.*` (DML + the DDL
  needed to run migrations). No global data privileges; `USAGE ON *.*` is only
  the connect placeholder.

## Local-only database access

- MariaDB listens on **`127.0.0.1:3306` only** (verified with `ss -ltnp`); it is
  not reachable publicly. The default Ubuntu bind-address was not changed.
- The driver connects over TCP loopback. MySqlConnector does not use Unix
  sockets, so the app account is `@'127.0.0.1'` (not the socket-only
  `@'localhost'`).

## Credential handling

- The connection string (including the DB password) is **never** committed. It
  is not in `appsettings*.json`, source, docs, or tests.
- Development/tests read it from **.NET user-secrets**:
  - API (`UserSecretsId: bitosx-api`): `ConnectionStrings:Bitosx`
  - Tests (`UserSecretsId: bitosx-infrastructure-tests`): `ConnectionStrings:BitosxTest`
- Production secret injection will be designed separately (not app-embedded).

## Schema (initial migration `0001_initial_account_schema.sql`)

All ids are UUID (`CHAR(36)`), non-sequential and externally safe; DB auto-
increment ids are never exposed. All timestamps are UTC `DATETIME(6)`.

| Table | Purpose | Key columns |
|---|---|---|
| `accounts` | Account identity | `id` PK, `email`, `normalized_email` (UNIQUE), `email_verified_at`, `phone_e164`, `phone_verified_at`, `password_hash` (nullable, future), `created_at`, `updated_at`, `disabled_at` |
| `email_verification_challenges` | Single-use email verification | `id` PK, `account_id` FK→accounts (CASCADE), `token_hash` (SHA-256), `expires_at`, `consumed_at`, `attempt_count` |
| `phone_verification_challenges` | Single-use phone OTP | `id` PK, `account_id` FK→accounts (CASCADE), `pending_phone_e164`, `code_hash` (HMAC-SHA256), `expires_at`, `consumed_at`, `attempt_count`, `max_attempts` |
| `sessions` | Session anchor | `id` PK, `account_id` FK→accounts (CASCADE), `created_at`, `last_seen_at` (idle), `absolute_expires_at`, `revoked_at`, `user_agent` |
| `refresh_tokens` | Rotation / reuse detection | `id` PK, `session_id` FK→sessions (CASCADE), `token_hash` (UNIQUE, SHA-256), `expires_at`, `consumed_at`, `revoked_at`, `replaced_by_token_id` FK→refresh_tokens (SET NULL) |
| `schema_migrations` | Applied-migration ledger | `id` PK, `applied_at` |

**Unique constraints:** `accounts.normalized_email`, `refresh_tokens.token_hash`.
**Foreign keys:** all children cascade from `accounts`; `refresh_tokens.session_id`
cascades from `sessions`; `refresh_tokens.replaced_by_token_id` self-references
(SET NULL). Indexes exist on every FK column.

## Zero-knowledge exclusions (hard rule)

No table or column stores, or may ever store:

- vault master password, raw Vault Key, decrypted vault contents,
- vault item passwords, or vault TOTP secrets.

All account secrets are stored **only as hashes**, never plaintext:
`password_hash` (future account password), `token_hash` (email/refresh),
`code_hash` (phone OTP). The account password is separate from the vault master
password. See [`SECURITY_MODEL.md`](SECURITY_MODEL.md).

## Migration 0002 (account registration + email verification)

`0002_account_registration_email_verification.sql` adds:
- `email_verification_challenges.invalidated_at DATETIME(6) NULL` — distinct from
  `consumed_at`. Active challenge := `consumed_at IS NULL AND invalidated_at IS NULL
  AND expires_at > now`. Verify sets `consumed_at`; resend sets `invalidated_at`.
- `UNIQUE INDEX ux_evc_token_hash` on `email_verification_challenges(token_hash)`
  (lookup by verifier + collision safety). Note: `token_hash` holds
  `HMAC-SHA256(pepper, token)` (0001's "SHA-256" comment is superseded; 0001 unchanged).
- `email_outbox` table: durable, encrypted email queue. Columns include `challenge_id`
  (FK → challenge, `ON DELETE CASCADE`), `recipient_email`, `payload_version`,
  `payload_nonce`/`payload_ciphertext`/`payload_tag` (AES-256-GCM; zeroed on terminal
  state), retry/lease columns (`available_at`, `attempt_count`, `locked_until`,
  `locked_by`), and `sent_at`/`failed_at`. Index `ix_outbox_due`.

`accounts` is unchanged: `password_hash VARCHAR(255)` is set (from NULL) at verification.
The runtime account performs only DML on these tables; the migrator applies `0002`.

## Migration procedure

1. Author the next script as `NNNN_description.sql` under
   `src/BitosX.Infrastructure/Persistence/Migrations/` (embedded resource).
2. Review the SQL before applying.
3. `SqlMigrationRunner.ApplyMigrationsAsync` applies pending scripts in order and
   records them; already-applied scripts are skipped.
4. Integration tests apply migrations to `bitosx_test` on startup.

## Backup considerations (future)

- Logical backups via `mariadb-dump` of the `bitosx` schema, stored off-box and
  encrypted; restic/borg or provider snapshots for the data directory.
- Backups contain only hashed secrets (never vault plaintext), but still hold
  personal data (emails, phone numbers) and must be encrypted at rest and
  access-controlled. Backup/restore automation is out of scope for this milestone.

## Future authentication relationships

- Registration will create an `accounts` row + an `email_verification_challenges`
  row; email confirmation sets `email_verified_at`.
- Phone verification promotes `pending_phone_e164` → `accounts.phone_e164` and
  sets `phone_verified_at` only on success.
- Login will create a `sessions` row and an initial `refresh_tokens` row; refresh
  rotates tokens (`consumed_at` + `replaced_by_token_id`) with **strict reuse detection**
  (any presentation of a `consumed_at`/`revoked_at` token revokes the whole session and
  its active tokens; no grace window). The refresh `token_hash` is `SHA-256(raw 32 token
  bytes)` — no pepper/secret (the token is 256 CSPRNG bits); email/phone `*_hash` HMACs are
  separate systems and unchanged.
- Access tokens (15-min JWTs) are stateless and are not stored.
