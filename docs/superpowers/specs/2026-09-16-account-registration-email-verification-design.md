# BitosX API — Account Registration + Email Verification (Design Spec v3)

- **Status:** DESIGN — v3 (security-hardened: email-first registration + password-at-verification). No code, packages, migrations, or secrets created by this document.
- **Date:** 2026-09-16
- **Repository:** `networkluki/bitosx-api` — branch `main` — HEAD at spec commit `70f3435` (this file amends it).
- **Milestone scope:** email-first account registration + email ownership verification **with account-password creation at verification time** + Gmail delivery via a transactional outbox. **Nothing else.**
- **Out of scope (hard):** login, JWT, refresh-token issuance, sessions, logout, forgot/reset password, phone verification, TOTP, passkeys, vault sync, billing, desktop integration, public exposure, the public verification web page.

**v3 amendments (approved security review):**
1. **Email-first registration** — `POST /v1/auth/register` accepts **only** an email; no password. The account is created with `password_hash = NULL`. This removes the pre-registration account-takeover vector (an initiator can no longer choose a victim's eventual password).
2. **Password created at verification** — `POST /v1/auth/verify-email` accepts `{ token, password }`; the holder of the emailed token chooses the password. Ownership + credential are bound together, atomically.
3. **`invalidated_at`** distinct from `consumed_at` (migration `0002`).
4. **Outbox recipient integrity** — AEAD AAD binds `outbox id + payload_version + message_type + recipient_email` with a canonical length-prefixed encoding; decrypted `toAddress` must equal the row `recipient_email` before send.
5. **PHC parser resource-exhaustion guard** — strict bounds + overflow-safe parsing before any Argon2 allocation.
6. **Honest enumeration wording** — best-effort, not "indistinguishable"; no dummy Argon2 in register.
7. **Stale-outbox invariant** — the dispatcher never sends a link for an invalidated/consumed/expired challenge.
8. **Future login invariant** — an account is login-usable only if `email_verified_at IS NOT NULL AND password_hash IS NOT NULL`.

---

## 1. Zero-knowledge boundary (unchanged, reaffirmed)

Account authentication and vault cryptography remain completely separate. The API/server MUST NEVER receive or store the vault master password, raw Vault Key, decrypted vault contents, vault item passwords, or vault TOTP secrets.

The **account password** (now set at verification time) is ONLY the BitosX online-account password — not the vault master password, not a vault encryption key, not a vault recovery key. No code path accepts, derives from, or stores vault key material. A full compromise of this API must not directly reveal or decrypt vault data.

Three mutually independent server secrets are used, all independent of vault cryptography: account-password hashing (no separate key — the salt is in the PHC string), `Security:EmailVerificationPepper` (HMAC), `Security:EmailOutboxKey` (AES-256-GCM). Persisted forms are one-way/encrypted: password → Argon2id PHC hash; verification token → `HMAC(pepper,token)` in the challenge table; token (transiently, for delivery) → AES-256-GCM ciphertext in the outbox.

---

## 2. Current state (inspected, not assumed)

At HEAD `70f3435` (code unchanged since persistence milestone):
- **`accounts`** (`0001`): `id CHAR(36)` PK, `email VARCHAR(320)`, `normalized_email VARCHAR(320)` UNIQUE, `email_verified_at`, `phone_e164`, `phone_verified_at`, `password_hash VARCHAR(255)` (nullable), `created_at`, `updated_at`, `disabled_at`. `DATETIME(6)` UTC.
- **`email_verification_challenges`** (`0001`): `id` PK, `account_id` FK→accounts (CASCADE), `token_hash VARBINARY(32)`, `created_at`, `expires_at`, `consumed_at`, `attempt_count`. Index `ix_evc_account_id`. **No index on `token_hash`; no `invalidated_at`.** The `0001` comment calls `token_hash` "SHA-256"; the registration subsystem uses **`HMAC-SHA256(pepper, token)`** (both are 32 bytes, so `VARBINARY(32)` fits). `0001` is applied+pushed and MUST NOT be edited — the comment stays as historical text; the discrepancy is documented here and in `0002` (§11).
- Data access: MySqlConnector 2.6.2 + Dapper 2.1.86 + embedded SQL migrations (`SqlMigrationRunner`), `MatchNamesWithUnderscores = true`. `AccountRepository` opens a connection per call (no shared txn) — §9 adds transactional stores.
- DB identities: `bitosx_app` (runtime DML-only on `bitosx.*`), `bitosx_migrator` (DDL on `bitosx.*` + SELECT/INSERT on `schema_migrations`), `bitosx_test_app` (DML+DDL on `bitosx_test.*`), `bitosx_test_runtime` (DML-only). **No grant changes** required.
- API host: minimal-API, RFC7807 via `UseExceptionHandler`, correlation-id middleware (no body/header logging), empty `/v1` seam, DI endpoint-contribution seam, Kestrel loopback-only, 64 KB body cap.
- `password_hash VARCHAR(255)` fits an Argon2id PHC string (≈90–110 chars). `token_hash VARBINARY(32)` fits a 32-byte HMAC verifier; `0002` adds its UNIQUE index + `invalidated_at` + the `email_outbox` table.

---

## 3. Proposed endpoints + contracts

| Method | Path | Request | Success |
|---|---|---|---|
| POST | `/v1/auth/register` | `{ "email": "..." }` | `202 Accepted` (generic) |
| POST | `/v1/auth/verify-email` | `{ "token": "...", "password": "<12..128>" }` | `200 OK` (generic) |
| POST | `/v1/auth/resend-verification` | `{ "email": "..." }` | `202 Accepted` (generic) |

Contracts (`BitosX.Contracts`): `RegisterRequest { string Email }`; `VerifyEmailRequest { string Token, string Password }`; `ResendVerificationRequest { string Email }`; `AcceptedResponse { string Message }`. **No response ever contains** a password, password hash, token, token verifier, or account internals. `RegisterRequest` has **no password field**.

---

## 4. Account password hashing (invoked at verification time)

### 4.1 Library
`Konscious.Security.Cryptography.Argon2` 1.3.1 (net8.0; runs on net10; managed, no native dep) for the Argon2id primitive + a BitosX-owned, **hardened** PHC codec (§4.2–4.3). Fallback: Isopoh 2.0.0. Vault KDF code is never referenced/copied.

### 4.2 Stored format
`accounts.password_hash` = `$argon2id$v=19$m=<KiB>,t=<t>,p=<p>$<b64 salt>$<b64 hash>` (self-describing; enables future upgrades via `NeedsRehash`; fits `VARCHAR(255)`). 16-byte CSPRNG salt/call; 32-byte output.

### 4.3 Hasher interface + hardened parser (resource-exhaustion guard)
`IAccountPasswordHasher`: `Hash(password) → phc`; `Verify(password, encoded) → { Success, Failed, NeedsRehash, InvalidHashFormat }`. Byte comparison via `CryptographicOperations.FixedTimeEquals`. `p=1` fixed; a `SemaphoreSlim(maxConcurrency)` gates the KDF.

**The PHC parser MUST validate strict bounds and use overflow-safe parsing BEFORE any Argon2 invocation or large allocation.** A malformed/corrupted/DB-modified PHC string must never be able to request arbitrarily large `m/t/p` and exhaust memory/CPU. Explicit accepted bounds (constants; anything outside → `InvalidHashFormat`, no allocation, no hashing):
- **Algorithm:** exactly `argon2id`. **Version:** exactly `19` (0x13).
- **Max encoded PHC length:** 512 chars (our strings are ~110; generous but bounded).
- **Salt:** decoded length 8–64 bytes. **Hash:** decoded length 16–64 bytes.
- **Memory `m`:** 8 MiB ≤ m ≤ 1 GiB expressed in KiB (i.e. `8192 ≤ m ≤ 1048576`) — and additionally rejected if `m` exceeds the configured verification ceiling (`Argon2:MaxVerifyMemoryKiB`, default = 4× the current hashing `m`, capped at 1048576).
- **Iterations `t`:** 1 ≤ t ≤ 16.
- **Parallelism `p`:** exactly 1 (we only ever produce `p=1`; any other value → `InvalidHashFormat`).
- **Numeric parsing:** `uint`/`int` via `TryParse` with explicit range checks (no silent overflow); reject non-numeric, leading `+`, or oversized digit runs.
- **Base64:** strict decode; malformed → `InvalidHashFormat`.
Only after all fields pass do we allocate and run Argon2 to verify. This protects the (future) login path and any admin/verify path from a hostile stored hash.

### 4.4 Argon2 parameters — benchmarked concurrency
Hardware: **1 vCPU, ~1 GB RAM.** Fixed `p=1`. `SemaphoreSlim(HashingMaxConcurrency)`. **Hard invariant:** `memoryKiB × HashingMaxConcurrency ≤ 192 MiB`. Candidate `m ≈ 46 MiB (47104 KiB), t=3, p=1`. The on-box benchmark measures `maxConcurrency ∈ {1,2,3}` (single-hash latency, p50/p95 under load, throughput, RSS, CPU saturation, queuing) and selects final values honoring the budget and avoiding pathological single-vCPU latency (1 or 2 likely preferred; measurements decide). Final `(m,t,p=1,maxConcurrency)` + evidence recorded in `SECURITY_MODEL.md` during implementation.

### 4.5 Plaintext-password limitation
Plaintext arrives only at `verify-email`, is hashed immediately, never stored/returned/logged. Managed `string` cannot be reliably zeroed (inherent limitation, documented). Lifetime minimized.

---

## 5. Password input policy (enforced at verification/finalization)
Min **12**, max **128** chars, used **exactly as supplied** (no trim/case/normalize — deliberate). No composition rules. Enforced in `POST /v1/auth/verify-email` (where the password is supplied), not at `register`. Failure → specific, safe `400` ProblemDetails. Argon2 hashing therefore happens when ownership is finalized.

---

## 6. Registration flow (`POST /v1/auth/register`) — email-first

Request: `{ "email": "..." }`. No password/other fields; unknown fields ignored.

Steps:
1. **Validate:** endpoint body cap (≤4 KB); email syntactically valid (§6.1).
2. **Normalize email** (`EmailNormalizer`). Keep original for display.
3. **Branch by normalized email** (DB uniqueness authoritative):
   - **New:** in ONE transaction (§9A) insert account with **`password_hash = NULL`, `email_verified_at = NULL`**; insert challenge (verifier only); insert outbox row (encrypted payload, §9B); commit. Delivery is out-of-band (§9C).
   - **Existing (any state — unverified or verified):** do nothing (create nothing, enqueue nothing, **send no email**). Recovery for a stalled unverified account is `resend-verification`. Duplicate-registration silence prevents mail-bombing existing users.
4. **Uniqueness by DB** unique `normalized_email`; the create path catches `DuplicateKeyEntry` → existing branch (race-safe).
5. **Response:** always `202 Accepted`, generic body (§12).

**No password is accepted, hashed, or stored here** — so there is **no Argon2 work in the register path** (and thus no dummy hashing for timing; see §12). An attacker may start registration for someone else's address but cannot choose the account password; the password is set only by whoever holds the emailed token (§7).

### 6.1 Email syntax validation
Non-authoritative: single `@`, non-empty local/domain, ≤320 chars, no whitespace/control. No DNS/MX. True validity is proven only by verification.

---

## 7. Verification + password creation (`POST /v1/auth/verify-email`)

Request: `{ "token": "...", "password": "<12..128>" }`.

Flow:
1. **Validate password bounds** (§5). Invalid → `400` ProblemDetails (generic-safe; this is input validation, not account state).
2. **Compute verifier** = `HMAC-SHA256(pepper, tokenBytes)` (§7A).
3. **Locate + lock** the challenge by `token_hash` (`SELECT … FOR UPDATE`), joined to its account.
4. **Verify all:** challenge exists; `consumed_at IS NULL`; `invalidated_at IS NULL`; `expires_at > now` (server UTC); **account `email_verified_at IS NULL`** (not already verified). Any failure → generic `Invalid` (no distinction).
5. **Hash the supplied password** (Argon2id, §4) — inside the request but after the lock is held only briefly; note Argon2 is CPU/memory-bound (~200–350 ms) and runs while the row is locked, so the lock is on a single challenge row (not global) and contention is per-token only. (Alternative considered: hash before locking to shorten lock hold; rejected because we must first confirm the challenge is valid/unconsumed to avoid hashing on every bogus token as a DoS amplifier. The `FOR UPDATE` is on one row; concurrent verifies of *different* tokens do not contend.)
6. **In ONE transaction:** `UPDATE accounts SET password_hash=@phc, email_verified_at=@now, updated_at=@now WHERE id=@accountId AND email_verified_at IS NULL` (conditional guard; affected=1 required); `UPDATE email_verification_challenges SET consumed_at=@now WHERE id=@id AND consumed_at IS NULL AND invalidated_at IS NULL` (affected=1 required); commit. If either conditional update affects 0 rows (raced), roll back → generic `Invalid`; the account is not partially activated and the token is not marked consumed.
7. Success → `200` generic.

**The holder of the token chooses the password.** A victim clicking an unsolicited link cannot activate an attacker-known password (the attacker never supplied one). **Future login invariant (documented, login out of scope):** an account is usable for login only if `email_verified_at IS NOT NULL AND password_hash IS NOT NULL`.

### 7A. Token + verifier
256-bit CSPRNG token; Base64URL (unpadded) transport. Challenge stores **only** `HMAC-SHA256(pepper, token)` (32 bytes). No AccountId binding (256-bit token self-identifies; verify carries only token+password, no account id). Explicit choice HMAC+pepper over plain SHA-256: defense-in-depth (DB-only leak yields verifiers useless without the out-of-DB pepper) + consistency with phone OTP; negligible cost. Pepper is `Security:EmailVerificationPepper` (user-secret; never DB/Git). Pepper rotation invalidates outstanding challenges (resend recovers).

---

## 8. Verification policy
TTL **30 minutes** (`expires_at = created_at + 30m`, server UTC; client timestamps never trusted). **Active challenge** := `consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > now`. **Single use.** Successful verification sets `consumed_at = now` (and the account fields, §7). **Resend replacement sets `invalidated_at = now`** on prior active challenges (NOT `consumed_at`, which means "actually verified"). Server time via injected `TimeProvider`. `attempt_count` retained for observability; no lockout (token unguessable).

---

## 9. Transactional outbox (SMTP off the request path)

Rationale unchanged: never send SMTP synchronously in the HTTP request path (removes the network-latency enumeration oracle). Registration/resend only write DB rows and return; a background dispatcher sends later.

### §9A — Registration transaction (atomic)
NEW registration, ONE transaction: insert `accounts` (`password_hash=NULL`, `email_verified_at=NULL`) + insert `email_verification_challenges` (verifier only) + insert `email_outbox` (encrypted, §9B) + commit. Encapsulated by `IAccountRegistrationStore.CreateUnverifiedAccountWithChallengeAndOutboxAsync(...)` which maps a `normalized_email` duplicate-key to `EmailAlreadyExists` (no rows written). No network I/O under the transaction/locks.

### §9B — Outbox data model + authenticated payload

`email_outbox` (final SQL in §11):

| Column | Type | Purpose |
|---|---|---|
| `id` | `CHAR(36)` PK | message id (UUID) |
| `message_type` | `VARCHAR(64)` | e.g. `email_verification` — **AAD-bound** |
| `recipient_email` | `VARCHAR(320)` | delivery address — **AAD-bound + must match decrypted `toAddress`** |
| `payload_version` | `TINYINT UNSIGNED` | envelope version (=1) — **AAD-bound** |
| `payload_nonce` | `VARBINARY(12)` | AES-GCM 96-bit nonce (unique/row) |
| `payload_ciphertext` | `VARBINARY(…)` | AES-256-GCM ciphertext of the payload JSON |
| `payload_tag` | `VARBINARY(16)` | AES-GCM 128-bit tag |
| `created_at` / `available_at` | `DATETIME(6)` | enqueue / earliest-next-attempt |
| `attempt_count` | `INT` | delivery attempts |
| `last_attempt_at` / `sent_at` / `failed_at` | `DATETIME(6) NULL` | state markers |
| `locked_until` / `locked_by` | `DATETIME(6) NULL` / `VARCHAR(64) NULL` | worker lease |

Indexes: PK(`id`); `ix_outbox_due (sent_at, failed_at, available_at, locked_until)`. No password/hash/SMTP-secret/pepper/outbox-key/plaintext-token column.

**Payload (encrypted at rest):** JSON `{ "v":1, "accountId":"…", "token":"<base64url>", "expiresAtUtc":"…", "toAddress":"…" }`, encrypted with **AES-256-GCM** (`System.Security.Cryptography.AesGcm`) under `Security:EmailOutboxKey`, stored as (`payload_nonce`,`payload_ciphertext`,`payload_tag`).
- **Nonce:** 96-bit CSPRNG per row (never reused under the key; volume tiny; documented, §18).
- **AAD (recipient integrity, canonical):** binds `outbox id`, `payload_version`, `message_type`, and `recipient_email`. **Encoding is canonical and unambiguous** — each field is emitted as `uint32 length-prefix (big-endian) || UTF-8 bytes` (id as its 36-char UTF-8, version as its 1-byte value framed the same way), concatenated in a fixed order. No ambiguous raw concatenation. A DB-write attacker without `EmailOutboxKey` cannot alter `recipient_email` (or id/type/version) without breaking the GCM tag → decryption fails.
- **Send-time recipient check:** after decrypt, the dispatcher asserts **decrypted `toAddress` == row `recipient_email`** (defense-in-depth beyond AAD). Mismatch → do not send, mark failed, erase payload, log a non-sensitive integrity failure (outbox id + recipient **domain** only).

**Threat model:** *DB-only leak* → verifiers useless without pepper; outbox ciphertext useless without `EmailOutboxKey`; recipient/type/id/version tamper detected by AAD; password only an Argon2id hash. *Full-app compromise* → holds all secrets → game-over regardless. *In transit* → MariaDB loopback-only; SMTP STARTTLS with cert validation.

**Retention/erasure:** the live encrypted token payload is erased (columns zeroed) as soon as the row reaches a terminal state (`sent_at` set on success, or `failed_at` set on expiry/terminal-failure/integrity-failure), in the same UPDATE. A ≤ 24 h cleanup marks-failed + erases the payload of any expired-but-unsent row. Sanitized metadata (payload columns already zeroed) may be retained ≤ 7 days, then the row is deleted. No usable token material persists beyond delivery/expiry.

### §9C — Background dispatcher (`EmailOutboxBackgroundService` inside `BitosX.Api`)
Polls due rows (`sent_at IS NULL AND failed_at IS NULL AND available_at<=now AND (locked_until IS NULL OR locked_until<now)`), small batches. **Atomic lease** per row (conditional UPDATE, affected=1) prevents duplicate concurrent processing; lease expiry recovers crashed workers.

**Per-row, after lease and BEFORE decrypt/send — hard eligibility invariant (server `TimeProvider` UTC):** the associated challenge must be **present, `consumed_at IS NULL`, `invalidated_at IS NULL`, and `expires_at > now`.** If not (expired, consumed, invalidated by a resend, or missing): **do not send**, set `failed_at=now`, zero payload columns, release lease. This guarantees the dispatcher never sends an obsolete/expired verification link. The token TTL is never extended for Gmail outages.

Then: **recipient integrity check** (§9B) → decrypt in memory (never logged) → send via `IEmailSender`.
- **Success (Gmail accepted):** `sent_at=now`, zero payload, clear lease (one UPDATE).
- **Transient failure:** `attempt_count++`, `last_attempt_at=now`, `available_at=now+backoff(attempt)` (bounded exponential + jitter) and release lease — **only if the next attempt still falls inside the token lifetime**; otherwise mark expired (above). **`MaxAttempts=6`**; whole schedule fits inside the 30-min TTL (concrete delays in the plan; tested via `TimeProvider`, no real sleeping). After `MaxAttempts` → `failed_at`, zero payload, non-sensitive alert.
- Cancellation-aware; never logs token/decrypted payload/SMTP credentials.

### §9D — Delivery semantics (at-least-once)
Exactly-once impossible; design for at-least-once. Duplicate delivery of the *same* link is acceptable (verification single-use; duplicates never create multiple valid tokens — the single token is minted once at enqueue). Lease avoids concurrent double-processing. **Crash window:** Gmail accepts then process crashes before `sent_at` → re-lease + re-send → possible duplicate email. Accepted; never creates a second challenge/token or partial account state.

### §9E — EmailOutboxKey rotation (v1: drain-then-rotate)
No multi-key read in v1 (`payload_version` reserved for the future). Procedure: (1) stop new enqueue; (2) pause dispatcher; (3) drain pending valid messages or expire/purge them (fast — 30-min TTL); (4) confirm no row has a non-null `payload_ciphertext`; (5) rotate `Security:EmailOutboxKey`; (6) restart; (7) verify with a controlled enqueue. **Do not rotate if pending encrypted rows cannot be drained** (they would strand → be marked expired → require resend; acceptable but avoided).

---

## 10. Resend verification (`POST /v1/auth/resend-verification`) — concurrency-safe
Request: `{ "email": "..." }`. Always generic `202`; reveals nothing about existence/verified/disabled.
- **Only unverified accounts** (`email_verified_at IS NULL`) get a new challenge. Verified/disabled/unknown → no-op.
- For an unverified account, ONE transaction with row locking: `SELECT … FOR UPDATE` the account by `normalized_email`; **invalidate all active challenges** (`UPDATE … SET invalidated_at=now WHERE account_id=@id AND consumed_at IS NULL AND invalidated_at IS NULL`); insert one fresh challenge (new token → new HMAC verifier, new 30-min expiry); insert one `email_outbox` row (encrypted); commit; return `202`.
- **No SMTP / network I/O under the transaction/locks.** The `FOR UPDATE` account lock serializes concurrent resends → **at most one active challenge per account.**
- **Anti-mail-bomb guard (pre-public):** reject issuing if the newest active challenge is younger than a configured interval (e.g. 60 s) — still returns `202`, enqueues nothing. Real rate limiting (§17) is the production control.

Prior challenges are marked `invalidated_at` (never `consumed_at`). Their still-pending outbox rows will be dropped by the dispatcher's eligibility check (§9C, §18 stale-outbox invariant).

---

## 11. Database changes — migration `0002`

**NEW MIGRATION REQUIRED: YES** — `0002_account_registration_email_verification.sql` (specified; **not written** now):
- `ALTER TABLE email_verification_challenges ADD COLUMN invalidated_at DATETIME(6) NULL;`
- `CREATE UNIQUE INDEX ux_evc_token_hash ON email_verification_challenges (token_hash);`
- `CREATE TABLE email_outbox (...)` per §9B, with `ix_outbox_due`, `ENGINE=InnoDB`, `utf8mb4`.
- No `accounts` change (`password_hash VARCHAR(255)` fits the PHC string; it is simply set from NULL at verification).
- **Documentation note in `0002`:** the historical `0001` comment describes `token_hash` as "SHA-256"; the implemented subsystem uses `HMAC-SHA256(EmailVerificationPepper, token)` (still 32 bytes). `0001` is **not** rewritten; `0002` records the clarification.
- `0001` unchanged; filename-ordered, tracked in `schema_migrations`, idempotent. Migrator applies to `bitosx`; tests to `bitosx_test`. No grant changes.

---

## 12. Account-enumeration posture (honest wording)
Register/verify/resend return **generic bodies + generic status**. SMTP is off the request path (removes the major network-latency oracle). **However, database work can still differ** between new vs existing, and unverified vs verified branches, so timing-based enumeration is **reduced, not mathematically eliminated.** We do **not** claim branches are "indistinguishable." Since `register` is email-only, we do **not** perform dummy Argon2 work there to fake timing parity (that would only add cost/DoS surface). The honest posture:
- generic response bodies/status; no SMTP in the request path; bounded local DB work only;
- **timing-oracle resistance is best-effort**, hardened further by **mandatory rate limiting and adaptive abuse controls before public exposure** (§17).
Internal logs distinguish outcomes by correlation id + account id — never token, verifier, password, hash, decrypted payload, or (in routine info logs) full email.

---

## 13. SMTP / email delivery
- **Library:** MailKit 4.18.0 (+ MimeKit 4.18.0) — native `net10.0`.
- **Transport:** `smtp.gmail.com:587`, **STARTTLS**, TLS cert validation **enabled**. Forbidden/NOT implemented: plaintext SMTP, insecure fallback, cert-bypass/allow-invalid-certs, hardcoded creds.
- **Auth:** Gmail username + **App Password** (config/secret store only).
- **Failure isolation:** SMTP/Gmail exceptions caught by the dispatcher → generic failure; logged without credentials/token/decrypted payload/Gmail text; never surfaced to clients (off-request).
- **Abstraction:** `IEmailSender.SendAsync(EmailMessage, ct)`; Application never references MailKit types. `FakeEmailSender` for tests; **automated tests never send real Gmail**; a manual, opt-in, secret-backed, excluded-from-CI smoke test may exist.

### 13.1 Configuration (secret vs non-secret) — never committed/logged
`Email:SmtpHost=smtp.gmail.com`, `Email:SmtpPort=587`, `Email:SmtpUsername`, `Email:FromAddress`, `Email:FromName`, `Email:PublicBaseUrl` (config; e.g. `https://vault.bitosx.se`), `Email:VerificationPath=/verify-email`; **SECRET:** `Email:SmtpAppPassword`, `Security:EmailVerificationPepper`, `Security:EmailOutboxKey` (random 256-bit, independent of pepper/password-hashing/vault). Non-secret: `Email:Outbox:{MaxAttempts=6,PollInterval,BatchSize,LeaseSeconds,BackoffBaseSeconds,RetentionDays=7,ExpiredCleanupInterval}`, `Security:Argon2:{MemoryKiB,Iterations,Lanes,MaxConcurrency,MaxVerifyMemoryKiB}`. No real Gmail credential is created/requested by this document.

---

## 14. Email content + verification link
Plain-text + HTML via `IVerificationEmailComposer` from `{ toAddress, verificationUrl, expiresAtUtc, expiresInMinutes }`. Contains: BitosX identity; the reason; expiry (30 min); the verification action; "if you didn't request this, ignore" (which is **not** relied on as a security boundary — the email-first + password-at-verify design is the actual boundary). Must NOT contain password, hash, DB detail, IPs, debug, stack traces, or vault info.

**Fragment-based link:** `${Email:PublicBaseUrl}${Email:VerificationPath}#token=<base64url>` (e.g. `https://vault.bitosx.se/verify-email#token=…`). The **fragment (`#`) is not sent to the web server**, so the token never lands in web/proxy access logs. The future browser page reads the fragment client-side, collects the chosen password, and POSTs `{token,password}` to the API. The **API accepts the token only in a POST body**, never a query string. Public page not built this milestone; base URL config-driven; tests read the token from `FakeEmailSender` (and/or decrypt the test outbox payload) and call the API directly.

---

## 15. Application interfaces + Infrastructure components

**Application (`BitosX.Application`) — no DB/MailKit types:**
- `IAccountPasswordHasher` (+`PasswordVerificationResult`), `Argon2ParametersOptions` (incl. `MaxVerifyMemoryKiB`).
- `IEmailVerificationTokenFactory`: `GenerateToken()`→`{TokenBase64Url, VerifierHash}`; `ComputeVerifier(token)`→`byte[]`.
- `IEmailSender`, `EmailMessage`; `IVerificationEmailComposer`, `EmailOptions`.
- `IOutboxPayloadProtector`: `Protect(OutboxPayload, OutboxAad)`/`Unprotect(ProtectedOutboxPayload, OutboxAad)`; `OutboxAad { id, version, messageType, recipientEmail }` with canonical length-prefixed encoding.
- Services: `IAccountRegistrationService.RegisterAsync(RegisterCommand{email})`; `IEmailVerificationService.VerifyAsync(VerifyEmailCommand{token,password})` / `.ResendAsync(ResendCommand{email})`. Generic result enums; no secrets.
- `AccountPasswordPolicy` (12..128); persistence intents `IAccountRegistrationStore`, `IEmailVerificationStore`, `IEmailOutboxStore`; existing `IAccountRepository` for reads; `TimeProvider`.

**Contracts (`BitosX.Contracts`):** `RegisterRequest{Email}`, `VerifyEmailRequest{Token,Password}`, `ResendVerificationRequest{Email}`, `AcceptedResponse{Message}`.

**Infrastructure (`BitosX.Infrastructure`):** `Argon2idPasswordHasher` (+ hardened `Argon2PhcString` codec), `HmacEmailVerificationTokenFactory`, `AesGcmOutboxPayloadProtector` (AAD canonical), `MailKitGmailEmailSender`, `AccountRegistrationStore`/`EmailVerificationStore`/`EmailOutboxStore` (transactional; `FOR UPDATE`/conditional/lease), `EmailOutboxBackgroundService`, `AddBitosxAccounts` DI extension. All DB/SMTP/crypto wiring in Infrastructure.

**API (`BitosX.Api`):** `AuthEndpoints.MapAuthEndpoints` mapping the three POSTs under `/v1/auth`; RFC7807 errors; endpoint body cap.

---

## 16. Test plan (automated tests never send real Gmail; DB integration uses `bitosx_test` + isolated identities; time via `TimeProvider`)

**Password policy (unit):** accept 12 & 128; reject 11 & 129; no trim/case/normalize (exact string only).

**Hardened PHC codec + hasher (unit):** encode→parse round-trip; hash→verify Success; wrong→Failed; distinct salts; correct-but-outdated params→NeedsRehash. **Resource-exhaustion guard (required):** each of these → `InvalidHashFormat` with **no Argon2 invocation / no large allocation** (assert via a hook/spy that the KDF was not called): enormous `m` (e.g. 9_999_999_999), enormous `t`, `p≠1`/enormous `p`, integer-overflow inputs, oversized salt/hash, decoded salt/hash below min, PHC string beyond max length, malformed base64, unsupported algorithm (`argon2i`/`argon2d`), unsupported version.

**Token/verifier (unit):** 256-bit Base64URL; deterministic 32-byte verifier; different pepper → different verifier.

**Outbox payload protector (unit):** protect→unprotect round-trips; different nonces across two protects; ciphertext ≠ token bytes; wrong key fails; tampered ciphertext/tag/nonce fails; **AAD tamper (required):** changing any of `id`, `payload_version`, `message_type`, `recipient_email` in the AAD causes authentication failure (no plaintext returned); canonical AAD encoding is length-prefixed (a test constructs two different field tuples that would collide under naive concatenation and asserts distinct AAD / decrypt failure).

**Email composer (unit):** text+HTML contain BitosX identity, 30-min expiry, the **fragment** link (`#token=`), and the "ignore" line; contain no password/hash/verifier/DB/IP.

**Registration (integration + fake sender):** valid new email → account persisted with **`password_hash IS NULL`** and `email_verified_at IS NULL`; one challenge (verifier only); one outbox row whose ciphertext ≠ token; response `202`. Existing email (verified & unverified) → identical `202`, **nothing created/enqueued/sent**, no password change. Uniqueness via DB (duplicate handled as existing). Invalid email → `400`. **No Argon2 invoked in register** (spy asserts zero hasher calls).

**Verify + password creation (integration) — pre-registration takeover (required):**
1. "attacker" registers `victim@example.com` (email-only) → account exists with `password_hash IS NULL`.
2. assert `password_hash` is NULL before verification (no attacker-chosen password was ever accepted/stored).
3. "victim" calls verify-email with the emailed token + a victim-chosen password → `200`.
4. assert `password_hash` now verifies the victim's password and never held any other value; `email_verified_at` set; challenge `consumed_at` set — **atomically** (both or neither).
- valid token+password → success as above; **expired** (advance clock) → generic Invalid, account unchanged; invalid/unknown token → Invalid; **already-consumed** → Invalid; **invalidated** (by resend) → Invalid; **already-verified account** → Invalid (cannot re-set password via a stale token); password too short/long → `400` (challenge NOT consumed).
- **Transaction failure:** if the account update or challenge consume conditional-update affects 0 rows (simulated race) → roll back: account remains unverified, `password_hash` stays as it was, token **not** marked consumed; generic Invalid.
- concurrent double-verify of one token+password → exactly one succeeds.
- no plaintext token persisted (challenge `token_hash == HMAC(pepper,token)`).

**Resend (integration):** unverified → all prior active challenges get `invalidated_at` (NOT `consumed_at`) + exactly one new active challenge + one outbox row; verified/disabled/unknown → `202`, nothing enqueued; concurrency: two simultaneous resends → at most one active challenge (FOR UPDATE); min-interval guard rejects immediate re-issue (no new row), still `202`.

**Dispatcher (integration; FakeTimeProvider, FakeEmailSender, no real sleeping):** lease → one worker per row (two claims → one wins); success sets `sent_at` + zeroes payload, metadata remains; transient failure → backoff/reschedule; after `MaxAttempts=6` → `failed_at` + payload zeroed.
- **Never-send-after-expiry (required):** not-yet-expired active row delivered; expired row → NOT delivered, `failed_at` + payload zeroed.
- **Stale-outbox / invalidated challenge (required):** (1) create challenge A + outbox A; (2) resend → A `invalidated_at`, challenge B + outbox B active; (3) dispatcher encounters outbox A → **not sent**, A marked terminal + payload erased; (4) outbox B is the only deliverable → sent once.
- **Recipient integrity (required):** tamper `recipient_email` (or `message_type`/`id`/`payload_version`) on a pending row → decrypt/AAD fails → **not sent**, marked failed, payload erased, only a non-sensitive integrity log; also: decrypted `toAddress` ≠ row `recipient_email` → not sent.
- **Duplicate delivery:** re-process a row (crash before `sent_at`) → same link re-sent, no second challenge/token.
- dispatcher never logs token/decrypted payload/credentials (capturing logger).

**Security (unit + integration):** zero-knowledge model/DTO guard (no vault master password/Vault Key/vault secret/vault TOTP anywhere; account exposes only `PasswordHash`; challenge exposes only hash + `invalidated_at`/`consumed_at`; outbox exposes no plaintext token; DTOs expose no password/token/hash); plaintext password absent from models/DTOs; plaintext token absent from challenge table + DB; `appsettings*.json` free of `SmtpAppPassword`/`Pepper`/`EmailOutboxKey`; error responses contain no SQL/stack/SMTP/Gmail/path/crypto internals.

---

## 17. Rate limiting (mandatory before public exposure — production blockers)
- **`/register`:** per-IP + per-normalized-email limits, backoff; bot mitigation. (Cheap endpoint now, but it enqueues mail for new addresses → must be capped.)
- **`/resend-verification`:** stricter per-account + per-IP limits + §10 min-interval + per-account daily send cap (triggers mail).
- **`/verify-email`:** per-IP limits + backoff (defends token probing despite high entropy; also bounds Argon2 work since hashing now occurs here).
- **Global outbound-email budget / circuit breaker** honored by the dispatcher.
- **Argon2 concurrency cap** (in-process, present) + request rate limiting to prevent hashing DoS at `/verify-email`.
- **Adaptive Turnstile/CAPTCHA** on register/resend.
A working local flow is not production-ready; these gates precede any public exposure.

---

## 18. Security self-review (v3 — fresh, focus areas)
- **Pre-registration account takeover:** ELIMINATED — register accepts no password (`password_hash=NULL`); the password is set only by the token holder at verify-email. A victim clicking an unsolicited link supplies their own password; no attacker-known credential can be activated. ✔
- **Password ownership binding:** password + `email_verified_at` are set together, atomically, in one transaction guarded by conditional updates. ✔
- **Partial activation:** conditional updates (affected=1) + single transaction ensure account is never left with one of {verified, password} without the other; future login invariant requires both non-null. Rolled back on race. ✔
- **Challenge invalidation:** distinct `invalidated_at` vs `consumed_at`; active := neither set and not expired; resend uses `invalidated_at`; verify uses `consumed_at`. No conflation. ✔
- **Stale outbox sends:** dispatcher eligibility check (present, not consumed, not invalidated, not expired) before every send; dedicated test proves an invalidated challenge's outbox is dropped + erased. ✔
- **Recipient-address tampering:** AAD binds id+version+type+recipient (canonical length-prefixed); send-time `toAddress == recipient_email` check; tests prove tamper → no send. ✔
- **AEAD AAD canonicalization:** length-prefixed UTF-8 per field, fixed order — no ambiguous concatenation; test covers a naive-concat collision case. ✔
- **PHC resource exhaustion:** strict bounds + overflow-safe parse + `p=1`-only + memory ceiling, rejected as `InvalidHashFormat` before any Argon2 allocation; tests assert the KDF is not invoked for hostile inputs. ✔
- **Timing enumeration:** wording corrected to best-effort (not "indistinguishable"); no dummy Argon2 in register; rate limiting mandated before public exposure. ✔
- **Nonce reuse (AES-GCM):** 96-bit CSPRNG per row, never reused under the key; volume tiny; AAD binds to row; `payload_version` reserved for future scheme. ✔
- **Concurrent dispatch / resend races:** atomic lease (one worker/row); `FOR UPDATE` account lock (≤1 active challenge). ✔
- **Crash recovery:** durable outbox; at-least-once; documented duplicate window never yields multiple valid tokens or partial state. ✔
- **Secret rotation:** pepper rotation invalidates outstanding challenges (resend recovers); `EmailOutboxKey` drain-then-rotate (§9E); Argon2 upgrade via PHC + `NeedsRehash`. ✔
- **Zero-knowledge:** no vault field anywhere; three server secrets independent of each other and of vault crypto. ✔
- **Managed-string wipe:** documented inherent limitation (§4.5). ✔

No unresolved zero-knowledge violation, accidental secret persistence, ambiguity, inconsistent interface, or unbounded-cost path found after this review. No TBD/TODO placeholders.

---

## 19. Files created/modified during implementation (not now)
As in the plan (`docs/superpowers/plans/2026-09-16-account-registration-email-verification.md`), adjusted for v3: `RegisterRequest{Email}`; `VerifyEmailRequest{Token,Password}`; hardened `Argon2PhcString`; `invalidated_at` in `0002`; canonical-AAD `AesGcmOutboxPayloadProtector`; registration service takes no password; verification service takes password + hasher. Secrets (`SmtpAppPassword`, `EmailVerificationPepper`, `EmailOutboxKey`, connection strings) live only in user-secrets / future production injection — never created or committed here.

## 20. Final decisions (all resolved)
Email-first registration; password created at verify-email; `invalidated_at` added; canonical AAD binding recipient; PHC resource-exhaustion guard; honest enumeration wording; stale-outbox invariant; future login invariant (`email_verified_at` AND `password_hash` both non-null). Argon2 `maxConcurrency` locked by on-box benchmark; retention (≤24 h payload / ≤7 d metadata); `MaxAttempts=6` within TTL; drain-then-rotate key. No open questions; no placeholders.
