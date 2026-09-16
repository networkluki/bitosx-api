# BitosX API — Account Registration + Email Verification (Design Spec v2)

- **Status:** DESIGN — v2 FINAL (all approval decisions incorporated; approved for implementation planning). No code, packages, migrations, or secrets created by this document.
- **Date:** 2026-09-16
- **Repository:** `networkluki/bitosx-api` — branch `main` — HEAD `a7fe248`
- **Milestone scope:** account registration + account-password hashing + email ownership verification + Gmail delivery via a **transactional outbox**. **Nothing else.**
- **Out of scope (hard):** login, JWT, refresh-token issuance, sessions, logout, forgot/reset password, phone verification, TOTP, passkeys, vault sync, billing, desktop integration, public exposure, the public verification web page.

**v2 amendments (approved):** resend included (§3, §10); silent duplicate-registration for verified accounts, no notice email (§6, §12); **synchronous request-path SMTP removed** — replaced by a **transactional outbox** + background dispatcher (§9, §9A–§9D); encrypted outbox token payload with an independent `Security:EmailOutboxKey` (AES-256-GCM) (§9B); at-least-once delivery semantics + crash window (§9D); resend concurrency via row locking (§10); fragment-based future verification link (§14); benchmarked Argon2 concurrency matrix (§4.4); single consolidated migration `0002` (§11); expanded rate-limiting plan (§17); fresh self-review (§18).

---

## 1. Zero-knowledge boundary (unchanged, reaffirmed)

Account authentication and vault cryptography remain completely separate. The API/server MUST NEVER receive or store the vault master password, raw Vault Key, decrypted vault contents, vault item passwords, or vault TOTP secrets.

The **account password** here is ONLY the BitosX online-account password — not the vault master password, not a vault encryption key, not a vault recovery key. No code path accepts, derives from, or stores vault key material. A full compromise of this API must not directly reveal or decrypt vault data.

This milestone adds only: an account-password **hash** (never plaintext); an email-verification **token verifier** (never the plaintext token in the challenge table); and a **short-lived, encrypted** outbox copy of the verification token needed to send the email (§9B). All three are independent of, and cannot decrypt, vault data. The three server secrets introduced/used — account-password hashing (no separate key; salt is in the PHC string), `Security:EmailVerificationPepper` (HMAC), and `Security:EmailOutboxKey` (AES-256-GCM) — are mutually independent and independent of vault cryptography.

---

## 2. Current state (inspected, not assumed)

Verified by reading the repository at HEAD `a7fe248`:

- **`accounts`** (`0001`): `id CHAR(36)` PK, `email VARCHAR(320)`, `normalized_email VARCHAR(320)` UNIQUE, `email_verified_at`, `phone_e164`, `phone_verified_at`, `password_hash VARCHAR(255)` (nullable, unused), `created_at`, `updated_at`, `disabled_at`. `DATETIME(6)` UTC.
- **`email_verification_challenges`** (`0001`): `id` PK, `account_id` FK→accounts (CASCADE), `token_hash VARBINARY(32)`, `created_at`, `expires_at`, `consumed_at`, `attempt_count`. Index `ix_evc_account_id`. **No index on `token_hash`.**
- Other tables untouched. Data access: MySqlConnector 2.6.2 + Dapper 2.1.86 + embedded SQL migrations (`SqlMigrationRunner`), `MatchNamesWithUnderscores = true`.
- `AccountRepository` opens a connection per call — no shared transaction yet; this milestone needs multi-statement atomicity (§9).
- DB identities: `bitosx_app` (runtime DML-only on `bitosx.*`), `bitosx_migrator` (DDL on `bitosx.*` + SELECT/INSERT on `schema_migrations`), `bitosx_test_app` (DML+DDL on `bitosx_test.*`), `bitosx_test_runtime` (DML-only on `bitosx_test.*`). **No grant changes required** — runtime performs only DML (incl. the outbox); the migrator applies `0002`.
- API host: minimal-API, RFC7807 via `UseExceptionHandler`, correlation-id middleware (no body/header logging), empty `/v1` seam, DI endpoint-contribution seam (test-only), Kestrel loopback-only, 64 KB body cap.
- `password_hash VARCHAR(255)` fits an Argon2id PHC string (≈90–110 chars) → no `accounts` change. `token_hash VARBINARY(32)` fits a 32-byte HMAC verifier; it needs a UNIQUE index (§11).

`0001` is applied+pushed and MUST NOT be edited. All changes go in a new `0002` (specified §11; **not written** now).

---

## 3. Proposed endpoints

Under the existing `/v1` group; JSON bodies; errors via the existing RFC7807 pipeline.

| Method | Path | Purpose | Success |
|---|---|---|---|
| POST | `/v1/auth/register` | Create unverified account + enqueue verification email (outbox) | `202 Accepted` (generic) |
| POST | `/v1/auth/verify-email` | Consume a verification token, mark email verified | `200 OK` (generic) |
| POST | `/v1/auth/resend-verification` | Replace challenge for an unverified account + enqueue email (outbox) | `202 Accepted` (generic) |

Resend is **included** (approved Q1). No login/JWT/session/reset endpoints.

---

## 4. Account password hashing

### 4.1 Library options (verified against NuGet)

| Option | Package | net10 | Notes |
|---|---|---|---|
| **A (recommended)** | `Konscious.Security.Cryptography.Argon2` 1.3.1 (net8.0) | ✔ | Most-used managed Argon2; no native dep; we own the PHC codec |
| B | `Isopoh.Cryptography.Argon2` 2.0.0 (net7.0/netstandard2.0) | ✔ | Built-in PHC + `SecureArray` buffer wiping; smaller ecosystem |
| C | `NSec.Cryptography` 26.4.0 (net9.0) / libsodium | ✔ | Native/audited; libsodium forces `p=1`; deployment dep |

**Decision: A** — Konscious for Argon2id + a BitosX-owned PHC codec (explicit, versioned, testable format; no native dep on the 1-vCPU VM). Isopoh is the documented fallback (its `SecureArray` reduces derived-buffer lifetime, §4.5). Vault KDF code is never referenced or copied.

### 4.2 Stored format (self-describing PHC)
`accounts.password_hash` = `$argon2id$v=19$m=<KiB>,t=<t>,p=<p>$<b64 salt>$<b64 hash>`. Encodes algorithm, version, params, 16-byte random salt (per call), 32-byte hash. Enables future param upgrades via a `NeedsRehash` signal with no schema change. Fits `VARCHAR(255)`.

### 4.3 Hasher interface + behavior
`IAccountPasswordHasher`: `string Hash(string password)`; `PasswordVerificationResult Verify(string password, string encodedHash)` → `{ Success, Failed, NeedsRehash, InvalidHashFormat }`. Parse/version/algorithm errors → `InvalidHashFormat` (never throws; callers treat as non-match). Byte comparison uses `CryptographicOperations.FixedTimeEquals`. Verify is defined now, exercised only by tests (no login this milestone).

### 4.4 Argon2 parameters — benchmarked concurrency (amended)

Hardware: **1 vCPU, ~1 GB RAM.** Fixed: `p = 1` (no benefit on 1 vCPU; extra lanes multiply memory). Hashing runs behind a `SemaphoreSlim` of size `HashingMaxConcurrency`. **Hard invariant:** `memoryKiB × HashingMaxConcurrency ≤ 192 MiB`.

Candidate params: `m ≈ 46 MiB (47104 KiB)`, `t = 3`, `p = 1`.

**`maxConcurrency` is NOT assumed to be 3.** The implementation-phase benchmark on `bitosx-prod` MUST measure `maxConcurrency ∈ {1, 2, 3}` and record, for each:
- single-hash latency (no contention),
- p50 and p95 latency under sustained concurrent load at that cap,
- process RSS / working-set memory,
- CPU saturation (1 vCPU),
- throughput (hashes/sec).

Selection rule: keep the `memory × cap ≤ 192 MiB` budget **and** avoid pathological p95 latency on the single vCPU. **A cap of 1 or 2 may be preferable** to 3 (a single core cannot truly run 3 memory-hard hashes in parallel; higher caps mainly add latency + memory pressure). The benchmark determines the final `(m, t, p=1, maxConcurrency)`, recorded in `docs/SECURITY_MODEL.md` with the measured numbers. Candidate values are the documented starting point/range, not placeholders.

### 4.5 Plaintext-password limitation
Plaintext is used only to compute the hash; never stored/returned/logged; lifetime minimized. **Managed `string` cannot be reliably zeroed** (inherent runtime limitation) — documented, not silently assumed. (Isopoh `SecureArray` mitigates derived buffers but not the inbound `string`.)

---

## 5. Password input policy
Min **12**, max **128** characters. Used **exactly as supplied**: no trim, no case folding, no Unicode normalization (deliberate, documented — normalization would change the credential). No composition rules. Validation failure → specific, safe `400` ProblemDetails (not enumeration-sensitive).

---

## 6. Registration flow (`POST /v1/auth/register`)

Request: `{ "email": "...", "password": "<12..128>" }`. No other fields (no vault password/key, username, phone, TOTP, recovery). Unknown fields ignored.

Steps:
1. **Bounds validation:** endpoint body cap (≤4 KB); email syntactically valid (§6.1); password length 12–128. Failure → `400` ProblemDetails.
2. **Normalize email** (`EmailNormalizer`: trim + invariant upper-case). Keep original `email` for display; use `normalized_email` for uniqueness/lookup.
3. **Hash the password unconditionally** (Argon2id, behind the semaphore) *before* branching — timing equalization (§12). Discarded if not creating.
4. **Branch by normalized email** (DB uniqueness authoritative, step 5):
   - **New:** in ONE transaction (§9A) insert account (unverified, `password_hash=<phc>`), insert challenge (verifier only), insert outbox row (encrypted token payload, §9B); commit. Delivery happens later via the dispatcher (§9C). **No SMTP in the request path.**
   - **Existing + unverified:** **do nothing here** — return the generic `202`. Recovery for a stalled registration is `POST /v1/auth/resend-verification` (explicitly, per approval), not repeated registration. Do not alter the password, do not create a challenge/outbox row.
   - **Existing + verified (or disabled):** **silent** — create nothing, enqueue nothing, **send no email** (approved Q2: a duplicate-registration email would be a mail-bombing primitive). Return the same generic `202`.
5. **Uniqueness enforced by DB** unique `normalized_email`; the create path catches `DuplicateKeyEntry` and converts it to the "existing" outcome (closes check-then-insert race).
6. **Response:** always `202 Accepted`, generic body (§12), independent of branch (timing equalized). Internal logs distinguish outcomes by correlation id + account id — never secrets, never full email in routine info logs.

Note vs v1: because register no longer performs synchronous SMTP, the "existing-unverified → resend inline" behavior is removed; registration never enqueues for an existing account. This keeps register's DB+outbox work uniform for the *new* path and trivial for existing paths, and moves all re-send logic to the dedicated endpoint (cleaner, and avoids register doubling as a resend oracle/abuse vector).

### 6.1 Email syntax validation
Lightweight non-authoritative check (single `@`, non-empty local/domain, ≤320 chars, no whitespace/control). No DNS/MX. True validity is proven only by verification.

---

## 7. Email verification token

- **Token:** 32 random bytes (256-bit) from `RandomNumberGenerator`; Base64URL (unpadded) transport.
- **Verifier (challenge table):** `HMAC-SHA256(EmailVerificationPepper, tokenBytes)` → 32 bytes in `email_verification_challenges.token_hash`. **Plaintext token is never stored in the challenge table and never logged.**
- **Lookup identity:** verifier alone identifies the challenge (§7.2). Verify request carries only `{ "token": ... }`; **no account id** required or accepted.
- **Pepper:** `Security:EmailVerificationPepper`, server secret (user-secrets locally; production injection later); never DB/Git. Rotation invalidates outstanding challenges (acceptable; users resend).

### 7.1 HMAC+pepper vs plain SHA-256 — explicit
A 256-bit random token makes plain `SHA-256(token)` already adequate against offline brute force. We still choose `HMAC-SHA256(pepper, token)` deliberately for: defense-in-depth (a DB-only leak yields verifiers useless without the out-of-DB pepper), design consistency with the phone OTP (which *needs* keying due to low entropy), and negligible cost. **Explicit choice: HMAC-SHA256 with a server pepper.**

### 7.2 No AccountId binding (contrast with phone OTP)
Phone OTP binds AccountId because a 6-digit code is low-entropy/reused; the email token is 256-bit unique so it self-identifies. Binding would force the request/link to carry an internal account id for no security gain. **Verifier = `HMAC(pepper, token)` without AccountId**; the challenge row's `account_id` tells us which account to verify after lookup. **Answer: account identity is not supplied on verify.**

---

## 8. Email verification policy
TTL **30 minutes** (`expires_at = created_at + 30m`, server UTC only; client timestamps never trusted). **Single use** (`consumed_at`). Success atomically sets `accounts.email_verified_at` + challenge `consumed_at` (§9.2/verify). Server time via injected `TimeProvider` (BCL); production `TimeProvider.System`. `attempt_count` retained for observability; no lockout this milestone (token is unguessable).

---

## 9. Transactional outbox architecture (amended — SMTP removed from request path)

### Why (timing side-channel)
v1's "commit → synchronous Gmail SMTP → respond" leaks account existence: a new registration incurs Gmail/network latency while an existing one does not, so response time distinguishes them even with an identical body. **Resolution: never send SMTP in the HTTP request path.** Registration/resend only write to the DB (account/challenge/outbox) and return; a background dispatcher sends later. New and existing paths now differ only by bounded, local DB work (plus the constant Argon2 hash from §6 step 3), not by network SMTP latency.

### §9A — Registration transaction (atomic)
For a successful NEW registration, ONE DB transaction atomically:
1. insert `accounts` (unverified),
2. insert `email_verification_challenges` (verifier only),
3. insert `email_outbox` (encrypted payload, §9B),
4. **commit.**

Only after commit is anything sent, and sending is out-of-band. The HTTP response (`202`) returns immediately after the DB commit. Transactions are encapsulated by coarse Infrastructure store methods (chosen over a general UnitOfWork, YAGNI): `IAccountRegistrationStore.CreateUnverifiedAccountWithChallengeAndOutboxAsync(account, challenge, outboxMessage)` runs all inserts in one transaction and converts a `normalized_email` duplicate-key into an `EmailAlreadyExists` result (no rows written). No network I/O occurs while the transaction/locks are held.

### §9B — Outbox data model + payload protection

New table `email_outbox` (columns; final SQL in §11, not written now):

| Column | Type | Purpose |
|---|---|---|
| `id` | `CHAR(36)` PK | message id (UUID) |
| `message_type` | `VARCHAR(64)` | e.g. `email_verification` |
| `recipient_email` | `VARCHAR(320)` | delivery address (account data, not a secret) |
| `payload_version` | `TINYINT UNSIGNED` | envelope/format version (starts at 1) |
| `payload_nonce` | `VARBINARY(12)` | AES-GCM 96-bit nonce (unique per row) |
| `payload_ciphertext` | `VARBINARY(…)` | AES-256-GCM ciphertext of the JSON payload |
| `payload_tag` | `VARBINARY(16)` | AES-GCM 128-bit auth tag |
| `created_at` | `DATETIME(6)` | enqueue time (UTC) |
| `available_at` | `DATETIME(6)` | earliest next attempt (for backoff) |
| `attempt_count` | `INT` | delivery attempts |
| `last_attempt_at` | `DATETIME(6) NULL` | last try |
| `sent_at` | `DATETIME(6) NULL` | success marker |
| `failed_at` | `DATETIME(6) NULL` | permanent-failure marker (max attempts exhausted) |
| `locked_until` | `DATETIME(6) NULL` | worker lease (concurrency guard, §9C) |
| `locked_by` | `VARCHAR(64) NULL` | worker/instance id holding the lease |

Indexes: PK(`id`); `ix_outbox_due (sent_at, failed_at, available_at, locked_until)` to fetch due, unsent, unfailed, unleased rows efficiently.

The row stores **no** account password, password hash, SMTP password, pepper, Gmail credential, or **plaintext verification token**.

**Payload protection (encrypted at rest):** the worker needs the raw verification token to build the email link, but the token must not sit in the DB as plaintext. The payload — a small JSON object, conceptually `{ "v":1, "accountId":"…", "token":"<base64url>", "expiresAtUtc":"…", "toAddress":"…" }` — is encrypted with **AES-256-GCM** under `Security:EmailOutboxKey` and stored as (`payload_nonce`, `payload_ciphertext`, `payload_tag`), with `payload_version` selecting the envelope/key schedule.
- **AEAD:** .NET `System.Security.Cryptography.AesGcm` (AES-256-GCM). 12-byte nonce, 16-byte tag.
- **AAD:** the outbox `id` (and `payload_version`) are passed as GCM associated data so ciphertext cannot be transplanted to another row.
- **Nonce:** 96-bit random from `RandomNumberGenerator` per row (never reused under the key). Random 96-bit nonces are safe well beyond the tiny message volume here; nonce-reuse risk is documented and bounded (§18). Payload versioning allows a future switch to a deterministic/counter nonce or key rotation without ambiguity.
- The `email_verification_challenges` table still stores **only** `HMAC(token)` — never the plaintext token, encrypted or otherwise. The encrypted token lives only in the outbox, only until delivery or expiry.

**Retention + data minimization (final):** two distinct retention concepts, documented to avoid ambiguity:
- **Live encrypted verification-token payload** (`payload_ciphertext`/`payload_nonce`/`payload_tag`): short-lived. It is **erased (overwritten with zero-length/zero bytes)** as soon as the message reaches a terminal state:
  - *On success* (`sent_at` set): the dispatcher zeroes `payload_ciphertext`/`payload_nonce`/`payload_tag` **in the same UPDATE** that sets `sent_at`. We never retain usable verification-token material after delivery (the token is single-use post-verify regardless).
  - *On terminal failure / expiry* (`failed_at` set): the dispatcher likewise zeroes the payload columns in the same UPDATE. A **cleanup pass runs at most every ≤ 24 hours** and proactively marks-failed + erases the payload of any row whose associated verification token has expired (see §9C eligibility) even if the dispatcher never picked it up. **No live encrypted verification-token payload persists longer than ~24 h**, and in practice far less (token TTL is 30 min).
- **Sanitized delivery metadata** (`id`, `message_type`, `recipient_email`, `created_at`, `available_at`, `attempt_count`, `last_attempt_at`, `sent_at`, `failed_at` — the payload columns already zeroed): may be retained **up to 7 days** for observability, then the row is deleted. This 7-day window applies **only** to metadata rows whose encrypted payload has already been erased — never to live encrypted token payloads.

**Threat model (explicit):**
- *DB read-only compromise (leaked backup / read injection):* attacker sees challenge verifiers (useless without pepper) and outbox ciphertext (useless without `EmailOutboxKey`, held outside the DB). No usable verification token is exposed. Account password is only an Argon2id hash.
- *Full app compromise:* attacker holds pepper + `EmailOutboxKey` + DB → can read pending tokens; this is game-over regardless (they could also mint sessions once login exists). The outbox encryption specifically defends the **DB-only** leak, which is the realistic exfiltration path.
- *In transit:* MariaDB is loopback-only; SMTP is STARTTLS with cert validation.

### §9C — Background email dispatcher
`IEmailOutboxDispatcher` implemented by an ASP.NET Core `BackgroundService` (`EmailOutboxBackgroundService`) hosted **inside `BitosX.Api`** (no separate systemd worker yet). It:
- Polls for **due** rows: `sent_at IS NULL AND failed_at IS NULL AND available_at <= now AND (locked_until IS NULL OR locked_until < now)`, ordered by `available_at`, in small batches.
- **Leases** each row before sending to avoid duplicate concurrent processing: a conditional `UPDATE … SET locked_until = now + lease, locked_by = @id WHERE id=@id AND (locked_until IS NULL OR locked_until < now)` and proceeds only if 1 row was affected (atomic claim; safe even if multiple dispatcher instances ever run).
- **Expiry pre-check before every send attempt (hard invariant):** after claiming the lease and **before** decrypting/sending, the dispatcher re-checks eligibility against server `TimeProvider` UTC: the row is unsent/unfailed **and** the associated verification challenge is not consumed and **not expired** (`expires_at > now`). The dispatcher **MUST NEVER send a verification email after its token/challenge has expired.** If expired (or the challenge is gone/consumed): **do not send**, set `failed_at = now` (terminal — "expired"), **zero `payload_ciphertext`/`payload_nonce`/`payload_tag`**, release the lease. Recovery is a fresh challenge via `resend-verification`. The token TTL is never extended because Gmail was unavailable.
- **Decrypts the payload only immediately before delivery**, in memory, and sends via `IEmailSender` (§13). Never logs the token, the decrypted payload, or SMTP credentials.
- On **success (Gmail accepted):** set `sent_at = now`, clear the lease, and **zero the ciphertext/nonce/tag** (single UPDATE).
- On **transient failure:** increment `attempt_count`, set `last_attempt_at`, set `available_at = now + backoff(attempt_count)` (bounded exponential backoff with jitter), release the lease — **but only if the next attempt would still fall inside the token lifetime**; otherwise treat as expired (above). **`MaxAttempts = 6`**; the entire retry schedule fits comfortably inside the 30-minute token TTL (concrete delays specified in the implementation plan; tested via `TimeProvider`, no real sleeping). After `MaxAttempts` set `failed_at` (permanent; no more sends), zero the payload, and log a non-sensitive alert (correlation id + outbox id + recipient **domain** only).
- Is **cancellation-aware** (honors the host `stoppingToken`); a lease naturally expires so a crash mid-send does not wedge a row.
- Never surfaces SMTP/Gmail error text to API clients (it runs off-request).
- All time comparisons use the injected `TimeProvider` (UTC); client timestamps are never trusted.

### §9D — Delivery semantics (at-least-once)
Exactly-once SMTP is impossible. Design for **at-least-once**: duplicate delivery of the same verification link is acceptable because verification is single-use (§8) and duplicates cannot create multiple valid tokens (the token is generated once, at enqueue; the dispatcher never mints tokens). Concurrent workers avoid the same row via the lease (§9C). Retry state is explicit (`attempt_count`, `available_at`, `locked_until`, `failed_at`).
**Documented crash window:** Gmail may accept a message just before the process crashes and before `sent_at` is written; on restart the row is re-leased and re-sent → the user may receive a duplicate email. **Accepted.** It never creates multiple valid tokens (same single token) and never changes account state. A duplicate delivery re-sends the *same* single verification link, so it also never creates a second valid challenge.

### §9E — EmailOutboxKey rotation (v1: drain-then-rotate)

v1 uses **drain-then-rotate**; multi-key decryption / versioned keyrings are **not** implemented now (`payload_version` remains in the schema/envelope so a key-versioned multi-read design can be added later without a table redesign). Documented procedure:
1. Prevent new outbox enqueue operations (pause registration/resend enqueue, or take the API out of the enqueue path).
2. Pause the dispatcher (stop the `BackgroundService` / disable processing).
3. Drain pending valid messages (let the dispatcher finish them) **or** intentionally expire/purge them (mark failed + zero payloads). Because verification payloads are short-lived (30-min TTL), draining is fast.
4. Confirm **no row contains an encrypted payload requiring the old key** — i.e. every non-terminal row's payload columns are erased/absent (query for rows with non-null `payload_ciphertext`).
5. Rotate `Security:EmailOutboxKey` (new random 256-bit) in the secret store.
6. Restart the dispatcher / re-enable enqueue.
7. Verify delivery end-to-end with the new key (a controlled test enqueue).

**Safety rule:** if pending encrypted rows cannot be safely drained (step 4 fails), **do NOT rotate the key** — rotating would strand those payloads (they would fail decryption, be marked expired/failed, and require resend). This is acceptable for v1 precisely because verification payloads are intentionally short-lived; a stranded payload only costs the user a resend, never account corruption.

---

## 10. Resend verification (`POST /v1/auth/resend-verification`) — concurrency-safe

Request: `{ "email": "..." }`. Behavior:
- Always return the same generic `202` (anti-enumeration, §12); never reveal existence/verified/disabled state; never expose token/account state.
- **Only unverified accounts** get a new challenge. Verified/disabled/unknown → do nothing, generic `202`.
- For an unverified account, in ONE DB transaction with row locking:
  1. `SELECT … FOR UPDATE` the account row by `normalized_email` (serializes concurrent resends for that account),
  2. invalidate ALL active challenges for the account (`UPDATE email_verification_challenges SET consumed_at = now WHERE account_id=@id AND consumed_at IS NULL`),
  3. insert exactly one fresh challenge (new 256-bit token → new HMAC verifier, new 30-min expiry),
  4. insert exactly one `email_outbox` row (encrypted payload, §9B),
  5. **commit**,
  6. return generic `202`.
- **No SMTP and no network I/O inside the transaction / while holding locks.** Delivery is via the dispatcher (§9C).
- **Concurrent-resend guarantee:** the `FOR UPDATE` account lock serializes step 2–4, so two simultaneous resends cannot leave two active challenges — the second waits, then invalidates the first's new challenge before creating its own. At most one active challenge per account at any time.
- **Anti-mail-bomb guard (pre-public):** reject issuing a new challenge if the account's newest active challenge is younger than a minimum interval (e.g. 60 s) — still returns the generic `202`, but enqueues nothing. This is a stopgap; real rate limiting (§17) is the production control.

Only the HMAC verifier is stored in the challenge table; the plaintext token exists only inside the encrypted outbox payload until delivery.

---

## 11. Database changes — consolidated migration

**NEW MIGRATION REQUIRED: YES** — a single coherent registration migration **`0002_account_registration_email_verification.sql`** (contents specified; **not written** now):
- `CREATE UNIQUE INDEX ux_evc_token_hash ON email_verification_challenges (token_hash);` (lookup by verifier + collision/idempotency safety).
- `CREATE TABLE email_outbox (...)` per §9B, with `ix_outbox_due` and a PK; `ENGINE=InnoDB`, `utf8mb4`.
- No `accounts` change (`password_hash VARCHAR(255)` already fits the PHC string).
- `0001` unchanged. Filename-ordered, tracked in `schema_migrations`, idempotent — consistent with the existing runner (no runner change). Migrator applies to `bitosx`; tests apply to `bitosx_test`. No grant changes.

---

## 12. Email enumeration defense
- `register` and `resend` always return an identical generic `202`:
  `{ "message": "If the address can be registered or needs verification, check your email." }`
- No field/status distinguishes new / existing-unverified / existing-verified / disabled.
- **Timing:** (a) **SMTP is off the request path** (§9) — the dominant network-latency oracle is eliminated; (b) `register` still **always performs one Argon2 hash** so the constant CPU cost dominates and the create/exist branches are indistinguishable; (c) both endpoints do only bounded local DB work. `resend`'s branches are cheap/uniform and rate-limited in production.
- `verify-email` returns generic failure for invalid/expired/consumed/unknown and generic success on valid.
- Internal logs record the outcome by correlation id + account id — never token, verifier, password, hash, decrypted payload, or (in routine info logs) full email.

---

## 13. SMTP / email delivery
- **Library:** MailKit 4.18.0 (+ MimeKit 4.18.0) — native `net10.0`.
- **Transport:** `smtp.gmail.com:587`, **STARTTLS** (`SecureSocketOptions.StartTls`), TLS cert validation **enabled**. Forbidden/NOT implemented: plaintext SMTP, insecure fallback, cert-validation bypass / allow-invalid-certs, hardcoded creds.
- **Auth:** Gmail username + **App Password** (account has 2FA + app password). From config/secret store only.
- **Failure isolation:** SMTP/Gmail exceptions are caught by the dispatcher and mapped to `EmailSendResult.Failed`; logged without credentials/token/decrypted payload/Gmail server text. Never surfaced to API clients (delivery is off-request anyway).
- **Abstraction:** `IEmailSender.SendAsync(EmailMessage, ct)`; `EmailMessage { ToAddress, ToDisplayName?, Subject, TextBody, HtmlBody }`. Application never references MailKit types. Infrastructure `MailKitGmailEmailSender` implements it. Tests use `FakeEmailSender` (in-memory); **automated tests never send real Gmail**. A real Gmail smoke test, if added later, is manual, opt-in, secret-backed, excluded from normal runs.

### 13.1 Configuration keys (secret vs non-secret) — never committed/logged
- `Email:SmtpHost=smtp.gmail.com`, `Email:SmtpPort=587`, `Email:SmtpUsername` (Gmail addr), `Email:FromAddress`, `Email:FromName`
- `Email:SmtpAppPassword` — **SECRET**
- `Email:PublicBaseUrl` (config-driven; e.g. future `https://vault.bitosx.se`), `Email:VerificationPath=/verify-email`
- `Security:EmailVerificationPepper` — **SECRET** (HMAC, §7)
- `Security:EmailOutboxKey` — **SECRET** (AES-256-GCM, §9B); random 256-bit; user-secrets locally; never Git/DB/appsettings; independent from the pepper, from account-password hashing, and from vault crypto
- `Email:Outbox:MaxAttempts`, `:PollInterval`, `:BatchSize`, `:LeaseSeconds`, `:BackoffBaseSeconds`, `:RetentionDays` — non-secret
- `Security:Argon2:MemoryKiB/Iterations/Lanes/MaxConcurrency` — non-secret, benchmark-locked (§4.4)

No real Gmail address/credential is created or requested by this document.

---

## 14. Email content + verification link
Two variants (plain-text + HTML) built by an Application `IVerificationEmailComposer` from `{ toAddress, verificationUrl, expiresAtUtc, expiresInMinutes }` using injected `Email:*` options.

Must contain: BitosX identity/sender; the reason; expiry (valid 30 minutes); the verification action; and an "if you didn't request this, ignore" line. Must NOT contain: password, password hash, DB detail, internal/host IPs, debug data, stack traces, or vault information.

**Verification link (amended, fragment-based):** `${Email:PublicBaseUrl}${Email:VerificationPath}#token=<base64url>`, e.g. `https://vault.bitosx.se/verify-email#token=…`. The **URL fragment (`#…`) is not sent to the web server** in the HTTP request, so the token never lands in web-server/proxy access logs. The future browser page reads the fragment client-side and POSTs the token in the JSON body to `POST /v1/auth/verify-email`; the **API only ever accepts the token in a POST body, never a query string.** The public page is NOT implemented this milestone. Base URL is config-driven; no publicly reachable link is assumed in local dev. Tests read the token from `FakeEmailSender` (and/or decrypt the test outbox payload with the test `EmailOutboxKey`) and call the API directly.

---

## 15. Application interfaces + Infrastructure components

**Application (`BitosX.Application`) — no DB/MailKit types:**
- `IAccountPasswordHasher` (+ `PasswordVerificationResult`), `Argon2ParametersOptions`.
- `IEmailVerificationTokenFactory`: `GenerateToken()` → `{ string TokenBase64Url, byte[] VerifierHash }`; `ComputeVerifier(tokenBase64Url)` → `byte[]` (uses injected pepper).
- `IEmailSender`, `EmailMessage`; `IVerificationEmailComposer`, `EmailOptions`.
- `IOutboxPayloadProtector`: `ProtectedOutboxPayload Protect(OutboxPayload)` / `OutboxPayload Unprotect(ProtectedOutboxPayload)` (AEAD abstraction; impl in Infrastructure using `EmailOutboxKey`). Application defines the plaintext model + interface; keys/AesGcm live in Infrastructure.
- Use-case services: `IAccountRegistrationService.RegisterAsync(RegisterCommand)`, `IEmailVerificationService.VerifyAsync(VerifyEmailCommand)` / `.ResendAsync(ResendCommand)`. Commands/results are Application types with generic result enums (no secrets).
- `AccountPasswordPolicy` (12..128).
- Persistence intents: `IAccountRegistrationStore`, `IEmailVerificationStore`, `IEmailOutboxStore` (enqueue within a caller-provided transaction; claim/lease due rows; mark sent/failed; cleanup). Existing `IAccountRepository` retained for reads.
- Server time via injected `TimeProvider`.

**Contracts (`BitosX.Contracts`):** `RegisterRequest{Email,Password}`, `VerifyEmailRequest{Token}`, `ResendVerificationRequest{Email}`, `AcceptedResponse{Message}`. No entity/DB types; no password/token/hash fields on responses.

**Infrastructure (`BitosX.Infrastructure`):**
- `Argon2idPasswordHasher` (+ owned `Argon2PhcString` codec) with the concurrency semaphore.
- `HmacEmailVerificationTokenFactory` (RNG + HMAC pepper).
- `AesGcmOutboxPayloadProtector : IOutboxPayloadProtector` (AES-256-GCM, `EmailOutboxKey`, per-row random nonce, AAD = outbox id + version).
- `MailKitGmailEmailSender : IEmailSender`.
- `AccountRegistrationStore`, `EmailVerificationStore`, `EmailOutboxStore` (transactional; `FOR UPDATE`/conditional updates/lease claims), over `BitosxConnectionFactory`.
- `EmailOutboxBackgroundService : BackgroundService` (dispatcher, §9C).
- `AddBitosxAccounts(...)` DI extension: registers the above, binds `Email:*`/`Security:*` options, and adds the hosted dispatcher; wired from `Program.cs` only when configured. All DB/SMTP/crypto wiring stays in Infrastructure.

**API (`BitosX.Api`):** `AuthEndpoints.MapAuthEndpoints(this IEndpointRouteBuilder v1)` mapping the three POSTs under `/v1/auth`, delegating to Application services; endpoint body cap; RFC7807 errors.

---

## 16. Test plan (automated tests never send real Gmail; integration uses `bitosx_test` + isolated identities)

**Password hashing (unit):** hash succeeds/PHC; verify success; wrong→Failed; distinct salts; malformed→InvalidHashFormat (no throw); unknown algo/version→InvalidHashFormat; outdated params→NeedsRehash; PHC codec round-trip + malformed rejection.

**Policy (unit):** accept 12 & 128; reject 11 & 129; no trim/case/normalize (exact string only verifies).

**Token/verifier (unit):** 256-bit, Base64URL-decodable; verifier deterministic per token+pepper, 32 bytes; different pepper → different verifier.

**Outbox payload protector (unit):** protect→unprotect round-trips; wrong key fails (auth-tag); tampered ciphertext/tag/nonce fails; AAD mismatch (wrong outbox id) fails; nonces differ across two protects of the same payload; ciphertext does not contain the plaintext token bytes.

**Email composer (unit):** text+HTML contain BitosX identity, 30-min expiry, configured base URL + token, and the "ignore" line; contain no password/hash/verifier/DB detail/IP.

**Registration (integration + fake sender):** valid → unverified account persisted, `password_hash` is a PHC (not plaintext), one challenge with `token_hash` (not plaintext token), one outbox row whose ciphertext is not the plaintext token; uniqueness enforced (DB) with existing handled as generic 202; duplicate-email anti-enumeration (verified & unverified → same 202, and existing paths enqueue nothing / send nothing); password too short/long → 400; invalid email → 400; DB failure → 500 ProblemDetails no leak; **timing-equalization**: Argon2 invoked on existing-email path too (spy hasher counts invocations).

**Outbox dispatcher (integration; `TimeProvider` fake clock, no real sleeping):** a due row is claimed via lease and only one worker processes it (two claim attempts → exactly one succeeds); success sets `sent_at` and zeroes ciphertext/nonce/tag; transient failure increments `attempt_count`, sets backoff `available_at`, releases lease; after `MaxAttempts=6` sets `failed_at`, zeroes payload, stops; dispatcher never logs token/decrypted payload/credentials (capturing logger); cancellation stops the loop cleanly.
- **Never-send-after-expiry invariant (required):** a pending row whose challenge is **not yet expired** IS delivered (fake sender receives it). A pending row whose challenge **has expired** (advance the fake clock past `expires_at`) is **NOT delivered** — no `IEmailSender` call — and is marked `failed_at` with payload columns zeroed.
- **Payload erasure (required):** after a successful send, payload columns are zeroed but sanitized metadata remains; after an expiry/terminal-failure, payload columns are zeroed. Cleanup deletes sanitized metadata rows older than 7 days; the ≤24 h cleanup marks-failed + erases any expired-but-unsent row's payload.
- **Duplicate delivery (required):** re-processing the same row (simulated crash before `sent_at`) sends the same link again and does **not** create a second challenge row or a second valid token.

**Verification (integration):** valid → 200, `email_verified_at` set + challenge `consumed_at` set atomically; expired (via `TimeProvider`) → generic failure; invalid/unknown → generic failure; already-consumed → generic failure; concurrent double-verify of the same token → exactly one succeeds; atomic both-or-neither; no plaintext token persisted in the challenge table (`token_hash == HMAC(pepper,token)`).

**Resend (integration):** unverified → all prior active challenges invalidated + exactly one new challenge + one outbox row, new expiry; verified/disabled/unknown → generic 202, nothing enqueued; **concurrency:** two simultaneous resends for one account → at most one active challenge afterward (FOR UPDATE serialization); min-interval guard rejects immediate re-issue (no new row) while returning generic 202.

**Security (unit + integration):** zero-knowledge model/DTO guard extended (no vault master password/Vault Key/vault secret/vault TOTP anywhere; account exposes only `PasswordHash`; challenge exposes only hash; outbox exposes no plaintext token; DTOs expose no password/token/hash); plaintext password absent from models/DTOs; plaintext token absent from challenge table + DB (outbox stores only ciphertext); SMTP/pepper/outbox-key secrets absent from tracked config (`appsettings*.json` asserted free of `SmtpAppPassword`/`Pepper`/`EmailOutboxKey`); error responses contain no SQL/stack/SMTP/Gmail/path/crypto internals.

---

## 17. Rate limiting (mandatory before public exposure)
Deferred while local-only; **production blockers**, documented in `docs/SECURITY_MODEL.md`:
- **`/register`:** per-IP and per-normalized-email limits (create attempts/hour), backoff/lockout; bot mitigation.
- **`/resend-verification`:** stricter per-account and per-IP limits (this triggers outbound mail) + the §10 min-interval guard; per-account daily send cap.
- **`/verify-email`:** per-IP limits + backoff (defends against automated token probing despite high entropy).
- **Global outbound-email budget:** a hard cap / circuit breaker on total emails/hour so a bug or abuse cannot exhaust the Gmail quota or trip spam flagging (the dispatcher honors it).
- **Argon2 concurrency cap** (in-process, present now) + request rate limiting to prevent hashing DoS.
- **Future adaptive Turnstile/CAPTCHA** on register/resend.
A working local flow is not production-ready; these gates precede any public exposure.

---

## 18. Security self-review (v2 — fresh, focus areas addressed)

- **Account-enumeration timing:** SMTP removed from request path (§9); register always hashes once (§6/§12); both endpoints do only bounded local DB work → no new/exist timing distinguisher. ✔
- **Token leakage from outbox:** challenge table stores only `HMAC(token)`; the raw token exists only inside an **AES-256-GCM-encrypted** outbox payload keyed by an out-of-DB secret, zeroed on send and purged on retention. DB-only leak exposes no usable token. ✔ (Residual: full-app compromise exposes pending tokens — game-over regardless; documented threat model §9B.)
- **Token leakage in logs:** dispatcher/services never log token, verifier, decrypted payload, password, hash, or SMTP/outbox secrets; correlation-id middleware logs no bodies; API accepts token only in POST body (fragment link keeps it out of web-server logs). ✔
- **Nonce reuse (AES-GCM):** 96-bit random nonce per row from CSPRNG, never reused under `EmailOutboxKey`; volume is tiny; AAD binds ciphertext to its row id; `payload_version` allows a future deterministic-nonce/key-rotation scheme. Nonce-reuse risk documented and bounded. ✔
- **Concurrent dispatch / duplicate processing:** atomic lease claim (`locked_until`/`locked_by` conditional UPDATE, affected-rows=1) ensures one worker per row; lease expiry recovers crashed workers. ✔
- **Resend race conditions:** `SELECT … FOR UPDATE` on the account serializes challenge replacement → at most one active challenge per account; min-interval guard bounds re-issue. ✔
- **Email abuse / mail-bombing:** duplicate-registration sends nothing (Q2 silent); resend is the only user-triggered send and is guarded (min-interval now; per-account/IP + global budget before public). Dispatcher honors a global outbound budget. ✔
- **Transaction boundaries:** account+challenge+outbox committed atomically (§9A); no network I/O under locks/transactions; verify updates are atomic (`FOR UPDATE` + conditional). ✔
- **Crash recovery:** outbox is durable; unsent rows are re-leased and retried (at-least-once). Documented crash window may duplicate an email but never creates multiple valid tokens or partial account state. ✔
- **Token lifetime vs retry schedule:** `MaxAttempts=6` with bounded exponential backoff + jitter, and a per-attempt expiry pre-check (§9C) guarantee the dispatcher never sends after the 30-min token TTL and the whole retry schedule fits inside it; the TTL is never extended for SMTP outages. Automated tests enforce the never-send-after-expiry invariant. ✔
- **Retention ambiguity:** two clearly separated concepts — live encrypted token payload (erased at terminal state; ≤24 h cleanup) vs sanitized metadata (≤7 days, payload already zeroed). No usable token material is retained after delivery/expiry. ✔
- **Secret rotation:** pepper rotation invalidates outstanding challenges (resend recovers). `EmailOutboxKey` rotation is **drain-then-rotate** (§9E), no multi-key read in v1; `payload_version` reserved for a future keyring; do-not-rotate-if-undrained safety rule. Argon2 param upgrade via PHC self-description + `NeedsRehash`. All documented, unambiguous. ✔
- **Managed-string wipe:** inherent limitation documented (§4.5). ✔
- **Uniqueness race:** DB unique constraint authoritative; duplicate-key mapped to existing branch (§6.5). ✔
- **Public-exposure assumptions:** none; fragment link + config base; rate limiting documented as blocker (§14, §17). ✔
- **Zero-knowledge:** no vault field anywhere; the three server secrets are mutually independent and independent of vault crypto (§1). ✔

No unresolved zero-knowledge violation, accidental secret persistence, ambiguity, or inconsistent interface found after this review.

---

## 19. Files that would be created/modified during implementation (not now)

**Created — source:** Contracts `RegisterRequest`/`VerifyEmailRequest`/`ResendVerificationRequest`/`AcceptedResponse`; Application `AccountPasswordPolicy`, `IAccountPasswordHasher`(+result/options), `IEmailVerificationTokenFactory`, `IEmailSender`+`EmailMessage`, `IVerificationEmailComposer`+`EmailOptions`, `IOutboxPayloadProtector`+payload models, `IAccountRegistrationService`/`IEmailVerificationService`(+commands/results), `IAccountRegistrationStore`/`IEmailVerificationStore`/`IEmailOutboxStore`, services `AccountRegistrationService`/`EmailVerificationService`; Infrastructure `Argon2idPasswordHasher`+`Argon2PhcString`, `HmacEmailVerificationTokenFactory`, `AesGcmOutboxPayloadProtector`, `MailKitGmailEmailSender`, `AccountRegistrationStore`/`EmailVerificationStore`/`EmailOutboxStore`, `EmailOutboxBackgroundService`, `AddBitosxAccounts`; migration `0002_account_registration_email_verification.sql`; API `AuthEndpoints`.
**Created — tests:** Application unit tests (hasher, policy, token factory, composer, outbox protector, extended zero-knowledge); shared `FakeEmailSender` + spy hasher; Infrastructure integration tests (registration store, verification store, outbox store + dispatcher, migration 0002); API endpoint tests (register/verify/resend).
**Modified:** `Program.cs` (wire `AddBitosxAccounts` + hosted dispatcher, bind options); `BitosX.Api.csproj`/`BitosX.Infrastructure.csproj` (MailKit, Konscious) + regenerated `packages.lock.json`; `Directory.Build.props` (only if a shared pin helps); `docs/API.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `docs/PERSISTENCE.md`.
**Never created/committed:** Gmail app password, verification pepper, `EmailOutboxKey`, connection strings, any `appsettings.*` secret — all only in user-secrets / future production injection.

---

## 20. Final decisions (all resolved — no open questions)
All prior open questions are now decided and incorporated:
1. **Argon2 params/concurrency:** the on-box benchmark is authoritative (§4.4); measure `maxConcurrency ∈ {1,2,3}` at candidate `m≈46 MiB, t=3, p=1`, honoring `memoryKiB × maxConcurrency ≤ 192 MiB` and avoiding pathological single-vCPU latency (1 or 2 likely preferred; measurements decide). Final values + benchmark evidence recorded in `SECURITY_MODEL.md` during implementation.
2. **Retention:** live encrypted token payload erased at terminal state, ≤24 h cleanup for expired/unsent; sanitized metadata retained ≤7 days then row deleted (§9B).
3. **SMTP retries:** `MaxAttempts=6`, bounded exponential backoff + jitter, never beyond token expiry; per-attempt expiry pre-check; schedule fits inside the 30-min TTL; tested via `TimeProvider` (§9C).
4. **EmailOutboxKey rotation:** drain-then-rotate for v1 (§9E); no multi-key read; `payload_version` reserved for the future; do not rotate if pending encrypted rows cannot be drained.

No TBD/TODO placeholders remain; every security-sensitive choice is explicit.
