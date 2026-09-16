# Implementation Plan — Account Registration + Email Verification

- **Design spec (authoritative):** `docs/superpowers/specs/2026-09-16-account-registration-email-verification-design.md` (committed `70f3435`).
- **Repo:** `networkluki/bitosx-api`, branch `main`. **Local-only; no public exposure.**
- **Method:** strict TDD — every task writes a failing test first (RED, with the expected failure reason), then the minimal implementation to GREEN, then a verification command and a logical commit boundary.
- **Invariants preserved by every task:** no vault master password / Vault Key server-side; no plaintext account password persisted; challenge table stores only `HMAC(token)`; outbox payload encrypted at rest under an independent `EmailOutboxKey`; independent `EmailVerificationPepper`; no synchronous SMTP in the HTTP request path; generic register/resend/verify responses; single-use tokens; MariaDB loopback-only; runtime/migrator DB privilege separation; secrets only in user-secrets (never Git/DB/appsettings/logs).
- **Test hosts:** unit tests in `BitosX.Application.Tests`; DB/dispatcher integration in `BitosX.Infrastructure.Tests` (uses `bitosx_test`, identities `bitosx_test_app`/`bitosx_test_runtime`); endpoint integration in `BitosX.Api.Tests` (WebApplicationFactory + fakes). Time is controlled with `TimeProvider` (`FakeTimeProvider` from `Microsoft.Extensions.TimeProvider.Testing` or a hand-rolled fake — decided in Task 1's package review). No real Gmail send in any automated test.
- **Config/secrets set once (local dev, before endpoint/integration tasks that need them):** `Security:EmailVerificationPepper`, `Security:EmailOutboxKey` (random 256-bit), `Email:*` in the relevant projects' user-secrets. These are set via `dotnet user-secrets` by the operator; **the plan never commits them**. The Gmail app password is only needed for the manual smoke test (Task 12), not for automated tests.

Task ordering respects dependencies: primitives first (hasher, token, crypto), then schema + persistence, then services, then transport, then endpoints, then cross-cutting tests and docs, then full verification.

---

## Task 0 — Package + tooling review (no code)
- **Goal:** confirm exact package versions/TFMs before adding anything (no guessing).
- **Actions:** confirm on NuGet: `Konscious.Security.Cryptography.Argon2` 1.3.1, `MailKit` 4.18.0 (+ `MimeKit` 4.18.0), and a testing time provider (`Microsoft.Extensions.TimeProvider.Testing` latest stable) — record versions. `System.Security.Cryptography.AesGcm` is in the BCL (no package). `RandomNumberGenerator`, `HMACSHA256`, `TimeProvider` are BCL.
- **Output:** the pinned versions used by later tasks; no repo change, no commit.

---

## Task 1 — Argon2 benchmark harness
- **Files:** `tools/BitosX.Benchmarks/BitosX.Benchmarks.csproj` (console, references `BitosX.Infrastructure`); `tools/BitosX.Benchmarks/Argon2Benchmark.cs`. Added to `BitosX.Api.slnx`.
- **Consumes:** the Argon2id hasher (Task 3) — so Task 1's *runnable* benchmark lands after Task 3; however the harness *scaffold* (arg parsing, measurement loop, CSV output) is written here against a tiny local Argon2 call so it compiles. (If cleaner, merge the runnable harness into a step after Task 3; the plan keeps the harness a distinct deliverable.)
- **Produces:** a CLI that, for `maxConcurrency ∈ {1,2,3}` at `m=47104 KiB, t=3, p=1`, measures single-hash latency, p50/p95 under concurrent load, throughput, and prints process RSS + wall-clock; emits a table for `SECURITY_MODEL.md`.
- **RED:** `Argon2BenchmarkTests.HarnessComputesPercentiles_FromSamples` (unit) asserts the percentile/summary math (p50/p95 over a known sample array) — fails: type absent.
- **GREEN:** implement the percentile/summary helper; test passes.
- **Not a unit-tested value:** the actual on-box numbers are produced by *running* the tool on `bitosx-prod` (operator-run), not asserted in CI. The tool is cancellation-aware and never logs secrets (it hashes a fixed dummy password).
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter Argon2BenchmarkTests`; manual `dotnet run --project tools/BitosX.Benchmarks -c Release` on the server (operator) → record results.
- **Commit:** `feat: add Argon2 benchmark harness`.
- **Note:** final `(m,t,p=1,maxConcurrency)` are locked from this tool's output and written into `SECURITY_MODEL.md` in Task 16; Task 3 reads params from config with the candidate defaults until locked.

---

## Task 2 — Account password policy
- **Files:** `src/BitosX.Application/Accounts/AccountPasswordPolicy.cs`; test `tests/BitosX.Application.Tests/AccountPasswordPolicyTests.cs`.
- **Consumes:** nothing. **Produces:** `AccountPasswordPolicy.Validate(string password) → PasswordPolicyResult { Valid, TooShort, TooLong }` (pure; min 12, max 128; no trim/case/normalize).
- **RED:** tests assert accept at 12 and 128; `TooShort` at 11; `TooLong` at 129; a password with leading/trailing spaces and mixed case is accepted **unchanged** (length counted as-is). Fails: type absent (CS0246).
- **GREEN:** implement the pure validator.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter AccountPasswordPolicyTests`.
- **Commit:** `feat: add account password policy (12..128, no normalization)`.

---

## Task 3 — Argon2id password hasher + PHC codec
- **Files:** `src/BitosX.Application/Security/IAccountPasswordHasher.cs`, `PasswordVerificationResult.cs`, `Argon2ParametersOptions.cs`; `src/BitosX.Infrastructure/Security/Argon2PhcString.cs`, `Argon2idPasswordHasher.cs`; tests `tests/BitosX.Application.Tests/Argon2PhcStringTests.cs` and `.../Argon2idPasswordHasherTests.cs` (hasher test lives in Application.Tests referencing Infrastructure, consistent with existing structure, or in Infrastructure.Tests if it needs no DB — placed in Application.Tests as a pure-CPU unit test).
- **Consumes:** `Konscious.Security.Cryptography.Argon2` 1.3.1 (added to `BitosX.Infrastructure.csproj`; lockfiles regenerated). `Argon2ParametersOptions` (m,t,p, maxConcurrency) bound from config with candidate defaults.
- **Produces:** `IAccountPasswordHasher.Hash(password) → phc string`; `Verify(password, encoded) → {Success,Failed,NeedsRehash,InvalidHashFormat}`. PHC codec `Argon2PhcString.Encode(params,salt,hash)` / `TryParse(string, out …)`.
- **RED (codec):** `Argon2PhcStringTests` — encode→parse round-trip yields identical params/salt/hash; `TryParse` returns false (no throw) for: empty, wrong scheme (`$argon2i$`/`$argon2d$`), missing fields, non-base64, unsupported `v`.
- **RED (resource-exhaustion guard, REQUIRED — budget-tied ceilings):** `TryParse`/`Verify` return `InvalidHashFormat` with **the Argon2 KDF never invoked and no large buffer allocated** (injected KDF spy counts invocations) for: enormous `m` (e.g. `9999999999`), `m` above `MaxVerifyMemoryKiB`, enormous `t`, `t` above `MaxVerifyIterations`, `p != 1`/enormous `p`, integer-overflow numeric inputs, PHC > 512 chars, decoded salt <8/>64 B, decoded hash <16/>64 B, malformed base64, unsupported algorithm/version. **Ceilings are budget-derived (not near whole-box):** `MaxVerifyMemoryKiB` defaults to `floor(192 MiB / HashingMaxConcurrency)`, clamped so `MaxVerifyMemoryKiB × HashingMaxConcurrency ≤ 192 MiB` and never below the active hashing `MemoryKiB`; `MaxVerifyIterations` defaults ≈ 2× active `Iterations`, never below it. A test proves the currently-configured hashing params always verify, and that a PHC demanding more than the budget is rejected without hashing (`m = MaxVerifyMemoryKiB + 1` → InvalidHashFormat, KDF spy == 0).
- **RED (hasher):** `Hash` returns `"$argon2id$v=19$…"`; `Verify(correct)`→`Success`; `Verify(wrong)`→`Failed`; two hashes of one password differ; `Verify(password,"garbage")`→`InvalidHashFormat` (no throw); weaker-than-current params→`NeedsRehash`. Fails: types absent.
- **GREEN:** implement the codec with **overflow-safe `TryParse` + strict range checks applied BEFORE any allocation/KDF call**, and the Konscious-backed hasher: 16-byte CSPRNG salt, 32-byte output, `p=1`, params from options, `FixedTimeEquals`, `SemaphoreSlim(maxConcurrency)` gate; `NeedsRehash` when stored params < configured. The KDF is reached only after all bounds pass.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter "Argon2"`.
- **Commit:** `feat: add Argon2id account password hasher and PHC codec`.

---

## Task 4 — Verification token generator + HMAC verifier
- **Files:** `src/BitosX.Application/Verification/IEmailVerificationTokenFactory.cs` (+ `GeneratedToken` record); `src/BitosX.Infrastructure/Security/HmacEmailVerificationTokenFactory.cs`; option `EmailVerificationSecurityOptions { byte[]/string Pepper }`; test `tests/BitosX.Application.Tests/EmailVerificationTokenFactoryTests.cs`.
- **Consumes:** BCL `RandomNumberGenerator`, `HMACSHA256`; pepper from options (user-secret).
- **Produces:** `GenerateToken() → { string TokenBase64Url, byte[] VerifierHash }`; `ComputeVerifier(string tokenBase64Url) → byte[]`.
- **RED:** token decodes from Base64URL to exactly 32 bytes; two tokens differ; `VerifierHash` length 32; `ComputeVerifier(token)` is deterministic and equals the `GenerateToken` verifier; a different pepper yields a different verifier for the same token. Fails: type absent.
- **GREEN:** 32-byte RNG token → Base64URL (unpadded); verifier = `HMACSHA256(pepper, tokenBytes)`.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter EmailVerificationTokenFactoryTests`.
- **Commit:** `feat: add email verification token factory (HMAC verifier)`.

---

## Task 5 — Encrypted outbox payload codec (AES-256-GCM)
- **Files:** `src/BitosX.Application/Email/IOutboxPayloadProtector.cs`, `OutboxPayload.cs` (`{ int Version, Guid AccountId, string TokenBase64Url, DateTime ExpiresAtUtc, string ToAddress }`), `ProtectedOutboxPayload.cs` (`{ byte Version, byte[] Nonce, byte[] Ciphertext, byte[] Tag }`); `src/BitosX.Infrastructure/Email/AesGcmOutboxPayloadProtector.cs`; option `EmailOutboxCryptoOptions { string Key }`; test `tests/BitosX.Application.Tests/AesGcmOutboxPayloadProtectorTests.cs`.
- **Consumes:** BCL `AesGcm`, `RandomNumberGenerator`; 256-bit `EmailOutboxKey` from options (user-secret).
- **Produces:** `Protect(OutboxPayload, OutboxAad) → ProtectedOutboxPayload`; `Unprotect(ProtectedOutboxPayload, OutboxAad) → OutboxPayload`. `OutboxAad { Guid id, byte version, string messageType, string recipientEmail }`. **AAD canonical encoding:** each field as `uint32 big-endian length-prefix || UTF-8 bytes`, concatenated in fixed order (id, version, messageType, recipientEmail) — never raw concatenation.
- **RED:** protect→unprotect round-trips; two `Protect` produce different nonces; ciphertext does not contain the raw token bytes; wrong key → typed authentication failure; tampering ciphertext/tag/nonce → fail; **AAD tamper (REQUIRED):** changing any of `id`, `version`, `messageType`, `recipientEmail` → authentication failure (no plaintext); **canonical-encoding test:** two field tuples that would collide under naive concatenation (e.g. `("ab","c")` vs `("a","bc")`) produce distinct AAD → cross-decrypt fails. Fails: type absent.
- **GREEN:** AES-256-GCM, 12-byte CSPRNG nonce, 16-byte tag; System.Text.Json payload; canonical length-prefixed AAD; `payload_version` selects envelope. Never logs key/plaintext.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter AesGcmOutboxPayloadProtectorTests`.
- **Commit:** `feat: add AES-256-GCM outbox payload protector`.

---

## Task 6 — Migration 0002
- **Files:** `src/BitosX.Infrastructure/Persistence/Migrations/0002_account_registration_email_verification.sql`; test `tests/BitosX.Infrastructure.Tests/Migration0002Tests.cs`.
- **Consumes:** existing `SqlMigrationRunner` (auto-discovers by filename); `bitosx_test` via `bitosx_test_app`.
- **Produces:** `ALTER TABLE email_verification_challenges ADD COLUMN invalidated_at DATETIME(6) NULL;`, `CREATE UNIQUE INDEX ux_evc_token_hash ON email_verification_challenges(token_hash);`, and `CREATE TABLE email_outbox (...)` (columns/indexes per spec §9B) InnoDB/utf8mb4. Includes a SQL comment noting `0001`'s `token_hash` "SHA-256" comment is superseded by `HMAC-SHA256(pepper,token)` (0001 not rewritten).
- **RED:** `Migration0002Tests` (Persistence collection) asserts: `email_verification_challenges.invalidated_at` column exists; `ux_evc_token_hash` unique index exists; `email_outbox` table + expected columns/indexes exist (query `information_schema`). Fails: objects absent (0002 not created yet).
- **GREEN:** add the migration file; runner applies it to `bitosx_test` on fixture init.
- **Verify:** `dotnet test tests/BitosX.Infrastructure.Tests --filter Migration0002Tests`.
- **Operator step (prod):** apply 0002 to `bitosx` with `bitosx_migrator` (documented; run out-of-band, not in CI).
- **Commit:** `feat: add migration 0002 (evc token_hash unique index + email_outbox)`.

---

## Task 7 — Persistence interfaces + transactional stores
- **Files:** `src/BitosX.Application/Abstractions/Persistence/IAccountRegistrationStore.cs`, `IEmailVerificationStore.cs`, `IEmailOutboxStore.cs` (+ result enums); `src/BitosX.Infrastructure/Persistence/AccountRegistrationStore.cs`, `EmailVerificationStore.cs`, `EmailOutboxStore.cs`; tests `tests/BitosX.Infrastructure.Tests/{AccountRegistrationStoreTests,EmailVerificationStoreTests,EmailOutboxStoreTests}.cs`.
- **Consumes:** `BitosxConnectionFactory`, MySqlConnector transactions, Dapper; `OutboxPayload`/protector (Task 5) for building outbox rows in tests.
- **Produces:**
  - `IAccountRegistrationStore.CreateUnverifiedAccountWithChallengeAndOutboxAsync(account, challenge, outboxRow, ct) → {Created, EmailAlreadyExists}` — one transaction: insert account (catch `DuplicateKeyEntry`→`EmailAlreadyExists`, roll back), insert challenge, insert outbox; commit.
  - `IEmailVerificationStore.FindActiveChallengeByVerifierAsync(verifierHash, nowUtc, ct) → ActiveChallengeView?` — **non-locking** read (Phase A) returning `{ challengeId, accountId, expiresAt, consumedAt, invalidatedAt, accountEmailVerifiedAt, accountPasswordHashIsNull }` or null; used only as a cheap pre-check/DoS gate.
  - `IEmailVerificationStore.FinalizeVerificationAsync(verifierHash, passwordHashPhc, nowUtc, ct) → {Verified, InvalidOrExpired}` — **Phase C** one transaction: `SELECT … FOR UPDATE` challenge by `token_hash` (join account); **re-check** `consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > nowUtc AND account.email_verified_at IS NULL AND account.password_hash IS NULL`; conditional `UPDATE accounts SET password_hash=@phc, email_verified_at=now, updated_at=now WHERE id=@accountId AND email_verified_at IS NULL AND password_hash IS NULL` (affected=1) and `UPDATE challenge SET consumed_at=now WHERE id=@id AND consumed_at IS NULL AND invalidated_at IS NULL` (affected=1); if either affected≠1 → roll back → `InvalidOrExpired` (no partial activation, token not consumed); commit. The Argon2 hash is computed by the caller (service) in Phase B before this call; the store only persists the resulting PHC string. **No Argon2 or network I/O runs inside this transaction.**
  - `IEmailVerificationStore.ReplaceActiveChallengeAsync(accountId, newChallenge, newOutboxRow, nowUtc, ct)` — one transaction: `SELECT … FOR UPDATE` account; `UPDATE … SET invalidated_at=now WHERE account_id=@id AND consumed_at IS NULL AND invalidated_at IS NULL` (marks prior active challenges **invalidated**, never consumed); insert new challenge; insert new outbox; commit. Min-interval guard (reject if newest active challenge younger than the configured interval → "skipped" result, enqueues nothing).
  - "Active challenge" everywhere := `consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > now`.
  - `IEmailOutboxStore`: `ClaimDueAsync(nowUtc, leaseUntil, workerId, batchSize, ct) → rows` (atomic lease UPDATE); `MarkSentAndErasePayloadAsync(id, nowUtc, ct)`; `MarkFailedAndErasePayloadAsync(id, nowUtc, ct)`; `RescheduleAsync(id, availableAt, nowUtc, ct)`; `PurgeExpiredPayloadsAsync(nowUtc, ct)`; `DeleteSanitizedOlderThanAsync(cutoffUtc, ct)`.
- **RED (registration store):** insert account+challenge+outbox in one call → all three rows present; duplicate normalized email → `EmailAlreadyExists` and **no** partial rows (transaction rolled back). Fails: type absent.
- **RED (verification store):** `FindActiveChallengeByVerifierAsync` returns a view for an active challenge and null for absent/expired/consumed/invalidated (non-locking, no state change); valid verifier + PHC → `Verified`, `password_hash` + `email_verified_at` set + challenge `consumed_at` set atomically; expired → `InvalidOrExpired`, account unchanged (password stays NULL); already-consumed or `invalidated_at` set → `InvalidOrExpired`; already-verified account → `InvalidOrExpired` (password not overwritten); simulated affected=0 race → roll back, account unverified, token not consumed; two concurrent finalizes of one verifier → exactly one `Verified`. Replace: prior active challenges get `invalidated_at` (NOT `consumed_at`) and exactly one active challenge remains; concurrent replaces (FOR UPDATE) → at most one active challenge. Fails: type absent.
- **RED (outbox store):** `ClaimDueAsync` returns due rows and marks the lease; a second concurrent claim of the same row returns nothing (affected=0); `MarkSent…`/`MarkFailed…` set the terminal column and zero payload columns; `PurgeExpiredPayloads` zeroes payloads of expired unsent rows; `DeleteSanitizedOlderThan` removes only old terminal rows. Fails: type absent.
- **GREEN:** implement the three stores with explicit transactions + `FOR UPDATE` + conditional updates + lease claims.
- **Verify:** `dotnet test tests/BitosX.Infrastructure.Tests --filter "Store"`.
- **Commit:** `feat: add transactional registration/verification/outbox stores`.

---

## Task 8 — Email-first registration service (no password)
- **Files:** `src/BitosX.Application/Accounts/IAccountRegistrationService.cs` (+ `RegisterCommand{email}`, `RegisterResult`), `AccountRegistrationService.cs`; test `tests/BitosX.Application.Tests/AccountRegistrationServiceTests.cs` (fakes for store/token factory/protector/clock; **spy hasher to assert it is NOT called**).
- **Consumes:** `IEmailVerificationTokenFactory`, `IOutboxPayloadProtector`, `IAccountRegistrationStore`, `IAccountRepository` (read), `EmailNormalizer`, `TimeProvider`, `EmailOptions`. **No password hasher, no password policy** (register takes no password).
- **Produces:** `RegisterAsync(RegisterCommand{email}) → RegisterResult { Accepted }` (always; internal outcome enum for logging: `Created | ExistingAccount | InvalidInput`).
- **RED:** valid new email → account built with **`PasswordHash=null`, `EmailVerifiedAt=null`**, token generated, verifier + challenge + encrypted outbox persisted via `CreateUnverifiedAccountWithChallengeAndOutboxAsync`, result `Accepted`; **existing email (verified or unverified)** → result `Accepted`, **nothing created/enqueued**, no account mutation; **no Argon2 hashing occurs anywhere in register** (spy hasher invocation count == 0); invalid email → `InvalidInput` (mapped to 400 in Task 14). Fails: type absent.
- **GREEN:** validate email → normalize → read existing → branch (new: build challenge+outbox, call store, handle `EmailAlreadyExists` race as existing; existing: no-op) → `Accepted`. No SMTP, no password handling. Never log token.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter AccountRegistrationServiceTests`.
- **Commit:** `feat: add account registration service`.

---

## Task 9 — Verify-email + password finalization service
- **Files:** `src/BitosX.Application/Verification/IEmailVerificationService.cs` (+ `VerifyEmailCommand{token,password}`, `VerifyResult`), `EmailVerificationService.cs`; test `tests/BitosX.Application.Tests/EmailVerificationServiceTests.cs`.
- **Consumes:** `AccountPasswordPolicy`, `IAccountPasswordHasher`, `IEmailVerificationTokenFactory.ComputeVerifier`, `IEmailVerificationStore.FindActiveChallengeByVerifierAsync` (Phase A) + `.FinalizeVerificationAsync` (Phase C), `TimeProvider`.
- **Produces:** `VerifyAsync(VerifyEmailCommand{token,password}) → VerifyResult { Verified | Invalid | InvalidPassword }`.
- **Two-phase orchestration:** Phase A — validate password policy (fail fast → `InvalidPassword`, no hashing, no store write), compute verifier, non-locking pre-check via `FindActiveChallengeByVerifierAsync`; if invalid → `Invalid` **without hashing**. Phase B — hash password (Argon2id), no DB lock held. Phase C — `FinalizeVerificationAsync` (FOR UPDATE re-check + conditional updates).
- **RED:** policy fail → `InvalidPassword`, hasher spy == 0, no store finalize call; bogus/expired/consumed/invalidated token or already-verified account → `Invalid`, **hasher spy == 0** (Phase A gate; no CPU amplification); valid token+password → `Verified`, the PHC verifies the supplied password; **two-phase race** — pre-check passes, challenge consumed/invalidated between A and C (fake store toggles state) → Phase C affected=0 → `Invalid`, no partial activation; never logs token/password. Fails: type absent.
- **GREEN:** implement Phase A→B→C exactly; discard the Phase-B hash if C fails.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter EmailVerificationServiceTests`.
- **Commit:** `feat: add email verification service`.

---

## Task 10 — Resend service
- **Files:** `src/BitosX.Application/Verification/` add `ResendCommand`/`ResendResult` + `IEmailVerificationService.ResendAsync` (same interface); implement in `EmailVerificationService.cs`; test `tests/BitosX.Application.Tests/EmailVerificationResendServiceTests.cs`.
- **Consumes:** `IAccountRepository` (read), `IEmailVerificationTokenFactory`, `IOutboxPayloadProtector`, `IEmailVerificationStore.ReplaceActiveChallengeAsync`, `EmailNormalizer`, `TimeProvider`, `EmailOptions`.
- **Produces:** `ResendAsync(ResendCommand{email}) → ResendResult { Accepted }` (always).
- **RED:** unverified account → old challenges invalidated, one fresh challenge + one outbox row created (via store), result `Accepted`; verified/disabled/unknown → `Accepted`, nothing created; min-interval guard → `Accepted`, nothing created (assert no new challenge/outbox). Fails: type absent.
- **GREEN:** normalize → read account → if unverified, generate token + build encrypted outbox + call `ReplaceActiveChallengeAsync` (with min-interval guard); else no-op → return `Accepted`.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter EmailVerificationResendServiceTests`.
- **Commit:** `feat: add resend-verification service`.

---

## Task 11 — Email composition
- **Files:** `src/BitosX.Application/Email/IVerificationEmailComposer.cs`, `EmailMessage.cs`, `EmailOptions.cs`, `VerificationEmailComposer.cs`; test `tests/BitosX.Application.Tests/VerificationEmailComposerTests.cs`.
- **Consumes:** `EmailOptions { PublicBaseUrl, VerificationPath, FromAddress, FromName }`.
- **Produces:** `Compose(toAddress, tokenBase64Url, expiresAtUtc, expiresInMinutes) → EmailMessage{To,Subject,TextBody,HtmlBody}` with the fragment link `${PublicBaseUrl}${VerificationPath}#token=<token>`.
- **RED:** text and HTML both contain BitosX identity, the 30-minute expiry, the fragment link (with `#token=`), and the "ignore if you didn't request" line; neither contains a password, hash, verifier, DB detail, or IP; the link uses a URL **fragment** (`#`) not a query (`?`). Fails: type absent.
- **GREEN:** implement pure composition from options.
- **Verify:** `dotnet test tests/BitosX.Application.Tests --filter VerificationEmailComposerTests`.
- **Commit:** `feat: add verification email composer (fragment link)`.

---

## Task 12 — MailKit Gmail sender
- **Files:** `src/BitosX.Infrastructure/Email/MailKitGmailEmailSender.cs`; option `SmtpOptions`; test `tests/BitosX.Infrastructure.Tests/MailKitGmailEmailSenderTests.cs` (no real network — asserts configuration/guard behavior only).
- **Consumes:** MailKit 4.18.0 (added to `BitosX.Infrastructure.csproj`; lockfiles regenerated); `SmtpOptions { Host, Port, Username, AppPassword, ... }`.
- **Produces:** `IEmailSender.SendAsync(EmailMessage, ct)` using `SmtpClient` with `SecureSocketOptions.StartTls` on `smtp.gmail.com:587`, cert validation left enabled (no custom callback), auth with app password; on failure returns/raises a typed failure without Gmail text.
- **RED:** a test asserts the sender is constructed to use StartTls + port 587 + host from options and **does not** set any certificate-bypass/`ServerCertificateValidationCallback` (verified by design/parameter assertions and a guard test that construction with an insecure port/option is rejected). No automated test connects to Gmail. Fails: type absent.
- **GREEN:** implement the MailKit sender; keep credentials only from options; never log the app password or Gmail server responses.
- **Manual smoke test (opt-in, excluded from CI):** a `[Trait("Category","ManualSmtp")]`/env-gated test that, only when `BITOSX_SMTP_SMOKE=1` and secrets present, sends one real email; excluded from `dotnet test` default runs via a filter.
- **Verify:** `dotnet test tests/BitosX.Infrastructure.Tests --filter MailKitGmailEmailSenderTests` (manual smoke excluded).
- **Commit:** `feat: add MailKit Gmail SMTP sender (STARTTLS, cert validation on)`.

---

## Task 13 — Outbox dispatcher (BackgroundService)
- **Files:** `src/BitosX.Application/Email/IEmailOutboxDispatcher.cs` (process-once abstraction for testing); `src/BitosX.Infrastructure/Email/EmailOutboxDispatcher.cs` + `EmailOutboxBackgroundService.cs`; option `EmailOutboxOptions { MaxAttempts=6, PollInterval, BatchSize, LeaseSeconds, BackoffBaseSeconds, RetentionDays=7, ExpiredCleanupInterval<=24h }`; tests `tests/BitosX.Infrastructure.Tests/EmailOutboxDispatcherTests.cs`.
- **Consumes:** `IEmailOutboxStore`, `IOutboxPayloadProtector`, `IEmailSender`, a challenge read (confirm present, not consumed, **not invalidated**, not expired), `TimeProvider`.
- **Produces:** `ProcessDueOnceAsync(ct)` (claim lease → per-row: **eligibility pre-check (present, `consumed_at IS NULL`, `invalidated_at IS NULL`, `expires_at > now`)** → **recipient integrity (AAD + decrypted `toAddress` == row `recipient_email`)** → decrypt → send → mark sent+erase / reschedule / mark failed+erase) and the hosted loop on `PollInterval`; plus `RunCleanupOnceAsync(ct)` (purge expired payloads; delete sanitized rows older than `RetentionDays`).
- **RED (required invariants, `FakeTimeProvider`, `FakeEmailSender`, no real sleeping):**
  - not-yet-expired pending row → delivered (fake sender receives exactly one message); row `sent_at` set; payload columns zeroed; sanitized metadata remains.
  - **expired** pending row (advance clock past `expires_at`) → **not delivered** (fake sender receives nothing); row `failed_at` set; payload zeroed.
  - **stale-outbox / invalidated challenge (REQUIRED):** create challenge A + outbox A; resend → A gets `invalidated_at`, challenge B + outbox B active; dispatcher encounters outbox A → **not sent**, A marked terminal + payload erased; outbox B is the only deliverable and is sent once.
  - **recipient integrity (REQUIRED):** tamper `recipient_email` (also test `message_type`/`id`/`payload_version`) on a pending row → decrypt/AAD authentication fails → **not sent**, marked failed, payload erased, only a non-sensitive integrity log; separately, decrypted `toAddress` ≠ row `recipient_email` → **not sent**.
  - transient send failure → `attempt_count` incremented, `available_at` advanced by backoff, lease released; after `MaxAttempts=6` → `failed_at` set + payload zeroed; total schedule stays within 30 min.
  - two dispatcher instances processing concurrently → each row delivered at most once (lease).
  - crash simulation (send succeeds but `sent_at` not written) → re-process re-sends the same link and does **not** create a second challenge/token.
  - cleanup: expired unsent payloads zeroed within ≤24 h; sanitized rows older than 7 days deleted.
  - dispatcher never logs token/decrypted payload/SMTP credentials (capturing logger asserts absence).
  Fails: type absent.
- **GREEN:** implement dispatcher + background service honoring `stoppingToken`.
- **Verify:** `dotnet test tests/BitosX.Infrastructure.Tests --filter EmailOutboxDispatcherTests`.
- **Commit:** `feat: add transactional outbox email dispatcher`.

---

## Task 14 — HTTP contracts + endpoints
- **Files:** `src/BitosX.Contracts/Accounts/RegisterRequest.cs`, `VerifyEmailRequest.cs`, `ResendVerificationRequest.cs`, `AcceptedResponse.cs`; `src/BitosX.Api/Endpoints/AuthEndpoints.cs`; `src/BitosX.Api/Program.cs` (wire `AddBitosxAccounts` + hosted dispatcher, map `/v1/auth`); `src/BitosX.Infrastructure/.../AccountsServiceCollectionExtensions.cs` (`AddBitosxAccounts`); tests `tests/BitosX.Api.Tests/{RegisterEndpointTests,VerifyEmailEndpointTests,ResendVerificationEndpointTests}.cs`.
- **Consumes:** the Application services (Tasks 8–10); options binding; DI endpoint seam.
- **Produces:** `POST /v1/auth/register` → `202 AcceptedResponse`; `POST /v1/auth/verify-email` → `200 AcceptedResponse`; `POST /v1/auth/resend-verification` → `202 AcceptedResponse`; validation failures → `400` ProblemDetails; endpoint-level body-size cap.
- **Contracts:** `RegisterRequest{Email}` (**no password**), `VerifyEmailRequest{Token,Password}`, `ResendVerificationRequest{Email}`, `AcceptedResponse{Message}`. No response returns password/hash/token/verifier/account internals.
- **RED:** register `{email}` valid → `202` generic; register with an extra `password` field → field ignored (still `202`, no password stored); register duplicate (verified & unverified) → identical `202`; invalid email → `400`; verify `{token,password}` valid → `200`; verify password too short/long → `400` ProblemDetails (challenge not consumed); verify invalid/expired/consumed/invalidated/already-verified → generic failure (`400`, generic body); resend → always `202`. Endpoint tests use WebApplicationFactory with `FakeEmailSender` + test DB via `ConfigureTestServices`. Fails: routes 404 (not mapped).
- **GREEN:** map endpoints; wire services; register the hosted dispatcher; bind options.
- **Verify:** `dotnet test tests/BitosX.Api.Tests --filter "Endpoint"`.
- **Commit:** `feat: add /v1/auth register, verify-email, resend-verification endpoints`.

---

## Task 15 — Cross-cutting integration + security tests
- **Files:** extend `tests/BitosX.Application.Tests/ZeroKnowledgeModelTests.cs`; add `tests/BitosX.Api.Tests/AuthSecurityTests.cs`; add `tests/BitosX.Infrastructure.Tests/PersistenceSecrecyTests.cs`.
- **Consumes:** all prior components + test DB + fakes.
- **Produces:** verification of the security invariants end to end.
- **RED then GREEN (lock the invariants):**
  - **Pre-registration takeover (REQUIRED):** (1) "attacker" registers `victim@example.com` (email-only); (2) assert the account exists with `password_hash IS NULL` before verification and that **no password was ever accepted by register**; (3) "victim" verifies with the emailed token + a victim-chosen password; (4) assert `password_hash` now verifies the victim's password, never held any other value, `email_verified_at` is set, and challenge is consumed — **atomically** (both-or-neither); no attacker-controlled password was ever persisted.
  - **Partial-activation failure (REQUIRED):** simulate the challenge-consume or account-update affecting 0 rows (race) → account remains unverified, `password_hash` stays NULL, token **not** marked consumed; endpoint returns generic Invalid.
  - zero-knowledge: no vault master password / Vault Key / vault secret / vault TOTP field on any model or DTO; DTOs expose no password/token/hash; account exposes only `PasswordHash`; challenge exposes only `token_hash` + `consumed_at`/`invalidated_at`; outbox exposes no plaintext token.
  - persistence secrecy: after a real registration against `bitosx_test`, challenge `token_hash == HMAC(pepper,token)` and equals no encoding of the plaintext token; outbox ciphertext does not contain the token bytes; after verify, `accounts.password_hash` is a PHC string (not plaintext).
  - config secrecy: `appsettings.json`/`appsettings.Development.json` contain no `SmtpAppPassword`, `EmailVerificationPepper`, or `EmailOutboxKey`.
  - error responses: forced DB failure and forced invalid input → ProblemDetails with no SQL/stack/SMTP/Gmail/path/crypto text.
  - register performs no Argon2 hashing (spy).
- **Verify:** `dotnet test BitosX.Api.slnx -c Debug` (whole suite).
- **Commit:** `test: add account/email zero-knowledge and secrecy guards`.

---

## Task 16 — Documentation updates
- **Files:** `docs/API.md` (register/verify/resend, generic responses, no auth-state leakage), `docs/ARCHITECTURE.md` (auth subsystem + outbox dispatcher), `docs/SECURITY_MODEL.md` (Argon2 **final benchmarked params + evidence**, pepper + outbox key handling + rotation, retention, never-send-after-expiry, rate-limiting production blockers), `docs/PERSISTENCE.md` (0002 schema, `email_outbox`).
- **RED:** n/a (docs). A lightweight test may assert `docs/API.md` mentions the three endpoints (optional).
- **Verify:** manual review + `dotnet test` unaffected.
- **Commit:** `docs: document account registration, email verification, outbox`.

---

## Task 17 — Full Debug/Release verification
- **Actions (fresh):** `dotnet restore --locked-mode`; `dotnet build -c Debug`; `dotnet test -c Debug`; `dotnet build -c Release`; `dotnet test -c Release`. Require 0 warnings, 0 errors, 0 failures. Re-verify `ss -ltnp` shows MariaDB `127.0.0.1:3306` only and Kestrel loopback. Confirm no secrets in tracked files/history.
- **Commit:** none (verification only); then STOP for milestone review before any push.

---

## Proposed package additions
- `Konscious.Security.Cryptography.Argon2` 1.3.1 → `BitosX.Infrastructure` (Task 3).
- `MailKit` 4.18.0 (+ transitive `MimeKit` 4.18.0) → `BitosX.Infrastructure` (Task 12).
- `Microsoft.Extensions.TimeProvider.Testing` (latest stable, test-only) → test projects (Tasks 1/13/…). BCL provides `AesGcm`, `RandomNumberGenerator`, `HMACSHA256`, `TimeProvider`.
- All additions regenerate `packages.lock.json`; locked-mode restore re-verified in Task 17.

## Proposed migration
`0002_account_registration_email_verification.sql`: unique index `ux_evc_token_hash` on `email_verification_challenges(token_hash)`; `CREATE TABLE email_outbox (...)` with the due-index. No `accounts` change. `0001` untouched. Applied to `bitosx` by `bitosx_migrator` (operator, out-of-band); to `bitosx_test` by `bitosx_test_app` (fixture).

## Expected test growth
Current 44 → roughly **+55–70 tests** (policy ~4; hardened PHC/hasher ~16 incl. resource-exhaustion cases; token ~5; outbox crypto ~9 incl. AAD/canonical/recipient; migration ~4 incl. `invalidated_at`; stores ~14; registration service ~6; verify+password service ~10 incl. takeover/partial-activation; resend ~5; composer ~3; sender ~2; dispatcher ~11 incl. stale-outbox + recipient integrity; endpoints ~11; security ~8). Target final suite ≈ **100–115 tests**, all green in Debug + Release; no real Gmail sends.

## Security review of the plan
- **Pre-registration takeover eliminated:** register accepts no password (`password_hash=NULL`); the token holder sets the password atomically at verify-email (Tasks 8/9); dedicated takeover + partial-activation tests (Task 15).
- No task persists a plaintext password (only PHC), a plaintext verification token in the challenge table (only HMAC), or a plaintext SMTP credential (options/user-secrets only).
- Outbox token payload is AES-256-GCM under an independent `EmailOutboxKey`, with AAD binding id+version+message_type+recipient_email (canonical length-prefixed) and a send-time `toAddress==recipient_email` check; erased at terminal state; never logged (Tasks 5/13).
- Hardened PHC parser rejects hostile params before any Argon2 allocation (Task 3).
- No synchronous SMTP in the request path (dispatcher only); register/verify/resend responses generic; **timing posture is best-effort (no dummy hashing in register)** — rate limiting mandated before public exposure.
- Distinct `consumed_at` vs `invalidated_at`; dispatcher never sends an invalidated/consumed/expired challenge's link (Tasks 6/7/13); never-send-after-expiry has dedicated tests.
- Concurrency: `FOR UPDATE` serializes resend and verify-finalization; atomic lease serializes dispatch; conditional updates (affected=1) prevent partial activation.
- Secrets set only via user-secrets; Task 15 asserts absence from committed config; secret scans in Task 17.
- MariaDB loopback-only; runtime (`bitosx_app`) vs migrator (`bitosx_migrator`) separation preserved (only the migrator applies 0002).
- No public exposure; no Apache/Cloudflare/systemd/DNS changes.

## Commit boundaries (summary)
One commit per task (Tasks 1–6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16). Each is independently reviewable, builds clean, and keeps the suite green. Nothing is pushed until the milestone is reviewed and approved.
