# BitosX API — Security Model

This document records the security boundaries and defaults for the BitosX
Account/API service, and the security work that is intentionally still
incomplete.

## Zero-knowledge vault boundary (hard rule)

BitosX desktop vaults are end-to-end encrypted. The Account/API server operates
under a **zero-knowledge** trust model with respect to vault contents.

The API server must **never** receive, process, log, or store:

- the vault master password,
- the raw Vault Key,
- decrypted vault contents,
- passwords stored inside the vault,
- vault TOTP secrets (future),
- any plaintext secret belonging to the encrypted desktop vault.

A full compromise of the account API must **not** directly reveal vault
plaintext or vault cryptographic keys.

Consequently, no DTO, endpoint parameter, database field, log field, or
telemetry field may be introduced that could accept vault cryptographic
secrets. The current `Contracts` DTOs (`HealthResponse`, `VersionResponse`)
carry only non-sensitive service identity/version data.

## Account authentication is separate from vault encryption

Account authentication and vault encryption are **completely separate systems**.
A future account password is **not** the vault master password, and the two must
never be conflated in code, storage, or transport.

## Secrets the server must never receive

See the zero-knowledge list above. In addition, the server must not accept vault
key material through any channel (headers, query strings, bodies, or logs).

## Logging restrictions

Structured logging is enabled with a per-request correlation id. Logging must
**never** record:

- request bodies (not logged by default; no broad request-dumping middleware),
- `Authorization` headers,
- `Cookie` headers,
- passwords,
- access tokens, refresh tokens,
- verification codes,
- any secret,
- connection strings.

The correlation-id middleware logs only a bounded, printable correlation
identifier and does not log headers or bodies.

## Error handling

- The developer exception page is **never** enabled (any environment).
- Clients receive **RFC7807 ProblemDetails** only — never stack traces,
  file paths, environment values, or configuration dumps.
- The `/version` endpoint exposes only `{ service, version }`; a test asserts
  the response contains no additional fields.

## Transport / network posture

- Kestrel binds to **loopback only** (`127.0.0.1:5080`); verified with `ss`.
- TLS is terminated upstream (Apache/Cloudflare); Kestrel serves HTTP on
  loopback only.
- Forwarded headers are trusted from **loopback proxies only** (`127.0.0.1`,
  `::1`) with `ForwardLimit = 1`. Arbitrary-network forwarded headers are never
  trusted.
- No CORS is configured. The Avalonia desktop client is not a browser and does
  not need CORS; none will be added without a concrete consumer requirement.
- A conservative request-body-size limit (64 KB) is applied at Kestrel; the
  server header is suppressed.

## Public-exposure restrictions

`api.bitosx.se` resolves to this host in Cloudflare DNS, but the API must
**not** be exposed publicly during this phase:

- Apache does not proxy to Kestrel.
- No Let's Encrypt certificate is requested for `api.bitosx.se` by this work.
- No Cloudflare configuration is changed.
- OpenAPI is currently served on loopback; it must be gated/reviewed before any
  public exposure.

## Database security (Persistence Foundation)

- MariaDB listens on **`127.0.0.1:3306` only** (verified with `ss`); it is not
  publicly reachable. The default bind-address was not modified.
- Dedicated least-privilege user `bitosx_app`@`127.0.0.1`, granted only on
  `bitosx.*` and the test schema `bitosx_test.*` — never `root`, never a legacy/
  vault user, never global data privileges.
- **All account secrets are stored only as hashes**, never plaintext:
  `password_hash` (future account password, separate from the vault master
  password), `token_hash` (email/refresh tokens, SHA-256), `code_hash` (phone
  OTP, HMAC-SHA256 with a server pepper not stored in the row). There is no
  plaintext password, token, or OTP column anywhere.
- No vault master password, Vault Key, vault secret, or vault TOTP column exists
  in any table (zero-knowledge boundary preserved at the schema level).
- Credentials are supplied from local user-secrets and are never committed (not
  in `appsettings*.json`, source, docs, or tests). Production secret injection
  is designed separately. See [`PERSISTENCE.md`](PERSISTENCE.md).

## Account registration + email verification

- **Email-first registration.** `POST /v1/auth/register` accepts only an email; the
  account is created with `password_hash = NULL`. The password is chosen by whoever
  holds the emailed token at `POST /v1/auth/verify-email`. This eliminates
  pre-registration account takeover (an initiator can never set a victim's password).
  Future login invariant: an account is usable only if `email_verified_at IS NOT NULL
  AND password_hash IS NOT NULL AND disabled_at IS NULL`. Disabled accounts can neither
  verify, receive a password, nor be sent resend emails.
- **Account password:** Argon2id (`Konscious`), self-describing PHC storage, `p=1`.
  **Locked parameters (benchmarked on `bitosx-prod`, 1 vCPU / ~1 GiB):**
  `m = 19456 KiB (19 MiB), t = 3, p = 1, maxConcurrency = 1` (hard budget
  `memoryKiB × maxConcurrency ≤ 192 MiB`). Benchmark evidence (`tools/BitosX.Benchmarks`,
  Release):

  | cap | single (ms) | p50 (ms) | p95 (ms) | throughput (h/s) | peak WS (MiB) |
  |----:|------------:|---------:|---------:|-----------------:|--------------:|
  | 1 | ~200–430 | ~2030 | ~8069 | ~2.1 | ~104 |
  | 2 | ~198 | ~1823 | ~5024 | ~4.3 | ~168 |
  | 3 | ~191 | ~4038 | ~6572 | ~3.6 | ~344 |

  On a single vCPU, memory-hard hashes cannot truly run in parallel; higher caps only
  queue and inflate memory/latency. **cap=1** was chosen for the lowest memory footprint
  (~104 MiB incl. runtime) and predictable latency; concurrent bursts are additionally
  bounded by rate limiting (a production blocker). Single-hash latency (~0.2–0.4 s) is
  acceptable for a rate-limited, once-per-verification cost. The PHC parser
  rejects out-of-budget/hostile parameters (`MaxVerifyMemoryKiB` = `floor(192 MiB /
  concurrency)`, `MaxVerifyIterations ≈ 2× active`, `p=1` only) **before** any Argon2
  allocation/execution. Verification is two-phase: a non-locking pre-check (no hashing
  for bogus/expired/consumed/invalidated tokens), then hashing with no DB lock held,
  then a short `FOR UPDATE` transaction that re-checks and applies conditional updates
  (no partial activation).
- **Verification token:** 256-bit random; the challenge table stores only
  `HMAC-SHA256(EmailVerificationPepper, token)` — never the plaintext token. TTL 30
  minutes, single use; `consumed_at` (verified) is distinct from `invalidated_at`
  (replaced by resend).
- **Delivery is at-least-once** (never claimed exactly-once). Three layers keep an
  invalidated/expired challenge's email from being sent: (1) **lease + resend
  coordination** — resend locks the active challenge's outbox row (coordinating with the
  dispatcher's `FOR UPDATE SKIP LOCKED` claim) and, if the row is currently leased for a
  bounded in-flight SMTP attempt, does **not** invalidate it (`SkippedDeliveryInProgress`,
  still a generic 202); (2) a **fresh per-row eligibility re-check** immediately before
  send; (3) the **verify endpoint** independently rejects consumed/invalidated/expired
  tokens. A bounded SMTP attempt timeout is enforced to always be shorter than the outbox
  lease (`LeaseDuration > SmtpTimeout + margin`, validated fail-closed at startup), so a
  delivery never outlives its lease. Verification state remains authoritative regardless
  of unusual SMTP behavior; a Gmail/provider-level **duplicate** may still occur in the
  documented accept-before-crash window (a duplicate re-sends the same single link and
  never creates a second valid challenge).
- **Transactional outbox (no synchronous SMTP in the request path** — removes the
  network-latency enumeration oracle). The verification token lives transiently in the
  outbox only as **AES-256-GCM ciphertext** under an independent `EmailOutboxKey`,
  with AAD binding `id + version + message_type + recipient_email` (canonical
  length-prefixed). The dispatcher checks the challenge is still active and verifies
  recipient integrity **before** sending, never sends after expiry/invalidation, uses
  bounded retries within the token TTL, and erases the encrypted payload on terminal
  state. Live encrypted token payloads persist ≤ 24 h; sanitized metadata ≤ 7 days.
- **Secrets** (`Security:EmailVerificationPepper`, `Security:EmailOutboxKey`,
  `Email:SmtpAppPassword`) live only in user-secrets / production injection — never in
  Git, DB, appsettings, or logs. Mutually independent and independent of vault crypto.
  `EmailOutboxKey` rotation is drain-then-rotate (do not rotate with undrained rows).
- **SMTP:** Gmail `smtp.gmail.com` **port 587 STARTTLS only** (implicit-TLS/465 is not
  accepted in v1 — the sender fails closed on any other port), TLS validation on, no
  bypass; failures isolated (never surfaced to clients). Automated tests never send real
  Gmail. **Two distinct timeouts:** MailKit's socket read/write `Timeout` (low-level
  stream defense) and the **overall attempt deadline** (`AttemptTimeout`, enforced via a
  linked `CancellationTokenSource` that cancels the entire connect→auth→send→disconnect
  sequence). The lease invariant is validated against the **overall** `AttemptTimeout`
  (`LeaseDuration > AttemptTimeout + margin`), so a bounded attempt always finishes within
  its lease. Caller cancellation propagates; an internal-deadline timeout returns a
  generic failure.
- **Authoritative verification time:** `FinalizeVerificationAsync` reads its authoritative
  timestamp from the server clock **only after** the `FOR UPDATE` row lock is held (the
  locking SELECT carries no expiry predicate), so a token that expires during Argon2 or
  during a lock wait is rejected against the true TTL. Delivery remains at-least-once
  (a provider accept-before-crash duplicate re-sends the same single link, never a second
  valid challenge).
- **Anti-enumeration:** register/resend return a single generic 202; verify returns
  generic failures. Timing resistance is **best-effort** (SMTP off the request path;
  no dummy hashing in register) — mandatory rate limiting precedes public exposure.

## Login, sessions, access + refresh tokens

- **Login is an independent capability** (`AddBitosxLogin`), layered on AccountCore and
  gated **only** on the current JWT signing key (`Security:JwtSigningKey` + mandatory
  `Security:Jwt:KeyId`). It requires **neither SMTP nor EmailVerification nor any
  refresh-token secret**. Non-secret JWT metadata alone never enables it.
- **Access token:** HS256 JWT with a **mandatory `kid`**, minimal claims (`sub`, `sid`,
  `jti`, `iat`, `nbf`, `exp`, `iss`, `aud`) — never email/phone/role/vault data. Issued
  and signed with the **current key only**; validated against **current + previous**
  (verification-only) during the rotation overlap, via the single
  `JwtTokenValidationParametersFactory` (HS256 only, exact issuer/audience, explicit clock
  skew, mandatory-kid resolution with no all-keys fallback). Phase 2B's JwtBearer consumes
  exactly those parameters — there is never a second validator.
- **Refresh token:** 256-bit CSPRNG, transmitted as 43-char unpadded Base64URL. The DB
  stores only the verifier `token_hash = SHA-256(raw 32 token bytes)` (`VARBINARY(32)`) —
  **no server pepper and no HMAC** (the token is already 256 bits of entropy, so a plain
  SHA-256 verifier makes offline preimage recovery infeasible). The plaintext token never
  reaches the store; verifier byte arrays are best-effort zeroed.
- **Strict rotation / reuse:** rotation is atomic under the canonical lock order
  (accounts → sessions → refresh_tokens) with authoritative post-lock time. There is
  **no reuse grace window**: any presentation of an already consumed/revoked token is
  treated as reuse and revokes the whole session (session-scoped); clients must
  single-flight refresh requests. Store `Invalid` and `ReuseDetected` both collapse to a
  single generic failure to callers.
- **Session lifetimes** (`RefreshTokenOptions`, no secret): idle (default 30 d) and
  absolute (default 90 d). Both are validated **once at composition (M-2)** to be positive
  and arithmetically safe for session-expiry math, so a malformed/oversized lifetime fails
  at startup — never on a user request. Session listing exposes the **effective** expiry
  `min(absolute, last_seen + idle)` and lists only currently-usable sessions.
- **Fail-closed config:** `AddBitosxLogin` and `DetectCapabilities` share one validation
  path, so malformed login config (short/non-canonical key, missing/duplicate `kid`, orphan
  previous key, blank issuer/audience, non-positive/oversized lifetimes) throws at startup
  and never registers a half-working login stack. Signing keys are Base64 secrets held only
  in the secret store; `JwtOptions` carries no secret-revealing `ToString`. `UseAuthentication`
  / JwtBearer / `/account/me` HTTP wiring is **deferred to Phase 2B**.

## Rate limiting (production blocker for account endpoints)
Per-IP + per-email limits on `/register`, stricter limits + min-interval + daily cap on
`/resend-verification`, per-IP + backoff on `/verify-email`, a global outbound-email
budget/circuit-breaker, the Argon2 concurrency cap (present), and adaptive
Turnstile/CAPTCHA must all be in place before any public exposure.

## Known incomplete security work (must precede public account/auth go-live)

These are acceptable to defer for **local** development, but public account/auth
production go-live **must be blocked** until they are completed and verified:

- final SSH hardening,
- Fail2ban configuration,
- Cloudflare-only origin protection,
- Apache reverse proxy to Kestrel (with reviewed real-client-IP handling),
- production `systemd` service,
- production DB secret injection, backups, and (recommended) a separate
  migrator vs. runtime DB user (local `bitosx` DB + least-privilege user is done),
- the account/auth implementation itself (hashing, tokens, sessions, etc.).

**A working API foundation does not make this server production-ready.**
