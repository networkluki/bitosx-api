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
secrets. The one place vault *ciphertext* crosses the boundary is the encrypted
envelope of phase 3 (`SyncUploadRequest.Envelope`, `vault_blobs.envelope`): the
desktop vault file, opaque to the server, stored and returned byte for byte —
see "Encrypted-envelope sync" below. It carries no key and no plaintext, and
`ZeroKnowledgeModelTests` keeps every other contract and model free of
vault-named fields.

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
- CORS exists for exactly one consumer: the browser-based web account app at
  `https://vault.bitosx.se` (its source lives in `networkluki/bitosx-manager`).
  See "Browser clients (CORS)" below. The Avalonia desktop client is not a
  browser and is unaffected.
- A conservative request-body-size limit (64 KB) is applied at Kestrel; the
  server header is suppressed.

## Browser clients (CORS)

The web account app runs on a different origin (`https://vault.bitosx.se`) than the
API (`https://api.bitosx.se`), so a browser only lets it read responses when the API
opts in through CORS. The policy (`BrowserCorsOptions`, configured under
`Security:Cors`) is deliberately narrow and fails closed at startup:

- **Exact `https://` origins only**, semicolon-separated in `Security:Cors:AllowedOrigins`
  (the repository `appsettings.json` lists `https://vault.bitosx.se`). No wildcard, no
  `http://` (not even loopback), no path, trailing slash, query, fragment, userinfo or
  uppercase: anything but `https://host[:port]` in canonical form refuses startup. A
  browser's `Origin` header must match byte for byte; `vault.bitosx.se.attacker.example`
  or a different port gets no CORS headers.
- **Inert when empty.** With no origin configured the CORS middleware is not registered
  and no CORS header is ever emitted — the pre-CORS behaviour.
- **Methods** `GET`, `POST`, `DELETE`; **request headers** `Authorization`,
  `Content-Type`, `Accept`; **exposed response headers** `Retry-After`,
  `X-Correlation-ID`; preflight cache `Security:Cors:PreflightMaxAgeSeconds`
  (default 600, max 86400). None of these lists is configurable: widening them is a
  code change with a review, not a config edit.
- **Never credentialed.** `Access-Control-Allow-Credentials` is never sent. The web app
  authenticates with a bearer access token it attaches itself and holds only in memory;
  the API sets no cookies, so a cross-site page can neither carry nor read a credential.
- **Placement.** The middleware runs after forwarded-header processing and the
  correlation id, and before authentication and the endpoints, so a preflight is answered
  with `204` without touching a rate limiter, Argon2 or the JWT handler. A disallowed
  origin is not an error: the request is processed as usual and only the CORS headers
  are absent, which makes the browser block the read.

CORS is a browser-side read permission, not authentication or authorization. It does not
change the zero-knowledge boundary, the generic-error model, rate limiting or token
validation, and it must not be mistaken for a defence against non-browser clients, which
never honoured it.

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

## Encrypted-envelope sync (phase 3)

The desktop app can store its vault file on the server and fetch it back (`/v1/sync`). This is
the first server feature that touches the vault at all, so the boundary is stated precisely:

- **What is stored:** the vault file as the client wrote it — a JSON envelope whose salt, nonces,
  wrapped key and content are ciphertext under a key derived from the master password *on the
  device* (`bitosx/docs/CRYPTOGRAPHY.md`). The server has no master password, no key-encryption
  key, no vault key, and no way to obtain one. A full compromise of the server yields the same
  thing a stolen vault file yields: an offline guessing problem against the master password,
  made expensive by Argon2id on the client's terms.
- **What the server reads of it:** the public header only — enough to confirm it is a JSON
  object with a positive integer `version` (`VaultSyncService.LooksLikeEnvelope`). The
  cryptographic fields are never decoded. The fingerprint (SHA-256 over the bytes) is computed
  server-side and is public: it lets a client tell whether its file matches without a download.
- **No merge.** The server never combines two envelopes (it could not: they are ciphertext). An
  upload names the revision the client last saw; if the server holds another, the upload is
  refused with 409 and the client decides. Two devices can therefore never silently overwrite
  each other.
- **Limits.** Envelope ≤ 16 MiB decoded (`Security:Sync:MaxEnvelopeBytes`, validated at startup,
  never above the desktop format's own cap); the upload endpoint's body limit is raised to the
  Base64 of that plus 1 KiB, every other endpoint keeps Kestrel's 64 KB. Under hardening, writes
  are limited per account (30 burst / 10 per minute, keyed by the JWT `sub` — a server-issued
  identity, never client input).
- **Account deletion** cascades to the envelope (FK `ON DELETE CASCADE`); an upload for an account
  deleted meanwhile is refused (the account row is locked first) and nothing is written.
- **Logging:** no envelope bytes, fingerprints or sizes are logged; the correlation id and the
  outcome are all a log line carries.
- **Database host note:** a 16 MiB row needs MariaDB's `max_allowed_packet` at 32M or more on
  the host (see `DEPLOYMENT.md`); below that an upload fails as a server error, never as a
  partial write.

## Password reset and account deletion (phase 6)

- **Reset = account password only.** `POST /v1/auth/forgot-password` → emailed link →
  `POST /v1/auth/reset-password` replaces `accounts.password_hash`. The vault master password,
  the vault key and the stored envelope are untouched and unrecoverable by this flow — the server
  never had them. The reset email says so explicitly.
- **Same machinery, bound by purpose.** Reset challenges live in `email_verification_challenges`
  with `purpose = 'password_reset'` (migration 0004) and ride the same HMAC-SHA256 pepper verifier,
  30-minute TTL, single use (`consumed_at` vs `invalidated_at`), encrypted outbox payload (AAD binds
  `message_type = password_reset`) and dispatcher eligibility re-check as verification. **Every
  verification query is bound to `purpose = 'email_verification'` and every reset query to
  `purpose = 'password_reset'`**, so a token issued for one can never be consumed for the other
  (tested at store and endpoint level). The dispatcher composes by `message_type` and fails closed
  on an unknown type.
- **Eligibility.** A reset challenge is issued, pre-checked and finalized only for an account with
  `email_verified_at IS NOT NULL AND password_hash IS NOT NULL AND disabled_at IS NULL`. An
  unverified account must finish verification instead (its password is set there); a disabled
  account gets nothing. The email goes to the stored account address, never the typed one.
- **Anti-enumeration.** forgot-password returns one generic 202 for unknown, unverified, disabled
  and eligible addresses, and for a request skipped by the min re-issue interval or an in-flight
  delivery. reset-password returns one generic 400 for every token failure.
- **Two-phase finalize, sessions revoked atomically.** Policy check and verifier pre-check before
  any Argon2; hashing outside any lock; then one `FOR UPDATE` transaction (authoritative time read
  after the lock) that replaces the hash, consumes the token, invalidates the account's other
  active reset challenges and revokes **every** session and refresh token in the canonical lock
  order (accounts → sessions → refresh_tokens). No partial state: a failed re-check rolls back.
- **Account deletion** (`POST /v1/account/delete`) is authenticated **and** password-confirmed; the
  account id is the JWT `sub`, never body input. Argon2 verify runs outside any lock; the store
  then locks the account row, re-checks the **exact PHC** it verified (a concurrent reset makes the
  delete fail closed) and deletes the row, cascading to challenges, outbox rows, sessions, refresh
  tokens and `vault_blobs`. A leased outbox row that disappears mid-delivery is simply not sent
  (the dispatcher's fresh state read returns nothing). Wrong password → generic 403 (not 401).
- **Rate limits** (hardened mode, same generic 429/503 contract): forgot/reset-password per trusted
  client IP (5 burst / 2 per 60 s), forgot-password per `SHA-256(normalizedEmail)` (3 burst / 1 per
  5 min), account deletion per account id (5 burst / 1 per 3 min). Hardening is now composed with
  AccountCore (not Login) because these limiters ride on EmailVerification alone. Argon2 admission
  applies as always.

## Second factor: TOTP (phase 7)

- **Capability `Totp`** = Login + `Security:TotpKey` (Base64, 256-bit; secret store only). The key
  never touches the DB or logs. Two sub-keys are derived with HKDF-SHA256 (distinct labels): one
  encrypts stored TOTP secrets (AES-256-GCM, fresh 96-bit nonce, AAD = account id + envelope
  version, so a row cannot be transplanted to another account), one keys the HMAC-SHA256
  verifiers of recovery codes (a leaked table cannot be brute-forced offline). A malformed key fails
  startup; a key without Login fails startup.
- **Fail closed, never bypass.** The TOTP *persistence* is registered with Login (DB only), so
  `LoginService` always sees whether an account has TOTP confirmed. If it has and the crypto
  capability is off, login returns a generic 503 — never a password-only session. Tested end to end
  (enroll with the key, boot without it).
- **Two steps, one session.** A correct password for a TOTP account creates **no** session and no
  JWT/refresh token: it stores an `mfa_challenges` row — SHA-256 verifier of a 256-bit opaque token
  (same scheme as refresh tokens), the SHA-256 fingerprint of the PHC that was just verified, the
  User-Agent — and returns 202 with the token (5-minute TTL). The second step strictly parses the
  token, re-reads the account, requires the **same PHC fingerprint** (a password reset between the
  steps kills the challenge), requires TOTP still confirmed, verifies and consumes the code, consumes
  the challenge (conditional UPDATE, single use), and only then runs the same `CreateOnLoginAsync`
  as a password-only login (exact-PHC re-check under the account lock). No Argon2 in step two.
- **Codes.** RFC 6238 HMAC-SHA1 / 6 digits / 30 s (verified against the RFC's own test vectors),
  window ±1 step, constant-time comparison per candidate with every candidate evaluated. **Replay
  guard in the store:** `last_used_step` is advanced by a conditional UPDATE (`last_used_step <
  step`), so a code is accepted once and never for an older step, even under concurrent
  presentations. Recovery codes: 10 characters from a look-alike-free alphabet (~49 bits), stored as
  keyed verifiers, consumed by conditional UPDATE (single use, account-bound). A wrong code
  increments the challenge's attempt count; at 5 the challenge is consumed. The second-step
  response is one generic 401 for every failure; no attempts-left hint.
- **Enrollment** is password-confirmed (Argon2 outside any lock, through the admission gate); the
  secret is generated server-side (160 bits), returned once as Base32 + otpauth URI, stored
  encrypted with `confirmed_at NULL`. A pending secret is not a factor; it is replaced by the next
  enroll and becomes the factor only when a valid code confirms it, which also issues the recovery
  codes (returned once). Disable and recovery-code regeneration require password **then** code (a
  wrong password never consumes a code). Disabling deletes the secret, the codes and open challenges.
- **Rate limits** (hardened mode): second step per trusted client IP (10 burst / 5 per 30 s),
  TOTP management per account id (10 burst / 2 per 60 s). Same generic 429/503 contract.
- **Scope.** The second factor protects the account sign-in only. It cannot protect, recover or
  weaken the vault: the master password and the envelope are untouched (zero-knowledge boundary).
  Account deletion cascades the TOTP rows; a password reset keeps TOTP enabled.

## Rate limiting (Phase 2D public-exposure hardening)

Configured under `Security:PublicExposureHardening` (a single validated model, fail-closed at
startup). **Inert unless `Enabled=true`** (development default false); production with the Login
capability must enable it before public deployment. Rate limiting is **process-local** for this
single-instance deployment; a multi-instance deployment needs a separately designed distributed limiter.

**Client-IP trust model (2D.1).** Topology is Cloudflare → Apache → loopback Kestrel. `UseForwardedHeaders`
processes exactly one hop of `X-Forwarded-For`/`-Proto` and trusts **only** the loopback proxy
(127.0.0.1, ::1); `KnownProxies`/`KnownIPNetworks` are **not** cleared (framework loopback defaults
retained). An `X-Forwarded-For` from any non-loopback peer is never honored, and `CF-Connecting-IP` is
never read in-process. The authoritative client IP is `HttpContext.Connection.RemoteIpAddress` after
forwarded-header processing (IPv4-mapped IPv6 folded to IPv4). In hardened mode, if no usable non-loopback
client IP can be resolved for a protected public endpoint, the request **fails closed with 503** — never a
shared/loopback bucket.

**Implemented (2D.1):** token-bucket limiters (`QueueLimit=0`, no queueing) on the unauthenticated auth
endpoints — `POST /v1/auth/login` per-IP (10 burst / 5 per 30 s) and per-normalized-email (5 burst / 1 per
3 min, partitioned by `SHA-256(normalizedEmail)` so the email is never the key or logged; identical for
existing and unknown accounts, enforced before credential evaluation), and `POST /v1/auth/refresh` per-IP
(30 burst / 15 per 30 s, partitioned only by the trusted client IP — never by token/hash/contents).
Rejection is a generic **429** (`title: Too Many Requests`, `detail: Too many requests. Try again later.`,
plus `Retry-After` when available) that never reveals which limiter fired or any account/email/IP/token
value; partition keys are never logged. Partition state is memory-bounded (≤4096 IP and ≤4096 email
partitions, 30-min idle expiration). **`MaxPartitions` is a memory-safety boundary, not a reset lever:**
a live (non-idle) limiter is **never** evicted to make room, so partition churn (flooding many distinct
IPs/emails) cannot reset an exhausted limiter. Only entries already past the idle-expiration threshold are
reclaimable (LRU applies solely among those). When the cache is full and no entry is idle-eligible, a
**new** partition fails closed with a generic **503** (existing partitions always keep their limiter);
capacity is never mapped to a `"overflow"`/`"unknown"` bucket, a credential 401, or unrestricted
execution. Inserts happen only under a lock after a capacity check, so the maximum is never exceeded under
concurrency. A limiter/IP-resolution failure likewise fails closed (503), never falling through to
unrestricted auth.

**Implemented (2D.2):**

- **Bounded Argon2 work admission (ALWAYS active — independent of `Enabled`).** Password hashing is a
  resource-safety chokepoint, so the Argon2 gate is wired in `AddBitosxAccountCore` and applies to every
  production Argon2 operation (login verify, email verification, password reset, account-deletion
  confirmation; future password-change goes through the same hasher). Built on a BCL `ConcurrencyLimiter`: at most **2** operations execute, at most **4** wait
  (**oldest-first / FIFO**), a queued operation waits at most **2 s**, and a further operation is rejected
  immediately. Queue-full and acquire-timeout both surface as an Application-level
  `PasswordHashingCapacityExceededException` (never a password mismatch); genuine cancellation propagates and
  is never rewritten. At the login boundary this maps to a generic **503** (`title: Service unavailable`,
  `detail: Service temporarily unavailable. Try again later.`, `Retry-After: 1`) — never a credential 401 and
  never a token; the response discloses nothing about slots/queue/account/credentials. Its configuration
  (`Security:PublicExposureHardening:Argon2`) is validated fail-closed at startup even when hardening is disabled.
- **Process-wide login budget (gated by `Enabled`).** One unpartitioned token bucket (30 burst / 15 per 15 s,
  `QueueLimit=0`), shared across all IPs and accounts, admitted AFTER the per-IP and per-email limiters (so a
  request already rejected there never consumes a global token) and BEFORE credential evaluation. Rejection is
  the same generic **429**; an unexpected limiter failure fails closed (503), never unrestricted login.
- **Bounded login-response jitter (gated by `Enabled`).** A uniform 25–75 ms async delay applied ONLY to the
  normal credential outcomes (200 / generic 401), after credential evaluation — never to 400/413/429/503 or a
  canceled request, and never derived from any identity data. Defense-in-depth only; it does not replace
  constant-time credential handling, Argon2 work, or rate limiting.

The login-path control order is: trusted client-IP → per-IP → 4 KiB body → per-normalized-email →
process-wide budget → credential/Argon2 admission → jitter → 200/401.

**Implemented (2D.3 — public-exposure gating):**

- **OpenAPI is Development-only.** `AddOpenApi`/`MapOpenApi` are gated behind `IsDevelopment()`; in
  Production the `/openapi/v1.json` route is absent (normal 404). No production switch is introduced — a
  future interactive-docs exposure is a separate, explicit decision.
- **Production posture fails closed at startup** (`ProductionExposureValidation`): in the Production
  environment, `LoginEnabled` requires `Security:PublicExposureHardening:Enabled = true`, and any
  repository-controlled Kestrel/`urls` listener must be loopback-only — a wildcard/public
  (`0.0.0.0`/`[::]`/`*`/`+`/public address) or malformed listener refuses to start. Development/Test are
  unaffected.
- **Host filtering** uses the built-in ASP.NET Core mechanism with `AllowedHosts =
  127.0.0.1;localhost;api.bitosx.se`; `X-Forwarded-Host` is not trusted. TLS/HSTS are terminated upstream
  (Cloudflare/Apache); Kestrel receives loopback HTTP and adds no `UseHttpsRedirection`/HSTS.

The Cloudflare→Apache→loopback-Kestrel trust boundary and its host-side enforcement (Kestrel loopback
binding, firewall, Apache real-IP config, secrets injection) are documented, with an app-enforced vs
deployment-enforced checklist and verification commands, in [`DEPLOYMENT.md`](DEPLOYMENT.md).

**Implemented (phase 7):** `POST /v1/auth/login/totp` per-IP, `/v1/account/totp/*` per-account — see
"Second factor: TOTP".

**Implemented (phase 6):** `POST /v1/auth/forgot-password` per-IP + per-normalized-email,
`POST /v1/auth/reset-password` per-IP (shared bucket), `POST /v1/account/delete` per-account — see
"Password reset and account deletion".

**Deferred:** adaptive Turnstile/CAPTCHA (separately approved later). Registration/verification limits
(`/register`, `/resend-verification`, `/verify-email`) and a global outbound-email budget remain future
policy — no dead endpoint code is added. Kestrel stays **loopback-only** and the public Apache/Cloudflare
path must not be configured until the **[host]** items in `DEPLOYMENT.md` are verified.

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
