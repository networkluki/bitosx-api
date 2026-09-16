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
- **SMTP:** Gmail `smtp.gmail.com:587` STARTTLS, TLS validation on, no bypass; failures
  isolated (never surfaced to clients). Automated tests never send real Gmail.
- **Anti-enumeration:** register/resend return a single generic 202; verify returns
  generic failures. Timing resistance is **best-effort** (SMTP off the request path;
  no dummy hashing in register) — mandatory rate limiting precedes public exposure.

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
