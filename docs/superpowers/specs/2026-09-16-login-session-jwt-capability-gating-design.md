# BitosX API — Capability Gating + Login/Session/JWT (Design Spec)

- **Status:** DESIGN ONLY. No source, migration, secret, commit, or push changes. Awaiting approval.
- **Date:** 2026-09-16
- **Baseline:** `networkluki/bitosx-api` @ `main` `65d2b2c`.
- **Scope:** (1) decouple Account/Auth from SMTP via capability-based composition; (2) design Login / Session / Refresh / Logout / account-session management + JWT. **Gmail SMTP is deferred** (outbound 25/465/587 blocked at the Linode network level; confirmed). No Login/JWT implementation in this milestone.

> **⚠️ SUPERSEDED IN PART (2026-09-17) — the implementation plan `docs/superpowers/plans/2026-09-17-login-session-jwt-refresh-implementation-plan.md` is authoritative.** Two refresh-token decisions in this spec were corrected: **(1)** the refresh-token verifier is **`SHA-256(raw 32 token bytes)`** with **no `RefreshTokenPepper` and no HMAC** (the 256-bit CSPRNG token makes plain SHA-256 adequate and matches the immutable `0001` `token_hash = SHA-256 of the opaque token` contract) — so there is **no** refresh-token secret and `LoginEnabled` depends only on `Security:JwtSigningKey`; **(2)** refresh reuse is **strict with no grace window** — any presentation of a `consumed_at`/`revoked_at` token triggers session-scoped revocation (the "rotation grace" idea below is **not** implemented; clients must single-flight refresh). Email-verification HMAC (and future phone-OTP HMAC) are separate systems and remain unchanged. Where this spec says HMAC-pepper, rotation grace, or a `RefreshTokenPepper` secret, read the plan instead.

---

## 1. Current architecture observations
- **Over-coupling:** `Program.cs` sets `accountsEnabled` only when `Security:EmailVerificationPepper` **and** `Security:EmailOutboxKey` **and** `Email:SmtpAppPassword` are all present, then calls a single `AddBitosxAccounts`. Removing the (now-deferred) SMTP app password disables the **entire** account subsystem — so it would also disable future Login. Too broad.
- **Monolithic composition:** `AddBitosxAccounts` registers password hashing, token factory, outbox crypto, stores, services, MailKit sender, and the background dispatcher together. Login needs only a subset (DB + hasher + future JWT/session), not SMTP.
- **Schema is ready for auth:** `sessions` (`id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent`) and `refresh_tokens` (`id, session_id, token_hash VARBINARY(32) UNIQUE, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id`) already support creation, rotation, linkage, reuse detection, revocation, and both expiry horizons.
- **Password verification exists:** `Argon2idPasswordHasher.Verify` (hardened PHC, `m=19 MiB, t=3, p=1, maxConcurrency=1`) is ready for login.
- **Secrets present:** `Security:EmailVerificationPepper`, `Security:EmailOutboxKey`, `ConnectionStrings:Bitosx`, `ConnectionStrings:BitosxMigrator`. Absent: SMTP app password (deferred), and **no JWT signing key or refresh pepper yet** (needed for Login).
- **Current DB state:** one unverified smoke-test account + active challenge + a pending (undeliverable) outbox row. This milestone does **not** mutate it.

---

## 2. Capability-gating design (recommended)

Three independent capabilities, each with its own DI extension and its own required config; higher capabilities require the lower ones.

| Capability | Enable condition | Provides | Endpoints |
|---|---|---|---|
| **AccountCore** | `ConnectionStrings:Bitosx` present (+ `Security:JwtSigningKey` once Login ships — **no refresh secret**, per the 2026-09-17 correction) | DB persistence, password hasher, account lookup, JWT service, session/refresh services | `/v1/auth/login`, `/refresh`, `/logout`, `/logout-all`, `/v1/account/*` |
| **EmailVerification** | AccountCore **and** `Security:EmailVerificationPepper` **and** `Security:EmailOutboxKey` | token factory, outbox payload crypto, registration/verification/resend services, outbox persistence | `/v1/auth/verify-email` always; `/register` + `/resend-verification` gated by EmailDelivery (see §3/§4) |
| **EmailDelivery** | EmailVerification **and** SMTP creds (`Email:SmtpUsername` + `Email:SmtpAppPassword` + host/port) | MailKit Gmail sender + background outbox dispatcher | (no endpoints; it powers delivery of enqueued mail) |

Composition:
- Split `AddBitosxAccounts` into `AddBitosxAccountCore(cfg)`, `AddBitosxEmailVerification(cfg)`, `AddBitosxEmailDelivery(cfg)`.
- `Program.cs` computes three booleans and calls the extensions in order; it maps endpoints per capability and exposes the booleans (see §3 `/health`).
- **Explicit flags over scattered checks:** a single `AccountCapabilities { AccountCore, EmailVerification, EmailDelivery }` singleton is registered and consulted by endpoint mapping and `/health`, rather than re-reading config in many places.
- **Fail-closed construction:** each extension validates its own required secrets at startup and throws if enabled-but-misconfigured (e.g., delivery invariant `LeaseDuration > AttemptTimeout + margin`, JWT key length).

This lets **Login run with SMTP disabled** (AccountCore needs no SMTP), which is exactly the current situation.

---

## 3. SMTP-deferred behavior — options (EmailVerification enabled, EmailDelivery disabled)

- **Option A — expose register/resend; enqueue anyway.** They return the generic `202` and write outbox rows that no dispatcher drains. *Con:* silently accumulates undeliverable rows; users are told to "check email" that never arrives; misleading.
- **Option B — disable register/resend; keep verify-email enabled (recommended).** When delivery is off, do not map `register`/`resend-verification` (or map them to a generic `503`), but keep `verify-email` mapped so already-issued links remain consumable. *Pro:* no undeliverable accumulation; no misleading 202; Login unaffected. *Con:* new registrations are unavailable until delivery returns (acceptable — email can't be delivered anyway).
- **Option C — expose register/resend but short-circuit with `503` and enqueue nothing.** *Pro:* no accumulation. *Con:* changes the generic-202 contract and advertises capability state; marginal benefit over B.

### 4. Recommended SMTP-deferred behavior
**Option B.** With `EmailDeliveryEnabled = false`:
- `register` and `resend-verification` are **not exposed** (return `404`/not-mapped, or a generic `503 email verification temporarily unavailable` — pick one; not-mapped is simplest and leaks least).
- `verify-email` **remains enabled** (consume already-issued links).
- `/health` reports capability booleans only, e.g. `{"service":"BitosX API","status":"healthy","capabilities":{"accountCore":true,"emailVerification":true,"emailDelivery":false}}` — **booleans only, never secrets or config values**. (Kept separate from the liveness `status`.)
- **No accumulation:** because register/resend are disabled, no new outbox rows are created while delivery is down. The single pre-existing smoke-test row is left as-is; it will be marked failed + payload-erased on a future dispatcher run once delivery is enabled, or when its challenge expires (a future cleanup pass handles expired rows).

---

## 5. Login endpoint design

### `POST /v1/auth/login`  (AccountCore; unauthenticated)
- **Request:** `{ "email": "...", "password": "..." }`.
- **Login invariant:** account is login-capable only if `email_verified_at IS NOT NULL AND password_hash IS NOT NULL AND disabled_at IS NULL`.
- **Flow:** normalize email → load account → if missing or not login-capable → generic `401` (see DoS §11 for hashing policy) → else `Argon2idPasswordHasher.Verify(password, phc)`; on `Failed`/`InvalidHashFormat` → generic `401`; on `NeedsRehash` → verify ok, optionally re-hash+update in the same success path (future). On success: create session + first refresh token, mint access JWT.
- **Response (200):** `{ "accessToken": "<jwt>", "accessTokenExpiresAt": "<iso8601 utc>", "refreshToken": "<base64url opaque>", "refreshTokenExpiresAt": "<iso8601 utc>" }`. Refresh token in the **body only**, never a URL/query.
- **Auth requirement:** none.
- **Generic failure:** identical `401` body/shape for unknown email, wrong password, unverified, and disabled — no distinction; never reveals whether the email exists.
- **DB transaction:** one transaction inserts the `sessions` row (`created_at=last_seen_at=now`, `absolute_expires_at=now+90d`) and the first `refresh_tokens` row (`R0`); commit before returning. Access JWT is stateless (not stored).
- **Race conditions:** two simultaneous logins → two independent sessions (fine). The Argon2 concurrency semaphore (cap=1) serializes hashing; rate limiting (§11) bounds abuse. No shared-row contention on login.

---

## 6. Session model (existing schema; no change required)
- **Session = one login on one device.** `sessions.absolute_expires_at = created_at + 90d` (hard cap). **Idle expiry** enforced via `last_seen_at + 30d`: `last_seen_at` is updated on each successful refresh; a refresh is rejected if `now > last_seen_at + 30d`. Refresh tokens carry `expires_at = min(now + 30d idle window, session.absolute_expires_at)`.
- **Revocation:** `sessions.revoked_at` (single session), or set for all account sessions (logout-all / disable). A revoked or expired session invalidates its refresh tokens and (via §10) its access tokens.
- **Refresh token hashing (CORRECTED 2026-09-17):** store **`SHA-256(raw 32 token bytes)`** in `token_hash` (VARBINARY(32) fits). The 256-bit opaque CSPRNG token makes plain SHA-256 adequate for offline-preimage resistance, matches the immutable `0001` contract, and removes the secret-lifecycle/rotation complexity of a pepper. **No `RefreshTokenPepper`, no HMAC.** *(This overrides the earlier HMAC-pepper proposal that previously sat here.)*

The schema supports session creation, refresh rotation, previous-token linkage (`replaced_by_token_id`), reuse detection (`consumed_at`), session revocation (`revoked_at`), logout-all (revoke all sessions for account), absolute expiry, idle expiry, and disabled-account revocation — **without schema changes** (see §12).

---

## 7. Refresh rotation state machine

### `POST /v1/auth/refresh`  (AccountCore; the refresh token IS the credential)
- **Request:** `{ "refreshToken": "..." }` (body only).
- States of a refresh-token row: **Active** (`consumed_at IS NULL AND revoked_at IS NULL AND expires_at > now`), **Consumed** (`consumed_at` set — rotated), **Revoked** (`revoked_at` set), **Expired** (`expires_at <= now`).
- **Normal flow (one transaction, `SELECT … FOR UPDATE` on the token row + session + account):**
  1. `R0` presented; compute verifier; lock the row by `token_hash`.
  2. Read authoritative `now` after the lock (same pattern as verify-email).
  3. Validate: `R0` Active; session `revoked_at IS NULL`, `absolute_expires_at > now`, `last_seen_at + 30d > now`; account `disabled_at IS NULL`.
  4. Conditional `UPDATE R0 SET consumed_at=now WHERE id=@id AND consumed_at IS NULL` (affected=1 or abort).
  5. Insert `R1` (new 256-bit token, HMAC hash, new expiry); `UPDATE R0 SET replaced_by_token_id=R1.id`; `UPDATE session SET last_seen_at=now`.
  6. Commit; mint a new access JWT; return `{accessToken, accessTokenExpiresAt, refreshToken=R1, refreshTokenExpiresAt}`.
- **Reuse (a Consumed or Revoked token is presented):** treat as compromise.
  - **Recommended: revoke the entire session (its whole refresh-token chain), not all account sessions.** Set `sessions.revoked_at=now` (reason `reuse_detected`), which invalidates all tokens in that session and its access tokens (via §10). Return generic `401`.
  - *Tradeoff:* revoking only the session preserves the user's other devices/sessions (better usability) while still containing the compromised chain. Revoking **all** account sessions is more aggressive (defends against an attacker who may hold multiple stolen tokens) but logs the user out everywhere on any single reuse (including benign double-submits). Given per-session isolation and the reuse being scoped to one stolen chain, **session-scoped revocation** is the balanced default; escalation to account-wide can be a future policy toggle.
- **Failure semantics:** all invalid cases (unknown token, expired, revoked, reused, session/account invalid) → identical generic `401`.

---

## 8. Concurrency / race handling
- **Two concurrent refreshes with the same `R0`:** `SELECT … FOR UPDATE` serializes them; the conditional consume (`WHERE consumed_at IS NULL`, affected=1) lets exactly one win; the loser then sees `R0` Consumed → **reuse → session revoked**. *Caveat:* a client that double-submits the same refresh can self-revoke its session. Documented; clients must not double-submit. (Optional future mitigation: a short "rotation grace" that returns the already-issued `R1` when the immediately-preceding token is presented once and its replacement is still the active head — deferred.)
- **Logout racing refresh:** both take `FOR UPDATE` on the session row; whichever commits first wins. Logout sets `revoked_at`; a refresh that locks after sees the revoked session → `401`. A refresh that commits first rotates; the subsequent logout still revokes.
- **`disabled_at` set during refresh:** the refresh transaction re-reads `account.disabled_at` under lock (join) → if set, abort with `401` and (optionally) revoke the session. Disabling an account should also bulk-revoke its sessions in the same admin action (future).
- **Absolute/idle expiry during refresh:** evaluated against the authoritative post-lock `now` inside the transaction → expired → `401`, no rotation.
- **Access-token expiry mid-request:** the API returns `401` (token `exp` passed); the client refreshes and retries. Stateless expiry needs no coordination.
- **Two simultaneous logins:** independent sessions; no shared row; Argon2 semaphore serializes CPU.
- No distributed lock service; all coordination is single-node MariaDB row locks + conditional updates.

---

## 9. JWT claims / signing model
- **Algorithm:** HS256 (symmetric) for the current single-service deployment. (If BitosX later runs multiple services that must verify without the signing secret, migrate to RS256/asymmetric — flagged, not now.)
- **Claims (minimal):** `iss` (config, e.g. `https://api.bitosx.se`), `aud` (config, e.g. `bitosx-api`), `sub` = account id (UUID), `sid` = session id (UUID), `jti` = random per-token id, `iat`, `exp` (= iat + 15 min). **Excluded:** email, phone, password metadata, vault info, roles (none exist).
- **Validation:** signature (HS256), `iss`, `aud`, `exp` with **clock skew ≤ 60 s**; then per-request session validation (§10).
- **Signing key:** `Security:JwtSigningKey` — ≥256-bit, Base64, HS256 key. **Never committed, never in DB, independent of the email pepper / outbox key / refresh pepper / vault crypto.** Generated with a CSPRNG into user-secrets (like the pepper/outbox key).
- **Rotation:** support `Security:JwtSigningKeyPrevious` accepted for **verification only** during a rollover window; since access tokens live 15 min, keep the previous key valid for ≥15 min after switching the signing key, then drop it. Optional `kid` header to select. New tokens always sign with the current key.

---

## 10. Access-token revocation model
A 15-minute HS256 JWT is normally stateless. Options:
1. **Stateless until expiry** — logout/disable take effect only after ≤15 min. Simplest; weakest.
2. **Per-request session lookup (recommended)** — after signature/exp validation, load the session by `sid` and require `revoked_at IS NULL AND absolute_expires_at > now AND last_seen_at + 30d > now AND account.disabled_at IS NULL`. Gives **immediate** logout/disable/reuse-revocation enforcement. Cost: one indexed PK read per authenticated request — negligible on a single node at BitosX volume.
3. **Session/token versioning** — embed a version claim; bump the session/account version to invalidate. Avoids a per-request row read but needs a schema column and still a lookup to learn the current version (unless cached).
- **Recommendation: Option 2 (per-request session lookup), with the 15-min `exp` as defense-in-depth.** For a security product, immediate revocation on logout/disable/reuse is worth one cheap DB read. Reuse-detected/logged-out/disabled sessions are enforced on the very next request. (If read volume ever demands it, add a short in-memory session cache with a ≤ few-seconds TTL — future.)

---

## 11. Rate-limit / Argon2 login-DoS model
Login is an expensive **unauthenticated** endpoint; with Argon2 `maxConcurrency=1` (~0.2–0.4 s/hash) it is a natural DoS/queue target. Mandatory **before public exposure** (implementation deferred, separately approved):
- **Per-IP** rate limit + exponential backoff on repeated failures.
- **Per-normalized-email / per-account** rate limit + lockout window (independent of IP).
- **Bounded Argon2 work queue:** cap queued hash operations (reject with generic `429`/`503` when saturated) so the cap=1 semaphore can't build an unbounded backlog.
- **Global login budget / circuit breaker.**
- **Adaptive Turnstile/CAPTCHA** later.
- **Enumeration:** generic `401` for all failure modes (text + status identical).
- **Dummy hashing for nonexistent accounts — recommendation: NO full Argon2 dummy on this host.** On 1 vCPU with cap=1, hashing on every nonexistent-email attempt is a CPU-amplification DoS (an attacker forces a full ~0.3 s hash per request with no valid account). Instead: **rate-limit first**, return generic `401` without Argon2 for non-login-capable accounts, and add a small randomized delay to blur the timing signal. The residual timing difference (hash vs no-hash) is acceptable given rate limiting + the Argon2 cap; a full dummy hash trades a minor enumeration signal for a serious DoS amplifier — a bad trade here. (Explicit decision; confirm.)

---

## 12. Required schema changes
- **Mandatory: none.** The existing `sessions`/`refresh_tokens` schema supports every required capability using per-request session lookup for revocation.
- **Optional `0003` (observability/ergonomics), not created now:**
  - `ALTER TABLE sessions ADD COLUMN revoked_reason VARCHAR(32) NULL` (values: `logout`, `logout_all`, `reuse_detected`, `disabled`, `superseded`) for audit/telemetry.
  - (Only if Option 3 revocation is later chosen: `sessions.token_version INT NOT NULL DEFAULT 0`.)
  - A composite index to speed session listing (`sessions(account_id, revoked_at)`) if `/account/sessions` volume warrants.
- `0001`/`0002` are immutable; any change is a new `0003` authored + reviewed separately. `refresh_tokens.token_hash VARBINARY(32)` already fits the **SHA-256** verifier (correction 2026-09-17) — no change.

---

## 13. Security invariants (reaffirmed)
- **Zero-knowledge:** Login/JWT never receive or store the vault master password, raw Vault Key, decrypted vault entries, item passwords, or (future) vault TOTP secrets. Account authentication is entirely separate from vault encryption. Account password ≠ vault master password.
- No plaintext account password persisted (Argon2id PHC only); no plaintext refresh token persisted (HMAC verifier only); access JWTs not stored.
- Generic responses: no email enumeration via body or status; login/refresh failures are uniform.
- JWT signing key, refresh pepper, verification pepper, outbox key, SMTP app password are mutually independent, out of Git/DB, in the secret store only.
- OpenAPI remains a public-exposure blocker; auth endpoints stay loopback-only operationally; Apache/Cloudflare unchanged.
- Login-capable ⟺ `email_verified_at IS NOT NULL AND password_hash IS NOT NULL AND disabled_at IS NULL`.

---

## 14. Test strategy
- **Unit:** JWT create/validate (claims present/absent, `iss`/`aud`/`exp`/skew, HS256 signature, previous-key verification during rotation, tamper → reject); refresh rotation state machine with fakes (active→consumed→replaced; reuse→session-revoke; expired/revoked → invalid); login invariant (unverified/no-password/disabled all rejected generically); refresh HMAC verifier determinism; capability-flag computation.
- **Integration (bitosx_test):** login creates session + `R0`; refresh rotates + updates `last_seen_at`; reuse of `R0` revokes the session; concurrent refresh with same token → exactly one rotates, other trips reuse (FOR UPDATE); logout / logout-all revoke; `disabled_at` set mid-refresh → reject; absolute/idle expiry → reject; `/account/me`, `/account/sessions`, `DELETE /account/sessions/{id}` (ownership enforced, generic 404 for others'); per-request revocation (access token rejected immediately after logout/disable).
- **Security:** no vault fields anywhere; no enumeration (identical responses for unknown vs wrong-password vs disabled); refresh token never stored plaintext; JWT signing key/refresh pepper absent from committed config; capability gating — **login works with SMTP disabled**, register/resend disabled when delivery off, verify-email still works.
- **Endpoint tests** via `WebApplicationFactory` with capabilities toggled through config (as the existing `AuthApiFactory` does). No real Gmail.

---

## 15. Proposed implementation phases
1. **Capability-gating refactor** — split `AddBitosxAccounts` into AccountCore/EmailVerification/EmailDelivery; `Program.cs` flags; `AccountCapabilities` singleton; `/health` capability booleans; SMTP-deferred behavior (Option B). *(Re-enables register/verify appropriately and unblocks Login composition; no login endpoints yet.)*
2. **JWT service** — signing key handling (+ rotation), claims, issue/validate, clock skew. New secret `Security:JwtSigningKey`.
3. **Login** — `POST /v1/auth/login`; session + `R0` creation stores. *(No `RefreshTokenPepper` — SHA-256 verifier; correction 2026-09-17.)*
4. **Refresh rotation + reuse detection** — `POST /v1/auth/refresh`; transactional rotation, **strict reuse** (any consumed/revoked-token presentation → session revoke; no grace window), concurrency.
5. **Logout / logout-all** + per-request session validation (auth handler that loads the session by `sid`).
6. **Account/session management** — `GET /v1/account/me`, `GET /v1/account/sessions`, `DELETE /v1/account/sessions/{id}`.
7. **Rate limiting / DoS protections** (separately approved) — required before any public exposure.
8. **Docs** updated each phase (`ARCHITECTURE`, `SECURITY_MODEL`, `API`, `PERSISTENCE`). Optional `0003` only if `revoked_reason`/index is wanted.

Each phase: TDD (RED→GREEN), local commits, no push until milestone review.

---

## 16. Risks / unresolved questions (need decisions)
1. **Access-token revocation:** confirm **Option 2 (per-request session lookup)** vs stateless-until-expiry.
2. **Refresh reuse scope:** confirm **session-scoped revocation** vs account-wide on reuse. Also: accept the double-submit self-revoke caveat, or build the rotation-grace window now?
3. **Dummy-hash-for-nonexistent:** confirm **NO full Argon2 dummy** on 1 vCPU (rate-limit + generic 401 + small jitter instead).
4. **New secrets (CORRECTED 2026-09-17):** only `Security:JwtSigningKey` (HS256, ≥256-bit), CSPRNG into user-secrets. The refresh token needs **no** secret (SHA-256 verifier) — the `RefreshTokenPepper` once proposed here was removed.
5. **JWT alg:** confirm **HS256** for now (RS256 only if multi-service verification is needed later).
6. **`iss`/`aud`:** confirm values (proposed `https://api.bitosx.se` / `bitosx-api`) and 60 s clock skew.
7. **`0003`:** author the optional `revoked_reason`/index migration now, or defer? (No mandatory schema change either way.)
8. **SMTP-deferred register/resend:** confirm **not-mapped** vs generic `503`.
9. **`/health` capabilities:** confirm exposing capability booleans is acceptable (they reveal feature availability, not secrets).
10. **Rate limiting** remains a hard **public-exposure blocker**; login stays loopback-only until it exists.

No source, migration, secret, commit, or push changes were made. Awaiting approval/decisions before Phase 1.
