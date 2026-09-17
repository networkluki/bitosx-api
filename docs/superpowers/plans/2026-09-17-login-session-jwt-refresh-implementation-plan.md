# BitosX API — Phase 2 Implementation Plan

**Login · Sessions · Access JWT · Refresh Rotation · Reuse Detection · Logout · Session Management**

- **Status:** PLAN ONLY. No source, test, migration, secret, commit, or push changes. Awaiting approval.
- **Date:** 2026-09-17
- **Baseline:** `networkluki/bitosx-api` @ `main` = `origin/main` = `d80dabcaf42fc171b0a7981a0f8124c0a8e311bd` (clean tree).
- **Approved design spec this plan implements:** `docs/superpowers/specs/2026-09-16-login-session-jwt-capability-gating-design.md` (all §16 decisions treated as approved: per-request session lookup revocation; session-scoped reuse revocation + 5s duplicate window; NO full dummy Argon2; HS256; `iss=https://api.bitosx.se` / `aud=bitosx-api`; 60s skew; defer rate limiting; no mandatory `0003`).
- **Current prod capabilities (unchanged by Phase 2):** AccountCore=true, EmailVerification=true, EmailDelivery=false. Gmail SMTP stays deferred.
- **Review decisions incorporated (2026-09-17):** **all §17 questions (1–9) are now RESOLVED** and folded into the affected sections. Additional approved directives folded in: **login request-body hardening** (§5.4), **refresh-pepper stability / no silent rotation** (§12.1), the **account-disable future invariant** (§19), and two final clarifications — **(A) previous-key config names** `Security:JwtPreviousSigningKey` / `Security:Jwt:PreviousKeyId` (paired, fail-closed) and **(B) `IAccessTokenService` is issuance-only** with a single shared `IJwtValidationParametersFactory` owning validation params (JwtBearer is the only validator). Phase 2A has **not** started: sequence is finalize plan → consistency review (done) → one approved docs-only local commit → then Phase 2A.
- **Hardening pass incorporated (2026-09-17, post-review):** **(1)** the JWT validation-parameters factory lives in **Infrastructure**, never Application (Application references no IdentityModel/JwtBearer/`TokenValidationParameters`); **(2)** a dedicated **`AddBitosxLogin`** composition method (registered only when `LoginEnabled`) — `AddBitosxAccountCore` stays clean; **(3)** an explicit **`LoginEnabled` fail-closed matrix** (§3.5); **(4)** explicit **accounts→sessions→refresh_tokens** lock hierarchy via separate `FOR UPDATE` statements + pre-tx non-authoritative locator + deadlock handling (§6/§7); **(5)** strengthened **kid/alg fail-closed test matrix** incl. no all-keys fallback (§13.2); **(6)** updated Phase 2A file map (§14).

---

## 1. Repository observations

### 1.1 Layering & composition (verified in tree)
- Modular monolith: `BitosX.Api` (host/composition root/endpoints) → `Application` (use-cases + abstractions) → `Infrastructure` (Dapper/MariaDB, crypto) → `Contracts` (DTOs). Dependencies point inward; `Contracts` depends on nothing.
- Capability composition already exists: `AccountsServiceCollectionExtensions.DetectCapabilities` + `AddBitosxAccountCore` / `AddBitosxEmailVerification` / `AddBitosxEmailDelivery`, gated in `Program.cs`. **AccountCore is already SMTP-independent** — Login composes into AccountCore and needs no SMTP.
- Endpoint style: minimal APIs, `MapGroup("/v1/...")`, handler-injected services via DI, `Results.Problem`/`Results.Json`. See `src/BitosX.Api/Endpoints/AuthEndpoints.cs`.
- Program exposes `public partial class Program;` for `WebApplicationFactory<Program>`; there is a DI seam `IEnumerable<Action<IEndpointRouteBuilder>>` used by tests to exercise the production error pipeline.

### 1.2 Data access patterns (verified — must be mirrored)
- **MySqlConnector + Dapper**, snake_case↔PascalCase via `DefaultTypeMap.MatchNamesWithUnderscores = true` (set in `PersistenceServiceCollectionExtensions.ConfigureDapper` and the test fixture). No EF Core.
- **Connection factory:** `BitosxConnectionFactory.OpenConnectionAsync(ct)`; runtime string is DML-only.
- **Transactional/locking pattern (authoritative reference: `EmailVerificationStore.FinalizeVerificationAsync`):**
  1. `BeginTransactionAsync`.
  2. `SELECT ... FOR UPDATE` locking the target row(s) **without an expiry predicate** (a caller-supplied time can be stale after a lock wait).
  3. Read authoritative `now = _clock.GetUtcNow().UtcDateTime` **only after** the lock is held.
  4. Evaluate expiry/state against that `now`.
  5. Conditional `UPDATE ... WHERE <still-in-expected-state>` and assert `affectedRows == 1`, else rollback.
  6. `CommitAsync`; return an **outcome enum** (never throw for expected business states).
- Duplicate-key handling: `catch (MySqlException ex) when (ex.ErrorCode == MySqlErrorCode.DuplicateKeyEntry)` → map to an outcome (see `AccountRegistrationStore`).
- Multi-row atomic insert pattern: `AccountRegistrationStore.CreateUnverifiedAccountWithChallengeAndOutboxAsync` (account + challenge + outbox in one tx) — the template for login's session + R0 insert.

### 1.3 Security primitives (reuse, do not re-implement)
- `IAccountPasswordHasher` (`Argon2idPasswordHasher`): `Verify` returns `Success | Failed | NeedsRehash | InvalidHashFormat`; validates PHC bounds **before** running Argon2; a `SemaphoreSlim(MaxConcurrency)` gate (prod cap=1) bounds concurrent hashing. **Login MUST reuse this**; no second hasher.
- `HmacEmailVerificationTokenFactory`: `HMAC-SHA256(pepperBytes, tokenBytes)`, 256-bit tokens, Base64URL. **This is the shape the refresh token factory mirrors** — but with a *stricter* decoder (see §12).
- Email normalization: `EmailNormalizer.Normalize` + `EmailAddressValidator.IsValid` (reuse for login).

### 1.4 Test infrastructure (verified — reuse)
- `WebApplicationFactory<Program>` + `builder.UseSetting(...)` for config (NOT `ConfigureAppConfiguration` — applies too late for minimal hosting). See `AuthApiFactory` / `CapabilityApiFactory`.
- Test DB `bitosx_test` via user-secrets id `bitosx-infrastructure-tests`, keys `ConnectionStrings:BitosxTest` (migrator-capable) and `ConnectionStrings:BitosxTestRuntime` (DML-only). Prod DB is never touched.
- `DatabaseFixture` applies migrations once, `[Collection("Persistence")]`, resets with `DELETE FROM email_outbox; DELETE FROM accounts;` — **sessions/refresh_tokens cascade from `accounts` via `ON DELETE CASCADE`**, so reset already clears them.
- Fakes for unit tests in `Application.Tests/Fakes.cs` (`FakeAccountRepository`, `SpyPasswordHasher`, etc.) — extend with fakes for the new stores.
- `FakeTimeProvider` (Microsoft.Extensions.Time.Testing) drives authoritative time in store tests (`AccountsTestContext.Clock`).

### 1.5 Current secrets present / absent
- Present: `ConnectionStrings:Bitosx`, `ConnectionStrings:BitosxMigrator`, `Security:EmailVerificationPepper`, `Security:EmailOutboxKey`.
- **Absent (needed for Phase 2, generated later, never in this milestone):** `Security:JwtSigningKey`, `Security:RefreshTokenPepper`.

---

## 2. Existing schema fit analysis (prove no migration required)

Schema is in `0001_initial_account_schema.sql` (+ `0002`). Both immutable.

### 2.1 `accounts` — login invariant & disable
Columns present: `email_verified_at`, `password_hash`, `disabled_at`, `normalized_email UNIQUE`. → **Login invariant** `email_verified_at IS NOT NULL AND password_hash IS NOT NULL AND disabled_at IS NULL` is fully expressible. Disable = `disabled_at` set. **Fit: complete.**

### 2.2 `sessions`
`id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent`, FK→accounts `ON DELETE CASCADE`, `INDEX ix_sessions_account_id`.

| Required transition | Representable? | How |
|---|---|---|
| Create session on login | ✅ | INSERT (`created_at=last_seen_at=now`, `absolute_expires_at=now+90d`) |
| Idle expiry (30d) | ✅ | reject refresh when `now - last_seen_at >= 30d` |
| Absolute expiry (90d) | ✅ | reject when `now >= absolute_expires_at` |
| Revoke one session (logout / reuse / delete) | ✅ | `revoked_at = now` |
| Revoke all (logout-all / disable) | ✅ | `UPDATE ... WHERE account_id=@id AND revoked_at IS NULL` |
| List sessions for account | ✅ | `WHERE account_id=@id` (uses `ix_sessions_account_id`) |
| Per-request access-token revocation | ✅ | PK lookup by `sid` + `revoked_at IS NULL` + expiry + account join |

### 2.3 `refresh_tokens`
`id, session_id, token_hash VARBINARY(32) UNIQUE, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id (self-FK, ON DELETE SET NULL)`, FK→sessions CASCADE, `INDEX ix_refresh_tokens_session_id`.

| Required transition | Representable? | How |
|---|---|---|
| Store verifier only (never plaintext) | ✅ | `token_hash` = HMAC-SHA256(pepper, rawBytes); 32 bytes fits VARBINARY(32) |
| Lookup by presented token | ✅ | `WHERE token_hash=@verifier` (UNIQUE index → PK-grade lookup + lock) |
| Rotate R0→R1 | ✅ | INSERT R1; `UPDATE R0 SET consumed_at=now, replaced_by_token_id=R1.id` |
| Reuse detection | ✅ | presented token already has `consumed_at` (or `revoked_at`) set |
| **5-second duplicate window** | ✅ | compare `now - consumed_at < 5s` — `consumed_at` is the authoritative source |
| Revoke chain on reuse | ✅ (via session) | set `sessions.revoked_at`; all its tokens invalid by join |
| Per-token expiry | ✅ | `expires_at` |

### 2.4 Verdict on migration 0003
**No migration is required for Phase 2** (see §18 for full justification against every transition). Optional `0003` (a `revoked_reason` audit column, a `sessions(account_id, revoked_at)` composite index) is **ergonomics/observability only, deferred, NOT authored now.** `revoked_reason` will instead be captured in structured logs (§11.2) so no schema dependency exists.

### 2.5 DB privileges
Runtime account is **database-level DML-only** (verified by `DatabasePrivilegeTests`: DDL denied, `SELECT`/DML allowed). Login/refresh/logout use only `INSERT`/`UPDATE`/`SELECT ... FOR UPDATE` on existing tables → **no grant change, no DDL, no migrator involvement.**

---

## 3. Required interfaces / models

### 3.1 Domain models — already present, reuse as-is
- `BitosX.Application.Sessions.Session`, `BitosX.Application.Sessions.RefreshToken`, `BitosX.Application.Accounts.Account`. No changes needed.

### 3.2 New Application abstractions (interfaces)
- `Security/IAccessTokenService` — **ISSUANCE-ONLY** (Clarification 2). Mints access JWTs; **contains no production `Validate()`** — request-path validation is owned entirely by `Microsoft.AspNetCore.Authentication.JwtBearer` (Decision 1). Its contract uses **only BitosX-owned primitive/model types** (`Guid`, `DateTime`, a small `AccessToken` record) — **no IdentityModel/JwtBearer/`TokenValidationParameters` types**, so it stays in Application without breaking the inward dependency boundary. Infrastructure implements it with `Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler`.
  - `AccessToken Issue(Guid accountId, Guid sessionId, DateTime nowUtc)` → `{ string Token; DateTime ExpiresAt; Guid Jti; }` (header carries current `kid`; signs with current key only).
- **JWT validation-parameters factory — lives in INFRASTRUCTURE, not Application (Correction 1).** Because it returns `Microsoft.IdentityModel.Tokens.TokenValidationParameters`, it must not sit in `BitosX.Application` (that would make the Application layer depend on IdentityModel framework types, violating the inward boundary). It is defined and implemented entirely in `BitosX.Infrastructure` (`Security/JwtTokenValidationParametersFactory`, optional `IJwtValidationParametersFactory` interface) and consumed by `BitosX.Api` (which already depends on Infrastructure). See §4.4/§8. **This factory — not a second validator — is what Phase 2A unit-tests.** There must never be two independently-maintained JWT validators.
- `Security/IRefreshTokenFactory` — generate + verify refresh tokens (Infrastructure implements HMAC).
  - `GeneratedRefreshToken Generate()` → `{ string TokenBase64Url; byte[] Verifier; }`.
  - `bool TryComputeVerifier(string presented, out byte[] verifier)` — **strict** parse (§12); returns false (no throw) on malformed/wrong-length input.
- `Abstractions/Persistence/ISessionStore` — login create, refresh rotate, logout, logout-all, list, delete, session lookup for auth.
- **Login account reads (two distinct reads per Decision 3):**
  - `Abstractions/Persistence/IAccountRepository.GetByNormalizedEmailAsync` (already exists) — **non-locking** candidate read (returns `password_hash`, `email_verified_at`, `disabled_at`); used to decide login-capability and to run Argon2 **outside** any transaction/lock.
  - `ISessionStore.CreateSessionOnLoginAsync(...)` performs the **post-Argon2 locked re-check + writes** in one transaction: `SELECT ... FOR UPDATE`, authoritative post-lock time, re-verify invariant **and that `password_hash` still equals the exact PHC string already verified**, then INSERT session + R0. It does **not** re-run Argon2.

### 3.3 New options (Decision 6 — names/values fixed)
- `Security/JwtOptions`:
  - **Secrets (flat):** `Security:JwtSigningKey` (current, base64, ≥32 bytes; **required when LoginEnabled**), optional `Security:JwtPreviousSigningKey`.
  - **Non-secret (nested `Security:Jwt:*`):** `Security:Jwt:Issuer` = `https://api.bitosx.se`, `Security:Jwt:Audience` = `bitosx-api`, `Security:Jwt:AccessTokenLifetimeSeconds` = `900`, `Security:Jwt:ClockSkewSeconds` = `60`, `Security:Jwt:KeyId` (current kid, e.g. `k1`; **required when LoginEnabled**, kid is mandatory — Q5), optional `Security:Jwt:PreviousKeyId`.
  - **Previous-key pairing / fail-closed composition:** `Security:JwtPreviousSigningKey` is optional **unless** `Security:Jwt:PreviousKeyId` is set — the two must be **present together**; a partial previous-key configuration (one without the other) **fails closed** at startup. The current key + current kid are required when LoginEnabled; a missing/short current key fails closed. Sign only with the current key; verification may temporarily accept current + previous during the documented rotation overlap (§8).
- `Security/RefreshTokenOptions` — **secret** `Security:RefreshTokenPepper` (flat, unchanged); non-secret `IdleLifetime` (default 30d), `AbsoluteLifetime` (default 90d), `ReuseGraceWindow` (default 5s). **The pepper is a stable server secret — never silently rotated (§12.1).**

### 3.4 New Application services
- `Sessions/LoginService` (`ILoginService`) — orchestrates §9.
- `Sessions/RefreshService` (`IRefreshService`) — orchestrates §11 state machine.
- `Sessions/SessionManagementService` (`ISessionManagementService`) — logout, logout-all, list, delete, /me.
- `Sessions/SessionAuthenticator` (`ISessionAuthenticator`) — the **session-state lookup** service invoked by the JwtBearer `OnTokenValidated` seam **after** JwtBearer has validated the JWT (§9). It performs only the per-request session/account check (§9); it is **not** a bearer/authentication handler and does no JWT crypto.

### 3.5 `LoginEnabled` capability — fail-closed detection matrix (Correction 3)

Computed once in `DetectCapabilities` (never re-read in endpoints). **Primary enable secrets:** `Security:JwtSigningKey` and `Security:RefreshTokenPepper`.

| `JwtSigningKey` | `RefreshTokenPepper` | Result |
|---|---|---|
| absent | absent | `LoginEnabled = false` (Login not requested) |
| present | absent | **startup fails closed** (throw) |
| absent | present | **startup fails closed** (throw) |
| present | present | **Login requested → validate ALL login/JWT config (below); fail closed on any invalid item** |

**When Login is requested (both primary secrets present), require (else throw at startup):**
- `Security:JwtSigningKey` decodes correctly and is **≥ 32 bytes** of key material.
- `Security:Jwt:KeyId` present and valid (non-blank; the mandatory current kid).
- `Security:Jwt:Issuer` valid/non-blank.
- `Security:Jwt:Audience` valid/non-blank.
- `Security:Jwt:AccessTokenLifetimeSeconds` valid (> 0; default 900 if unset is acceptable — a present-but-invalid value throws).
- `Security:Jwt:ClockSkewSeconds` valid (≥ 0; default 60 if unset).
- `Security:RefreshTokenPepper` valid and **≥ 32 bytes**.

**Previous-key rules (rotation):**
- `Security:JwtPreviousSigningKey` and `Security:Jwt:PreviousKeyId` must be **both present or both absent** — a partial pair **fails closed**.
- A previous-key pair present **without** valid current login configuration is invalid → **fail closed** (no partial rotation config may silently disable itself).
- When present, `JwtPreviousSigningKey` must also decode to ≥ 32 bytes.

**Non-secret metadata tolerance:** non-secret keys such as `Security:Jwt:KeyId` may exist while **both** primary secrets are absent **without** enabling Login (they are inert) — unless a concrete reason later makes that fatal. Only the two primary secrets gate `LoginEnabled`.

These rules mirror the existing EmailVerification partial-config fail-closed policy. Explicit capability tests are added to the Phase 2A test plan (§13.7).

---

## 4. Exact proposed files to add/change

> All paths relative to repo root. **This section is the change map for implementation phases (§14); nothing is written in this planning milestone.**

### 4.1 Contracts (new)
- `src/BitosX.Contracts/Accounts/LoginContracts.cs` — `LoginRequest(Email, Password)`, `TokenResponse(AccessToken, AccessTokenExpiresAt, RefreshToken, RefreshTokenExpiresAt)`, `RefreshRequest(RefreshToken)`, `MeResponse(AccountId, Email, EmailVerified, CreatedAt)`, `SessionResponse(Id, CreatedAt, LastSeenAt, ExpiresAt, Current)`. **`SessionResponse` deliberately excludes raw `user_agent` (Decision 8)** — no token hashes, chain ids, or jti either.

### 4.2 Application (new)
- `src/BitosX.Application/Security/IAccessTokenService.cs` (BitosX-owned types only — no IdentityModel)
- `src/BitosX.Application/Security/IRefreshTokenFactory.cs`
- `src/BitosX.Application/Security/JwtOptions.cs`, `RefreshTokenOptions.cs` (POCO options — plain values/`TimeSpan`, no framework types)
- `src/BitosX.Application/Abstractions/Persistence/ISessionStore.cs` (+ result/view records + outcome enums)
- `src/BitosX.Application/Sessions/LoginService.cs` (+ `LoginCommand`, `LoginResult`)
- `src/BitosX.Application/Sessions/RefreshService.cs` (+ `RefreshCommand`, `RefreshResult`)
- `src/BitosX.Application/Sessions/SessionManagementService.cs`
- `src/BitosX.Application/Sessions/SessionAuthenticator.cs` (+ `AuthenticatedPrincipal`)
- **NOT in Application (Correction 1):** the JWT validation-parameters factory — it lives in Infrastructure (§4.4). `BitosX.Application` must NOT reference `Microsoft.IdentityModel.Tokens`, `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.AspNetCore.Authentication.JwtBearer`, or `TokenValidationParameters`.

### 4.3 Application (change)
- `src/BitosX.Application/Abstractions/Persistence/IAccountRepository.cs` — add `GetLoginCandidateForUpdateAsync` **OR** put the locked login read on `ISessionStore` (recommendation: `ISessionStore`, since login's account-read participates in the login transaction). Decide in Phase 2B.

### 4.4 Infrastructure (new)
- `src/BitosX.Infrastructure/Security/JwtAccessTokenService.cs` (HS256 **issuance-only** via `JsonWebTokenHandler`; header carries current `kid`).
- `src/BitosX.Infrastructure/Security/JwtTokenValidationParametersFactory.cs` (+ optional `src/BitosX.Infrastructure/Security/IJwtValidationParametersFactory.cs` — a concrete factory alone is acceptable if the interface adds no value) — the single shared `TokenValidationParameters` source (HS256-only, issuer/audience/60 s skew, mandatory-kid resolver over current+optional-previous, fail-closed). **Lives entirely in Infrastructure (Correction 1)**; consumed by `BitosX.Api`/JwtBearer in 2B and unit-tested in 2A. **`BitosX.Application` never references it or `TokenValidationParameters`.**
- `src/BitosX.Infrastructure/Security/HmacRefreshTokenFactory.cs` (mirror of the email token factory, strict decode).
- `src/BitosX.Infrastructure/Persistence/SessionStore.cs` (all session/refresh SQL — statements detailed inline in §5/§6/§7/§9).

### 4.5 Infrastructure (change) — separate `AddBitosxLogin` composition method (Correction 2)
- **`AddBitosxAccountCore` stays clean — UNCHANGED in responsibility:** account-core services + Argon2id password hashing only. It is **not** expanded into a secret-dependent auth composition method and gains **no** JWT/refresh/session registrations.
- **New `AddBitosxLogin(configuration, runtimeConnectionString)` in `AccountsServiceCollectionExtensions.cs`** — registered **only when `AccountCapabilities.LoginEnabled == true`**. It owns registration of: `IAccessTokenService` (issuance), the Infrastructure `JwtTokenValidationParametersFactory` (validation params), `IRefreshTokenFactory`, `ISessionStore`, `ILoginService`, `IRefreshService`, `ISessionManagementService`, `ISessionAuthenticator`, and binds/validates `JwtOptions`+`RefreshTokenOptions` (fail closed, incl. paired previous-key config — §3.3/§3.5/§8). No raw login-capability config is re-read in endpoints; the `AccountCapabilities` singleton + `DetectCapabilities` remain the single source.
- **Desired composition order (Program.cs / composition root):**
  ```
  AddBitosxAccountCore(...)
  if EmailVerificationEnabled: AddBitosxEmailVerification(...)
  if EmailDeliveryEnabled:     AddBitosxEmailDelivery(...)
  if LoginEnabled:             AddBitosxLogin(...)
  ```
- **Phase split:** Phase 2A implements + unit/integration-tests `AddBitosxLogin` (composition + fail-closed validation) **without** wiring HTTP endpoints or JwtBearer. Program.cs endpoint/JwtBearer wiring may remain Phase 2B, but the `AddBitosxLogin` composition boundary is explicit now.
- `AccountCapabilities` — add `LoginEnabled` (computed in `DetectCapabilities`; see the §3.5 fail-closed matrix). AccountCore/EmailVerification/EmailDelivery flags unchanged.

### 4.6 Api (change)
- `src/BitosX.Api/Endpoints/AuthEndpoints.cs` — add `login`, `refresh`, `logout`, `logout-all` (mapped when `LoginEnabled`); each with an endpoint-specific 4 KiB body limit + strict field-length validation (§5.4).
- New `src/BitosX.Api/Endpoints/AccountEndpoints.cs` — `/v1/account/me`, `/v1/account/sessions`, `DELETE /v1/account/sessions/{id}` (mapped when `LoginEnabled`; require auth).
- `src/BitosX.Api/Program.cs` — under `if (capabilities.LoginEnabled)` call **`AddBitosxLogin(...)`** (Correction 2); **register `Microsoft.AspNetCore.Authentication.JwtBearer` (Decision 1)** configured from the Infrastructure `JwtTokenValidationParametersFactory` (the single shared HS256-only params), plus `AddAuthentication`/`AddAuthorization` and the `UseAuthentication`/`UseAuthorization` middleware; map the new groups under `LoginEnabled`; log `LoginEnabled` in the capability line. (This wiring may land in Phase 2B; the composition boundary is fixed now.)
- New `src/BitosX.Api/Auth/SessionValidation.cs` — the **single authorization seam** implemented as the JwtBearer `OnTokenValidated` event (or an authorization policy/endpoint filter) that performs the per-request session lookup (§9/§15). **Not a bespoke bearer `AuthenticationHandler`** — JwtBearer does the crypto/claims validation; this adds only the session-state check.

### 4.7 Tests (new) — TDD, added **before** the code they cover
- `tests/BitosX.Application.Tests/` — `JwtAccessTokenServiceTests` unit is Infra; here: `LoginServiceTests`, `RefreshServiceTests`, `SessionManagementServiceTests`, `RefreshTokenParserTests` (via fakes), extend `Fakes.cs` with `FakeSessionStore`, `FakeAccessTokenService`, `FakeRefreshTokenFactory`.
- `tests/BitosX.Infrastructure.Tests/` — `JwtAccessTokenServiceTests` (issuance), `JwtValidationParametersFactoryTests` (the single shared validator params + mandatory-kid/fail-closed cases), `HmacRefreshTokenFactoryTests`, `SessionStoreTests` (real `bitosx_test`), `RefreshRotationTests`, `RefreshReuseTests`, `RefreshConcurrencyTests`, `LoginStoreTests`, extend `AccountsTestContext`.
- `tests/BitosX.Api.Tests/` — `LoginEndpointTests`, `RefreshEndpointTests`, `LogoutEndpointTests`, `SessionAuthorizationTests`, `AccountEndpointsTests`; a `LoginApiFactory` (sets JWT key + refresh pepper via `UseSetting`, ephemeral).

### 4.8 Docs (change, per phase)
- `docs/API.md` (new endpoint contracts), `docs/ARCHITECTURE.md` (auth composition + authorization seam), `docs/SECURITY_MODEL.md` (token/session/reuse model, DoS deferral), `docs/PERSISTENCE.md` (session/refresh SQL + locking + why no `0003`).

### 4.9 Project references (Decision 1 — dependency boundary; NOT added in this planning step)
- **JWT issuance + validation-parameters factory** (`Microsoft.IdentityModel.JsonWebTokens` / `Microsoft.IdentityModel.Tokens`) → referenced by **`BitosX.Infrastructure`** only (it consumes them for `JwtAccessTokenService` **and** `JwtTokenValidationParametersFactory`, both Infrastructure-resident per Correction 1).
- **Protected-endpoint authentication** (`Microsoft.AspNetCore.Authentication.JwtBearer`) → referenced by **`BitosX.Api`** (the host that configures authentication, consuming the Infrastructure factory). Prefer this standard package over any custom bearer middleware.
- **`BitosX.Application` references NONE of these** — not `Microsoft.IdentityModel.Tokens`, `Microsoft.IdentityModel.JsonWebTokens`, `Microsoft.AspNetCore.Authentication.JwtBearer`, or `TokenValidationParameters`. The inward dependency boundary (Api→Infrastructure→Application→Contracts) is preserved.
- **Requirements:** explicit **pinned** versions (no floating/`*`), `packages.lock.json` updated, `dotnet restore --locked-mode` must succeed, keep each reference **only** in the project that actually consumes it, avoid duplicate direct references (JwtBearer transitively brings the IdentityModel libraries — reference `JsonWebTokens`/`Tokens` directly only in Infrastructure). Added at the start of Phase 2A, only after Phase 2A is approved.

---

## 5. Login transaction (exact flow)

### 5.1 `LoginService.LoginAsync(LoginCommand{Email,Password,UserAgent?})` — Argon2 OUTSIDE the lock (Decision 3)
1. **Bound + normalize input (Decision 2 + body hardening §5.4):** enforce strict max field lengths on `email`/`password` **before** any work; `EmailNormalizer.Normalize(email)`. If the email value is not a valid email (`!EmailAddressValidator.IsValid`) → **generic 401** invalid-credentials (same shape as every other login failure — no distinction between unknown / bad-password / invalid-format / unverified / disabled / null-hash). (Malformed JSON / structurally invalid HTTP → 400; oversized body → 413 — these are transport errors, not credential outcomes; see §5.4/§11.)
2. **Non-locking candidate read:** `IAccountRepository.GetByNormalizedEmailAsync(normalized)` (no `FOR UPDATE`, no transaction). Capture the exact `password_hash` PHC string.
3. **Login-capability gate (no Argon2 for non-capable):** if row missing ∨ `email_verified_at IS NULL` ∨ `password_hash IS NULL` ∨ `disabled_at IS NOT NULL` → generic 401. **Argon2 is NOT run** (§10 — no dummy hash).
4. **Verify Argon2 OUTSIDE any transaction/row lock:** `IAccountPasswordHasher.Verify(password, phc)` (Argon2 concurrency gate only; no DB lock held). `Failed`/`InvalidHashFormat` → generic 401. `Success`/`NeedsRehash` → proceed (`NeedsRehash` → success now; opportunistic re-hash deferred — §17 Q4).
5. **Begin transaction.**
6. `SELECT id, password_hash, email_verified_at, disabled_at FROM accounts WHERE normalized_email=@n FOR UPDATE;` (lock the same account row).
7. Authoritative `now` + state read **after** the lock.
8. **Re-check under lock:** row still exists ∧ `email_verified_at IS NOT NULL` ∧ `password_hash IS NOT NULL` ∧ `disabled_at IS NULL` ∧ **`password_hash` still equals the exact PHC string verified in step 4** (`StringComparer.Ordinal`). If anything changed (password changed / account disabled / verified-state changed while Argon2 ran) → **rollback + generic 401**. **Argon2 is NOT re-run under the lock.**
9. Generate session id; INSERT `sessions` (`created_at=last_seen_at=now`, `absolute_expires_at=now + AbsoluteLifetime`, `revoked_at=NULL`, `user_agent`); assert affected==1.
10. `IRefreshTokenFactory.Generate()` → raw R0 (Base64URL) + verifier; INSERT `refresh_tokens` R0 (`token_hash=verifier`, `created_at=now`, `expires_at=min(now+IdleLifetime, session.absolute_expires_at)`); assert affected==1.
11. `CommitAsync`. Return committed `{ accountId, sessionId, refreshTokenPlaintext (in-memory only), refreshTokenExpiresAt }`.
12. **Only after commit succeeds**, `IAccessTokenService.Issue(accountId, sessionId, now)` mints the access JWT (never before the session row is durable). Access JWT is stateless — not stored.
13. Return `TokenResponse`.

### 5.2 Transaction boundary + the Argon2/state race (documented explicitly)
- **Argon2 runs entirely outside the DB transaction and holds no row lock** (Decision 3) — the 1 vCPU host must never extend a lock across a ~0.3 s hash; that would amplify lock-contention/DoS.
- The transaction (steps 5–11) is short: lock account row → post-lock re-check (incl. exact-PHC equality) → INSERT session + R0 → commit.
- **The race:** the account's `password_hash`/state can change between the non-locking verify (step 4) and acquiring the lock (step 6). Step 8's **exact-PHC-equality re-check under lock** closes it: if the stored hash no longer equals the string that was verified (e.g. a concurrent password change), or the account became disabled/unverified, login fails generically with no session issued. A stale successful Argon2 result can therefore never mint a session against a changed credential. (Cost: on the rare change-during-login, the user simply retries; correctness is preserved.)

### 5.3 Raw refresh-token bytes lifetime & clearing
- Raw R0 bytes exist only: inside `IRefreshTokenFactory.Generate()` (to compute verifier + Base64URL) and in the `TokenResponse` string returned to the caller.
- The `byte[]` used to compute the verifier is **best-effort cleared** via `CryptographicOperations.ZeroMemory(buffer)` before the factory returns (the verifier and the Base64URL string are what survive). The Base64URL string is unavoidably a managed `string` (immutable, not zeroable) — documented residual; it leaves the process in the HTTP response body and is never persisted/logged.
- **Never** persist the plaintext (only `token_hash`). **Never** log it (§11.2).

### 5.4 Request-body hardening (approved directive)
- **Endpoint-specific body limit:** `login`/`refresh`/`logout`(-token-style) endpoints cap the request body at **4 KiB** (via per-endpoint `RequestSizeLimit`/`IHttpMaxRequestBodySizeFeature`), not merely the global 64 KiB Kestrel limit. Oversized → **413**.
- **Strict field-length validation BEFORE** email normalization, Base64URL parsing, Argon2, and DB lookup (where practical): bounded `email` length (≤320, the column width), bounded `password` length (account policy 12–128; reject > max before hashing), refresh token exactly 43 Base64URL chars (§12). Field-length rejection uses the **same generic 401** for login (no credential distinction); a structurally invalid request (bad JSON) → 400.
- These limits + length checks are covered by Phase 2 endpoint tests (§13.1a).

---

## 6. Refresh rotation state machine (exact)

Token row states: **Active** (`consumed_at IS NULL ∧ revoked_at IS NULL ∧ expires_at > now`), **Consumed** (`consumed_at` set), **Revoked** (`revoked_at` set), **Expired** (`expires_at <= now`).

### 6.1 `RefreshService.RefreshAsync(RefreshCommand{RefreshToken})` — explicit lock hierarchy (Correction 4)

**Do not rely on SQL JOIN textual order or the optimizer to acquire locks in a safe order.** Locks are taken in **explicit, separate `SELECT … FOR UPDATE` statements** in the fixed hierarchy **accounts → sessions → refresh_tokens**.

1. **Parse first (no DB):** `IRefreshTokenFactory.TryComputeVerifier(presented, out verifier)`. On false (malformed/wrong length) → generic 401, **no DB work** (§12).
2. **A — Pre-transaction locator lookup (bounded, NON-locking):** resolve `accountId, sessionId, refreshTokenId` from the verifier:
   `SELECT rt.id AS refreshTokenId, rt.session_id AS sessionId, s.account_id AS accountId FROM refresh_tokens rt JOIN sessions s ON s.id=rt.session_id WHERE rt.token_hash=@verifier;`
   This is **only a locator hint** to know which rows to lock in order — it is **NOT authoritative state validation**. If it returns nothing → generic 401 (no tx opened).
3. `ISessionStore.RotateAsync(...)` — **one transaction**, locks acquired in hierarchy order:
   - **B — Begin transaction.**
   - **C — Lock account:** `SELECT id, disabled_at FROM accounts WHERE id=@accountId FOR UPDATE;`
   - **D — Lock session:** `SELECT id, revoked_at, absolute_expires_at, last_seen_at FROM sessions WHERE id=@sessionId AND account_id=@accountId FOR UPDATE;`
   - **E — Lock refresh token:** `SELECT id, expires_at, consumed_at, revoked_at, replaced_by_token_id FROM refresh_tokens WHERE id=@refreshTokenId AND session_id=@sessionId AND token_hash=@verifier FOR UPDATE;`
   - **F — Authoritative time only after ALL locks held:** `now = TimeProvider.GetUtcNow()`.
   - **G — Re-evaluate ALL authoritative state under the locks** (never trust the step-A locator for security state):
     - If any locator row disappeared or no longer matches (C/D/E returned nothing, or FKs no longer line up) → **rollback → generic `Invalid`**.
     - **Reuse classification (before freshness):** if refresh-token `consumed_at IS NOT NULL` OR `revoked_at IS NOT NULL`:
       - `consumed_at IS NOT NULL ∧ (now − consumed_at) < ReuseGraceWindow (5s)` → **duplicate window**: rollback, issue nothing, **do not revoke** → `DuplicateWithinGrace` (generic 401). (Benign double-submit / rotation-race loser.)
       - else (consumed ≥5s ago, or revoked) → **reuse detected**: `UPDATE sessions SET revoked_at=@now WHERE id=@sessionId AND revoked_at IS NULL;` then `UPDATE refresh_tokens SET revoked_at=@now WHERE session_id=@sessionId AND revoked_at IS NULL AND consumed_at IS NULL;` commit; `ReuseDetected` (generic 401 + `refresh.reuse_detected` log, §11.2). **Session-scoped only.**
     - **Freshness** (token Active): reject (rollback → `Invalid`) if `expires_at <= now` OR session `revoked_at IS NOT NULL` OR `absolute_expires_at <= now` OR `(now − last_seen_at) >= IdleLifetime (30d)` OR account `disabled_at IS NOT NULL`.
     - **Rotate:** conditional consume `UPDATE refresh_tokens SET consumed_at=@now WHERE id=@refreshTokenId AND consumed_at IS NULL;` → assert affected==1 (else rollback). INSERT R1 (`token_hash=newVerifier`, `expires_at=min(now+IdleLifetime, absolute_expires_at)`). `UPDATE refresh_tokens SET replaced_by_token_id=@r1 WHERE id=@refreshTokenId;`. `UPDATE sessions SET last_seen_at=@now WHERE id=@sessionId;`.
   - Commit. Return `{accountId, sessionId, r1Plaintext, r1ExpiresAt}`.
4. After commit: `IAccessTokenService.Issue(accountId, sessionId, now)`; return `TokenResponse` with R1 + new access JWT.

**R0 never becomes valid again:** after commit it is Consumed (and linked); any later presentation hits the reuse classification in step G.

**Deadlocks are still possible DB outcomes** (the explicit order minimizes but cannot eliminate them). On a deadlock/lock-timeout: the transaction is rolled back, **no token is issued/returned**, and the caller gets a generic failure. A **bounded retry** is permitted **only if explicitly designed and tested** (not assumed) — otherwise a single generic 401/temporary-failure is returned with no partial state.

---

## 7. Locking / concurrency model

- **Two concurrent refreshes with same R0:** both reach step E (`SELECT … FOR UPDATE` on the same refresh-token row, UNIQUE `token_hash`). MariaDB serializes; winner consumes (affected==1) and commits R1; loser proceeds only after the winner's commit, re-reads under its own lock, sees `consumed_at` set → step-G reuse classification: within 5s → `DuplicateWithinGrace` (no revocation); ≥5s → reuse (revoke session). Immediate double-submit is **non-revoking**, satisfying the approved 5s window.
- **Refresh racing logout / logout-all:** both lock the **session** row (§6.1 step D / logout's explicit session lock). Whichever commits first wins. Logout first → refresh sees `revoked_at` → `Invalid`. Refresh first → logout still sets `revoked_at` (idempotent).
- **`disabled_at` set while refresh waits for lock:** refresh re-reads account `disabled_at` under the step-C lock (post-lock `now`) → aborts with `Invalid`, no rotation. (The auth path fails closed on `disabled_at` regardless — per-request session join (§9) + refresh re-check. Proactive bulk-revoke-sessions-on-disable is **out of Phase 2 scope** — §19.)
- **Absolute/idle expiry while refresh waits for lock:** evaluated against post-lock authoritative `now` (step F/G) → expired → `Invalid`, no partial issuance.
- **Two simultaneous logins (same account):** login locks only the **account** row (§5.1 step 6) then inserts children; independent sessions + R0 created sequentially. No shared refresh-row contention.
- **Lock ordering (deadlock safety) — explicit, not optimizer-dependent (Correction 4):** every operation that touches multiple layers acquires locks in **separate `SELECT … FOR UPDATE` statements** in the fixed hierarchy **accounts → sessions → refresh_tokens**. This is deliberate so lock acquisition never depends on SQL JOIN textual order or the query optimizer, which reduces deadlock risk. The same hierarchy applies to **refresh, logout, logout-all, delete-session, and future disable/session-revoke** operations:
  - **logout (single session):** lock account (by the authenticated `sub`) → lock the session (`WHERE id=@sid AND account_id=@accountId FOR UPDATE`) → `UPDATE sessions SET revoked_at=@now WHERE id=@sid AND revoked_at IS NULL` → `UPDATE refresh_tokens SET revoked_at=@now WHERE session_id=@sid AND revoked_at IS NULL`. Idempotent (already-revoked → no-op, still 204).
  - **delete-session (`DELETE /account/sessions/{id}`):** identical to logout but for the target `{id}`, gated by `account_id=@accountId`; a non-owned/nonexistent id affects 0 rows → generic **404** (no ownership disclosure, §11.1/§18-equivalent).
  - **logout-all:** lock account → select the account's active session ids **ordered deterministically by `sessions.id` ASC** and lock/update them in that order (`FOR UPDATE`), then bulk `UPDATE sessions SET revoked_at=@now WHERE account_id=@accountId AND revoked_at IS NULL` + `UPDATE refresh_tokens … WHERE session_id IN (…) AND revoked_at IS NULL`. **Deterministic `id`-ASC ordering** avoids lock-order inversion between concurrent multi-session operations.
  - No distributed lock; all coordination is single-node InnoDB row locks + conditional `affected==N` writes. **Deadlocks/lock-timeouts are handled safely** (rollback, no partial issuance, no token returned; bounded retry only if explicitly designed/tested).

---

## 8. JWT implementation model

- **Library (Decision 1 + Clarification 2 + Correction 1):** **issuance-only** uses `Microsoft.IdentityModel.JsonWebTokens` (`JsonWebTokenHandler`) with `SymmetricSecurityKey` (HS256) in **Infrastructure** (`JwtAccessTokenService`); the shared `TokenValidationParameters` are built by **`JwtTokenValidationParametersFactory`, also in Infrastructure** (never in Application — it returns `TokenValidationParameters`); request-path validation uses `Microsoft.AspNetCore.Authentication.JwtBearer` in **Api** (2B), configured from that factory. There is **no second/production `Validate()` on `IAccessTokenService`** — one validator only. Explicitly restrict `ValidAlgorithms = ["HS256"]`.
- **Config (Decision 6 + previous-key names):** secrets `Security:JwtSigningKey` (current) + optional `Security:JwtPreviousSigningKey`; non-secret `Security:Jwt:Issuer=https://api.bitosx.se`, `Security:Jwt:Audience=bitosx-api`, `Security:Jwt:AccessTokenLifetimeSeconds=900`, `Security:Jwt:ClockSkewSeconds=60`, `Security:Jwt:KeyId` (current kid) + optional `Security:Jwt:PreviousKeyId`. `Security:JwtPreviousSigningKey` and `Security:Jwt:PreviousKeyId` must be present **together** or a partial config fails closed.
- **Issue:** claims `sub` (accountId), `sid` (sessionId), `jti` (`Guid.NewGuid()`), `iat`, `exp` (=iat+900s), `iss`, `aud`. **No** email/phone/vault/roles. `nbf` optional (=iat). Header `alg=HS256` + **mandatory `kid`** = the current key id (§17 Q5). **Sign only with the current key** (Decision 6).
- **Validate (shared `TokenValidationParameters` from the Infrastructure `JwtTokenValidationParametersFactory`, consumed by JwtBearer):** `ValidateIssuer=true` (`ValidIssuer=https://api.bitosx.se`), `ValidateAudience=true` (`ValidAudience=bitosx-api`), `ValidateLifetime=true`, `ValidateIssuerSigningKey=true`, `ClockSkew=TimeSpan.FromSeconds(60)`, `RequireExpirationTime=true`, `RequireSignedTokens=true`, `ValidAlgorithms=["HS256"]`, and an **`IssuerSigningKeyResolver` that returns exactly the one key whose id matches the token `kid`** (empty set → validation fails). **Reject `alg=none` and any non-HS256**; do **not** let IdentityModel fall back to trying all `IssuerSigningKeys` when the resolver yields nothing (see §13.2 kid tests). Algorithm-confusion fails closed (`ValidAlgorithms` + a fixed symmetric key that cannot be interpreted as an RSA public key).
- **Key model / rotation (Decision 6 + previous-key names):** current key always signs; `Security:JwtPreviousSigningKey` (optional, paired with `Security:Jwt:PreviousKeyId`) is added to `IssuerSigningKeys` for **verification only** during rollover. **Previous-key overlap must last at least `AccessTokenLifetime + ClockSkew` (900 + 60 = 960 s) before the previous verification key is retired**, so every token signed just before the switch can still validate through its full lifetime + skew. **Fail closed at composition:** current key must decode to ≥32 bytes or startup throws; a partial previous-key config (`JwtPreviousSigningKey` XOR `PreviousKeyId`) throws (misconfig, not silent disable).
- **`kid` — MANDATORY (Q5 resolved):** key IDs are **non-secret** monotonic labels `k1, k2, k3, …` (`Security:Jwt:KeyId` current, `Security:Jwt:PreviousKeyId` during rotation); an id is **never reused for different key material**. Every issued token's header carries the current `kid`; the verifier resolves **exactly one** configured key by `kid`, accepting only **current** or **previous**. **Missing `kid` → generic 401; unknown `kid` → generic 401; never fall back to trying every configured key.** `alg` must still be exactly **HS256** — `kid` does not relax algorithm validation.
- **Operator rotation sequence (exact):**
  1. Generate new key material with a fresh id (e.g. `k2`); place it as current: `Security:JwtSigningKey`=<new>, `Security:Jwt:KeyId=k2`. Move the outgoing key to previous: `Security:JwtPreviousSigningKey`=<old>, `Security:Jwt:PreviousKeyId=k1`. Deploy/restart.
  2. From this moment new tokens sign with `k2`; tokens already issued under `k1` still verify (previous key accepted).
  3. Wait **≥ 960 s** (`AccessTokenLifetimeSeconds` 900 + `ClockSkewSeconds` 60) so every `k1`-signed token has fully expired.
  4. Retire the previous key **and** its kid **together**: clear `Security:JwtPreviousSigningKey` and `Security:Jwt:PreviousKeyId`. Deploy/restart. Any lingering `k1` token now → generic 401 (client transparently refreshes; the opaque refresh path is unaffected).

---

## 9. Session authorization model (per-request)

- **Approved model: per-request session lookup** (spec §10 Option 2). Built on **`Microsoft.AspNetCore.Authentication.JwtBearer` (Decision 1)** — JwtBearer performs the crypto/claims validation; the per-request session lookup is a single centralized step in the JwtBearer `OnTokenValidated` event (or an authorization policy/endpoint filter), so DB session checks are **not scattered** across endpoints and there is **no bespoke bearer middleware**.
- **Flow for a protected request:**
  1. **JwtBearer** extracts `Authorization: Bearer <jwt>` (missing/malformed → 401) and validates signature/`iss`/`aud`/`exp`/skew/`alg=HS256` against the shared `TokenValidationParameters` (§8). Failure → 401.
  2. **`OnTokenValidated`:** extract `sid` (+ `sub`); validate `sid` is a well-formed GUID → else fail the context (401).
  3. `ISessionStore.GetActiveSessionForAuthAsync(sid, now)`: `SELECT s.account_id, s.revoked_at, s.absolute_expires_at, s.last_seen_at, a.disabled_at FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.id=@sid;` (**PK read, no lock** — read-only auth path). Require `revoked_at IS NULL ∧ absolute_expires_at > now ∧ (now - last_seen_at) < 30d ∧ disabled_at IS NULL ∧ sub == account_id`. Any failure → fail the context (401).
  4. On success, expose `AuthenticatedPrincipal{ AccountId, SessionId }` (claims on `HttpContext.User`) to the endpoint.
- **No write on ordinary authenticated requests:** step 4 is read-only; `last_seen_at` is updated **only** on successful refresh (§6). This is the explicit idle-lifetime semantic: idle is measured from last **refresh**, not from every API call. (Trade-off: a session actively making API calls but never refreshing could idle-expire at 30d after its last refresh; since access tokens are 15m, a live client refreshes well within 30d, so this is benign. Documented.)
- **No JWT blacklist, no access-JWT storage** (approved).

---

## 10. Login timing / Argon2 DoS (design only; NOT implemented in 2A–2C)

- **Approved: NO full dummy Argon2** for nonexistent/non-login-capable accounts (1 vCPU + cap=1 → dummy hashing is a CPU-amplification DoS). Non-login-capable → generic 401 **without** running Argon2.
- **Argon2 never runs under a DB lock (Decision 3):** verify happens outside the transaction (§5.1 steps 4–8), so an expensive hash never extends a row-lock — this removes lock-contention amplification on the 1 vCPU host as an additional DoS surface.
- **Residual:** this leaves a timing difference (hash vs no-hash) → **best-effort, not perfect non-enumerability** (explicitly stated). Mitigated by: small bounded random jitter on the login response; and (Phase 2D, hard blockers) per-IP rate limit, per-normalized-email/account limiter + lockout, **bounded Argon2 work queue** (reject with generic 503/429 when saturated — note the current `SemaphoreSlim.Wait()` blocks unboundedly; 2D adds a bounded queue/try-acquire-with-timeout), global login budget/circuit breaker, adaptive Turnstile later.
- **Hard blockers before public exposure:** rate limiting **and** bounded Argon2 queue. Login stays loopback-only until both exist (§13 in spec; §17 here).

---

## 11. Error model & logging model

### 11.1 Errors (RFC7807 ProblemDetails, camelCase, `X-Correlation-ID` already added by middleware)
- **Login failure (any of unknown / bad-password / invalid-email-format / unverified / disabled / null-password-hash — Decision 2):** identical `401` generic body — `title: "Unauthorized"`, `detail: "Invalid email or password."`. No distinction, no email existence signal.
- **Transport-level input errors (distinct from credential outcomes):** malformed JSON / structurally invalid request → **`400`**; request body over the endpoint limit (4 KiB for auth endpoints, §5.4) → **`413`**. These precede credential evaluation and do not leak account state.
- **Refresh failure (unknown/expired/revoked/reused/duplicate-in-grace/session-or-account-invalid):** identical `401` generic — `detail: "Invalid or expired refresh token."`.
- **Protected endpoint (missing/invalid token or invalid session):** generic `401`.
- **`DELETE /account/sessions/{id}` for another account's (or nonexistent) session:** **`404`** generic (do not disclose ownership/existence). Own already-revoked session → `204` (idempotent, §18).
- Never expose: token hashes, DB internals, SQL/crypto parse errors, account existence, disabled state, reuse-classification detail.

### 11.2 Logging (structured, single-line, correlation-scoped — existing `AddSimpleConsole`)
- Safe events: `login.success` (accountId, sessionId), `login.failure` (reason-code **coarse**: `invalid_credentials` only — not which sub-condition; no email in plaintext), `session.created`, `refresh.success` (sessionId, new jti), `refresh.reuse_detected` (sessionId — **security event**, no token value), `session.revoked` (sessionId, reason), `logout_all` (accountId, count), `disabled_account.attempt` (accountId if known post-auth).
- **Never log:** password, refresh token, access JWT, `Authorization` header, token hash, `JwtSigningKey`, `RefreshTokenPepper`, any vault data.
- **Normalized email in logs:** **omit before auth**, or log a **truncated HMAC/hash** if correlation is needed for abuse investigation. Prefer account/session IDs **after** authentication. Recommendation: pre-auth failures log no email (only correlation id + coarse reason); post-auth events log accountId/sessionId.

---

## 12. Token parser / HMAC model (refresh)

- **Refresh token:** 256 bits CSPRNG (`RandomNumberGenerator.GetBytes(32)`), Base64URL **unpadded** transport.
- **Store only** `HMAC-SHA256(RefreshTokenPepper_bytes, rawTokenBytes)` in `refresh_tokens.token_hash` (VARBINARY(32)). **HMAC the raw bytes, not the Base64 text** (raw bytes are available at generation and at parse).
- **Strict parse before any DB/HMAC work (`TryComputeVerifier`):**
  - Reject `null`/empty; **bounded length** (43 chars = unpadded Base64URL of 32 bytes; reject anything not exactly 43, before decoding, to cap work).
  - Canonical **Base64URL unpadded** only: allow `[A-Za-z0-9_-]`; reject `+`, `/`, `=` padding, whitespace, and any non-canonical form (unlike the *permissive* email-token `Base64UrlDecode`, which re-pads and accepts `+//`; the refresh parser is deliberately stricter).
  - Decode; require **exactly 32 bytes**; else reject.
  - No exceptions for malformed input — return `false` (caller → generic 401).
- Compute verifier; **constant-time comparison** happens implicitly at the DB layer via exact `token_hash` match on a UNIQUE index (the lookup either finds the row or not; no application-side byte compare of secrets is needed). Where any application-side byte comparison is introduced, use `CryptographicOperations.FixedTimeEquals`.
- **Best-effort clear** the decoded 32-byte buffer (`CryptographicOperations.ZeroMemory`) after computing the verifier.
- The **4 KiB body limit + 43-char length gate (§5.4)** apply to the refresh endpoint before parsing, capping parser work.

### 12.1 Refresh-token pepper stability (no silent rotation — approved directive)
- `Security:RefreshTokenPepper` is a **stable server secret** for Phase 2. It is loaded once and **never silently rotated** at runtime.
- **Why:** `token_hash = HMAC-SHA256(pepper, rawBytes)` and lookup is by exact `token_hash`. Changing the pepper changes every verifier, so all existing refresh tokens would fail lookup at once (every session forced to re-login) unless a **previous-pepper verification overlap** is implemented (compute the candidate verifier under both current and previous peppers during a rollover window) — analogous to JWT previous-key overlap.
- **Therefore:** pepper rotation is a **future, explicit, operator-initiated security operation** with its own overlap design — **not** an automatic Phase 2 feature. Documented here so no implementer treats the pepper as freely rotatable.

---

## 13. Detailed TDD test matrix

> RED→GREEN per phase. Unit tests use fakes (`Application.Tests`); store/crypto tests hit `bitosx_test` (`Infrastructure.Tests`); endpoint tests use `WebApplicationFactory` (`Api.Tests`). No real Gmail, no prod DB.

### 13.1 LOGIN
- valid verified+password+enabled → 200, session + R0 created, tokens returned.
- unknown email → 401 generic; **Argon2 NOT invoked** (spy hasher `HashCalls`/`VerifyCalls`==0 for non-candidate).
- **invalid email format (Decision 2)** → 401 generic; Argon2 not invoked (identical body to unknown/bad-password).
- bad password → 401 generic (Verify called, returns Failed).
- unverified (`email_verified_at NULL`) → 401 generic; Argon2 not invoked.
- null `password_hash` → 401 generic; Argon2 not invoked.
- disabled (`disabled_at` set) → 401 generic; Argon2 not invoked.
- normalized email: mixed-case/whitespace input logs in.
- **Argon2 outside lock (Decision 3):** `password_hash` changed between the non-locking verify and the locked re-check → **401, no session created** (store-level test: mutate the row after verify, before commit, via the exact-PHC re-check path). Account disabled between verify and lock → 401, no session.
- transaction rollback: forced failure after session INSERT → no session, no R0 persisted.
- no plaintext password persisted/logged (scan account row + captured logs).
- `NeedsRehash` path → still 200 (re-hash deferred — §17 Q4).

### 13.1a REQUEST-BODY HARDENING (§5.4)
- login/refresh body > 4 KiB → **413** (before credential evaluation).
- oversized `email` (> max) / oversized `password` (> policy max) → generic 401 for login, no Argon2, no DB write.
- malformed JSON / structurally invalid request → **400** (not 401).
- refresh token not exactly 43 canonical Base64URL chars → 401 with **no DB call** (spy store `Calls==0`).

### 13.2 JWT (Infrastructure unit — issuance `JwtAccessTokenService` + the shared `IJwtValidationParametersFactory`; NOT a second validator)
> Validation cases below are asserted by running `JsonWebTokenHandler.ValidateToken` against the **factory-produced** `TokenValidationParameters` (the exact params JwtBearer will use in 2B), so there is one validator under test — never a bespoke duplicate.
- correct claims present (`sub`,`sid`,`jti`,`iat`,`exp`,`iss`,`aud`); excluded claims absent (no email/phone/vault/roles); header carries current `kid`.
- 15-minute lifetime (`exp - iat == 900s`).
- exact issuer/audience validated; wrong issuer → invalid; wrong audience → invalid.
- explicit 60s skew: token expired 30s → still valid; expired 90s → invalid.
- bad signature (tampered) → invalid.
- expired beyond skew → invalid.
- missing `sub` / missing `sid` / malformed `sid` (non-GUID) → rejected at the session-lookup step (§9), not by the JWT validator.
- **`kid` + algorithm fail-closed matrix (Correction 5) — the factory must prove ALL of:**
  - valid **current** kid → validates against the **current key only**.
  - valid **previous** kid → validates against the **previous key only** (during the ≥960 s overlap).
  - **missing** `kid` → reject.
  - **unknown** `kid` (not current/previous) → reject.
  - **retired previous** kid (previous key/kid cleared) → reject.
  - **HS256 + valid kid** → allowed.
  - `alg=none` → reject.
  - `alg=HS384` / `alg=HS512` → reject.
  - asymmetric algorithm (e.g. RS256/ES256 forged) → reject.
  - **no fallback to "try every signing key":** the `IssuerSigningKeyResolver` returns only the key matching `kid` (or none); assert a token whose signature is valid under a *configured-but-non-matching-kid* key is still **rejected** (proves no all-keys fallback).
  - If IdentityModel would otherwise fall back to trying all `IssuerSigningKeys`, that behavior is **explicitly disabled/bypassed** in the configured `TokenValidationParameters` (resolver-only key selection; `TryAllIssuerSigningKeys=false` where applicable). A test asserts the fallback does not occur.
  - All cases exercise the **single shared factory** — no second validator is created for tests.

### 13.3 SESSION AUTHORIZATION
- active session → allowed (principal exposed).
- revoked session → 401.
- disabled account → 401.
- absolute-expired session → 401.
- idle-expired session (last_seen_at > 30d) → 401.
- **no write to `last_seen_at` on an ordinary authenticated request** (capture value before/after a /me call → unchanged).
- missing/garbage `Authorization` header → 401.

### 13.4 REFRESH
- valid R0 → R1 (200); R0 `consumed_at` set; `replaced_by_token_id`=R1; `session.last_seen_at` updated to authoritative now.
- old R0 never accepted again (post-rotation presentation → 401).
- concurrent double refresh (two tasks, same R0): exactly one gets R1; the other → generic 401 without revocation (within 5s) — assert session NOT revoked.
- duplicate within 5s → 401, no token, **session not revoked**.
- duplicate after 5s → reuse: session revoked, remaining active tokens revoked, 401.
- revoked session presented → 401.
- disabled account mid-refresh → 401, no rotation.
- idle-expired / absolute-expired → 401.
- expiry while waiting for row lock (drive via `FakeTimeProvider` advancing after lock in a store-level test) → 401.
- logout/refresh race → deterministic (winner rotates or logout wins; no partial issuance).
- transaction rollback → no R1, R0 unchanged.
- token hash only in DB (no plaintext; assert `token_hash` present, no plaintext column).
- token parser bounds: wrong length / non-canonical / padding / bad chars → 401 with **no DB call** (spy store `Calls==0`).

### 13.5 LOGOUT / SESSION MANAGEMENT
- logout current session → session revoked; its refresh tokens revoked; 204.
- repeat logout (already revoked) → 204 idempotent.
- logout-all → all account sessions revoked (locked/updated in deterministic `id`-ASC order, §7); count logged.
- `DELETE /sessions/{ownId}` → 204; session revoked.
- `DELETE /sessions/{otherAccountId'sSession}` → 404 (no ownership disclosure).
- `DELETE /sessions/{nonexistent}` → 404.
- `GET /sessions` → lists only caller's sessions; `current=true` for the calling session; no hashes/chain-ids/jti/raw internals.
- `GET /me` → `{accountId, email, emailVerified, createdAt}` only; no password/token/session internals.

### 13.6 ZERO KNOWLEDGE
- reflection/scan test: no vault-related type/field/secret appears in auth DTOs, stores, services, JWT claims, or logs (extend existing `ZeroKnowledgeModelTests`).
- login accepts only account password; no vault key/master-password parameter anywhere in the login path.

### 13.7 CAPABILITY GATING — `LoginEnabled` fail-closed matrix (Correction 3; extend existing)
- **DetectCapabilities matrix (§3.5):** neither primary secret → `LoginEnabled=false`; `JwtSigningKey` only → **throws**; `RefreshTokenPepper` only → **throws**; both present + all config valid → `LoginEnabled=true`.
- **Login requested but invalid config → throws:** `JwtSigningKey` < 32 bytes / undecodable; missing/blank `Security:Jwt:KeyId`; blank `Issuer`; blank `Audience`; invalid `AccessTokenLifetimeSeconds`; invalid `ClockSkewSeconds`; `RefreshTokenPepper` < 32 bytes.
- **Previous-key pairing:** `JwtPreviousSigningKey` without `PreviousKeyId` (and vice-versa) → **throws**; a previous-key pair present without valid current login config → **throws**; both previous present + valid → `LoginEnabled=true` with rotation overlap.
- **Non-secret metadata tolerance:** `Security:Jwt:KeyId` present while both primary secrets absent → `LoginEnabled=false`, **no throw** (inert metadata).
- **`AddBitosxLogin` composition:** registered only when `LoginEnabled`; registers issuance service, validation-params factory, refresh factory, session store, login/refresh/session-management services, session authenticator, options — and **`AddBitosxAccountCore` gains none of these** (Correction 2). Endpoints mapped only when `LoginEnabled`; absent → routes 404.
- **Login works with EmailDelivery disabled** (current prod shape): AccountCore + Login present, SMTP absent → login/refresh/logout/me/sessions all function; register/resend still 503; verify-email still mapped.

---

## 14. Implementation phasing (small, reviewable, each compiles + tests green)

- **Phase 2A — primitives + persistence state machines + composition (NO HTTP). Conceptual add/change map (Correction 6):**
  - **APPLICATION (add):** `IAccessTokenService` (BitosX-owned types only), `IRefreshTokenFactory`, `JwtOptions`/`RefreshTokenOptions` (POCO), `ISessionStore`, `LoginService`/`RefreshService`/`SessionManagementService`, `ISessionAuthenticator`. **No IdentityModel/`TokenValidationParameters` types in Application (Correction 1).**
  - **INFRASTRUCTURE (add):** `JwtAccessTokenService` (issuance-only, mandatory `kid`), `JwtTokenValidationParametersFactory` (+ optional `IJwtValidationParametersFactory`) — the single shared validation params, **Infrastructure-resident**; `HmacRefreshTokenFactory` (strict parser); `SessionStore` (explicit accounts→sessions→refresh_tokens lock hierarchy per Correction 4: login-create non-locking-read + locked exact-PHC re-check; rotate/reuse; logout/logout-all/list/delete/auth-lookup); **`AddBitosxLogin` composition method** (Correction 2, registered only when `LoginEnabled`; `AddBitosxAccountCore` stays clean); **`LoginEnabled` detection + fail-closed validation** in `DetectCapabilities`/`AccountCapabilities` (§3.5 matrix).
  - Add the `Microsoft.IdentityModel.JsonWebTokens` / `Microsoft.IdentityModel.Tokens` references to **Infrastructure** (pinned) + lockfile update.
  - **Tests:** all unit (issuance + the shared validation factory incl. §13.2 kid/alg fail-closed matrix, refresh parser) + store/concurrency/reuse/login-race + `LoginEnabled` capability matrix (§13.7). **No endpoints mapped, no JwtBearer wiring, no secrets generated.**
- **Phase 2B — login + JWT issuance + session authorization:**
  - `POST /v1/auth/login` (+ 4 KiB body limit + field-length gate, §5.4); add the **`Microsoft.AspNetCore.Authentication.JwtBearer`** reference to Api (pinned) and configure it + the `OnTokenValidated` session-lookup seam (§9); protect a trivial endpoint to prove authz; `LoginApiFactory`. Endpoint + authorization tests.
- **Phase 2C — refresh rotation/reuse + logout + session management endpoints:**
  - `POST /v1/auth/refresh`, `/logout`, `/logout-all`; `GET /v1/account/me`, `GET /v1/account/sessions`, `DELETE /v1/account/sessions/{id}`. Endpoint tests incl. races, 5s window, ownership 404.
- **Phase 2D — DoS/public-exposure hardening (separately approved, HARD blocker before public):**
  - per-IP + per-account rate limits, bounded Argon2 work queue, global login budget, jitter, Turnstile hook. Kestrel stays loopback until done.
- **Docs** updated within each phase (2A: PERSISTENCE/SECURITY_MODEL; 2B/2C: API/ARCHITECTURE).

Better-split note: 2A is deliberately endpoint-free so the risky concurrency/reuse logic is fully tested at the store level (with `FakeTimeProvider` + real MariaDB row locks) before any HTTP surface exists. This matches how email-verification was built (store tests before endpoints).

---

## 15. Verification commands (run each phase, gate before any push)

```
git status --short && git branch -vv && git rev-parse HEAD
dotnet restore --locked-mode
dotnet build BitosX.Api.slnx -c Debug   && dotnet test BitosX.Api.slnx -c Debug
dotnet build BitosX.Api.slnx -c Release && dotnet test BitosX.Api.slnx -c Release
# expect: 0 warnings, 0 errors; test count = 196 + <new phase tests> (explain delta)
# secret scan (added lines only), forbidden-file check, migration-untouched check:
git diff origin/main..HEAD --stat
git diff origin/main..HEAD | grep -E '^\+' | grep -inE '(password|secret|pepper|key|token)\s*[=:]\s*"?[A-Za-z0-9+/]{16,}' | grep -viE 'example|test-|RandomNumberGenerator|GetBytes'
git diff --name-only origin/main..HEAD | grep -iE 'migrations?/|\.sql$'   # expect empty
git ls-files | grep -iE '(^|/)(\.env|secrets\.json|.*\.key|.*\.pem)$'      # expect empty
# prod DB metadata unchanged (read-only): accounts / pending outbox / active challenges counts
```

Each phase: TDD RED→GREEN, then the full gate; **local commits only, no push until the milestone is reviewed** (same discipline as Phase 1).

---

## 16. Commit boundaries (small; no giant all-in-one auth commit)

Proposed commit sequence (each compiles + green):
1. `feat: JWT issuance service + Infrastructure validation-parameters factory (HS256, mandatory kid, rotation overlap) + tests` (adds Microsoft.IdentityModel.JsonWebTokens/Tokens to Infrastructure, pinned + lockfile; no Application dependency on IdentityModel)
2. `feat: HMAC refresh-token factory with strict Base64URL parser + tests`
3. `feat: session store — login create (Argon2-outside-lock, explicit accounts→sessions→refresh_tokens locks) + refresh rotation/reuse state machine + tests`
4. `feat: login/refresh/session-management application services + tests`
5. `feat: AddBitosxLogin composition + LoginEnabled fail-closed capability detection (AccountCore stays clean) + tests`  *(end of 2A)*
6. `feat: POST /v1/auth/login + JwtBearer + session-lookup authorization seam + body limits + tests`  *(2B; adds Microsoft.AspNetCore.Authentication.JwtBearer to Api, pinned + lockfile)*
7. `feat: POST /v1/auth/refresh + logout + logout-all + tests`  *(2C part 1)*
8. `feat: /v1/account/me + sessions list + delete-session + tests`  *(2C part 2)*
9. `docs: auth token/session/refresh model (API, ARCHITECTURE, SECURITY_MODEL, PERSISTENCE)`
Rate-limiting/DoS (2D) is its own separately-approved series.

---

## 17. Risks / open questions

### Resolved by the 2026-09-17 review (incorporated above)
1. **JWT dependency — RESOLVED (Decision 1):** `Microsoft.IdentityModel.JsonWebTokens` in Infrastructure (issuance); **`Microsoft.AspNetCore.Authentication.JwtBearer` in Api** for protected-endpoint auth (no custom bearer middleware). Pinned versions, `packages.lock.json` updated, locked restore must pass, each reference only in its consuming project. (§3.2, §4.4/§4.6/§4.9, §8, §9)
2. **Malformed login email — RESOLVED (Decision 2):** same generic **401** as all login failures; malformed JSON → 400; oversized body → 413; strict bounded lengths before normalize/hash. (§5.1, §5.4, §11.1)
3. **Argon2 vs DB lock — RESOLVED (Decision 3):** Argon2 runs **OUTSIDE** any transaction/row lock; after a successful verify, begin tx → `SELECT ... FOR UPDATE` → re-check invariant **and exact-PHC equality** → create session+R0 → commit → issue tokens. Never re-run Argon2 under lock. Race documented. (§5.1, §5.2, §10)
6. **Config names — RESOLVED (Decision 6):** keep flat `Security:JwtSigningKey` / `Security:RefreshTokenPepper`; non-secret `Security:Jwt:Issuer=https://api.bitosx.se`, `Audience=bitosx-api`, `AccessTokenLifetimeSeconds=900`, `ClockSkewSeconds=60`; kid IDs non-secret; sign current-only; previous-key overlap ≥ lifetime+skew (960 s). (§3.3, §8)
8. **Session `user_agent` — RESOLVED (Decision 8):** omit raw UA from `GET /v1/account/sessions`; DTO = `id, createdAt, lastSeenAt, expiresAt, current`; raw UA stays internal to persistence; sanitized device label designed later. (§4.1 `SessionResponse`, §13.5)

**Also incorporated (approved directives):** request-body hardening — 4 KiB per auth request + strict field-length gates before normalize/parse/hash/DB (§5.4, §13.1a); refresh-pepper stability — stable secret, no silent rotation, future explicit overlap operation (§12.1).

### Resolved by the 2026-09-17 final decisions (incorporated above)
4. **`NeedsRehash` on login — RESOLVED (Q4): DEFER opportunistic re-hash.** `Success` and `NeedsRehash` are **both successful** password-verification outcomes; login continues normally. **No second Argon2 hash and no `UPDATE accounts.password_hash` in the login path** (CPU-constrained host; Argon2 already concurrency-bounded). `Failed`/`InvalidHashFormat` remain generic login failure. A future dedicated password-hash-upgrade policy handles upgrades explicitly. Optional safe observability: a structured maintenance metric/event that an authenticated account uses a hash needing upgrade — **account ID only, after auth succeeds; never log password/PHC string/normalized email/hash parameters.** (§5.1, §11.2, §13.1)
5. **`kid` in JWT header — RESOLVED (Q5): USE kid, MANDATORY.** Simple monotonic non-secret ids `k1, k2, k3, …` (never reuse an id for different key material). Signer uses the **current key only** and the header carries the current `kid`; verifier resolves **exactly one** configured key by `kid`, accepting only **current** or **previous** kid during rotation. **Missing kid → generic 401; unknown kid → generic 401; never try every configured key.** `alg` must still be exactly **HS256** (kid does not weaken algorithm validation). Config: `Security:Jwt:KeyId=k1` (+ `Security:Jwt:PreviousKeyId` during rotation); secret material is `Security:JwtSigningKey` (current) + optional `Security:JwtPreviousSigningKey` — the previous secret and `Security:Jwt:PreviousKeyId` must be present together or fail closed. Previous verification-key overlap ≥ **960 s** (900 access lifetime + 60 skew), then retire previous key **and** previous kid together. Operator rotation sequence documented in §8. (§3.3, §8, §13.2, §16)
7. **Migration `0003` — RESOLVED (Q7): DO NOT create it in Phase 2.** Current schema is sufficient for the approved auth model (§18). Do **not** add speculative `sessions.revoked_reason` or `sessions(account_id, revoked_at)` index. Revocation reason lives in structured logs for now (§11.2). Propose a future migration only on **measured/query-driven evidence** of need. `0001`/`0002` remain immutable. (§2.4, §18)
9. **Login before Phase 2D — RESOLVED (Q9): ALLOW in 2B/2C, LOOPBACK-ONLY.** Explicit development/testing state, **not** production-public readiness. **Hard public-exposure blockers (all of Phase 2D) before any public auth exposure through Apache / api.bitosx.se:** bounded Argon2 work queue; per-IP login rate limit; normalized-email/account rate limit; global login budget; bounded jitter/failure behavior; refresh/login abuse limits; real-client-IP trust-chain validation; OpenAPI gating; origin/public-exposure review. Until then Kestrel stays loopback-only and **do NOT** configure the Apache API proxy, Cloudflare API exposure, a public Kestrel listener, or systemd production deployment for public auth. (§10, §14)

---

## 18. Is migration 0003 actually required?

**No.** Every required state transition maps to existing columns/indexes (proved in §2.2/§2.3):

- Login-capability, disable → `accounts.email_verified_at / password_hash / disabled_at`.
- Session create/idle/absolute/revoke/list → `sessions.created_at / last_seen_at / absolute_expires_at / revoked_at` + `ix_sessions_account_id`.
- Refresh store-verifier/lookup/rotate/link/reuse/expiry → `refresh_tokens.token_hash (VARBINARY(32) UNIQUE) / consumed_at / revoked_at / replaced_by_token_id / expires_at` + `ix_refresh_tokens_session_id`.
- **5-second duplicate window** → `now - consumed_at` (schema already stores `consumed_at` at microsecond precision, `DATETIME(6)`).
- Per-request revocation → PK read of `sessions.id` + account join.
- Session-scoped reuse revocation → `UPDATE sessions ... WHERE id=@sid` + `UPDATE refresh_tokens ... WHERE session_id=@sid`.
- DML-only runtime grants already cover all INSERT/UPDATE/SELECT (no DDL, no grant change).

**Nothing genuinely cannot be represented.** The only candidates for a future optional `0003` are non-functional: `sessions.revoked_reason` (audit — handled by logs instead) and a `sessions(account_id, revoked_at)` composite index (perf, only if listing volume warrants). Both are deferred; **no `0003` is created during Phase 2.** `0001`/`0002` remain immutable.

---

## 19. Account-disable: current guarantee + future invariant

**Phase 2 scope (implemented by the auth path, no admin endpoint):** `disabled_at IS NOT NULL` **immediately blocks** login (§5.1 capability gate + locked re-check), refresh (§6 freshness check re-reads `a.disabled_at` under lock), and authenticated session authorization (§9 per-request session+account join). No token or session survives an account being disabled — every credential path fails closed on `disabled_at` via authoritative account/session checks.

**Future invariant (NOT implemented in Phase 2 — no admin/disable flow exists yet):** when an administrative account-disable operation is eventually built, it **SHOULD revoke all active sessions for that account in the same security operation** (`UPDATE sessions SET revoked_at=now WHERE account_id=@id AND revoked_at IS NULL`). *Reason:* otherwise sessions merely blocked by the `disabled_at` join remain stored and could become usable again if the account is later re-enabled. The join-based block is sufficient **while** the account stays disabled; proactive session revocation makes disable durable across a future re-enable. Account-disable administration itself remains **out of Phase 2 scope**.

---

## Consistency review (2026-09-17, whole-document)

Verified **absent** (no residual claim that): opportunistic rehash occurs on login; kid is optional; migration `0003` is planned for Phase 2; Login must wait for Phase 2D; raw `user_agent` appears in the session response; custom bearer middleware is used; Argon2 runs while holding login DB locks.

Verified **consistently stated**: Argon2 verification outside transaction/lock; exact-PHC re-check under account lock; mandatory kid (HS256-only, unknown/missing kid → 401); HS256 only; 15-minute (900 s) access token; 60 s clock skew; 30-day idle session lifetime; 90-day absolute lifetime; 5-second non-revoking duplicate refresh window; session-scoped refresh reuse revocation; no migration `0003`; no public exposure before Phase 2D (loopback-only); zero-knowledge boundary unchanged (login accepts only the account password; no vault material in DTOs/stores/claims/logs).

**Final clarifications (2026-09-17) verified applied:** (A) previous-key config uses exactly `Security:JwtSigningKey` / `Security:JwtPreviousSigningKey` (secrets) and `Security:Jwt:KeyId` / `Security:Jwt:PreviousKeyId` (non-secret); previous secret + previous kid are paired and **fail closed** on partial config; current key + current kid required when LoginEnabled; sign current-only; verify current+previous during overlap; retire previous key+kid together. (B) `IAccessTokenService` is **issuance-only** (no production `Validate()`); a single shared `IJwtValidationParametersFactory` (`JwtTokenValidationParametersFactory`) produces the `TokenValidationParameters` for JwtBearer; Phase 2A unit-tests that factory, never a second validator. No stale `JwtSigningKeyPrevious` or `BuildValidationParameters()` references remain.

**Hardening pass (2026-09-17) verified applied:** (1) **Dependency boundary** — the validation-params factory is Infrastructure-only; `BitosX.Application` references no `Microsoft.IdentityModel.*` / `JwtBearer` / `TokenValidationParameters` (§3.2, §4.2, §4.4, §4.9, §8, §14). (2) **Composition** — `AddBitosxAccountCore` unchanged/clean; new `AddBitosxLogin` registered only when `LoginEnabled`; order AccountCore → EmailVerification → EmailDelivery → Login (§4.5, §4.6). (3) **`LoginEnabled` matrix** — neither→false, exactly-one→fail-closed, both→validate-all; previous-key pair both-or-neither; non-secret metadata inert (§3.5, §13.7). (4) **Lock order** — explicit accounts→sessions→refresh_tokens via separate `FOR UPDATE`; pre-tx locator is non-authoritative; authoritative `now` + full re-validation only after all locks; applied to refresh/logout/logout-all/delete-session; logout-all deterministic `id`-ASC; deadlocks → rollback/no partial issuance (§6, §7). (5) **kid/alg tests** — current-only/previous-only/missing/unknown/retired/HS256-ok/none/HS384/HS512/asymmetric/no-all-keys-fallback, single factory (§13.2). (6) **Phase 2A file map** updated (§14).

---

**No source, test, migration, secret, NuGet, commit, or push changes were made. This is a working plan document only. All §17 questions (1–9) are resolved and incorporated.** Sequence before implementation: consistency review (done) → one approved docs-only local commit → then Phase 2A. Awaiting your approval of the docs-only commit.
