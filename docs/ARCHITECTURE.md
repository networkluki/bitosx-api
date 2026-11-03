# BitosX API — Architecture

A pragmatic **modular monolith** on .NET 10 / ASP.NET Core. The goal for this
milestone is a small, clean foundation with clear boundaries — not premature
abstraction.

## Projects and responsibilities

```
src/
  BitosX.Api             ASP.NET Core host, HTTP endpoints, middleware,
                         DI composition root, OpenAPI, process configuration.
  BitosX.Application     Application/use-case logic, interfaces, validation,
                         domain-independent orchestration.
  BitosX.Infrastructure  External-service and persistence implementations
                         (future MariaDB, tokens, email/SMS).
  BitosX.Contracts       Public API request/response DTOs (stable shapes).

tests/
  BitosX.Api.Tests           Integration tests (WebApplicationFactory).
  BitosX.Application.Tests   Unit tests for application logic.
```

## Dependency direction

Dependencies point inward toward `Contracts`; nothing depends on the host.

```
Api  ->  Application
Api  ->  Infrastructure
Api  ->  Contracts
Infrastructure  ->  Application
Infrastructure  ->  Contracts
Application     ->  Contracts
Contracts       ->  (no project dependencies)
```

- `Contracts` must **not** depend on Infrastructure, Application, or ASP.NET
  host details. It is the stable, shareable DTO surface.
- `Application` holds interfaces (e.g. `IProductVersionProvider`) that
  `Infrastructure` implements (e.g. `AssemblyProductVersionProvider`), keeping
  reflection/IO concerns out of the application layer.
- `Api` is the composition root: it wires implementations to interfaces and
  maps endpoints.

## Runtime / network model

```
Cloudflare
  -> Apache :443 (TLS termination, Let's Encrypt)
    -> [FUTURE reverse proxy hop]
      -> Kestrel 127.0.0.1:5080
        -> BitosX.Api
```

- **Kestrel binds to loopback only** (`127.0.0.1:5080`). It must never bind to
  `0.0.0.0`, `::`, or a public address. This is enforced via Kestrel endpoint
  configuration and verified with `ss -ltnp`.
- Kestrel serves plain HTTP on loopback; TLS is terminated upstream by Apache/
  Cloudflare. There is intentionally no HTTPS redirection in Kestrel.
- Forwarded headers (`X-Forwarded-For` / `X-Forwarded-Proto`) are trusted from
  **loopback proxies only** (`127.0.0.1`, `::1`), never from arbitrary
  networks. Cloudflare-origin / real-client-IP handling will be designed at the
  Apache layer and reviewed before any public exposure.
- In production Apache proxies to Kestrel over loopback; see `DEPLOYMENT.md` for the host-side
  checklist.

## Endpoint organization

- **Infrastructure endpoints** are unversioned: `/health`, `/version`.
- **Business endpoints** live under `/v1/...`: `/v1/auth/*` (`AuthEndpoints`),
  `/v1/account/*` (`AccountEndpoints`), `/v1/sync/*` (`SyncEndpoints`), each mapped only when its
  capability is enabled.
- **`migrate`** (`Hosting/MigrateCommand`): `dotnet BitosX.Api.dll migrate` applies schema
  migrations and exits; the web host is never built in that mode.

## Persistence boundary

Schema, data access and the account subsystem are in place. Details in
[`PERSISTENCE.md`](PERSISTENCE.md).

- Engine: **MariaDB 11.8**, isolated `bitosx` database (tests use `bitosx_test`),
  loopback-only (`127.0.0.1:3306`).
- Data access: **MySqlConnector + Dapper + versioned SQL migrations** (not EF
  Core — no stable EF Core 10 MariaDB provider exists; see `PERSISTENCE.md`).
- Persistence adapters live in `BitosX.Infrastructure` behind interfaces defined
  in `BitosX.Application` (`IAccountRepository`, `IDatabaseMigrator`). The API
  layer never talks to the database driver directly; it depends on application
  abstractions and composes them at the root.
- Domain models (`Account`, `Session`, `RefreshToken`, verification challenges)
  live in `BitosX.Application`; EF/DB entities are never exposed through
  `BitosX.Contracts`.
- Connection strings/credentials are supplied from local user-secrets and are
  never committed.

## Account subsystem (registration + email verification)

- **Application** defines the use-case services (`AccountRegistrationService`,
  `EmailVerificationService`), the password/token/outbox abstractions
  (`IAccountPasswordHasher`, `IEmailVerificationTokenFactory`,
  `IOutboxPayloadProtector`, `IEmailSender`, `IVerificationEmailComposer`,
  `IVerificationChallengeFactory`), and the persistence intents
  (`IAccountRegistrationStore`, `IEmailVerificationStore`, `IEmailOutboxStore`).
- **Infrastructure** implements them: `Argon2idPasswordHasher` (+ hardened PHC codec),
  `HmacEmailVerificationTokenFactory`, `AesGcmOutboxPayloadProtector`,
  `MailKitGmailEmailSender`, the transactional stores, and the
  `EmailOutboxBackgroundService` (in-process dispatcher — no separate worker).
  Wired by `AddBitosxAccounts` (gated on configured secrets).
- **Contracts** exposes only DTOs (`RegisterRequest`, `VerifyEmailRequest`,
  `ResendVerificationRequest`, `AcceptedResponse`) — no password/token/hash fields.
- **API** maps `/v1/auth/{register,verify-email,resend-verification}`.
- Delivery is decoupled from the request via a transactional outbox; SMTP never runs
  in the HTTP request path. See `SECURITY_MODEL.md` and `PERSISTENCE.md`.

### Capability-based composition

The account subsystem composes as four independent capabilities, detected once at
startup (`AccountsServiceCollectionExtensions.DetectCapabilities`) and exposed via a
DI `AccountCapabilities` singleton (never re-derived in endpoints):
- **AccountCore** (`AddBitosxAccountCore`): DB + Argon2id password hashing.
  **Independent of SMTP.** Enabled when the runtime connection string is configured.
  Stays clean — it registers Argon2 only, no JWT/session wiring.
- **Login** (`AddBitosxLogin`): access-JWT issuance, the single validation-parameters
  source, the SHA-256 refresh-token factory, the session store, and the login / refresh /
  session-management / session-authentication application services. An **independent**
  capability layered on AccountCore, gated **only** on the current JWT signing key
  (`Security:JwtSigningKey` + mandatory `Security:Jwt:KeyId`). **Requires neither SMTP,
  EmailVerification, nor any refresh-token secret** — the refresh verifier is
  `SHA-256(raw 32 token bytes)` with no server pepper. Tokens are signed with the current
  key only and validated against current **+** previous (verification-only) during rotation.
  The HTTP host wires this under `if (capabilities.LoginEnabled)`: `AddBitosxLogin`, then
  ASP.NET Core **JwtBearer** configured from exactly the one `JwtTokenValidationParametersFactory`
  (`MapInboundClaims = false`), `UseAuthentication`/`UseAuthorization`, and a **single** per-request
  authorization seam — the JwtBearer `OnTokenValidated` event (`BitosX.Api/Auth/SessionValidation`)
  that runs the authoritative session-state check via `ISessionAuthenticator` (not a bespoke bearer
  handler; DB session checks are never scattered across endpoints). `POST /v1/auth/login` and
  `POST /v1/auth/refresh` are unauthenticated (refresh resolves identity from the token, strict reuse
  handled in the store); `POST /v1/auth/logout` and `POST /v1/auth/logout-all` are authenticated with
  identity taken from the validated JWT claims, never the body (4 KiB body limit on token endpoints,
  generic 401). The protected account endpoints `GET /v1/account/me`, `GET /v1/account/sessions`, and
  `DELETE /v1/account/sessions/{id}` (all `RequireAuthorization`) take identity from the validated JWT
  claims, reuse the session-management service for effective-expiry listing and server-side ownership
  (non-owned and nonexistent sessions are an indistinguishable 404), and map explicit DTOs so no
  persistence field leaks into the contract. Public-exposure hardening (`Security:PublicExposureHardening`,
  Phase 2D.1) layers process-local token-bucket rate limiting on the unauthenticated `login`/`refresh`
  endpoints as endpoint filters (per-IP + per-normalized-email for login, per-IP for refresh; generic 429,
  memory-bounded partitions where a live limiter is never evicted for capacity — a new key fails closed
  with 503 when the cache is full and nothing is idle, so partition churn cannot reset a limiter); the
  client IP comes only from the loopback-trusted `UseForwardedHeaders`
  result and fails closed (503) when unresolvable. Phase 2D.2 adds: a **process-wide login budget**
  (unpartitioned token bucket, generic 429, after per-IP/per-email so their rejections don't consume it) and
  **25–75 ms login-response jitter** on normal outcomes only — both gated by `Enabled`; plus a **bounded
  Argon2 work-admission gate** (`ConcurrencyLimiter`, 2 executing + 4 FIFO-queued, 2 s wait) wired in
  `AddBitosxAccountCore` and thus **always active** (a resource-safety property of hashing), which surfaces
  overload as an Application `PasswordHashingCapacityExceededException` mapped to a generic 503 at login. The
  HTTP rate limiters are inert unless enabled. OpenAPI/origin gating (2D.3) is a later slice.
- **EmailVerification** (`AddBitosxEmailVerification`): register/verify/resend services,
  token factory, outbox payload crypto, and outbox persistence. Enabled when the
  verification pepper **and** outbox key are configured. Verifying an already-issued
  token does not require SMTP.
- **EmailDelivery** (`AddBitosxEmailDelivery`): the MailKit Gmail sender and the
  background outbox dispatcher. Enabled only when SMTP credentials are configured;
  when absent, **no dispatcher runs and no queued mail is attempted**.

Presence vs. malformed: an optional capability whose secrets are **absent** is simply
disabled (the API still starts). A capability whose secrets are **present but malformed**
fails closed at startup (throws) — e.g. an invalid `EmailOutboxKey`, a non-587 SMTP
port, a **partial verification config** (only one of pepper/outbox key set), an
explicitly-enabled delivery (SMTP app password present) with missing username/FromAddress,
or **malformed login config** (a short/non-canonical signing key, a missing `kid`, a blank
issuer/audience, an orphan previous signing key, or a non-positive/oversized refresh
lifetime — M-2 is enforced once at composition). `AddBitosxLogin` reuses the same single
validation path as detection, so it can never register a half-working login stack even if
called directly. When EmailVerification is enabled but EmailDelivery is not, `register` and
`resend-verification` return a generic **503** (routes stay mapped; nothing is enqueued),
while `verify-email` remains available. Capability booleans are logged at startup but are
**not** exposed on the public `/health` endpoint.
