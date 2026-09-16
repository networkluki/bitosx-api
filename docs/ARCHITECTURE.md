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
- During this phase Apache does **not** yet proxy to Kestrel.

## Endpoint organization

- **Infrastructure endpoints** are unversioned: `/health`, `/version`.
- **Business endpoints** will live under a versioned group: `/v1/...`
  (e.g. `/v1/auth/...`, `/v1/account/...`). The `/v1` route group exists as a
  seam (`ApiV1Endpoints.MapApiV1`) but has no endpoints yet.

## Persistence boundary

The Persistence Foundation is in place (schema + data access only; no
account/auth behavior yet). Details in [`PERSISTENCE.md`](PERSISTENCE.md).

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
