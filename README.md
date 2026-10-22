# BitosX API

Account/API service for BitosX. This repository currently contains the
**API foundation** only.

> **Status: local development, not production-ready.**
> Account registration and authentication are **not implemented yet**. The API
> is bound to loopback and is **not** exposed publicly. Do not treat a working
> foundation as a green light for public go-live — see
> [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

## What this currently implements

- ASP.NET Core (.NET 10) host on Kestrel, **loopback-only** (`127.0.0.1:5080`).
- Infrastructure endpoints:
  - `GET /health` — liveness only (no database/dependency readiness claim).
  - `GET /version` — non-sensitive product/build version.
- Baseline: RFC7807 ProblemDetails error handling, correlation id per request,
  structured logging, OpenAPI document, loopback-only forwarded-header trust,
  conservative request-body-size limit.
- A modular-monolith project layout (`Api` / `Application` / `Infrastructure` /
  `Contracts`) that establishes the architecture for future account/auth work.

See [`docs/API.md`](docs/API.md) for endpoint details and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the project layout.

## What is NOT implemented yet

SMS verification and CAPTCHA. (Registration with email verification,
login/refresh/logout, sessions, encrypted-envelope sync, password reset by emailed
link, password-confirmed account deletion, and TOTP two-factor sign-in exist; see
`docs/API.md`.)

## Requirements

- .NET SDK **10.x** (ASP.NET Core runtime 10.x).

## Build / test / run

All commands are run from the repository root as the `luki` user.

```bash
# Restore
dotnet restore BitosX.Api.slnx

# Build
dotnet build BitosX.Api.slnx -c Debug
dotnet build BitosX.Api.slnx -c Release

# Test
dotnet test BitosX.Api.slnx -c Debug
dotnet test BitosX.Api.slnx -c Release

# Run (explicit loopback binding)
ASPNETCORE_URLS="http://127.0.0.1:5080" \
  dotnet run --project src/BitosX.Api -c Release --no-launch-profile
```

Quick check once running:

```bash
curl http://127.0.0.1:5080/health
curl http://127.0.0.1:5080/version
```

## Current local architecture

```
Cloudflare -> Apache :443 -> [FUTURE reverse proxy] -> Kestrel 127.0.0.1:5080 -> BitosX.Api
```

During this phase Apache does **not** proxy to Kestrel; the reverse-proxy hop is
future work.
