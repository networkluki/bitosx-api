# BitosX API

Account/API service for BitosX: accounts, sessions and the zero-knowledge encrypted-envelope sync
for the BitosX desktop and web vault clients.

> **Status.** The API runs behind Cloudflare → Apache → loopback Kestrel at `api.bitosx.se`.
> Public exposure depends on the host-side checklist in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
> (every **[host]** item verified) and the security model in
> [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

## What this currently implements

- ASP.NET Core (.NET 10) host on Kestrel, **loopback-only** (`127.0.0.1:5080`), fail-closed
  production checks (hardening required, loopback listener only).
- Infrastructure endpoints `GET /health` (liveness only) and `GET /version`.
- Email-first registration with email verification, login with refresh-token rotation and
  sessions, password reset by emailed link, password change while signed in, password-confirmed
  account deletion, TOTP two-factor sign-in with recovery codes, and encrypted-envelope sync.
- Rate limiting, bounded Argon2id work, CORS for the web vault (and `/health`+`/version` for the
  product page), RFC7807 ProblemDetails, correlation ids, UTC timestamps, background outbox
  delivery and housekeeping.
- OpenAPI document in the Development environment only.
- A modular-monolith layout (`Api` / `Application` / `Infrastructure` / `Contracts`).

See [`docs/API.md`](docs/API.md) for endpoint details and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the project layout.

## What is NOT implemented yet

SMS verification and CAPTCHA.

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

Apply schema migrations (schema-management account, `ConnectionStrings:BitosxMigrator`; the web
host never migrates and never reads that secret):

```bash
dotnet run --project src/BitosX.Api -c Release --no-launch-profile -- migrate
```

Quick check once running:

```bash
curl http://127.0.0.1:5080/health
curl http://127.0.0.1:5080/version
```

## Against a real database (MariaDB)

```bash
# The API's own test suites on a throwaway MariaDB container (11.8 by default):
tools/devstack/test-db.sh up
set -a; . tools/devstack/.state/test-db.env; set +a
dotnet test tests/BitosX.Application.Tests -c Release
dotnet test tests/BitosX.Infrastructure.Tests -c Release   # one project after another:
dotnet test tests/BitosX.Api.Tests -c Release              # they reset the same tables
tools/devstack/test-db.sh down

# The local live stack for the client live suites (web vault, desktop):
tools/devstack/up.sh          # writes tools/devstack/.state/env (BITOSX_LIVE_API_URL, _WEB_ORIGIN, _MAIL_CMD)
tools/devstack/selftest.sh    # every flow once, with curl
tools/devstack/smoke.sh       # a Production-configured API, black-box checks
tools/devstack/down.sh
```

See [`tools/devstack/README.md`](tools/devstack/README.md). CI (`.github/workflows/ci.yml`) runs the build with
warnings as errors, the dependency audit, the test suites on MariaDB 11.8 and 12.3 and the live stack;
`.github/workflows/e2e.yml` runs the web and desktop live suites against it (nightly and on `main`).

## Deployment

`deploy/` holds the systemd unit, the Apache vhost and the deploy, verify and Cloudflare-IP scripts; the procedure
and the host checklist are in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Architecture

```
Cloudflare -> Apache :443 (reverse proxy) -> Kestrel 127.0.0.1:5080 -> BitosX.Api
```

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for what the application enforces and what must be
verified on the host.
