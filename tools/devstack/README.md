# Local live stack (`tools/devstack`)

A complete BitosX API stack on this machine, for the client live suites (web vault, desktop) and for checking a
change against a real database: MariaDB in a container, the API published in Release and migrated with the real
`dotnet BitosX.Api.dll migrate` deploy step, listening on loopback.

Requirements: Linux with bash ≥ 4.4, Docker, the .NET 10 SDK, `curl`, `openssl`; `python3` and `timeout` for
`selftest.sh`/`smoke.sh`, `ss` (iproute2) for the listener check.

## Commands

```bash
tools/devstack/up.sh        # bring up (or replace) the stack; 10-15 s (5-12 s with BITOSX_DEVSTACK_SKIP_BUILD=1)
tools/devstack/selftest.sh  # one account through every flow with curl (uses only the three client variables)
                            # and the dev authenticator for the passkey steps
tools/devstack/smoke.sh     # black-box checks of a Production-configured API (separate port, see below)
tools/devstack/down.sh      # stop the API, remove the container; safe to run any time
```

`up.sh` is idempotent: run it again and the running stack is replaced by a fresh one (new database, new secrets).
A failed bring-up cleans up after itself and prints the relevant log tail. `down.sh` with nothing up is a no-op.

## What clients get

`up.sh` writes `tools/devstack/.state/env` (mode 0600) with exactly three variables:

```
BITOSX_LIVE_API_URL=http://127.0.0.1:5080
BITOSX_LIVE_WEB_ORIGIN=http://localhost:8788
BITOSX_LIVE_MAIL_CMD=/absolute/path/to/bitosx-api/tools/devstack/mail.sh
```

Plain `KEY=value` lines, no quotes (`up.sh` refuses a repository path that would need quoting). Load them with
`set -a; . tools/devstack/.state/env; set +a`. Clients use nothing else about the stack.

- `BITOSX_LIVE_API_URL` — the API, `ASPNETCORE_ENVIRONMENT=Testing`, capabilities AccountCore, EmailVerification,
  Login, Totp and Passkeys on; EmailDelivery off. Public-exposure hardening (rate limits) is **off** so client suites are not
  flaky; the hardened behaviour is what `smoke.sh` checks. Production Argon2 parameters.
- `BITOSX_LIVE_WEB_ORIGIN` — the one CORS origin the API allows (methods GET/POST/PUT/DELETE, headers Authorization,
  Content-Type, Accept, no credentials), `Email:PublicBaseUrl`, and the WebAuthn relying party: RP ID `localhost`
  (the origin's host), name `BitosX`, origin exactly `BITOSX_LIVE_WEB_ORIGIN` (Testing allows RP ID `localhost` with
  `http://localhost:<port>`; Production refuses both). The client suite serves the web vault there; a page on any
  other origin (`http://127.0.0.1:8788` included) cannot use the passkeys. WebAuthn needs a domain name, so with a
  `BITOSX_DEVSTACK_WEB_ORIGIN` whose host is an IP address `up.sh` turns passkeys off (their routes answer 404).
- `BITOSX_LIVE_MAIL_CMD latest <verify|reset> <email>` — prints ONE line on stdout: the token of the latest pending
  outbox message of that kind for that address (exit 0), or exits 1 with a message on stderr when there is none
  (errors exit 2). The token is exactly what follows `#token=` in the emailed link
  (`<web origin>/verify-email#token=…`, `<web origin>/reset-password#token=…`); the outbox stores the token, not the
  link. Post it as `{"token": …}` to `/v1/auth/verify-email` or `/v1/auth/reset-password`. Addresses match the way
  the API matches them (trimmed, case-insensitive). "Latest pending" means the newest message of that kind that was
  neither sent nor failed — a token that was already used is still returned until a newer message exists.

Mail is never delivered: the API runs with `Email:HoldInOutbox=true`, a Development/Testing-only setting (startup
fails in any other environment) that queues verification and reset mail in the encrypted `email_outbox` without an
SMTP sender or dispatcher. `mail.sh` decrypts it with `tools/BitosX.DevMail`, which uses the Infrastructure's own
`AesGcmOutboxPayloadProtector`, reads its inputs only from the environment, and refuses to run unless
`ASPNETCORE_ENVIRONMENT`/`DOTNET_ENVIRONMENT` is Development or Testing (unset counts as Production, as in ASP.NET Core;
`mail.sh` defaults it to Testing).

TOTP: RFC 6238, HMAC-SHA1, 6 digits, 30 s, ±1 step; a step that was used once (confirmation, a sign-in, a
confirmation of a sensitive action) is refused again, so a second code inside the same 30 s needs the next step.

Passkeys: an account needs TOTP confirmed before it can register one. Browsers: Chromium's virtual authenticator
(CDP `WebAuthn.addVirtualAuthenticator`, resident keys + user verification) works against the page at
`BITOSX_LIVE_WEB_ORIGIN`. Shell: `tools/BitosX.DevAuthenticator` (published by `up.sh` to
`.state/build/devauth/`) is the API test suite's software authenticator behind a command line —
`dotnet .state/build/devauth/BitosX.DevAuthenticator.dll <create|get> --origin <web origin> --state <file> [--no-uv]`
reads the API's options answer on stdin and prints the credential JSON a browser's `PublicKeyCredential.toJSON()`
would; the state file holds private keys in the clear (0600), for throwaway accounts only. `selftest.sh` uses it.

## Settings

All optional, as environment variables of `up.sh`:

| Variable | Default | Meaning |
|---|---|---|
| `BITOSX_DEVSTACK_MARIADB_IMAGE` | `mariadb:11.8` | MariaDB image (11.8 and 12.3 are tested; 10.11 cannot run the migrations). |
| `BITOSX_DEVSTACK_DB_PORT` | `3407` | MariaDB port on `127.0.0.1`. |
| `BITOSX_DEVSTACK_API_PORT` | `5080` | API port on `127.0.0.1`. |
| `BITOSX_DEVSTACK_WEB_ORIGIN` | `http://localhost:8788` | The web vault's origin: CORS, email links and the WebAuthn relying party. Must be loopback `http://host:port`; passkeys only with the host `localhost`. |
| `BITOSX_DEVSTACK_HEALTH_TIMEOUT` | `60` | Seconds to wait for `GET /health` = 200. |
| `BITOSX_DEVSTACK_SKIP_BUILD` | `0` | `1` reuses the last published build in `.state/build`. |
| `BITOSX_DEVSTACK_EXTERNAL_DB` | `0` | `1` uses an existing server (CI service container) instead of starting a container. |
| `BITOSX_DEVSTACK_DB_HOST` | `127.0.0.1` | External server host. |
| `BITOSX_DEVSTACK_DB_ROOT_USER` | `root` | External server administrative account. |
| `BITOSX_DEVSTACK_DB_ROOT_PASSWORD` | — | Required with an external server. |
| `BITOSX_DEVSTACK_DB_CLIENT` | auto | `mariadb`, `mysql` or `docker` for the provisioning SQL (external server). |
| `BITOSX_DEVSTACK_SMOKE_PORT` | `5081` | Port of `smoke.sh`'s Production instance. |

With an external server, `up.sh` creates database `bitosx` and the accounts if needed (re-runs only reset their
passwords) and `down.sh` leaves the server alone.

## What `up.sh` does

1. Starts MariaDB (`--max-allowed-packet=64M`; an external server gets `SET GLOBAL max_allowed_packet` when it is
   below 32M) on `127.0.0.1:<port>`, while `dotnet publish` builds the API, the outbox reader and the dev
   authenticator in parallel.
2. Creates database `bitosx`, the schema account `bitosx_migrator`
   (`SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON bitosx.*`) and the runtime account
   `bitosx_app` (`SELECT, INSERT, UPDATE, DELETE ON bitosx.*`) — the grants of `docs/DEPLOYMENT.md`. The accounts use
   host `%` because the containerized server sees the Docker gateway, not `127.0.0.1`; the server is published on
   loopback only.
3. Generates every secret fresh (`openssl rand`): database passwords, JWT signing key and key id, email
   verification pepper, outbox key, TOTP key.
4. Runs `dotnet BitosX.Api.dll migrate` with the migrator connection string in its environment only; the web host
   never receives it.
5. Starts the API with a clean environment read from `.state/api.env` (no secret on any command line), waits for
   `GET /health` = 200.
6. Writes `.state/env`.

`.state/` (gitignored, mode 0700) holds `env`, the 0600 environment files with the secrets, the API's pid,
`logs/` (`api.log`, `build.log`, `migrate.log`, `smoke-api.log`) and `build/`. `down.sh` removes every secret file and
keeps `logs/` and `build/`.

## `smoke.sh`

Starts a second API on `127.0.0.1:${BITOSX_DEVSTACK_SMOKE_PORT:-5081}` with `ASPNETCORE_ENVIRONMENT=Production`,
hardening on, `Email:PublicBaseUrl=https://vault.bitosx.se` and the real CORS origins from `appsettings.json`, against
the stack's database with its own fresh secrets, and turns the verification commands of `docs/DEPLOYMENT.md` into
assertions: Production refuses to start with hardening off, a wildcard listener, `Email:HoldInOutbox`, an http CORS
origin, an http WebAuthn origin, a `localhost` or IP-address WebAuthn RP ID or an RP ID that does not cover the
origin; it starts with the shipped `Security:WebAuthn` section and serves passwordless options for RP ID
`vault.bitosx.se`; the listener is loopback-only; OpenAPI 404; `/health` and `/version` 200; CORS exactly as documented;
no `Server` header, a correlation id, no exception details; Host filtering; 413 for oversized bodies; the client
address is the last `X-Forwarded-For` hop (forged earlier hops and `CF-Connecting-IP` change nothing) and a hardened
credential route without one answers 503. It stops its API on exit and fails on the first mismatch.

## `test-db.sh` (the API's own test suites on MariaDB)

```bash
tools/devstack/test-db.sh up        # container on 127.0.0.1:3408 (BITOSX_DEVSTACK_TEST_DB_PORT), image as above
set -a; . tools/devstack/.state/test-db.env; set +a
dotnet test tests/BitosX.Application.Tests -c Release
dotnet test tests/BitosX.Infrastructure.Tests -c Release
dotnet test tests/BitosX.Api.Tests -c Release
tools/devstack/test-db.sh down
```

It sets `ConnectionStrings__BitosxTest` (schema account on `bitosx_test`) and `ConnectionStrings__BitosxTestRuntime`
(DML only), which override the user-secrets the tests read otherwise. Run the test projects one after another: the
Infrastructure and Api tests reset the same tables.
