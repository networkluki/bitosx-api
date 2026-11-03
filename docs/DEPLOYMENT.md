# BitosX API — Public-Exposure Readiness

Pre-Internet-exposure checklist for the intended production topology:

```
Internet → Cloudflare → Apache (reverse proxy) → loopback Kestrel (BitosX.Api)
```

Kestrel is **not** an Internet-facing server in this model. Until every item below is satisfied,
Kestrel stays **loopback-only** and the Apache/Cloudflare public path must not be configured.

Status legend:
- **[app]** — enforced by the application (fails closed at startup or per request; covered by tests)
- **[repo]** — verified from repository-controlled configuration
- **[host]** — requires production-host verification (outside this repository)

---

## Production artifacts (`deploy/`)

| File | What it is |
|---|---|
| [`deploy/systemd/bitosx-api.service`](../deploy/systemd/bitosx-api.service) | The service: user `bitosx-api`, `ASPNETCORE_ENVIRONMENT=Production`, loopback Kestrel, `EnvironmentFile=/etc/bitosx-api/bitosx-api.env`, `Restart=on-failure`, graceful stop, sandboxing (`systemd-analyze security`: exposure 3.0). No `MemoryDenyWriteExecute` (the .NET JIT needs it off). |
| [`deploy/apache/api.bitosx.se.conf`](../deploy/apache/api.bitosx.se.conf) | The TLS vhost: proxies to `http://127.0.0.1:5080/`, trusts `CF-Connecting-IP` only from the Cloudflare ranges in `/etc/apache2/cloudflare-trusted-proxies.conf`, sends Kestrel exactly one `X-Forwarded-For`/`-Proto`, adds HSTS/nosniff and never `Access-Control-*`, `LimitRequestBody` = the API's envelope body limit with a clean 413 above it, `ProxyTimeout 150` (> the 120 s envelope transfer time). |
| [`deploy/scripts/deploy.sh`](../deploy/scripts/deploy.sh) | One release, with `--dry-run`: versioned directory under `/opt/bitosx-api/releases/`, database backup, `migrate`, atomic `current` switch, restart, health check, automatic switch back, keeps the last 5 releases. |
| [`deploy/scripts/verify.sh`](../deploy/scripts/verify.sh) | The verification procedure below as assertions; `--local` adds the host checks. |
| [`deploy/scripts/update-cloudflare-ips.sh`](../deploy/scripts/update-cloudflare-ips.sh) | Refreshes the Cloudflare trusted-proxy list (validated CIDRs, atomic install, `apachectl -t` before the reload, previous file kept on any failure). |

### One-time host setup

```bash
# Service account and directories
useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin bitosx-api
install -d -o root -g root -m 0755 /opt/bitosx-api /opt/bitosx-api/releases
install -d -o root -g bitosx-api -m 0750 /etc/bitosx-api

# Runtime secrets of the web host only (KEY=value lines, systemd EnvironmentFile syntax):
#   ConnectionStrings__Bitosx, Security__JwtSigningKey, Security__Jwt__KeyId, Security__EmailVerificationPepper,
#   Security__EmailOutboxKey, Security__TotpKey, Security__PublicExposureHardening__Enabled=true,
#   Email__PublicBaseUrl=https://vault.bitosx.se, Email__FromAddress, Email__SmtpUsername, Email__SmtpAppPassword
install -o root -g bitosx-api -m 0640 /dev/null /etc/bitosx-api/bitosx-api.env
# The migrator secret, for deploy.sh only (one line ConnectionStrings__BitosxMigrator=...); never in the file above
install -o root -g root -m 0600 /dev/null /etc/bitosx-api/migrator.env

install -m 0644 deploy/systemd/bitosx-api.service /etc/systemd/system/ && systemctl daemon-reload
systemctl enable bitosx-api            # started by the first deploy.sh

a2enmod ssl proxy proxy_http headers remoteip rewrite
deploy/scripts/update-cloudflare-ips.sh --no-reload    # before the site: the vhost names the list file
install -m 0644 deploy/apache/api.bitosx.se.conf /etc/apache2/sites-available/
a2ensite api.bitosx.se && apachectl -t && systemctl reload apache2
# /etc/apache2/conf-available/security.conf: ServerTokens Prod, ServerSignature Off, TraceEnable Off
# A weekly root timer or cron entry runs deploy/scripts/update-cloudflare-ips.sh.
```

### Database accounts

MariaDB **11.8** (production; Debian 13) and **12.3** are tested (CI runs the whole suite on both). **10.11 is not
supported**: it cannot run the migrations (unknown collation `utf8mb4_0900_ai_ci`). As the MariaDB root (unix socket):

```sql
CREATE DATABASE bitosx CHARACTER SET utf8mb4;
-- schema management: used only by `migrate` (deploy.sh)
CREATE USER 'bitosx_migrator'@'127.0.0.1' IDENTIFIED BY '<openssl rand -hex 24>';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON bitosx.* TO 'bitosx_migrator'@'127.0.0.1';
-- the web host: DML only (DELETE is needed by housekeeping)
CREATE USER 'bitosx_app'@'127.0.0.1' IDENTIFIED BY '<openssl rand -hex 24>';
GRANT SELECT, INSERT, UPDATE, DELETE ON bitosx.* TO 'bitosx_app'@'127.0.0.1';
```

These are exactly the grants the test suite, the local live stack and CI run with (the migrations need nothing
more). `deploy.sh` backs up with `mariadb-dump` as root over the unix socket (or `BITOSX_DEPLOY_DUMP_DEFAULTS_FILE`).

## Deploy procedure (every release)

With the artifacts above, one command does every step below and stops at the first failure:

```bash
dotnet publish src/BitosX.Api -c Release -o out && tar -C out -czf bitosx-api-<version>.tar.gz .
deploy/scripts/deploy.sh --dry-run bitosx-api-<version>.tar.gz   # checks + plan, changes nothing
deploy/scripts/deploy.sh bitosx-api-<version>.tar.gz             # as root
deploy/scripts/verify.sh --local                                 # on the host
```

`deploy.sh` unpacks the release, backs the database up (`mariadb-dump --single-transaction`, gzip, 0600, checked
for completeness) into `/var/backups/bitosx-api`, runs `migrate` with the migrator secret in that one process's
environment, switches `/opt/bitosx-api/current` atomically, restarts the service and waits for `/health`. If the
new release is not healthy within 60 s it switches back to the previous release and fails. **Migrations are
forward-only**: a switch back keeps the new schema, which works because every migration so far only adds; if a
future migration does not, restore the backup the run printed.

The manual steps, for reference:

1. **Apply migrations first** (required — nothing else runs them). With the new build, before the web
   host is restarted:

   ```bash
   ASPNETCORE_ENVIRONMENT=Production dotnet BitosX.Api.dll migrate
   ```

   It reads `ConnectionStrings:BitosxMigrator` (the schema-management account, from the secret store /
   environment, e.g. `ConnectionStrings__BitosxMigrator`) through the same configuration sources as the
   web host, applies every pending migration in order, prints the applied ids, and exits — `0` success,
   `1` a migration failed (the message names the script; DDL commits implicitly, so inspect that script's
   tables before running again), `2` the connection string is missing. It never starts the web host.
   Concurrent runs are serialized by an advisory lock. **The web host never needs the migrator secret**:
   do not put `ConnectionStrings:BitosxMigrator` into the service's environment.
2. Restart the web host (it uses only the DML runtime account `ConnectionStrings:Bitosx`).
3. Run the verification commands at the end of this document.

Phase 8 adds migrations 0006 (envelope `LONGBLOB`, revision tombstones), 0007 (binary collation for
`normalized_email` and `password_hash`) and 0008 (outbox payload size, per-account recovery-code
uniqueness, housekeeping indexes). All are online `ALTER TABLE`s on small tables except `vault_blobs`
(0006 rewrites it; schedule the migration in a quiet minute if many vaults are stored).

Phase 10 adds migration 0009 (passkeys): one nullable unique column on `accounts` (`webauthn_user_handle`)
and two new tables (`webauthn_credentials`, `webauthn_challenges`). The `ALTER TABLE accounts` is online on
MariaDB 11.8; no grant changes (the runtime account's DML on `bitosx.*` covers the new tables).

## Configuration added in phase 10

| Key | Default | Notes |
|---|---|---|
| `Security:WebAuthn:RelyingPartyId` | `vault.bitosx.se` (appsettings.json) | The WebAuthn RP ID passkeys are scoped to. Lower-case domain name with at least two labels; never an IP address; must equal, or be a dot-boundary suffix of, every origin's host. `localhost` only in Development/Testing. Changing it later orphans every registered passkey (they are bound to the RP ID). |
| `Security:WebAuthn:RelyingPartyName` | `BitosX` (appsettings.json) | Shown by authenticators at registration; 1-64 characters, no control characters. |
| `Security:WebAuthn:Origins` | `["https://vault.bitosx.se"]` (appsettings.json) | List (or one `;`/`,`-separated string) of exact origins (`scheme://host[:port]`, nothing else), at most 10, `https://` only; `http://localhost:<port>` only in Development/Testing. |
| `Security:PublicExposureHardening:PasskeyPerAddress` | 20 / 10 / 60 s | Passwordless passkey options + sign-in per trusted client IP (one bucket for both), validated. |

The Passkeys capability is on when Login, Totp (`Security:TotpKey`) and a valid `Security:WebAuthn` section
are present. Any key of the section set makes all of it required and validated at startup (fail closed — an
`http://` origin, a `localhost` or IP-address RP ID, or an RP ID that does not cover an origin refuses to
start outside Development/Testing). To turn passkeys off, set all three keys to empty values (the routes then
answer 404 and the second sign-in step does not offer `passkey`); existing passkeys stay stored, and TOTP still
cannot be disabled on an account that has them. Nothing in the section is a secret.

## Configuration added in phase 9

| Key | Default | Notes |
|---|---|---|
| `Email:HoldInOutbox` | `false` | **Development/Testing only** (startup fails in any other environment, Production included): register/resend/forgot-password queue mail in the encrypted outbox without SMTP and nothing delivers it. Used by the local live stack (`tools/devstack`). Cannot be combined with `Email:SmtpAppPassword`. |
| `Security:Cors:AllowedOrigins` / `StatusPageOrigins` | unchanged | A loopback `http://` origin is now accepted in Development/Testing only (the local live stack); Production still requires `https://`. |

## Configuration added in phase 8

| Key | Default | Notes |
|---|---|---|
| `Email:PublicBaseUrl` | (none) | **Required** when EmailVerification is enabled: absolute `https://` origin of the web app, e.g. `https://vault.bitosx.se`. Startup fails otherwise (`http://localhost` only in Development/Testing). Not a secret. |
| `Security:Cors:StatusPageOrigins` | `https://bitosx.se` (appsettings.json) | Origins that may read only `GET /health` and `GET /version`. |
| `Security:PublicExposureHardening:PasswordChangePerAccount` | 5 / 1 / 180 s | `TokenLimit` / `TokensPerPeriod` / `ReplenishmentSeconds`, validated. |
| `Security:PublicExposureHardening:MfaPerAccount` | 10 / 2 / 60 s | Second sign-in step per account, validated. |
| `Housekeeping:Enabled` | `true` | Background pruning of dead challenges and sessions. |
| `Housekeeping:IntervalMinutes` | 60 | 1..1440. |
| `Housekeeping:RetentionDays` | 30 | 1..3650: how long dead rows are kept. |
| `Housekeeping:BatchSize` | 200 | 1..5000 rows per DELETE. |
| `Housekeeping:MaxBatchesPerRun` | 50 | 1..1000 batches per table per run. |
| `Email:Outbox:*` | unchanged | Now validated: `MaxAttempts` 1..100, `BatchSize` 1..500, `PollInterval` 1 s..1 h, `LeaseDuration` (0, 1 h], `BackoffBase` (0, 1 h], `RetentionPeriod` 1 h..365 d. |
| `Email:AttemptTimeoutSeconds` | 30 | Now actually applied to the SMTP sender (before, only validated). |
| `ConnectionStrings:BitosxMigrator` | (none) | Read **only** by `migrate`; never by the web host. |

## Application-enforced (code)

- **[app] Production hardening gate** — in the Production environment, `LoginEnabled` **or**
  `EmailVerificationEnabled` **requires** `Security:PublicExposureHardening:Enabled = true`, or startup
  fails (`ProductionExposureValidation`; forgot/reset-password and their limiters ride on
  EmailVerification alone). Development/Test may run with it disabled.
- **[app] Email link base** — with EmailVerification enabled, `Email:PublicBaseUrl` must be an absolute
  `https://` origin or startup fails, so no email can ever carry a relative, dead link.
- **[app] Bounded Argon2 work admission** — always active (independent of hardening): 2 executing + 4
  FIFO-queued, 2 s acquire timeout; overload → generic 503 (`Retry-After: 1`), never a credential 401.
- **[app] Login/refresh rate limits** — per-IP + per-normalized-email (login) and per-IP (refresh);
  generic 429; memory-bounded partitions that never reset a live limiter.
- **[app] Process-wide login budget** — one token bucket after the per-IP/per-email limiters; generic 429.
- **[app] Rate limits on every other public or credential-confirming route** — forgot/reset-password
  per IP and per email, second sign-in step per IP and per account, envelope writes, account deletion,
  password change and TOTP management per account. The envelope write limiter runs before the body is read.
- **[app] Login-response jitter** — 25–75 ms after credential evaluation (200, 401, 202 second factor
  required, 503 two-factor unavailable). It does not hide the Argon2 cost; see SECURITY_MODEL
  "Anti-enumeration: what holds".
- **[app] Trusted forwarded-header policy** — one hop of `X-Forwarded-For`/`-Proto`, loopback proxy only;
  `KnownProxies`/`KnownIPNetworks` are not cleared; `CF-Connecting-IP` is never read in-process; an
  `X-Forwarded-For` from a non-loopback peer is never honored.
- **[app] Production OpenAPI disabled** — `AddOpenApi`/`MapOpenApi` are Development-only; in Production the
  `/openapi/v1.json` route is absent (normal 404). No production switch exists (a future, explicit decision).
- **[app] Production Kestrel listener validation** — any repository-controlled Kestrel/`urls` listener must
  be loopback-only in Production; wildcard/public (`0.0.0.0`, `[::]`, `*`, `+`, a public address) or a
  malformed listener fails startup.
- **[app] Login capability/config validation** — JWT/refresh/hardening config is validated fail-closed at
  startup (short/non-canonical key, missing kid, orphan previous key, bad lifetimes, invalid limiter values).
- **[app] Generic error model** — RFC7807 ProblemDetails (a few framework rejections, e.g. malformed JSON → 400,
  unknown route → 404, carry an empty body); no stack/type/path leakage; correlation id.
- **[app] Development-only settings refused** — `Email:HoldInOutbox` and loopback `http://` CORS origins /
  `Email:PublicBaseUrl` fail startup outside Development/Testing (`tools/devstack/smoke.sh` checks this).

## Repository-verified configuration

- **[repo] Kestrel endpoint** — `appsettings.json` → `Kestrel:Endpoints:Http:Url = http://127.0.0.1:5080`
  (loopback-only). This is the authoritative production listener; the app validates it in Production.
- **[repo] Host filtering** — `appsettings.json` → `AllowedHosts = 127.0.0.1;localhost;api.bitosx.se`
  (ASP.NET Core Host Filtering is enabled by default and consumes this). `X-Forwarded-Host` is not trusted.
- **[repo] CORS allowlist** — `appsettings.json` → `Security:Cors:AllowedOrigins = https://vault.bitosx.se`
  (methods GET/POST/PUT/DELETE) and `Security:Cors:StatusPageOrigins = https://bitosx.se` (GET /health and
  GET /version only). Exact https origins, validated fail-closed; both empty disables CORS. Methods/headers
  are fixed in code and credentials are never allowed. See SECURITY_MODEL — "Browser clients (CORS)".
- **[repo] No committed secrets** — `appsettings*.json` and templates contain no JWT signing key, DB
  credentials, refresh tokens, passwords, Cloudflare tokens, origin private keys, or SMTP credentials;
  secrets come from user-secrets / production injection only.

## Deployment-enforced (production host — verify before exposure)

These are **not** verifiable from this repository. Each is a blocker until confirmed on the host.

- **[host] Kestrel loopback-only binding** — ensure `ASPNETCORE_URLS`/systemd env do not override the
  loopback endpoint with a public/wildcard address (the app rejects a wildcard it *can* observe, but a
  binding injected purely by the environment must still be checked on the host).
- **[host] Firewall** — the Kestrel port (e.g. `5080`) is not exposed on any public interface. Port 443 accepts only
  Cloudflare's ranges (or Cloudflare Authenticated Origin Pulls is enabled; see the commented `SSLVerifyClient`
  lines in the vhost), so nothing reaches Apache except through Cloudflare. The repository cannot enforce this.
- **[host] Apache is the sole Kestrel peer** — only the local reverse proxy reaches loopback Kestrel;
  no direct-origin path bypasses Cloudflare/Apache.
- **[host] Cloudflare → Apache real-IP trust** — Apache derives the real client address only from
  Cloudflare-controlled traffic via the deployment's trusted-Cloudflare-network mechanism, ignores
  client-supplied spoofed origin-IP headers from untrusted peers, and forwards a **normalized**
  `X-Forwarded-For` plus the correct `X-Forwarded-Proto` to loopback Kestrel. (Do not hardcode a
  Cloudflare CIDR list in application source.) The repository's vhost does this with `mod_remoteip`
  (`RemoteIPHeader CF-Connecting-IP`, `RemoteIPTrustedProxyList` kept current by `update-cloudflare-ips.sh`) and
  replaces `X-Forwarded-For`/`-Proto` with one value each; confirm the installed vhost is that file and the list
  is refreshed on a schedule.
- **[host] Host/Origin** — Apache validates/normalizes the Host; `api.bitosx.se` is the authoritative
  production hostname (already in `AllowedHosts`).
- **[host] TLS / HSTS** — TLS is terminated upstream (Cloudflare/Apache); Kestrel receives loopback HTTP.
  Kestrel does **not** terminate public TLS or add `UseHttpsRedirection`/HSTS (that would risk proxy
  redirect loops); HSTS is an Apache/Cloudflare responsibility. `X-Forwarded-Proto` is processed before
  any scheme-dependent component.
- **[host] Apache passes CORS through untouched** — the vhost must forward `OPTIONS` requests and the
  `Origin` / `Access-Control-Request-*` headers to Kestrel and must **not** add its own
  `Access-Control-*` headers (`Header set/add Access-Control-...`): a duplicated or conflicting header makes
  the browser reject the response, and a permissive one at the proxy would widen the policy the
  application enforces.
- **[host] MariaDB `max_allowed_packet`** — at least `32M` (`/etc/mysql/mariadb.conf.d/*.cnf`, `[mysqld]`
  section), so a 16 MiB encrypted envelope (`/v1/sync/envelope`) can be written in one statement. Below
  that an upload fails as a server error; nothing is partially written.
- **[host] MariaDB `binlog_format`** — if binary logging is enabled it must be `MIXED` (the MariaDB
  default) or `ROW`, not `STATEMENT`: several write transactions run under READ COMMITTED (to avoid
  gap-lock deadlocks), which statement-based binary logging refuses.
- **[host] Migrator account** — the schema-management account (`ConnectionStrings:BitosxMigrator`, DDL on
  `bitosx.*`) is used only by `migrate` during a deploy; the runtime account (`ConnectionStrings:Bitosx`)
  keeps DML only (it needs `DELETE` for housekeeping).
- **[host] Secrets supplied outside source control** — JWT signing key(s), DB credentials (runtime and,
  for `migrate` only, migrator), SMTP/outbox keys, and the TOTP key (`Security:TotpKey`, Base64 of 32 random bytes, e.g.
  `openssl rand -base64 32`) provided via a secret store / environment, never committed. Without
  `Security:TotpKey` two-factor enrollment is unavailable and any account that already has TOTP is
  refused at login (fail closed); rotating the key invalidates every stored TOTP secret and recovery
  code (users must re-enroll), so treat it like the JWT key: back it up, never rotate casually.

## Deferred (separate future decisions — not in Phase 2D)

- Adaptive Cloudflare Turnstile / CAPTCHA.
- Registration / resend / verify-email rate-limit policies and a global outbound-email budget (no dead
  endpoint code is added for these).
- Any production interactive OpenAPI/Swagger exposure.

---

## Verification procedure (run on the production host; values are deployment-specific placeholders)

`deploy/scripts/verify.sh` runs the public-chain checks below as assertions (OpenAPI 404, `/health` 200, CORS
exactly as documented with a single `Access-Control-Allow-Origin`, HSTS/nosniff, no version in `Server`, 413 for an
oversized envelope); `verify.sh --local` on the host adds the listener, service, Apache, secret-file and MariaDB
checks. Before a release, `tools/devstack/smoke.sh` runs the application-side checks against a Production-configured
API on a developer machine or in CI (startup refusals, loopback listener, CORS, headers, Host filtering, 413,
`X-Forwarded-For`/`CF-Connecting-IP` handling). The commands below remain the manual equivalent.

```bash
# Kestrel listens on loopback only (expect 127.0.0.1:<port> / ::1, never 0.0.0.0/[::]):
ss -ltnp | grep -i dotnet

# The Kestrel port is not reachable on a public interface (expect refused/filtered from off-host):
#   from another host:  curl -sS --max-time 5 http://<public-ip>:<port>/health   # must fail

# Apache proxies to loopback Kestrel (inspect the vhost ProxyPass target — placeholder path):
#   grep -Ri "ProxyPass" /etc/apache2/sites-enabled/    # expect http://127.0.0.1:<port>/

# A spoofed X-Forwarded-For from an untrusted (non-loopback) peer is ignored — the app keys on the
# real connection IP. Covered by AuthRateLimitTests.SpoofedForwardedFor_FromUntrustedPeer_IsIgnored.

# Production OpenAPI route is absent (expect 404):
curl -si https://api.bitosx.se/openapi/v1.json | head -n 1

# Health is reachable through the proxy chain (expect 200):
curl -si https://api.bitosx.se/health | head -n 1

# The product page may read /health (expect Access-Control-Allow-Origin: https://bitosx.se):
curl -si https://api.bitosx.se/health -H 'Origin: https://bitosx.se' | grep -i access-control-allow-origin

# ...but nothing else (expect no Access-Control-* headers):
curl -si -X OPTIONS https://api.bitosx.se/v1/auth/login \
  -H 'Origin: https://bitosx.se' -H 'Access-Control-Request-Method: POST' | grep -i access-control

# The web vault's envelope upload passes its preflight (expect PUT in Access-Control-Allow-Methods):
curl -si -X OPTIONS https://api.bitosx.se/v1/sync/envelope \
  -H 'Origin: https://vault.bitosx.se' -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: content-type,authorization' | grep -i access-control-allow-methods

# CORS: a preflight from the web account app is answered (expect 204 and
# Access-Control-Allow-Origin: https://vault.bitosx.se, no Allow-Credentials):
curl -si -X OPTIONS https://api.bitosx.se/v1/auth/login \
  -H 'Origin: https://vault.bitosx.se' -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type,authorization' | grep -i -E '^HTTP|access-control'

# CORS: any other origin gets no Access-Control-* headers at all (expect none):
curl -si https://api.bitosx.se/health -H 'Origin: https://attacker.example' | grep -i access-control
```

Do not mark any **[host]** item as done based on this document alone — confirm each against the running host.
