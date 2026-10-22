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

## Application-enforced (code)

- **[app] Production hardening gate** — in the Production environment, `LoginEnabled` **requires**
  `Security:PublicExposureHardening:Enabled = true`, or startup fails
  (`ProductionExposureValidation`). Development/Test may run with it disabled.
- **[app] Bounded Argon2 work admission** — always active (independent of hardening): 2 executing + 4
  FIFO-queued, 2 s acquire timeout; overload → generic 503 (`Retry-After: 1`), never a credential 401.
- **[app] Login/refresh rate limits** — per-IP + per-normalized-email (login) and per-IP (refresh);
  generic 429; memory-bounded partitions that never reset a live limiter.
- **[app] Process-wide login budget** — one token bucket after the per-IP/per-email limiters; generic 429.
- **[app] Login-response jitter** — 25–75 ms on normal 200/401 outcomes only.
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
- **[app] Generic error model** — RFC7807 ProblemDetails only; no stack/type/path leakage; correlation id.

## Repository-verified configuration

- **[repo] Kestrel endpoint** — `appsettings.json` → `Kestrel:Endpoints:Http:Url = http://127.0.0.1:5080`
  (loopback-only). This is the authoritative production listener; the app validates it in Production.
- **[repo] Host filtering** — `appsettings.json` → `AllowedHosts = 127.0.0.1;localhost;api.bitosx.se`
  (ASP.NET Core Host Filtering is enabled by default and consumes this). `X-Forwarded-Host` is not trusted.
- **[repo] CORS allowlist** — `appsettings.json` → `Security:Cors:AllowedOrigins = https://vault.bitosx.se`
  (exact https origin, validated fail-closed; empty disables CORS). Methods/headers are fixed in code and
  credentials are never allowed. See SECURITY_MODEL — "Browser clients (CORS)".
- **[repo] No committed secrets** — `appsettings*.json` and templates contain no JWT signing key, DB
  credentials, refresh tokens, passwords, Cloudflare tokens, origin private keys, or SMTP credentials;
  secrets come from user-secrets / production injection only.

## Deployment-enforced (production host — verify before exposure)

These are **not** verifiable from this repository. Each is a blocker until confirmed on the host.

- **[host] Kestrel loopback-only binding** — ensure `ASPNETCORE_URLS`/systemd env do not override the
  loopback endpoint with a public/wildcard address (the app rejects a wildcard it *can* observe, but a
  binding injected purely by the environment must still be checked on the host).
- **[host] Firewall** — the Kestrel port (e.g. `5080`) is not exposed on any public interface.
- **[host] Apache is the sole Kestrel peer** — only the local reverse proxy reaches loopback Kestrel;
  no direct-origin path bypasses Cloudflare/Apache.
- **[host] Cloudflare → Apache real-IP trust** — Apache derives the real client address only from
  Cloudflare-controlled traffic via the deployment's trusted-Cloudflare-network mechanism, ignores
  client-supplied spoofed origin-IP headers from untrusted peers, and forwards a **normalized**
  `X-Forwarded-For` plus the correct `X-Forwarded-Proto` to loopback Kestrel. (Do not hardcode a
  Cloudflare CIDR list in application source.)
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
- **[host] Secrets supplied outside source control** — JWT signing key(s), DB credentials, SMTP/outbox
  keys, and the TOTP key (`Security:TotpKey`, Base64 of 32 random bytes, e.g.
  `openssl rand -base64 32`) provided via a secret store / environment, never committed. Without
  `Security:TotpKey` two-factor enrollment is unavailable and any account that already has TOTP is
  refused at login (fail closed); rotating the key invalidates every stored TOTP secret and recovery
  code (users must re-enroll), so treat it like the JWT key: back it up, never rotate casually.

## Deferred (separate future decisions — not in Phase 2D)

- Adaptive Cloudflare Turnstile / CAPTCHA.
- Registration / resend / verify-email / password-reset rate-limit policies and a global outbound-email
  budget (no dead endpoint code is added for these).
- Any production interactive OpenAPI/Swagger exposure.

---

## Verification procedure (run on the production host; values are deployment-specific placeholders)

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

# CORS: a preflight from the web account app is answered (expect 204 and
# Access-Control-Allow-Origin: https://vault.bitosx.se, no Allow-Credentials):
curl -si -X OPTIONS https://api.bitosx.se/v1/auth/login \
  -H 'Origin: https://vault.bitosx.se' -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type,authorization' | grep -i -E '^HTTP|access-control'

# CORS: any other origin gets no Access-Control-* headers at all (expect none):
curl -si https://api.bitosx.se/health -H 'Origin: https://attacker.example' | grep -i access-control
```

Do not mark any **[host]** item as done based on this document alone — confirm each against the running host.
