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
