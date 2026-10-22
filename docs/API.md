# BitosX API — Endpoints

Base (local, this phase): `http://127.0.0.1:5080`

All responses are JSON (`application/json`) with camelCase property names.
Error responses use RFC7807 ProblemDetails. Every response carries an
`X-Correlation-ID` header.

**Browser clients (CORS).** Only the origins listed in `Security:Cors:AllowedOrigins`
(repository default: `https://vault.bitosx.se`, the web account app) may read responses
from a browser. Allowed methods `GET`/`POST`/`DELETE`, request headers
`Authorization`/`Content-Type`/`Accept`, exposed headers `Retry-After`/`X-Correlation-ID`,
no credentials; a preflight (`OPTIONS` + `Access-Control-Request-Method`) is answered with
**204** before any endpoint runs. Other origins get no CORS headers. See
[`SECURITY_MODEL.md`](SECURITY_MODEL.md) — "Browser clients (CORS)".

> **Implemented account endpoints:** email-first registration and email
> ownership verification with account-password creation (`/v1/auth/register`,
> `/v1/auth/verify-email`, `/v1/auth/resend-verification`), plus **login**
> (`/v1/auth/login`), **refresh** (`/v1/auth/refresh`), **logout**
> (`/v1/auth/logout`), **logout-all** (`/v1/auth/logout-all`), and the protected
> account endpoints **`/v1/account/me`**, **`/v1/account/sessions`**, and
> **`DELETE /v1/account/sessions/{id}`**. **Encrypted-envelope sync** (`/v1/sync/*`) rides on Login.
> **Password reset by emailed link** (`/v1/auth/forgot-password`, `/v1/auth/reset-password`) and
> **password-confirmed account deletion** (`POST /v1/account/delete`) exist since phase 6.
> **Phone/SMS does not exist yet.** Registration/verification/password reset are exposed when
> EmailVerification is configured; **login/refresh/logout and the account
> endpoints are exposed independently when the Login capability is enabled** (DB
> connection + JWT signing key + kid), even without SMTP. The API otherwise stays
> health/version only.

## `POST /v1/auth/register`

Email-first registration. Accepts **only** an email; **no password**. Creates an
unverified account (`password_hash = NULL`) and queues a verification email.
The response is generic regardless of whether the address is new or already
registered (anti-enumeration); no email is sent for an already-registered
address.

Request: `{ "email": "user@example.com" }` → **202 Accepted**
`{ "message": "If the address can be registered or needs verification, check your email." }`

Invalid email → **400** `application/problem+json`.

When **email delivery is not configured** (no SMTP credentials), `register` and
`resend-verification` return a generic **503** `application/problem+json` and create
nothing (no account/challenge/outbox); `verify-email` remains available so
already-issued links can still be consumed. `/health` does not reveal capability state.

## `POST /v1/auth/verify-email`

Consumes a verification token and **sets the account password** (chosen by the
token holder). Password policy: 12–128 characters, used exactly as supplied.
Verification + password + challenge-consume are applied atomically.

Request: `{ "token": "<base64url>", "password": "<12..128>" }` → **200 OK**
`{ "message": "Your email is verified and your password is set." }`

Invalid/expired/consumed/invalidated token → **400** generic ProblemDetails.
Password outside 12–128 → **400** ProblemDetails (challenge not consumed).

## `POST /v1/auth/resend-verification`

Re-issues a verification email for an **unverified** account (invalidating any
prior active challenge). Always returns the same generic **202** regardless of
account existence/state. Rate limiting is a production blocker (see SECURITY_MODEL).

Request: `{ "email": "user@example.com" }` → **202 Accepted** (generic message)

No response ever contains a password, password hash, token, or token verifier.

## `POST /v1/auth/forgot-password`

Starts an **account-password reset** by email. Accepts only an email. For a verified, enabled
account with a password it queues a reset email (to the address on the account, never the one
typed) carrying a single-use link `https://vault.bitosx.se/reset-password#token=<base64url>`
(token in the URL fragment, TTL 30 minutes). For an unknown, unverified or disabled address it
does nothing. The response is **identical in every case**:

Request: `{ "email": "user@example.com" }` → **202 Accepted**
`{ "message": "If an account exists for this address, check your email for a password-reset link." }`

- Malformed email → still the generic **202**. Malformed JSON → **400**; body over **4 KiB** → **413**.
- A new request invalidates the previous reset link (min re-issue interval 60 s; a request within
  it, or while the previous email is in flight, is silently skipped — still **202**).
- Email delivery not configured → generic **503**, nothing created (like register/resend).
- Under hardening: per-IP (5 burst / 2 per 60 s) and per-normalized-email (3 burst / 1 per 5 min)
  limits → generic **429**; unresolvable trusted client IP → **503**.

This resets only the **account** password used to sign in. It cannot recover or change the vault
**master password**; the stored envelope stays ciphertext the server cannot read.

## `POST /v1/auth/reset-password`

Consumes a reset token and **replaces the account password**. In one transaction: the new
Argon2id hash is stored, the token is consumed, any other outstanding reset link for the account
is invalidated, and **every session and refresh token of the account is revoked** (all devices
must sign in again). Stays available without SMTP so an already-issued link can be consumed.

Request: `{ "token": "<base64url>", "password": "<12..128>" }` → **200 OK**
`{ "message": "Your password has been reset. Sign in again on every device." }`

- Invalid/expired/consumed/invalidated token, a verification token, or a token for an account
  that can no longer sign in → **400** generic ProblemDetails
  (`detail: "Invalid or expired password-reset token."`). No Argon2 runs for such a token.
- Password outside 12–128 → **400** ProblemDetails (token not consumed).
- Argon2 admission overload → **503** (`Retry-After: 1`); the token stays usable.
- Body over **4 KiB** → **413**. Under hardening the forgot-password per-IP limit applies here too.

## `POST /v1/auth/login`

Authenticates an account and starts a session. Mapped only when the **Login**
capability is enabled. The password is used exactly as supplied; the email is
case-folded for lookup (surrounding whitespace is invalid). The optional session
client descriptor is taken from the `User-Agent` header, never the body.

Request: `{ "email": "user@example.com", "password": "<12..128>" }` → **200 OK**

```json
{
  "accessToken": "<jwt>",
  "accessTokenExpiresAt": "2026-01-01T00:15:00Z",
  "refreshToken": "<base64url, opaque>",
  "refreshTokenExpiresAt": "2026-01-31T00:00:00Z",
  "tokenType": "Bearer"
}
```

- **Every** credential failure (unknown email, wrong password, unverified,
  disabled, null password hash, invalid email format) → one identical generic
  **401** `application/problem+json` (`detail: "Invalid email or password."`) —
  no account-existence signal. No Argon2 runs for a non-login-capable account.
- Malformed JSON → **400**. Request body over **4 KiB** → **413** (before any
  credential evaluation).
- The access token is a short-lived HS256 JWT (mandatory `kid`); the refresh
  token is an opaque rotating credential. The response contains no account id,
  email, session id, password, or token verifier.
- When public-exposure hardening is enabled: per-IP, per-normalized-email, and a
  process-wide login budget apply → generic **429** (`Retry-After` when available);
  an unresolvable trusted client IP → **503**. Bounded Argon2 work admission is
  **always** active (independent of hardening): if the hash queue is saturated or the
  bounded wait times out, login returns a generic **503** (`Retry-After: 1`) — never a
  credential 401 and never a token. See SECURITY_MODEL for the full policy.

## `POST /v1/auth/refresh`

**Unauthenticated** (the access token may already be expired). Exchanges an opaque
refresh token for a new access JWT + a **rotated** refresh token. Account/session
identity is resolved from the token by the server; no identity is accepted in the body.

Request: `{ "refreshToken": "<base64url, 43 chars>" }` → **200 OK** (same `TokenResponse`
shape as login).

- On success the presented token is consumed and replaced; the previous token is
  never valid again.
- **Strict reuse (no grace window):** presenting an already-consumed/revoked token
  revokes the **whole session** (and its remaining tokens); the response is the same
  generic **401**. Reuse revocation is session-scoped — other sessions of the account stay active.
- Unknown / malformed / wrong-length / expired / revoked / reused → one identical
  generic **401** `{ detail: "Invalid or expired refresh token." }` (no token-state
  disclosure). Malformed JSON → **400**; body over **4 KiB** → **413**.
- When public-exposure hardening is enabled: a per-IP rate limit applies → generic
  **429** (`Retry-After` when available); unresolvable trusted client IP → **503**.

## `POST /v1/auth/logout`

**Authenticated** (`Authorization: Bearer <access-jwt>`). Revokes **only the caller's
current session** (identified from the validated JWT, not the body) and its refresh
tokens. No request body. → **204 No Content**.

Missing/invalid token, or a token whose session is already revoked/expired → **401**.
(After logout the same access token no longer authenticates.)

## `POST /v1/auth/logout-all`

**Authenticated.** Revokes **every** session for the account (from the validated JWT
identity) and all their refresh tokens. No request body. → **204 No Content**. Missing/
invalid token → **401**.

## `GET /v1/account/me`

**Authenticated.** Returns the caller's own profile, resolved from the validated JWT
identity. → **200 OK**

```json
{ "accountId": "<guid>", "email": "user@example.com", "emailVerified": true, "createdAt": "2026-01-01T00:00:00Z" }
```

No other fields are exposed — no password hash, phone, disabled/updated state,
normalized email, token, or session internals. Missing/invalid token, or a token whose
session is revoked/expired → generic **401**.

## `GET /v1/account/sessions`

**Authenticated.** Lists **only the caller's own current-usable sessions** (a management
view, not history): `revoked_at IS NULL ∧ absolute_expires_at > now ∧ (now − last_seen_at)
< IdleLifetime` — the same authoritative predicate the session authenticator uses. → **200 OK**

```json
[ { "id": "<guid>", "createdAt": "…", "lastSeenAt": "…", "expiresAt": "…", "current": true } ]
```

- `expiresAt` is the **effective** expiry `min(absolute_expires_at, last_seen_at +
  IdleLifetime)`, computed by the session service (not the endpoint).
- `current` marks the calling session. Another account's sessions can never appear.
- No user-agent, account id, refresh-token hash/verifier, chain id, or jti is exposed.
- Missing/invalid token → **401**.

## `DELETE /v1/account/sessions/{id}`

**Authenticated.** Revokes one of the caller's own sessions (and its refresh tokens).
Ownership is determined server-side from the validated JWT identity. → **204 No Content**.

- A **nonexistent** session and a session **owned by another account** return the
  **identical generic 404** (`application/problem+json`) — existence/ownership is never
  disclosed, and another account's session is never affected.
- A non-GUID `{id}` does not match the route (→ **404**), so a malformed id never reaches
  the service. Missing/invalid token → **401**.
- Deleting the caller's **current** session is allowed (effectively logout); the access
  token's session is then gone and subsequent authenticated calls return **401**.

## `POST /v1/account/delete`

**Authenticated.** Permanently deletes the **caller's own** account (from the validated JWT
identity, never an id in the body), confirmed with the account password. Removes the account and,
by cascade, its sessions, refresh tokens, verification/reset challenges, queued mail and the
**stored vault envelope**. A local vault file on the user's device is not touched.

Request: `{ "password": "<current account password>" }` → **204 No Content**.

- Wrong password, empty password, or an account that cannot be deleted this way → one generic
  **403** `application/problem+json` (`detail: "Password confirmation failed."`); nothing is
  deleted and the session stays valid (403, not 401, so a client does not mistake it for a dead
  session).
- Missing/invalid bearer → **401**. Body over **4 KiB** → **413**. Extra body fields (e.g. an
  `accountId`) are ignored.
- Argon2 admission overload → **503** (`Retry-After: 1`).
- Under hardening: per-account limit (5 burst / 1 per 3 min, keyed by the server-issued account
  id) → generic **429**. After deletion the address can register again from scratch.

## Encrypted-envelope sync (`/v1/sync`)

**Authenticated**, mapped with the Login capability. The *envelope* is the desktop vault file
exactly as BitosX writes it: JSON whose cryptographic fields are ciphertext under a key derived
from the master password on the device. The server stores and returns those bytes and never has
anything that could decrypt them; the only thing it reads is the public header (a JSON object with
a numeric `version`), to refuse arbitrary bytes. One envelope per account.

Every stored envelope has a **revision** (1, 2, 3, …) and a **fingerprint** (SHA-256 over the
bytes, lowercase hex). Uploads are compare-and-set on the revision, so two devices can never
overwrite each other unknowingly: the client names the revision it last saw, and the server writes
only if that is still current.

### `GET /v1/sync/status`

→ **200** `{ "revision": 3, "fingerprint": "<64 hex>", "sizeBytes": 12345, "updatedAt": "…" }`,
or **404** when nothing is stored.

### `GET /v1/sync/envelope`

→ **200** `{ "revision", "fingerprint", "sizeBytes", "updatedAt", "envelope": "<base64>" }`
(`Cache-Control: no-store`), or **404** when nothing is stored.

### `PUT /v1/sync/envelope`

Request: `{ "baseRevision": 0, "envelope": "<base64>" }` — `baseRevision` is the revision the
client last saw, `0` when it has never uploaded.

- **200** `{ "revision", "fingerprint", "sizeBytes", "updatedAt" }` — stored as `baseRevision + 1`.
- **409** `application/problem+json` with `currentRevision` — the server holds a revision the
  client has not seen; nothing was written. Download it first, or upload against it deliberately.
- **400** — not Base64, empty, or not a BitosX envelope (not UTF-8 JSON, not an object, no
  positive integer `version`, or trailing content).
- **413** — the decoded envelope exceeds `Security:Sync:MaxEnvelopeBytes` (default and maximum
  16 MiB, the desktop format's own cap); the request body limit for this endpoint is raised
  accordingly (Base64 of that plus 1 KiB).
- Under public-exposure hardening a per-account write limit applies (30 burst / 10 per minute,
  keyed by the account id from the JWT) → generic **429**.

### `DELETE /v1/sync/envelope`

Removes the account's stored envelope. → **204**, also when nothing was stored (idempotent). Under
hardening the same per-account write limit applies.

## `GET /health`

Liveness check only. It does **not** report database or dependency readiness
(there is no database in this milestone).

**200 OK**

```json
{
  "service": "BitosX API",
  "status": "healthy"
}
```

## `GET /version`

Non-sensitive product/build version, read from assembly metadata. The response
contains **only** `service` and `version` — no host details, paths, environment,
configuration, usernames, IPs, or secrets.

**200 OK**

```json
{
  "service": "BitosX API",
  "version": "0.1.0"
}
```

## OpenAPI

An OpenAPI document is served at `/openapi/v1.json` (loopback only in this
phase; exposure must be reviewed before any public go-live).
