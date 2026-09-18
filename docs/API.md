# BitosX API — Endpoints

Base (local, this phase): `http://127.0.0.1:5080`

All responses are JSON (`application/json`) with camelCase property names.
Error responses use RFC7807 ProblemDetails. Every response carries an
`X-Correlation-ID` header.

> **Implemented account endpoints:** email-first registration and email
> ownership verification with account-password creation (`/v1/auth/register`,
> `/v1/auth/verify-email`, `/v1/auth/resend-verification`), plus **login**
> (`/v1/auth/login`), **refresh** (`/v1/auth/refresh`), **logout**
> (`/v1/auth/logout`), and **logout-all** (`/v1/auth/logout-all`). **Session
> listing, `/account/me`, delete-session, password reset, phone/SMS, sync, and
> vault endpoints do not exist yet.** Registration/verification are exposed when
> EmailVerification is configured; **login/refresh/logout are exposed
> independently when the Login capability is enabled** (DB connection + JWT
> signing key + kid), even without SMTP. The API otherwise stays health/version only.

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
  email, session id, password, or token verifier. Rate limiting is a production
  blocker before public exposure (see SECURITY_MODEL).

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
