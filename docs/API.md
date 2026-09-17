# BitosX API — Endpoints

Base (local, this phase): `http://127.0.0.1:5080`

All responses are JSON (`application/json`) with camelCase property names.
Error responses use RFC7807 ProblemDetails. Every response carries an
`X-Correlation-ID` header.

> **Implemented account endpoints:** email-first registration and email
> ownership verification with account-password creation (`/v1/auth/register`,
> `/v1/auth/verify-email`, `/v1/auth/resend-verification`). **Login, logout,
> JWT, refresh tokens, sessions, password reset, phone/SMS, sync, and vault
> endpoints do not exist yet.** Account endpoints are exposed only when the
> account subsystem is configured (DB connection + verification pepper + outbox
> key + SMTP app password); the API otherwise stays health/version only.

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
