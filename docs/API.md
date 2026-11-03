# BitosX API — Endpoints

Base: `https://api.bitosx.se` in production (Cloudflare → Apache → loopback Kestrel);
`http://127.0.0.1:5080` locally.

All responses are JSON (`application/json`) with camelCase property names. **Null fields are
omitted** (a `null` value is never written; a client treats a missing optional field as null).
Error responses use RFC7807 ProblemDetails. Every response carries an
`X-Correlation-ID` header.

**Timestamps.** Every timestamp is UTC in ISO 8601 with an explicit `Z`
(`2026-01-01T00:15:00.123456Z`), including values read from the database (the connection
forces UTC). Clients still treat a timestamp without an offset as UTC.

**Browser clients (CORS).** Only the origins listed in `Security:Cors:AllowedOrigins`
(repository default: `https://vault.bitosx.se`, the web account app) may read responses
from a browser. Allowed methods `GET`/`POST`/`PUT`/`DELETE` (`PUT` is the envelope upload),
request headers `Authorization`/`Content-Type`/`Accept`, exposed headers
`Retry-After`/`X-Correlation-ID`, no credentials; a preflight (`OPTIONS` +
`Access-Control-Request-Method`) is answered with **204** before any endpoint runs. The
origins in `Security:Cors:StatusPageOrigins` (repository default: `https://bitosx.se`, the
product page) may read **only** `GET /health` and `GET /version` (method `GET` only); every
other endpoint gives them no CORS headers. Other origins get no CORS headers. See
[`SECURITY_MODEL.md`](SECURITY_MODEL.md) — "Browser clients (CORS)".

**Request bodies.** Auth and account endpoints refuse a declared `Content-Length` over **4 KiB**
with **413** before the handler runs; a body without `Content-Length` is bounded by Kestrel's 64 KB
cap (also **413**). Only `PUT /v1/sync/envelope` accepts more.

> **Implemented account endpoints:** email-first registration and email
> ownership verification with account-password creation (`/v1/auth/register`,
> `/v1/auth/verify-email`, `/v1/auth/resend-verification`), plus **login**
> (`/v1/auth/login`), **refresh** (`/v1/auth/refresh`), **logout**
> (`/v1/auth/logout`), **logout-all** (`/v1/auth/logout-all`), and the protected
> account endpoints **`/v1/account/me`**, **`/v1/account/sessions`**, and
> **`DELETE /v1/account/sessions/{id}`**. **Encrypted-envelope sync** (`/v1/sync/*`) rides on Login.
> **Password reset by emailed link** (`/v1/auth/forgot-password`, `/v1/auth/reset-password`) and
> **password-confirmed account deletion** (`POST /v1/account/delete`) exist since phase 6. **TOTP
> two-factor sign-in** (`POST /v1/auth/login/totp`, `/v1/account/totp/*`) exists since phase 7 and is
> exposed when the **Totp** capability is enabled (`Security:TotpKey`). **Password change while signed
> in** (`POST /v1/account/password`) exists since phase 8. **Passkeys (WebAuthn)** — as the second
> factor and for sign-in without email and password (`/v1/auth/login/passkey*`, `/v1/auth/passkey*`,
> `/v1/account/passkeys*`) — exist since phase 10 and are exposed when the **Passkeys** capability is
> enabled (Totp + a valid `Security:WebAuthn`; otherwise those routes are **404**). **Phone/SMS does not exist yet.** Registration/verification/password reset are exposed when
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

In the Development and Testing environments only, `Email:HoldInOutbox=true` makes `register`,
`resend-verification` and `forgot-password` behave as with delivery (202, the message queued in the
encrypted outbox) while nothing is ever sent — the local live stack reads the token from the outbox
(`tools/devstack/mail.sh`). Every other environment, Production included, refuses to start with it.

## `POST /v1/auth/verify-email`

Consumes a verification token and **sets the account password** (chosen by the
token holder). Password policy: 12–128 characters, used exactly as supplied.
Verification + password + challenge-consume are applied atomically.

Request: `{ "token": "<base64url>", "password": "<12..128>" }` → **200 OK**
`{ "message": "Your email is verified and your password is set." }`

Invalid/expired/consumed/invalidated, missing or `null` token → **400** generic ProblemDetails
(`detail: "Invalid or expired verification token."`).
Password outside 12–128 → **400** ProblemDetails (challenge not consumed).
Argon2 admission overload → **503** (`Retry-After: 1`); the token stays usable.

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
does nothing. The response **status and body are identical in every case** (the response time is
not: an eligible account costs a database transaction an unknown address does not, so a precise
timing measurement can still tell them apart; see SECURITY_MODEL "Anti-enumeration: what holds"):

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
  **401** `application/problem+json` (`detail: "Invalid email or password."`): the
  status and body never say whether the account exists. **No Argon2 runs for a
  non-login-capable account** (an approved DoS trade-off), so the response time
  still differs: an unknown address answers without the ~0.2–0.4 s hash, only
  partly masked by the 25–75 ms jitter, and while the Argon2 queue is full only a
  login-capable account gets the **503**. Rate limits bound how often this can be
  probed; see SECURITY_MODEL "Anti-enumeration: what holds".
- Malformed JSON → **400**. Request body over **4 KiB** → **413** (when
  `Content-Length` is declared, before any credential evaluation; otherwise the
  64 KB Kestrel cap applies).
- The access token is a short-lived HS256 JWT (mandatory `kid`); the refresh
  token is an opaque rotating credential. The response contains no account id,
  email, session id, password, or token verifier.
- **Second factor (phase 7).** When the account has TOTP confirmed, a correct password
  does **not** return tokens: the response is **202 Accepted**
  `{ "mfaToken": "<base64url, 43 chars>", "mfaTokenExpiresAt": "…", "method": "totp", "methods": ["totp", "recovery"] }`
  and no session exists until `POST /v1/auth/login/totp` (or, phase 10, `POST /v1/auth/login/passkey`)
  succeeds. `methods` lists how the step can be completed: `"totp"`, `"recovery"` and — when the server
  offers passkeys and the account has at least one — `"passkey"`; clients ignore values they do not know
  (`method` stays `"totp"` for older clients). The token is a one-step bearer secret (5-minute lifetime,
  5 failed attempts — wrong codes and refused passkeys alike —, single use). If TOTP is required but the
  server's Totp capability is off, login returns **503** rather than a password-only session (fail closed).
- When public-exposure hardening is enabled: per-IP, per-normalized-email, and a
  process-wide login budget apply → generic **429** (`Retry-After` when available);
  an unresolvable trusted client IP → **503**. Bounded Argon2 work admission is
  **always** active (independent of hardening): if the hash queue is saturated or the
  bounded wait times out, login returns a generic **503** (`Retry-After: 1`) — never a
  credential 401 and never a token. See SECURITY_MODEL for the full policy.

## `POST /v1/auth/login/totp`

**Unauthenticated** second sign-in step. Exchanges the challenge token from the password step plus a
6-digit TOTP code **or** a recovery code (`xxxxx-xxxxx`, case and separators ignored) for the same
`TokenResponse` login returns. The session's client descriptor is the `User-Agent` of the password step.

Request: `{ "mfaToken": "<from the 202>", "code": "123456" }` → **200 OK** (`TokenResponse`).

- Every failure (unknown/expired/spent token, wrong code, replayed code, used recovery code,
  password changed between the steps, TOTP disabled meanwhile) → one identical generic **401**
  (`detail: "Invalid or expired sign-in code."`). No attempts-left hint. Each request reserves one
  of the challenge's **5** attempts atomically *before* its code is checked, so even parallel
  requests get at most 5 code checks per challenge; after that the challenge is spent and the
  password must be entered again.
- A TOTP code is accepted within ±1 step (30 s) of the server's clock and **once**: the step is
  recorded and no code for it, or for an older step, is accepted again. A recovery code is single use.
- Totp capability off → **503**. Body over **4 KiB** → **413**. Under hardening a per-IP limit
  (10 burst / 5 per 30 s) and a per-account limit across all of the account's challenges
  (`MfaPerAccount`, 10 burst / 2 per 60 s, keyed by the account the challenge names) apply →
  generic **429** (`Retry-After`); a per-account limiter at capacity → **503**.

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

- At most **200** sessions are returned, newest (`createdAt`) first. Clients size their
  reads for that (≥ 128 KiB).
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
identity, never an id in the body), confirmed with the account password and, **when the account has
TOTP confirmed, a TOTP or recovery code** (the same confirmation that turning TOTP off needs).
Removes the account and, by cascade, its sessions, refresh tokens, verification/reset challenges,
queued mail, TOTP rows and the **stored vault envelope**. A local vault file on the user's device is
not touched.

Request: `{ "password": "<current account password>", "code": "123456" }` → **204 No Content**.
`code` is needed only with TOTP confirmed; accounts without TOTP send `{ "password" }` alone.

- Wrong password, empty password, a missing or wrong code when TOTP is confirmed, or an account
  that cannot be deleted this way → one generic **403** `application/problem+json`
  (`detail: "Password confirmation failed."`); nothing is deleted and the session stays valid
  (403, not 401, so a client does not mistake it for a dead session). The password is checked
  first, so a wrong password never uses up a code.
- TOTP confirmed but the server's Totp capability is off → **503** (no `Retry-After`); nothing is
  deleted (fail closed).
- Missing/invalid bearer → **401**. Body over **4 KiB** → **413**. Extra body fields (e.g. an
  `accountId`) are ignored.
- Argon2 admission overload → **503** (`Retry-After: 1`).
- Under hardening: per-account limit (5 burst / 1 per 3 min, keyed by the server-issued account
  id) → generic **429**. After deletion the address can register again from scratch.

## `POST /v1/account/password`

**Authenticated.** Changes the caller's own **account** password while signed in. The vault master
password is **not** affected (the server never has it); clients say so in their UI.

Request: `{ "currentPassword": "…", "newPassword": "<12..128>", "code": "123456" }` → **204 No Content**.
`code` (TOTP or recovery code) is required only when the account has TOTP confirmed.

- On success, in one transaction: the new Argon2id hash is stored (after an exact re-check, under the
  account lock, that the hash the current password was verified against is still the stored one),
  **every other session and its refresh tokens are revoked**, the **calling session stays valid**,
  and every open password-reset link is invalidated.
- New password outside 12–128 → **400** ProblemDetails (`detail` names the policy). Checked first,
  without any Argon2.
- Wrong current password, missing or wrong code when TOTP is confirmed, or an account that cannot
  sign in → one generic **403** (`detail: "Password confirmation failed."`); nothing changes and the
  session stays valid. The password is checked before the code.
- TOTP confirmed but the Totp capability is off → **503** (no `Retry-After`).
- Argon2 admission overload → **503** (`Retry-After: 1`). Body over **4 KiB** → **413**. Missing or
  invalid bearer → **401**.
- Under hardening: per-account limit (`PasswordChangePerAccount`, 5 burst / 1 per 3 min, keyed by
  the JWT `sub`) → generic **429**.

## Two-factor authentication (`/v1/account/totp`)

**Authenticated.** TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30 s — what every authenticator app
expects) for the caller's own account. All routes answer **503** when the Totp capability is off,
**401** without a valid session, and **413** over 4 KiB. Under hardening a per-account limit
(10 burst / 2 per 60 s) applies → **429**.

- `GET /v1/account/totp` → **200** `{ "enabled": false, "recoveryCodesRemaining": 0,
  "pendingEnrollment": false }` (`confirmedAt` is present only once TOTP is confirmed: null fields are
  omitted). No secret is ever included.
- `POST /v1/account/totp/enroll` `{ "password": "<account password>" }` → **200**
  `{ "secret": "<Base32>", "otpauthUri": "otpauth://totp/BitosX:<email>?secret=…&issuer=BitosX&algorithm=SHA1&digits=6&period=30",
  "issuer": "BitosX", "label": "<email>", "digits": 6, "periodSeconds": 30 }`. The secret is
  returned **exactly once**; the client shows it (and the URI, for a QR code) and never stores it.
  A pending secret is **not** a second factor yet and is replaced by the next enroll call. Wrong
  password → **403** generic; TOTP already enabled → **409** (disable first).
- `POST /v1/account/totp/confirm` `{ "code": "123456" }` → **200**
  `{ "recoveryCodes": ["abcde-fghjk", … ×10] }`. A first valid code for the pending secret turns
  it into the account's second factor and issues **10 single-use recovery codes**, returned
  exactly once (only keyed verifiers are stored). Wrong code → **400**; nothing pending → **409**
  (also when another enroll call replaced the pending secret after this code was checked: the
  confirmation is bound to the secret the code matched).
- `POST /v1/account/totp/disable` `{ "password": "…", "code": "<TOTP or recovery code>" }`
  → **204**. Removes the second factor, every recovery code and every open challenge. Wrong
  password or code → **403** generic (the password is checked first, so a wrong password never
  consumes a code); not enabled → **409**; the account has passkeys → **409**
  (`detail: "The account has passkeys. Remove the passkeys first."`, checked before the password and
  code, so nothing is used up). Passkeys exist only on top of TOTP; this holds even when the server's
  Passkeys capability is off (the passkeys then have to be re-enabled to be removed, or the account deleted).
- `POST /v1/account/totp/recovery-codes` `{ "password": "…", "code": "…" }` → **200**
  `{ "recoveryCodes": [ … ] }`: replaces every recovery code. Same failure contract as disable.

Enabling TOTP changes only the **account** sign-in (and the confirmation of password change and
account deletion). The vault master password, the vault key and the encrypted envelope are
unaffected. A password reset (phase 6) keeps TOTP enabled; deleting the account removes it.

## Passkeys (WebAuthn, phase 10)

Passkeys are added **on top of TOTP, never instead of it**: an account must have TOTP confirmed to
register one, TOTP cannot be disabled while passkeys exist, and the desktop app keeps signing in with
TOTP/recovery codes. A passkey authenticates the **account** only; the vault master password is
untouched (zero-knowledge). Every route below exists only with the **Passkeys** capability (Login + Totp
+ a valid `Security:WebAuthn`, see DEPLOYMENT); without it they are **404**.

`options` objects are the standard WebAuthn JSON (`PublicKeyCredentialCreationOptionsJSON` /
`PublicKeyCredentialRequestOptionsJSON`: binary members are unpadded base64url strings) as the server's
WebAuthn library (Fido2 4.3.2) writes them — pass them to `PublicKeyCredential.parseCreationOptionsFromJSON` /
`parseRequestOptionsFromJSON` (or convert the base64url members) and send `credential.toJSON()` back as
`credential`. Unknown members are ignored. A ceremony (registration, second step, passwordless) is
server-side, **single use** whatever its outcome, valid for **5 minutes** (`timeout` 300000 ms), and bound
to its purpose: a challenge issued for one ceremony is refused by every other.

### Account (`/v1/account/passkeys`, authenticated)

- `GET /v1/account/passkeys` → **200**
  `{ "passkeys": [ { "id": "<guid>", "name": "…", "createdAt": "…Z", "lastUsedAt": "…Z", "backedUp": true } ], "max": 10 }`
  (oldest first; `lastUsedAt` is absent until the first sign-in with it; `backedUp` is the authenticator's
  backup-state flag, i.e. a synced passkey). Never key material or credential ids.
- `POST /v1/account/passkeys/registration/options` `{ "password": "…", "code": "<TOTP or recovery code>" }`
  → **200** `{ "registrationId": "<base64url, 43 chars>", "options": { … } }`. The options require a
  discoverable credential (`residentKey: "required"`) and user verification, `attestation: "none"`, offer
  ES256 (-7), EdDSA (-8) and RS256 (-257), exclude the account's passkeys (`excludeCredentials`), and carry
  `user.id` = the account's random 32-byte WebAuthn user handle (never the account id or email) and
  `user.name` = `user.displayName` = the account email; `rp.id` is the configured RP ID.
  TOTP not confirmed → **409** (`"Two-factor authentication is required before a passkey can be added."`);
  10 passkeys already → **409**; both checked before the password and code, so nothing is used up. Wrong
  password or code → **403** generic (password first; the code is used up only on success). Argon2
  overload → **503** (`Retry-After: 1`).
- `POST /v1/account/passkeys/registration` `{ "registrationId": "…", "name": "Laptop", "credential": { … } }`
  → **201** `{ "id": "<guid>", "name": "Laptop", "createdAt": "…Z", "backedUp": false }`.
  The name is trimmed, 1-64 characters, without control characters, line separators or bidirectional
  overrides; an invalid name → **400** before the ceremony is used (retry with the same `registrationId`).
  Unknown, expired, already used or another account's `registrationId` → **410**. Any verification failure
  (origin, RP ID hash, type, challenge, user presence/verification flags, algorithm, malformed data) or a
  credential id that is already registered (to this or any account) → **400** generic
  (`"The passkey could not be verified."`). TOTP removed or the 10th passkey added meanwhile → **409**.
  Body over **16 KiB** → **413**.
- `PATCH /v1/account/passkeys/{id}` **or** `POST /v1/account/passkeys/{id}/rename` `{ "name": "…" }` →
  **204**. Browsers must use the POST route: the CORS policy allows no PATCH. Invalid name → **400**;
  unknown or another account's id → **404**.
- `POST /v1/account/passkeys/{id}/delete` `{ "password": "…", "code": "…" }` → **204**. Unknown or another
  account's id → **404** (checked first); wrong password or code → **403** generic.

These routes share the TOTP-management limit per account (`TotpManagePerAccount`) under hardening.

### Second factor after the password

- `POST /v1/auth/login/passkey/options` `{ "mfaToken": "<from the 202>" }` → **200** `{ "options": { … } }`
  with `allowCredentials` = the account's passkeys and `userVerification: "preferred"` (the password was the
  first factor). Each call replaces the previous passkey challenge of this MFA token. A bad, expired or spent
  token, or an account without passkeys → **401** generic (`"Passkey sign-in failed."`).
- `POST /v1/auth/login/passkey` `{ "mfaToken": "…", "credential": { … } }` → **200** (`TokenResponse`, the
  session exactly as `/v1/auth/login/totp` creates it). Every failure → **401** generic, and it uses up one
  of the MFA token's **5** attempts exactly like a wrong code (reserved atomically before anything is
  verified, same `MfaPerAccount`/`MfaPerIp` limits → **429**/**503**). The credential must be one of the
  account's passkeys. Body over **16 KiB** → **413**.

### Sign-in without email and password

- `POST /v1/auth/passkey/options` (no body) → **200** `{ "assertionId": "<base64url, 43 chars>", "options": { … } }`
  with an empty `allowCredentials` (a discoverable credential) and `userVerification: "required"`. The
  answer is the same for everyone and reveals nothing about any account.
- `POST /v1/auth/passkey` `{ "assertionId": "…", "credential": { … } }` → **200** (`TokenResponse`); the
  passkey counts as **both factors**. Requires the UV flag, a `userHandle` equal to the stored credential's
  and the account's, and an account that is verified, not disabled and still has TOTP confirmed. Every
  failure → **401** generic (`"Passkey sign-in failed."`). Body over **16 KiB** → **413**.
- Under hardening both routes share a per-client-address limit (`PasskeyPerAddress`, 20 burst / 10 per 60 s)
  → **429**; no usable client address → **503**.

Every successful use records `lastUsedAt` and the authenticator's signature counter; a counter that does
not increase (when either it or the stored one is non-zero) is refused as a possible cloned authenticator
and logged. A password reset by email does not remove passkeys; "sign out everywhere" does not touch them;
deleting the account removes them. Account deletion and password change keep requiring the password plus a
TOTP or recovery code.

## Encrypted-envelope sync (`/v1/sync`)

**Authenticated**, mapped with the Login capability. The *envelope* is the desktop vault file
exactly as BitosX writes it: JSON whose cryptographic fields are ciphertext under a key derived
from the master password on the device. The server stores and returns those bytes and never has
anything that could decrypt them; the only thing it reads is the public header (a JSON object with
a numeric `version`), to refuse arbitrary bytes. One envelope per account.

Every stored envelope has a **revision** (1, 2, 3, …) and a **fingerprint** (SHA-256 over the
bytes, lowercase hex). Uploads are compare-and-set on the revision, so two devices can never
overwrite each other unknowingly: the client names the revision it last saw, and the server writes
only if that is still current. **Revisions never restart:** after a delete the next upload gets the
previous revision + 1, never 1, so a device that recorded an old revision can never mistake a new
lineage for the one it saw.

### `GET /v1/sync/status`

→ **200** `{ "revision": 3, "fingerprint": "<64 hex>", "sizeBytes": 12345, "updatedAt": "…" }`,
or **404** when nothing is stored.

### `GET /v1/sync/envelope`

→ **200** `{ "revision", "fingerprint", "sizeBytes", "updatedAt", "envelope": "<base64>" }`
(`Cache-Control: no-store`), or **404** when nothing is stored.

### `PUT /v1/sync/envelope`

Request: `{ "baseRevision": 0, "envelope": "<base64>" }` — `baseRevision` is the revision the
client last saw, `0` when nothing is stored (never uploaded, or deleted since). `0` is accepted
only while nothing is stored.

- **200** `{ "revision", "fingerprint", "sizeBytes", "updatedAt" }` — stored as the next revision
  (`baseRevision + 1`, or after a delete the deleted revision + 1).
- **409** `application/problem+json` with `currentRevision` — the server holds a revision the
  client has not seen (`currentRevision` is `0` while nothing is stored); nothing was written.
  Download it first, or upload against it deliberately.
- **400** — not Base64, empty, or not a BitosX envelope (not UTF-8 JSON, not an object, no
  positive integer `version`, or trailing content).
- **413** — the decoded envelope exceeds `Security:Sync:MaxEnvelopeBytes` (default and maximum
  16 MiB, the desktop format's own cap); the request body limit for this endpoint is raised
  accordingly (Base64 of that plus 1 KiB).
- Under public-exposure hardening a per-account write limit applies (30 burst / 10 per minute,
  keyed by the account id from the JWT) → generic **429**. It runs before the body is read, so a
  limited upload costs no body transfer or parsing.
- Clients give envelope transfers a longer timeout (120 s) than ordinary calls (15 s).

### `DELETE /v1/sync/envelope`

Removes the account's stored envelope. → **204**, also when nothing was stored (idempotent). The
revision is kept as a tombstone (status/download answer **404**), so the next upload continues the
numbering. Under hardening the same per-account write limit applies.

## `GET /health`

Process liveness only. It does **not** report database or dependency readiness, so a public probe
learns nothing about the configuration behind it. Readable cross-origin by the status-page origins.

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

An OpenAPI document is served at `/openapi/v1.json` **in the Development environment only**; in
Production the route does not exist (404). Exposing it publicly would be a separate decision.
