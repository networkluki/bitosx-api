# BitosX API — Endpoints

Base (local, this phase): `http://127.0.0.1:5080`

All responses are JSON (`application/json`) with camelCase property names.
Error responses use RFC7807 ProblemDetails. Every response carries an
`X-Correlation-ID` header.

> **Authentication endpoints do not exist yet.** There is no
> `/v1/auth/register`, login, logout, JWT, refresh-token, account, session,
> email/SMS verification, sync, or vault endpoint in this milestone. The `/v1`
> route group is reserved for future business endpoints and is currently empty.

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
