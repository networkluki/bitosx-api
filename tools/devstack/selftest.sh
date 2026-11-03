#!/usr/bin/env bash
# selftest.sh — drives one fresh account through the local live stack with curl, using ONLY the three client
# variables (BITOSX_LIVE_API_URL, BITOSX_LIVE_WEB_ORIGIN, BITOSX_LIVE_MAIL_CMD; read from the environment, or from
# tools/devstack/.state/env when they are unset). Proves the stack works the way the client live suites use it:
#
#   register -> verify token via the mail command -> verify-email (sets the password) -> login -> /me ->
#   TOTP enroll + confirm (RFC 6238 code computed here) -> login + second step -> PUT/GET envelope (+409) ->
#   CORS preflight from the web origin -> change password (recovery code) -> old password refused ->
#   forgot + reset via the mail token -> delete account (recovery code) -> sign-in fails.
#
# Needs curl and python3. Fails on the first mismatch with a clear line on stderr.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR

# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

devstack_need curl python3

if [[ -z "${BITOSX_LIVE_API_URL:-}" && -f "${CLIENT_ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "${CLIENT_ENV_FILE}"
    set +a
fi
: "${BITOSX_LIVE_API_URL:?not set (run tools/devstack/up.sh)}"
: "${BITOSX_LIVE_WEB_ORIGIN:?not set (run tools/devstack/up.sh)}"
: "${BITOSX_LIVE_MAIL_CMD:?not set (run tools/devstack/up.sh)}"
api="${BITOSX_LIVE_API_URL}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() { printf 'selftest: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'selftest: ok   %s\n' "$*" >&2; }

# req <method> <path> [json-body] [bearer]: sets STATUS and BODY (the response body file).
req() {
    local method="$1" path="$2" body="${3:-}" bearer="${4:-}"
    local -a args=(-s -o "${work}/body" -w '%{http_code}' -X "${method}" "${api}${path}" -H 'Accept: application/json')
    [[ -n "${body}" ]] && args+=(-H 'Content-Type: application/json' --data-binary "${body}")
    [[ -n "${bearer}" ]] && args+=(-H "Authorization: Bearer ${bearer}")
    STATUS="$(curl "${args[@]}")"
    BODY="${work}/body"
}

expect() {
    local want="$1" what="$2"
    [[ "${STATUS}" == "${want}" ]] || fail "${what}: expected HTTP ${want}, got ${STATUS}: $(head -c 400 "${BODY}")"
    pass "${what} (${STATUS})"
}

# json <file> <python-expression over `d`>
json() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"; }

# totp <base32-secret> <step-offset>: RFC 6238 (HMAC-SHA1, 6 digits, 30 s), for the current step + offset.
totp() {
    python3 -I - "$1" "$2" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1].upper()
key = base64.b32decode(secret + "=" * (-len(secret) % 8))
counter = int(time.time()) // 30 + int(sys.argv[2])
mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = mac[-1] & 0x0F
code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
print(f"{code:06d}")
PY
}

email="e2e-$(openssl rand -hex 8)@example.test"
password="selftest-$(openssl rand -hex 12)"
new_password="selftest-$(openssl rand -hex 12)"
reset_password="selftest-$(openssl rand -hex 12)"
printf 'selftest: account %s against %s\n' "${email}" "${api}" >&2

req GET /health
expect 200 "GET /health"

# ---- register + verify through the outbox ----
req POST /v1/auth/register "{\"email\":\"${email}\"}"
expect 202 "register"

set +e
"${BITOSX_LIVE_MAIL_CMD}" latest reset "${email}" >/dev/null 2>&1
none_status=$?
ASPNETCORE_ENVIRONMENT=Production "${BITOSX_LIVE_MAIL_CMD}" latest verify "${email}" >/dev/null 2>&1
prod_status=$?
set -e
[[ "${none_status}" == "1" ]] || fail "mail command with no pending reset message: expected exit 1, got ${none_status}"
pass "mail command: no pending message -> exit 1"
[[ "${prod_status}" != "0" ]] || fail "mail command ran with ASPNETCORE_ENVIRONMENT=Production"
pass "mail command: refused with ASPNETCORE_ENVIRONMENT=Production (exit ${prod_status})"

verify_token="$("${BITOSX_LIVE_MAIL_CMD}" latest verify "${email}")"
[[ "${verify_token}" =~ ^[A-Za-z0-9_-]{20,}$ ]] || fail "the verify token does not look like Base64url"
pass "mail command: verify token read from the outbox"

req POST /v1/auth/verify-email "{\"token\":\"${verify_token}\",\"password\":\"${password}\"}"
expect 200 "verify-email (sets the password)"
req POST /v1/auth/verify-email "{\"token\":\"${verify_token}\",\"password\":\"${password}\"}"
expect 400 "verify-email again (single use)"

# ---- login ----
req POST /v1/auth/login "{\"email\":\"${email}\",\"password\":\"${password}\"}"
expect 200 "login (password only)"
access="$(json "${BODY}" 'd["accessToken"]')"

req GET /v1/account/me "" "${access}"
expect 200 "GET /v1/account/me"
[[ "$(json "${BODY}" 'd["email"]')" == "${email}" ]] || fail "/me returned another email"
[[ "$(json "${BODY}" 'd["createdAt"]')" == *Z ]] || fail "/me createdAt is not UTC (no Z)"

# ---- TOTP ----
req POST /v1/account/totp/enroll "{\"password\":\"${password}\"}" "${access}"
expect 200 "TOTP enroll"
secret="$(json "${BODY}" 'd["secret"]')"
[[ "$(json "${BODY}" 'd["digits"]')" == "6" && "$(json "${BODY}" 'd["periodSeconds"]')" == "30" ]] \
    || fail "TOTP parameters are not 6 digits / 30 s"

req POST /v1/account/totp/confirm "{\"code\":\"$(totp "${secret}" 0)\"}" "${access}"
expect 200 "TOTP confirm (current step)"
recovery1="$(json "${BODY}" 'd["recoveryCodes"][0]')"
recovery2="$(json "${BODY}" 'd["recoveryCodes"][1]')"

req POST /v1/auth/login "{\"email\":\"${email}\",\"password\":\"${password}\"}"
expect 202 "login now asks for the second factor"
mfa_token="$(json "${BODY}" 'd["mfaToken"]')"
# The current step is used up by the confirmation (replay guard); the next one is inside the +-1 window.
req POST /v1/auth/login/totp "{\"mfaToken\":\"${mfa_token}\",\"code\":\"$(totp "${secret}" 1)\"}"
expect 200 "second sign-in step with a TOTP code"
access="$(json "${BODY}" 'd["accessToken"]')"

# ---- envelope sync ----
envelope_json='{"version":1,"kdf":"argon2id","kdfParameters":{"memoryKiB":262144,"iterations":3,"parallelism":4,"keyLengthBytes":32},"salt":"AAAAAAAAAAAAAAAAAAAAAA==","algorithm":"AES-256-GCM","keyWrapNonce":"AAAAAAAAAAAAAAAA","encryptedVaultKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","contentNonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAA"}'
envelope_b64="$(printf '%s' "${envelope_json}" | base64 | tr -d '\n')"

req PUT /v1/sync/envelope "{\"baseRevision\":0,\"envelope\":\"${envelope_b64}\"}" "${access}"
expect 200 "PUT /v1/sync/envelope (first upload)"
revision="$(json "${BODY}" 'd["revision"]')"

req GET /v1/sync/envelope "" "${access}"
expect 200 "GET /v1/sync/envelope"
[[ "$(json "${BODY}" 'd["envelope"]')" == "${envelope_b64}" ]] || fail "the downloaded envelope differs from the upload"
[[ "$(json "${BODY}" 'd["revision"]')" == "${revision}" ]] || fail "the downloaded revision differs"
pass "downloaded envelope is byte-identical (revision ${revision})"

req PUT /v1/sync/envelope "{\"baseRevision\":0,\"envelope\":\"${envelope_b64}\"}" "${access}"
expect 409 "PUT with a stale baseRevision (compare-and-set)"

# ---- CORS from the web origin (the real response headers, as a browser sees them) ----
cors_headers="$(curl -s -D - -o /dev/null -X OPTIONS "${api}/v1/sync/envelope" \
    -H "Origin: ${BITOSX_LIVE_WEB_ORIGIN}" -H 'Access-Control-Request-Method: PUT' \
    -H 'Access-Control-Request-Headers: content-type,authorization' | tr -d '\r')"
grep -qi "^access-control-allow-origin: ${BITOSX_LIVE_WEB_ORIGIN}\$" <<<"${cors_headers}" \
    || fail "the envelope preflight from ${BITOSX_LIVE_WEB_ORIGIN} is not allowed"
grep -qi '^access-control-allow-methods:.*PUT' <<<"${cors_headers}" || fail "the preflight does not allow PUT"
pass "CORS preflight from ${BITOSX_LIVE_WEB_ORIGIN} allows PUT"

# ---- change password (recovery code), the old one stops working ----
req POST /v1/account/password "{\"currentPassword\":\"${password}\",\"newPassword\":\"${new_password}\",\"code\":\"${recovery1}\"}" "${access}"
expect 204 "change password (confirmed with a recovery code)"
req GET /v1/account/me "" "${access}"
expect 200 "the calling session stays valid"
req POST /v1/auth/login "{\"email\":\"${email}\",\"password\":\"${password}\"}"
expect 401 "login with the old password"

# ---- forgot + reset via the outbox ----
req POST /v1/auth/forgot-password "{\"email\":\"${email}\"}"
expect 202 "forgot-password"
reset_token="$("${BITOSX_LIVE_MAIL_CMD}" latest reset "${email}")"
pass "mail command: reset token read from the outbox"
req POST /v1/auth/reset-password "{\"token\":\"${reset_token}\",\"password\":\"${reset_password}\"}"
expect 200 "reset-password"
req GET /v1/account/me "" "${access}"
expect 401 "every session is signed out by the reset"
req POST /v1/auth/login "{\"email\":\"${email}\",\"password\":\"${reset_password}\"}"
expect 202 "login with the reset password (second factor still required)"
mfa_token="$(json "${BODY}" 'd["mfaToken"]')"
req POST /v1/auth/login/totp "{\"mfaToken\":\"${mfa_token}\",\"code\":\"${recovery2}\"}"
expect 200 "second sign-in step with a recovery code"
access="$(json "${BODY}" 'd["accessToken"]')"

# ---- delete the account ----
req POST /v1/account/delete "{\"password\":\"${reset_password}\"}" "${access}"
expect 403 "delete without the second factor is refused"
# The next TOTP step after the one the sign-in used: wait until it is inside the window if needed.
code="$(totp "${secret}" 1)"
req POST /v1/account/delete "{\"password\":\"${reset_password}\",\"code\":\"${code}\"}" "${access}"
if [[ "${STATUS}" == "403" ]]; then
    devstack_log "TOTP step already used; waiting for the next step"
    sleep $((30 - $(date +%s) % 30 + 1))
    req POST /v1/account/delete "{\"password\":\"${reset_password}\",\"code\":\"$(totp "${secret}" 1)\"}" "${access}"
fi
expect 204 "delete account (password + TOTP code)"
req POST /v1/auth/login "{\"email\":\"${email}\",\"password\":\"${reset_password}\"}"
expect 401 "login after deletion"

printf 'selftest: PASS (%s)\n' "${email}" >&2
