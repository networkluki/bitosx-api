#!/usr/bin/env bash
# smoke.sh — black-box checks of a PRODUCTION-configured API, started by this script on its own loopback port
# (BITOSX_DEVSTACK_SMOKE_PORT, default 5081) against the live stack's database (run up.sh first). It turns the
# verification commands at the end of docs/DEPLOYMENT.md into assertions that need no proxy in front:
#
#   - Production refuses to start when unsafe: hardening off, a wildcard listener, Email:HoldInOutbox, an http CORS
#     origin, an http WebAuthn origin, a localhost or IP WebAuthn RP ID, an RP ID that does not cover the origin;
#   - it starts with the shipped Security:WebAuthn section and serves passkey options for RP ID vault.bitosx.se;
#   - the listener is loopback-only (and not reachable on another local address);
#   - OpenAPI is absent (404), /health and /version answer 200;
#   - CORS is exactly as documented: the vault origin's preflights pass (envelope PUT included), https://bitosx.se
#     may read only GET /health and GET /version, any other origin gets no Access-Control-* header, credentials
#     are never allowed;
#   - the application's own response headers (no Server header, a correlation id, no stack traces), Host filtering;
#   - 413 for an oversized body;
#   - client identity comes only from the last X-Forwarded-For hop the loopback proxy wrote: forged earlier hops
#     and CF-Connecting-IP do not change it.
#
# The Apache-side checks (HSTS, Cloudflare real-IP, TLS) are deploy/scripts/verify.sh's job on the host.
# Fails on the first mismatch with a clear line on stderr.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR

# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

devstack_need curl openssl timeout

port="${BITOSX_DEVSTACK_SMOKE_PORT:-5081}"
if ! [[ "${port}" =~ ^[1-9][0-9]{0,4}$ ]] || ((port > 65535)); then
    devstack_die "invalid BITOSX_DEVSTACK_SMOKE_PORT '${port}'"
fi
base="http://127.0.0.1:${port}"
vault="https://vault.bitosx.se"
status_page="https://bitosx.se"

[[ -f "${API_ENV_FILE}" && -f "${BUILD_DIR}/api/BitosX.Api.dll" ]] || devstack_die "the live stack is not up (run tools/devstack/up.sh first)"
devstack_port_in_use "${port}" && devstack_die "127.0.0.1:${port} is already in use (set BITOSX_DEVSTACK_SMOKE_PORT)"

# The live stack's runtime connection string; everything else is generated fresh for this Production instance.
# shellcheck disable=SC1090,SC2154 # api.env (written by up.sh) defines ConnectionStrings__Bitosx
runtime_cs="$(set -a && . "${API_ENV_FILE}" && printf '%s' "${ConnectionStrings__Bitosx}")"

smoke_env="${STATE_DIR}/smoke-api.env"
smoke_pid="${STATE_DIR}/smoke-api.pid"
smoke_log="${LOG_DIR}/smoke-api.log"
work="$(mktemp -d)"
cleanup() {
    local status=$?
    devstack_stop_pid_file "${smoke_pid}"
    rm -f "${smoke_env}" "${smoke_env}".*
    rm -rf "${work}"
    exit "${status}"
}
trap cleanup EXIT

fail() { printf 'smoke: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'smoke: ok   %s\n' "$*" >&2; }

# write_env <file> [KEY=VALUE overrides...]: the production configuration (real CORS origins from appsettings.json).
write_env() {
    local file="$1"
    shift
    {
        printf '%s=%q\n' \
            ASPNETCORE_ENVIRONMENT Production \
            Kestrel__Endpoints__Http__Url "${base}" \
            ConnectionStrings__Bitosx "${runtime_cs}" \
            Security__JwtSigningKey "$(devstack_random_key)" \
            Security__Jwt__KeyId "smoke-$(openssl rand -hex 4)" \
            Security__EmailVerificationPepper "$(devstack_random_key)" \
            Security__EmailOutboxKey "$(devstack_random_key)" \
            Security__TotpKey "$(devstack_random_key)" \
            Security__PublicExposureHardening__Enabled true \
            Email__PublicBaseUrl "${vault}"
        local kv
        for kv in "$@"; do
            printf '%s=%q\n' "${kv%%=*}" "${kv#*=}"
        done
    } | devstack_write_private "${file}"
}

# ---- 1. Production fails closed on an unsafe configuration ----
expect_refused() {
    local what="$1" pattern="$2" status
    shift 2
    write_env "${smoke_env}.bad" "$@"
    devstack_clean_env_argv "${smoke_env}.bad" "${BUILD_DIR}/api" - dotnet BitosX.Api.dll
    status=0
    # The inner shell reports the host's abort (unhandled startup exception) into the log, not to this terminal.
    bash -c '"$@"; exit $?' refused timeout 60 "${DEVSTACK_ARGV[@]}" >"${work}/refused.log" 2>&1 || status=$?
    rm -f "${smoke_env}.bad"
    [[ "${status}" != "0" && "${status}" != "124" ]] || fail "${what}: the Production host started (exit ${status}) instead of refusing"
    grep -q -- "${pattern}" "${work}/refused.log" || fail "${what}: refused, but the log does not name '${pattern}': $(tail -n 3 "${work}/refused.log")"
    pass "Production refuses to start with ${what}"
}
expect_refused "hardening disabled" "PublicExposureHardening" Security__PublicExposureHardening__Enabled=false
expect_refused "a wildcard listener" "must bind to loopback" "Kestrel__Endpoints__Http__Url=http://0.0.0.0:${port}"
expect_refused "Email:HoldInOutbox" "Email:HoldInOutbox" Email__HoldInOutbox=true
expect_refused "an http CORS origin" "https://" Security__Cors__AllowedOrigins=http://127.0.0.1:8788
expect_refused "an http WebAuthn origin" "Security:WebAuthn:Origins" Security__WebAuthn__Origins__0=http://vault.bitosx.se
expect_refused "a localhost WebAuthn RP ID" "Security:WebAuthn:RelyingPartyId" \
    Security__WebAuthn__RelyingPartyId=localhost Security__WebAuthn__Origins__0=http://localhost:8788
expect_refused "an IP address as WebAuthn RP ID" "Security:WebAuthn:RelyingPartyId" \
    Security__WebAuthn__RelyingPartyId=127.0.0.1 Security__WebAuthn__Origins__0=https://127.0.0.1
expect_refused "a WebAuthn RP ID that does not cover the origin" "registrable suffix" Security__WebAuthn__Origins__0=https://bitosx.example

# ---- 2. the Production instance ----
write_env "${smoke_env}"
devstack_start_api "${smoke_pid}" "${smoke_log}" "${smoke_env}"
devstack_wait_health "${base}" 60 "${smoke_pid}" "${smoke_log}" || fail "the Production API did not become healthy"
pass "Production API is up on ${base} (hardening on)"

# hdr <out-file> <curl args...>: response headers (CR stripped, lower-cased names kept as sent) into <out-file>;
# prints the status code.
hdr() {
    local out="$1"
    shift
    curl -s -D "${out}.raw" -o "${out}.body" -w '%{http_code}' --max-time 10 "$@"
    tr -d '\r' <"${out}.raw" >"${out}"
}
has_header() { grep -qi "^$2:" "$1"; }
header_value() { grep -i "^$2:" "$1" | head -n 1 | cut -d: -f2- | sed 's/^ *//'; }
no_cors() { ! grep -qi '^access-control-' "$1"; }

# ---- 3. loopback-only listener ----
if command -v ss >/dev/null 2>&1; then
    listeners="$(ss -Hltn "( sport = :${port} )" | awk '{print $4}')"
    [[ -n "${listeners}" ]] || fail "ss shows no listener on port ${port}"
    while read -r address; do
        [[ "${address}" == 127.0.0.1:${port} || "${address}" == "[::1]:${port}" ]] \
            || fail "listener ${address} is not loopback-only"
    done <<<"${listeners}"
    pass "listener is loopback-only ($(tr '\n' ' ' <<<"${listeners}"))"
else
    devstack_log "ss not found; skipping the socket table check (the address probe below still runs)"
fi
other_ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -n 1 || true)"
if [[ -n "${other_ip}" ]]; then
    if curl -s -o /dev/null --max-time 3 "http://${other_ip}:${port}/health"; then
        fail "the API answers on ${other_ip}:${port} (not loopback-only)"
    fi
    pass "not reachable on ${other_ip}:${port}"
fi

# Every request below that reaches a rate-limited route carries the X-Forwarded-For the loopback Apache writes;
# in hardened mode a loopback peer without it has no usable client address and is refused (fail closed).
via_proxy=(-H "X-Forwarded-For: 192.0.2.$((RANDOM % 200 + 20))")

# ---- 4. surface ----
code="$(hdr "${work}/h" "${base}/openapi/v1.json")"
[[ "${code}" == "404" ]] || fail "GET /openapi/v1.json: expected 404, got ${code}"
pass "OpenAPI document is absent (404)"

code="$(hdr "${work}/h" "${base}/health")"
[[ "${code}" == "200" ]] || fail "GET /health: expected 200, got ${code}"
grep -q '"healthy"' "${work}/h.body" || fail "GET /health body does not report healthy"
has_header "${work}/h" server && fail "GET /health sends a Server header"
has_header "${work}/h" x-powered-by && fail "GET /health sends X-Powered-By"
has_header "${work}/h" x-correlation-id || fail "GET /health carries no X-Correlation-ID"
pass "GET /health 200, no Server/X-Powered-By header, X-Correlation-ID present"

code="$(hdr "${work}/h" "${base}/version")"
[[ "${code}" == "200" ]] || fail "GET /version: expected 200, got ${code}"
pass "GET /version 200"

code="$(hdr "${work}/h" -X POST "${base}/v1/auth/login" -H 'Content-Type: application/json' --data-binary '{"email":')"
[[ "${code}" == "400" ]] || fail "malformed login JSON: expected 400, got ${code}"
if [[ -s "${work}/h.body" ]]; then
    [[ "$(header_value "${work}/h" content-type)" == application/problem+json* ]] || fail "the 400 body is not application/problem+json"
fi
grep -qiE 'exception|stack ?trace|   at |\.cs:line' "${work}/h.body" && fail "the error response leaks exception details"
code="$(hdr "${work}/h" -X POST "${base}/v1/auth/login" "${via_proxy[@]}" -H 'Content-Type: application/json' --data-binary '{"email":"nobody@example.test","password":"wrong-password-123"}')"
[[ "${code}" == "401" && "$(header_value "${work}/h" content-type)" == application/problem+json* ]] \
    || fail "a failed login: expected 401 application/problem+json, got ${code}"
pass "errors carry no exception details (malformed JSON 400, failed login 401 ProblemDetails)"

code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base}/v1/auth/login" -H 'Content-Type: application/json' \
    --data-binary '{"email":"nobody@example.test","password":"wrong-password-123"}')"
[[ "${code}" == "503" ]] || fail "hardened login without a proxy-supplied client address: expected 503 (fail closed), got ${code}"
pass "hardened mode: a credential request without a usable client address is refused (503)"

code="$(hdr "${work}/h" -H 'Host: attacker.example' "${base}/health")"
[[ "${code}" == "400" ]] || fail "Host: attacker.example: expected 400 (AllowedHosts), got ${code}"
pass "Host filtering refuses an unknown Host (400)"

# ---- 4b. passkeys with the shipped relying party ----
code="$(hdr "${work}/h" -X POST "${base}/v1/auth/passkey/options" "${via_proxy[@]}")"
[[ "${code}" == "200" ]] || fail "POST /v1/auth/passkey/options: expected 200, got ${code}"
python3 -I -c '
import json, sys
o = json.load(open(sys.argv[1]))["options"]
assert o["rpId"] == "vault.bitosx.se", o["rpId"]
assert o["userVerification"] == "required" and o["allowCredentials"] == [], o
' "${work}/h.body" || fail "the passwordless options are not for RP ID vault.bitosx.se with UV required and no allow list"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base}/v1/auth/passkey/options")"
[[ "${code}" == "503" ]] || fail "hardened passkey options without a proxy-supplied client address: expected 503, got ${code}"
pass "passkeys: options for RP ID vault.bitosx.se (UV required); per-address limiter fails closed without a client address"

# ---- 5. CORS exactly as documented ----
code="$(hdr "${work}/h" -H "Origin: ${status_page}" "${base}/health")"
[[ "$(header_value "${work}/h" access-control-allow-origin)" == "${status_page}" ]] || fail "GET /health from ${status_page} is not readable"
has_header "${work}/h" access-control-allow-credentials && fail "GET /health from ${status_page} allows credentials"
code="$(hdr "${work}/h" -H "Origin: ${status_page}" "${base}/version")"
[[ "$(header_value "${work}/h" access-control-allow-origin)" == "${status_page}" ]] || fail "GET /version from ${status_page} is not readable"
pass "${status_page} may read GET /health and GET /version"

code="$(hdr "${work}/h" -X OPTIONS "${base}/health" -H "Origin: ${status_page}" -H 'Access-Control-Request-Method: POST')"
no_cors "${work}/h" || fail "a POST preflight to /health from ${status_page} got Access-Control-* headers"
code="$(hdr "${work}/h" -X OPTIONS "${base}/v1/auth/login" -H "Origin: ${status_page}" -H 'Access-Control-Request-Method: POST')"
no_cors "${work}/h" || fail "a preflight to /v1/auth/login from ${status_page} got Access-Control-* headers"
code="$(hdr "${work}/h" -H "Origin: ${status_page}" "${base}/v1/sync/status")"
no_cors "${work}/h" || fail "GET /v1/sync/status from ${status_page} got Access-Control-* headers"
pass "${status_page} gets nothing else (no Access-Control-* headers)"

code="$(hdr "${work}/h" -X OPTIONS "${base}/v1/sync/envelope" -H "Origin: ${vault}" \
    -H 'Access-Control-Request-Method: PUT' -H 'Access-Control-Request-Headers: content-type,authorization')"
[[ "${code}" == "204" ]] || fail "the envelope PUT preflight from ${vault}: expected 204, got ${code}"
[[ "$(header_value "${work}/h" access-control-allow-origin)" == "${vault}" ]] || fail "the envelope preflight does not allow ${vault}"
header_value "${work}/h" access-control-allow-methods | grep -q 'PUT' || fail "the envelope preflight does not list PUT"
has_header "${work}/h" access-control-allow-credentials && fail "the envelope preflight allows credentials"
pass "${vault}: envelope PUT preflight passes (204, PUT listed, no credentials)"

code="$(hdr "${work}/h" -X OPTIONS "${base}/v1/auth/login" -H "Origin: ${vault}" \
    -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type,authorization')"
[[ "${code}" == "204" && "$(header_value "${work}/h" access-control-allow-origin)" == "${vault}" ]] \
    || fail "the login preflight from ${vault} is not answered (status ${code})"
has_header "${work}/h" access-control-allow-credentials && fail "the login preflight allows credentials"
pass "${vault}: login preflight passes (204, no credentials)"

code="$(hdr "${work}/h" -X OPTIONS "${base}/v1/auth/passkey" -H "Origin: ${vault}" \
    -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type')"
[[ "${code}" == "204" && "$(header_value "${work}/h" access-control-allow-origin)" == "${vault}" ]] \
    || fail "the passkey sign-in preflight from ${vault} is not answered (status ${code})"
pass "${vault}: passkey sign-in preflight passes (204)"

for origin in "https://attacker.example" "http://vault.bitosx.se" "https://vault.bitosx.se.attacker.example" "null"; do
    hdr "${work}/h" -H "Origin: ${origin}" "${base}/health" >/dev/null
    no_cors "${work}/h" || fail "GET /health from ${origin} got Access-Control-* headers"
    hdr "${work}/h" -X OPTIONS "${base}/v1/sync/envelope" -H "Origin: ${origin}" -H 'Access-Control-Request-Method: PUT' >/dev/null
    no_cors "${work}/h" || fail "a preflight from ${origin} got Access-Control-* headers"
done
pass "any other origin gets no Access-Control-* headers"

# ---- 6. oversized bodies ----
python3 -I -c 'import sys; sys.stdout.write("{\"email\":\"" + "a" * 5000 + "\",\"password\":\"x\"}")' >"${work}/5k.json"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base}/v1/auth/login" "${via_proxy[@]}" -H 'Content-Type: application/json' --data-binary "@${work}/5k.json")"
[[ "${code}" == "413" ]] || fail "a 5 KB login body: expected 413, got ${code}"
python3 -I -c 'import sys; sys.stdout.write("{\"refreshToken\":\"" + "a" * 70000 + "\"}")' >"${work}/70k.json"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base}/v1/auth/refresh" "${via_proxy[@]}" -H 'Content-Type: application/json' --data-binary "@${work}/70k.json")"
[[ "${code}" == "413" ]] || fail "a 70 KB body (over the 64 KB Kestrel cap): expected 413, got ${code}"
pass "oversized bodies are refused with 413 (4 KiB auth cap, 64 KB server cap)"

# ---- 7. client identity: only the last X-Forwarded-For hop written by the loopback proxy counts ----
client_a="198.51.100.$((RANDOM % 200 + 20))"
client_b="203.0.113.$((RANDOM % 200 + 20))"
refresh() {
    curl -s -o /dev/null -w '%{http_code}' -X POST "${base}/v1/auth/refresh" -H 'Content-Type: application/json' \
        --data-binary '{"refreshToken":"smoke-not-a-token"}' "$@"
}
limited=0
for i in $(seq 1 40); do
    code="$(refresh -H "X-Forwarded-For: ${client_a}")"
    if [[ "${code}" == "429" ]]; then
        limited="${i}"
        break
    fi
done
((limited > 1)) || fail "the per-IP refresh limiter did not engage for ${client_a} within 40 requests"
pass "per-IP refresh limiter engaged for ${client_a} after $((limited - 1)) requests"

code="$(refresh -H "X-Forwarded-For: 192.0.2.77, ${client_a}")"
[[ "${code}" == "429" ]] || fail "a forged earlier X-Forwarded-For hop escaped the limit (got ${code})"
code="$(refresh -H "X-Forwarded-For: ${client_a}" -H 'CF-Connecting-IP: 192.0.2.78')"
[[ "${code}" == "429" ]] || fail "CF-Connecting-IP changed the client identity (got ${code})"
pass "forged earlier X-Forwarded-For hops and CF-Connecting-IP are ignored"
code="$(refresh -H "X-Forwarded-For: ${client_b}")"
[[ "${code}" != "429" ]] || fail "another client (${client_b}) is limited too: the limiter is not per client"
pass "another client address keeps its own budget (${code})"

printf 'smoke: PASS (%s)\n' "${base}" >&2
