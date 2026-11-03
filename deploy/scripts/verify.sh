#!/usr/bin/env bash
# verify.sh [--url https://api.bitosx.se] [--resolve HOST:PORT:ADDRESS] [--cacert FILE] [--local]
#
# Runs the verification procedure of docs/DEPLOYMENT.md against a deployed API and fails on the first mismatch.
#
# Through the public chain (Cloudflare -> Apache -> Kestrel), from anywhere:
#   OpenAPI absent (404); /health 200; CORS exactly as documented (https://bitosx.se reads only /health and /version,
#   https://vault.bitosx.se passes its preflights including the envelope PUT, no credentials, one
#   Access-Control-Allow-Origin header only, any other origin gets none); HSTS and nosniff set at the edge; no
#   version in the Server header, no X-Powered-By; 413 for an oversized envelope upload.
#
# With --local, on the production host itself (as root), additionally:
#   Kestrel listens on loopback only; the service is active; Apache's ProxyPass targets loopback Kestrel and
#   `apachectl -t` passes; the secret files have the documented owners and modes and the service's file holds no
#   migrator secret; MariaDB max_allowed_packet >= 32M and binlog_format is not STATEMENT.
#
#   --resolve / --cacert are passed to curl (e.g. to test a staging origin before switching DNS).
# Environment for --local: BITOSX_VERIFY_PORT (5080), BITOSX_VERIFY_SERVICE (bitosx-api),
# BITOSX_VERIFY_ENV_FILE (/etc/bitosx-api/bitosx-api.env), BITOSX_VERIFY_MIGRATOR_FILE (/etc/bitosx-api/migrator.env).
set -euo pipefail

url="https://api.bitosx.se"
local_checks=0
curl_extra=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) [[ $# -ge 2 ]] || exit 2; url="${2%/}"; shift 2 ;;
        --resolve) [[ $# -ge 2 ]] || exit 2; curl_extra+=(--resolve "$2"); shift 2 ;;
        --cacert) [[ $# -ge 2 ]] || exit 2; curl_extra+=(--cacert "$2"); shift 2 ;;
        --local) local_checks=1; shift ;;
        *) echo "usage: verify.sh [--url URL] [--resolve HOST:PORT:ADDRESS] [--cacert FILE] [--local]" >&2; exit 2 ;;
    esac
done

vault="https://vault.bitosx.se"
status_page="https://bitosx.se"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() { printf 'verify: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'verify: ok   %s\n' "$*" >&2; }

# hdr <name> <curl args...>: response headers (CR stripped) in ${work}/<name>; prints the status code.
hdr() {
    local name="$1"
    shift
    curl -s "${curl_extra[@]}" -D "${work}/${name}.raw" -o "${work}/${name}.body" -w '%{http_code}' --max-time 20 "$@"
    tr -d '\r' <"${work}/${name}.raw" >"${work}/${name}"
}
has_header() { grep -qi "^$2:" "${work}/$1"; }
header_value() { grep -i "^$2:" "${work}/$1" | head -n 1 | cut -d: -f2- | sed 's/^ *//'; }
header_count() { grep -ci "^$2:" "${work}/$1" || true; }
no_cors() { ! grep -qi '^access-control-' "${work}/$1"; }

printf 'verify: %s\n' "${url}" >&2

# ---- through the public chain ----
code="$(hdr openapi "${url}/openapi/v1.json")"
[[ "${code}" == "404" ]] || fail "GET /openapi/v1.json: expected 404, got ${code}"
pass "OpenAPI document is absent (404)"

code="$(hdr health "${url}/health")"
[[ "${code}" == "200" ]] || fail "GET /health: expected 200, got ${code}"
pass "GET /health 200"

[[ "$(header_value health strict-transport-security)" == *max-age=* ]] || fail "no Strict-Transport-Security header"
[[ "$(header_value health x-content-type-options)" == "nosniff" ]] || fail "X-Content-Type-Options is not nosniff"
has_header health x-powered-by && fail "X-Powered-By is sent"
if [[ "$(header_value health server)" =~ [0-9]+\.[0-9]+ ]]; then
    fail "the Server header discloses a version: $(header_value health server)"
fi
pass "HSTS and nosniff at the edge, no version in Server, no X-Powered-By"

code="$(hdr status -H "Origin: ${status_page}" "${url}/health")"
[[ "$(header_value status access-control-allow-origin)" == "${status_page}" ]] || fail "GET /health from ${status_page} is not readable"
[[ "$(header_count status access-control-allow-origin)" == "1" ]] || fail "more than one Access-Control-Allow-Origin header (proxy adds its own?)"
has_header status access-control-allow-credentials && fail "credentials are allowed for ${status_page}"
code="$(hdr status2 -X OPTIONS "${url}/v1/auth/login" -H "Origin: ${status_page}" -H 'Access-Control-Request-Method: POST')"
no_cors status2 || fail "a login preflight from ${status_page} got Access-Control-* headers"
pass "${status_page} reads /health and nothing else"

code="$(hdr put -X OPTIONS "${url}/v1/sync/envelope" -H "Origin: ${vault}" \
    -H 'Access-Control-Request-Method: PUT' -H 'Access-Control-Request-Headers: content-type,authorization')"
[[ "${code}" == "204" ]] || fail "the envelope PUT preflight from ${vault}: expected 204, got ${code}"
[[ "$(header_value put access-control-allow-origin)" == "${vault}" ]] || fail "the envelope preflight does not allow ${vault}"
[[ "$(header_count put access-control-allow-origin)" == "1" ]] || fail "more than one Access-Control-Allow-Origin header on the preflight"
header_value put access-control-allow-methods | grep -q PUT || fail "the envelope preflight does not list PUT"
has_header put access-control-allow-credentials && fail "the envelope preflight allows credentials"
pass "${vault}: envelope PUT preflight passes (204, PUT, no credentials, one Allow-Origin)"

code="$(hdr login -X OPTIONS "${url}/v1/auth/login" -H "Origin: ${vault}" \
    -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type,authorization')"
[[ "${code}" == "204" && "$(header_value login access-control-allow-origin)" == "${vault}" ]] \
    || fail "the login preflight from ${vault} is not answered (status ${code})"
pass "${vault}: login preflight passes"

for origin in "https://attacker.example" "http://vault.bitosx.se"; do
    hdr other -H "Origin: ${origin}" "${url}/health" >/dev/null
    no_cors other || fail "GET /health from ${origin} got Access-Control-* headers"
done
pass "any other origin gets no Access-Control-* headers"

# A declared body above the envelope limit (22,370,648 bytes) is refused at the edge before it is read: curl sends
# "Expect: 100-continue" for a body this size and stops at the 413, so the file is not actually uploaded.
head -c 23000000 /dev/zero >"${work}/big.bin"
code="$(curl -s "${curl_extra[@]}" -o /dev/null -w '%{http_code}' --max-time 60 -X PUT "${url}/v1/sync/envelope" \
    -H 'Content-Type: application/json' --data-binary "@${work}/big.bin")"
[[ "${code}" == "413" ]] || fail "a 23 MB envelope upload: expected 413, got ${code}"
pass "oversized body refused (413)"

if [[ "${local_checks}" == "0" ]]; then
    printf 'verify: PASS (public chain; run with --local on the host for the host checks)\n' >&2
    exit 0
fi

# ---- on the host ----
port="${BITOSX_VERIFY_PORT:-5080}"
service="${BITOSX_VERIFY_SERVICE:-bitosx-api}"
env_file="${BITOSX_VERIFY_ENV_FILE:-/etc/bitosx-api/bitosx-api.env}"
migrator_file="${BITOSX_VERIFY_MIGRATOR_FILE:-/etc/bitosx-api/migrator.env}"

listeners="$(ss -Hltn "( sport = :${port} )" | awk '{print $4}')"
[[ -n "${listeners}" ]] || fail "nothing listens on port ${port}"
while read -r address; do
    [[ "${address}" == "127.0.0.1:${port}" || "${address}" == "[::1]:${port}" ]] || fail "Kestrel listens on ${address} (not loopback)"
done <<<"${listeners}"
pass "Kestrel listens on loopback only ($(tr '\n' ' ' <<<"${listeners}"))"

systemctl is-active --quiet "${service}" || fail "${service} is not active"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${port}/health")"
[[ "${code}" == "200" ]] || fail "http://127.0.0.1:${port}/health: expected 200, got ${code}"
pass "${service} is active and healthy on loopback"

apachectl -t >/dev/null 2>&1 || fail "apachectl -t fails"
proxy_targets="$(grep -RhiE '^\s*ProxyPass\s' /etc/apache2/sites-enabled/ | awk '{print $3}' | sort -u)"
[[ -n "${proxy_targets}" ]] || fail "no ProxyPass in /etc/apache2/sites-enabled"
while read -r target; do
    [[ "${target}" == "http://127.0.0.1:${port}/" ]] || fail "ProxyPass target ${target} is not http://127.0.0.1:${port}/"
done <<<"${proxy_targets}"
grep -RqiE '^\s*Header\s+(always\s+)?(set|add|append|merge)\s+Access-Control-' /etc/apache2/sites-enabled/ /etc/apache2/conf-enabled/ \
    && fail "Apache adds an Access-Control-* header"
pass "apachectl -t passes; ProxyPass -> http://127.0.0.1:${port}/; Apache adds no Access-Control-* header"

[[ "$(stat -c '%U:%G %a' "${env_file}")" == "root:${service} 640" ]] || fail "${env_file} must be root:${service} 0640"
grep -q 'BitosxMigrator' "${env_file}" && fail "${env_file} contains the migrator secret"
[[ "$(stat -c '%U %a' "${migrator_file}")" == "root 600" ]] || fail "${migrator_file} must be root-owned 0600"
pass "secret files: service env root:${service} 0640 without the migrator secret; migrator file root 0600"

packet="$(mariadb -N -B -e 'SELECT @@GLOBAL.max_allowed_packet')"
((packet >= 33554432)) || fail "MariaDB max_allowed_packet is ${packet} (< 32M)"
binlog="$(mariadb -N -B -e 'SELECT @@GLOBAL.log_bin, @@GLOBAL.binlog_format')"
if [[ "${binlog}" == 1* && "${binlog}" == *STATEMENT ]]; then
    fail "binary logging uses binlog_format=STATEMENT"
fi
pass "MariaDB max_allowed_packet ${packet}; binlog: ${binlog//$'\t'/ }"

printf 'verify: PASS (public chain and host)\n' >&2
