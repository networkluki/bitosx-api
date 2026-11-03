#!/usr/bin/env bash
# Brings up the BitosX local live stack: MariaDB, the published API (migrated with the real `migrate` command) on
# loopback, and writes tools/devstack/.state/env for the client live suites. Re-running replaces the running stack
# with a fresh one (new database, new secrets). See tools/devstack/README.md.
#
# Settings (environment, all optional):
#   BITOSX_DEVSTACK_MARIADB_IMAGE   MariaDB image for the container            (default mariadb:11.8)
#   BITOSX_DEVSTACK_DB_PORT         MariaDB port on 127.0.0.1                  (default 3407)
#   BITOSX_DEVSTACK_API_PORT        API port on 127.0.0.1                      (default 5080)
#   BITOSX_DEVSTACK_WEB_ORIGIN      web vault origin (CORS, email links, WebAuthn) (default http://localhost:8788;
#                                   passkeys need the host localhost — an IP address is not a valid WebAuthn RP ID)
#   BITOSX_DEVSTACK_HEALTH_TIMEOUT  seconds to wait for GET /health = 200       (default 60)
#   BITOSX_DEVSTACK_SKIP_BUILD=1    reuse the last published build in .state/build (fast re-run)
#   BITOSX_DEVSTACK_EXTERNAL_DB=1   use an existing server instead of a container (e.g. a CI service container):
#     BITOSX_DEVSTACK_DB_HOST           (default 127.0.0.1)
#     BITOSX_DEVSTACK_DB_ROOT_USER      (default root)
#     BITOSX_DEVSTACK_DB_ROOT_PASSWORD  (required)
set -euo pipefail
# shellcheck source-path=SCRIPTDIR

# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

db_port="${BITOSX_DEVSTACK_DB_PORT:-3407}"
api_port="${BITOSX_DEVSTACK_API_PORT:-5080}"
web_origin="${BITOSX_DEVSTACK_WEB_ORIGIN:-http://localhost:8788}"
health_timeout="${BITOSX_DEVSTACK_HEALTH_TIMEOUT:-60}"
skip_build="${BITOSX_DEVSTACK_SKIP_BUILD:-0}"
db_name="bitosx"
migrator_user="bitosx_migrator"
runtime_user="bitosx_app"

# ---- validate settings (fail before touching anything) ----
if ! [[ "${api_port}" =~ ^[1-9][0-9]{0,4}$ ]] || ((api_port > 65535)); then
    devstack_die "invalid BITOSX_DEVSTACK_API_PORT '${api_port}'"
fi
[[ "${db_port}" != "${api_port}" ]] || devstack_die "the database and API ports must differ"
[[ "${health_timeout}" =~ ^[0-9]+$ ]] || devstack_die "BITOSX_DEVSTACK_HEALTH_TIMEOUT must be a number of seconds"
[[ "${web_origin}" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):[0-9]{1,5}$ ]] \
    || devstack_die "BITOSX_DEVSTACK_WEB_ORIGIN must be a loopback http origin such as http://localhost:8788 (got '${web_origin}')"
[[ "${DEVSTACK_DIR}" =~ ^[A-Za-z0-9_./-]+$ ]] \
    || devstack_die "the repository path '${DEVSTACK_DIR}' contains characters the env file cannot carry unquoted"
devstack_need dotnet curl openssl
devstack_db_init "bitosx-devstack-db-${db_port}" "${db_port}"

api_url="http://127.0.0.1:${api_port}"

# ---- replace whatever is up (idempotent re-run; down.sh is a no-op when nothing is) ----
if [[ -e "${STACK_STATE_FILE}" || -e "${API_PID_FILE}" || -e "${CLIENT_ENV_FILE}" ]]; then
    devstack_log "a stack is already up; replacing it"
fi
"${DEVSTACK_DIR}/down.sh"
devstack_ensure_state_dir

succeeded=0
build_pid=""
cleanup() {
    local status=$?
    devstack_db_cleanup
    rm -f "${STATE_DIR}/migrate.env"
    if [[ -n "${build_pid}" ]] && devstack_is_pid_alive "${build_pid}"; then
        kill "${build_pid}" 2>/dev/null || true
    fi
    if [[ "${succeeded}" != "1" ]]; then
        devstack_log "bring-up failed (exit ${status}); cleaning up (logs stay in ${LOG_DIR})"
        "${DEVSTACK_DIR}/down.sh" >/dev/null 2>&1 || true
    fi
    exit "${status}"
}
trap cleanup EXIT

if devstack_port_in_use "${api_port}"; then
    devstack_die "127.0.0.1:${api_port} is already in use (set BITOSX_DEVSTACK_API_PORT to another port)"
fi

# ---- secrets: all fresh, written only under .state (0600) ----
migrator_password="$(devstack_random_password)"
runtime_password="$(devstack_random_password)"
jwt_key="$(devstack_random_key)"
jwt_kid="devstack-$(openssl rand -hex 4)"
email_pepper="$(devstack_random_key)"
outbox_key="$(devstack_random_key)"
totp_key="$(devstack_random_key)"

# ---- build (in the background while the database starts) ----
build_log="${LOG_DIR}/build.log"
if [[ "${skip_build}" == "1" && -f "${BUILD_DIR}/api/BitosX.Api.dll" && -f "${BUILD_DIR}/devmail/BitosX.DevMail.dll" \
    && -f "${BUILD_DIR}/devauth/BitosX.DevAuthenticator.dll" ]]; then
    devstack_log "reusing the last build (BITOSX_DEVSTACK_SKIP_BUILD=1)"
else
    devstack_log "publishing the API, the outbox reader and the dev authenticator (Release)"
    (
        dotnet publish "${REPO_ROOT}/src/BitosX.Api/BitosX.Api.csproj" -c Release -o "${BUILD_DIR}/api" --nologo
        dotnet publish "${REPO_ROOT}/tools/BitosX.DevMail/BitosX.DevMail.csproj" -c Release -o "${BUILD_DIR}/devmail" --nologo
        dotnet publish "${REPO_ROOT}/tools/BitosX.DevAuthenticator/BitosX.DevAuthenticator.csproj" -c Release -o "${BUILD_DIR}/devauth" --nologo
    ) >"${build_log}" 2>&1 &
    build_pid=$!
fi

# ---- database ----
devstack_db_start
# Record what down.sh needs before anything else can fail (no secrets in this file).
devstack_write_private "${STACK_STATE_FILE}" <<STATE
DEVSTACK_DB_MODE=$([[ "${DB_EXTERNAL}" == "1" ]] && echo external || echo container)
DEVSTACK_DB_CONTAINER=${DB_CONTAINER}
DEVSTACK_DB_ENDPOINT=${DB_HOST}:${DB_PORT}
DEVSTACK_API_URL=${api_url}
STATE
devstack_db_wait
devstack_db_provision "${db_name}" "${migrator_user}" "${migrator_password}" "${runtime_user}" "${runtime_password}"
migrator_cs="$(devstack_connection_string "${db_name}" "${migrator_user}" "${migrator_password}")"
runtime_cs="$(devstack_connection_string "${db_name}" "${runtime_user}" "${runtime_password}")"

# ---- wait for the build ----
if [[ -n "${build_pid}" ]]; then
    if ! wait "${build_pid}"; then
        build_pid=""
        tail -n 40 "${build_log}" >&2 || true
        devstack_die "dotnet publish failed (full log: ${build_log})"
    fi
    build_pid=""
fi

# ---- migrate: the real deploy step, with the migrator secret only in this process's environment ----
devstack_log "applying migrations (dotnet BitosX.Api.dll migrate)"
devstack_write_private "${STATE_DIR}/migrate.env" <<ENV
$(printf 'ASPNETCORE_ENVIRONMENT=%q\n' Testing)
$(printf 'ConnectionStrings__BitosxMigrator=%q\n' "${migrator_cs}")
ENV
devstack_clean_env_argv "${STATE_DIR}/migrate.env" "${BUILD_DIR}/api" - dotnet BitosX.Api.dll migrate
if ! "${DEVSTACK_ARGV[@]}" >"${LOG_DIR}/migrate.log" 2>&1; then
    cat "${LOG_DIR}/migrate.log" >&2
    devstack_die "migrate failed"
fi
rm -f "${STATE_DIR}/migrate.env"
sed 's/^/  /' "${LOG_DIR}/migrate.log" >&2

# ---- passkeys: the relying party is the web origin's host, which WebAuthn requires to be a domain name ----
# localhost qualifies (Testing allows RP ID localhost with http://localhost:<port>); 127.0.0.1 and [::1] do not, so with
# such an origin the shipped Security:WebAuthn section (vault.bitosx.se) is blanked and passkeys are off (404).
web_host="${web_origin#http://}"
web_host="${web_host%:*}"
if [[ "${web_host}" == "localhost" ]]; then
    webauthn_rp_id="localhost"
    webauthn_rp_name="BitosX"
    webauthn_origin="${web_origin}"
else
    devstack_log "passkeys are off: ${web_origin} is an IP address, not a valid WebAuthn RP ID (use http://localhost:<port>)"
    webauthn_rp_id=""
    webauthn_rp_name=""
    webauthn_origin=""
fi

# ---- the functional API (Testing: loopback http origin allowed, hardening off, mail held in the outbox) ----
devstack_write_private "${API_ENV_FILE}" <<ENV
$(printf '%s=%q\n' \
    ASPNETCORE_ENVIRONMENT Testing \
    Kestrel__Endpoints__Http__Url "${api_url}" \
    ConnectionStrings__Bitosx "${runtime_cs}" \
    Security__JwtSigningKey "${jwt_key}" \
    Security__Jwt__KeyId "${jwt_kid}" \
    Security__EmailVerificationPepper "${email_pepper}" \
    Security__EmailOutboxKey "${outbox_key}" \
    Security__TotpKey "${totp_key}" \
    Security__Cors__AllowedOrigins "${web_origin}" \
    Security__WebAuthn__RelyingPartyId "${webauthn_rp_id}" \
    Security__WebAuthn__RelyingPartyName "${webauthn_rp_name}" \
    Security__WebAuthn__Origins__0 "${webauthn_origin}" \
    Security__PublicExposureHardening__Enabled false \
    Email__PublicBaseUrl "${web_origin}" \
    Email__HoldInOutbox true)
ENV

devstack_write_private "${DEVMAIL_ENV_FILE}" <<ENV
$(printf '%s=%q\n' \
    ConnectionStrings__Bitosx "${runtime_cs}" \
    Security__EmailOutboxKey "${outbox_key}")
ENV

devstack_log "starting the API on ${api_url} (ASPNETCORE_ENVIRONMENT=Testing)"
devstack_start_api "${API_PID_FILE}" "${API_LOG_FILE}" "${API_ENV_FILE}"
devstack_wait_health "${api_url}" "${health_timeout}" "${API_PID_FILE}" "${API_LOG_FILE}" \
    || devstack_die "the API did not become healthy"

# ---- the client contract: exactly these three variables ----
devstack_write_private "${CLIENT_ENV_FILE}" <<ENV
BITOSX_LIVE_API_URL=${api_url}
BITOSX_LIVE_WEB_ORIGIN=${web_origin}
BITOSX_LIVE_MAIL_CMD=${DEVSTACK_DIR}/mail.sh
ENV

succeeded=1
devstack_log "stack is up; environment written to ${CLIENT_ENV_FILE}:"
cat "${CLIENT_ENV_FILE}"
