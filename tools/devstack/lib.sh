# shellcheck shell=bash
# Shared helpers for the BitosX local live stack (tools/devstack). Sourced by up.sh, down.sh, mail.sh,
# smoke.sh and selftest.sh; never run directly. Callers set `set -euo pipefail` themselves.
# shellcheck disable=SC2034 # the paths below are used by the scripts that source this file

DEVSTACK_SCRIPT="$(basename "$0")"
DEVSTACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DEVSTACK_DIR}/../.." && pwd)"
STATE_DIR="${DEVSTACK_DIR}/.state"
BUILD_DIR="${STATE_DIR}/build"
LOG_DIR="${STATE_DIR}/logs"

# The client-facing environment file (exactly three variables) and the internal state files.
CLIENT_ENV_FILE="${STATE_DIR}/env"
STACK_STATE_FILE="${STATE_DIR}/stack.state"   # container name, DB endpoint, API pid file (no secrets)
API_ENV_FILE="${STATE_DIR}/api.env"           # the functional API's environment (0600)
DEVMAIL_ENV_FILE="${STATE_DIR}/devmail.env"   # the outbox reader's environment (0600)
API_PID_FILE="${STATE_DIR}/api.pid"
API_LOG_FILE="${LOG_DIR}/api.log"

devstack_log() { printf '%s: %s\n' "${DEVSTACK_SCRIPT:-devstack}" "$*" >&2; }
devstack_die() { printf '%s: error: %s\n' "${DEVSTACK_SCRIPT:-devstack}" "$*" >&2; exit 1; }

devstack_need() {
    local cmd
    for cmd in "$@"; do
        command -v "${cmd}" >/dev/null 2>&1 || devstack_die "'${cmd}' is required but was not found on PATH"
    done
}

# 32 random bytes, canonical Base64 (the format every BitosX key setting expects).
devstack_random_key() { openssl rand -base64 32; }

# A database password that needs no quoting in a connection string or SQL literal.
devstack_random_password() { openssl rand -hex 24; }

devstack_ensure_state_dir() {
    umask 077
    mkdir -p "${STATE_DIR}" "${BUILD_DIR}" "${LOG_DIR}"
    chmod 700 "${STATE_DIR}"
}

# Writes stdin to a file created with mode 0600 (never readable by others, even briefly).
devstack_write_private() {
    local target="$1" tmp
    tmp="$(mktemp "${target}.XXXXXX")"
    chmod 600 "${tmp}"
    cat >"${tmp}"
    mv -f "${tmp}" "${target}"
}

# True when something accepts TCP connections on 127.0.0.1:<port>.
devstack_port_in_use() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# devstack_is_pid_alive <pid>: the process exists (signal 0 is permitted).
devstack_is_pid_alive() { [[ -n "$1" ]] && kill -0 "$1" 2>/dev/null; }

# devstack_clean_env_argv <env-file> <cwd> <pid-file|-> <command...>: sets DEVSTACK_ARGV to a command line that runs
# <command> in <cwd> with ONLY a minimal base environment (PATH, HOME, DOTNET_ROOT) plus the variables in <env-file>.
# The file is read by the inner shell, so no secret ever appears on a command line. With a pid file, the inner shell
# records its own pid and then execs the command in place, so the pid file names the command's process.
devstack_clean_env_argv() {
    local env_file="$1" cwd="$2" pid_file="$3"
    shift 3
    local -a base_env=("PATH=${PATH}" "HOME=${HOME:-/tmp}" "DOTNET_NOLOGO=1" "DOTNET_CLI_TELEMETRY_OPTOUT=1")
    if [[ -n "${DOTNET_ROOT:-}" ]]; then
        base_env+=("DOTNET_ROOT=${DOTNET_ROOT}")
    fi
    # shellcheck disable=SC2016 # the inner shell expands its own positional parameters
    DEVSTACK_ARGV=(env -i "${base_env[@]}" bash -c '
        set -euo pipefail
        set -a
        . "$1"
        set +a
        if [[ "$3" != "-" ]]; then echo "$$" >"$3"; fi
        cd "$2"
        shift 3
        exec "$@"
    ' devstack-run "${env_file}" "${cwd}" "${pid_file}" "$@")
}

# devstack_start_api <pid-file> <log-file> <env-file>: starts the published API in the background (in its own session
# when setsid exists, so a terminal hang-up does not reach it) and waits until its pid is recorded.
devstack_start_api() {
    local pid_file="$1" log_file="$2" env_file="$3"
    local -a launcher=()
    if command -v setsid >/dev/null 2>&1; then
        launcher=(setsid)
    fi
    rm -f "${pid_file}"
    : >"${log_file}"
    devstack_clean_env_argv "${env_file}" "${BUILD_DIR}/api" "${pid_file}" dotnet BitosX.Api.dll
    "${launcher[@]}" "${DEVSTACK_ARGV[@]}" >>"${log_file}" 2>&1 </dev/null &
    for _ in $(seq 1 100); do
        if [[ -s "${pid_file}" ]]; then
            return 0
        fi
        sleep 0.1
    done
    devstack_die "the API process did not start (see ${log_file})"
}

# devstack_stop_pid_file <pid-file>: TERM, wait up to 20 s, then KILL. Only signals a process whose command line
# names BitosX.Api.dll (never an unrelated process that reused the pid). Removes the pid file.
devstack_stop_pid_file() {
    local pid_file="$1" pid
    [[ -f "${pid_file}" ]] || return 0
    pid="$(cat "${pid_file}" 2>/dev/null || true)"
    if devstack_is_pid_alive "${pid}"; then
        if [[ -r "/proc/${pid}/cmdline" ]] && ! tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -q 'BitosX.Api.dll'; then
            devstack_log "pid ${pid} is no longer the API; not signalling it"
        else
            kill -TERM "${pid}" 2>/dev/null || true
            for _ in $(seq 1 200); do
                devstack_is_pid_alive "${pid}" || break
                sleep 0.1
            done
            if devstack_is_pid_alive "${pid}"; then
                devstack_log "API pid ${pid} did not stop within 20 s; killing it"
                kill -KILL "${pid}" 2>/dev/null || true
            fi
        fi
    fi
    rm -f "${pid_file}"
}

# devstack_wait_health <base-url> <timeout-seconds> <pid-file> <log-file>: waits for GET /health = 200.
devstack_wait_health() {
    local url="$1" timeout="$2" pid_file="$3" log_file="$4" deadline status pid
    deadline=$((SECONDS + timeout))
    while ((SECONDS < deadline)); do
        pid="$(cat "${pid_file}" 2>/dev/null || true)"
        if ! devstack_is_pid_alive "${pid}"; then
            devstack_log "the API exited during startup; last log lines:"
            tail -n 40 "${log_file}" >&2 || true
            return 1
        fi
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${url}/health" || true)"
        [[ "${status}" == "200" ]] && return 0
        sleep 0.5
    done
    devstack_log "GET ${url}/health did not answer 200 within ${timeout} s; last log lines:"
    tail -n 40 "${log_file}" >&2 || true
    return 1
}

# ---- MariaDB: a throwaway container, or an existing server (BITOSX_DEVSTACK_EXTERNAL_DB=1) ----
# devstack_db_init <container-name|""> <port>: reads the BITOSX_DEVSTACK_* database settings and sets DB_* globals.
# An empty container name with BITOSX_DEVSTACK_EXTERNAL_DB=0 is an error.
devstack_db_init() {
    DB_CONTAINER="$1"
    DB_PORT="$2"
    DB_IMAGE="${BITOSX_DEVSTACK_MARIADB_IMAGE:-mariadb:11.8}"
    DB_EXTERNAL="${BITOSX_DEVSTACK_EXTERNAL_DB:-0}"
    DB_HOST="127.0.0.1"
    DB_ROOT_USER="root"
    DB_SQL_DEFAULTS=""
    if ! [[ "${DB_PORT}" =~ ^[1-9][0-9]{0,4}$ ]] || ((DB_PORT > 65535)); then
        devstack_die "invalid database port '${DB_PORT}'"
    fi
    case "${DB_EXTERNAL}" in
        0)
            devstack_need docker
            DB_ROOT_PASSWORD="$(devstack_random_password)"
            ;;
        1)
            DB_CONTAINER=""
            DB_HOST="${BITOSX_DEVSTACK_DB_HOST:-127.0.0.1}"
            DB_ROOT_USER="${BITOSX_DEVSTACK_DB_ROOT_USER:-root}"
            DB_ROOT_PASSWORD="${BITOSX_DEVSTACK_DB_ROOT_PASSWORD:-}"
            [[ -n "${DB_ROOT_PASSWORD}" ]] || devstack_die "BITOSX_DEVSTACK_EXTERNAL_DB=1 needs BITOSX_DEVSTACK_DB_ROOT_PASSWORD"
            ;;
        *) devstack_die "BITOSX_DEVSTACK_EXTERNAL_DB must be 0 or 1" ;;
    esac
}

# devstack_db_cleanup: removes the temporary client defaults file (call from the caller's EXIT trap).
devstack_db_cleanup() {
    if [[ -n "${DB_SQL_DEFAULTS:-}" ]]; then
        rm -f "${DB_SQL_DEFAULTS}"
    fi
}

# devstack_db_sql: runs SQL from stdin as the root account; prints result rows (tab-separated, no header). The
# password never appears on a command line: an environment variable for docker, a 0600 defaults file otherwise.
devstack_db_sql() {
    if [[ "${DB_EXTERNAL}" == "0" ]]; then
        MYSQL_PWD="${DB_ROOT_PASSWORD}" docker exec -i -e MYSQL_PWD "${DB_CONTAINER}" \
            mariadb --protocol=TCP -h127.0.0.1 -P3306 -u"${DB_ROOT_USER}" --skip-ssl-verify-server-cert --batch --skip-column-names
        return
    fi
    local client="${BITOSX_DEVSTACK_DB_CLIENT:-}"
    if [[ -z "${client}" ]]; then
        if command -v mariadb >/dev/null 2>&1; then
            client=mariadb
        elif command -v mysql >/dev/null 2>&1; then
            client=mysql
        else
            client=docker
        fi
    fi
    if [[ "${client}" == "docker" ]]; then
        MYSQL_PWD="${DB_ROOT_PASSWORD}" docker run --rm -i --network host -e MYSQL_PWD "${DB_IMAGE}" \
            mariadb --protocol=TCP -h"${DB_HOST}" -P"${DB_PORT}" -u"${DB_ROOT_USER}" --skip-ssl-verify-server-cert --batch --skip-column-names
        return
    fi
    if [[ -z "${DB_SQL_DEFAULTS}" ]]; then
        DB_SQL_DEFAULTS="$(mktemp "${STATE_DIR}/sql-defaults.XXXXXX")"
        chmod 600 "${DB_SQL_DEFAULTS}"
        printf '[client]\nuser=%s\npassword=%s\nhost=%s\nport=%s\nprotocol=TCP\n' \
            "${DB_ROOT_USER}" "${DB_ROOT_PASSWORD}" "${DB_HOST}" "${DB_PORT}" >"${DB_SQL_DEFAULTS}"
    fi
    "${client}" --defaults-extra-file="${DB_SQL_DEFAULTS}" --batch --skip-column-names
}

# devstack_db_remove_container <name>: removes a container this tooling created (label bitosx.devstack=1) and its data.
devstack_db_remove_container() {
    local name="$1"
    [[ -n "${name}" ]] && command -v docker >/dev/null 2>&1 || return 0
    if [[ "$(docker inspect -f '{{index .Config.Labels "bitosx.devstack"}}' "${name}" 2>/dev/null || true)" == "1" ]]; then
        docker rm -f -v "${name}" >/dev/null
        devstack_log "removed container ${name}"
    fi
}

# devstack_db_start: starts the container (container mode; external mode only logs), waits until the server accepts
# TCP connections (60 s) and ensures max_allowed_packet >= 32M (DEPLOYMENT.md; a 16 MiB envelope in one statement).
devstack_db_start() {
    if [[ "${DB_EXTERNAL}" == "0" ]]; then
        devstack_db_remove_container "${DB_CONTAINER}"
        if devstack_port_in_use "${DB_PORT}"; then
            devstack_die "127.0.0.1:${DB_PORT} is already in use (choose another database port)"
        fi
        devstack_log "starting ${DB_IMAGE} as ${DB_CONTAINER} on 127.0.0.1:${DB_PORT}"
        MARIADB_ROOT_PASSWORD="${DB_ROOT_PASSWORD}" docker run -d --name "${DB_CONTAINER}" --label bitosx.devstack=1 \
            -p "127.0.0.1:${DB_PORT}:3306" -e MARIADB_ROOT_PASSWORD "${DB_IMAGE}" --max-allowed-packet=64M >/dev/null
    else
        devstack_log "using the existing MariaDB server at ${DB_HOST}:${DB_PORT}"
    fi
}

devstack_db_wait() {
    local ready=0 packet
    devstack_log "waiting for MariaDB"
    for _ in $(seq 1 120); do
        if [[ -n "${DB_CONTAINER}" ]] \
            && [[ "$(docker inspect -f '{{.State.Running}}' "${DB_CONTAINER}" 2>/dev/null || echo false)" != "true" ]]; then
            docker logs --tail 40 "${DB_CONTAINER}" >&2 || true
            devstack_die "the MariaDB container stopped during startup"
        fi
        if echo 'SELECT 1;' | devstack_db_sql >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.5
    done
    [[ "${ready}" == "1" ]] || devstack_die "MariaDB did not accept connections within 60 s"
    devstack_log "MariaDB $(echo 'SELECT VERSION();' | devstack_db_sql) is up"

    packet="$(echo 'SELECT @@GLOBAL.max_allowed_packet;' | devstack_db_sql)"
    if ((packet < 33554432)); then
        echo 'SET GLOBAL max_allowed_packet = 67108864;' | devstack_db_sql
        packet="$(echo 'SELECT @@GLOBAL.max_allowed_packet;' | devstack_db_sql)"
    fi
    ((packet >= 33554432)) || devstack_die "max_allowed_packet is ${packet}; at least 32M is required"
}

# devstack_db_provision <database> <migrator-user> <migrator-password> <runtime-user> <runtime-password>: the two
# accounts of DEPLOYMENT.md — schema management (used only by `migrate`) and the DML-only runtime account. Host '%'
# because the server sees the container network's gateway, not 127.0.0.1 (the server itself is published on
# loopback only); production uses '127.0.0.1'. CREATE + ALTER keeps a re-run against an existing server idempotent.
devstack_db_provision() {
    local db="$1" migrator="$2" migrator_pw="$3" runtime="$4" runtime_pw="$5"
    devstack_log "creating database '${db}' and the accounts '${migrator}' (schema) and '${runtime}' (DML only)"
    devstack_db_sql <<SQL
CREATE DATABASE IF NOT EXISTS \`${db}\` CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS '${migrator}'@'%' IDENTIFIED BY '${migrator_pw}';
ALTER USER '${migrator}'@'%' IDENTIFIED BY '${migrator_pw}';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON \`${db}\`.* TO '${migrator}'@'%';
CREATE USER IF NOT EXISTS '${runtime}'@'%' IDENTIFIED BY '${runtime_pw}';
ALTER USER '${runtime}'@'%' IDENTIFIED BY '${runtime_pw}';
GRANT SELECT, INSERT, UPDATE, DELETE ON \`${db}\`.* TO '${runtime}'@'%';
SQL
}

# devstack_connection_string <database> <user> <password>
devstack_connection_string() {
    printf 'Server=%s;Port=%s;Database=%s;User ID=%s;Password=%s' "${DB_HOST}" "${DB_PORT}" "$1" "$2" "$3"
}
