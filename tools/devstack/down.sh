#!/usr/bin/env bash
# Stops the BitosX local live stack started by up.sh: the API (and a smoke.sh API left behind), and removes the
# MariaDB container with its data. Idempotent: running it with nothing up is a no-op that exits 0. Logs stay in
# tools/devstack/.state/logs and the build output in .state/build (for a fast re-run); every secret file is removed.
# An external database (BITOSX_DEVSTACK_EXTERNAL_DB=1) is left as it is.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR

# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

DEVSTACK_DB_MODE=""
DEVSTACK_DB_CONTAINER=""
if [[ -f "${STACK_STATE_FILE}" ]]; then
    # Written by up.sh (no secrets): DEVSTACK_DB_MODE, DEVSTACK_DB_CONTAINER, DEVSTACK_DB_ENDPOINT, DEVSTACK_API_URL.
    # shellcheck disable=SC1090
    . "${STACK_STATE_FILE}"
fi

devstack_stop_pid_file "${STATE_DIR}/smoke-api.pid"
devstack_stop_pid_file "${API_PID_FILE}"

# Without a state file (a crashed up.sh, a deleted .state), fall back to the container name up.sh would use.
if [[ -z "${DEVSTACK_DB_MODE}" && -z "${DEVSTACK_DB_CONTAINER}" ]]; then
    DEVSTACK_DB_CONTAINER="bitosx-devstack-db-${BITOSX_DEVSTACK_DB_PORT:-3407}"
fi

# Only a container this tooling created (label bitosx.devstack=1) is ever removed.
devstack_db_remove_container "${DEVSTACK_DB_CONTAINER}"

rm -f "${CLIENT_ENV_FILE}" "${STACK_STATE_FILE}" "${API_ENV_FILE}" "${DEVMAIL_ENV_FILE}" \
    "${STATE_DIR}/smoke-api.env" "${STATE_DIR}/migrate.env" "${STATE_DIR}"/sql-defaults.*
devstack_log "stack is down"
