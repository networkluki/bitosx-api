#!/usr/bin/env bash
# test-db.sh up [--github-env] | down
#
# A MariaDB for the API's own test suites (Infrastructure and Api tests): database `bitosx_test`, a schema account
# (ConnectionStrings:BitosxTest — the tests apply the migrations with it) and a DML-only runtime account
# (ConnectionStrings:BitosxTestRuntime — the privilege tests prove it cannot run DDL). Same grants as production.
#
#   up    starts a throwaway container (BITOSX_DEVSTACK_MARIADB_IMAGE, default mariadb:11.8, on 127.0.0.1:
#         ${BITOSX_DEVSTACK_TEST_DB_PORT:-3408}) or provisions an existing server (BITOSX_DEVSTACK_EXTERNAL_DB=1, same
#         variables as up.sh), then writes tools/devstack/.state/test-db.env (0600) for
#             set -a; . tools/devstack/.state/test-db.env; set +a
#         With --github-env (GitHub Actions) the two variables are also appended to $GITHUB_ENV, passwords masked.
#   down  removes the container (idempotent).
#
# The test suites reset their tables, so never point them at a database that holds anything you need.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR

# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

usage() { echo "usage: test-db.sh up [--github-env] | down" >&2; exit 2; }
[[ $# -ge 1 ]] || usage

port="${BITOSX_DEVSTACK_TEST_DB_PORT:-3408}"
[[ "${BITOSX_DEVSTACK_EXTERNAL_DB:-0}" == "1" ]] && port="${BITOSX_DEVSTACK_DB_PORT:-3408}"
container="bitosx-devstack-testdb-${port}"
env_file="${STATE_DIR}/test-db.env"

case "$1" in
    down)
        [[ $# -eq 1 ]] || usage
        devstack_db_remove_container "${container}"
        rm -f "${env_file}"
        devstack_log "test database is down"
        exit 0
        ;;
    up)
        github_env=0
        if [[ $# -eq 2 && "$2" == "--github-env" ]]; then
            github_env=1
            [[ -n "${GITHUB_ENV:-}" ]] || devstack_die "--github-env needs GITHUB_ENV (GitHub Actions)"
        elif [[ $# -ne 1 ]]; then
            usage
        fi
        ;;
    *) usage ;;
esac

devstack_need openssl
devstack_db_init "${container}" "${port}"
devstack_ensure_state_dir
trap devstack_db_cleanup EXIT

migrator_password="$(devstack_random_password)"
runtime_password="$(devstack_random_password)"
if [[ "${github_env}" == "1" ]]; then
    echo "::add-mask::${migrator_password}"
    echo "::add-mask::${runtime_password}"
fi

devstack_db_start
devstack_db_wait
devstack_db_provision bitosx_test bitosx_test_migrator "${migrator_password}" bitosx_test_app "${runtime_password}"
test_cs="$(devstack_connection_string bitosx_test bitosx_test_migrator "${migrator_password}")"
runtime_cs="$(devstack_connection_string bitosx_test bitosx_test_app "${runtime_password}")"

printf '%s=%q\n' ConnectionStrings__BitosxTest "${test_cs}" ConnectionStrings__BitosxTestRuntime "${runtime_cs}" \
    | devstack_write_private "${env_file}"
if [[ "${github_env}" == "1" ]]; then
    printf '%s=%s\n' ConnectionStrings__BitosxTest "${test_cs}" ConnectionStrings__BitosxTestRuntime "${runtime_cs}" >>"${GITHUB_ENV}"
fi
devstack_log "test database is up; load it with: set -a; . ${env_file}; set +a"
