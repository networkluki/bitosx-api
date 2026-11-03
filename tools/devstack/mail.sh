#!/usr/bin/env bash
# mail.sh latest <verify|reset> <email>
#
# Prints on stdout ONE line: the token carried by the latest pending outbox message of that kind for that address
# on the local live stack (exactly the value after "#token=" in the emailed link; the outbox stores the token, not
# the link). Exit 0 when found; exit 1 with a message on stderr when there is none. Errors exit 2.
#
# Reads the stack's database and outbox key from tools/devstack/.state (written by up.sh) and decrypts with the
# Infrastructure's own protector (tools/BitosX.DevMail). Refuses to run with ASPNETCORE_ENVIRONMENT or
# DOTNET_ENVIRONMENT set to anything other than Development or Testing.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR

# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

if [[ $# -ne 3 || "$1" != "latest" || ( "$2" != "verify" && "$2" != "reset" ) ]]; then
    echo "usage: mail.sh latest <verify|reset> <email>" >&2
    exit 2
fi

# An explicit Production (or any other) environment is refused here and again by the tool itself.
environment="${ASPNETCORE_ENVIRONMENT:-${DOTNET_ENVIRONMENT:-Testing}}"
case "${environment}" in
    Development | Testing) ;;
    *)
        echo "mail.sh: refused: runs only in Development or Testing (ASPNETCORE_ENVIRONMENT/DOTNET_ENVIRONMENT is '${environment}')" >&2
        exit 2
        ;;
esac

if [[ ! -f "${DEVMAIL_ENV_FILE}" || ! -f "${BUILD_DIR}/devmail/BitosX.DevMail.dll" ]]; then
    echo "mail.sh: the live stack is not up (run tools/devstack/up.sh)" >&2
    exit 2
fi

# The env file holds the runtime connection string and the outbox key; the tool reads them from its environment.
printf '%s=%q\n' ASPNETCORE_ENVIRONMENT "${environment}" >"${STATE_DIR}/devmail-run.env.$$"
chmod 600 "${STATE_DIR}/devmail-run.env.$$"
trap 'rm -f "${STATE_DIR}/devmail-run.env.$$"' EXIT
cat "${DEVMAIL_ENV_FILE}" >>"${STATE_DIR}/devmail-run.env.$$"

devstack_clean_env_argv "${STATE_DIR}/devmail-run.env.$$" "${BUILD_DIR}/devmail" - dotnet BitosX.DevMail.dll latest "$2" "$3"
status=0
"${DEVSTACK_ARGV[@]}" || status=$?
exit "${status}"
