#!/usr/bin/env bash
# deploy.sh [--dry-run] <release-archive.tar.gz>
#
# Deploys one BitosX API release on the production host (run as root). The archive is the `dotnet publish` output
# packed at its root (BitosX.Api.dll at the top level):
#
#     dotnet publish src/BitosX.Api -c Release -o out && tar -C out -czf bitosx-api-<version>.tar.gz .
#
# Steps (each one stops the deploy on failure; nothing after it runs):
#   1. checks: the archive (no absolute or .. paths, BitosX.Api.dll at the top), the migrator secret file
#      (root-owned, mode 0600), the tools;
#   2. unpacks it into a new versioned directory /opt/bitosx-api/releases/<UTC time>-<archive sha256 prefix>;
#   3. backs the database up: mariadb-dump --single-transaction, gzip, mode 0600, checked for completeness;
#   4. applies the migrations: `dotnet BitosX.Api.dll migrate` with ConnectionStrings__BitosxMigrator read from the
#      root-only file into that one process's environment (never a command-line argument, never the service's
#      environment);
#   5. switches /opt/bitosx-api/current to the new release atomically (rename of a symlink) and restarts the service;
#   6. waits for GET /health = 200; if it does not come, switches `current` back to the previous release, restarts,
#      and fails. Migrations are forward-only: the database keeps the new schema, so the previous release must work
#      with it (every migration so far only adds) — otherwise restore the backup from step 3;
#   7. keeps the newest N releases (never the current or the previous one).
#
# --dry-run runs every check (and unpacks into a temporary directory to inspect the archive), prints what it would
# do, and changes nothing.
#
# Settings (environment): BITOSX_DEPLOY_ROOT (/opt/bitosx-api), BITOSX_DEPLOY_SERVICE (bitosx-api),
# BITOSX_DEPLOY_MIGRATOR_FILE (/etc/bitosx-api/migrator.env, one line ConnectionStrings__BitosxMigrator=...),
# BITOSX_DEPLOY_BACKUP_DIR (/var/backups/bitosx-api), BITOSX_DEPLOY_DATABASE (bitosx), BITOSX_DEPLOY_KEEP (5),
# BITOSX_DEPLOY_HEALTH_URL (http://127.0.0.1:5080/health), BITOSX_DEPLOY_HEALTH_TIMEOUT (60 s),
# BITOSX_DEPLOY_DUMP_DEFAULTS_FILE (a client option file for mariadb-dump; default: root's unix-socket login),
# DOTNET (/usr/bin/dotnet), SYSTEMCTL (systemctl), MARIADB_DUMP (mariadb-dump).
set -euo pipefail

usage() { echo "usage: deploy.sh [--dry-run] <release-archive.tar.gz>" >&2; exit 2; }

dry_run=0
archive=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) dry_run=1; shift ;;
        -h | --help) usage ;;
        -*) usage ;;
        *) [[ -z "${archive}" ]] || usage; archive="$1"; shift ;;
    esac
done
[[ -n "${archive}" ]] || usage

root="${BITOSX_DEPLOY_ROOT:-/opt/bitosx-api}"
service="${BITOSX_DEPLOY_SERVICE:-bitosx-api}"
migrator_file="${BITOSX_DEPLOY_MIGRATOR_FILE:-/etc/bitosx-api/migrator.env}"
backup_dir="${BITOSX_DEPLOY_BACKUP_DIR:-/var/backups/bitosx-api}"
database="${BITOSX_DEPLOY_DATABASE:-bitosx}"
keep="${BITOSX_DEPLOY_KEEP:-5}"
health_url="${BITOSX_DEPLOY_HEALTH_URL:-http://127.0.0.1:5080/health}"
health_timeout="${BITOSX_DEPLOY_HEALTH_TIMEOUT:-60}"
dump_defaults="${BITOSX_DEPLOY_DUMP_DEFAULTS_FILE:-}"
dotnet_cmd="${DOTNET:-/usr/bin/dotnet}"
systemctl_cmd="${SYSTEMCTL:-systemctl}"
dump_cmd="${MARIADB_DUMP:-mariadb-dump}"

log() { printf 'deploy: %s\n' "$*" >&2; }
die() { printf 'deploy: error: %s\n' "$*" >&2; exit 1; }
plan() { printf 'deploy: [dry-run] would %s\n' "$*" >&2; }

# ---- 1. checks ----
[[ "${keep}" =~ ^[1-9][0-9]*$ ]] || die "BITOSX_DEPLOY_KEEP must be a positive number"
[[ "${health_timeout}" =~ ^[1-9][0-9]*$ ]] || die "BITOSX_DEPLOY_HEALTH_TIMEOUT must be a positive number of seconds"
[[ "${database}" =~ ^[A-Za-z0-9_]+$ ]] || die "BITOSX_DEPLOY_DATABASE must be a plain database name"
for cmd in tar sha256sum gzip curl flock "${systemctl_cmd}" "${dump_cmd}" "${dotnet_cmd}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "'${cmd}' is required but was not found"
done
if [[ "${dry_run}" == "0" && "${EUID}" -ne 0 ]]; then
    die "run as root (or use --dry-run)"
fi

[[ -f "${archive}" && -r "${archive}" ]] || die "release archive '${archive}' is not a readable file"
archive_listing="$(tar -tzf "${archive}")" || die "'${archive}' is not a readable .tar.gz"
while IFS= read -r entry; do
    case "${entry}" in
        /* | ../* | */../* | .. | */..) die "the archive contains an unsafe path '${entry}'" ;;
    esac
done <<<"${archive_listing}"
grep -qxE '(\./)?BitosX\.Api\.dll' <<<"${archive_listing}" || die "the archive has no BitosX.Api.dll at its top level"

# The migrator secret: a root-owned file nobody else can read, holding only ConnectionStrings__BitosxMigrator.
[[ -f "${migrator_file}" ]] || die "the migrator secret file ${migrator_file} does not exist"
read -r migrator_owner migrator_mode < <(stat -c '%u %a' "${migrator_file}")
[[ "${migrator_owner}" == "0" ]] || die "${migrator_file} must be owned by root"
[[ "${migrator_mode}" == "600" || "${migrator_mode}" == "400" ]] || die "${migrator_file} must have mode 0600 (it has ${migrator_mode})"
grep -qE '^ConnectionStrings__BitosxMigrator=.+' "${migrator_file}" \
    || die "${migrator_file} has no ConnectionStrings__BitosxMigrator=... line"

digest="$(sha256sum "${archive}" | cut -c1-12)"
release_id="$(date -u +%Y%m%dT%H%M%SZ)-${digest}"
releases="${root}/releases"
release_dir="${releases}/${release_id}"
current_link="${root}/current"
previous_dir=""
if [[ -L "${current_link}" ]]; then
    previous_dir="$(readlink -f "${current_link}")"
fi

log "release ${release_id} from $(basename "${archive}")"
log "current release: ${previous_dir:-none}"

# ---- dry run: inspect the archive in a scratch directory and print the plan ----
if [[ "${dry_run}" == "1" ]]; then
    scratch="$(mktemp -d)"
    trap 'rm -rf "${scratch}"' EXIT
    tar -xzf "${archive}" -C "${scratch}" --no-same-owner --no-same-permissions
    [[ -f "${scratch}/BitosX.Api.dll" ]] || die "BitosX.Api.dll did not unpack"
    log "archive ok: $(wc -l <<<"${archive_listing}") entries, BitosX.Api.dll present"
    plan "unpack into ${release_dir}"
    plan "back up database '${database}' with ${dump_cmd} --single-transaction into ${backup_dir}/${database}-${release_id}.sql.gz"
    plan "run ${dotnet_cmd} BitosX.Api.dll migrate in ${release_dir} with ConnectionStrings__BitosxMigrator from ${migrator_file}"
    plan "point ${current_link} at releases/${release_id} and run: ${systemctl_cmd} restart ${service}"
    plan "wait up to ${health_timeout} s for ${health_url} = 200, else switch back to ${previous_dir:-<nothing: first release>}"
    mapfile -t would_prune < <(find "${releases}" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -printf '%f\n' 2>/dev/null | sort -r | tail -n "+${keep}")
    for old in "${would_prune[@]}"; do
        [[ "${releases}/${old}" == "${previous_dir}" ]] && continue
        plan "remove old release ${releases}/${old}"
    done
    log "dry run complete; nothing was changed"
    exit 0
fi

umask 022
mkdir -p "${releases}"
# One deploy at a time. Commands that may leave processes behind run with fd 9 closed, so they never hold the lock.
exec 9>"${root}/.deploy.lock"
flock -n 9 || die "another deploy is running (${root}/.deploy.lock)"
[[ ! -e "${release_dir}" ]] || die "${release_dir} already exists"

# ---- 2. unpack (root-owned, read-only for the service) ----
staging="${releases}/.${release_id}.staging"
rm -rf "${staging}"
mkdir "${staging}"
trap 'rm -rf "${staging}"' EXIT
tar -xzf "${archive}" -C "${staging}" --no-same-owner --no-same-permissions
chown -R root:root "${staging}"
chmod -R u=rwX,go=rX "${staging}"
[[ -f "${staging}/BitosX.Api.dll" ]] || die "BitosX.Api.dll did not unpack"
mv "${staging}" "${release_dir}"
trap - EXIT
log "unpacked into ${release_dir}"

# ---- 3. database backup ----
mkdir -p "${backup_dir}"
chmod 0700 "${backup_dir}"
backup="${backup_dir}/${database}-${release_id}.sql.gz"
dump_args=()
[[ -n "${dump_defaults}" ]] && dump_args+=("--defaults-extra-file=${dump_defaults}")
dump_args+=(--single-transaction --routines --triggers --hex-blob --default-character-set=utf8mb4 --databases "${database}")
log "backing up database '${database}' to ${backup}"
(
    umask 077
    "${dump_cmd}" "${dump_args[@]}" | gzip -c >"${backup}.partial"
) || { rm -f "${backup}.partial"; die "the database backup failed; nothing was migrated or switched"; }
gzip -dc "${backup}.partial" | tail -n 1 | grep -q 'Dump completed' \
    || { rm -f "${backup}.partial"; die "the database backup is incomplete; nothing was migrated or switched"; }
mv "${backup}.partial" "${backup}"

# ---- 4. migrations (forward-only) ----
# Runs in a clean environment; reads the secret from the root-only file itself, so it never appears on a command line
# and never enters any other process's environment. Accepts KEY=value or KEY="value" (systemd EnvironmentFile style).
deploy_migrate() {
    local file="$1" dir="$2" dotnet="$3" line value=""
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        if [[ "${line}" == ConnectionStrings__BitosxMigrator=* ]]; then
            value="${line#ConnectionStrings__BitosxMigrator=}"
        fi
    done <"${file}"
    if [[ "${value}" == \"*\" ]]; then
        value="${value:1:${#value}-2}"
    fi
    export ConnectionStrings__BitosxMigrator="${value}"
    cd "${dir}"
    exec "${dotnet}" BitosX.Api.dll migrate
}

log "applying migrations"
if ! env -i PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" HOME=/root \
    ASPNETCORE_ENVIRONMENT=Production DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    bash -c "set -euo pipefail; $(declare -f deploy_migrate); "'deploy_migrate "$@"' \
    deploy-migrate "${migrator_file}" "${release_dir}" "${dotnet_cmd}" 9>&-; then
    die "migrate failed: the service still runs ${previous_dir:-nothing}; the failing script may be partly applied (DDL commits implicitly) - inspect it; backup: ${backup}"
fi

# ---- 5. switch and restart ----
switch_to() {
    local target="$1"
    ln -sfn "${target}" "${root}/.current.new"
    mv -Tf "${root}/.current.new" "${current_link}"
}

wait_healthy() {
    local deadline=$((SECONDS + health_timeout)) code
    while ((SECONDS < deadline)); do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${health_url}" || true)"
        [[ "${code}" == "200" ]] && return 0
        sleep 1
    done
    return 1
}

switch_to "releases/${release_id}"
log "current -> releases/${release_id}; restarting ${service}"
"${systemctl_cmd}" restart "${service}" 9>&- || log "systemctl restart ${service} reported a failure"

# ---- 6. health check, automatic switch back ----
if ! wait_healthy; then
    log "${health_url} did not answer 200 within ${health_timeout} s"
    if [[ -n "${previous_dir}" ]]; then
        switch_to "releases/$(basename "${previous_dir}")"
        "${systemctl_cmd}" restart "${service}" 9>&- || true
        if wait_healthy; then
            log "switched back to ${previous_dir}; it is healthy"
        else
            log "switched back to ${previous_dir}, but it is NOT healthy either"
        fi
    fi
    die "release ${release_id} failed its health check. Migrations are forward-only: the database keeps the new schema (backup before the migration: ${backup})"
fi
log "release ${release_id} is healthy"

# ---- 7. keep the newest N releases ----
mapfile -t old_releases < <(find "${releases}" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -printf '%f\n' | sort -r | tail -n "+$((keep + 1))")
for old in "${old_releases[@]}"; do
    [[ "${releases}/${old}" == "${previous_dir}" || "${old}" == "${release_id}" ]] && continue
    rm -rf "${releases:?}/${old}"
    log "removed old release ${old}"
done
log "done"
