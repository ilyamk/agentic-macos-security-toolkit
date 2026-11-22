#!/bin/sh
# SPDX-License-Identifier: MIT
set -u
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_updates.sh
. "$ROOT_DIR/lib/macos_security_updates.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"

usage() {
    printf '%s\n' 'Usage: macos-security updates status [--online] [--mscp-metadata FILE]'
}
[ "${1:-}" = status ] || { case "${1:-}" in -h|--help) usage; exit 0 ;; esac; usage >&2; exit 2; }
shift
online=0; mscp=''
while [ "$#" -gt 0 ]; do
    case $1 in
        --online) online=1 ;;
        --mscp-metadata) [ "$#" -ge 2 ] || exit 2; shift; mscp=$1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done
msl_use_review_path
msc_require_jq || exit 2
version=$(/usr/bin/sw_vers -productVersion 2>/dev/null) || exit 2
build=$(/usr/bin/sw_vers -buildVersion 2>/dev/null) || exit 2
baseline=$(msu_branch_status "$version" "$(/bin/date -u +%F)" "$ROOT_DIR/config/macos-updates.json") || exit 2
supplement=$(/usr/bin/sw_vers -productVersionExtra 2>/dev/null) || supplement=''
if ! printf '%s\n' "$supplement" | /usr/bin/grep -Eq '^\([a-z]{1,3}\)$'; then supplement=''; fi
offered=not_requested; restart=null; metadata=null
if [ -n "$mscp" ]; then
    mscp=$(msl_explicit_file "$mscp" 16384) || exit 2
    metadata=$(jq -ces '
        select(length==1)|.[0]|select(.schema=="macos-security-mscp-metadata/v1" and
            (.release|type=="string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")) and
            (.profile|type=="string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"))) |
        {release,profile,provenance:"user_supplied_metadata"}
    ' "$mscp" 2>/dev/null) || exit 2
fi
if [ "$online" -eq 1 ]; then
    work=$(msc_mktemp_dir macos-security-update-status) || exit 2
    trap '/bin/rm -f "$work/offers" "$work/timeout"; /bin/rmdir "$work"' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
    offered=unknown
    if LC_ALL=C msc_run_timed_capture 90 "$work/offers" /dev/null "$work/timeout" /usr/sbin/softwareupdate --list; then
        if /usr/bin/grep -Eq '^[[:space:]]*\*?[[:space:]]*Label:' "$work/offers"; then
            offered=available
            if /usr/bin/grep -Eiq 'Action:[[:space:]]*restart' "$work/offers"; then restart=true; fi
        elif /usr/bin/grep -Eq '^No new software available\.?$' "$work/offers"; then
            offered=none_reported
        fi
    fi
fi
jq -cn --argjson baseline "$baseline" --arg build "$build" --arg offered "$offered" \
    --argjson restart "$restart" --arg supplement "$supplement" --argjson mscp "$metadata" '
    {schema:"macos-security-update-status/v1",record_type:"update_status",baseline:$baseline,
     installed_build:$build,software_update:{state:$offered,offered_restart_required:$restart},
     background_security:{installed_state:(if $supplement=="" then "unknown" else "supplement_reported" end),
        reported_supplement:(if $supplement=="" then null else $supplement end),pending_restart:null},
     mscp:$mscp,evidence_trust:"untrusted_observations"}'
