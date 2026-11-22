#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"

usage() {
    printf '%s\n' 'Usage: macos-security network import INPUT --timeline FILE [--from UTC] [--to UTC]'
}
case ${1:-} in -h|--help) usage; exit 0 ;; esac
[ "${1:-}" = import ] && [ "$#" -ge 4 ] || { usage >&2; exit 2; }
shift
input=$1; timeline=''; from=''; to=''
shift
while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 2; }
    case $1 in
        --timeline) timeline=$2 ;;
        --from) from=$2 ;;
        --to) to=$2 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift 2
done
[ -n "$input" ] && [ -n "$timeline" ] || exit 2
msl_use_review_path
msc_require_jq || exit 2
input=$(msl_explicit_file "$input" 2097152) || exit 2
timeline=$(msl_explicit_file "$timeline" 16777216) || exit 2
# Every nonempty line must be its own JSON object. Suppress parser output that
# could otherwise include untrusted text.
if ! /usr/bin/awk 'NF && ++n>4000 {exit 1} length>8192 {exit 1}' "$input" ||
    ! jq -Rse --arg from "$from" --arg to "$to" --slurpfile timeline "$timeline" \
         -f "$ROOT_DIR/collectors/monitoring/import-network.jq" "$input" 2>/dev/null; then
    printf '%s\n' 'Network input, timeline or time window could not be verified.' >&2
    exit 2
fi
