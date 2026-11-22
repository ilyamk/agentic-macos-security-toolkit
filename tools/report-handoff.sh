#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"
# shellcheck source=lib/macos_security_schema.sh
. "$ROOT_DIR/lib/macos_security_schema.sh"
usage() {
    printf '%s\n' \
        'Usage: macos-security report export REPORT_DIR --audience agent [--output FILE]' \
        '       macos-security report action REPORT_DIR --bundle SHA256 review-coverage' \
        '       macos-security report action REPORT_DIR --bundle SHA256 review-finding ORDINAL'
}
mode=${1:-}; output=''; expected=''; ordinal=0
case $mode in
    -h|--help) usage; exit 0 ;;
    export)
        [ "$#" -ge 4 ] && [ "$3" = --audience ] && [ "$4" = agent ] || { usage >&2; exit 2; }
        report=$2; shift 4
        if [ "$#" -ne 0 ]; then
            [ "$#" -eq 2 ] && [ "$1" = --output ] && [ -n "$2" ] || { usage >&2; exit 2; }
            output=$2
        fi ;;
    action)
        [ "$#" -ge 5 ] && [ "$3" = --bundle ] || { usage >&2; exit 2; }
        report=$2; expected=$4; mode=$5; shift 5
        printf '%s\n' "$expected" | /usr/bin/grep -Eq '^[a-f0-9]{64}$' || exit 2
        case $mode in
            review-coverage) [ "$#" -eq 0 ] || exit 2 ;;
            review-finding)
                [ "$#" -eq 1 ] && printf '%s\n' "$1" | /usr/bin/grep -Eq '^[1-9][0-9]{0,6}$' || exit 2
                ordinal=$1 ;;
            *) usage >&2; exit 2 ;;
        esac ;;
    *) usage >&2; exit 2 ;;
esac
msl_use_review_path
msc_require_jq || exit 2
report=$(msl_directory "$report") || exit 2
work=$(msc_mktemp_dir macos-security-agent-export) || exit 2
trap '/bin/rm -f "$work/SHA256SUMS" "$work/findings.jsonl" "$work/coverage.json" "$work/.validation.timeout" "$work/export.json"; /bin/rmdir "$work"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
msl_snapshot_assessment "$ROOT_DIR" "$report" "$work" findings.jsonl coverage.json || {
    printf '%s\n' 'Expected a valid, completed assessment with bounded export inputs.' >&2
    exit 2
}
digest=$(msc_sha256_file "$work/SHA256SUMS")
[ "${#digest}" -eq 64 ] || exit 2
[ -z "$expected" ] || [ "$expected" = "$digest" ] || { printf '%s\n' 'The selected assessment does not match this action.' >&2; exit 2; }
jq -en --arg mode "$mode" --arg digest "$digest" --argjson ordinal "$ordinal" \
    --slurpfile findings "$work/findings.jsonl" --slurpfile coverage "$work/coverage.json" \
    -f "$ROOT_DIR/tools/agent-export.jq" >"$work/export.json" || exit 2
case $mode in export) schema=agent-export ;; *) schema=agent-action ;; esac
msc_schema_validate "$ROOT_DIR/schemas/$schema.schema.json" "$work/export.json" >/dev/null || exit 2
if [ -n "$output" ]; then
    output=$(msc_report_file "$output") || exit 2
    (set -C; /bin/cat "$work/export.json" >"$output") || exit 2
else
    /bin/cat "$work/export.json"
fi
