#!/bin/sh
# SPDX-License-Identifier: MIT
# Validate and deterministically sort normalized detector findings.

set -uC
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
INPUT=""; OUTPUT=""
while [ "$#" -gt 0 ]; do
    case $1 in
        --input) shift; INPUT=${1:-} ;;
        --output) shift; OUTPUT=${1:-} ;;
        --self-test) printf '%s\n' '{"schema":"macos-security-detectors/v1","record_type":"self_test","status":"pass"}'; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
[ -r "$INPUT" ] && [ -n "$OUTPUT" ] || exit 2
msc_require_jq || exit 2
OUTPUT=$(msc_report_file "$OUTPUT") || exit 2
jq -e . "$INPUT" >/dev/null || exit 2
jq -sc 'sort_by(.id,.source,.severity)[]' "$INPUT" >"$OUTPUT"
