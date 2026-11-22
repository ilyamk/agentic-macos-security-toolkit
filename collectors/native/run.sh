#!/bin/sh
# SPDX-License-Identifier: MIT
# Modular dependency-free native collectors for macOS.

set -u
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
. "$ROOT_DIR/lib/macos_security_common.sh"
. "$ROOT_DIR/lib/macos_security_execution.sh"
. "$ROOT_DIR/lib/macos_security_evidence.sh"
. "$ROOT_DIR/lib/macos_security_dependencies.sh"
. "$ROOT_DIR/collectors/native/background_security.sh"
. "$ROOT_DIR/collectors/native/shell_startup.sh"
. "$ROOT_DIR/collectors/native/native_messaging.sh"
. "$ROOT_DIR/collectors/native/credential_metadata.sh"
. "$ROOT_DIR/collectors/native/homebrew.sh"
. "$ROOT_DIR/detectors/native.sh"

OUTPUT=""; TARGET_USER=""; SELF_TEST=0
while [ "$#" -gt 0 ]; do
    case $1 in
        --output) shift; OUTPUT=${1:-} ;;
        --target-user) shift; TARGET_USER=${1:-} ;;
        --self-test) SELF_TEST=1 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
msc_require_jq || exit 2
if [ "$SELF_TEST" -eq 1 ]; then
    printf '%s\n' '{"schema":"macos-security-native-collectors/v1","record_type":"self_test","status":"pass"}'
    exit 0
fi
[ -n "$OUTPUT" ] || exit 2
[ -n "$TARGET_USER" ] || TARGET_USER=$(msc_default_target_user)
msc_validate_target_user "$TARGET_USER" || exit 2
TARGET_HOME=$(msc_target_home "$TARGET_USER")
OUTPUT=$(msc_create_private_dir "$OUTPUT") || exit 2
OBSERVATIONS="$OUTPUT/observations.jsonl"; COVERAGE="$OUTPUT/coverage.jsonl"; FINDINGS="$OUTPUT/findings.jsonl"
: >"$OBSERVATIONS"; : >"$COVERAGE"; : >"$FINDINGS"
/bin/chmod 600 "$OBSERVATIONS" "$COVERAGE" "$FINDINGS"

msn_collect_background_security "$OUTPUT" "$OBSERVATIONS" "$COVERAGE"
msn_collect_shell_startup "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$TARGET_HOME"
msn_collect_native_messaging "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$TARGET_HOME"
msn_collect_credential_metadata "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$TARGET_HOME"
msn_collect_homebrew "$OUTPUT" "$OBSERVATIONS" "$COVERAGE"
msd_detect_native "$OBSERVATIONS" "$FINDINGS"
mse_aggregate_coverage "$COVERAGE" "$OUTPUT/coverage.json"
jq -n --arg generated_at "$(msc_utc_now)" --arg target_user "$TARGET_USER" --slurpfile coverage "$COVERAGE" '{schema:"macos-security-native-collectors/v1",record_type:"native_summary",generated_at:$generated_at,target_user:$target_user,coverage:$coverage}' >"$OUTPUT/summary.json"
printf '%s\n' "$OUTPUT/summary.json"
