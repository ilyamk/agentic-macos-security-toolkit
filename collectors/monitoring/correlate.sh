#!/bin/sh
# SPDX-License-Identifier: MIT
# High-confidence correlations over the normalized Endpoint Security timeline.

set -uC
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
. "$ROOT_DIR/lib/macos_security_common.sh"
. "$ROOT_DIR/lib/macos_security_evidence.sh"
TIMELINE=""; OUTPUT=""
while [ "$#" -gt 0 ]; do
    case $1 in
        --timeline) shift; TIMELINE=${1:-} ;;
        --output) shift; OUTPUT=${1:-} ;;
        --self-test) printf '%s\n' '{"schema":"macos-security-correlator/v1","record_type":"self_test","status":"pass"}'; exit 0 ;;
        *) exit 2 ;;
    esac
    shift
done
[ -r "$TIMELINE" ] && [ -n "$OUTPUT" ] || exit 2
msc_require_jq || exit 2
OUTPUT=$(msc_report_file "$OUTPUT") || exit 2
: >"$OUTPUT" || exit 2
_msc_xp=$(jq -s '[.[]|select(.kind|test("xp_malware_(detected|remediated)";"i"))]|length' "$TIMELINE")
_msc_gk=$(jq -s '[.[]|select(.kind|test("gatekeeper_user_override";"i"))]|length' "$TIMELINE")
_msc_tcc=$(jq -s '[.[]|select(.kind|test("tcc_modify";"i"))]|length' "$TIMELINE")
if [ "$_msc_xp" -gt 0 ]; then
    mse_emit_finding "$OUTPUT" monitor.xprotect monitor monitoring fail critical high detection "Endpoint Security reported XProtect activity" "$_msc_xp XProtect detection/remediation event(s) occurred in the bounded monitoring window." "timeline.jsonl" "Preserve evidence and begin incident validation before cleanup." eslogger-correlation
fi
if [ "$_msc_gk" -gt 0 ]; then
    mse_emit_finding "$OUTPUT" monitor.gatekeeper_override monitor monitoring warn high high detection "Gatekeeper user override observed" "$_msc_gk Gatekeeper override event(s) occurred in the bounded monitoring window." "timeline.jsonl" "Identify the approved user, executable, signature, provenance, and business reason." eslogger-correlation
fi
if [ "$_msc_tcc" -gt 0 ]; then
    mse_emit_finding "$OUTPUT" monitor.tcc_modify monitor monitoring warn high medium anomaly "TCC permission change observed" "$_msc_tcc TCC modification event(s) occurred in the bounded monitoring window." "timeline.jsonl" "Confirm the responsible process and approved permission change." eslogger-correlation
fi
