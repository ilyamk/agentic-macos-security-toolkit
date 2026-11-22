#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"

usage() {
    printf '%s\n' 'Usage: macos-security recovery check [--report DIR] [--drill FILE]' \
        '       macos-security recovery record-drill ORIGINAL RESTORED [--output FILE]'
}
mode=${1:-}
[ "$#" -gt 0 ] || { usage >&2; exit 2; }
shift
case $mode in -h|--help) usage; exit 0 ;; check|record-drill) ;; *) usage >&2; exit 2 ;; esac
msl_use_review_path
msc_require_jq || exit 2
if [ "$mode" = record-drill ]; then
    [ "$#" -eq 2 ] || { [ "$#" -eq 4 ] && [ "$3" = --output ] && [ -n "$4" ]; } || { usage >&2; exit 2; }
    original=$(msl_explicit_file "$1" 131072) || exit 2
    restored=$(msl_explicit_file "$2" 131072) || exit 2
    original_id=$(/usr/bin/stat -f '%d:%i' "$original") || exit 2
    restored_id=$(/usr/bin/stat -f '%d:%i' "$restored") || exit 2
    [ "$original_id" != "$restored_id" ] || { printf '%s\n' 'Select distinct original and restored files.' >&2; exit 2; }
    if [ ! -s "$original" ] || ! /usr/bin/cmp -s "$original" "$restored"; then
        printf '%s\n' 'The files are empty or differ.' >&2; exit 1;
    fi
    result=$(jq -cn --arg at "$(msc_utc_now)" '{schema:"macos-security-recovery-drill/v1",checked_at:$at,
       sample_matches:true,provenance:"owner_selected_files"}') || exit 2
    if [ "$#" -eq 4 ]; then
        output=$(msc_report_file "$4") || exit 2
        (set -C; printf '%s\n' "$result" >"$output") || exit 2
    else
        printf '%s\n' "$result"
    fi
    exit 0
fi

report=''; drill=''
while [ "$#" -gt 0 ]; do
    case $1 in
        --report) [ "$#" -ge 2 ] && [ -n "$2" ] || exit 2; shift; report=$1 ;;
        --drill) [ "$#" -ge 2 ] && [ -n "$2" ] || exit 2; shift; drill=$1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done
if [ -z "$report" ]; then report=$("$ROOT_DIR/bin/macos-security" latest assessments 2>/dev/null) || report=''; fi
backup='{"state":"unknown","backup_date":null,"age_days":null,"assessment_observed_at":null}'
if [ -n "$report" ]; then
    report=$(msl_directory "$report") || exit 2
    work=$(msc_mktemp_dir macos-security-recovery) || exit 2
    trap '/bin/rm -f "$work/posture.jsonl" "$work/SHA256SUMS" "$work/.validation.timeout"; /bin/rmdir "$work"' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
    msl_snapshot_assessment "$ROOT_DIR" "$report" "$work" posture.jsonl || exit 2
    backup=$(jq -cs '
      def date_stamp: type=="string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$");
      ([.[]|select(.record_type=="meta" and (.generated_at_utc|date_stamp))|.generated_at_utc][0] // null) as $observed |
      ([.[]|select(.record_type=="evidence" and .id=="recovery.time_machine" and .collection_state=="collected") |
        .data|strings|split("\n")[]|select(startswith("/"))|
        scan("(?:^|/)(?:com\\.apple\\.TimeMachine\\.)?([0-9]{4}-[0-9]{2}-[0-9]{2})-[0-9]{6}(?:\\.backup)?(?:/|$)")|.[0]] | max // null) as $date |
      (try (($date+"T00:00:00Z")|fromdateiso8601) catch null) as $stamp |
      (if $stamp!=null then (((now/86400|floor)*86400-$stamp)/86400) else null end) as $age |
      if $age!=null and $age>=0 then {state:"observed",backup_date:$date,age_days:$age,assessment_observed_at:$observed}
      else {state:"unknown",backup_date:null,age_days:null,assessment_observed_at:$observed} end
    ' "$work/posture.jsonl") || exit 2
fi
proof=null
if [ -n "$drill" ]; then
    drill=$(msl_explicit_file "$drill" 16384) || exit 2
    proof=$(jq -ces '
       select(length==1)|.[0]|select(.schema=="macos-security-recovery-drill/v1" and
       .sample_matches==true and .provenance=="owner_selected_files" and
       (.checked_at|type=="string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") and
           ((try fromdateiso8601 catch (now+1))<=now))) |
       {checked_at,sample_matches,provenance}
    ' "$drill" 2>/dev/null) || exit 2
fi
jq -cn --argjson backup "$backup" --argjson drill "$proof" '
  {schema:"macos-security-recovery-check/v1",record_type:"recovery_check",time_machine:$backup,
   recorded_drill:$drill,evidence_trust:"untrusted_observations"}'
