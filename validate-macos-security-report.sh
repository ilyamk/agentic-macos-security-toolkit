#!/bin/sh
# SPDX-License-Identifier: MIT
# Deterministically validate a saved v3 assessment: required artifacts,
# JSON Schema contracts from schemas/, cross-artifact consistency, and the
# SHA-256 integrity manifest.

set -u
SCRIPT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
COMMON_LIB="$SCRIPT_DIR/lib/macos_security_common.sh"
SCHEMA_LIB="$SCRIPT_DIR/lib/macos_security_schema.sh"
SCHEMA_DIR="$SCRIPT_DIR/schemas"
REPORT_DIR=""; SELF_TEST=0
[ -r "$COMMON_LIB" ] || { printf 'Missing library: %s\n' "$COMMON_LIB" >&2; exit 2; }
# shellcheck source=lib/macos_security_common.sh
. "$COMMON_LIB"
[ -r "$SCHEMA_LIB" ] || { printf 'Missing library: %s\n' "$SCHEMA_LIB" >&2; exit 2; }
# shellcheck source=lib/macos_security_schema.sh
. "$SCHEMA_LIB"
# shellcheck source=lib/macos_security_reporting.sh
. "$SCRIPT_DIR/lib/macos_security_reporting.sh"

usage() { printf '%s\n' 'Usage: ./validate-macos-security-report.sh REPORT_DIR' '       ./validate-macos-security-report.sh --self-test' 'REPORT_DIR may be the latest symlink of a results directory.'; }
while [ "$#" -gt 0 ]; do
    case $1 in
        --self-test) SELF_TEST=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
        *) [ -z "$REPORT_DIR" ] || { printf 'Only one report directory is allowed.\n' >&2; exit 2; }; REPORT_DIR=$1 ;;
    esac
    shift
done
msc_require_jq || exit 2
if [ "$SELF_TEST" -eq 1 ]; then
    _vst_dir=$(msc_mktemp_dir macos-security-validate-selftest) || exit 2
    printf '%s\n' '{"schema":"macos-security-diff/v1","record_type":"assessment_diff","baseline_established":true,"previous_run":null,"added":[],"resolved":[],"changed":[]}' >"$_vst_dir/good.json"
    printf '%s\n' '{"schema":"macos-security-diff/v1","record_type":"assessment_diff","baseline_established":"yes","added":[]}' >"$_vst_dir/bad.json"
    _vst_ok=1
    msc_schema_validate "$SCHEMA_DIR/diff.schema.json" "$_vst_dir/good.json" >/dev/null || _vst_ok=0
    if msc_schema_validate "$SCHEMA_DIR/diff.schema.json" "$_vst_dir/bad.json" >/dev/null; then _vst_ok=0; fi
    /bin/rm -rf "$_vst_dir"
    [ "$_vst_ok" -eq 1 ] || { printf '%s\n' '{"schema":"macos-security-report-validation/v1","record_type":"self_test","status":"fail","failed":["schema_validator"]}'; exit 2; }
    printf '%s\n' '{"schema":"macos-security-report-validation/v1","record_type":"self_test","status":"pass","checks":["schema_validator"]}'
    exit 0
fi
[ -n "$REPORT_DIR" ] && [ -d "$REPORT_DIR" ] || { usage >&2; exit 2; }
REPORT_DIR=$(CDPATH='' cd -- "$REPORT_DIR" && /bin/pwd -P) || exit 2
if ! msc_report_file_list "$REPORT_DIR" >/dev/null; then
    jq -cn --arg report "$REPORT_DIR" '{schema:"macos-security-report-validation/v1",record_type:"validation_result",report_dir:$report,valid:false,checks:1,errors:["Report contains unreadable or unsafe file entries."],next_actions_ref:null}'
    exit 1
fi
VALIDATION_TMP=$(msc_mktemp_dir macos-security-validate) || exit 2
trap '/bin/rm -f "$VALIDATION_TMP/index.json" "$VALIDATION_TMP/SHA256SUMS"; /bin/rmdir "$VALIDATION_TMP"' EXIT
INTEGRITY_MODE=legacy
jq -e '.integrity_format==2' "$REPORT_DIR/run-manifest.json" >/dev/null 2>&1 && INTEGRITY_MODE=current

ERRORS=""; CHECKS=0
record_error() { ERRORS="${ERRORS}${ERRORS:+
}$CHECKS:$1"; }
check() { CHECKS=$((CHECKS + 1)); if ! "$@" >/dev/null 2>&1; then record_error "$*"; fi; }
check_schema() {
    _v_artifact=$1; _v_schema=$(msc_schema_name_for "$_v_artifact")
    CHECKS=$((CHECKS + 1))
    [ -n "$_v_schema" ] || { record_error "no schema mapping for $_v_artifact"; return; }
    _v_out=$(msc_schema_validate "$SCHEMA_DIR/$_v_schema.schema.json" "$REPORT_DIR/$_v_artifact") && return
    record_error "schema $_v_schema for $_v_artifact: $(printf '%s' "$_v_out" | /usr/bin/head -n 3 | /usr/bin/tr '\n' ';')"
}

for required in run-manifest.json agent-context.json agent-summary.json agent-report.md coverage.json coverage.jsonl observations.jsonl findings.jsonl diff-from-previous.json evidence-index.json posture.jsonl triage/report.jsonl SHA256SUMS policy.json; do
    check test -s "$REPORT_DIR/$required"
done
check test ! -e "$REPORT_DIR/INCOMPLETE"
for artifact in run-manifest.json agent-summary.json agent-context.json coverage.jsonl coverage.json observations.jsonl findings.jsonl diff-from-previous.json evidence-index.json posture.jsonl triage/report.jsonl; do
    [ -s "$REPORT_DIR/$artifact" ] && check_schema "$artifact"
done
check msc_schema_validate "$SCHEMA_DIR/security-policy.schema.json" "$REPORT_DIR/policy.json"

# Cross-artifact consistency an agent relies on. $-names inside single quotes
# are jq variables.
# shellcheck disable=SC2016
cross_checks() {
    check jq -e '.complete==true and .evidence_trust=="untrusted_observations" and (.agent_read_order|index("agent-context.json")!=null)' "$REPORT_DIR/run-manifest.json"
    check jq -e -s 'length>0 and (map(.id)|length)==(map(.id)|unique|length)' "$REPORT_DIR/findings.jsonl"
    check jq -e --slurpfile summary "$REPORT_DIR/agent-summary.json" '.requires_review==$summary[0].requires_review' "$REPORT_DIR/agent-context.json"
    check jq -e --slurpfile coverage "$REPORT_DIR/coverage.json" '.coverage_summary.complete_for_required_scope==$coverage[0].complete_for_required_scope' "$REPORT_DIR/agent-summary.json"
    check jq -e 'any(.components[]; .component=="posture" and .required) and any(.components[]; .component=="triage" and .required)' "$REPORT_DIR/coverage.json"
    check jq -e '(.next_actions|length)>0 and all(.next_actions[]; (.command|type=="string") and (.requires_root|type=="boolean"))' "$REPORT_DIR/agent-context.json"
    check /usr/bin/grep -q '^## Next actions' "$REPORT_DIR/agent-report.md"
    check msr_build_evidence_index "$REPORT_DIR" "$VALIDATION_TMP/index.json" "$INTEGRITY_MODE"
    check jq -e --slurpfile actual "$VALIDATION_TMP/index.json" '.files==$actual[0].files' "$REPORT_DIR/evidence-index.json"
    if [ "$INTEGRITY_MODE" = current ]; then
        check jq -e -s --slurpfile index "$VALIDATION_TMP/index.json" '
            ($index[0].files|map(.path)) as $paths | all(.[]; .evidence_ref==null or (.evidence_ref as $ref | $paths|index($ref)!=null))' "$REPORT_DIR/findings.jsonl"
    fi
}
cross_checks
if [ -s "$REPORT_DIR/SHA256SUMS" ]; then
    CHECKS=$((CHECKS + 1))
    if ! msc_write_report_checksums "$REPORT_DIR" "$INTEGRITY_MODE" >"$VALIDATION_TMP/SHA256SUMS" ||
       ! /usr/bin/cmp -s "$VALIDATION_TMP/SHA256SUMS" "$REPORT_DIR/SHA256SUMS"; then record_error "SHA256SUMS integrity"; fi
fi
if [ -z "$ERRORS" ]; then
    jq -cn --arg report "$REPORT_DIR" --argjson checks "$CHECKS" --arg requires_review "$(jq -r '.requires_review' "$REPORT_DIR/run-manifest.json")" '{schema:"macos-security-report-validation/v1",record_type:"validation_result",report_dir:$report,valid:true,checks:$checks,errors:[],requires_review:($requires_review=="true"),next_actions_ref:"agent-context.json"}'
    exit 0
fi
printf '%s\n' "$ERRORS" | jq -R -s --arg report "$REPORT_DIR" --argjson checks "$CHECKS" '{schema:"macos-security-report-validation/v1",record_type:"validation_result",report_dir:$report,valid:false,checks:$checks,errors:(split("\n")|map(select(length>0))),next_actions_ref:null}'
exit 1
