# SPDX-License-Identifier: MIT
# Canonical v4 observation, coverage, and finding emitters. Requires jq and
# macos_security_common.sh.
# shellcheck disable=SC2034

if [ "${MSC_EVIDENCE_LOADED:-0}" = "1" ]; then
    return 0
fi
MSC_EVIDENCE_LOADED=1
MSC_EVIDENCE_VERSION="4.0.0"

mse_emit_coverage() {
    _mse_output=$1; _mse_component=$2; _mse_state=$3; _mse_detail=$4
    _mse_required=${5:-false}; _mse_tool=${6:-native}; _mse_evidence=${7:-}
    jq -cn --arg at "$(msc_utc_now)" --arg component "$_mse_component" \
        --arg state "$_mse_state" --arg detail "$_mse_detail" --arg tool "$_mse_tool" \
        --arg evidence "$_mse_evidence" --argjson required "$_mse_required" \
        '{schema:"macos-security-coverage/v1",record_type:"coverage",observed_at:$at,component:$component,state:$state,required:$required,tool:$tool,detail:$detail,evidence_ref:(if $evidence=="" then null else $evidence end),evidence_trust:"untrusted_observations"}' >>"$_mse_output"
}

mse_emit_observation() {
    _mse_output=$1; _mse_id=$2; _mse_category=$3; _mse_state=$4
    _mse_summary=$5; _mse_evidence=$6; _mse_data=${7:-'{}'}; _mse_sensitivity=${8:-medium}
    printf '%s' "$_mse_data" | jq -ce --arg at "$(msc_utc_now)" --arg id "$_mse_id" \
        --arg category "$_mse_category" --arg state "$_mse_state" --arg summary "$_mse_summary" \
        --arg evidence "$_mse_evidence" --arg sensitivity "$_mse_sensitivity" \
        '{schema:"macos-security-observation/v1",record_type:"observation",observed_at:$at,id:$id,category:$category,state:$state,summary:$summary,evidence_ref:$evidence,sensitivity:$sensitivity,data:.,evidence_trust:"untrusted_observations"}' >>"$_mse_output"
}

mse_emit_finding() {
    _mse_output=$1; _mse_id=$2; _mse_source=$3; _mse_category=$4
    _mse_status=$5; _mse_severity=$6; _mse_confidence=$7; _mse_class=$8
    _mse_title=$9; shift 9
    _mse_detail=$1; _mse_evidence=$2; _mse_remediation=${3:-}; _mse_detector=${4:-native-v4}
    jq -cn --arg id "$_mse_id" --arg source "$_mse_source" --arg category "$_mse_category" \
        --arg status "$_mse_status" --arg severity "$_mse_severity" --arg confidence "$_mse_confidence" \
        --arg class "$_mse_class" --arg title "$_mse_title" --arg detail "$_mse_detail" \
        --arg evidence "$_mse_evidence" --arg remediation "$_mse_remediation" --arg detector "$_mse_detector" \
        '{schema:"macos-security-finding/v1",record_type:"finding",source:$source,id:$id,category:$category,status:$status,severity:$severity,confidence:$confidence,class:$class,title:$title,detail:$detail,observed_evidence:null,evidence_ref:$evidence,remediation:$remediation,reference:null,expected:false,decision_status:(if ($status=="pass" or $status=="info") then "no_action" else "review" end),requires_confirmation:(if ($status=="pass" or $status=="info") then false else true end),evidence_trust:"untrusted_observations",false_positive_conditions:[],detector:{id:$detector,version:"4.0.0"}}' >>"$_mse_output"
}

mse_aggregate_coverage() {
    _mse_jsonl=$1; _mse_output=$2
    jq -s '{schema:"macos-security-coverage-summary/v1",record_type:"coverage_summary",generated_at:(now|todateiso8601),counts:(group_by(.state)|map({key:.[0].state,value:length})|from_entries),complete_for_required_scope:(all(.[]; (.required|not) or .state=="collected")),incomplete_required_components:[.[]|select(.required and .state!="collected")|.component],components:.}' "$_mse_jsonl" >"$_mse_output"
}
