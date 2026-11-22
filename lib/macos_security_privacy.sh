# SPDX-License-Identifier: MIT
# Build a portable report from statuses and bounded metadata. Raw collector
# files, custom policy prose and machine-specific context stay in staging.

msr_export_redacted() (
    _privacy_source=$1; _privacy_dest=$2
    /bin/mkdir -p "$_privacy_dest/triage/evidence" || exit 1
    jq -cs 'to_entries | map(select(.value.source=="triage" and (.value.id|test("^(listener_|process_path_|persistence_.*_[0-9a-f]{12}$)")))
      | {key:.value.id,value:("redacted.triage."+(.key|tostring))}) | from_entries' \
        "$_privacy_source/findings.jsonl" >"$_privacy_source/.redaction-ids.json" || exit 1
    jq -c '
      if .record_type=="meta" then
        {schema_version,record_type,suite_role,collector,collector_version,generated_at_utc,reference_date,reference_patch_version,mode,online,
         redacted:true,effective_user:"<USER>",target_user:"<USER>",target_home:"~",hostname:"<HOST>",evidence_trust}
      elif .record_type=="evidence" then
        {schema_version,record_type,id,category,title,collection_state,sensitivity,requires_root,exit_code,source:"withheld",data:"",error:""}
      elif .record_type=="finding" then
        {schema_version,record_type,id,category,status,severity,title,summary:"Host-specific details withheld.",evidence:"",recommendation:"",reference:""}
      else {schema_version,record_type,completed_at_utc,findings,evidence} end
    ' "$_privacy_source/posture.jsonl" >"$_privacy_dest/posture.jsonl" || exit 1
    jq -c 'select(.record_type=="summary")' "$_privacy_dest/posture.jsonl" >"$_privacy_dest/posture-summary.json" || exit 1
    /bin/cp "$_privacy_dest/posture.jsonl" "$_privacy_dest/triage/evidence/posture.jsonl" || exit 1

    jq -c --slurpfile ids "$_privacy_source/.redaction-ids.json" '
      if .record_type=="finding" then .id=($ids[0][.id] // .id) else . end |
      if .record_type=="meta" then
        {schema,record_type,suite_role,run_id:"redacted",started_at,tool_version,mode,read_only,effective_user:"<USER>",target_user:"<USER>",target_home:"~",
         evidence_trust,online_delegated_to_posture,posture_source,monitor_seconds,report_dir:"."}
      elif .record_type=="summary" then
        {schema,record_type,suite_role,run_id:"redacted",completed_at,overall,risk_score_0_100,counts,posture_evidence:"evidence/posture.jsonl",report_dir:"."}
      elif .record_type=="finding" then
        {schema,record_type,id,category,severity,confidence,status,class,title,detail:"Host-specific details withheld.",evidence:"",remediation:""}
      else {schema,record_type,id,category,title,detail:"Host-specific details withheld.",evidence:""} end
    ' "$_privacy_source/triage/report.jsonl" >"$_privacy_dest/triage/report.jsonl" || exit 1
    jq -c 'select(.record_type=="summary")' "$_privacy_dest/triage/report.jsonl" >"$_privacy_dest/triage/summary.json" || exit 1
    /bin/cp "$_privacy_dest/triage/summary.json" "$_privacy_dest/triage-summary.json" || exit 1

    jq -c --slurpfile ids "$_privacy_source/.redaction-ids.json" '
      (if .source=="triage" then .id=($ids[0][.id] // .id) else . end) |
      {schema,record_type,source,id,category,status,severity,confidence,class,title,
      detail:"Host-specific details withheld.",observed_evidence:null,evidence_ref:(if .source=="posture" then "posture.jsonl" elif .source=="triage" then "triage/report.jsonl" else "observations.jsonl" end),
      remediation:"Review privately on the source Mac.",reference:null,expected,decision_status,requires_confirmation,evidence_trust,false_positive_conditions:[]}
    ' "$_privacy_source/findings.jsonl" >"$_privacy_dest/findings.jsonl" || exit 1
    jq -c '{schema,record_type,observed_at,id,category,state,summary:"Host-specific details withheld.",evidence_ref:"observations.jsonl",sensitivity,data:{},evidence_trust}' \
        "$_privacy_source/observations.jsonl" >"$_privacy_dest/observations.jsonl" || exit 1
    jq -c '{schema,record_type,observed_at,component,state,required,tool,detail:"Host-specific details withheld.",evidence_ref:null,evidence_trust}' \
        "$_privacy_source/coverage.jsonl" >"$_privacy_dest/coverage.jsonl" || exit 1
    mse_aggregate_coverage "$_privacy_dest/coverage.jsonl" "$_privacy_dest/coverage.json" || exit 1
    jq '{schema,policy_id:"redacted-policy",threat_model:{name:"Redacted policy",asset_value:.threat_model.asset_value,assumptions:[]},
      expected_services:(.expected_services|{screen_sharing,smb_guest,remote_login,remote_management,legacy_vnc}),
      adapters:(if .adapters==null then null else (.adapters|with_entries(.value|=map(select(IN("knockknock","clamav","yara","yara-x","osv-scanner","gitleaks","trivy","osquery","santa","mscp"))))) end),
      dependency_policy,privacy,remediation:{auto_apply:false,require_confirmation:true,require_rollback:true}} | with_entries(select(.value!=null))' \
        "$_privacy_source/policy.json" >"$_privacy_dest/policy.json"
)
