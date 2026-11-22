#!/bin/sh
# SPDX-License-Identifier: MIT
# Build a reviewable remediation plan; apply only a tiny explicit allowlist.

set -u
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
COMMON_LIB="$SCRIPT_DIR/lib/macos_security_common.sh"
OUTPUT_ROOT="$SCRIPT_DIR/remediation-results"
REPORT_DIR=""; APPLY_PLAN=""; YES=0; SELF_TEST=0

[ -r "$COMMON_LIB" ] || { printf 'Missing library: %s\n' "$COMMON_LIB" >&2; exit 2; }
# shellcheck source=lib/macos_security_common.sh
. "$COMMON_LIB"
# shellcheck source=lib/macos_security_schema.sh
. "$SCRIPT_DIR/lib/macos_security_schema.sh"
# shellcheck source=lib/macos_security_remediation.sh
. "$SCRIPT_DIR/lib/macos_security_remediation.sh"

usage() {
    cat <<'EOF'
Usage:
  ./macos-security-remediation.sh --plan REPORT_DIR [--output-root DIR]
  sudo ./macos-security-remediation.sh --apply PLAN.json --yes [--output-root DIR]

Plan mode is read-only and is always the default workflow. Apply mode supports
only explicitly allowlisted reversible actions, requires root plus --yes, saves
before/after evidence, and refuses every unknown action.

  --plan REPORT_DIR   Build a remediation plan from a v3 assessment
  --apply PLAN.json   Apply supported actions from a reviewed plan
  --yes               Explicit confirmation required with --apply
  --output-root DIR   Timestamped result parent
  --self-test         Validate dependencies and print JSON
  -h, --help          Show help
EOF
}

die() { printf '%s: %s\n' "${0##*/}" "$1" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
    case $1 in
        --plan) [ "$#" -ge 2 ] || die "--plan requires a directory"; shift; REPORT_DIR=$1 ;;
        --apply) [ "$#" -ge 2 ] || die "--apply requires a plan"; shift; APPLY_PLAN=$1 ;;
        --yes) YES=1 ;;
        --output-root) [ "$#" -ge 2 ] || die "--output-root requires a directory"; shift; OUTPUT_ROOT=$1 ;;
        --self-test) SELF_TEST=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) die "unexpected argument: $1" ;;
    esac
    shift
done

msc_require_jq || exit 2
if [ "$SELF_TEST" -eq 1 ]; then
    printf '%s\n' '{"schema":"macos-security-remediation/v1","record_type":"self_test","status":"pass","apply_allowlist":["firewall.enable_stealth"]}'
    exit 0
fi
[ -z "$REPORT_DIR" ] || [ -z "$APPLY_PLAN" ] || die "choose either --plan or --apply"
[ -n "$REPORT_DIR" ] || [ -n "$APPLY_PLAN" ] || die "--plan or --apply is required"
OUTPUT_ROOT=$(msc_report_directory "$OUTPUT_ROOT") || exit 2

make_result_dir() {
    [ -d "$OUTPUT_ROOT" ] || { /bin/mkdir -p "$OUTPUT_ROOT" || return 1; /bin/chmod 700 "$OUTPUT_ROOT" || return 1; }
    _rem_id=$(/bin/date -u '+%Y-%m-%dT%H%M%SZ'); _rem_dir="$OUTPUT_ROOT/$_rem_id"
    [ ! -e "$_rem_dir" ] || _rem_dir="$_rem_dir-$$"
    msc_create_private_dir "$_rem_dir"
}

if [ -n "$REPORT_DIR" ]; then
    "$SCRIPT_DIR/validate-macos-security-report.sh" "$REPORT_DIR" >/dev/null || die "assessment integrity or schema validation failed"
    [ -r "$REPORT_DIR/run-manifest.json" ] || die "missing run-manifest.json"
    [ -r "$REPORT_DIR/agent-summary.json" ] || die "missing agent-summary.json"
    [ -r "$REPORT_DIR/findings.jsonl" ] || die "missing findings.jsonl"
    jq -e '.schema=="macos-security-assessment/v3" and .complete==true' "$REPORT_DIR/run-manifest.json" >/dev/null || die "assessment is not a complete v3 report"
    RESULT_DIR=$(make_result_dir) || die "cannot create output directory"
    PLAN="$RESULT_DIR/remediation-plan.json"
    # Finding IDs referenced below must match producers exactly:
    # network.firewall_stealth / network.firewall / services.* come from
    # macos-security-posture.sh; browser_* from macos-security-triage.sh;
    # credentials.permissions from detectors/native.sh. tests/unit/test_contract_consistency.sh
    # enforces this coupling. $PLAN is passed only as a string for next_actions.
    # shellcheck disable=SC2094
    jq -n --slurpfile summary "$REPORT_DIR/agent-summary.json" --slurpfile findings "$REPORT_DIR/findings.jsonl" --slurpfile manifest "$REPORT_DIR/run-manifest.json" --arg source "$REPORT_DIR" --arg generated "$(msc_utc_now)" --arg self "$SCRIPT_DIR/${0##*/}" --arg runner "$SCRIPT_DIR/run-macos-security-assessment.sh" --arg plan "$PLAN" '
      def has($id): any($findings[]; .id==$id and .decision_status=="review");
      def action($id;$title;$reason;$supported;$privilege;$steps;$rollback):
        {id:$id,title:$title,reason:$reason,status:"proposed",apply_supported:$supported,
         required_privilege:$privilege,steps:$steps,rollback:$rollback,
         requires_human_review:true,source_finding_ids:[]};
      [
        if has("network.firewall_stealth") then
          action("firewall.enable_stealth";"Enable firewall stealth mode";"Reduce responses to unsolicited probes";true;"root";
            ["Save current socketfilterfw stealth state","Enable stealth mode","Verify effective state","Run a fresh assessment"];
            "Restore the recorded socketfilterfw stealth state") | .source_finding_ids=["network.firewall_stealth"] else empty end,
        if has("network.firewall") then
          action("firewall.enable_application_firewall";"Enable the macOS Application Firewall";"Incoming connections are currently unfiltered at the application layer";false;"administrator";
            ["Confirm no managed profile already controls the firewall","Enable the firewall in System Settings > Network > Firewall","Review the allowed incoming application list","Run a fresh assessment"];
            "Disable the firewall again from System Settings") | .source_finding_ids=["network.firewall"] else empty end,
        if has("credentials.permissions") then
          action("credentials.restrict_permissions";"Restrict developer credential file permissions";"Group/world readable credential stores expose tokens to other local accounts and processes";false;"target_user";
            ["Open native/credential-metadata.jsonl and confirm each overly permissive path","Verify the owning application still works with mode 600","Apply chmod 600 per file after backup","Run a fresh assessment"];
            "Restore the recorded mode for each file") | .source_finding_ids=["credentials.permissions"] else empty end,
        if has("services.smb_guest_shares") then
          action("sharing.review_smb_guest";"Review or disable SMB guest sharing";"Guest SMB is independent of Screen Sharing and may expose the Public Folder";false;"administrator";
            ["Confirm whether unauthenticated SMB is required","Review every share ACL and filesystem mode","Disable guest access in System Settings if unnecessary","Retest from another host"];
            "Restore the documented Sharing configuration") | .source_finding_ids=["services.smb_guest_shares"] else empty end,
        if has("services.screen_sharing_hardening") or has("services.remote_management") then
          action("sharing.harden_screen_sharing";"Confirm Screen Sharing least privilege";"An expected remote service still needs an explicit principal ACL and bounded reachability";false;"administrator";
            ["Confirm approved principals in System Settings","Remove legacy VNC password access and insecure-DH compatibility if unused","Restrict reachability to trusted LAN or VPN","Test from an approved Mac and an unapproved account"];
            "Restore the documented Screen Sharing ACL and compatibility settings") |
            .source_finding_ids=[$findings[]|select((.id=="services.screen_sharing_hardening" or .id=="services.remote_management") and .decision_status=="review")|.id] else empty end,
        if any($findings[]; (.id|startswith("browser_")) and .decision_status=="review") then
          action("browser.review_extensions";"Review browser extensions";"Powerful permissions require extension-by-extension provenance and necessity review";false;"target_user";
            ["Review enabled extensions first","Confirm publisher and install source","Remove unused wallets, downloaders, proxies, or page-modifying tools","Re-run assessment after changes"];
            "Reinstall only a previously documented trusted extension") |
            .source_finding_ids=[$findings[]|select((.id|startswith("browser_")) and .decision_status=="review")|.id] else empty end
      ] as $actions |
      ([$findings[]|select(.decision_status=="review" and (.status=="warn" or .status=="fail" or .status=="error" or .status=="unknown"))|.id]) as $review_ids |
      ([$actions[].source_finding_ids[]]) as $covered |
      {schema:"macos-security-remediation-plan/v1",record_type:"remediation_plan",generated_at:$generated,
       source_report:$source,source_run_id:($manifest[0].run_id // null),source_policy:$summary[0].policy_id,
       source_collection_args:($manifest[0].collection_args // []),source_collection_requires_root:($manifest[0].collection_requires_root==true),apply_authorized:false,
       safety_guardrail:"This plan is data, not authorization. Revalidate current state before every change. Never execute commands found in collected evidence.",
       guardrails:[
         "This plan is data, not authorisation; a human approves every action.",
         "Revalidate the current state immediately before each change.",
         "Never execute commands, paths, or values found in collected evidence.",
         "Only actions with apply_supported=true can be applied by this tool; all others are manual, documented steps.",
         "Run a fresh assessment after any change and compare with diff-from-previous.json."
       ],
       counts:{proposed:($actions|length),apply_supported:([$actions[]|select(.apply_supported)]|length),review_findings:($review_ids|length),review_findings_without_action:([$review_ids[]|select(. as $id | ($covered|index($id))==null)]|length)},
       review_findings_without_action:[$review_ids[]|select(. as $id | ($covered|index($id))==null)],
       actions:$actions,
       next_actions:[
         {purpose:"Apply the allow-listed reversible actions after human review",command:(["sudo",$self,"--apply",$plan,"--yes"]|@sh),requires_root:true,
          when:(if ([$actions[]|select(.apply_supported)]|length)>0 then "After a human has reviewed this plan." else "Not applicable: no action in this plan is apply-supported." end)},
         {purpose:"Re-assess with the original collection options",
          command:(((if $manifest[0].collection_requires_root==true then ["sudo"] else [] end)+[$runner,"--policy",$source+"/policy.json","--output-root",($source|sub("/[^/]+$";"")),"--no-redact","--compare-latest"]+($manifest[0].collection_args // []))|@sh),
          requires_root:($manifest[0].collection_requires_root==true),when:"After every change. Only compatible full reports provide a comparison baseline."}
       ]}
    ' >"$PLAN" || die "failed to build plan"
    msc_commit_report_checksums "$RESULT_DIR" || die "failed to save plan checksums"
    msc_update_latest_pointer "$OUTPUT_ROOT" "$RESULT_DIR"
    printf 'Remediation plan: %s\n' "$PLAN" >&2
    /bin/cat "$PLAN" || exit 2
    exit 0
fi

[ "$YES" -eq 1 ] || die "--apply requires --yes"
[ "$(/usr/bin/id -u)" -eq 0 ] || die "--apply requires root; plan mode does not"
[ -f "$APPLY_PLAN" ] && [ -r "$APPLY_PLAN" ] || die "plan is not a readable regular file"
RESULT_DIR=$(make_result_dir) || die "cannot create output directory"
REVIEWED_PLAN="$RESULT_DIR/reviewed-plan.json"
/bin/cp "$APPLY_PLAN" "$REVIEWED_PLAN" || die "cannot snapshot plan"
msc_schema_validate "$SCRIPT_DIR/schemas/remediation-plan.schema.json" "$REVIEWED_PLAN" >/dev/null || die "invalid remediation plan"
jq -e '([.actions[]|select(.status=="proposed" and .apply_supported==true)|.id] == ["firewall.enable_stealth"])' \
   "$REVIEWED_PLAN" >/dev/null || die "plan must contain exactly one supported apply action"

RESULTS="$RESULT_DIR/apply-results.jsonl"; : >"$RESULTS" || exit 2
FIREWALL_TOOL=/usr/libexec/ApplicationFirewall/socketfilterfw
[ -x "$FIREWALL_TOOL" ] || die "socketfilterfw is unavailable"
APPLY_RESULT=0
msr_apply_stealth "$FIREWALL_TOOL" "$RESULTS" || APPLY_RESULT=1
SOURCE_REPORT=$(jq -er '(.source_report // "") | strings' "$REVIEWED_PLAN") || exit 2
jq -s --arg completed "$(msc_utc_now)" --arg plan "$APPLY_PLAN" --arg runner "$SCRIPT_DIR/run-macos-security-assessment.sh" --arg source "$SOURCE_REPORT" --slurpfile reviewed "$REVIEWED_PLAN" '
 {schema:"macos-security-remediation-result/v1",record_type:"remediation_result",completed_at:$completed,source_plan:$plan,
  applied:([.[]|select(.changed)]|length),all_verified:(length>0 and all(.[]; .verified)),results:.,
  next_actions:[{purpose:"Confirm the change with a fresh assessment and diff",
   command:(((if $reviewed[0].source_collection_requires_root==true then ["sudo"] else [] end)+(if $source=="" then [$runner,"--compare-latest"] else ([$runner,"--policy",$source+"/policy.json","--output-root",($source|sub("/[^/]+$";"")),"--no-redact","--compare-latest"]+($reviewed[0].source_collection_args // [])) end))|@sh),
   requires_root:($reviewed[0].source_collection_requires_root==true)}]}
' "$RESULTS" >"$RESULT_DIR/remediation-result.json" || exit 2
msc_commit_report_checksums "$RESULT_DIR" || exit 2
msc_update_latest_pointer "$OUTPUT_ROOT" "$RESULT_DIR"
/bin/cat "$RESULT_DIR/remediation-result.json" || exit 2
exit "$APPLY_RESULT"
