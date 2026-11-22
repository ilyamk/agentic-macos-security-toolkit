#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

PROJECT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && /bin/pwd -P)
RUNNER="$PROJECT_DIR/run-macos-security-assessment.sh"
VALIDATOR="$PROJECT_DIR/validate-macos-security-report.sh"
REMEDIATION="$PROJECT_DIR/macos-security-remediation.sh"
TEST_TMP=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/macos-security-runner-test.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT HUP INT TERM
TEST_TMP=$(CDPATH='' cd -- "$TEST_TMP" && /bin/pwd -P)

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

[ -x "$RUNNER" ] || fail "runner is not executable"
/bin/sh -n "$RUNNER"
"$RUNNER" --help | /usr/bin/grep -q 'run-manifest.json' || \
    fail "runner help does not document its stdout contract"

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
    printf '%s\n' 'SKIP: live assessment runner test requires macOS'
    exit 0
fi

set +e
"$RUNNER" --quick --redact --output-root "$TEST_TMP/results" \
    --target-user "$(id -un)" --no-compare --no-auto-install --adapters none \
    >"$TEST_TMP/manifest.stdout.json" 2>"$TEST_TMP/runner.stderr"
runner_rc=$?
set -e
if [ "$runner_rc" -ne 0 ] && [ "$runner_rc" -ne 1 ]; then
    reason=$(/usr/bin/grep -E '^(Posture collection|Triage collection|Failed to |Artifact violates|Unsafe evidence|Schema violation)' "$TEST_TMP/runner.stderr" | /usr/bin/tail -n 1)
    fail "runner returned incomplete exit $runner_rc${reason:+ ($reason)}"
fi

if command -v jq >/dev/null 2>&1; then
    jq -e '.schema=="macos-security-assessment/v3" and .complete==true and .evidence_trust=="untrusted_observations" and .target_user=="<USER>" and .target_home=="~" and .report_dir=="." and .redaction_scope=="portable_summary"' \
        "$TEST_TMP/manifest.stdout.json" >/dev/null 2>&1 || \
        fail "runner manifest is invalid"
    run_dir="$TEST_TMP/results/$(jq -r '.run_id' "$TEST_TMP/manifest.stdout.json")"
else
    /usr/bin/plutil -convert json -o - -- "$TEST_TMP/manifest.stdout.json" >/dev/null || \
        fail "runner manifest is invalid"
    run_id=$(/usr/bin/sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p' "$TEST_TMP/manifest.stdout.json")
    run_dir="$TEST_TMP/results/$run_id"
fi

[ -d "$run_dir" ] || fail "timestamped report directory is missing"
[ ! -e "$run_dir/triage/evidence/candidate_files.txt" ] && [ ! -e "$run_dir/native" ] && [ ! -e "$run_dir/adapters" ] || fail "raw evidence survived redaction"
if /usr/bin/grep -FRq -- "$HOME/" "$run_dir"; then fail "redacted bundle contains a home path"; fi
jq -e '.command_templates==true and .report_dir=="." and .tool_root==null' "$run_dir/agent-context.json" >/dev/null || fail "redacted context retained local paths"
for artifact in agent-context.json agent-summary.json agent-report.md coverage.json coverage.jsonl observations.jsonl findings.jsonl diff-from-previous.json evidence-index.json policy.json posture-summary.json triage-summary.json; do
    [ -s "$run_dir/$artifact" ] || fail "missing v3 artifact: $artifact"
done
[ ! -e "$run_dir/timeline.jsonl" ] || fail "assessment must not emit an empty timeline.jsonl"
[ "$(CDPATH='' cd -- "$TEST_TMP/results/latest" && /bin/pwd -P)" = "$run_dir" ] || fail "latest pointer does not resolve to the run"
/usr/bin/cmp -s "$TEST_TMP/manifest.stdout.json" "$run_dir/run-manifest.json" || \
    fail "stdout does not match saved manifest"
(CDPATH='' cd -- "$run_dir" && /usr/bin/shasum -a 256 -c SHA256SUMS >/dev/null) || \
    fail "assessment integrity check failed"
jq -e '.next_actions_ref=="agent-context.json" and (.requires_review|type=="boolean") and (.coverage_complete_for_required_scope|type=="boolean")' \
    "$run_dir/run-manifest.json" >/dev/null || fail "manifest lacks agent hand-off fields"
jq -e '(.next_actions|length)>=5 and any(.next_actions[]; .recommended==true and (.command|contains("validate-macos-security-report.sh"))) and (.artifacts|has("timeline")|not)' \
    "$run_dir/agent-context.json" >/dev/null || fail "agent context next_actions are incomplete"
jq -e 'any(.components[]; .component=="posture" and .state=="collected" and .required) and any(.components[]; .component=="triage" and .required) and any(.components[]; .component=="posture.privileged")' \
    "$run_dir/coverage.json" >/dev/null || fail "coverage does not represent posture and triage layers"
/usr/bin/grep -q '^## Next actions' "$run_dir/agent-report.md" || fail "markdown report lacks next actions"
"$VALIDATOR" "$run_dir" | jq -e '.valid==true and .checks>=30' >/dev/null || \
    fail "deterministic report validator rejected the run"
"$VALIDATOR" "$TEST_TMP/results/latest" | jq -e '.valid==true' >/dev/null || \
    fail "validator does not accept the latest pointer"
# A tampered artifact must be rejected by both the hash manifest and the schema layer.
/bin/cp -R "$run_dir" "$TEST_TMP/tampered"
printf '%s\n' '{"schema":"macos-security-finding/v1","record_type":"finding","id":"tampered"}' >>"$TEST_TMP/tampered/findings.jsonl"
if "$VALIDATOR" "$TEST_TMP/tampered" >"$TEST_TMP/tampered.json" 2>/dev/null; then fail "validator accepted a tampered report"; fi
jq -e '.valid==false and (.errors|length)>=2 and any(.errors[]; contains("schema finding")) and any(.errors[]; contains("SHA256SUMS"))' "$TEST_TMP/tampered.json" >/dev/null || \
    fail "validator did not report both schema and integrity failures"
"$REMEDIATION" --plan "$run_dir" --output-root "$TEST_TMP/remediation" \
    >"$TEST_TMP/remediation-plan.stdout.json"
jq -e '.schema=="macos-security-remediation-plan/v1" and .apply_authorized==false and all(.actions[]; .requires_human_review==true and (.source_finding_ids|length)>0) and (.guardrails|length)>=4 and (.next_actions|length)>=2 and .source_run_id==(input.run_id)' \
    "$TEST_TMP/remediation-plan.stdout.json" "$run_dir/run-manifest.json" >/dev/null || fail "remediation plan guardrails are invalid"
. "$PROJECT_DIR/lib/macos_security_common.sh"
. "$PROJECT_DIR/lib/macos_security_schema.sh"
msc_schema_validate "$PROJECT_DIR/schemas/remediation-plan.schema.json" "$TEST_TMP/remediation-plan.stdout.json" >/dev/null || fail "remediation plan violates schema"
[ -L "$TEST_TMP/remediation/latest" ] || fail "remediation latest pointer missing"
# Every review finding referenced by the plan must exist in the source report.
jq -r '.actions[].source_finding_ids[]' "$TEST_TMP/remediation-plan.stdout.json" | while IFS= read -r finding_id; do
    jq -e --arg id "$finding_id" 'select(.id==$id and .decision_status=="review")' "$run_dir/findings.jsonl" >/dev/null || { printf 'plan references non-review finding: %s\n' "$finding_id" >&2; exit 1; }
done || fail "plan/finding coupling"

printf '%s\n' 'PASS: v3 runner, target context, agent artifacts, latest pointer, schema validator, tamper rejection, and plan-only remediation'
