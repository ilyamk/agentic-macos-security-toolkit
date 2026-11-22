#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
. "$ROOT_DIR/lib/macos_security_schema.sh"
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir "$TEST_TMP/suite" "$TEST_TMP/staging" "$TEST_TMP/output"
export TMPDIR="$TEST_TMP/staging"
suite=$TEST_TMP/suite
cp -R "$ROOT_DIR/config" "$ROOT_DIR/lib" "$ROOT_DIR/schemas" \
    "$ROOT_DIR/detectors" "$ROOT_DIR/run-macos-security-assessment.sh" "$suite/"
mkdir -p "$suite/collectors/native" "$suite/adapters"
printf '%s\n' '#!/bin/sh' 'exit 8' >"$suite/adapters/run.sh"
canary='private-release-canary'
export CANARY=$canary
jq --arg private "$CANARY" '.policy_id=$private | .threat_model.assumptions=[$private]' \
    "$suite/config/security-policy.json" >"$TEST_TMP/policy.json"

cat >"$suite/macos-security-posture.sh" <<'FAKE'
#!/bin/sh
case ${ASSESS_CASE:-good} in
    fail) printf '%s\n' "$CANARY"; exit 8 ;;
    signal)
        trap '' TERM
        : >"$ASSESS_READY"
        exec /bin/sleep 30
        ;;
esac
jq -cn --arg p "$CANARY" '
    ({record_type:"meta",generated_at_utc:"2026-01-02T00:00:00Z",target_user:$p,hostname:$p,target_home:("/Users/"+$p),reference_patch_version:"26.6.2",evidence_trust:"untrusted_observations"},
     {record_type:"finding",id:"fixture.posture",category:"system",status:"PASS",severity:"none",title:"Synthetic posture",summary:$p,evidence:$p,recommendation:$p,reference:$p},
     {record_type:"evidence",id:"fixture.evidence",category:"system",title:"Synthetic evidence",collection_state:"collected",sensitivity:"high",requires_root:false,source:$p,data:$p,error:$p,exit_code:0},
     {record_type:"evidence",id:"recovery.time_machine",category:"recovery",title:"Synthetic backup",collection_state:"collected",sensitivity:"high",requires_root:false,source:"tmutil",data:("/Synthetic/"+$p+"/2026-01-01-120000.backup"),error:"",exit_code:0},
     {record_type:"summary",completed_at_utc:"2026-01-01T00:00:00Z",findings:{unknown:0},evidence:{denied:0,timeouts:0}})
    + {schema_version:"3.0"}'
FAKE
cat >"$suite/macos-security-triage.sh" <<'FAKE'
#!/bin/sh
while [ "$1" != --output ]; do shift; done
output=$2
mkdir -p "$output/evidence"
printf '%s\n' "$CANARY" >"$output/evidence/candidate_files.txt"
jq -cn --arg p "$CANARY" --arg title "${FIXTURE_TITLE:-Synthetic listener}" '
    ({record_type:"meta",target_user:$p,run_id:$p,report_dir:("/Users/"+$p)},
     {record_type:"finding",id:("listener_"+$p+"_1234"),category:"network",severity:"low",confidence:"medium",status:"warn",class:"configuration",title:$title,detail:$p,evidence:"evidence/candidate_files.txt",remediation:$p},
     {record_type:"summary",run_id:$p,report_dir:("/Users/"+$p),overall:"low"})
    + {schema:"macos-security-triage/v3"}' >"$output/report.jsonl"
jq -c 'select(.record_type=="summary")' "$output/report.jsonl" >"$output/summary.json"
cat "$output/report.jsonl"
FAKE
cat >"$suite/collectors/native/run.sh" <<'FAKE'
#!/bin/sh
mkdir "$2"
jq -cn --arg p "$CANARY" '{schema:"macos-security-observation/v1",record_type:"observation",observed_at:"2026-01-01T00:00:00Z",id:"fixture.native",category:"system",state:"collected",summary:$p,evidence_ref:$p,sensitivity:"high",data:{private_value:$p},evidence_trust:"untrusted_observations"}' >"$2/observations.jsonl"
: >"$2/coverage.jsonl"
: >"$2/findings.jsonl"
FAKE
chmod 700 "$suite/macos-security-posture.sh" "$suite/macos-security-triage.sh" \
    "$suite/adapters/run.sh" "$suite/collectors/native/run.sh"

run() {
    exec "$suite/run-macos-security-assessment.sh" --quick --redact --policy "$TEST_TMP/policy.json" \
        --output-root "$TEST_TMP/output" --no-compare --no-auto-install --adapters none "$@"
}
assert_clean_staging() {
    [ -z "$(ls -A "$TMPDIR")" ]
    [ -z "$(find "$TEST_TMP/output" -name '.latest.*' -print)" ]
}

(run) >"$TEST_TMP/first.json" 2>"$TEST_TMP/first.stderr" &
first=$!
(run) >"$TEST_TMP/second.json" 2>"$TEST_TMP/second.stderr" &
second=$!
wait "$first" || { cat "$TEST_TMP/first.stderr" >&2; exit 1; }
wait "$second" || { cat "$TEST_TMP/second.stderr" >&2; exit 1; }
a=$(jq -er .run_id "$TEST_TMP/first.json"); b=$(jq -er .run_id "$TEST_TMP/second.json")
[ "$a" != "$b" ]
for id in "$a" "$b"; do
    report=$TEST_TMP/output/$id
    "$ROOT_DIR/validate-macos-security-report.sh" "$report" | jq -e .valid >/dev/null
    if grep -Frq -- "$CANARY" "$report"; then printf '%s\n' 'Synthetic private data survived export.' >&2; exit 1; fi
    jq -se 'any(.[]; .id|startswith("redacted.triage."))' "$report/findings.jsonl" >/dev/null
    [ ! -e "$report/triage/evidence/candidate_files.txt" ]
done
latest=$(readlink "$TEST_TMP/output/latest")
case $latest in "$a"|"$b") ;; *) exit 1 ;; esac
assert_clean_staging

result=0
(ASSESS_CASE=fail; export ASSESS_CASE; run) >"$TEST_TMP/failure.out" 2>"$TEST_TMP/failure.err" || result=$?
[ "$result" -eq 2 ] && [ ! -s "$TEST_TMP/failure.out" ]
assert_clean_staging
[ "$(readlink "$TEST_TMP/output/latest")" = "$latest" ]

export ASSESS_READY="$TEST_TMP/ready"
(ASSESS_CASE=signal; export ASSESS_CASE; run) >"$TEST_TMP/signal.out" 2>"$TEST_TMP/signal.err" &
pending=$!
tries=0
until [ -f "$ASSESS_READY" ]; do
    tries=$((tries+1)); [ "$tries" -le 50 ] || { kill "$pending" 2>/dev/null || true; wait "$pending" || true; exit 1; }
    sleep 0.1
done
kill -TERM "$pending"
result=0
wait "$pending" || result=$?
[ "$result" -eq 143 ] && [ ! -s "$TEST_TMP/signal.out" ]
assert_clean_staging
[ "$(readlink "$TEST_TMP/output/latest")" = "$latest" ]

(FIXTURE_TITLE=$CANARY; export FIXTURE_TITLE; run --no-redact) >"$TEST_TMP/full.json" 2>"$TEST_TMP/full.stderr" || { cat "$TEST_TMP/full.stderr" >&2; exit 1; }
full="$TEST_TMP/output/$(jq -er .run_id "$TEST_TMP/full.json")"
cli=$ROOT_DIR/bin/macos-security
grep -Fq -- "$CANARY" "$full/findings.jsonl"
"$cli" report export "$full" --audience agent --output "$TEST_TMP/export.json"
jq -e '.review_count==1 and .findings[0].action.id=="review-finding" and .findings[0].action.mutates==false' \
    "$TEST_TMP/export.json" >/dev/null
if grep -Fq -- "$CANARY" "$TEST_TMP/export.json"; then exit 1; fi
digest=$(jq -er .bundle_sha256 "$TEST_TMP/export.json")
ordinal=$(jq -er '.findings[0].action.arguments.ordinal' "$TEST_TMP/export.json")
"$cli" report action "$full" --bundle "$digest" review-finding "$ordinal" >"$TEST_TMP/action.json"
jq -e '.action=="review-finding" and .finding.class=="configuration"' "$TEST_TMP/action.json" >/dev/null
if grep -Fq -- "$CANARY" "$TEST_TMP/action.json"; then exit 1; fi
"$cli" report action "$full" --bundle "$digest" review-coverage | jq -e '.action=="review-coverage" and (.coverage|length)>0' >/dev/null
if "$cli" report action "$full" --bundle "$digest" run "echo fixture" >/dev/null 2>&1; then exit 1; fi
if "$cli" report action "$TEST_TMP/output/$a" --bundle "$digest" review-coverage >/dev/null 2>&1; then exit 1; fi
git init -q "$TEST_TMP/checkout"
if "$cli" report export "$full" --audience agent --output "$TEST_TMP/checkout/export.json" >/dev/null 2>&1; then exit 1; fi
[ ! -e "$TEST_TMP/checkout/export.json" ]

printf '%s\n' 'Disposable backup sample' >"$TEST_TMP/original"
cp "$TEST_TMP/original" "$TEST_TMP/restored"
"$cli" recovery record-drill "$TEST_TMP/original" "$TEST_TMP/restored" --output "$TEST_TMP/drill.json"
"$cli" recovery check --report "$full" --drill "$TEST_TMP/drill.json" >"$TEST_TMP/recovery.json"
jq -e '.time_machine.state=="observed" and .time_machine.backup_date=="2026-01-01" and
    .recorded_drill.sample_matches' "$TEST_TMP/recovery.json" >/dev/null
msc_schema_validate "$ROOT_DIR/schemas/recovery-drill.schema.json" "$TEST_TMP/drill.json" >/dev/null
msc_schema_validate "$ROOT_DIR/schemas/recovery-check.schema.json" "$TEST_TMP/recovery.json" >/dev/null
if grep -Fq -- "$CANARY" "$TEST_TMP/recovery.json"; then exit 1; fi
if "$cli" recovery record-drill "$TEST_TMP/original" "$TEST_TMP/original" >/dev/null 2>&1; then exit 1; fi
printf '\n' >>"$full/findings.jsonl"
if "$cli" report export "$full" --audience agent >/dev/null 2>&1; then exit 1; fi
assert_clean_staging
printf '%s\n' 'PASS: parallel portable assessments, publication, cleanup after child errors and TERM'
