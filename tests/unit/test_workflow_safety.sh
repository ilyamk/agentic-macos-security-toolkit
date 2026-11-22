#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
TEST_TMP=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/msc-workflow-test.XXXXXX")
trap '/bin/rm -rf "$TEST_TMP"' EXIT HUP INT TERM
. "$ROOT_DIR/lib/macos_security_common.sh"
. "$ROOT_DIR/lib/macos_security_reporting.sh"
. "$ROOT_DIR/lib/macos_security_remediation.sh"

[ "$(msc_application_firewall_mode 'Firewall is disabled. (State = 0)')" = disabled ]
[ "$(msc_application_firewall_mode 'Firewall is enabled. (State = 1)')" = enabled ]
[ "$(msc_application_firewall_mode 'Firewall is blocking all non-essential incoming connections. (State = 2)')" = blocks_nonessential ]
[ "$(msc_application_firewall_mode 'Unrecognised output')" = unknown ]
printf '%s\n' 'Started scanner SampleMalwareDetected' 'No malware was detected' 'Threat was not detected' >"$TEST_TMP/xprotect.log"
if msc_xprotect_log_has_event "$TEST_TMP/xprotect.log"; then exit 1; fi
printf '%s\n' 'Malware was detected.' >>"$TEST_TMP/xprotect.log"
msc_xprotect_log_has_event "$TEST_TMP/xprotect.log"
printf '%s\n' 'Event: xp_malware_remediated' >"$TEST_TMP/xprotect.log"
msc_xprotect_log_has_event "$TEST_TMP/xprotect.log"

if msc_run_timed_capture 1 "$TEST_TMP/out" "$TEST_TMP/err" "$TEST_TMP/marker" /bin/sleep 10; then
    exit 1
else
    [ "$?" -eq 124 ] && [ -f "$TEST_TMP/marker" ]
fi
msc_run_timed_capture 1 "$TEST_TMP/out" "$TEST_TMP/err" "$TEST_TMP/marker" /usr/bin/true
[ ! -e "$TEST_TMP/marker" ]
# The child stays in the command's process group after its immediate parent exits.
# shellcheck disable=SC2016
msc_run_timed_capture 4 "$TEST_TMP/out" "$TEST_TMP/err" "$TEST_TMP/marker" \
    /bin/sh -c '(/bin/sleep 1; : >"$1") &' sh "$TEST_TMP/delayed-write"
/bin/sleep 1.2
[ ! -e "$TEST_TMP/delayed-write" ]

/usr/bin/env PATH=/nonexistent "$ROOT_DIR/bin/macos-security" --help | /usr/bin/grep -q '^Usage:'
mkdir -p "$TEST_TMP/checkout/bin" "$TEST_TMP/checkout/lib" "$TEST_TMP/checkout/security-results/assessments/001" "$TEST_TMP/checkout/security-results/assessments/002"
cp "$ROOT_DIR/bin/macos-security" "$TEST_TMP/checkout/bin/"
cp "$ROOT_DIR/lib/macos_security_common.sh" "$TEST_TMP/checkout/lib/"
printf '%s\n' '{"complete":true}' >"$TEST_TMP/checkout/security-results/assessments/001/run-manifest.json"
printf '%s\n' checksum >"$TEST_TMP/checkout/security-results/assessments/001/SHA256SUMS"
printf '%s\n' '{"complete":false}' >"$TEST_TMP/checkout/security-results/assessments/002/run-manifest.json"
ln -s 002 "$TEST_TMP/checkout/security-results/assessments/latest"
[ "$("$TEST_TMP/checkout/bin/macos-security" latest assessments)" = "$(cd "$TEST_TMP/checkout/security-results/assessments/001" && /bin/pwd -P)" ]

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    "$ROOT_DIR/adapters/run.sh" --output "$TEST_TMP/candidates" --ids clamav --candidates "$TEST_TMP/missing" --no-auto-install >/dev/null
    jq -e '(.complete_for_required_scope|not) and any(.components[]; .component=="adapter.clamav" and .state=="error" and .required)' "$TEST_TMP/candidates/coverage.json" >/dev/null
    mkdir "$TEST_TMP/fake-bin"
    cat >"$TEST_TMP/fake-bin/clamscan" <<'EOF'
#!/bin/sh
if [ "$1" = --version ]; then printf '%s\n' 'fixture scanner'; exit 0; fi
for argument do
    case $argument in --file-list=*) /bin/cat "${argument#--file-list=}" >"$CANDIDATE_RECORD"; exit $? ;; esac
done
exit 2
EOF
    chmod 700 "$TEST_TMP/fake-bin/clamscan"
    printf '%s\n' 'fixture candidate' >"$TEST_TMP/candidate_files.txt"
    PATH="$TEST_TMP/fake-bin:$PATH" CANDIDATE_RECORD="$TEST_TMP/scanner-input" MSC_ALLOW_NETWORK=0 \
        "$ROOT_DIR/adapters/run.sh" --output "$TEST_TMP/offline-scan" --ids clamav --candidates "$TEST_TMP/candidate_files.txt" --no-auto-install >/dev/null
    /usr/bin/cmp -s "$TEST_TMP/candidate_files.txt" "$TEST_TMP/scanner-input"
    jq -e '.complete_for_required_scope' "$TEST_TMP/offline-scan/coverage.json" >/dev/null
fi

mkdir "$TEST_TMP/runs" "$TEST_TMP/runs/one" "$TEST_TMP/runs/two" "$TEST_TMP/runs/three"
for name in one two three; do
    printf '%s\n' '{"id":"known"}' >"$TEST_TMP/runs/$name/findings.jsonl"
done
printf '%s\n' '{"complete":true,"coverage_complete_for_required_scope":true,"comparison_scope_hash":"matching"}' >"$TEST_TMP/runs/one/run-manifest.json"
printf '%s\n' '{"complete":true,"coverage_complete_for_required_scope":false,"comparison_scope_hash":"matching"}' >"$TEST_TMP/runs/two/run-manifest.json"
printf '%s\n' '{"complete":true,"coverage_complete_for_required_scope":true,"comparison_scope_hash":"different"}' >"$TEST_TMP/runs/three/run-manifest.json"
[ "$(msr_find_comparison "$TEST_TMP/runs" matching /usr/bin/true)" = "$TEST_TMP/runs/one" ]
[ -z "$(msr_find_comparison "$TEST_TMP/runs" unmatched /usr/bin/true)" ]
printf '%s\n' '{"id":"one","status":"warn","decision_status":"review"}' '{"id":"two","status":"fail","decision_status":"review"}' >"$TEST_TMP/previous.jsonl"
printf '%s\n' '{"id":"one","status":"pass","decision_status":"no_action"}' >"$TEST_TMP/current.jsonl"
msr_build_diff "$TEST_TMP/current.jsonl" "$TEST_TMP/previous.jsonl" "$TEST_TMP/diff.json" one
jq -e '([.resolved[].id]==["one"]) and ([.not_observed[].id]==["two"])' "$TEST_TMP/diff.json" >/dev/null

cat >"$TEST_TMP/firewall" <<'EOF'
#!/bin/sh
case "$1" in
    --getstealthmode)
        case $(cat "$STEALTH_FIXTURE/state") in
            on) printf '%s\n' 'Stealth mode enabled' ;;
            off) printf '%s\n' 'Stealth mode disabled' ;;
            *) exit 6 ;;
        esac ;;
    --setstealthmode)
        : >"$STEALTH_FIXTURE/attempted"
        [ ! -f "$STEALTH_FIXTURE/fail" ] || exit 7
        printf '%s\n' on >"$STEALTH_FIXTURE/state" ;;
esac
EOF
chmod 700 "$TEST_TMP/firewall"
STEALTH_FIXTURE=$TEST_TMP; export STEALTH_FIXTURE
printf '%s\n' on >"$TEST_TMP/state"
msr_apply_stealth "$TEST_TMP/firewall" "$TEST_TMP/already.jsonl"
[ ! -e "$TEST_TMP/attempted" ]
jq -e '.verified and (.changed|not) and .rollback==null' "$TEST_TMP/already.jsonl" >/dev/null
printf '%s\n' off >"$TEST_TMP/state"
: >"$TEST_TMP/fail"
if msr_apply_stealth "$TEST_TMP/firewall" "$TEST_TMP/failed.jsonl"; then exit 1; fi
jq -e '(.verified|not) and .exit_code==7 and .rollback==null' "$TEST_TMP/failed.jsonl" >/dev/null
/bin/rm "$TEST_TMP/fail"
msr_apply_stealth "$TEST_TMP/firewall" "$TEST_TMP/changed.jsonl"
jq -e '.verified and .changed and (.rollback|type=="string")' "$TEST_TMP/changed.jsonl" >/dev/null

mkdir "$TEST_TMP/unsafe-report"
ln -s "$TEST_TMP/previous.jsonl" "$TEST_TMP/unsafe-report/evidence.jsonl"
if "$ROOT_DIR/validate-macos-security-report.sh" "$TEST_TMP/unsafe-report" >"$TEST_TMP/validation.json"; then exit 1; fi
jq -e '(.valid|not) and any(.errors[]; contains("unsafe"))' "$TEST_TMP/validation.json" >/dev/null

printf '%s\n' 'PASS: timeouts, compatible comparisons, non-mutating firewall fixtures and report isolation'
