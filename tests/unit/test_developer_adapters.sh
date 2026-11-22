#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir "$TEST_TMP/bin" "$TEST_TMP/project"
SCAN_TARGET=$TEST_TMP/project
SCAN_CALLS=$TEST_TMP/calls
export SCAN_TARGET SCAN_CALLS

cat >"$TEST_TMP/bin/osv-scanner" <<'FAKE'
#!/bin/sh
[ "$*" = "scan source --recursive --allow-no-lockfiles --format json --verbosity error $SCAN_TARGET" ] || exit 8
printf '%s\n' osv >>"$SCAN_CALLS"
case $SCAN_CASE in
    clean) printf '%s\n' '{"results":null}' ;;
    findings) printf '%s\n' '{"results":[{"packages":[{"vulnerabilities":[{"id":"FIXTURE"}]}]}]}'; exit 1 ;;
    invalid) printf '%s\n' '{"wrong_key":[]}' ;;
esac
FAKE
cat >"$TEST_TMP/bin/trivy" <<'FAKE'
#!/bin/sh
[ "$*" = "filesystem --format json --scanners vuln,misconfig --quiet $SCAN_TARGET" ] || exit 8
printf '%s\n' trivy >>"$SCAN_CALLS"
case $SCAN_CASE in
    clean) printf '%s\n' '{"SchemaVersion":2}' ;;
    findings) printf '%s\n' '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{}],"Misconfigurations":[{}]}]}' ;;
    invalid) printf '%s\n' '{"SchemaVersion":9,"Results":[]}' ;;
esac
FAKE
chmod 700 "$TEST_TMP/bin/osv-scanner" "$TEST_TMP/bin/trivy"
PATH="$TEST_TMP/bin:$PATH"
export PATH SCAN_CASE
scan() {
    MSC_ALLOW_NETWORK="$2" "$ROOT_DIR/adapters/run.sh" --output "$TEST_TMP/$1" \
        --ids osv-scanner,trivy --dev-target "$SCAN_TARGET" --no-auto-install >/dev/null
}
SCAN_CASE=clean
scan offline 0
[ ! -e "$SCAN_CALLS" ]
jq -e 'all(.components[]; .state=="not_requested") and (.complete_for_required_scope|not)' "$TEST_TMP/offline/coverage.json" >/dev/null
scan clean 1
jq -e '.complete_for_required_scope' "$TEST_TMP/clean/coverage.json" >/dev/null
for report in "$TEST_TMP/clean/findings.jsonl" "$TEST_TMP/offline/findings.jsonl"; do
    jq -se 'all(.[]; .decision_status=="no_action")' "$report" >/dev/null
done
SCAN_CASE=findings
scan findings 1
jq -se 'length==2 and all(.[]; .decision_status=="review")' "$TEST_TMP/findings/findings.jsonl" >/dev/null
jq -se 'any(.[]; .data.vulnerability_records==1) and any(.[]; .data.finding_count==2)' "$TEST_TMP/findings/observations.jsonl" >/dev/null
SCAN_CASE=invalid
scan invalid 1
jq -e 'all(.components[]; .state=="error") and (.complete_for_required_scope|not)' "$TEST_TMP/invalid/coverage.json" >/dev/null
[ ! -s "$TEST_TMP/invalid/findings.jsonl" ]
[ "$(wc -l <"$SCAN_CALLS" | tr -d ' ')" -eq 6 ]
printf '%s\n' 'PASS: developer scanner arguments, offline boundary and JSON contracts'
