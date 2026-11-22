#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")
AUDITOR="$PROJECT_DIR/macos-security-posture.sh"
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/macos-security-posture-test.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

[ -x "$AUDITOR" ] || fail "collector is not executable"

"$AUDITOR" --help | grep -q 'JSONL' || fail "help output missing JSONL contract"
"$AUDITOR" --version | grep -Eq '[0-9]+\.[0-9]+\.[0-9]+' || fail "version output invalid"

if "$AUDITOR" --not-a-real-option >"$TEST_TMP/invalid.out" 2>"$TEST_TMP/invalid.err"; then
    fail "invalid option unexpectedly succeeded"
else
    rc=$?
    [ "$rc" -eq 64 ] || fail "invalid option returned $rc instead of 64"
fi

if [ "$(uname -s)" != "Darwin" ]; then
    printf 'SKIP: live collector test requires macOS\n'
    exit 0
fi

"$AUDITOR" --quick --redact --target-user "$(id -un)" >"$TEST_TMP/report.jsonl" 2>"$TEST_TMP/report.err"
[ -s "$TEST_TMP/report.jsonl" ] || fail "report is empty"

if command -v jq >/dev/null 2>&1; then
    jq -e . "$TEST_TMP/report.jsonl" >/dev/null || fail "one or more JSONL records are invalid"
    [ "$(jq -r 'select(.record_type=="meta") | .record_type' "$TEST_TMP/report.jsonl" | wc -l | tr -d ' ')" -eq 1 ] || fail "meta record missing or duplicated"
    [ "$(jq -r 'select(.record_type=="summary") | .record_type' "$TEST_TMP/report.jsonl" | wc -l | tr -d ' ')" -eq 1 ] || fail "summary record missing or duplicated"
    jq -e 'select(.record_type=="meta") | .schema_version=="3.0" and .target_user=="<USER>" and .evidence_trust=="untrusted_observations"' "$TEST_TMP/report.jsonl" >/dev/null || fail "v3 target/evidence context missing"
    for id in platform.sip platform.authenticated_root storage.filevault platform.gatekeeper network.firewall; do
        jq -e --arg id "$id" 'select(.record_type=="finding" and .id==$id)' "$TEST_TMP/report.jsonl" >/dev/null || fail "required finding missing: $id"
    done
else
    grep -q '"record_type":"meta"' "$TEST_TMP/report.jsonl" || fail "meta record missing"
    grep -q '"record_type":"summary"' "$TEST_TMP/report.jsonl" || fail "summary record missing"
fi

grep -q '"hostname":"<HOST>"' "$TEST_TMP/report.jsonl" || fail "redacted host marker missing"
real_host=$(hostname)
real_user=$(id -un)
if [ -n "$real_host" ] && grep -Fq "$real_host" "$TEST_TMP/report.jsonl"; then
    fail "hostname leaked from redacted report"
fi
if [ -n "$real_user" ] && grep -Fq "/Users/$real_user" "$TEST_TMP/report.jsonl"; then
    fail "user home path leaked from redacted report"
fi
if [ -n "$real_user" ] && grep -Fq "\"$real_user\"" "$TEST_TMP/report.jsonl"; then
    fail "user name leaked as a JSON value from redacted report"
fi
# Redaction runs through sed for every record; a broken expression would
# silently empty the evidence and only show up on stderr.
if grep -Eq 'sed:|RE error' "$TEST_TMP/report.err"; then
    fail "redaction pipeline reported errors: $(head -n 1 "$TEST_TMP/report.err")"
fi
printf 'PASS: collector CLI and live JSONL report validated\n'
