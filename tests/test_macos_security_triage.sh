#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
AUDITOR="$SCRIPT_DIR/macos-security-triage.sh"
POSTURE="$SCRIPT_DIR/macos-security-posture.sh"
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/macos-security-triage-test.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT HUP INT TERM

/bin/sh -n "$AUDITOR"

SELF_TEST_OUTPUT=$(/bin/sh "$AUDITOR" --self-test)
printf '%s\n' "$SELF_TEST_OUTPUT" | /usr/bin/grep -q '"status":"pass"'

if command -v plutil >/dev/null 2>&1; then
  printf '%s\n' "$SELF_TEST_OUTPUT" | plutil -convert json -o - -- - >/dev/null
fi

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x -s sh "$SCRIPT_DIR/lib/macos_security_common.sh" \
    "$SCRIPT_DIR/lib/macos_security_dependencies.sh" "$SCRIPT_DIR/lib/macos_security_schema.sh" \
    "$POSTURE" "$AUDITOR" "$0"
else
  printf '%s\n' 'shellcheck not installed; skipped static lint.' >&2
fi

if [ "$(uname -s)" = "Darwin" ]; then
  "$POSTURE" --quick --redact --target-user "$(id -un)" --output "$TEST_TMP/posture" >"$TEST_TMP/posture.stdout"
  [ ! -s "$TEST_TMP/posture.stdout" ]
  [ "$(/usr/bin/stat -f '%Lp' "$TEST_TMP/posture")" = 700 ]
  [ "$(/usr/bin/stat -f '%Lp' "$TEST_TMP/posture/posture.jsonl")" = 600 ]
  set +e
  "$AUDITOR" --posture-report "$TEST_TMP/posture/posture.jsonl" --lookback-hours 1 \
    --target-user "$(id -un)" --output "$TEST_TMP/triage" >"$TEST_TMP/stdout.jsonl" 2>"$TEST_TMP/stderr.txt"
  triage_rc=$?
  set -e
  [ "$triage_rc" -eq 0 ] || [ "$triage_rc" -eq 1 ] || {
    printf 'triage integration failed with exit %s\n' "$triage_rc" >&2
    exit 1
  }
  if command -v jq >/dev/null 2>&1; then
    [ ! -e "$TEST_TMP/triage/evidence/background_tasks.txt" ]
    jq -e -s 'any(.[]; .record_type=="inventory" and .id=="background_tasks" and (.title|contains("skipped")))' "$TEST_TMP/triage/report.jsonl" >/dev/null
    jq -e . "$TEST_TMP/triage/report.jsonl" >/dev/null
    jq -e . "$TEST_TMP/triage/summary.json" >/dev/null
    jq -e 'select(.record_type=="inventory" and .id=="posture")' \
      "$TEST_TMP/triage/report.jsonl" >/dev/null
    jq -e 'select(.record_type=="meta") | .schema=="macos-security-triage/v3" and .target_user==env.USER and .evidence_trust=="untrusted_observations"' \
      "$TEST_TMP/triage/report.jsonl" >/dev/null
    [ -f "$TEST_TMP/triage/evidence/network_exposure.jsonl" ] || {
      printf '%s\n' 'normalized network exposure evidence is missing' >&2; exit 1;
    }
    jq -e -s 'all(.[]; (.scope|IN("loopback","lan_or_vpn","interface")) and .internet_reachability=="unknown_not_tested")' \
      "$TEST_TMP/triage/evidence/network_exposure.jsonl" >/dev/null
    expected_launch_count=$(
      for launch_dir in /Library/LaunchAgents /Library/LaunchDaemons "${HOME:-/var/empty}/Library/LaunchAgents"; do
        [ -d "$launch_dir" ] || continue
        /usr/bin/find -x "$launch_dir" -type f -name '*.plist' -print 2>/dev/null
      done | /usr/bin/sort -u | wc -l | tr -d ' '
    )
    launch_count=$(wc -l <"$TEST_TMP/triage/evidence/launch_queue.txt" | tr -d ' ')
    [ "$launch_count" -eq "$expected_launch_count" ] || {
      printf 'triage launchd inventory count mismatch: expected=%s actual=%s\n' \
        "$expected_launch_count" "$launch_count" >&2
      exit 1
    }
    if jq -e 'select(.id=="sip_enabled" or .id=="filevault" or .id=="gatekeeper")' \
      "$TEST_TMP/triage/report.jsonl" >/dev/null; then
      printf '%s\n' 'triage duplicated a delegated baseline finding' >&2
      exit 1
    fi
    # IDs must be stable across runs: no PID or loop counter suffixes, no duplicates.
    jq -e -s '[.[]|select(.record_type=="finding")] | (map(.id)|length)==(map(.id)|unique|length) and all(.[]; .id|test("^(listener_[A-Za-z0-9._-]+_[0-9]+|persistence_[a-z]+_[0-9a-f]{12}|process_path_[0-9a-f]{12}|[a-z_]+)$"))' \
      "$TEST_TMP/triage/report.jsonl" >/dev/null || {
      printf '%s\n' 'triage finding IDs are not stable/unique' >&2; exit 1;
    }
    jq -e -s 'all(.[]; .schema=="macos-security-triage/v3")' "$TEST_TMP/triage/report.jsonl" >/dev/null
    # shellcheck source=lib/macos_security_schema.sh
    . "$SCRIPT_DIR/lib/macos_security_schema.sh"
    msc_schema_validate "$SCRIPT_DIR/schemas/triage-record.schema.json" "$TEST_TMP/triage/report.jsonl" >/dev/null || {
      printf '%s\n' 'triage report violates triage-record schema' >&2; exit 1;
    }
    msc_schema_validate "$SCRIPT_DIR/schemas/posture-record.schema.json" "$TEST_TMP/posture/posture.jsonl" >/dev/null || {
      printf '%s\n' 'posture report violates posture-record schema' >&2; exit 1;
    }
  fi
  (CDPATH='' cd -- "$TEST_TMP/triage" && shasum -a 256 -c SHA256SUMS >/dev/null)
fi

printf '%s\n' 'PASS: triage syntax, helpers, delegation, JSONL, and evidence integrity'
