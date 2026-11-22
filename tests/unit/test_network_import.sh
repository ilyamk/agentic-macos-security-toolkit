#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && /bin/pwd -P)
TEST_TMP=$(mktemp -d)
. "$ROOT_DIR/lib/macos_security_schema.sh"
trap 'rm -rf "$TEST_TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
cat >"$TEST_TMP/es.jsonl" <<'DATA'
{"time":"2026-01-01T00:00:02.404547610Z","event_type":9,"process":{"pid":4},"event":{"exec":{"target":{"audit_token":{"pid":33},"start_time":"2026-01-01T00:00:00.000100Z","path":"/private-for-fixture"}}}}
{"timestamp":"2026-01-01T00:00:02Z","event_type":"ES_EVENT_TYPE_NOTIFY_EXEC","process":{"pid":4},"event":{"exec":{"target":{"audit_token":{"pid":34},"start_time":{"tv_sec":1767225600,"tv_usec":100},"path":"/private-for-fixture"}}}}
DATA
"$ROOT_DIR/collectors/monitoring/normalize-eslogger.sh" --input "$TEST_TMP/es.jsonl" --output "$TEST_TMP/timeline.jsonl"
jq -se 'map(.data.pid)==[33,34] and all(.[]; .data.process_start_us==1767225600000100) and .[0].kind=="exec"' "$TEST_TMP/timeline.jsonl" >/dev/null
jq -cn '
    {schema:"macos-security-network-observation/v1",direction:"outbound",
     observed_at:"2026-01-01T00:00:05Z",protocol:"tcp",decision:"allowed",
     remote_scope:"public",pid:33,process_start_us:1767225600000100,
     remote_address:"private-network-value",payload:"private-payload-value"} |
    ., (.process_start_us+=1), (.observed_at="2026-01-01T00:10:00Z"), (.process_start_us=null)
' >"$TEST_TMP/network.jsonl"
"$ROOT_DIR/bin/macos-security" network import "$TEST_TMP/network.jsonl" --timeline "$TEST_TMP/timeline.jsonl" \
    --from 2026-01-01T00:00:00Z --to 2026-01-01T00:01:00Z >"$TEST_TMP/network-result.json"
jq -e '.input_count==4 and .event_count==3 and .out_of_window_count==1 and .correlated_count==1 and
    .collection_coverage=="unknown" and .events[0].correlation.method=="pid_and_process_start" and
    all(.events[1:][]; .correlation==null)' "$TEST_TMP/network-result.json" >/dev/null
if grep -q 'private-' "$TEST_TMP/network-result.json"; then exit 1; fi
msc_schema_validate "$ROOT_DIR/schemas/network-observation.schema.json" "$TEST_TMP/network.jsonl" >/dev/null
msc_schema_validate "$ROOT_DIR/schemas/network-import.schema.json" "$TEST_TMP/network-result.json" >/dev/null
cat "$TEST_TMP/timeline.jsonl" "$TEST_TMP/timeline.jsonl" >"$TEST_TMP/ambiguous.jsonl"
"$ROOT_DIR/bin/macos-security" network import "$TEST_TMP/network.jsonl" --timeline "$TEST_TMP/ambiguous.jsonl" |
    jq -e '.correlated_count==0' >/dev/null
printf '%s\n' 'not valid JSON' >"$TEST_TMP/invalid.jsonl"
if "$ROOT_DIR/bin/macos-security" network import "$TEST_TMP/invalid.jsonl" --timeline "$TEST_TMP/timeline.jsonl" >/dev/null 2>&1; then exit 1; fi
printf '%s\n' 'PASS: network import, PID reuse, window limits, schema input and redaction'
