#!/bin/sh
# SPDX-License-Identifier: MIT
# Fast, host-independent contract tests: every finding ID referenced by the
# remediation planner is produced by a collector, fixtures satisfy their
# schemas, the schema validator rejects drift, and self-tests pass.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && /bin/pwd -P)
TEST_TMP=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/msc-contract-test.XXXXXX")
trap '/bin/rm -rf "$TEST_TMP"' EXIT HUP INT TERM
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

. "$ROOT_DIR/lib/macos_security_common.sh"
. "$ROOT_DIR/lib/macos_security_evidence.sh"
. "$ROOT_DIR/lib/macos_security_schema.sh"
. "$ROOT_DIR/detectors/native.sh"

# 1. Remediation planner IDs must match producer IDs exactly (regression for
#    the firewall.stealth_mode / network.firewall_stealth mismatch).
/usr/bin/sed -n 's/.*has("\([^"]*\)").*/\1/p' "$ROOT_DIR/macos-security-remediation.sh" | /usr/bin/sort -u >"$TEST_TMP/planner-ids.txt"
[ -s "$TEST_TMP/planner-ids.txt" ] || fail "planner references no finding IDs"
{
  /usr/bin/sed -n -e 's/.*emit_finding "\([A-Za-z0-9._]*\)".*/\1/p' -e 's/^check_contains "\([A-Za-z0-9._]*\)".*/\1/p' "$ROOT_DIR/macos-security-posture.sh"
  /usr/bin/sed -n 's/.*emit_finding[_a-z]* \([A-Za-z0-9._]*\) .*/\1/p' "$ROOT_DIR/macos-security-triage.sh"
  /usr/bin/sed -n 's/.*mse_emit_finding "\$[A-Za-z_]*" \([A-Za-z0-9._]*\) .*/\1/p' "$ROOT_DIR/detectors/native.sh" "$ROOT_DIR/adapters"/*.sh "$ROOT_DIR/collectors/monitoring/correlate.sh"
} | /usr/bin/sort -u >"$TEST_TMP/producer-ids.txt"
while IFS= read -r planner_id; do
  /usr/bin/grep -qx "$planner_id" "$TEST_TMP/producer-ids.txt" || fail "remediation planner references unknown finding id: $planner_id"
done <"$TEST_TMP/planner-ids.txt"

# 2. Fixtures and generated records satisfy their schemas.
msc_schema_validate "$ROOT_DIR/schemas/observation.schema.json" "$ROOT_DIR/tests/fixtures/native-observations.jsonl" || fail "native observation fixture violates schema"
: >"$TEST_TMP/findings.jsonl"
msd_detect_native "$ROOT_DIR/tests/fixtures/native-observations.jsonl" "$TEST_TMP/findings.jsonl"
msc_schema_validate "$ROOT_DIR/schemas/finding.schema.json" "$TEST_TMP/findings.jsonl" || fail "native detector findings violate schema"
"$ROOT_DIR/collectors/monitoring/normalize-eslogger.sh" --input "$ROOT_DIR/tests/fixtures/eslogger.jsonl" --output "$TEST_TMP/timeline.jsonl"
msc_schema_validate "$ROOT_DIR/schemas/event.schema.json" "$TEST_TMP/timeline.jsonl" || fail "normalised events violate schema"
for policy in "$ROOT_DIR"/config/security-policy.json "$ROOT_DIR"/config/profiles/*.json; do
  msc_schema_validate "$ROOT_DIR/schemas/security-policy.schema.json" "$policy" || fail "policy violates schema: $policy"
done
mse_emit_coverage "$TEST_TMP/coverage.jsonl" posture collected "ok" true native "posture.jsonl"
mse_emit_coverage "$TEST_TMP/coverage.jsonl" adapter.clamav not_installed "missing" true clamav ""
mse_aggregate_coverage "$TEST_TMP/coverage.jsonl" "$TEST_TMP/coverage.json"
msc_schema_validate "$ROOT_DIR/schemas/coverage.schema.json" "$TEST_TMP/coverage.jsonl" || fail "coverage records violate schema"
msc_schema_validate "$ROOT_DIR/schemas/coverage-summary.schema.json" "$TEST_TMP/coverage.json" || fail "coverage summary violates schema"
jq -e '.complete_for_required_scope==false and .incomplete_required_components==["adapter.clamav"]' "$TEST_TMP/coverage.json" >/dev/null || fail "incomplete required components are not reported"

# 3. The validator must reject drift, not only accept good data.
printf '%s\n' '{"schema":"macos-security-finding/v1","record_type":"finding","source":"posture","id":"x","status":"WARN","severity":"high","confidence":"high","class":"configuration","title":"t","detail":"d","expected":false,"decision_status":"review","requires_confirmation":true,"evidence_trust":"untrusted_observations"}' >"$TEST_TMP/bad-finding.jsonl"
if msc_schema_validate "$ROOT_DIR/schemas/finding.schema.json" "$TEST_TMP/bad-finding.jsonl" >/dev/null; then fail "schema validator accepted an upper-case status"; fi
printf '%s\n' '{"schema":"macos-security-diff/v1","record_type":"assessment_diff","baseline_established":true,"previous_run":null,"added":[],"resolved":[],"changed":[],"extra":1}' >"$TEST_TMP/bad-diff.json"
if msc_schema_validate "$ROOT_DIR/schemas/diff.schema.json" "$TEST_TMP/bad-diff.json" >/dev/null; then fail "schema validator accepted an unexpected property"; fi

# 4. Stable identifiers and helper behaviour.
[ "$(msc_short_hash /Library/LaunchAgents/a.plist)" = "$(msc_short_hash /Library/LaunchAgents/a.plist)" ] || fail "short hash is not deterministic"
[ "$(msc_id_token 'Google Chrome Helper (GPU)')" = "Google_Chrome_Helper__GPU_" ] || fail "id token sanitisation"
[ "$(msc_regex_escape 'a.b[c]')" = 'a\.b\[c\]' ] || fail "regex escaping"
printf '%s\n' '{"a":1}' 'null' >"$TEST_TMP/nullable.jsonl"
msc_validate_jsonl "$TEST_TMP/nullable.jsonl" || fail "JSONL validator rejected a trailing null value"

# 5. Self-tests of every entry point are real checks, not constants.
"$ROOT_DIR/run-macos-security-assessment.sh" --self-test | jq -e '.status=="pass" and (.checks|length)>=8' >/dev/null || fail "runner self-test"
"$ROOT_DIR/validate-macos-security-report.sh" --self-test | jq -e '.status=="pass"' >/dev/null || fail "validator self-test"
"$ROOT_DIR/macos-security-triage.sh" --self-test | jq -e '.status=="pass"' >/dev/null || fail "triage self-test"
if "$ROOT_DIR/macos-security-triage.sh" --self-test --lookback-hours 0 >/dev/null 2>&1; then fail "triage accepted a zero lookback"; fi

printf '%s\n' 'PASS: planner/producer ID coupling, schema contracts, validator rejection, stable IDs, self-tests'
