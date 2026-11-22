# SPDX-License-Identifier: MIT
# Minimal JSON Schema (draft 2020-12 subset) validator implemented in jq so
# the contracts in schemas/ are enforced without extra dependencies.
# Supported keywords: type, const, enum, required, properties, items,
# minItems, additionalProperties=false, minLength, minimum, maximum, pattern,
# allOf, anyOf, if/then/else.
# shellcheck disable=SC2034

if [ "${MSC_SCHEMA_LOADED:-0}" = "1" ]; then
    return 0
fi
MSC_SCHEMA_LOADED=1
MSC_SCHEMA_VERSION="1.0.0"

# jq program; $-prefixed names are jq variables, not shell expansions.
# shellcheck disable=SC2016
MSC_SCHEMA_JQ='
def matches_type($t):
  . as $v |
  if $t == "integer" then ($v|type) == "number" and (($v|floor) == $v)
  elif $t == "number" then ($v|type) == "number"
  else ($v|type) == $t end;

def validate($schema; $path):
  . as $v | ($schema // {}) as $s |
  [
    (if $s|has("type") then
        ([$s.type]|flatten) as $types |
        if any($types[]; . as $t | $v|matches_type($t)) then empty
        else "\($path): expected type \($types|join("|")), got \($v|type)" end
     else empty end),
    (if $s|has("const") then
        (if $v == $s.const then empty else "\($path): expected \($s.const|tojson), got \($v|tojson)" end)
     else empty end),
    (if $s|has("enum") then
        (if ($s.enum|index([$v])) != null then empty else "\($path): \($v|tojson) is not one of \($s.enum|tojson)" end)
     else empty end),
    (if ($s|has("minLength")) and ($v|type) == "string" then
        (if ($v|length) >= $s.minLength then empty else "\($path): shorter than \($s.minLength)" end)
     else empty end),
    (if ($s|has("minimum")) and ($v|type) == "number" then
        (if $v >= $s.minimum then empty else "\($path): \($v) is below minimum \($s.minimum)" end)
     else empty end),
    (if ($s|has("maximum")) and ($v|type) == "number" then
        (if $v <= $s.maximum then empty else "\($path): \($v) is above maximum \($s.maximum)" end)
     else empty end),
    (if ($s|has("pattern")) and ($v|type) == "string" then
        (if ($v|test($s.pattern)) then empty else "\($path): does not match \($s.pattern)" end)
     else empty end),
    (if ($v|type) == "object" then
        (($s.required // [])[] as $r | select(($v|has($r))|not) | "\($path): missing required property \($r)"),
        (($s.properties // {}) | to_entries[] | .key as $k | .value as $sub | select($v|has($k)) |
            ($v[$k] | validate($sub; "\($path).\($k)"))),
        (if $s.additionalProperties == false then
            ($v|keys[]) as $k | select((($s.properties // {})|has($k))|not) | "\($path): unexpected property \($k)"
         else empty end)
     else empty end),
    (if ($v|type) == "array" and ($s|has("items")) then
        ($v|to_entries[] | .key as $i | .value | validate($s.items; "\($path)[\($i)]"))
     else empty end),
    (if ($v|type) == "array" and ($s|has("minItems")) then
        (if ($v|length) >= $s.minItems then empty else "\($path): fewer than \($s.minItems) items" end)
     else empty end),
    (($s.allOf // [])[] as $sub | ($v|validate($sub; $path))),
    (if $s|has("if") then
        (if ([$v|validate($s.if; $path)]|length) == 0 then
            (if $s|has("then") then ($v|validate($s.then; $path)) else empty end)
         else
            (if $s|has("else") then ($v|validate($s.else; $path)) else empty end)
         end)
     else empty end),
    (if $s|has("anyOf") then
        (if any($s.anyOf[]; . as $sub | ([$v|validate($sub; $path)]|length) == 0) then empty
         else "\($path): no anyOf branch matched" end)
     else empty end)
  ] | .[];
'

# Usage: msc_schema_validate SCHEMA_FILE DATA_FILE
# DATA_FILE may hold one JSON document or JSONL; every top-level value is
# validated. Errors are printed one per line (at most 25); returns 1 when any
# value fails, 2 when the schema or data cannot be parsed.
msc_schema_validate() {
    _mss_schema=$1; _mss_data=$2
    [ -r "$_mss_schema" ] && [ -r "$_mss_data" ] || { printf 'schema or data unreadable: %s %s\n' "$_mss_schema" "$_mss_data"; return 2; }
    jq -e . "$_mss_schema" >/dev/null 2>&1 || { printf 'schema is not valid JSON: %s\n' "$_mss_schema"; return 2; }
    jq -c . "$_mss_data" >/dev/null 2>&1 || { printf 'data is not valid JSON: %s\n' "$_mss_data"; return 2; }
    _mss_errors=$(jq -r --slurpfile schema "$_mss_schema" "$MSC_SCHEMA_JQ"'validate($schema[0]; "value \(input_line_number)")' "$_mss_data" 2>&1 | /usr/bin/head -n 25)
    [ -z "$_mss_errors" ] && return 0
    printf '%s\n' "$_mss_errors"
    return 1
}

# Usage: msc_schema_name_for ARTIFACT_RELATIVE_PATH -> schema basename or ""
msc_schema_name_for() {
    case $1 in
        run-manifest.json) printf 'assessment-manifest' ;;
        agent-summary.json) printf 'agent-summary' ;;
        agent-context.json) printf 'agent-context' ;;
        coverage.jsonl|native/coverage.jsonl|adapters/coverage.jsonl) printf 'coverage' ;;
        coverage.json|native/coverage.json|adapters/coverage.json) printf 'coverage-summary' ;;
        observations.jsonl|native/observations.jsonl|adapters/observations.jsonl) printf 'observation' ;;
        findings.jsonl|native/findings.jsonl|adapters/findings.jsonl) printf 'finding' ;;
        diff-from-previous.json) printf 'diff' ;;
        evidence-index.json) printf 'evidence-index' ;;
        posture.jsonl) printf 'posture-record' ;;
        triage/report.jsonl) printf 'triage-record' ;;
        timeline.jsonl) printf 'event' ;;
        summary.json) printf 'monitor-summary' ;;
        remediation-plan.json) printf 'remediation-plan' ;;
        *) printf '' ;;
    esac
}
