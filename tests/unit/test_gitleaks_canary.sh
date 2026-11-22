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

scan() {
    "$ROOT_DIR/adapters/run.sh" --output "$TEST_TMP/$1" --ids gitleaks \
        --dev-target "$TEST_TMP/project" --no-auto-install >/dev/null
}
mkdir "$TEST_TMP/project" "$TEST_TMP/bin"
printf '%s\n' 'ordinary project data' >"$TEST_TMP/project/clean.txt"
scan clean
jq -e 'length==0' "$TEST_TMP/clean/gitleaks.json" >/dev/null
jq -e '.complete_for_required_scope' "$TEST_TMP/clean/coverage.json" >/dev/null

# Assemble a synthetic token at execution time. The project attempts to suppress it.
canary="ghp_$(printf %s abcde12345 ABCDE67890 fghij12345 FGHIJ6)"
printf '# gitleaks:allow\ncredential=%s # gitleaks:allow\n' "$canary" >"$TEST_TMP/project/data.txt"
printf '%s\n' '[extend]' 'useDefault = false' >"$TEST_TMP/project/.gitleaks.toml"
scan finding
jq -e 'any(.[]; .RuleID=="github-pat") and all(.[]; .Secret=="REDACTED" and (has("Match")|not))' \
    "$TEST_TMP/finding/gitleaks.json" >/dev/null
jq -e '.decision_status=="review"' "$TEST_TMP/finding/findings.jsonl" >/dev/null
if grep -Frq -- "$canary" "$TEST_TMP/finding"; then exit 1; fi

printf '%s\n' '#!/bin/sh' 'exit 8' >"$TEST_TMP/bin/gitleaks"
chmod 700 "$TEST_TMP/bin/gitleaks"
PATH="$TEST_TMP/bin:$PATH" scan error
jq -e '.complete_for_required_scope==false and .components[0].state=="error"' "$TEST_TMP/error/coverage.json" >/dev/null
[ ! -e "$TEST_TMP/error/gitleaks.json" ]
printf '%s\n' 'PASS: Gitleaks CLI, coverage, local suppression and secret redaction'
