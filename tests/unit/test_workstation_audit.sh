#!/bin/sh
# SPDX-License-Identifier: MIT
# Host-free tests for tools/workstation-audit/workstation-audit.sh: fixture
# homes, a fake brew and gh, schema validation, exit codes and privacy.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
AUDIT="$ROOT_DIR/tools/workstation-audit/workstation-audit.sh"
FX="$ROOT_DIR/tests/fixtures/workstation-audit"
SCHEMA="$ROOT_DIR/schemas/workstation-audit-record.schema.json"
T=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/msc-workstation-audit-test.XXXXXX")
T=$(CDPATH='' cd -- "$T" && /bin/pwd -P)
cleanup() { /bin/rm -rf "$T"; }
# Invoked by the EXIT trap.
# shellcheck disable=SC2329
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

. "$ROOT_DIR/lib/macos_security_common.sh"
. "$ROOT_DIR/lib/macos_security_schema.sh"

ALL_IDS="HB-01 HB-02 HB-03 HB-04 HB-05 HB-06 HB-07 HB-08 HB-09 HB-10 HB-11 HB-12 NPM-01 NPM-02 NPM-03 NPM-04 NPM-05 PNPM-01 PNPM-02 NODE-01 NODE-02 NODE-03 UV-01 SHELL-01 SHELL-02 OSEE-01 OSEE-02 OSEE-03 TCC-01 AGENT-01"

# Fake binaries only: the host's pnpm, node, gh and brew must not be visible.
/bin/mkdir -p "$T/bin" "$T/apps/LuLu.app" "$T/apps/BlockBlock.app" "$T/apps/KnockKnock.app" "$T/empty"
/bin/ln -s "$FX/bin/brew" "$T/bin/brew"
/bin/ln -s "$FX/bin/gh" "$T/bin/gh"

# Usage: make_home NAME -> $T/NAME/home with dot-* renamed, and $T/NAME/prefix.
make_home() {
    /bin/mkdir -p "$T/$1/prefix/bin"
    /bin/cp -R "$FX/$1/home" "$T/$1/home"
    for _p in "$T/$1/home"/dot-*; do
        [ -e "$_p" ] || continue
        /bin/mv "$_p" "$T/$1/home/.${_p##*/dot-}"
    done
}
# Usage: make_node HOME VERSION new|old
make_node() {
    _npm="$1/.nvm/versions/node/$2/lib/node_modules/npm"
    /bin/mkdir -p "$_npm/node_modules/@npmcli/config/lib/definitions" "$1/.nvm/versions/node/$2/bin"
    if [ "$3" = new ]; then
        printf '{"version":"11.19.0"}\n' >"$_npm/package.json"
        printf "%s\n" "  'min-release-age': {}," "  'strict-allow-scripts': {}," >"$_npm/node_modules/@npmcli/config/lib/definitions/definitions.js"
    else
        printf '{"version":"10.9.0"}\n' >"$_npm/package.json"
        printf "%s\n" "  'ignore-scripts': {}," >"$_npm/node_modules/@npmcli/config/lib/definitions/definitions.js"
    fi
}

make_home hardened
make_home weak
make_node "$T/hardened/home" v24.1.0 new
make_node "$T/weak/home" v22.1.0 old
make_node "$T/weak/home" v22.2.0 new
printf '#!/bin/sh\nexit 0\n' >"$T/hardened/prefix/bin/pnpm"; /bin/chmod 755 "$T/hardened/prefix/bin/pnpm"
TCC_TABLE="create table access (service text, client text, client_type integer, auth_value integer);"
/usr/bin/sqlite3 "$T/tcc-ok.db" "$TCC_TABLE insert into access values ('kTCCServiceSystemPolicyAllFiles','com.objective-see.knockknock',0,2); insert into access values ('kTCCServiceSystemPolicyAllFiles','com.googlecode.iterm2',0,0);"
/usr/bin/sqlite3 "$T/tcc-bad.db" "$TCC_TABLE insert into access values ('kTCCServiceSystemPolicyAllFiles','com.googlecode.iterm2',0,2);"

# Usage: run NAME OUTFILE [extra args...]; sets RC. WA_EXTRA_ENV adds one VAR=value.
run() {
    _name=$1; _out=$2; shift 2
    set +e
    /usr/bin/env -i HOME="$T/$_name/home" TMPDIR="$T" PATH="$T/bin:/usr/bin:/bin" \
        WA_FAKE_BREW_DATA="${WA_BREW_DATA:-$FX/$_name/brew}" WA_FAKE_BREW_PREFIX="$T/$_name/prefix" WA_FAKE_BREW_LOG="$T/brew.log" \
        "${WA_EXTRA_ENV:-WA_NONE=1}" \
        "$AUDIT" --home "$T/$_name/home" --brew "$T/bin/brew" --apps "$T/apps" --tcc-db "$T/tcc-ok.db" \
        --system-brew-env "$T/empty/brew.env" "$@" >"$_out" 2>"$_out.err"
    RC=$?
    set -e
}
statuses() { jq -r --arg s "$2" 'select(.status==$s) | .id' "$1" | /usr/bin/sort | /usr/bin/paste -sd ' ' -; }

# 1. Hardened home: valid records, every registry ID exactly once, no warn/fail, exit 0.
run hardened "$T/hardened.jsonl" --json
[ "$RC" -eq 0 ] || fail "hardened run exit $RC (warn: $(statuses "$T/hardened.jsonl" warn); stderr: $(/bin/cat "$T/hardened.jsonl.err"))"
msc_schema_validate "$SCHEMA" "$T/hardened.jsonl" || fail "hardened records violate schema"
[ "$(jq -r .id "$T/hardened.jsonl" | /usr/bin/paste -sd ' ' -)" = "$ALL_IDS" ] || fail "hardened run does not emit every registry ID exactly once in order"
for _id in HB-01 HB-02 HB-03 HB-04 HB-05 HB-06 HB-07 HB-08 HB-09 HB-10 HB-11 HB-12 NPM-01 NPM-02 NPM-03 NPM-04 NPM-05 PNPM-01 PNPM-02 NODE-01 NODE-02 UV-01 SHELL-02 OSEE-03 TCC-01 AGENT-01; do
    jq -e --arg id "$_id" 'select(.id==$id) | .status=="pass"' "$T/hardened.jsonl" >/dev/null || fail "hardened $_id is not pass: $(jq -c --arg id "$_id" 'select(.id==$id)' "$T/hardened.jsonl")"
done
[ "$(statuses "$T/hardened.jsonl" unknown)" = "OSEE-01 OSEE-02" ] || fail "fixture mode must leave live Objective-See state unknown"

# 2. Weak home: exactly the expected warnings, exit 1.
run weak "$T/weak.jsonl" --json
[ "$RC" -eq 1 ] || fail "weak run exit $RC"
msc_schema_validate "$SCHEMA" "$T/weak.jsonl" || fail "weak records violate schema"
_got=$(statuses "$T/weak.jsonl" warn)
_want="AGENT-01 HB-01 HB-02 HB-03 HB-05 NODE-01 NPM-02 NPM-04 NPM-05 PNPM-01 SHELL-02"
[ "$_got" = "$_want" ] || fail "weak warnings: got [$_got], want [$_want]"
[ "$(statuses "$T/weak.jsonl" info)" = "HB-06 HB-07 HB-09 SHELL-01 UV-01" ] || fail "weak info set: $(statuses "$T/weak.jsonl" info)"
jq -e 'select(.id=="NPM-04") | .detail | contains("node v22.1.0 (npm 10.9.0)") and (contains("v22.2.0")|not)' "$T/weak.jsonl" >/dev/null || fail "NPM-04 detail"
jq -e 'select(.id=="NPM-05") | .detail | contains("(lines 2)")' "$T/weak.jsonl" >/dev/null || fail "NPM-05 line number"
jq -e 'select(.id=="SHELL-02") | .detail | contains("~/.zshrc:2")' "$T/weak.jsonl" >/dev/null || fail "SHELL-02 location"
jq -e 'select(.id=="AGENT-01") | .detail | contains("claude:example-browser") and (contains("project-memory")|not)' "$T/weak.jsonl" >/dev/null || fail "AGENT-01 detail"
jq -e 'select(.id=="HB-05") | .detail | contains("example-org/tools")' "$T/weak.jsonl" >/dev/null || fail "HB-05 detail"

# 3. Read-only brew usage: only allow-listed subcommands, auto-update disabled.
if /usr/bin/grep -q FORBIDDEN "$T/brew.log"; then fail "audit ran a non-allow-listed brew command: $(/usr/bin/grep FORBIDDEN "$T/brew.log")"; fi
/usr/bin/awk -F '|' '$1 != "1" { bad=1 } $2 !~ /^(--version|config|tap|developer|info --json=v2 --installed|tap-info --json --installed|list --full-name)$/ { bad=1 } END { exit bad }' "$T/brew.log" || fail "unexpected brew invocation or auto-update enabled"

# 4. Variants: env-only brew setting, gh not authenticated, FDA for a terminal,
#    unreadable TCC.db, developer mode enabled.
# Prefix assignments to functions persist in some sh implementations; set and unset explicitly.
WA_EXTRA_ENV=HOMEBREW_VERIFY_ATTESTATIONS=1; run weak "$T/envonly.jsonl" --json --only HB-01; unset WA_EXTRA_ENV
jq -e 'select(.id=="HB-01") | .status=="warn" and (.detail|contains("only in the environment"))' "$T/envonly.jsonl" >/dev/null || fail "HB-01 environment-only case"
WA_EXTRA_ENV=WA_FAKE_GH_RC=1; run hardened "$T/gh.jsonl" --json --only HB-04; unset WA_EXTRA_ENV
jq -e 'select(.id=="HB-04") | .status=="warn" and .detail=="gh installed; authenticated: no"' "$T/gh.jsonl" >/dev/null || fail "HB-04 unauthenticated case"
run hardened "$T/tcc.jsonl" --json --only TCC --tcc-db "$T/tcc-bad.db"
jq -e 'select(.id=="TCC-01") | .status=="warn" and (.detail|contains("com.googlecode.iterm2"))' "$T/tcc.jsonl" >/dev/null || fail "TCC-01 terminal with FDA"
run hardened "$T/tcc2.jsonl" --json --only TCC-01 --tcc-db "$T/missing.db"
jq -e -s 'length==1 and .[0].status=="unknown"' "$T/tcc2.jsonl" >/dev/null || fail "TCC-01 unreadable database"
/bin/mkdir -p "$T/devdata"; /bin/cp "$FX/hardened/brew/"* "$T/devdata/"
printf '%s\n' 'Developer mode is enabled because brew developer on was run.' >"$T/devdata/developer.txt"
WA_BREW_DATA="$T/devdata"; run hardened "$T/dev.jsonl" --json --only HB-10; unset WA_BREW_DATA
jq -e 'select(.id=="HB-10") | .status=="warn"' "$T/dev.jsonl" >/dev/null || fail "HB-10 developer mode enabled"

# Early-exit heuristic: exported CLAUDE_CODE_* tuning plus an unrelated
# function return is not an agent early exit.
/bin/mkdir -p "$T/rc/home/.homebrew" "$T/rc/prefix" "$T/rc/brew"
/bin/cp "$FX/hardened/brew/"* "$T/rc/brew/"
# Literal rc content for the fixture.
# shellcheck disable=SC2016
printf '%s\n' 'export CLAUDE_CODE_MAX_OUTPUT_TOKENS=1000' 'helper() {' '    return 0' '}' '. "$HOME/.secrets.sh"' >"$T/rc/home/.zshrc"
WA_BREW_DATA="$T/rc/brew"; run rc "$T/rc.jsonl" --json --only SHELL-02; unset WA_BREW_DATA
jq -e 'select(.id=="SHELL-02") | .status=="info"' "$T/rc.jsonl" >/dev/null || fail "SHELL-02 must not treat an exported CLAUDE_CODE_* variable as an early exit"

# brew.env exactly as bin/brew reads it: "export " lines are skipped, values
# are verbatim (a quoted "false" is non-empty, so on), --require-sha must be a
# word, the deprecated REQUIRE_SHA variable is disabled, and a final line
# without a newline is never read.
# Usage: brew_case NAME "brew.env content" [system brew.env content]
brew_case() {
    /bin/mkdir -p "$T/$1/home/.homebrew" "$T/$1/prefix"
    printf '%b' "$2" >"$T/$1/home/.homebrew/brew.env"
    printf '%b' "${3:-}" >"$T/$1/system.env"
    WA_BREW_DATA="$FX/hardened/brew"
    set +e
    /usr/bin/env -i HOME="$T/$1/home" TMPDIR="$T" PATH="$T/bin:/usr/bin:/bin" \
        WA_FAKE_BREW_DATA="$WA_BREW_DATA" WA_FAKE_BREW_PREFIX="$T/$1/prefix" WA_FAKE_BREW_LOG="$T/brew.log" \
        "$AUDIT" --home "$T/$1/home" --brew "$T/bin/brew" --system-brew-env "$T/$1/system.env" --json --only HB-0 >"$T/$1.jsonl" 2>"$T/$1.err"
    set -e
    unset WA_BREW_DATA
}
# Usage: brew_expect NAME ID STATUS [detail substring]
brew_expect() {
    jq -e --arg id "$2" --arg s "$3" --arg d "${4:-}" 'select(.id==$id) | .status==$s and (.detail|contains($d))' "$T/$1.jsonl" >/dev/null ||
        fail "brew.env case $1: $2 expected $3 [${4:-}], got $(jq -c --arg id "$2" 'select(.id==$id) | [.status,.detail]' "$T/$1.jsonl")"
}
brew_case bexport 'export HOMEBREW_VERIFY_ATTESTATIONS=1\nexport HOMEBREW_NO_INSECURE_REDIRECT=1\nHOMEBREW_CASK_OPTS="--appdir=/Applications --require-sha"\n'
brew_expect bexport HB-01 warn "export prefix"
brew_expect bexport HB-03 warn "export prefix"
brew_expect bexport HB-02 pass
brew_case bquoted 'HOMEBREW_VERIFY_ATTESTATIONS="false"\nHOMEBREW_NO_INSECURE_REDIRECT="false"\nHOMEBREW_CASK_OPTS=--require-sha-not\n'
brew_expect bquoted HB-01 pass
brew_expect bquoted HB-03 pass
brew_expect bquoted HB-02 warn "no --require-sha word"
brew_case bfalse '  HOMEBREW_VERIFY_ATTESTATIONS=  \nHOMEBREW_NO_INSECURE_REDIRECT=Off\nHOMEBREW_CASK_OPTS_REQUIRE_SHA=1\n'
brew_expect bfalse HB-01 warn "treats as off"
brew_expect bfalse HB-03 warn "treats as off"
brew_expect bfalse HB-02 warn "deprecated HOMEBREW_CASK_OPTS_REQUIRE_SHA"
brew_case bnonl 'HOMEBREW_NO_INSECURE_REDIRECT=1\nHOMEBREW_VERIFY_ATTESTATIONS=1'
brew_expect bnonl HB-01 warn "has no newline"
brew_expect bnonl HB-03 pass
brew_case bprio 'HOMEBREW_NO_INSECURE_REDIRECT=1\n' 'HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1\nHOMEBREW_NO_INSECURE_REDIRECT=0\n'
brew_expect bprio HB-03 warn "system.env"
brew_case bnoprio 'HOMEBREW_NO_INSECURE_REDIRECT=1\n' 'HOMEBREW_NO_INSECURE_REDIRECT=0\n'
brew_expect bnoprio HB-03 pass
brew_case boverride 'HOMEBREW_VERIFY_ATTESTATIONS=1\nHOMEBREW_NO_VERIFY_ATTESTATIONS=1\n'
brew_expect boverride HB-01 warn "HOMEBREW_NO_VERIFY_ATTESTATIONS"

# Developer mode with HOMEBREW_UPDATE_TO_TAG is information, not a warning;
# command-only taps are not untap candidates.
/bin/mkdir -p "$T/tag/home/.homebrew" "$T/tag/prefix" "$T/tagdata"
/bin/cp "$FX/hardened/brew/"* "$T/tagdata/"
printf '%s\n' 'Developer mode is enabled.' >"$T/tagdata/developer.txt"
printf '%s\n' 'HOMEBREW_UPDATE_TO_TAG=1' >"$T/tag/home/.homebrew/brew.env"
WA_BREW_DATA="$T/tagdata"; run tag "$T/tag.jsonl" --json --only HB-10; unset WA_BREW_DATA
jq -e 'select(.id=="HB-10") | .status=="info" and (.detail|contains("HOMEBREW_UPDATE_TO_TAG"))' "$T/tag.jsonl" >/dev/null || fail "HB-10 with HOMEBREW_UPDATE_TO_TAG"
jq -e 'select(.id=="HB-06") | .detail | contains("example-org/commands") and (contains("homebrew/")|not)' "$T/weak.jsonl" >/dev/null || fail "HB-06 command-only and official taps"

# ~/.npmrc accepts blanks around "=".
/bin/mkdir -p "$T/npmsp/home" "$T/npmsp/prefix"
printf '%s\n' 'min-release-age = 7' 'strict-allow-scripts = true' 'ignore-scripts = true' >"$T/npmsp/home/.npmrc"
run npmsp "$T/npmsp.jsonl" --json --only NPM-0
jq -e -s 'map({key:.id,value:.status})|from_entries | .["NPM-01"]=="pass" and .["NPM-02"]=="pass" and .["NPM-03"]=="info"' "$T/npmsp.jsonl" >/dev/null || fail "npmrc with blanks around ="

# The CLI wrapper must not install anything and must accept --no-auto-install.
/usr/bin/env -i HOME="$T/hardened/home" TMPDIR="$T" PATH="$T/bin:/usr/bin:/bin" "$ROOT_DIR/bin/macos-security" workstation-audit --no-auto-install --self-test | jq -e '.status=="pass"' >/dev/null || fail "bin/macos-security workstation-audit --no-auto-install"
/bin/mkdir -p "$T/nojqbin"; /bin/ln -s "$FX/bin/brew" "$T/nojqbin/brew"
set +e
/usr/bin/env -i HOME="$T/hardened/home" TMPDIR="$T" PATH="$T/nojqbin" WA_FAKE_BREW_LOG="$T/nojq-brew.log" /bin/sh "$ROOT_DIR/bin/macos-security" workstation-audit >/dev/null 2>&1
RC=$?
set -e
[ "$RC" -eq 2 ] || fail "bin/macos-security workstation-audit without jq must exit 2 (got $RC)"
if [ -s "$T/nojq-brew.log" ]; then fail "bin/macos-security workstation-audit called brew without jq (install path)"; fi

# Mapping consistency with docs/attack-catalogue.md: a check carries ATK-x in
# attack_ids exactly when the catalogue cites it for ATK-x in both the summary
# matrix Detect column and the ATK-x "Detection with this repository" line.
CATALOGUE="$ROOT_DIR/docs/attack-catalogue.md"
jq -r '.id as $c | .attack_ids[] | "\(.) \($c)"' "$T/hardened.jsonl" | LC_ALL=C /usr/bin/sort -u >"$T/map-records"
EXTRACT='function ids(atk, s,   m) {
    while (match(s, /(^|[^A-Za-z0-9])(HB|NPM|PNPM|NODE|UV|SHELL|OSEE|TCC|AGENT)-[0-9][0-9]/)) {
        m=substr(s, RSTART, RLENGTH); sub(/^[^A-Z]/, "", m); print atk " " m; s=substr(s, RSTART + RLENGTH)
    }
}'
/usr/bin/awk -F '|' "$EXTRACT"' $2 ~ /^ ATK-[0-9][0-9] $/ { atk=$2; gsub(/ /, "", atk); ids(atk, $(NF-1)) }' "$CATALOGUE" | LC_ALL=C /usr/bin/sort -u >"$T/map-matrix"
/usr/bin/awk "$EXTRACT"' /^## ATK-[0-9][0-9] / { atk=$2 } /^\*\*Detection with this repository\.\*\*/ { ids(atk, $0) }' "$CATALOGUE" | LC_ALL=C /usr/bin/sort -u >"$T/map-sections"
[ -s "$T/map-matrix" ] && [ -s "$T/map-sections" ] || fail "could not parse docs/attack-catalogue.md"
/usr/bin/diff "$T/map-records" "$T/map-matrix" >"$T/map-diff1" || fail "attack_ids vs catalogue matrix (< records, > matrix): $(/usr/bin/tr '\n' ' ' <"$T/map-diff1")"
/usr/bin/diff "$T/map-records" "$T/map-sections" >"$T/map-diff2" || fail "attack_ids vs catalogue detection lines (< records, > sections): $(/usr/bin/tr '\n' ' ' <"$T/map-diff2")"

# 5. Text mode, exit codes and usage errors.
run weak "$T/weak.txt"
[ "$RC" -eq 1 ] || fail "weak text run exit $RC"
/usr/bin/grep -q '^  WARN    NPM-02    ' "$T/weak.txt" || fail "text table row"
/usr/bin/grep -q '^Summary: 30 checks; pass .*, warn 11,' "$T/weak.txt" || fail "text summary line"
run hardened "$T/bad.out" --bogus
[ "$RC" -eq 2 ] || fail "unknown option must exit 2"
run hardened "$T/bad.out" --only 'x;y'
[ "$RC" -eq 2 ] || fail "invalid --only must exit 2"
set +e
/usr/bin/env -i HOME="$T/hardened/home" TMPDIR="$T" PATH="$T/empty" /bin/sh "$AUDIT" --home "$T/hardened/home" >/dev/null 2>"$T/nojq.err"
RC=$?
set -e
[ "$RC" -eq 2 ] || fail "missing jq must exit 2 (got $RC)"
/usr/bin/grep -q 'jq is required' "$T/nojq.err" || fail "missing jq must explain itself"
"$AUDIT" --self-test | jq -e '.status=="pass" and .checks>=15' >/dev/null || fail "self-test"

# 6. Privacy: no secret values, env blocks, account names, project paths or home paths.
/bin/cat "$T"/*.jsonl "$T"/*.txt "$T"/*.err >"$T/all-output"
for _needle in FAKE-VALUE-NOT-A-TOKEN FAKE-ENV-VALUE example-user /Users/example/my-project "$T/hardened/home" "$T/weak/home"; do
    if /usr/bin/grep -qF -- "$_needle" "$T/all-output"; then fail "output leaks $_needle"; fi
done
if [ -n "${HOME:-}" ] && /usr/bin/grep -qF -- "$HOME/" "$T/all-output"; then fail "output leaks the real home directory: $(/usr/bin/grep -F -- "$HOME/" "$T/all-output" | /usr/bin/head -n 3 | /usr/bin/sed "s|$HOME|<HOME>|g")"; fi

# 7. The schema rejects drift.
printf '%s\n' '{"schema":"macos-security-workstation-audit/v1","id":"HB-01","status":"WARN","title":"t","detail":"d","playbook":"PB-01","attack_ids":["ATK-10"],"remediation":"r"}' >"$T/bad1.jsonl"
if msc_schema_validate "$SCHEMA" "$T/bad1.jsonl" >/dev/null; then fail "schema accepted an upper-case status"; fi
printf '%s\n' '{"schema":"macos-security-workstation-audit/v1","id":"XX-01","status":"warn","title":"t","detail":"d","playbook":"PB-01","attack_ids":["ATK-10"],"remediation":"r","extra":1}' >"$T/bad2.jsonl"
if msc_schema_validate "$SCHEMA" "$T/bad2.jsonl" >/dev/null; then fail "schema accepted an unknown ID and extra property"; fi

printf '%s\n' 'PASS: workstation audit checks, privacy and schema'
