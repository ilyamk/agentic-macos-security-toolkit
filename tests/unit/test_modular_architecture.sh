#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && /bin/pwd -P)
TEST_TMP=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/msc-modular-test.XXXXXX")
trap '/bin/rm -rf "$TEST_TMP"' EXIT HUP INT TERM

. "$ROOT_DIR/lib/macos_security_common.sh"
. "$ROOT_DIR/lib/macos_security_evidence.sh"
. "$ROOT_DIR/lib/macos_security_dependencies.sh"
. "$ROOT_DIR/detectors/native.sh"

MSC_AUTO_INSTALL=0
msd_spec knockknock | /usr/bin/grep -q '^cask|knockknock|' || exit 1
if msd_spec arbitrary-package >/dev/null 2>&1; then exit 1; fi
msd_inventory_json yara-x | jq -e '.id=="yara-x" and (.installed|type=="boolean")' >/dev/null

# Exercise the automatic Homebrew path without changing the host. The fake
# allow-listed install creates the expected command only for this test.
/bin/mkdir "$TEST_TMP/fakebin"
cat >"$TEST_TMP/fakebin/brew" <<'FAKE'
#!/bin/sh
if [ "$1" = --prefix ]; then printf '%s\n' "$TEST_BREW_PREFIX"; exit 0; fi
printf '%s\n' "$*" >>"$TEST_INSTALL_CALLS"
[ "${HOMEBREW_VERIFY_ATTESTATIONS:-}" = 1 ] &&
[ -z "${HOMEBREW_NO_VERIFY_ATTESTATIONS:-}" ] &&
[ "${HOMEBREW_NO_INSECURE_REDIRECT:-}" = 1 ] &&
[ "${HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK:-}" = 1 ] || exit 2
case "$*" in
    'install --formula --force-bottle homebrew/core/yara-x') binary=yr ;;
    'install --cask --require-sha homebrew/cask/santa') binary=santactl ;;
    *) exit 2 ;;
esac
printf '%s\n' '#!/bin/sh' 'exit 0' >"${0%/*}/$binary"
/bin/chmod 755 "${0%/*}/$binary"
FAKE
/bin/chmod 755 "$TEST_TMP/fakebin/brew"
(
    /bin/ln -s "$(command -v jq)" "$TEST_TMP/fakebin/jq"
    PATH="$TEST_TMP/fakebin:/usr/bin:/bin"
    TEST_INSTALL_CALLS=$TEST_TMP/brew-calls
    TEST_BREW_PREFIX=$TEST_TMP/fakebrew
    XDG_CONFIG_HOME=$TEST_TMP/fake-config
    export PATH TEST_INSTALL_CALLS TEST_BREW_PREFIX XDG_CONFIG_HOME
    /bin/mkdir -p "$TEST_BREW_PREFIX/etc/homebrew"
    MSC_AUTO_INSTALL=0
    MSC_ALLOW_NETWORK=1
    MSC_ALLOW_CASKS=0
    if msd_ensure yara-x "$TEST_TMP/install.log"; then exit 1; fi
    MSC_AUTO_INSTALL=1
    MSC_ALLOW_NETWORK=0
    if msd_ensure yara-x "$TEST_TMP/install.log"; then exit 1; fi
    MSC_ALLOW_NETWORK=1
    if msd_ensure santa "$TEST_TMP/install.log"; then exit 1; fi
    if msd_ensure unknown "$TEST_TMP/install.log"; then exit 1; fi
    [ ! -e "$TEST_INSTALL_CALLS" ]
    (
        printf '%s\n' 'HOMEBREW_NO_VERIFY_ATTESTATIONS=1' >"$TEST_BREW_PREFIX/etc/homebrew/brew.env"
        if msd_ensure yara-x "$TEST_TMP/install.log"; then exit 1; fi
        [ ! -e "$TEST_INSTALL_CALLS" ]
    )
    /bin/rm "$TEST_BREW_PREFIX/etc/homebrew/brew.env"
    YRX_PATH=$(msd_ensure yara-x "$TEST_TMP/install.log")
    [ "$YRX_PATH" = "$TEST_TMP/fakebin/yr" ] || exit 1
    MSC_ALLOW_CASKS=1
    SANTA_PATH=$(msd_ensure santa "$TEST_TMP/install.log")
    [ "$SANTA_PATH" = "$TEST_TMP/fakebin/santactl" ] || exit 1
    MSC_ALLOW_NETWORK=0
    [ "$(msd_ensure yara-x "$TEST_TMP/install.log")" = "$YRX_PATH" ]
    [ "$(wc -l <"$TEST_INSTALL_CALLS" | tr -d ' ')" -eq 2 ]
)

: >"$TEST_TMP/findings.jsonl"
msd_detect_native "$ROOT_DIR/tests/fixtures/native-observations.jsonl" "$TEST_TMP/findings.jsonl"
jq -e -s 'length==5 and all(.[]; .evidence_trust=="untrusted_observations")' "$TEST_TMP/findings.jsonl" >/dev/null

"$ROOT_DIR/collectors/monitoring/normalize-eslogger.sh" --input "$ROOT_DIR/tests/fixtures/eslogger.jsonl" --output "$TEST_TMP/timeline.jsonl"
jq -e -s 'length==2 and all(.[]; .data.arguments_collected==false) and ([.[]|tostring]|join(" ")|contains("secret-value")|not)' "$TEST_TMP/timeline.jsonl" >/dev/null
"$ROOT_DIR/collectors/monitoring/correlate.sh" --timeline "$TEST_TMP/timeline.jsonl" --output "$TEST_TMP/monitor-findings.jsonl"
jq -e -s 'length==2 and any(.[]; .severity=="critical")' "$TEST_TMP/monitor-findings.jsonl" >/dev/null

"$ROOT_DIR/bin/macos-security" self-test | jq -e '.status=="pass"' >/dev/null

git init -q "$TEST_TMP/checkout"
cp "$ROOT_DIR/.gitignore" "$TEST_TMP/checkout/.gitignore"
(
    cd "$TEST_TMP/checkout"
    mkdir docs
    for path in audit-results/run/report.jsonl monitoring-results/run/events.jsonl \
        remediation-results/run/remediation-plan.json security-results/run/posture.jsonl \
        private-notes/audit/audit.md mac-security-report.jsonl report.jsonl report-redacted.jsonl \
        docs/.env docs/.env.local docs/.envrc docs/.DS_Store docs/private.pem docs/.netrc; do
        git -c core.excludesFile=/dev/null check-ignore -q -- "$path"
    done
    for path in docs/.env.example docs/report.jsonl tests/fixtures/eslogger.jsonl; do
        if git -c core.excludesFile=/dev/null check-ignore -q -- "$path"; then exit 1; fi
    done

    if msc_create_private_dir docs/unprotected 2>/dev/null; then exit 1; fi
    [ ! -e docs/unprotected ]
    saved=$(msc_create_private_dir 'security-results/private run')
    [ "$(/usr/bin/stat -f '%Lp' "$saved")" = 700 ]
    ln -s ../docs security-results/escape
    if msc_create_private_dir security-results/escape/run 2>/dev/null; then exit 1; fi
    if msc_create_private_dir security-results/../docs/run 2>/dev/null; then exit 1; fi
    [ ! -e docs/run ]
    ln -s ../docs/run security-results/report-link.jsonl
    if msc_report_file security-results/report-link.jsonl 2>/dev/null; then exit 1; fi

    : >security-results/indexed.json
    git add -f security-results/indexed.json
    if msc_report_directory security-results 2>/dev/null; then exit 1; fi
    if "$ROOT_DIR/macos-security-remediation.sh" --plan example --output-root docs/report \
        >/dev/null 2>"$TEST_TMP/output-error"; then exit 1; fi
    /usr/bin/grep -q 'Refusing report output in Git' "$TEST_TMP/output-error"
    [ ! -e docs/report ]

    if "$ROOT_DIR/collectors/monitoring/normalize-eslogger.sh" --input "$ROOT_DIR/tests/fixtures/eslogger.jsonl" \
        --output docs/timeline.jsonl 2>/dev/null; then exit 1; fi
    [ ! -e docs/timeline.jsonl ]
)
msc_create_private_dir "$TEST_TMP/standalone-report" >/dev/null

printf '%s\n' 'PASS: modular dependency allow-list, native detectors, event privacy, correlations and Git-safe report paths'
