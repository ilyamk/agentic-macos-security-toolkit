#!/bin/sh
# SPDX-License-Identifier: MIT
# Host-free test of tools/brewup/brewup with a fake brew on PATH.
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && /bin/pwd -P)
BREWUP=$ROOT_DIR/tools/brewup/brewup
TEST_TMP=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/brewup-test.XXXXXX")
trap '/bin/rm -rf "$TEST_TMP"' EXIT
trap 'exit 130' HUP INT TERM

FAKEBIN=$TEST_TMP/fakebin
LOG=$TEST_TMP/brew.log
OUT=$TEST_TMP/out.txt
fail() { printf 'FAIL: %s\n' "$1" >&2; [ ! -f "$OUT" ] || /bin/cat "$OUT" >&2; exit 1; }

/bin/mkdir -p "$FAKEBIN" "$TEST_TMP/home"
# Work from the temporary directory so a stray relative path lands there.
cd "$TEST_TMP"
/bin/cat >"$FAKEBIN/brew" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_BREW_LOG"
case $* in
  "update --quiet") exit 0 ;;
  "outdated --vulnerable --quiet")
    [ -z "${FAKE_VULN_FAIL:-}" ] || exit 1
    [ -n "${FAKE_NOTHING:-}" ] || printf '%s\n' vulnf
    exit 0 ;;
  "list --full-name --formula") printf '%s\n' someuser/tap/tool3p pinnedf vulnf plainf; exit 0 ;;
  "list --full-name --cask") printf '%s\n' plaincask pinnedcask; exit 0 ;;
  "outdated --json=v2")
    if [ -n "${FAKE_NOTHING:-}" ]; then
      printf '%s\n' '{"formulae":[],"casks":[]}'
    else
      printf '%s\n' '{"formulae":[
        {"name":"someuser/tap/tool3p","installed_versions":["1.0"],"current_version":"1.1","pinned":false},
        {"name":"pinnedf","installed_versions":["2.0"],"current_version":"2.1","pinned":true},
        {"name":"vulnf","installed_versions":["3.0"],"current_version":"3.1","pinned":false},
        {"name":"plainf","installed_versions":["4.0"],"current_version":"4.1","pinned":false}],
       "casks":[{"name":"plaincask","installed_versions":["5.0"],"current_version":"5.1"},
        {"name":"pinnedcask","installed_versions":["6.0"],"current_version":"6.1","pinned":true}]}'
    fi
    exit 0 ;;
  upgrade*)
    printf 'env dependents_check=%s install_cleanup=%s\n' "${HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK:-}" \
      "${HOMEBREW_NO_INSTALL_CLEANUP:-}" >>"$FAKE_BREW_LOG"
    exit 0 ;;
  "autoremove --dry-run") printf '%s\n' '==> Would autoremove 1 unneeded formula:' orphanlib; exit 0 ;;
  autoremove) exit 0 ;;
  cleanup)
    printf 'env no_cleanup=%s\n' "${HOMEBREW_NO_CLEANUP_FORMULAE:-}" >>"$FAKE_BREW_LOG"
    exit 0 ;;
  "bundle dump --file="*" --force --no-vscode")
    file=${3#--file=}
    case $file in /*) ;; *) printf 'fake brew: relative --file refused: %s\n' "$file" >&2; exit 4 ;; esac
    printf '%s\n' 'brew "plainf"' 'brew "vulnf"' >"$file"
    exit 0 ;;
esac
printf 'fake brew: unexpected arguments: %s\n' "$*" >&2
exit 3
EOF
/bin/chmod 755 "$FAKEBIN/brew"

unset BREWUP_COOLDOWN_DAYS BREWUP_BREWFILE NO_COLOR FAKE_VULN_FAIL FAKE_NOTHING HOMEBREW_NO_CLEANUP_FORMULAE
HOME=$TEST_TMP/home XDG_STATE_HOME=$TEST_TMP/state XDG_CONFIG_HOME=$TEST_TMP/config
PATH=$FAKEBIN:/usr/bin:/bin FAKE_BREW_LOG=$LOG
export HOME XDG_STATE_HOME XDG_CONFIG_HOME PATH FAKE_BREW_LOG
STATE=$XDG_STATE_HOME/brewup/seen.tsv
BREWFILE=$XDG_CONFIG_HOME/homebrew/Brewfile

# Environment for one run only (assignments before a function call may persist).
# shellcheck disable=SC2163
with() { (export "$1"; shift; "$@"); }
run() { : >"$LOG"; "$BREWUP" "$@" </dev/null >"$OUT" 2>&1; }
# Run with no controlling terminal (fork, then setsid), so no case can block on
# a prompt even when the suite itself runs in a terminal.
detached() {
  /usr/bin/perl -MPOSIX -e 'my $p = fork; die "fork" unless defined $p;
    if ($p) { waitpid($p, 0); exit($? >> 8) }
    POSIX::setsid() or die "setsid"; exec @ARGV or die "exec"' -- "$@"
}
run_notty() { : >"$LOG"; detached "$BREWUP" "$@" </dev/null >"$OUT" 2>&1; }
# STATUS column of the table row whose NAME field equals $1.
status_of() { /usr/bin/awk -v n="$1" '$2 == n { $1 = $2 = $3 = $4 = $5 = ""; sub(/^ +/, ""); print; exit }' "$OUT"; }
logged() { /usr/bin/grep -c -- "$1" "$LOG" || :; }
no_maintenance() {
  for c in '^upgrade' '^autoremove$' '^cleanup' '^bundle'; do
    [ "$(logged "$c")" -eq 0 ] || fail "$1: called $c"
  done
}

detached /bin/sh -c '( : </dev/tty ) 2>/dev/null && exit 9; exit 0' </dev/null ||
  fail "could not detach from the controlling terminal"

# 1. First dry run: everything new is waiting; pinned, vulnerable, third-party flagged.
run -n || fail "dry run exit"
status_of someuser/tap/tool3p | /usr/bin/grep -q '^waiting 3d more \[3rd-party: someuser/tap\]$' || fail "tool3p status"
[ "$(status_of pinnedf)" = pinned ] || fail "pinnedf status"
[ "$(status_of pinnedcask)" = pinned ] || fail "pinnedcask status"
status_of vulnf | /usr/bin/grep -q '^VULNERABLE' || fail "vulnf status"
status_of plainf | /usr/bin/grep -q '^waiting' || fail "plainf status"
status_of plaincask | /usr/bin/grep -q '^waiting' || fail "plaincask status"
[ "$(logged '^update --quiet$')" -eq 1 ] || fail "-n should still run brew update"
no_maintenance "dry run"
[ "$(logged '^autoremove --dry-run$')" -eq 0 ] || fail "dry run ran autoremove --dry-run"
[ "$(/usr/bin/wc -l <"$STATE" | /usr/bin/tr -d ' ')" -eq 6 ] || fail "seen.tsv should have 6 lines"

# 1b. -N skips brew update.
run -n -N || fail "-n -N exit"
[ "$(logged '^update')" -eq 0 ] || fail "-N ran brew update"

# 1c. No terminal, no -y, only the vulnerable formula is ready: change nothing.
run_notty || fail "no-tty run exit"
no_maintenance "no terminal"
/usr/bin/grep -q 'No terminal' "$OUT" || fail "no-tty message"
/usr/bin/grep -q 'orphanlib' "$OUT" || fail "autoremove preview not shown"
[ ! -e "$BREWFILE" ] || fail "no-tty run wrote a Brewfile"

# 1d. No terminal, nothing ready (vulnerability scan failed, so no bypass): change nothing.
with FAKE_VULN_FAIL=1 run_notty || fail "no-tty nothing-ready exit"
/usr/bin/grep -q 'Nothing past the cool-down yet' "$OUT" || fail "nothing-ready message"
no_maintenance "no terminal, nothing ready"

# 2. plainf seen 4 days ago: vulnf (bypass) and plainf upgrade; casks wait.
old=$(( $(/bin/date +%s) - 4 * 86400 ))
/usr/bin/awk -F '\t' -v OFS='\t' -v t="$old" '$2 == "plainf" { $4 = t } { print }' "$STATE" >"$TEST_TMP/seen" && /bin/mv "$TEST_TMP/seen" "$STATE"
/bin/mkdir -p "${BREWFILE%/*}"
printf '%s\n' 'brew "vulnf"' >"$BREWFILE"
for s in 20000101T000000Z 20000102T000000Z 20000103T000000Z; do : >"$BREWFILE.bak-$s"; done
run -y || fail "-y run exit"
upgrades=$(/usr/bin/grep '^upgrade' "$LOG" || :)
case $upgrades in
  "upgrade --formula vulnf plainf"|"upgrade --formula plainf vulnf") ;;
  *) fail "unexpected upgrades: $upgrades" ;;
esac
/usr/bin/grep -q '^env dependents_check=1 install_cleanup=1$' "$LOG" || fail "upgrade env not set"
[ "$(logged '^autoremove$')" -eq 1 ] && [ "$(logged '^cleanup$')" -eq 1 ] || fail "cleanup calls"
/usr/bin/grep -Eq '^env no_cleanup=(vulnf,plainf|plainf,vulnf)$' "$LOG" || fail "cleanup must keep upgraded formulae"
[ "$(logged '^bundle dump --file='"$BREWFILE"' --force --no-vscode$')" -eq 1 ] || fail "bundle dump call"
/usr/bin/grep -q 'Brewfile changed:' "$OUT" || fail "Brewfile change header"
/usr/bin/grep -q '^+brew "plainf"' "$OUT" || fail "Brewfile diff"
set -- "$BREWFILE".bak-*
[ "$#" -eq 3 ] || fail "expected 3 Brewfile backups, found $#"
[ ! -e "$BREWFILE.bak-20000101T000000Z" ] || fail "oldest backup not pruned"
for latest; do :; done
[ "$(/bin/cat "$latest")" = 'brew "vulnf"' ] || fail "newest backup is not the previous Brewfile"
for c in '--force ' 'bundle cleanup' linkage; do
  /usr/bin/grep -v '^bundle dump' "$LOG" | /usr/bin/grep -q -- "$c" && fail "forbidden brew call: $c"
done

# 3. -a ignores the cool-down but never upgrades pinned formulae or casks.
run -a -n || fail "-a -n exit"
plan=$(/usr/bin/grep '^Dry run: would upgrade' "$OUT") || fail "no plan line"
for n in someuser/tap/tool3p vulnf plainf plaincask; do
  case " $plan " in *" $n "*) ;; *) fail "plan lacks $n" ;; esac
done
case " $plan " in *" pinnedf "*|*" pinnedcask "*) fail "plan includes a pinned package" ;; esac

# 4. -a without -y and without a terminal: nothing upgraded.
run_notty -a || fail "no-tty -a exit"
no_maintenance "no terminal with -a"

# 5. Vulnerability scan failure: warning, and no bypass.
with FAKE_VULN_FAIL=1 run -n || fail "vuln-fail exit"
/usr/bin/grep -q 'warning: vulnerability scan (OSV.dev) failed' "$OUT" || fail "vuln-fail warning"
status_of vulnf | /usr/bin/grep -q '^waiting' || fail "vulnf should wait without OSV data"

# 6. Nothing outdated, no -y, no terminal: message, emptied state, nothing else.
with FAKE_NOTHING=1 run_notty || fail "up-to-date no-tty exit"
/usr/bin/grep -q 'Everything is up to date' "$OUT" || fail "up-to-date message"
[ -f "$STATE" ] && [ ! -s "$STATE" ] || fail "seen.tsv not emptied"
no_maintenance "up to date, no terminal"
with FAKE_NOTHING=1 run -y || fail "up-to-date -y exit"
[ "$(logged '^cleanup$')" -eq 1 ] || fail "-y should clean up when up to date"

# 7. Invalid arguments.
rc=0; run -d abc || rc=$?
[ "$rc" -eq 2 ] || fail "-d abc exit $rc"
rc=0; with BREWUP_BREWFILE=Brewfile run -n || rc=$?
[ "$rc" -eq 2 ] || fail "relative BREWUP_BREWFILE exit $rc"
[ ! -s "$LOG" ] || fail "invalid arguments called brew"
[ ! -e "$TEST_TMP/Brewfile" ] && [ ! -e "$TEST_TMP/dump" ] || fail "stray relative file created"

printf '%s\n' 'PASS: brewup cool-down, vulnerability bypass, pinning, third-party tagging and confirmation'
