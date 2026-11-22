#!/bin/sh
# macOS Security Triage — read-only incident triage for macOS
# SPDX-License-Identifier: MIT

set -u
umask 077

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec:/opt/homebrew/bin:/usr/local/bin"
LC_ALL=C
export PATH LC_ALL

SCRIPT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
COMMON_LIB="$SCRIPT_DIR/lib/macos_security_common.sh"
DEPENDENCY_LIB="$SCRIPT_DIR/lib/macos_security_dependencies.sh"
POSTURE_SCRIPT="$SCRIPT_DIR/macos-security-posture.sh"
[ -r "$COMMON_LIB" ] || { printf 'Missing library: %s\n' "$COMMON_LIB" >&2; exit 2; }
# shellcheck source=lib/macos_security_common.sh
. "$COMMON_LIB"
[ -r "$DEPENDENCY_LIB" ] || { printf 'Missing library: %s\n' "$DEPENDENCY_LIB" >&2; exit 2; }
# shellcheck source=lib/macos_security_dependencies.sh
. "$DEPENDENCY_LIB"

SCRIPT_VERSION="3.0.0"
SCHEMA_VERSION="macos-security-triage/v3"
MODE="standard"
ONLINE=0
MONITOR_SECONDS=0
MONITOR_INTERVAL=10
LOOKBACK_HOURS=24
MAX_CANDIDATES=300
OUTPUT_DIR=""
POSTURE_REPORT_INPUT=""
YARA_RULES=""
EXTRA_SCAN_PATHS=""
SELF_TEST=0
TARGET_USER=""
MSC_AUTO_INSTALL=0
BACKGROUND_ITEMS=0
LOCAL_SCANNERS=1

usage() {
  cat <<'EOF'
Usage: ./macos-security-triage.sh [options]

Read-only incident triage for macOS. Baseline checks are delegated
to macos-security-posture.sh and retained as evidence/posture.jsonl.

  --deep                   Increase process/file/log coverage
  --background-items      Request background-item inventory, which may prompt
  --online                 Let delegated posture query Apple updates
  --posture-report FILE    Reuse an existing posture JSONL
  --monitor-seconds N      Monitor events and snapshots for N seconds
  --interval N             Snapshot interval (default 10)
  --lookback-hours N       Log lookback (default 24; deep 168)
  --output DIR             New private report directory
  --target-user USER       User context to inspect (defaults to SUDO_USER/caller)
  --scan-path PATH         Add a candidate scan root; repeatable
  --yara-rules PATH        Use a reviewed local YARA rule file
  --auto-install           Install missing explicitly selected dependencies with brew
  --no-auto-install        Do not install missing dependencies
  --self-test              Test helpers without auditing
  -h, --help               Show help
  -V, --version            Show version

Exit: 0=no high/critical result, 1=review needed, 2=fatal/incomplete.
The script never remediates, quarantines, deletes, or uploads. It may install
only allow-listed dependencies selected by an option; Homebrew is not bootstrapped.
EOF
}

die_usage() {
  printf '%s: %s\n' "${0##*/}" "$1" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case $1 in
    --deep) MODE="deep"; LOOKBACK_HOURS=168; MAX_CANDIDATES=1200 ;;
    --background-items) BACKGROUND_ITEMS=1 ;;
    --delegate-scanners) LOCAL_SCANNERS=0 ;;
    --online) ONLINE=1 ;;
    --posture-report) [ "$#" -ge 2 ] || die_usage "missing posture report"; shift; POSTURE_REPORT_INPUT=$1 ;;
    --monitor-seconds) [ "$#" -ge 2 ] || die_usage "missing monitor duration"; shift; MONITOR_SECONDS=$1 ;;
    --interval) [ "$#" -ge 2 ] || die_usage "missing interval"; shift; MONITOR_INTERVAL=$1 ;;
    --lookback-hours) [ "$#" -ge 2 ] || die_usage "missing lookback"; shift; LOOKBACK_HOURS=$1 ;;
    --output) [ "$#" -ge 2 ] || die_usage "missing output directory"; shift; OUTPUT_DIR=$1 ;;
    --target-user) [ "$#" -ge 2 ] || die_usage "missing target user"; shift; TARGET_USER=$1 ;;
    --scan-path)
      [ "$#" -ge 2 ] || die_usage "missing scan path"; shift
      case $1 in *'
'*) die_usage "newlines are not supported in scan paths" ;; esac
      if [ -z "$EXTRA_SCAN_PATHS" ]; then EXTRA_SCAN_PATHS=$1; else EXTRA_SCAN_PATHS="$EXTRA_SCAN_PATHS
$1"; fi
      ;;
    --yara-rules) [ "$#" -ge 2 ] || die_usage "missing YARA rules"; shift; YARA_RULES=$1 ;;
    --auto-install) MSC_AUTO_INSTALL=1 ;;
    --no-auto-install) MSC_AUTO_INSTALL=0 ;;
    --self-test) SELF_TEST=1 ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) printf '%s %s\n' "${0##*/}" "$SCRIPT_VERSION"; exit 0 ;;
    -*) die_usage "unknown option: $1" ;;
    *) die_usage "unexpected argument: $1" ;;
  esac
  shift
done

for number in "$MONITOR_SECONDS" "$MONITOR_INTERVAL" "$LOOKBACK_HOURS"; do
  msc_is_uint "$number" || die_usage "numeric options require integers"
done
[ "$MONITOR_INTERVAL" -ge 1 ] && [ "$MONITOR_INTERVAL" -le 60 ] || die_usage "interval must be 1..60"
[ "$MONITOR_SECONDS" -le 86400 ] || die_usage "monitor duration is capped at 86400"
[ "$LOOKBACK_HOURS" -ge 1 ] && [ "$LOOKBACK_HOURS" -le 8760 ] || die_usage "lookback must be 1..8760 hours"
[ -z "$POSTURE_REPORT_INPUT" ] || [ "$ONLINE" -eq 0 ] || \
  die_usage "--online cannot be combined with an existing --posture-report"
[ -z "$POSTURE_REPORT_INPUT" ] || [ -r "$POSTURE_REPORT_INPUT" ] || \
  die_usage "--posture-report must be readable"

if [ "$SELF_TEST" -eq 1 ]; then
  escaped=$(msc_jesc 'quote" slash\ tab')
  [ "$escaped" = 'quote\" slash\\ tab' ] || exit 2
  test_dir=$(msc_mktemp_dir macos-security-selftest) || exit 2
  /bin/rm -rf "$test_dir"
  printf '%s\n' '{"schema":"macos-security-triage/v3","record_type":"self_test","status":"pass"}'
  exit 0
fi

msc_require_jq || exit 2
MSC_ALLOW_NETWORK=$ONLINE
[ "$(/usr/bin/uname -s 2>/dev/null || printf unknown)" = "Darwin" ] || exit 2
[ -n "$TARGET_USER" ] || TARGET_USER=$(msc_default_target_user)
msc_validate_target_user "$TARGET_USER" || die_usage "target user is invalid or unavailable: $TARGET_USER"
TARGET_HOME=$(msc_target_home "$TARGET_USER")
[ -n "$TARGET_HOME" ] || die_usage "cannot resolve home for target user: $TARGET_USER"
[ -x "$POSTURE_SCRIPT" ] || { printf 'Missing posture collector: %s\n' "$POSTURE_SCRIPT" >&2; exit 2; }
if [ -n "$OUTPUT_DIR" ]; then
  OUTPUT_DIR=$(msc_create_private_dir "$OUTPUT_DIR") || { printf 'Refusing output path\n' >&2; exit 2; }
else
  OUTPUT_DIR=$(msc_mktemp_dir macos-security-triage) || exit 2
fi
/bin/mkdir -m 700 "$OUTPUT_DIR/evidence" || exit 2
EVIDENCE_DIR="$OUTPUT_DIR/evidence"
REPORT_FILE="$OUTPUT_DIR/report.jsonl"
SUMMARY_FILE="$OUTPUT_DIR/summary.json"
: >"$REPORT_FILE"


RUN_ID=$(/bin/date -u '+%Y%m%dT%H%M%SZ')-$$
STARTED_AT=$(msc_utc_now)
PASS_COUNT=0 INFO_COUNT=0 WARN_COUNT=0 FAIL_COUNT=0 ERROR_COUNT=0
LOW_RISK=0 MEDIUM_RISK=0 HIGH_RISK=0 CRITICAL_RISK=0 FINDING_COUNT=0
INCOMPLETE=0

emit_line() { printf '%s\n' "$1" | /usr/bin/tee -a "$REPORT_FILE"; }
emit_meta() {
  posture_source="generated"; [ -n "$POSTURE_REPORT_INPUT" ] && posture_source="provided"
  emit_line "{\"schema\":\"$SCHEMA_VERSION\",\"record_type\":\"meta\",\"suite_role\":\"triage\",\"run_id\":\"$(msc_jesc "$RUN_ID")\",\"started_at\":\"$STARTED_AT\",\"tool_version\":\"$SCRIPT_VERSION\",\"mode\":\"$MODE\",\"read_only\":true,\"effective_user\":\"$(msc_jesc "$(/usr/bin/id -un)")\",\"target_user\":\"$(msc_jesc "$TARGET_USER")\",\"target_home\":\"$(msc_jesc "$TARGET_HOME")\",\"evidence_trust\":\"untrusted_observations\",\"online_delegated_to_posture\":$([ "$ONLINE" -eq 1 ] && printf true || printf false),\"posture_source\":\"$posture_source\",\"monitor_seconds\":$MONITOR_SECONDS,\"report_dir\":\"$(msc_jesc "$OUTPUT_DIR")\"}"
}
emit_inventory() {
  id=$1 category=$2 title=$3 detail=$4 evidence=$5; INFO_COUNT=$((INFO_COUNT + 1))
  emit_line "{\"schema\":\"$SCHEMA_VERSION\",\"record_type\":\"inventory\",\"id\":\"$(msc_jesc "$id")\",\"category\":\"$(msc_jesc "$category")\",\"title\":\"$(msc_jesc "$title")\",\"detail\":\"$(msc_jesc "$detail")\",\"evidence\":\"$(msc_jesc "$evidence")\"}"
}
emit_finding() {
  id=$1 category=$2 severity=$3 confidence=$4 status=$5 class=$6 title=$7 detail=$8 evidence=$9
  shift 9; remediation=${1:-}; FINDING_COUNT=$((FINDING_COUNT + 1))
  case $status in pass) PASS_COUNT=$((PASS_COUNT + 1));; info) INFO_COUNT=$((INFO_COUNT + 1));; warn) WARN_COUNT=$((WARN_COUNT + 1));; fail) FAIL_COUNT=$((FAIL_COUNT + 1));; error) ERROR_COUNT=$((ERROR_COUNT + 1));; esac
  case "$status:$severity" in pass:*|info:*) :;; *:critical) CRITICAL_RISK=$((CRITICAL_RISK + 1));; *:high) HIGH_RISK=$((HIGH_RISK + 1));; *:medium) MEDIUM_RISK=$((MEDIUM_RISK + 1));; *:low) LOW_RISK=$((LOW_RISK + 1));; esac
  emit_line "{\"schema\":\"$SCHEMA_VERSION\",\"record_type\":\"finding\",\"id\":\"$(msc_jesc "$id")\",\"category\":\"$(msc_jesc "$category")\",\"severity\":\"$severity\",\"confidence\":\"$confidence\",\"status\":\"$status\",\"class\":\"$class\",\"title\":\"$(msc_jesc "$title")\",\"detail\":\"$(msc_jesc "$detail")\",\"evidence\":\"$(msc_jesc "$evidence")\",\"remediation\":\"$(msc_jesc "$remediation")\"}"
}
capture_evidence() {
  name=$1 timeout=$2; shift 2; path="$EVIDENCE_DIR/$name.txt"
  msc_run_with_timeout "$timeout" "$path" "$@"; rc=$?
  printf '\n[exit_status=%s]\n' "$rc" >>"$path"; return "$rc"
}
redact_home() { msc_redact_home "$1" "$TARGET_HOME"; }
# Finding IDs must be stable across runs so diff-from-previous.json reflects
# real change rather than PID or ordering churn. Duplicate IDs (e.g. the same
# service on IPv4 and IPv6, or one binary under several PIDs) are emitted once.
EMITTED_IDS="
"
emit_finding_once() {
  case $EMITTED_IDS in *"
$1
"*) return 1 ;; esac
  EMITTED_IDS="${EMITTED_IDS}$1
"
  emit_finding "$@"
}

emit_meta

# Single source of truth for baseline posture.
POSTURE_EVIDENCE="$EVIDENCE_DIR/posture.jsonl"
POSTURE_STDERR="$EVIDENCE_DIR/posture.stderr"
POSTURE_RC=0
if [ -n "$POSTURE_REPORT_INPUT" ]; then
  if [ -r "$POSTURE_REPORT_INPUT" ]; then /bin/cp "$POSTURE_REPORT_INPUT" "$POSTURE_EVIDENCE" || POSTURE_RC=2; : >"$POSTURE_STDERR"
  else printf 'Unreadable posture report: %s\n' "$POSTURE_REPORT_INPUT" >"$POSTURE_STDERR"; : >"$POSTURE_EVIDENCE"; POSTURE_RC=2; fi
else
  POSTURE_MARKER="$EVIDENCE_DIR/posture.timeout"
  if [ "$ONLINE" -eq 1 ]; then msc_run_timed_capture 180 "$POSTURE_EVIDENCE" "$POSTURE_STDERR" "$POSTURE_MARKER" "$POSTURE_SCRIPT" --quick --online --target-user "$TARGET_USER"
  else msc_run_timed_capture 90 "$POSTURE_EVIDENCE" "$POSTURE_STDERR" "$POSTURE_MARKER" "$POSTURE_SCRIPT" --quick --target-user "$TARGET_USER"; fi
  POSTURE_RC=$?; /bin/rm -f "$POSTURE_MARKER"
fi
if [ "$POSTURE_RC" -eq 0 ] && msc_validate_jsonl "$POSTURE_EVIDENCE"; then
  POSTURE_FAIL=$(msc_jsonl_count "$POSTURE_EVIDENCE" status FAIL)
  POSTURE_WARN=$(msc_jsonl_count "$POSTURE_EVIDENCE" status WARN)
  POSTURE_UNKNOWN=$(msc_jsonl_count "$POSTURE_EVIDENCE" status UNKNOWN)
  POSTURE_DENIED=$(msc_jsonl_count "$POSTURE_EVIDENCE" collection_state denied)
  emit_inventory posture integration "Delegated posture report" "fail=$POSTURE_FAIL warn=$POSTURE_WARN unknown=$POSTURE_UNKNOWN denied=$POSTURE_DENIED" "evidence/posture.jsonl"
  if [ "$POSTURE_FAIL" -gt 0 ]; then emit_finding posture_attention integration high high warn configuration "Posture contains failed controls" "$POSTURE_FAIL failure(s)." "evidence/posture.jsonl" "Resolve or accept each; not proof of compromise."
  elif [ "$POSTURE_UNKNOWN" -gt 0 ] || [ "$POSTURE_DENIED" -gt 0 ]; then emit_finding posture_visibility integration low high warn visibility_gap "Posture has visibility gaps" "unknown=$POSTURE_UNKNOWN denied=$POSTURE_DENIED" "evidence/posture.jsonl" "Rerun posture with authorized access."
  else emit_finding posture_baseline integration info high pass configuration "Posture has no failed controls" "Warnings remain role-dependent." "evidence/posture.jsonl" ""; fi
else
  INCOMPLETE=1
  emit_finding posture_report integration high high error visibility_gap "Posture collection incomplete" "exit=$POSTURE_RC or invalid JSONL." "evidence/posture.stderr" "Run posture separately and use --posture-report."
fi

# SSH trust metadata; no key material.
SSH_KEYS_EVIDENCE="$EVIDENCE_DIR/authorized_keys.tsv"
printf 'path\tmode\towner\tkeys\tsha256\n' >"$SSH_KEYS_EVIDENCE"; SSH_KEY_FILES=0
for user_home in /Users/*; do
  [ -d "$user_home" ] || continue
  for key_file in "$user_home/.ssh/authorized_keys" "$user_home/.ssh/authorized_keys2"; do
    [ -f "$key_file" ] || continue; SSH_KEY_FILES=$((SSH_KEY_FILES + 1))
    printf '%s\t%s\t%s\t%s\t%s\n' "$(redact_home "$key_file")" "$(/usr/bin/stat -f '%Lp' "$key_file" 2>/dev/null || printf unknown)" "$(/usr/bin/stat -f '%Su:%Sg' "$key_file" 2>/dev/null || printf unknown)" "$(/usr/bin/awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$key_file" 2>/dev/null)" "$(msc_sha256_file "$key_file")" >>"$SSH_KEYS_EVIDENCE"
  done
done
if [ "$SSH_KEY_FILES" -gt 0 ]; then emit_finding ssh_keys accounts low medium warn anomaly "SSH keys require review" "$SSH_KEY_FILES authorized_keys file(s); metadata only." "evidence/authorized_keys.tsv" "Verify each key and owner."
else emit_finding ssh_keys accounts info medium pass configuration "No SSH authorized_keys found" "No standard key file visible." "evidence/authorized_keys.tsv" ""; fi

# Current network activity; configuration topology lives in posture.jsonl.
capture_evidence listeners 20 /usr/sbin/lsof -nP -iTCP -sTCP:LISTEN || true
capture_evidence connections 20 /usr/sbin/lsof -nP -iTCP -sTCP:ESTABLISHED || true
capture_evidence shares 15 /usr/sbin/sharing -l || true
NETWORK_EXPOSURE="$EVIDENCE_DIR/network_exposure.jsonl"
: >"$NETWORK_EXPOSURE"
/usr/bin/awk 'NR > 1 && $NF == "(LISTEN)" {print $1 "\t" $2 "\t" $3 "\t" $(NF-1)}' \
  "$EVIDENCE_DIR/listeners.txt" | while IFS="$(printf '\t')" read -r listener_command listener_pid listener_user listener_endpoint; do
    listener_scope=interface
    case $listener_endpoint in
      127.0.0.1:*|localhost:*|'[::1]':*|::1:*) listener_scope=loopback ;;
      \**|0.0.0.0:*|'[::]':*|:::*) listener_scope=lan_or_vpn ;;
    esac
    listener_port=${listener_endpoint##*:}
    jq -cn --arg command "$listener_command" --arg pid "$listener_pid" --arg user "$listener_user" \
      --arg endpoint "$listener_endpoint" --arg scope "$listener_scope" --arg port "$listener_port" \
      '{schema:"macos-security-network-exposure/v1",record_type:"listener",command:$command,pid:($pid|tonumber? // $pid),user:$user,endpoint:$endpoint,port:($port|tonumber? // $port),scope:$scope,internet_reachability:"unknown_not_tested",evidence_trust:"untrusted_observations"}' >>"$NETWORK_EXPOSURE"
  done
SENSITIVE_LISTENER_COUNT=0
while IFS= read -r listener_record; do
  listener_scope=$(printf '%s\n' "$listener_record" | jq -r '.scope'); listener_port=$(printf '%s\n' "$listener_record" | jq -r '.port'); listener_pid=$(printf '%s\n' "$listener_record" | jq -r '.pid'); listener_command=$(printf '%s\n' "$listener_record" | jq -r '.command'); listener_endpoint=$(printf '%s\n' "$listener_record" | jq -r '.endpoint')
  case "$listener_scope:$listener_port" in
    loopback:*) : ;;
    *:21|*:22|*:23|*:445|*:548|*:5900|*:3283)
      if emit_finding_once "listener_$(msc_id_token "$listener_command")_${listener_port}" network high medium warn exposure "Sensitive service listens beyond loopback" "command=$listener_command pid=$listener_pid endpoint=$listener_endpoint scope=$listener_scope internet_reachability=unknown_not_tested" "evidence/network_exposure.jsonl" "Confirm service intent, effective ACL, firewall/PF and VPN/internet reachability."; then
        SENSITIVE_LISTENER_COUNT=$((SENSITIVE_LISTENER_COUNT + 1))
      fi
      ;;
  esac
done <"$NETWORK_EXPOSURE"
if [ "$SENSITIVE_LISTENER_COUNT" -eq 0 ]; then
  if [ -s "$NETWORK_EXPOSURE" ]; then emit_finding network_listeners network low medium warn exposure "Network listeners present" "No sensitive-port rule matched; review normalized listener inventory." "evidence/network_exposure.jsonl" "Review process signature and expected scope."
  else emit_finding network_listeners network info medium pass configuration "No visible TCP listeners" "None visible to this user." "evidence/network_exposure.jsonl" ""; fi
fi
if /usr/bin/grep -Eq 'guest access:[[:space:]]*1' "$EVIDENCE_DIR/shares.txt"; then emit_inventory guest_shares network "Guest-enabled share inventory" "Configuration risk is owned by delegated posture; effective filesystem ACL still applies." "evidence/shares.txt"
else emit_inventory guest_shares network "Guest-enabled share inventory" "No visible guest-enabled share." "evidence/shares.txt"; fi
emit_inventory connections network "Established TCP connections" "Metadata only; no payload/DNS capture." "evidence/connections.txt"

# Third-party launchd persistence heuristics.
PERSISTENCE_EVIDENCE="$EVIDENCE_DIR/persistence.tsv"
printf 'plist\tlabel\ttarget\tmode\towner\tsha256\n' >"$PERSISTENCE_EVIDENCE"
PERSISTENCE_COUNT=0 PERSISTENCE_ANOMALIES=0
for launch_dir in /Library/LaunchAgents /Library/LaunchDaemons "$TARGET_HOME/Library/LaunchAgents"; do
  [ -d "$launch_dir" ] || continue; /usr/bin/find -x "$launch_dir" -type f -name '*.plist' -print 2>/dev/null
done | /usr/bin/sort >"$EVIDENCE_DIR/launch_queue.txt"
while IFS= read -r launch_plist; do
  [ -f "$launch_plist" ] || continue; PERSISTENCE_COUNT=$((PERSISTENCE_COUNT + 1))
  launch_key=$(msc_short_hash "$launch_plist")
  launch_mode=$(/usr/bin/stat -f '%Lp' "$launch_plist" 2>/dev/null || printf unknown)
  launch_owner=$(/usr/bin/stat -f '%Su:%Sg' "$launch_plist" 2>/dev/null || printf unknown)
  launch_label=$(/usr/bin/plutil -extract Label raw "$launch_plist" 2>/dev/null || /usr/bin/basename "$launch_plist")
  launch_target=$(/usr/bin/plutil -extract Program raw "$launch_plist" 2>/dev/null || true)
  [ -n "$launch_target" ] || launch_target=$(/usr/bin/plutil -extract ProgramArguments.0 raw "$launch_plist" 2>/dev/null || true)
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(redact_home "$launch_plist")" "$(printf '%s' "$launch_label" | /usr/bin/tr '\t\r\n' '   ')" "$(redact_home "$launch_target")" "$launch_mode" "$launch_owner" "$(msc_sha256_file "$launch_plist")" >>"$PERSISTENCE_EVIDENCE"
  if ! /usr/bin/plutil -lint "$launch_plist" >/dev/null 2>&1; then PERSISTENCE_ANOMALIES=$((PERSISTENCE_ANOMALIES + 1)); emit_finding "persistence_invalid_$launch_key" persistence medium high warn anomaly "Invalid launchd plist" "$(redact_home "$launch_plist")" "evidence/persistence.tsv" "Verify origin before removal."; fi
  case $launch_mode in ?[2367][0-7]|??[2367][0-7]|?[0-7][2367]|??[0-7][2367]) PERSISTENCE_ANOMALIES=$((PERSISTENCE_ANOMALIES + 1)); emit_finding "persistence_writable_$launch_key" persistence high high fail anomaly "Writable launchd configuration" "$(redact_home "$launch_plist") mode=$launch_mode" "evidence/persistence.tsv" "Validate, then fix permissions.";; esac
  case $launch_target in /private/tmp/*|/tmp/*|/var/tmp/*|*/Downloads/*|*/.Trash/*|*/Library/.*) PERSISTENCE_ANOMALIES=$((PERSISTENCE_ANOMALIES + 1)); emit_finding "persistence_path_$launch_key" persistence high medium warn anomaly "Persistence uses risky path" "$(redact_home "$launch_plist") -> $(redact_home "$launch_target")" "evidence/persistence.tsv" "Validate hash/signature/provenance.";; esac
  if [ -n "$launch_target" ] && [ "${launch_target#/}" != "$launch_target" ] && [ ! -e "$launch_target" ]; then PERSISTENCE_ANOMALIES=$((PERSISTENCE_ANOMALIES + 1)); emit_finding "persistence_missing_$launch_key" persistence medium medium warn anomaly "Persistence target is missing" "$(redact_home "$launch_plist") -> $(redact_home "$launch_target")" "evidence/persistence.tsv" "Determine whether this is stale software or partial removal."; fi
  if [ -f "$launch_target" ] && /usr/bin/file -b "$launch_target" 2>/dev/null | /usr/bin/grep -q 'Mach-O'; then if ! /usr/bin/codesign --verify --strict "$launch_target" >/dev/null 2>&1 && ! /usr/sbin/spctl -a -t execute "$launch_target" >/dev/null 2>&1; then PERSISTENCE_ANOMALIES=$((PERSISTENCE_ANOMALIES + 1)); emit_finding "persistence_unsigned_$launch_key" persistence medium medium warn anomaly "Persistent Mach-O is not trusted" "$(redact_home "$launch_plist") -> $(redact_home "$launch_target") failed signature and policy assessment." "evidence/persistence.tsv" "Validate hash, publisher, origin, and necessity."; fi; fi
  if /usr/bin/plutil -convert xml1 -o - "$launch_plist" 2>/dev/null | /usr/bin/grep -Eqi '(curl|wget|base64|osascript|mkfifo|/dev/tcp|/private/tmp|/var/tmp)'; then PERSISTENCE_ANOMALIES=$((PERSISTENCE_ANOMALIES + 1)); emit_finding "persistence_command_$launch_key" persistence medium low warn anomaly "Launch command needs review" "$(redact_home "$launch_plist"): downloader/interpreter/temp-path pattern; contents excluded." "evidence/persistence.tsv" "Inspect locally for intent/secrets."; fi
done <"$EVIDENCE_DIR/launch_queue.txt"
if [ "$PERSISTENCE_ANOMALIES" -eq 0 ]; then emit_finding persistence_review persistence info medium pass configuration "No high-confidence launchd anomaly" "$PERSISTENCE_COUNT third-party item(s) checked." "evidence/persistence.tsv" ""; fi
if [ "$BACKGROUND_ITEMS" -eq 1 ]; then
  if ! capture_evidence background_tasks 30 /usr/bin/sfltool dumpbtm; then
    emit_finding background_tasks persistence low high warn visibility_gap "Background-item inventory unavailable" "The requested system inventory did not complete." "evidence/background_tasks.txt" "Review Login Items & Extensions in System Settings."
  fi
else
  emit_inventory background_tasks persistence "Background-item inventory skipped" "Use --background-items to request the protected system inventory." ""
fi
capture_evidence system_extensions 30 /usr/bin/systemextensionsctl list || true
# shellcheck disable=SC2329
# Invoked indirectly through capture_evidence.
collect_privileged_helpers() {
  for helper_dir in /Library/PrivilegedHelperTools /Library/StartupItems /Library/Extensions; do
    [ -d "$helper_dir" ] || continue
    /usr/bin/find -x "$helper_dir" -mindepth 1 -maxdepth 2 -print 2>/dev/null
  done
  printf '\n[loaded kernel collections]\n'
  /usr/bin/kmutil showloaded --list-only 2>&1 || true
}
capture_evidence privileged_helpers 30 collect_privileged_helpers || true

# Running process paths and masquerading.
/bin/ps -ww -axo pid=,ppid=,user=,%cpu=,%mem=,etime=,comm= >"$EVIDENCE_DIR/processes.txt" 2>&1
printf 'pid\tpath\treason\tsha256\n' >"$EVIDENCE_DIR/suspicious_processes.tsv"; PROCESS_ANOMALIES=0
while read -r proc_pid _ppid _user _cpu _mem _etime proc_path; do
  [ -n "${proc_path:-}" ] || continue; proc_reason=""
  case $proc_path in /private/tmp/*|/tmp/*|/var/tmp/*|*/Downloads/*|*/.Trash/*|/dev/fd/*|*/Library/.*) proc_reason="high-risk execution path";; esac
  proc_base=$(/usr/bin/basename "$proc_path" 2>/dev/null || printf unknown)
  case $proc_base in launchd|WindowServer|trustd|securityd|syspolicyd|XProtect|kernel_task) case $proc_path in /System/*|/usr/*|/sbin/*|/bin/*|/Library/Apple/*) :;; *) proc_reason="system name outside trusted path";; esac;; esac
  if [ -n "$proc_reason" ]; then PROCESS_ANOMALIES=$((PROCESS_ANOMALIES + 1)); proc_hash=""; [ -f "$proc_path" ] && proc_hash=$(msc_sha256_file "$proc_path"); printf '%s\t%s\t%s\t%s\n' "$proc_pid" "$(redact_home "$proc_path")" "$proc_reason" "$proc_hash" >>"$EVIDENCE_DIR/suspicious_processes.tsv"; emit_finding_once "process_path_$(msc_short_hash "$proc_path")" processes high medium warn anomaly "Suspicious process path/name" "PID $proc_pid: $(redact_home "$proc_path") ($proc_reason); other PIDs of the same path are listed in the evidence file." "evidence/suspicious_processes.tsv" "Validate parent, signature, persistence, hash, network." || true; fi
done <"$EVIDENCE_DIR/processes.txt"
/usr/bin/awk '{for (i=7;i<=NF;i++) printf "%s%s", $i, (i<NF?OFS:ORS)}' "$EVIDENCE_DIR/processes.txt" | /usr/bin/sort -u | /usr/bin/awk 'NR <= 500' >"$EVIDENCE_DIR/running_paths.txt"
printf 'path\tsha256\n' >"$EVIDENCE_DIR/untrusted_running_macho.tsv"; UNTRUSTED_RUNNING=0
while IFS= read -r running_path; do
  [ -f "$running_path" ] || continue
  case $running_path in /System/*|/usr/*|/bin/*|/sbin/*|/Library/Apple/*) continue;; esac
  /usr/bin/file -b "$running_path" 2>/dev/null | /usr/bin/grep -q 'Mach-O' || continue
  signature_ok=0
  if [ "$MODE" = deep ]; then /usr/bin/codesign --verify --strict "$running_path" >/dev/null 2>&1 && signature_ok=1
  else signature_info=$(/usr/bin/codesign -d --verbose=2 "$running_path" 2>&1); signature_rc=$?; if [ "$signature_rc" -eq 0 ] && ! printf '%s\n' "$signature_info" | /usr/bin/grep -q 'Signature=adhoc'; then signature_ok=1; fi; fi
  if [ "$signature_ok" -eq 0 ] && /usr/sbin/spctl -a -t execute "$running_path" >/dev/null 2>&1; then signature_ok=1; fi
  if [ "$signature_ok" -eq 0 ]; then UNTRUSTED_RUNNING=$((UNTRUSTED_RUNNING + 1)); printf '%s\t%s\n' "$(redact_home "$running_path")" "$(msc_sha256_file "$running_path")" >>"$EVIDENCE_DIR/untrusted_running_macho.tsv"; fi
done <"$EVIDENCE_DIR/running_paths.txt"
if [ "$UNTRUSTED_RUNNING" -gt 0 ]; then emit_finding untrusted_running processes medium medium warn anomaly "Untrusted third-party Mach-O processes are running" "$UNTRUSTED_RUNNING executable(s) failed the selected trust assessment; developer/open-source tools may be legitimate." "evidence/untrusted_running_macho.tsv" "Review hash, origin, parent, persistence, and notarization before containment."
elif [ "$PROCESS_ANOMALIES" -eq 0 ]; then emit_finding running_processes processes info medium pass configuration "No strong process/trust anomaly" "Visible paths, masquerading, and third-party Mach-O trust were checked." "evidence/processes.txt" ""; fi

# Recent executable/archive candidates; no contents copied.
CANDIDATES_ALL="$EVIDENCE_DIR/candidate_files.all"; CANDIDATES="$EVIDENCE_DIR/candidate_files.txt"; : >"$CANDIDATES_ALL"
append_candidates() { candidate_root=$1 candidate_days=$2; [ -d "$candidate_root" ] || return 0; /usr/bin/find -x "$candidate_root" -type f -mtime "-$candidate_days" -size -100m \( -perm -111 -o -name '*.app' -o -name '*.pkg' -o -name '*.dmg' -o -name '*.command' -o -name '*.sh' -o -name '*.py' -o -name '*.js' -o -name '*.jar' \) -print 2>/dev/null; }
{
  append_candidates "$TARGET_HOME/Downloads" 30
  append_candidates /private/tmp 7
  append_candidates /var/tmp 7
  if [ "$MODE" = deep ]; then
    append_candidates "$TARGET_HOME/Library/Application Support" 30
    append_candidates "$TARGET_HOME/Applications" 3650
  fi
} >>"$CANDIDATES_ALL"
if [ -n "$EXTRA_SCAN_PATHS" ]; then printf '%s\n' "$EXTRA_SCAN_PATHS" | while IFS= read -r extra_root; do if [ -d "$extra_root" ]; then append_candidates "$extra_root" 3650; elif [ -f "$extra_root" ]; then printf '%s\n' "$extra_root"; fi; done >>"$CANDIDATES_ALL"; fi
/usr/bin/sort -u "$CANDIDATES_ALL" | /usr/bin/awk -v max="$MAX_CANDIDATES" 'NR <= max' >"$CANDIDATES"
printf 'path\ttype\tmode\tmtime\tquarantine\tsha256\n' >"$EVIDENCE_DIR/candidate_metadata.tsv"; CANDIDATE_COUNT=0
while IFS= read -r candidate; do
  [ -f "$candidate" ] || continue; CANDIDATE_COUNT=$((CANDIDATE_COUNT + 1)); candidate_quarantine=$(/usr/bin/xattr -p com.apple.quarantine "$candidate" 2>/dev/null || true)
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(redact_home "$candidate")" "$(/usr/bin/file -b "$candidate" 2>/dev/null | /usr/bin/tr '\t\r\n' '   ')" "$(/usr/bin/stat -f '%Lp' "$candidate" 2>/dev/null || printf unknown)" "$(/usr/bin/stat -f '%Sm' -t '%Y-%m-%dT%H:%M:%SZ' "$candidate" 2>/dev/null || printf unknown)" "$(printf '%s' "$candidate_quarantine" | /usr/bin/tr '\t\r\n' '   ')" "$(msc_sha256_file "$candidate")" >>"$EVIDENCE_DIR/candidate_metadata.tsv"
done <"$CANDIDATES"
emit_inventory candidate_files malware_scan "Recent/risky candidates" "$CANDIDATE_COUNT file(s) hashed/typed; contents excluded." "evidence/candidate_metadata.tsv"

# Chromium-family extension metadata. Manifest content is untrusted data.
BROWSER_TSV="$EVIDENCE_DIR/browser_extensions.tsv"; BROWSER_JSONL="$EVIDENCE_DIR/browser_extensions.jsonl"
BROWSER_QUEUE_RAW="$EVIDENCE_DIR/browser_manifest_queue.raw.tsv"; BROWSER_QUEUE="$EVIDENCE_DIR/browser_manifest_queue.tsv"
printf 'browser\tprofile\textension_id\tname\tversion\tenabled\tinstall_source\trequired_permissions\thost_permissions\toptional_permissions\tmanifest_sha256\n' >"$BROWSER_TSV"
: >"$BROWSER_JSONL"; : >"$BROWSER_QUEUE_RAW"
for browser_spec in \
  "Chrome|$TARGET_HOME/Library/Application Support/Google/Chrome" \
  "Chromium|$TARGET_HOME/Library/Application Support/Chromium" \
  "Brave|$TARGET_HOME/Library/Application Support/BraveSoftware/Brave-Browser" \
  "Edge|$TARGET_HOME/Library/Application Support/Microsoft Edge"; do
  browser_name=${browser_spec%%|*}; extension_root=${browser_spec#*|}; [ -d "$extension_root" ] || continue
  /usr/bin/find -x "$extension_root" -path '*/Extensions/*/*/manifest.json' -type f -print 2>/dev/null | /usr/bin/awk 'NR <= 2000' | while IFS= read -r manifest; do
    relative_manifest=${manifest#"$extension_root"/}; extension_profile=${relative_manifest%%/*}
    extension_id=$(/usr/bin/basename "$(/usr/bin/dirname "$(/usr/bin/dirname "$manifest")")")
    printf '%s\t%s\t%s\t%s\t%s\n' "$browser_name" "$extension_root" "$extension_profile" "$extension_id" "$manifest"
  done >>"$BROWSER_QUEUE_RAW"
done
LC_ALL=C /usr/bin/sort -r "$BROWSER_QUEUE_RAW" | /usr/bin/awk -F '\t' '!seen[$1 FS $3 FS $4]++' >"$BROWSER_QUEUE"
EXTENSION_COUNT=0 ENABLED_EXTENSION_COUNT=0 DISABLED_EXTENSION_COUNT=0 RISKY_EXTENSION_COUNT=0 DEBUG_NATIVE_COUNT=0
while IFS="$(printf '\t')" read -r browser_name extension_root extension_profile extension_id manifest; do
  [ -r "$manifest" ] || continue; EXTENSION_COUNT=$((EXTENSION_COUNT + 1))
  extension_name=$(jq -r '.name // "unknown"' "$manifest" 2>/dev/null || printf unknown)
  extension_locale=$(jq -r '.default_locale // "en"' "$manifest" 2>/dev/null || printf en)
  case $extension_name in
    __MSG_*__)
      message_key=${extension_name#__MSG_}; message_key=${message_key%__}; locale_file="$(/usr/bin/dirname "$manifest")/_locales/$extension_locale/messages.json"
      [ -r "$locale_file" ] && extension_name=$(jq -r --arg key "$message_key" '.[$key].message // $key' "$locale_file" 2>/dev/null || printf '%s' "$message_key")
      ;;
  esac
  extension_version=$(jq -r '.version // "unknown"' "$manifest" 2>/dev/null || printf unknown)
  required_permissions=$(jq -c '(.permissions // []) | map(select(type=="string")) | unique' "$manifest" 2>/dev/null || printf '[]')
  optional_permissions=$(jq -c '[(.optional_permissions // [])[],(.optional_host_permissions // [])[]] | map(select(type=="string")) | unique' "$manifest" 2>/dev/null || printf '[]')
  host_permissions=$(jq -c '[(.host_permissions // [])[],(.content_scripts // [])[]?.matches[]?] | map(select(type=="string")) | unique' "$manifest" 2>/dev/null || printf '[]')
  secure_preferences="$extension_root/$extension_profile/Secure Preferences"; disable_mask=0; from_webstore=false; install_location=unknown
  if [ -r "$secure_preferences" ]; then
    disable_mask=$(jq -r --arg id "$extension_id" '(.extensions.settings[$id].disable_reasons // []) | add // 0' "$secure_preferences" 2>/dev/null || printf 0)
    from_webstore=$(jq -r --arg id "$extension_id" '.extensions.settings[$id].from_webstore // false' "$secure_preferences" 2>/dev/null || printf false)
    install_location=$(jq -r --arg id "$extension_id" '.extensions.settings[$id].location // "unknown"' "$secure_preferences" 2>/dev/null || printf unknown)
  fi
  enabled=true; [ "$disable_mask" -ne 0 ] && enabled=false
  if [ "$enabled" = true ]; then ENABLED_EXTENSION_COUNT=$((ENABLED_EXTENSION_COUNT + 1)); else DISABLED_EXTENSION_COUNT=$((DISABLED_EXTENSION_COUNT + 1)); fi
  broad_or_powerful=$(jq -n --argjson required "$required_permissions" --argjson hosts "$host_permissions" '(($required + $hosts) | any(. == "debugger" or . == "nativeMessaging" or . == "management" or . == "cookies" or . == "history" or . == "webRequest" or . == "<all_urls>" or . == "http://*/*" or . == "https://*/*" or . == "*://*/*"))')
  debugger_native=$(jq -n --argjson required "$required_permissions" '(($required | index("debugger")) != null) and (($required | index("nativeMessaging")) != null)')
  [ "$enabled" = true ] && [ "$broad_or_powerful" = true ] && RISKY_EXTENSION_COUNT=$((RISKY_EXTENSION_COUNT + 1))
  [ "$enabled" = true ] && [ "$debugger_native" = true ] && DEBUG_NATIVE_COUNT=$((DEBUG_NATIVE_COUNT + 1))
  install_source=other; [ "$from_webstore" = true ] && install_source=chrome_web_store; manifest_hash=$(msc_sha256_file "$manifest")
  jq -cn --arg browser "$browser_name" --arg profile "$extension_profile" --arg id "$extension_id" --arg name "$extension_name" --arg version "$extension_version" --argjson enabled "$enabled" --arg source "$install_source" --arg location "$install_location" --argjson required "$required_permissions" --argjson hosts "$host_permissions" --argjson optional "$optional_permissions" --argjson disable_mask "$disable_mask" --arg hash "$manifest_hash" --argjson broad "$broad_or_powerful" '{schema:"macos-security-browser-extension/v1",record_type:"browser_extension",browser:$browser,profile:$profile,id:$id,name:$name,version:$version,enabled:$enabled,install_source:$source,install_location:$location,permissions:{required:$required,hosts:$hosts,optional:$optional},disable_reason_mask:$disable_mask,broad_or_powerful:$broad,manifest_sha256:$hash,evidence_trust:"untrusted_observations"}' >>"$BROWSER_JSONL"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$browser_name" "$extension_profile" "$extension_id" "$(printf '%s' "$extension_name" | /usr/bin/tr '\t\r\n' '   ')" "$extension_version" "$enabled" "$install_source" "$required_permissions" "$host_permissions" "$optional_permissions" "$manifest_hash" >>"$BROWSER_TSV"
done <"$BROWSER_QUEUE"
if [ "$RISKY_EXTENSION_COUNT" -gt 0 ]; then emit_finding browser_extensions browser medium medium warn exposure "Enabled extensions have broad or powerful access" "$RISKY_EXTENSION_COUNT of $ENABLED_EXTENSION_COUNT enabled extension(s); debugger+nativeMessaging=$DEBUG_NATIVE_COUNT; disabled=$DISABLED_EXTENSION_COUNT." "evidence/browser_extensions.jsonl" "Review ID, publisher, site access, incognito/file access and necessity in chrome://extensions."
else emit_inventory browser_extensions browser "Browser extension inventory" "$EXTENSION_COUNT unique extension(s); enabled=$ENABLED_EXTENSION_COUNT disabled=$DISABLED_EXTENSION_COUNT." "evidence/browser_extensions.jsonl"; fi

# Bounded, category-specific security history. Raw log strings are untrusted data.
LOG_TIMEOUT=25; [ "$MODE" = deep ] && LOG_TIMEOUT=45
msc_run_with_timeout "$LOG_TIMEOUT" "$EVIDENCE_DIR/xprotect_events.raw.log" /usr/bin/log show --last "${LOOKBACK_HOURS}h" --style compact --info --predicate '(process == "XProtect" OR process == "XProtectRemediator")'; XPROTECT_LOG_RC=$?
/usr/bin/tail -n 1800 "$EVIDENCE_DIR/xprotect_events.raw.log" >"$EVIDENCE_DIR/xprotect_events.log"; printf '\n[log_exit_status=%s timeout_seconds=%s]\n' "$XPROTECT_LOG_RC" "$LOG_TIMEOUT" >>"$EVIDENCE_DIR/xprotect_events.log"; /bin/rm -f "$EVIDENCE_DIR/xprotect_events.raw.log"
msc_run_with_timeout "$LOG_TIMEOUT" "$EVIDENCE_DIR/gatekeeper_events.raw.log" /usr/bin/log show --last "${LOOKBACK_HOURS}h" --style compact --predicate '(process == "syspolicyd" AND (eventMessage CONTAINS[c] "Gatekeeper" OR eventMessage CONTAINS[c] "assessment" OR eventMessage CONTAINS[c] "notarization"))'; GATEKEEPER_LOG_RC=$?
/usr/bin/tail -n 1800 "$EVIDENCE_DIR/gatekeeper_events.raw.log" >"$EVIDENCE_DIR/gatekeeper_events.log"; printf '\n[log_exit_status=%s timeout_seconds=%s]\n' "$GATEKEEPER_LOG_RC" "$LOG_TIMEOUT" >>"$EVIDENCE_DIR/gatekeeper_events.log"; /bin/rm -f "$EVIDENCE_DIR/gatekeeper_events.raw.log"
if msc_xprotect_log_has_event "$EVIDENCE_DIR/xprotect_events.log"; then emit_finding historical_malware_event malware_scan high medium warn detection "XProtect logs contain possible malware events" "Inspect exact objects/times." "evidence/xprotect_events.log" "Preserve and validate with a second source."
elif [ "$XPROTECT_LOG_RC" -ne 0 ]; then emit_finding historical_malware_event malware_scan low medium warn visibility_gap "XProtect log search partial" "Bounded query exit=$XPROTECT_LOG_RC." "evidence/xprotect_events.log" "Use EDR/SIEM for longer history."
else emit_finding historical_malware_event malware_scan info low pass detection "No explicit malware event in visible XProtect logs" "No detection phrase in $LOOKBACK_HOURS hour(s); not proof of absence." "evidence/xprotect_events.log" ""; fi
if [ "$GATEKEEPER_LOG_RC" -ne 0 ]; then emit_finding gatekeeper_log_visibility logging low medium warn visibility_gap "Gatekeeper log search partial" "Bounded query exit=$GATEKEEPER_LOG_RC." "evidence/gatekeeper_events.log" "Use shorter lookback or centralized logging."
else emit_inventory gatekeeper_events logging "Gatekeeper/notarization log inventory" "Bounded query completed; absence of events is not proof of absence." "evidence/gatekeeper_events.log"; fi

# The composed assessment delegates scanner selection to the adapter runner.
if [ "$LOCAL_SCANNERS" -eq 1 ] && [ "$(/usr/bin/id -u)" -ne 0 ]; then
if command -v clamscan >/dev/null 2>&1 && [ "$CANDIDATE_COUNT" -gt 0 ]; then
  CLAMSCAN_BIN=$(command -v clamscan); msc_run_with_timeout 600 "$EVIDENCE_DIR/clamav.txt" "$CLAMSCAN_BIN" --infected --no-summary --max-filesize=100M --file-list="$CANDIDATES"; CLAM_RC=$?
  case $CLAM_RC in 0) emit_finding clamav malware_scan info medium pass detection "ClamAV found no local match" "Local signatures only." "evidence/clamav.txt" "";; 1) emit_finding clamav malware_scan critical high fail detection "ClamAV reported candidate" "Validate before containment." "evidence/clamav.txt" "Preserve and follow IR.";; *) emit_finding clamav malware_scan low medium error visibility_gap "ClamAV incomplete" "exit=$CLAM_RC" "evidence/clamav.txt" "Review errors/signature age.";; esac
else printf '%s\n' 'clamscan unavailable or no candidates.' >"$EVIDENCE_DIR/clamav.txt"; emit_inventory clamav malware_scan "ClamAV integration" "Optional scanner unused." "evidence/clamav.txt"; fi
if [ -n "$YARA_RULES" ]; then
  : >"$EVIDENCE_DIR/dependency-install.log"
  if [ -f "$YARA_RULES" ] && ! command -v yara >/dev/null 2>&1; then
    msd_ensure yara "$EVIDENCE_DIR/dependency-install.log" >/dev/null 2>&1 || true
  fi
  if ! command -v yara >/dev/null 2>&1 || [ ! -f "$YARA_RULES" ]; then printf 'Unavailable yara/rules: %s\n' "$YARA_RULES" >"$EVIDENCE_DIR/yara.txt"; emit_finding yara malware_scan low high error visibility_gap "YARA unavailable" "Binary/rules missing." "evidence/yara.txt" "Correct installation/path."
  else
    YARA_BIN=$(command -v yara)
    YARA_ERRORS=0
    if [ -s "$CANDIDATES" ]; then
      msc_run_timed_capture 600 "$EVIDENCE_DIR/yara.txt" "$EVIDENCE_DIR/yara.stderr" "$EVIDENCE_DIR/.yara.timeout" \
        "$YARA_BIN" --scan-list -w -a 30 -z 104857600 "$YARA_RULES" "$CANDIDATES" || YARA_ERRORS=1
    else
      : >"$EVIDENCE_DIR/yara.txt"
    fi
    YARA_MATCHES=$(/usr/bin/awk 'NF && $0 !~ /^(warning|error):/ {n++} END {print n+0}' "$EVIDENCE_DIR/yara.txt")
    if [ "$YARA_ERRORS" -gt 0 ]; then emit_finding yara malware_scan low high error visibility_gap "YARA scan incomplete" "The bounded scan returned an error; stdout matches=$YARA_MATCHES." "evidence/yara.txt" "Review rules, permissions, limits, and errors."
    elif [ "$YARA_MATCHES" -gt 0 ]; then emit_finding yara malware_scan high medium warn detection "YARA produced matches" "$YARA_MATCHES match output line(s)." "evidence/yara.txt" "Validate with second source."
    else emit_finding yara malware_scan info medium pass detection "YARA found no match" "Supplied rules found none in the bounded candidate set; this is not proof of absence." "evidence/yara.txt" ""; fi
  fi
else printf '%s\n' 'No --yara-rules supplied.' >"$EVIDENCE_DIR/yara.txt"; emit_inventory yara malware_scan "YARA integration" "Not requested." "evidence/yara.txt"; fi

if command -v osqueryi >/dev/null 2>&1; then
  OSQUERY_BIN=$(command -v osqueryi); OSQUERY_TMP="$EVIDENCE_DIR/.osquery.$$"
  msc_run_with_timeout 35 "$OSQUERY_TMP.processes" "$OSQUERY_BIN" --json 'select pid,parent,name,path,uid from processes;'; OSQ_P=$?
  msc_run_with_timeout 35 "$OSQUERY_TMP.listeners" "$OSQUERY_BIN" --json 'select pid,address,port,protocol,family from listening_ports;'; OSQ_L=$?
  msc_run_with_timeout 35 "$OSQUERY_TMP.launchd" "$OSQUERY_BIN" --json 'select name,path,program,run_at_load,keep_alive from launchd;'; OSQ_D=$?
  if [ "$OSQ_P" -eq 0 ] && [ "$OSQ_L" -eq 0 ] && [ "$OSQ_D" -eq 0 ] && jq -e . "$OSQUERY_TMP.processes" "$OSQUERY_TMP.listeners" "$OSQUERY_TMP.launchd" >/dev/null 2>&1; then
    jq -n --slurpfile processes "$OSQUERY_TMP.processes" --slurpfile listeners "$OSQUERY_TMP.listeners" --slurpfile launchd "$OSQUERY_TMP.launchd" '{processes:$processes[0],listeners:$listeners[0],launchd:$launchd[0]}' >"$EVIDENCE_DIR/osquery.json"
    emit_inventory osquery tooling "osquery inventory" "Snapshot tables collected as one valid JSON object; event tables were not tested." "evidence/osquery.json"
  else
    printf 'processes_exit=%s listeners_exit=%s launchd_exit=%s\n' "$OSQ_P" "$OSQ_L" "$OSQ_D" >"$EVIDENCE_DIR/osquery.error.txt"
    emit_finding osquery tooling low high error visibility_gap "osquery snapshot incomplete" "One or more tables failed or returned invalid JSON." "evidence/osquery.error.txt" "Check whether the installed osquery version supports these tables on this release of macOS."
  fi
  /bin/rm -f "$OSQUERY_TMP.processes" "$OSQUERY_TMP.listeners" "$OSQUERY_TMP.launchd" "$OSQUERY_TMP.stderr"
else printf '%s\n' 'osqueryi unavailable.' >"$EVIDENCE_DIR/osquery.json.txt"; emit_inventory osquery tooling "osquery integration" "Native checks used." "evidence/osquery.json.txt"; fi
else
  emit_inventory local_scanners tooling "Standalone scanners skipped" "Use an unprivileged adapter run for optional scanners." ""
fi

# Use the same bounded monitor and normalised event stream as the CLI.
if [ "$MONITOR_SECONDS" -gt 0 ]; then
  MONITOR_SUMMARY="$EVIDENCE_DIR/monitor-summary.json"
  if "$SCRIPT_DIR/macos-security-monitor.sh" --duration "$MONITOR_SECONDS" --interval "$MONITOR_INTERVAL" \
       --target-user "$TARGET_USER" --no-auto-install --output-root "$EVIDENCE_DIR/monitor" >"$MONITOR_SUMMARY" &&
     jq -e '.visibility=="full" or .visibility=="partial"' "$MONITOR_SUMMARY" >/dev/null; then
    if jq -e '.correlation_finding_count>0' "$MONITOR_SUMMARY" >/dev/null; then
      emit_finding monitor_detection monitoring high high warn detection "Live high-value event" "Review the correlated Endpoint Security findings." "evidence/monitor-summary.json" "Preserve and follow IR."
    fi
    if jq -e '.visibility=="partial"' "$MONITOR_SUMMARY" >/dev/null; then
      emit_finding monitor_eslogger monitoring low high warn visibility_gap "Endpoint Security monitoring incomplete" "Snapshot monitoring may still be available." "evidence/monitor-summary.json" "Review the monitor status and macOS approvals."
    else
      emit_inventory monitor_complete monitoring "Bounded monitoring completed" "The monitor saved snapshots and a normalised timeline." "evidence/monitor-summary.json"
    fi
  else
    emit_finding monitor_incomplete monitoring low high error visibility_gap "Bounded monitoring incomplete" "The monitor failed to produce a summary." "evidence/monitor-summary.json" "Review monitor diagnostics."
  fi
fi

RISK_SCORE=$((CRITICAL_RISK * 40 + HIGH_RISK * 15 + MEDIUM_RISK * 5 + LOW_RISK)); [ "$RISK_SCORE" -le 100 ] || RISK_SCORE=100
if [ "$CRITICAL_RISK" -gt 0 ]; then OVERALL=critical; elif [ "$HIGH_RISK" -gt 0 ]; then OVERALL=high; elif [ "$MEDIUM_RISK" -gt 0 ]; then OVERALL=medium; elif [ "$LOW_RISK" -gt 0 ]; then OVERALL=low; else OVERALL=informational; fi
COMPLETED_AT=$(msc_utc_now)
cat >"$SUMMARY_FILE" <<EOF
{"schema":"$SCHEMA_VERSION","record_type":"summary","suite_role":"triage","run_id":"$(msc_jesc "$RUN_ID")","completed_at":"$COMPLETED_AT","overall":"$OVERALL","risk_score_0_100":$RISK_SCORE,"counts":{"findings":$FINDING_COUNT,"pass":$PASS_COUNT,"info":$INFO_COUNT,"warn":$WARN_COUNT,"fail":$FAIL_COUNT,"error":$ERROR_COUNT,"critical_risk":$CRITICAL_RISK,"high_risk":$HIGH_RISK,"medium_risk":$MEDIUM_RISK,"low_risk":$LOW_RISK},"interpretation":"Posture failure is configuration risk; detection is stronger than anomaly; clean triage does not prove absence of compromise.","posture_evidence":"evidence/posture.jsonl","report_dir":"$(msc_jesc "$OUTPUT_DIR")"}
EOF
emit_line "$(/usr/bin/tr -d '\n' <"$SUMMARY_FILE")"
if ! (
  CDPATH='' cd -- "$OUTPUT_DIR" || exit 1
  find evidence -type f -print | LC_ALL=C /usr/bin/sort | while IFS= read -r evidence_file; do /usr/bin/shasum -a 256 "$evidence_file"; done
  /usr/bin/shasum -a 256 report.jsonl summary.json
) >"$OUTPUT_DIR/SHA256SUMS"; then
  printf '%s\n' 'Failed to create evidence integrity manifest.' >&2
  exit 2
fi
printf 'Triage complete: %s (overall=%s score=%s)\n' "$OUTPUT_DIR" "$OVERALL" "$RISK_SCORE" >&2
[ "$INCOMPLETE" -eq 0 ] || exit 2
if [ "$CRITICAL_RISK" -gt 0 ] || [ "$HIGH_RISK" -gt 0 ]; then exit 1; fi
exit 0
