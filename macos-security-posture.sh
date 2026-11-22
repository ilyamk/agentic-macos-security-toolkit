#!/bin/sh
# SPDX-License-Identifier: MIT
# Read-only macOS security posture collector for macOS.
# Output: one self-contained JSON object per line (JSONL/NDJSON).
# shellcheck disable=SC2329
# Helper functions below are invoked indirectly through capture/collect.

set -u
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
COMMON_LIB="$SCRIPT_DIR/lib/macos_security_common.sh"
if [ ! -r "$COMMON_LIB" ]; then
    printf '%s: required library is missing: %s\n' "${0##*/}" "$COMMON_LIB" >&2
    exit 70
fi
# shellcheck source=lib/macos_security_common.sh
. "$COMMON_LIB"
# shellcheck source=lib/macos_security_updates.sh
. "$SCRIPT_DIR/lib/macos_security_updates.sh"

PROGRAM=${0##*/}
VERSION="3.0.0"
SCHEMA_VERSION="3.0"
REFERENCE_DATE=""
REFERENCE_PATCH_VERSION=""
APPLE_SECURITY_RELEASES="https://support.apple.com/100100"
APPLE_PLATFORM_SECURITY="https://support.apple.com/guide/security/welcome/web"
NIST_MSCP="https://pages.nist.gov/macos_security/"
CIS_MACOS="https://www.cisecurity.org/benchmark/apple_os"

PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec:/opt/homebrew/bin:/usr/local/bin"
export PATH
msc_system_path_if_root
LC_ALL=C
export LC_ALL

MODE="standard"
ONLINE=0
REDACT=0
BACKGROUND_ITEMS=0
INCIDENT_LOGS=1
FAIL_ON_FINDINGS=0
LOG_HOURS=24
MAX_OUTPUT_BYTES=131072
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
INFO_COUNT=0
UNKNOWN_COUNT=0
EVIDENCE_COUNT=0
DENIED_COUNT=0
ERROR_COUNT=0
TIMEOUT_COUNT=0
TARGET_USER=""
OUTPUT_DIR=""

usage() {
    cat <<EOF
Usage: $PROGRAM [options]

Collect a read-only macOS security posture report for analysis by a security
agent. Writes JSONL to stdout by default. To save a private report, use
--output security-results/posture from the project directory.

Options:
  --quick                 Core findings and compact evidence only
  --deep                  Add app signatures, persistence metadata, TCC and logs
  --background-items      Request background-item inventory, which may prompt
  --online                Ask softwareupdate for currently available updates
  --redact                Best-effort masking of host/user/network identifiers
  --log-hours N           Security-log lookback for --deep (1-168, default 24)
  --max-output-kb N       Per evidence-record limit (16-1024, default 128)
  --target-user USER      User context to inspect (defaults to SUDO_USER/caller)
  --output DIR            Save posture.jsonl in a new private report directory
  --fail-on-findings      Exit 1 if FAIL findings exist, otherwise exit 0
  -h, --help              Show this help
  -V, --version           Show version

The script never invokes sudo. Run it as root only if you intentionally want
PF, system TCC, audit and other privileged evidence included.
EOF
}

die_usage() {
    printf '%s: %s\n' "$PROGRAM" "$1" >&2
    printf 'Try %s --help\n' "$PROGRAM" >&2
    exit 64
}

is_uint() {
    msc_is_uint "$1"
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --quick) MODE="quick" ;;
        --deep) MODE="deep" ;;
        --online) ONLINE=1 ;;
        --redact) REDACT=1 ;;
        --background-items) BACKGROUND_ITEMS=1 ;;
        --skip-incident-logs) INCIDENT_LOGS=0 ;;
        --fail-on-findings) FAIL_ON_FINDINGS=1 ;;
        --log-hours)
            [ "$#" -ge 2 ] || die_usage "--log-hours requires a value"
            shift
            is_uint "$1" || die_usage "--log-hours must be an integer"
            [ "$1" -ge 1 ] && [ "$1" -le 168 ] || die_usage "--log-hours must be 1..168"
            LOG_HOURS=$1
            ;;
        --max-output-kb)
            [ "$#" -ge 2 ] || die_usage "--max-output-kb requires a value"
            shift
            is_uint "$1" || die_usage "--max-output-kb must be an integer"
            [ "$1" -ge 16 ] && [ "$1" -le 1024 ] || die_usage "--max-output-kb must be 16..1024"
            MAX_OUTPUT_BYTES=$(( $1 * 1024 ))
            ;;
        --target-user)
            [ "$#" -ge 2 ] || die_usage "--target-user requires a value"
            shift
            TARGET_USER=$1
            ;;
        --output)
            [ "$#" -ge 2 ] && [ -n "$2" ] || die_usage "--output requires a directory"
            shift
            OUTPUT_DIR=$1
            ;;
        -h|--help) usage; exit 0 ;;
        -V|--version) printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
        --) shift; [ "$#" -eq 0 ] || die_usage "unexpected positional arguments"; break ;;
        -*) die_usage "unknown option: $1" ;;
        *) die_usage "unexpected argument: $1" ;;
    esac
    shift
done

[ -n "$TARGET_USER" ] || TARGET_USER=$(msc_default_target_user)
msc_validate_target_user "$TARGET_USER" || die_usage "target user is invalid or unavailable: $TARGET_USER"
TARGET_HOME=$(msc_target_home "$TARGET_USER")
[ -n "$TARGET_HOME" ] || die_usage "cannot resolve home for target user: $TARGET_USER"
EFFECTIVE_USER=$(/usr/bin/id -un)

REPORT_TMP=$(msc_mktemp_dir macos-security-posture) || {
    printf '%s: cannot create temporary directory\n' "$PROGRAM" >&2
    exit 70
}

cleanup() {
    # REPORT_TMP is created by mktemp above and never accepts user input.
    rm -rf "$REPORT_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "$OUTPUT_DIR" ]; then
    REPORT_DIR=$(msc_create_private_dir "$OUTPUT_DIR") || die_usage "cannot create private report directory"
    exec >"$REPORT_DIR/posture.jsonl"
fi

json_escape() {
    printf '%s' "$1" | msc_json_escape
}

jqstr() {
    printf '"%s"' "$(json_escape "$1")"
}

emit_meta() {
    printf '{"record_type":"meta","schema_version":%s,"suite_role":"posture","collector":%s,"collector_version":%s,"generated_at_utc":%s,"reference_date":%s,"reference_patch_version":%s,"mode":%s,"online":%s,"redacted":%s,"effective_uid":%s,"effective_user":%s,"target_user":%s,"target_home":%s,"hostname":%s,"evidence_trust":%s,"notice":%s}\n' \
        "$(jqstr "$SCHEMA_VERSION")" "$(jqstr "$PROGRAM")" "$(jqstr "$VERSION")" \
        "$(jqstr "$GENERATED_AT")" "$(jqstr "$REFERENCE_DATE")" \
        "$(jqstr "$REFERENCE_PATCH_VERSION")" "$(jqstr "$MODE")" "$ONLINE" "$REDACT" \
        "$(id -u)" "$(jqstr "$REPORT_EFFECTIVE_USER")" "$(jqstr "$REPORT_TARGET_USER")" \
        "$(jqstr "$REPORT_TARGET_HOME")" "$(jqstr "$REPORT_HOSTNAME")" \
        "$(jqstr "untrusted_observations")" \
        "$(jqstr "Read-only point-in-time evidence. UNKNOWN/DENIED is not equivalent to insecure. Findings are baseline guidance, not proof of compromise.")"
}

emit_finding() {
    _id=$1; _category=$2; _status=$3; _severity=$4; _title=$5
    _summary=$6; _evidence=$7; _recommendation=$8; _reference=$9
    if [ "$REDACT" -eq 1 ]; then
        _summary=$(printf '%s' "$_summary" | redact_stream)
        _evidence=$(printf '%s' "$_evidence" | redact_stream)
        _recommendation=$(printf '%s' "$_recommendation" | redact_stream)
    fi

    case $_status in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        INFO) INFO_COUNT=$((INFO_COUNT + 1)) ;;
        UNKNOWN) UNKNOWN_COUNT=$((UNKNOWN_COUNT + 1)) ;;
    esac

    printf '{"record_type":"finding","schema_version":%s,"id":%s,"category":%s,"status":%s,"severity":%s,"title":%s,"summary":%s,"evidence":%s,"recommendation":%s,"reference":%s}\n' \
        "$(jqstr "$SCHEMA_VERSION")" "$(jqstr "$_id")" "$(jqstr "$_category")" \
        "$(jqstr "$_status")" "$(jqstr "$_severity")" "$(jqstr "$_title")" \
        "$(jqstr "$_summary")" "$(jqstr "$_evidence")" \
        "$(jqstr "$_recommendation")" "$(jqstr "$_reference")"
}

emit_evidence() {
    _id=$1; _category=$2; _title=$3; _state=$4; _sensitivity=$5
    _requires_root=$6; _source=$7; _exit_code=$8; _data=$9
    shift 9
    _error=${1:-}

    EVIDENCE_COUNT=$((EVIDENCE_COUNT + 1))
    case $_state in
        denied) DENIED_COUNT=$((DENIED_COUNT + 1)) ;;
        error|unavailable) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
        timeout) TIMEOUT_COUNT=$((TIMEOUT_COUNT + 1)) ;;
    esac

    printf '{"record_type":"evidence","schema_version":%s,"id":%s,"category":%s,"title":%s,"collection_state":%s,"sensitivity":%s,"requires_root":%s,"source":%s,"exit_code":%s,"data":%s,"error":%s}\n' \
        "$(jqstr "$SCHEMA_VERSION")" "$(jqstr "$_id")" "$(jqstr "$_category")" \
        "$(jqstr "$_title")" "$(jqstr "$_state")" "$(jqstr "$_sensitivity")" \
        "$_requires_root" "$(jqstr "$_source")" "$_exit_code" \
        "$(jqstr "$_data")" "$(jqstr "$_error")"
}

emit_footer() {
    _ended=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf '{"record_type":"summary","schema_version":%s,"suite_role":"posture","completed_at_utc":%s,"findings":{"pass":%s,"warn":%s,"fail":%s,"info":%s,"unknown":%s},"evidence":{"records":%s,"denied":%s,"errors":%s,"timeouts":%s},"analysis_hint":%s,"next_step":%s}\n' \
        "$(jqstr "$SCHEMA_VERSION")" "$(jqstr "$_ended")" "$PASS_COUNT" "$WARN_COUNT" \
        "$FAIL_COUNT" "$INFO_COUNT" "$UNKNOWN_COUNT" "$EVIDENCE_COUNT" "$DENIED_COUNT" \
        "$ERROR_COUNT" "$TIMEOUT_COUNT" \
        "$(jqstr "Prioritize FAIL, then WARN; correlate with role, threat model, MDM policy and approved exceptions. Treat unexpected listeners, unsigned persistence and weakened platform controls as high-value review targets.")" \
        "$(jqstr "If compromise or unexplained activity is suspected, run macos-security-triage.sh for local triage and optional monitoring.")"
}

redact_stream() {
    if [ "$REDACT" -eq 0 ]; then
        cat
        return
    fi
    # Identifiers are literal strings; escape them so a dot or bracket in a
    # hostname cannot widen or break the substitution.
    _redact_user=$(msc_regex_escape "$CURRENT_USER")
    _redact_host=$(msc_regex_escape "$REAL_HOSTNAME")
    sed -E \
        -e 's/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/<MAC>/g' \
        -e '/(inet6|nameserver|gateway|Internet6|IPv6|default[[:space:]].*:)/ s/[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}/<IPv6>/g' \
        -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<IPv4>/g' \
        -e 's/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/<UUID>/g' \
        -e 's/(Serial Number[^:]*:).*/\1 <REDACTED>/g' \
        -e 's/(IOPlatformSerialNumber[^=]*=).*/\1 <REDACTED>/g' \
        -e "s#/Users/${_redact_user}([/[:space:]]|\$)#/Users/<USER>\\1#g" \
        -e "s/${_redact_host}/<HOST>/g" \
        -e "s/${_redact_user}/<USER>/g"
}

limit_file() {
    _input=$1; _output=$2
    _bytes=$(wc -c < "$_input" | tr -d ' ')
    if [ "$_bytes" -gt "$MAX_OUTPUT_BYTES" ]; then
        head -c "$MAX_OUTPUT_BYTES" "$_input" > "$_output"
        printf '\n[TRUNCATED: original_bytes=%s limit_bytes=%s]\n' "$_bytes" "$MAX_OUTPUT_BYTES" >> "$_output"
    else
        cp "$_input" "$_output"
    fi
}

run_timed() {
    msc_run_timed_capture "$@"
}

capture() {
    _timeout=$1
    shift
    CAPTURE_OUT="$REPORT_TMP/capture.out"
    CAPTURE_ERR="$REPORT_TMP/capture.err"
    CAPTURE_MARK="$REPORT_TMP/capture.timeout"
    run_timed "$_timeout" "$CAPTURE_OUT" "$CAPTURE_ERR" "$CAPTURE_MARK" "$@"
    CAPTURE_RC=$?
    CAPTURE_DATA=$(cat "$CAPTURE_OUT")
    CAPTURE_ERROR=$(cat "$CAPTURE_ERR")
    if [ -e "$CAPTURE_MARK" ]; then
        CAPTURE_STATE="timeout"
        CAPTURE_RC=124
    elif [ "$CAPTURE_RC" -eq 0 ]; then
        CAPTURE_STATE="collected"
    elif printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR" | grep -Eiq 'operation not permitted|permission denied|must be root|requires.*root|not authorized|authorization denied'; then
        CAPTURE_STATE="denied"
    else
        CAPTURE_STATE="error"
    fi
}

collect() {
    _timeout=$1; _id=$2; _category=$3; _title=$4; _sensitivity=$5
    _requires_root=$6; _source=$7
    shift 7

    _command=$1
    if ! command -v "$_command" >/dev/null 2>&1; then
        emit_evidence "$_id" "$_category" "$_title" "unavailable" "$_sensitivity" \
            "$_requires_root" "$_source" 127 "" "command unavailable: $_command"
        return
    fi

    capture "$_timeout" "$@"
    _combined_raw="$REPORT_TMP/combined.raw"
    _combined_safe="$REPORT_TMP/combined.safe"
    _combined_limited="$REPORT_TMP/combined.limited"
    cat "$CAPTURE_OUT" >"$_combined_raw"
    redact_stream <"$_combined_raw" >"$_combined_safe"
    limit_file "$_combined_safe" "$_combined_limited"
    _data=$(cat "$_combined_limited")
    _error=$(printf '%s' "$CAPTURE_ERROR" | redact_stream)
    emit_evidence "$_id" "$_category" "$_title" "$CAPTURE_STATE" "$_sensitivity" \
        "$_requires_root" "$_source" "$CAPTURE_RC" "$_data" "$_error"
}

check_contains() {
    _id=$1; _category=$2; _title=$3; _pass_pattern=$4; _severity=$5
    _pass_summary=$6; _fail_summary=$7; _recommendation=$8; _reference=$9
    shift 9
    capture 15 "$@"
    _all=$(printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR")
    if [ "$CAPTURE_STATE" != "collected" ]; then
        emit_finding "$_id" "$_category" "UNKNOWN" "$_severity" "$_title" \
            "State could not be determined (${CAPTURE_STATE})." "$_all" \
            "$_recommendation" "$_reference"
    elif printf '%s' "$_all" | grep -Eiq "$_pass_pattern"; then
        emit_finding "$_id" "$_category" "PASS" "none" "$_title" \
            "$_pass_summary" "$_all" "No action required; monitor for changes." "$_reference"
    else
        emit_finding "$_id" "$_category" "FAIL" "$_severity" "$_title" \
            "$_fail_summary" "$_all" "$_recommendation" "$_reference"
    fi
}

pref_value() {
    defaults read "$1" "$2"
}

collect_update_packages() {
    pkgutil --pkgs | grep -E 'XProtect|Gatekeeper|MRT|ConfigData|Security' | while IFS= read -r _pkg; do
        _version=$(pkgutil --pkg-info "$_pkg" 2>/dev/null | awk -F': ' '$1 == "version" {print $2}')
        _time=$(pkgutil --pkg-info "$_pkg" 2>/dev/null | awk -F': ' '$1 == "install-time" {print $2}')
        printf '%s\tversion=%s\tinstall_time_epoch=%s\n' "$_pkg" "$_version" "$_time"
    done
}

collect_network_services() {
    networksetup -listallnetworkservices 2>/dev/null | sed '1d' | while IFS= read -r _service; do
        [ -n "$_service" ] || continue
        case $_service in \** ) _service=${_service#\*} ;; esac
        printf '\n[service] %s\n' "$_service"
        networksetup -getinfo "$_service" 2>&1
        printf '[dns] '; networksetup -getdnsservers "$_service" 2>&1 | tr '\n' ' '; printf '\n'
        printf '[web_proxy] '; networksetup -getwebproxy "$_service" 2>&1 | tr '\n' ' '; printf '\n'
        printf '[secure_web_proxy] '; networksetup -getsecurewebproxy "$_service" 2>&1 | tr '\n' ' '; printf '\n'
        printf '[auto_proxy] '; networksetup -getautoproxyurl "$_service" 2>&1 | tr '\n' ' '; printf '\n'
    done
}

collect_firewall() {
    _fw=/usr/libexec/ApplicationFirewall/socketfilterfw
    for _flag in --getglobalstate --getstealthmode --getblockall --getallowsigned --getloggingmode --listapps; do
        printf '[%s]\n' "$_flag"
        "$_fw" "$_flag" 2>&1
    done
}

collect_launch_metadata() {
    for _dir in /Library/LaunchAgents /Library/LaunchDaemons "$USER_HOME/Library/LaunchAgents" /Library/StartupItems; do
        [ -d "$_dir" ] || continue
        find "$_dir" -maxdepth 2 -type f -name '*.plist' -print | sort | while IFS= read -r _plist; do
            _owner_mode=$(stat -f 'owner=%Su group=%Sg mode=%Sp' "$_plist" 2>/dev/null)
            _label=$(plutil -extract Label raw -o - "$_plist" 2>/dev/null || true)
            _program=$(plutil -extract Program raw -o - "$_plist" 2>/dev/null || true)
            _run=$(plutil -extract RunAtLoad raw -o - "$_plist" 2>/dev/null || true)
            _keep=$(plutil -extract KeepAlive raw -o - "$_plist" 2>/dev/null || true)
            printf '%s\t%s\tlabel=%s\tprogram=%s\trun_at_load=%s\tkeep_alive=%s\n' \
                "$_plist" "$_owner_mode" "$_label" "$_program" "$_run" "$_keep"
        done
    done
}

collect_periodic_and_cron() {
    for _path in /etc/crontab /etc/periodic /Library/Scripts /var/at/jobs; do
        if [ -e "$_path" ]; then
            printf '\n[%s]\n' "$_path"
            find "$_path" -maxdepth 2 -type f -print -exec stat -f '  owner=%Su group=%Sg mode=%Sp modified=%Sm' {} \; 2>&1
        fi
    done
    printf '\n[current user crontab]\n'
    crontab -l 2>&1 || true
}

collect_sshd_configuration() {
    for _file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$_file" ] || continue
        printf '\n[%s]\n' "$_file"
        awk 'NF && $1 !~ /^#/' "$_file"
    done
}

collect_tcc_summary() {
    _tcc_denied=0
    for _db in /Library/Application\ Support/com.apple.TCC/TCC.db "$USER_HOME/Library/Application Support/com.apple.TCC/TCC.db"; do
        printf '\n[database] %s\n' "$_db"
        if [ ! -r "$_db" ]; then
            printf 'UNREADABLE: Full Disk Access or root may be required\n'
            _tcc_denied=1
            continue
        fi
        sqlite3 -readonly -header -column "$_db" \
            'SELECT service, client, auth_value, auth_reason, COUNT(*) AS entries FROM access GROUP BY service, client, auth_value, auth_reason ORDER BY service, client;' 2>&1
    done
    if [ "$_tcc_denied" -ne 0 ]; then
        printf 'Permission denied for one or more TCC databases; evidence is partial.\n' >&2
        return 1
    fi
}

collect_app_inventory() {
    find /Applications "$USER_HOME/Applications" -maxdepth 3 -type d -name '*.app' -prune 2>/dev/null | sort | while IFS= read -r _app; do
        _info="$_app/Contents/Info.plist"
        _bid=$(plutil -extract CFBundleIdentifier raw -o - "$_info" 2>/dev/null || true)
        _ver=$(plutil -extract CFBundleShortVersionString raw -o - "$_info" 2>/dev/null || true)
        _sig_raw=$(codesign -dv --verbose=4 "$_app" 2>&1)
        _sig_rc=$?
        _sig=$(printf '%s\n' "$_sig_raw" | awk -F= '/^(Identifier|TeamIdentifier|Authority|CDHash|Signature|Runtime Version)=/{printf "%s=%s;",$1,$2}')
        printf '%s\tbundle_id=%s\tversion=%s\tsignature_metadata_available=%s\t%s\n' \
            "$_app" "$_bid" "$_ver" "$([ "$_sig_rc" -eq 0 ] && printf true || printf false)" "$_sig"
    done
}

collect_xprotect_logs() {
    log show --last "${LOG_HOURS}h" --style compact --info \
        --predicate '(process == "XProtect" OR process == "XProtectRemediator")' 2>&1 |
        /usr/bin/tail -n 1200
}

collect_gatekeeper_logs() {
    log show --last "${LOG_HOURS}h" --style compact \
        --predicate '(process == "syspolicyd" AND (eventMessage CONTAINS[c] "Gatekeeper" OR eventMessage CONTAINS[c] "assessment" OR eventMessage CONTAINS[c] "notarization"))' 2>&1 |
        /usr/bin/tail -n 1200
}

collect_authentication_logs() {
    log show --last "${LOG_HOURS}h" --style compact \
        --predicate '(process == "sudo" OR process == "sshd" OR process == "screensharingd")' 2>&1 |
        /usr/bin/tail -n 1200
}

launchd_service_presence() {
    if [ "$1" -eq 0 ]; then
        printf true
    elif printf '%s' "$2" | /usr/bin/grep -Eiq 'could not find (specified )?service'; then
        printf false
    else
        printf unknown
    fi
}

collect_screen_sharing_effective() {
    _screen_launch=$(/bin/launchctl print system/com.apple.screensharing 2>&1)
    _screen_rc=$?
    _remote_launch=$(/bin/launchctl print system/com.apple.RemoteDesktop.agent 2>&1)
    _remote_rc=$?
    _screen_disabled=$(/bin/launchctl print-disabled system 2>/dev/null |
        /usr/bin/grep -F '"com.apple.screensharing"' || true)
    _screen_acl=$(/usr/bin/dscl . -read /Groups/com.apple.access_screensharing \
        GroupMembership NestedGroups 2>/dev/null | /usr/bin/tr '\n\t' '  ')
    _ard_all=$(/usr/bin/defaults read /Library/Preferences/com.apple.RemoteManagement \
        ARD_AllLocalUsers 2>/dev/null || printf unknown)
    _ard_privs=$(/usr/bin/defaults read /Library/Preferences/com.apple.RemoteManagement \
        ARD_AllLocalUsersPrivs 2>/dev/null || printf unknown)
    _insecure_dh=$(/usr/bin/defaults read /Library/Preferences/com.apple.RemoteManagement \
        allowInsecureDH 2>/dev/null || printf unknown)
    _firewall=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getappblocked \
        /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent 2>&1 || true)
    printf 'configured=%s\n' "$(launchd_service_presence "$_screen_rc" "$_screen_launch")"
    printf 'remote_management_configured=%s\n' "$(launchd_service_presence "$_remote_rc" "$_remote_launch")"
    printf 'enabled_override=%s\n' "${_screen_disabled:-none}"
    printf 'active=%s\n' "$(printf '%s' "$_screen_launch" | /usr/bin/grep -q 'state = running' && printf true || printf false)"
    printf 'socket_activated=%s\n' "$(printf '%s' "$_screen_launch" | /usr/bin/grep -q 'service name = vnc-server' && printf true || printf false)"
    printf 'acl=%s\n' "${_screen_acl:-unavailable}"
    printf 'ard_all_local_users_preference=%s\n' "$_ard_all"
    printf 'ard_all_local_users_privileges=%s\n' "$_ard_privs"
    printf 'legacy_vnc_settings_file=%s\n' "$([ -e /Library/Preferences/com.apple.VNCSettings.txt ] && printf present || printf absent)"
    printf 'allow_insecure_dh_preference=%s\n' "$_insecure_dh"
    printf 'firewall=%s\n' "$_firewall"
}

collect_smb_effective() {
    /usr/sbin/sharing -l 2>&1 || return $?
    printf '\n[target public folder permissions]\n'
    for _share_path in "$USER_HOME/Public" "$USER_HOME/Public/Drop Box"; do
        [ -e "$_share_path" ] || continue
        /usr/bin/stat -f 'mode=%Sp owner=%Su:%Sg path=%N' "$_share_path" 2>&1
        /bin/ls -lde "$_share_path" 2>&1
    done
    return 0
}

collect_auditd_effective() {
    _audit_launch=$(/bin/launchctl print system 2>/dev/null |
        /usr/bin/grep -E '\tcom\.apple\.auditd([[:space:]]|$)' || true)
    _audit_condition=$(/usr/sbin/audit -c 2>&1 || true)
    printf 'launchd_present=%s\n' "$([ -n "$_audit_launch" ] && printf true || printf false)"
    printf 'audit_condition=%s\n' "$(printf '%s' "$_audit_condition" | /usr/bin/tr '\n\t' '  ')"
    printf 'audit_control=%s\n' "$([ -e /etc/security/audit_control ] && printf present || printf absent)"
    [ -r /etc/security/audit_control ] && /usr/bin/sed -n '/^[[:space:]]*\(flags\|naflags\|filesz\|expire-after\):/p' /etc/security/audit_control
}

collect_sharing_status() {
    _disabled=$(launchctl print-disabled system 2>/dev/null)
    for _label in com.openssh.sshd com.apple.screensharing com.apple.RemoteDesktop.agent com.apple.smbd com.apple.ftp-proxy com.apple.AEServer; do
        printf '%s\t' "$_label"
        if launchctl print "system/$_label" >/dev/null 2>&1; then
            printf 'running=true\t'
        else
            printf 'running=false\t'
        fi
        printf '%s\n' "$(printf '%s' "$_disabled" | grep -F "\"$_label\"" || printf 'no explicit launchd override')"
    done
    printf '\n[shares]\n'
    sharing -l 2>&1
}

GENERATED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
CURRENT_USER=$TARGET_USER
USER_HOME=$TARGET_HOME
REAL_HOSTNAME=$(hostname 2>/dev/null || printf unknown)
REPORT_HOSTNAME=$REAL_HOSTNAME
REPORT_TARGET_USER=$TARGET_USER
REPORT_TARGET_HOME=$TARGET_HOME
REPORT_EFFECTIVE_USER=$EFFECTIVE_USER
if [ "$REDACT" -eq 1 ]; then
    REPORT_HOSTNAME="<HOST>"
    REPORT_TARGET_USER="<USER>"
    REPORT_TARGET_HOME="~"
    if [ "$EFFECTIVE_USER" = "$TARGET_USER" ]; then REPORT_EFFECTIVE_USER="<USER>"; else REPORT_EFFECTIVE_USER="<EFFECTIVE_USER>"; fi
fi

OS_VERSION=$(sw_vers -productVersion 2>/dev/null || printf unknown)
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || printf unknown)
PATCH_STATUS=unknown
if command -v jq >/dev/null 2>&1 && PATCH_REFERENCE=$(msu_branch_status "$OS_VERSION" "${GENERATED_AT%%T*}" "$SCRIPT_DIR/config/macos-updates.json" 2>/dev/null); then
    REFERENCE_DATE=$(printf '%s\n' "$PATCH_REFERENCE" | jq -r .reviewed_at)
    REFERENCE_PATCH_VERSION=$(printf '%s\n' "$PATCH_REFERENCE" | jq -r '.reference.version // ""')
    PATCH_STATUS=$(printf '%s\n' "$PATCH_REFERENCE" | jq -r .status)
fi

emit_meta

# ---- Core posture findings -------------------------------------------------

if [ "$(uname -s 2>/dev/null || true)" != "Darwin" ]; then
    emit_finding "platform.macos" "system" "FAIL" "critical" "Supported platform" \
        "This collector must run on macOS." "uname=$(uname -s 2>/dev/null || printf unavailable)" \
        "Run the collector directly on the target Mac." "$APPLE_PLATFORM_SECURITY"
    emit_footer
    exit 2
fi

if [ -n "$REFERENCE_PATCH_VERSION" ]; then
    emit_finding "platform.patch_reference" "system" "PASS" "none" "macOS patch reference coverage" \
        "The offline catalogue includes an entry for the installed macOS branch." "version=$OS_VERSION build=$OS_BUILD" \
        "Review the age and result of the branch comparison." "$APPLE_SECURITY_RELEASES"
else
    emit_finding "platform.patch_reference" "system" "INFO" "none" "macOS patch reference coverage" \
        "No branch entry could be established for the installed macOS version." "version=$OS_VERSION build=$OS_BUILD" \
        "Check Apple guidance for the installed release." "$APPLE_SECURITY_RELEASES"
fi
_patch_evidence="installed=$OS_VERSION reference=$REFERENCE_PATCH_VERSION reviewed_at=$REFERENCE_DATE state=$PATCH_STATUS"
case $PATCH_STATUS in
    at_or_above_reference)
        emit_finding "updates.reference_version" "updates" "PASS" "none" "Reference OS patch level" \
            "Installed macOS meets the reviewed comparison for its branch." "$_patch_evidence" \
            "Check Software Update for device-specific offers." "$APPLE_SECURITY_RELEASES" ;;
    behind)
        emit_finding "updates.reference_version" "updates" "FAIL" "high" "Reference OS patch level" \
            "Installed macOS is behind the reviewed comparison for its branch." "$_patch_evidence" \
            "Check compatible updates and organisation policy before applying changes." "$APPLE_SECURITY_RELEASES" ;;
    *)
        emit_finding "updates.reference_version" "updates" "UNKNOWN" "medium" "Reference OS patch level" \
            "The offline patch comparison could not be established from a fresh branch entry." "$_patch_evidence" \
            "Refresh the catalogue or check Apple guidance for this Mac." "$APPLE_SECURITY_RELEASES" ;;
esac

if [ "$(id -u)" -eq 0 ]; then
    emit_finding "coverage.privileged" "coverage" "PASS" "none" "Privileged evidence coverage" \
        "Collector is running as root; privileged read-only checks are available." "euid=0" \
        "Protect the resulting report because it can contain sensitive configuration." "$NIST_MSCP"
else
    emit_finding "coverage.privileged" "coverage" "INFO" "none" "Privileged evidence coverage" \
        "Collector is unprivileged; some security state will be DENIED or UNKNOWN." "euid=$(id -u)" \
        "If authorized, rerun with sudo for PF, system TCC and audit coverage; compare both reports." "$NIST_MSCP"
fi

check_contains "platform.sip" "platform_security" "System Integrity Protection" \
    'status:[[:space:]]*enabled' "critical" \
    "SIP is enabled." "SIP is not fully enabled." \
    "Re-enable SIP from macOS Recovery unless a documented, time-bounded exception requires otherwise." \
    "https://support.apple.com/102149" csrutil status

check_contains "platform.authenticated_root" "platform_security" "Authenticated Root / SSV" \
    'status:[[:space:]]*enabled' "critical" \
    "Authenticated Root is enabled." "Authenticated Root is not enabled." \
    "Restore the signed system volume policy from Recovery and investigate why it was weakened." \
    "https://support.apple.com/guide/security/secd698747c9/web" csrutil authenticated-root status

check_contains "storage.filevault" "storage" "FileVault" \
    'FileVault is On' "high" \
    "FileVault is on." "FileVault is not on or encryption is incomplete." \
    "Enable FileVault and escrow the recovery key using an approved process." \
    "https://support.apple.com/guide/security/sec4c6dc1b6e/web" fdesetup status

check_contains "platform.gatekeeper" "platform_security" "Gatekeeper assessment" \
    'assessments enabled' "high" \
    "Gatekeeper assessments are enabled." "Gatekeeper assessments are disabled." \
    "Enable Gatekeeper and investigate any workflow that required disabling it." \
    "https://support.apple.com/guide/security/sec5599b66df/web" spctl --status

capture 15 /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
case "$CAPTURE_STATE:$(msc_application_firewall_mode "$CAPTURE_DATA")" in
    collected:enabled)
        _fw_status=PASS; _fw_severity=none
        _fw_summary="The macOS Application Firewall is enabled."
        _fw_recommendation="No action required; monitor for changes." ;;
    collected:blocks_nonessential)
        _fw_status=PASS; _fw_severity=none
        _fw_summary="The macOS Application Firewall is blocking all non-essential incoming connections."
        _fw_recommendation="No action required; monitor for changes." ;;
    collected:disabled)
        _fw_status=FAIL; _fw_severity=high
        _fw_summary="The macOS Application Firewall is disabled."
        _fw_recommendation="Enable the firewall and review allowed incoming applications." ;;
    *)
        _fw_status=UNKNOWN; _fw_severity=high
        _fw_summary="The macOS Application Firewall state could not be determined."
        _fw_recommendation="Verify the firewall setting in System Settings." ;;
esac
emit_finding "network.firewall" "network" "$_fw_status" "$_fw_severity" "Application Firewall" \
    "$_fw_summary" "$(printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR")" "$_fw_recommendation" \
    "https://support.apple.com/guide/mac-help/mh11783/mac"

capture 10 /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
if [ "$CAPTURE_STATE" = "collected" ] && printf '%s' "$CAPTURE_DATA" | grep -Eiq 'stealth mode is on|enabled'; then
    emit_finding "network.firewall_stealth" "network" "PASS" "none" "Firewall stealth mode" \
        "Stealth mode is enabled." "$CAPTURE_DATA" "No action required." \
        "https://support.apple.com/guide/mac-help/mh17133/mac"
elif [ "$CAPTURE_STATE" = "collected" ]; then
    emit_finding "network.firewall_stealth" "network" "WARN" "medium" "Firewall stealth mode" \
        "Stealth mode is disabled; the Mac may answer unauthorised probes." "$CAPTURE_DATA" \
        "Enable stealth mode when compatible with operational requirements." \
        "https://support.apple.com/guide/mac-help/mh17133/mac"
else
    emit_finding "network.firewall_stealth" "network" "UNKNOWN" "medium" "Firewall stealth mode" \
        "Stealth-mode state could not be determined." "$CAPTURE_ERROR" \
        "Inspect Network > Firewall > Options manually." \
        "https://support.apple.com/guide/mac-help/mh17133/mac"
fi

for _pref_spec in \
    "AutomaticDownload|updates.auto_download|Automatic update download" \
    "AutomaticallyInstallMacOSUpdates|updates.auto_install|Automatic macOS security update installation" \
    "CriticalUpdateInstall|updates.critical|Critical update installation" \
    "ConfigDataInstall|updates.security_data|Security configuration data installation"
do
    _key=${_pref_spec%%|*}
    _rest=${_pref_spec#*|}; _id=${_rest%%|*}; _title=${_rest#*|}
    capture 10 pref_value /Library/Preferences/com.apple.SoftwareUpdate "$_key"
    if [ "$CAPTURE_STATE" = "collected" ] && [ "$CAPTURE_DATA" = "1" ]; then
        emit_finding "$_id" "updates" "PASS" "none" "$_title" \
            "The explicit system preference is enabled." "$_key=$CAPTURE_DATA" \
            "No action required; verify MDM policy and successful update history." \
            "https://support.apple.com/101591"
    elif [ "$CAPTURE_STATE" = "collected" ] && [ "$CAPTURE_DATA" = "0" ]; then
        emit_finding "$_id" "updates" "FAIL" "high" "$_title" \
            "The explicit system preference is disabled." "$_key=$CAPTURE_DATA" \
            "Enable automatic system/security data updates, or enforce and monitor an equivalent managed workflow." \
            "https://support.apple.com/101591"
    else
        emit_finding "$_id" "updates" "UNKNOWN" "medium" "$_title" \
            "No readable explicit value was found; the effective default or MDM declaration must be correlated." \
            "$_key state=$CAPTURE_STATE error=$CAPTURE_ERROR" \
            "Review Software Update settings and any DDM/MDM declaration." \
            "https://support.apple.com/101591"
    fi
done

capture 10 sysadminctl -screenLock status
if [ "$CAPTURE_STATE" = "collected" ] && printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR" | grep -Eiq 'delay is immediate|delay is ([0-5])([[:space:]]|$)'; then
    emit_finding "auth.screen_lock" "authentication" "PASS" "none" "Password after screen lock" \
        "Screen-lock authentication is immediate or within five seconds." \
        "$(printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR")" "No action required." "$CIS_MACOS"
elif [ "$CAPTURE_STATE" = "collected" ]; then
    emit_finding "auth.screen_lock" "authentication" "WARN" "high" "Password after screen lock" \
        "Screen-lock delay does not appear to meet the five-second baseline." \
        "$(printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR")" \
        "Require a password immediately after sleep or screen saver activation." "$CIS_MACOS"
else
    emit_finding "auth.screen_lock" "authentication" "UNKNOWN" "high" "Password after screen lock" \
        "Screen-lock delay could not be determined." "$CAPTURE_ERROR" \
        "Verify the effective screen-lock policy for each interactive user." "$CIS_MACOS"
fi

capture 10 defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser
if [ "$CAPTURE_STATE" = "collected" ] && [ -n "$CAPTURE_DATA" ]; then
    emit_finding "auth.auto_login" "authentication" "FAIL" "high" "Automatic login" \
        "Automatic login appears configured." "autoLoginUser=$CAPTURE_DATA" \
        "Disable automatic login and investigate whether credentials are stored for it." "$CIS_MACOS"
elif [ "$CAPTURE_STATE" = "collected" ] || { [ "$CAPTURE_STATE" = "error" ] && printf '%s' "$CAPTURE_ERROR" | grep -Fq 'does not exist'; }; then
    emit_finding "auth.auto_login" "authentication" "PASS" "none" "Automatic login" \
        "No automatic-login user is configured." "autoLoginUser not present" "No action required." "$CIS_MACOS"
else
    emit_finding "auth.auto_login" "authentication" "UNKNOWN" "high" "Automatic login" \
        "Automatic login could not be determined." "state=$CAPTURE_STATE" "Verify the login settings locally." "$CIS_MACOS"
fi

capture 10 defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled
if [ "$CAPTURE_STATE" = "collected" ] && [ "$CAPTURE_DATA" = "1" ]; then
    emit_finding "auth.guest_account" "authentication" "WARN" "medium" "Guest account" \
        "The macOS Guest account is enabled." "GuestEnabled=1" \
        "Disable Guest User unless its limited workflow is explicitly required and accepted." "$CIS_MACOS"
elif [ "$CAPTURE_STATE" = "collected" ] && [ "$CAPTURE_DATA" = "0" ]; then
    emit_finding "auth.guest_account" "authentication" "PASS" "none" "Guest account" \
        "The macOS Guest account is disabled." "GuestEnabled=0" "No action required." "$CIS_MACOS"
else
    emit_finding "auth.guest_account" "authentication" "UNKNOWN" "medium" "Guest account" \
        "Guest-account state could not be determined." "state=$CAPTURE_STATE error=$CAPTURE_ERROR" \
        "Review Users & Groups and any MDM restriction." "$CIS_MACOS"
fi

capture 10 dscl . -read /Users/root AuthenticationAuthority
if [ "$CAPTURE_STATE" = "collected" ] && [ -n "$CAPTURE_DATA" ]; then
    emit_finding "auth.root_account" "authentication" "FAIL" "critical" "Root account authentication" \
        "The root account has an authentication authority and may be enabled." "$CAPTURE_DATA" \
        "Disable direct root login; use audited privilege elevation instead." "$NIST_MSCP"
elif [ "$CAPTURE_STATE" = "collected" ] || { [ "$CAPTURE_STATE" = "error" ] && printf '%s' "$CAPTURE_ERROR" | grep -Fq 'eDSAttributeNotFound'; }; then
    emit_finding "auth.root_account" "authentication" "PASS" "none" "Root account authentication" \
        "No root AuthenticationAuthority was returned." "state=$CAPTURE_STATE" "No action required." "$NIST_MSCP"
else
    emit_finding "auth.root_account" "authentication" "UNKNOWN" "critical" "Root account authentication" \
        "The root account authentication state could not be determined." "state=$CAPTURE_STATE" "Verify direct root login locally." "$NIST_MSCP"
fi

capture 10 launchctl print system/com.openssh.sshd
if [ "$CAPTURE_STATE" = "collected" ]; then
    emit_finding "services.ssh" "remote_access" "WARN" "high" "Remote Login (SSH)" \
        "The SSH service is configured or available through launchd and expands remote attack surface." "launchd service present; active state requires listener correlation" \
        "Disable Remote Login if unused; otherwise restrict users, keys, network reachability and sshd policy." "$NIST_MSCP"
elif [ "$CAPTURE_STATE" = "error" ] && printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR" | grep -Eiq 'could not find (specified )?service'; then
    emit_finding "services.ssh" "remote_access" "PASS" "none" "Remote Login (SSH)" \
        "The SSH service was absent from the queried launchd domain." "service not found" "Check listener coverage if exposure is suspected." "$NIST_MSCP"
else
    emit_finding "services.ssh" "remote_access" "UNKNOWN" "high" "Remote Login (SSH)" \
        "The SSH service state could not be determined." "state=$CAPTURE_STATE" "Verify Remote Login and listeners locally." "$NIST_MSCP"
fi

collect 15 "services.screen_sharing_effective" "remote_access" "Effective Screen Sharing and Remote Management state" "high" false "launchctl, dscl, RemoteManagement preferences and firewall" collect_screen_sharing_effective
if [ "$CAPTURE_STATE" = "collected" ] && printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -q '^configured=true'; then
    _screen_active=$(printf '%s\n' "$CAPTURE_DATA" | /usr/bin/awk -F= '/^active=/{print $2}')
    _screen_socket=$(printf '%s\n' "$CAPTURE_DATA" | /usr/bin/awk -F= '/^socket_activated=/{print $2}')
    emit_finding "services.screen_sharing" "remote_access" "WARN" "high" "Screen Sharing" \
        "Screen Sharing is enabled; it may be idle until launchd receives a connection." \
        "configured=true active=${_screen_active:-unknown} socket_activated=${_screen_socket:-unknown}" \
        "If expected, restrict principals, disable legacy VNC and constrain LAN/VPN reachability; otherwise disable it." "$NIST_MSCP"
elif [ "$CAPTURE_STATE" = "collected" ] && printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -qx 'configured=false'; then
    emit_finding "services.screen_sharing" "remote_access" "PASS" "none" "Screen Sharing" \
        "The Screen Sharing service was absent from the queried launchd domain." "configured=false" \
        "No action required if remote screen access is not required." "$NIST_MSCP"
else
    emit_finding "services.screen_sharing" "remote_access" "UNKNOWN" "high" "Screen Sharing" \
        "Screen Sharing could not be confirmed." "state=$CAPTURE_STATE" "Check effective access in System Settings." "$NIST_MSCP"
fi

_screen_all=$(printf '%s\n' "$CAPTURE_DATA" | /usr/bin/awk -F= '/^ard_all_local_users_preference=/{print $2}')
_screen_insecure=$(printf '%s\n' "$CAPTURE_DATA" | /usr/bin/awk -F= '/^allow_insecure_dh_preference=/{print $2}')
_screen_legacy=$(printf '%s\n' "$CAPTURE_DATA" | /usr/bin/awk -F= '/^legacy_vnc_settings_file=/{print $2}')
_screen_acl=$(printf '%s\n' "$CAPTURE_DATA" | /usr/bin/awk -F= '/^acl=/{sub(/^acl=/,""); print}')
if [ "$_screen_all" = "1" ] || [ "$_screen_all" = "true" ] || [ "$_screen_insecure" = "1" ] || [ "$_screen_insecure" = "true" ] || [ "$_screen_legacy" = "present" ]; then
    emit_finding "services.screen_sharing_hardening" "remote_access" "WARN" "high" "Screen Sharing least privilege and legacy compatibility" \
        "At least one broad or legacy remote-control compatibility setting is present." \
        "all_local_users=${_screen_all:-unknown} allow_insecure_dh=${_screen_insecure:-unknown} legacy_vnc_file=${_screen_legacy:-unknown} acl=${_screen_acl:-unavailable}" \
        "Restrict Screen Sharing to approved principals and remove legacy VNC password/insecure-DH compatibility if no tested client requires it." "$NIST_MSCP"
elif [ "$CAPTURE_STATE" != "collected" ] || [ -z "$_screen_acl" ] || [ "$_screen_acl" = "unavailable" ] ||
     [ "${_screen_all:-unknown}" = unknown ] || [ "${_screen_insecure:-unknown}" = unknown ]; then
    emit_finding "services.screen_sharing_hardening" "remote_access" "UNKNOWN" "medium" "Screen Sharing least privilege and legacy compatibility" \
        "The effective principal ACL or compatibility preferences could not be fully confirmed." \
        "all_local_users=${_screen_all:-unknown} allow_insecure_dh=${_screen_insecure:-unknown} legacy_vnc_file=${_screen_legacy:-unknown} acl=${_screen_acl:-unavailable}" \
        "Confirm 'Allow access for: Only these users' and disable legacy VNC compatibility unless required." "$NIST_MSCP"
else
    emit_finding "services.screen_sharing_hardening" "remote_access" "PASS" "none" "Screen Sharing least privilege and legacy compatibility" \
        "No broad or legacy compatibility flag was observed and an ACL was visible." \
        "all_local_users=${_screen_all:-unknown} allow_insecure_dh=${_screen_insecure:-unknown} legacy_vnc_file=${_screen_legacy:-unknown} acl=${_screen_acl}" \
        "Retest access from an approved and an unapproved account after changes." "$NIST_MSCP"
fi

if [ "$CAPTURE_STATE" = "collected" ] && printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -q '^remote_management_configured=true'; then
    emit_finding "services.remote_management" "remote_access" "WARN" "high" "Apple Remote Management" \
        "Apple Remote Management appears configured independently from Screen Sharing." "remote_management_configured=true" \
        "Disable Remote Management if only Screen Sharing is required; otherwise restrict its principals and privileges." "$NIST_MSCP"
elif [ "$CAPTURE_STATE" = "collected" ] && printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -qx 'remote_management_configured=false'; then
    emit_finding "services.remote_management" "remote_access" "PASS" "none" "Apple Remote Management" \
        "Apple Remote Management was not configured as a system launchd service." "remote_management_configured=false" "No action required." "$NIST_MSCP"
else
    emit_finding "services.remote_management" "remote_access" "UNKNOWN" "high" "Apple Remote Management" \
        "Remote Management could not be confirmed." "state=$CAPTURE_STATE" "Check effective access in System Settings." "$NIST_MSCP"
fi

collect 15 "logging.auditd_effective" "logging" "Effective OpenBSM audit state" "high" true "launchctl, audit condition and audit_control" collect_auditd_effective
if [ "$CAPTURE_STATE" = "collected" ] && printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -q '^launchd_present=true' && \
   printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -q 'AUC_AUDITING'; then
    emit_finding "logging.auditd" "logging" "PASS" "none" "OpenBSM audit service" \
        "OpenBSM auditing is active." "launchd_present=true and AUC_AUDITING" \
        "Also review audit policy, retention and centralized collection where required." "$NIST_MSCP"
else
    emit_finding "logging.auditd" "logging" "INFO" "none" "OpenBSM audit service" \
        "OpenBSM auditing is not active or could not be fully confirmed; this is normal on modern macOS unless an explicit compliance profile requires legacy auditing." "$CAPTURE_DATA" \
        "Use Endpoint Security telemetry for modern monitoring; review OpenBSM only for a documented compliance or legacy requirement." "$NIST_MSCP"
fi

collect 15 "services.smb_effective" "remote_access" "Effective SMB shares and filesystem permissions" "high" false "sharing inventory, stat and ACL" collect_smb_effective
if [ "$CAPTURE_STATE" = "collected" ] && printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -Eq 'guest access:[[:space:]]*1'; then
    _smb_rw=false
    printf '%s' "$CAPTURE_DATA" | /usr/bin/grep -Eq 'read-only:[[:space:]]*0' && _smb_rw=true
    emit_finding "services.smb_guest_shares" "remote_access" "WARN" "high" "SMB guest sharing" \
        "One or more SMB shares permit unauthenticated guest access." \
        "guest_access=true share_not_read_only=$_smb_rw; effective filesystem ACL still applies" \
        "Disable guest access if unnecessary; prefer an authenticated sharing-only account and least-privilege folder ACL." "$NIST_MSCP"
elif [ "$CAPTURE_STATE" = "collected" ]; then
    emit_finding "services.smb_guest_shares" "remote_access" "PASS" "none" "SMB guest sharing" \
        "No guest-enabled SMB share was observed." "sharing inventory collected" "No action required." "$NIST_MSCP"
else
    emit_finding "services.smb_guest_shares" "remote_access" "UNKNOWN" "high" "SMB guest sharing" \
        "The SMB guest-access inventory could not be confirmed." "state=$CAPTURE_STATE" "Verify File Sharing and guest access locally." "$NIST_MSCP"
fi

capture 10 defaults read -g LDMGlobalEnabled
if [ "$CAPTURE_STATE" = "collected" ] && [ "$CAPTURE_DATA" = "1" ]; then
    emit_finding "privacy.lockdown_mode" "privacy" "PASS" "none" "Lockdown Mode" \
        "Lockdown Mode is enabled for the current user." "LDMGlobalEnabled=1" "No action required." \
        "https://support.apple.com/105120"
else
    emit_finding "privacy.lockdown_mode" "privacy" "INFO" "none" "Lockdown Mode" \
        "Lockdown Mode is not confirmed; this is expected for most users and is not a general baseline failure." \
        "state=$CAPTURE_STATE value=${CAPTURE_DATA:-unset}" \
        "High-risk users targeted by sophisticated attacks should assess Lockdown Mode with their security team." \
        "https://support.apple.com/105120"
fi

capture 10 defaults read /Library/Preferences/com.apple.applicationaccess allowUSBRestrictedMode
if [ "$CAPTURE_STATE" = "collected" ] && [ "$CAPTURE_DATA" = "0" ]; then
    emit_finding "hardware.usb_restricted_mode" "hardware" "FAIL" "high" "USB Restricted Mode" \
        "USB Restricted Mode is explicitly disabled." "allowUSBRestrictedMode=0" \
        "Enable USB Restricted Mode unless a documented hardware workflow requires an exception." "$NIST_MSCP"
elif [ "$CAPTURE_STATE" = "collected" ]; then
    emit_finding "hardware.usb_restricted_mode" "hardware" "PASS" "none" "USB Restricted Mode" \
        "USB Restricted Mode is explicitly enabled." "allowUSBRestrictedMode=$CAPTURE_DATA" \
        "No action required." "$NIST_MSCP"
elif printf '%s' "$CAPTURE_ERROR" | grep -Fq 'does not exist'; then
    emit_finding "hardware.usb_restricted_mode" "hardware" "PASS" "none" "USB Restricted Mode" \
        "No preference that disables USB Restricted Mode was found." "allowUSBRestrictedMode is unset" \
        "No action required; managed fleets can enforce the setting explicitly." "$NIST_MSCP"
else
    emit_finding "hardware.usb_restricted_mode" "hardware" "UNKNOWN" "high" "USB Restricted Mode" \
        "USB Restricted Mode could not be determined." "state=$CAPTURE_STATE error=$CAPTURE_ERROR" \
        "Review the effective MDM/application-access restriction." "$NIST_MSCP"
fi

if [ -d /Library/Apple/System/Library/CoreServices/XProtect.bundle ] && \
   [ -d /Library/Apple/System/Library/CoreServices/XProtect.app ]; then
    emit_finding "malware.xprotect" "malware_defense" "PASS" "none" "XProtect components" \
        "The expected XProtect scanning and remediation components are present." \
        "XProtect.bundle and XProtect.app are installed" \
        "Keep system data files and security updates enabled." \
        "https://support.apple.com/guide/security/sec469d47bd8/web"
else
    emit_finding "malware.xprotect" "malware_defense" "FAIL" "critical" "XProtect components" \
        "One or more expected XProtect components are missing." \
        "Expected XProtect.bundle and XProtect.app under /Library/Apple/System/Library/CoreServices" \
        "Stop running untrusted software, install current security updates, and investigate system integrity." \
        "https://support.apple.com/guide/security/sec469d47bd8/web"
fi

# ---- Compact evidence available in every mode ------------------------------

collect 10 "system.version" "system" "macOS version and build" "low" false "sw_vers" sw_vers
collect 10 "system.kernel" "system" "Kernel, architecture and boot details" "low" false "uname/sysctl" sh -c \
    'uname -a; sysctl kern.boottime hw.model hw.machine hw.optional.arm64 2>&1; uptime'
collect 10 "system.root_mount" "platform_security" "Root volume mount flags and seal" "low" false "mount" mount
collect 10 "storage.disk_root" "storage" "Root disk encryption and APFS properties" "medium" false "diskutil info /" diskutil info /
collect 15 "updates.history" "updates" "Installed software update history" "low" false "softwareupdate --history" softwareupdate --history
collect 20 "updates.security_assets" "updates" "XProtect, Gatekeeper and security-data packages" "low" false "pkgutil" collect_update_packages
collect 10 "management.enrollment" "management" "Automated enrollment and MDM status" "medium" false "profiles status" profiles status -type enrollment
collect 15 "extensions.system" "extensions" "System extensions" "medium" false "systemextensionsctl list" systemextensionsctl list
collect 15 "extensions.kernel" "extensions" "Loaded kernel extensions" "medium" false "kmutil showloaded" kmutil showloaded --list-only
collect 10 "accounts.local" "accounts" "Local accounts and numeric UIDs" "medium" false "dscl users" dscl . -list /Users UniqueID
collect 10 "accounts.admins" "accounts" "Local administrators" "high" false "dscacheutil admin group" dscacheutil -q group -a name admin
collect 15 "network.interfaces" "network" "Network interfaces and assigned addresses" "high" false "ifconfig" ifconfig -a
collect 10 "network.routes" "network" "Routing table" "high" false "netstat -rn" netstat -rn
collect 10 "network.dns" "network" "Effective DNS resolver configuration" "high" false "scutil --dns" scutil --dns
collect 10 "network.proxy" "network" "System proxy configuration" "high" false "scutil --proxy" scutil --proxy
collect 15 "network.services" "network" "Per-service IP, DNS and proxy configuration" "high" false "networksetup" collect_network_services
collect 20 "network.firewall_config" "network" "Application Firewall policy and allow list" "medium" false "socketfilterfw" collect_firewall
collect 15 "network.tcp_listeners" "network" "Listening TCP sockets with owning processes" "high" false "lsof TCP LISTEN" lsof -nP -iTCP -sTCP:LISTEN
collect 15 "network.udp_sockets" "network" "Open UDP sockets with owning processes" "high" false "lsof UDP" lsof -nP -iUDP
collect 10 "network.vpn" "network" "Configured and active VPN connections" "high" false "scutil --nc list" scutil --nc list
collect 15 "services.sharing" "remote_access" "Remote access and sharing services" "medium" false "launchctl/sharing" collect_sharing_status
collect 20 "persistence.launch_items" "persistence" "Third-party launch item metadata" "high" false "LaunchAgents/LaunchDaemons" collect_launch_metadata
collect 15 "persistence.cron_periodic" "persistence" "Cron, periodic and legacy scheduled items" "high" false "cron/periodic inventory" collect_periodic_and_cron
collect 10 "remote_access.sshd_config" "remote_access" "Effective SSH daemon configuration files" "medium" false "sshd_config" collect_sshd_configuration
collect 15 "recovery.time_machine" "recovery" "Time Machine status and destinations" "high" false "tmutil" sh -c \
    'tmutil status; tmutil destinationinfo; tmutil latestbackup 2>&1'
collect 10 "trust.custom" "trust" "User and admin trust overrides" "medium" false "security trust settings" sh -c \
    'security dump-trust-settings 2>&1; security dump-trust-settings -d 2>&1'

if [ "$ONLINE" -eq 1 ]; then
    capture 120 softwareupdate --list
    _online_data=$(printf '%s\n%s' "$CAPTURE_DATA" "$CAPTURE_ERROR" | redact_stream)
    emit_evidence "updates.available_online" "updates" "Updates currently offered by Apple" \
        "$CAPTURE_STATE" "low" false "softwareupdate --list" "$CAPTURE_RC" "$_online_data" "$CAPTURE_ERROR"
    if [ "$CAPTURE_STATE" != "collected" ]; then
        emit_finding "updates.available" "updates" "UNKNOWN" "high" "Available Apple updates" \
            "The online update query did not complete successfully." "state=$CAPTURE_STATE error=$CAPTURE_ERROR" \
            "Open Software Update or rerun --online on a trusted network." "$APPLE_SECURITY_RELEASES"
    elif printf '%s' "$CAPTURE_DATA" | grep -Eiq 'No new software available|No new software'; then
        emit_finding "updates.available" "updates" "PASS" "none" "Available Apple updates" \
            "Apple Software Update reports no compatible update currently offered." "$CAPTURE_DATA" \
            "Continue normal patch monitoring." "$APPLE_SECURITY_RELEASES"
    elif printf '%s' "$CAPTURE_DATA" | grep -Eq '^\* Label:|^[[:space:]]+Label:'; then
        emit_finding "updates.available" "updates" "FAIL" "high" "Available Apple updates" \
            "Apple Software Update reports one or more compatible updates." "$CAPTURE_DATA" \
            "Review release notes, back up critical data, and install security-relevant updates promptly." "$APPLE_SECURITY_RELEASES"
    else
        emit_finding "updates.available" "updates" "UNKNOWN" "medium" "Available Apple updates" \
            "The online update response was not recognized." "$CAPTURE_DATA" \
            "Verify Software Update manually." "$APPLE_SECURITY_RELEASES"
    fi
else
    emit_evidence "updates.available_online" "updates" "Updates currently offered by Apple" \
        "skipped" "low" false "softwareupdate --list" 0 "" "Use --online to perform this networked check."
fi

# Root-only evidence. We attempt it rather than silently skipping so coverage is explicit.
collect 15 "network.pf_info" "network" "PF packet-filter state" "medium" true "pfctl -s info" pfctl -s info
collect 20 "network.pf_rules" "network" "PF filter and NAT rules" "high" true "pfctl rules" sh -c \
    'pfctl -a "*" -sr; pfctl -a "*" -sn; pfctl -a "*" -s Tables'
collect 15 "platform.boot_policy" "platform_security" "Apple silicon local boot security policy" "medium" true "bputil -d" bputil -d
collect 15 "logging.audit_config" "logging" "OpenBSM audit status and policy" "medium" true "audit/audit_control" sh -c \
    'audit -c 2>&1; sed -n "1,200p" /etc/security/audit_control 2>&1; ls -ld /var/audit 2>&1'

if [ "$MODE" = "standard" ] || [ "$MODE" = "deep" ]; then
    collect 25 "management.profiles" "management" "Installed configuration profiles" "high" false \
        "profiles show" profiles show -type configuration
    collect 20 "storage.apfs" "storage" "APFS volumes and encryption state" "high" false \
        "diskutil apfs list" diskutil apfs list
    collect 20 "updates.preferences" "updates" "Software Update preferences and declaration state" "medium" false \
        "SoftwareUpdate preferences" sh -c \
        'defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>&1; if [ -r /var/db/softwareupdate/SoftwareUpdateDDMStatePersistence.plist ]; then plutil -p /var/db/softwareupdate/SoftwareUpdateDDMStatePersistence.plist; fi'
    collect 15 "authentication.password_policy" "authentication" "Local password policy" "medium" false \
        "pwpolicy" pwpolicy -getaccountpolicies
    collect 15 "hardware.usb" "hardware" "Connected USB device inventory" "high" false \
        "system_profiler SPUSBDataType" system_profiler SPUSBDataType
fi

if [ "$MODE" = "deep" ]; then
    collect 90 "applications.signatures" "applications" "Installed application versions and signature metadata" "high" false \
        "codesign application inventory" collect_app_inventory
    collect 30 "privacy.tcc" "privacy" "TCC grants summary" "critical" true \
        "TCC databases" collect_tcc_summary
    if [ "$INCIDENT_LOGS" -eq 1 ]; then
        collect 35 "logging.xprotect_events" "logging" "Recent XProtect events" "critical" true \
            "log show XProtect predicate" collect_xprotect_logs
        collect 35 "logging.gatekeeper_events" "logging" "Recent Gatekeeper/notarization events" "high" true \
            "log show narrow syspolicyd predicate" collect_gatekeeper_logs
    fi
    collect 30 "logging.authentication_events" "logging" "Recent remote/admin authentication events" "high" true \
        "log show authentication predicate" collect_authentication_logs
    # shellcheck disable=SC2016
    collect 30 "persistence.launch_plists" "persistence" "Non-system launch plist file metadata" "high" false \
        "stat LaunchAgents/LaunchDaemons" sh -c \
        'for d in /Library/LaunchAgents /Library/LaunchDaemons "$1/Library/LaunchAgents"; do [ -d "$d" ] || continue; /usr/bin/find "$d" -maxdepth 1 -type f -name "*.plist" -exec /usr/bin/stat -f "mode=%Sp owner=%Su:%Sg path=%N" {} + || exit 1; done; exit 0' sh "$USER_HOME"
fi

if [ "$BACKGROUND_ITEMS" -eq 1 ]; then
    collect 30 "persistence.background_items" "persistence" "Background task management inventory" "high" false \
        "sfltool dumpbtm" /usr/bin/sfltool dumpbtm
else
    emit_evidence "persistence.background_items" "persistence" "Background task management inventory" \
        "skipped" "high" false "sfltool dumpbtm" 0 "" "Use --background-items to request this inventory."
fi

emit_footer

if [ "$FAIL_ON_FINDINGS" -eq 1 ] && [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
exit 0
