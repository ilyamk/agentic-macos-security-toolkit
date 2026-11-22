# SPDX-License-Identifier: MIT
# Shared, read-only helpers for the macOS Security Audit suite.
# This file is sourced by the posture and triage scripts; it is not executable.
# shellcheck disable=SC2034,SC2329
# The version is consumed by callers; helpers are invoked after sourcing.

if [ "${MSC_COMMON_LOADED:-0}" = "1" ]; then
    return 0
fi
MSC_COMMON_LOADED=1
MSC_COMMON_VERSION="3.0.0"

msc_is_uint() {
    case ${1:-} in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

msc_json_escape() {
    LC_ALL=C /usr/bin/awk '
        BEGIN { ORS=""; first=1 }
        {
            if (!first) printf "\\n"
            first=0
            gsub(/\\/, "\\\\")
            gsub(/\"/, "\\\"")
            gsub(/\t/, "\\t")
            gsub(/\r/, "\\r")
            gsub(/[[:cntrl:]]/, "")
            printf "%s", $0
        }
    '
}

msc_jesc() {
    printf '%s' "$1" | msc_json_escape
}

msc_sha256_file() {
    /usr/bin/shasum -a 256 "$1" 2>/dev/null | /usr/bin/awk '{print $1}'
}

msc_report_file_list() (
    CDPATH='' cd -- "$1" || exit 1
    _report_special=$(/usr/bin/find . ! -type f ! -type d -print) || exit 1
    [ -z "$_report_special" ] || exit 1
    # The path variable belongs to the child shell invoked by find.
    # shellcheck disable=SC2016
    /usr/bin/find . -type f -exec /bin/sh -c '
        for path do
            case $path in *\\*|*"
"*) exit 1 ;; esac
        done
    ' sh {} + || exit 1
    if [ "${2:-current}" = legacy ]; then
        /usr/bin/find . -type f ! -name SHA256SUMS -print
    else
        /usr/bin/find . -type f ! -path ./SHA256SUMS -print
    fi
)

msc_write_report_checksums() (
    _sum_files=$(msc_report_file_list "$1" "${2:-current}") || exit 1
    CDPATH='' cd -- "$1" || exit 1
    printf '%s\n' "$_sum_files" | LC_ALL=C /usr/bin/sort |
        while IFS= read -r _sum_file; do
            [ -n "$_sum_file" ] || continue
            /usr/bin/shasum -a 256 "$_sum_file" || exit 1
        done
)

msc_commit_report_checksums() (
    _sum_output=$(msc_write_report_checksums "$1") || exit 1
    [ -n "$_sum_output" ] || exit 1
    _sum_temp=$(/usr/bin/mktemp "$1/.SHA256SUMS.XXXXXX") || exit 1
    trap '/bin/rm -f "$_sum_temp"' EXIT
    printf '%s\n' "$_sum_output" >"$_sum_temp" && /bin/mv -f "$_sum_temp" "$1/SHA256SUMS"
)

# Short, stable identifier fragment derived from a string (e.g. a path), so
# finding IDs survive PID and ordering changes between runs.
msc_short_hash() {
    printf '%s' "$1" | /usr/bin/shasum -a 256 | /usr/bin/cut -c1-12
}

# Reduce a free-form token to the identifier alphabet used in finding IDs.
msc_id_token() {
    printf '%s' "$1" | LC_ALL=C /usr/bin/tr -c 'A-Za-z0-9._-' '_' | /usr/bin/cut -c1-48
}

# Escape a literal string for use inside a sed extended regular expression.
msc_regex_escape() {
    printf '%s' "$1" | /usr/bin/sed -e 's/[][\.^$*+?(){}|\/]/\\&/g'
}

# Maintain ROOT/latest as a relative symlink to the newest run directory.
# Failure is non-fatal: the pointer is a convenience, not evidence.
msc_update_latest_pointer() (
    _msc_root=$1; _msc_dir=$2
    [ -d "$_msc_root" ] && [ -d "$_msc_dir" ] || exit 0
    [ ! -e "$_msc_root/latest" ] || [ -L "$_msc_root/latest" ] || exit 0
    _msc_pointer=$(/usr/bin/mktemp -d "$_msc_root/.latest.XXXXXX") || exit 0
    trap '/bin/rm -f "$_msc_pointer/link"; /bin/rmdir "$_msc_pointer"' EXIT
    /bin/ln -s "${_msc_dir##*/}" "$_msc_pointer/link" &&
        /bin/mv -fh "$_msc_pointer/link" "$_msc_root/latest" 2>/dev/null || true
)

msc_utc_now() {
    /bin/date -u '+%Y-%m-%dT%H:%M:%SZ'
}

msc_default_target_user() {
    if [ "$(/usr/bin/id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && \
       [ "${SUDO_USER:-root}" != "root" ]; then
        printf '%s\n' "$SUDO_USER"
    else
        /usr/bin/id -un
    fi
}

msc_validate_target_user() {
    _msc_user=${1:-}
    case $_msc_user in
        ''|*[!A-Za-z0-9._-]*) return 64 ;;
    esac
    /usr/bin/dscl . -read "/Users/$_msc_user" NFSHomeDirectory >/dev/null 2>&1
}

msc_target_home() {
    _msc_user=$1
    /usr/bin/dscl . -read "/Users/$_msc_user" NFSHomeDirectory 2>/dev/null |
        /usr/bin/awk 'NR == 1 {print $2}'
}

msc_json_bool() {
    case ${1:-0} in
        1|true|TRUE|yes|YES|on|ON) printf '%s' true ;;
        *) printf '%s' false ;;
    esac
}

msc_application_firewall_mode() {
    case $(printf '%s\n' "$1" | /usr/bin/sed -nE 's/.*\(State[[:space:]]*=[[:space:]]*([012])[[:space:]]*\).*/\1/p') in
        0) printf '%s\n' disabled ;;
        1) printf '%s\n' enabled ;;
        2) printf '%s\n' blocks_nonessential ;;
        *) printf '%s\n' unknown ;;
    esac
}

msc_xprotect_log_has_event() {
    LC_ALL=C /usr/bin/awk '
        {
            line=tolower($0)
            if (line ~ /(^|[^[:alnum:]_])(no[[:space:]]+(known[[:space:]]+)?(threats?|malware|xp_malware_)|(not|never)[[:space:]]+(detected|remediated|blocked))/) next
            if (line ~ /(^|[^[:alnum:]_])xp_malware_(detected|remediated)([^[:alnum:]_]|$)/ ||
                line ~ /(^|[^[:alnum:]_])(malware|threats?)[[:space:]]+((was|were)[[:space:]]+)?(detected|remediated|blocked)([^[:alnum:]_]|$)/) {
                found=1
                exit
            }
        }
        END { exit !found }
    ' "$1"
}

msc_system_path_if_root() {
    if [ "$(/usr/bin/id -u)" -eq 0 ]; then
        PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec
        export PATH
    fi
}

msc_require_jq() {
    msc_system_path_if_root
    command -v jq >/dev/null 2>&1 && return 0
    printf '%s\n' 'jq is required. Install it separately before running this command.' >&2
    return 69
}

msc_file_sensitivity() {
    case $1 in
        *tcc*|*connections*|*process*|*listener*|*shares*|*profile*|*authorized_keys*|*security_events*|*eslogger*)
            printf '%s\n' high
            ;;
        *summary*|*manifest*|*index*|*SHA256SUMS|*stderr*)
            printf '%s\n' medium
            ;;
        *) printf '%s\n' medium ;;
    esac
}

msc_secure_tmp_base() {
    if [ "$(/usr/bin/id -u)" -eq 0 ]; then
        printf '%s\n' /private/tmp
    else
        printf '%s\n' "${TMPDIR:-/tmp}"
    fi
}

# Resolve existing ancestors, including symlinks, before asking Git about the
# destination. Check the index as well in case an ignored path was force-added.
msc_report_directory() (
    [ -n "$1" ] || exit 64
    case $1 in
        /*) _report_parent=$1 ;;
        *) _report_parent=$(/bin/pwd -P)/$1 ;;
    esac
    _report_suffix=''
    while [ ! -d "$_report_parent" ]; do
        [ ! -e "$_report_parent" ] && [ ! -L "$_report_parent" ] || exit 73
        _report_component=${_report_parent##*/}
        case $_report_component in
            .|..) exit 73 ;;
            '') ;;
            *) _report_suffix=/$_report_component$_report_suffix ;;
        esac
        _report_parent=${_report_parent%/*}
        _report_parent=${_report_parent:-/}
    done
    _report_parent=$(CDPATH='' cd -- "$_report_parent" && /bin/pwd -P) || exit 73
    _report_path=${_report_parent%/}$_report_suffix
    _report_path=${_report_path:-/}

    _report_repo=$_report_parent
    while [ "$_report_repo" != / ]; do
        if [ -e "$_report_repo/.git" ] || [ -L "$_report_repo/.git" ]; then
            unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
            _report_relative=${_report_path#"$_report_repo"/}
            if [ "$_report_relative" != "$_report_path" ] &&
                /usr/bin/git -C "$_report_repo" check-ignore -q -- "./$_report_relative/" 2>/dev/null &&
                _report_tracked=$(/usr/bin/git -C "$_report_repo" --literal-pathspecs ls-files -- "$_report_relative/" 2>/dev/null) &&
                [ -z "$_report_tracked" ]; then
                break
            fi
            printf '%s\n' 'Refusing report output in Git. Use an ignored directory or a path outside the checkout.' >&2
            exit 73
        fi
        _report_repo=${_report_repo%/*}
        _report_repo=${_report_repo:-/}
    done
    printf '%s\n' "$_report_path"
)

msc_report_file() (
    case $1 in ''|*/|.|..|*/.|*/..) exit 73 ;; esac
    _report_dir=$(msc_report_directory "$(/usr/bin/dirname -- "$1")") || exit $?
    _report_file=${_report_dir%/}/${1##*/}
    [ ! -e "$_report_file" ] && [ ! -L "$_report_file" ] || {
        printf '%s\n' 'Choose a new file for report output.' >&2
        exit 73
    }
    printf '%s\n' "$_report_file"
)

msc_mktemp_dir() {
    _msc_prefix=${1:-macos-security}
    case $_msc_prefix in
        *[!A-Za-z0-9._-]*) return 64 ;;
    esac
    _msc_base=$(msc_secure_tmp_base) || return 70
    _msc_base=$(msc_report_directory "$_msc_base") || return 70
    _msc_dir=$(/usr/bin/mktemp -d "$_msc_base/${_msc_prefix}.XXXXXX") || return 70
    /bin/chmod 700 "$_msc_dir" || {
        /bin/rm -rf "$_msc_dir"
        return 70
    }
    printf '%s\n' "$_msc_dir"
}

msc_create_private_dir() {
    [ ! -e "$1" ] && [ ! -L "$1" ] || return 73
    _msc_requested=$(msc_report_directory "$1") || return $?
    (umask 077; /bin/mkdir -p -- "$(/usr/bin/dirname -- "$_msc_requested")" && /bin/mkdir -m 700 -- "$_msc_requested") || return 73
    printf '%s\n' "$_msc_requested"
}

msc_stop_process_group() {
    _msc_pid=${1:-}
    _msc_signal=${2:-TERM}
    msc_is_uint "$_msc_pid" || return 0
    [ "$_msc_pid" -gt 1 ] || return 0
    /bin/kill "-$_msc_signal" -- "-$_msc_pid" 2>/dev/null || \
        /bin/kill "-$_msc_signal" "$_msc_pid" 2>/dev/null || true
}

# Usage: msc_run_timed_capture SECONDS STDOUT STDERR MARKER COMMAND [ARG...]
# The command receives a dedicated process group so descendants are bounded too.
msc_run_timed_capture() (
    _msc_seconds=$1
    _msc_stdout=$2
    _msc_stderr=$3
    _msc_marker=$4
    shift 4

    /bin/rm -f "$_msc_marker"
    set -m
    "$@" >"$_msc_stdout" 2>"$_msc_stderr" &
    _msc_command_pid=$!
    (
        /bin/sleep "$_msc_seconds"
        if /bin/kill -0 "$_msc_command_pid" 2>/dev/null; then
            : >"$_msc_marker"
            msc_stop_process_group "$_msc_command_pid" TERM
            /bin/sleep 1
            msc_stop_process_group "$_msc_command_pid" KILL
        fi
    ) &
    _msc_watchdog_pid=$!
    set +m
    trap 'msc_stop_process_group "$_msc_command_pid" KILL; msc_stop_process_group "$_msc_watchdog_pid" KILL; exit 130' HUP INT TERM

    wait "$_msc_command_pid" 2>/dev/null
    _msc_rc=$?
    if [ -e "$_msc_marker" ]; then
        wait "$_msc_watchdog_pid" 2>/dev/null || true
        exit 124
    fi
    /bin/kill -KILL -- "-$_msc_command_pid" 2>/dev/null || true
    msc_stop_process_group "$_msc_watchdog_pid" KILL
    wait "$_msc_watchdog_pid" 2>/dev/null || true
    exit "$_msc_rc"
)

# Compatibility form used by the triage collector: stdout and stderr are
# combined into one evidence file, with a 124 return code on timeout.
msc_run_with_timeout() {
    _msc_seconds=$1
    _msc_output=$2
    shift 2
    _msc_error="${_msc_output}.stderr.$$"
    _msc_marker="${_msc_output}.timeout.$$"
    msc_run_timed_capture "$_msc_seconds" "$_msc_output" "$_msc_error" "$_msc_marker" "$@"
    _msc_rc=$?
    if [ -s "$_msc_error" ]; then
        /bin/cat "$_msc_error" >>"$_msc_output"
    fi
    /bin/rm -f "$_msc_error" "$_msc_marker"
    return "$_msc_rc"
}

msc_redact_home() {
    _msc_value=$1
    _msc_home=${2:-${HOME:-}}
    printf '%s' "$_msc_value" | /usr/bin/awk -v home_path="$_msc_home" '
        {
            value=$0
            while (home_path != "" && index(value, home_path)) {
                value=substr(value, 1, index(value, home_path)-1) "~" substr(value, index(value, home_path)+length(home_path))
            }
            printf "%s", value
        }
    '
}

msc_jsonl_count() {
    _msc_file=$1
    _msc_field=$2
    _msc_value=$3
    [ -r "$_msc_file" ] || { printf '0\n'; return; }
    /usr/bin/grep -F "\"$_msc_field\":\"$_msc_value\"" "$_msc_file" 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' '
}

msc_validate_jsonl() {
    _msc_file=$1
    [ -s "$_msc_file" ] || return 1
    if command -v jq >/dev/null 2>&1; then
        # Parse-only: jq -e would reject a file whose last value is false/null.
        jq -c . "$_msc_file" >/dev/null 2>&1
        return
    fi
    while IFS= read -r _msc_line || [ -n "$_msc_line" ]; do
        printf '%s\n' "$_msc_line" | /usr/bin/plutil -convert json -o - -- - >/dev/null 2>&1 || return 1
    done <"$_msc_file"
}
