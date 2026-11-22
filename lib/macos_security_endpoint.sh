# SPDX-License-Identifier: MIT
# Stream Endpoint Security events through the normaliser before writing them.

msc_endpoint_start() {
    if [ "$(/usr/bin/id -u)" -ne 0 ] || [ ! -x /usr/bin/eslogger ]; then
        MSC_ENDPOINT_PID=''; MSC_ENDPOINT_READER=''
        printf '%s\n' 'Endpoint Security requires root and the system eslogger.' >"$1/eslogger.status"
        : >"$1/timeline.jsonl"
        return 1
    fi
    msc_endpoint_stream "$1" "$2" /usr/bin/eslogger
}

msc_endpoint_stream() {
    _endpoint_dir=$1; _endpoint_normaliser=$2; _endpoint_binary=$3
    _endpoint_status="$_endpoint_dir/eslogger.status"
    _endpoint_timeline="$_endpoint_dir/timeline.jsonl"
    _endpoint_fifo="$_endpoint_dir/.endpoint-events"
    MSC_ENDPOINT_PID=''; MSC_ENDPOINT_READER=''
    if msc_run_timed_capture 5 "$_endpoint_dir/.supported-events" /dev/null "$_endpoint_dir/.supported-timeout" "$_endpoint_binary" --list-events; then
        set --
        for _endpoint_event in exec btm_launch_item_add btm_launch_item_remove gatekeeper_user_override xp_malware_detected xp_malware_remediated profile_add profile_remove tcc_modify openssh_login screensharing_attach sudo su; do
            /usr/bin/grep -Fxq "$_endpoint_event" "$_endpoint_dir/.supported-events" && set -- "$@" "$_endpoint_event"
        done
    else
        set --
    fi
    /bin/rm -f "$_endpoint_dir/.supported-events" "$_endpoint_dir/.supported-timeout"
    if [ "$#" -eq 0 ]; then
        printf '%s\n' 'Supported Endpoint Security events could not be determined.' >"$_endpoint_status"
        : >"$_endpoint_timeline"
        return 1
    fi
    /usr/bin/mkfifo -m 600 "$_endpoint_fifo" || return 2
    set -m
    "$_endpoint_normaliser" --input - --output "$_endpoint_timeline" <"$_endpoint_fifo" &
    MSC_ENDPOINT_READER=$!
    "$_endpoint_binary" "$@" >"$_endpoint_fifo" 2>/dev/null &
    MSC_ENDPOINT_PID=$!
    set +m
}

msc_endpoint_finish() {
    [ -n "$MSC_ENDPOINT_PID" ] || return 1
    _endpoint_running=0
    if /bin/kill -0 "$MSC_ENDPOINT_PID" 2>/dev/null; then
        _endpoint_running=1
        msc_stop_process_group "$MSC_ENDPOINT_PID" INT
    fi
    set -m
    (
        /bin/sleep 3
        msc_stop_process_group "$MSC_ENDPOINT_PID" KILL
        msc_stop_process_group "$MSC_ENDPOINT_READER" KILL
    ) &
    _endpoint_watchdog=$!
    set +m
    _endpoint_rc=0; wait "$MSC_ENDPOINT_PID" 2>/dev/null || _endpoint_rc=$?
    _endpoint_reader_rc=0; wait "$MSC_ENDPOINT_READER" 2>/dev/null || _endpoint_reader_rc=$?
    msc_stop_process_group "$_endpoint_watchdog" KILL
    wait "$_endpoint_watchdog" 2>/dev/null || true
    MSC_ENDPOINT_PID=''; MSC_ENDPOINT_READER=''
    /bin/rm -f "$_endpoint_fifo"
    if [ "$_endpoint_running" -eq 1 ] && [ "$_endpoint_reader_rc" -eq 0 ] && [ -f "$_endpoint_timeline" ]; then
        case $_endpoint_rc in
            0|130) printf '%s\n' 'Endpoint Security stream completed.' >"$_endpoint_status"; return 0 ;;
        esac
    fi
    printf 'Endpoint Security stream incomplete (eslogger=%s, normaliser=%s).\n' "$_endpoint_rc" "$_endpoint_reader_rc" >"$_endpoint_status"
    return 1
}
