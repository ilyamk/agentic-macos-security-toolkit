# SPDX-License-Identifier: MIT
# Optional inventory and continuous-sensor health adapters.

msa_osquery_run() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5
    if ! _msa_bin=$(msd_ensure osquery "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.osquery not_installed "osquery is unavailable after the allowed Homebrew installation attempt." false osquery "adapters/install.log"
        return 0
    fi
    _msa_raw="$_msa_out/osquery.json"; _msa_err="$_msa_out/osquery.stderr"; _msa_tmp="$_msa_out/.osquery"
    : >"$_msa_err"
    msc_run_timed_capture 35 "${_msa_tmp}.processes" "$_msa_err" "${_msa_tmp}.timeout" "$_msa_bin" --json 'select pid,parent,name,path,uid from processes;'; _msa_p=$?
    msc_run_timed_capture 35 "${_msa_tmp}.listeners" "$_msa_err" "${_msa_tmp}.timeout" "$_msa_bin" --json 'select pid,address,port,protocol,family from listening_ports;'; _msa_l=$?
    msc_run_timed_capture 35 "${_msa_tmp}.launchd" "$_msa_err" "${_msa_tmp}.timeout" "$_msa_bin" --json 'select name,path,program,run_at_load,keep_alive from launchd;'; _msa_d=$?
    if [ "$_msa_p" -ne 0 ] || [ "$_msa_l" -ne 0 ] || [ "$_msa_d" -ne 0 ] || ! jq -e . "${_msa_tmp}.processes" "${_msa_tmp}.listeners" "${_msa_tmp}.launchd" >/dev/null 2>&1; then
        mse_emit_coverage "$_msa_coverage" adapter.osquery error "One or more osquery snapshot queries failed." false osquery "adapters/osquery.stderr"
        /bin/rm -f "${_msa_tmp}.processes" "${_msa_tmp}.listeners" "${_msa_tmp}.launchd"
        return 0
    fi
    jq -n --slurpfile processes "${_msa_tmp}.processes" --slurpfile listeners "${_msa_tmp}.listeners" --slurpfile launchd "${_msa_tmp}.launchd" '{processes:$processes[0],listeners:$listeners[0],launchd:$launchd[0]}' >"$_msa_raw"
    /bin/rm -f "${_msa_tmp}.processes" "${_msa_tmp}.listeners" "${_msa_tmp}.launchd"
    mse_emit_observation "$_msa_observations" adapter.osquery inventory collected "osquery snapshot tables were collected as one valid JSON object." "adapters/osquery.json" "$(jq -cn --arg version "$(msd_version osquery "$_msa_bin")" '{tool_version:$version,event_tables_tested:false}')" high
    mse_emit_coverage "$_msa_coverage" adapter.osquery collected "Snapshot queries succeeded; this does not validate osqueryd Endpoint Security event tables." false osquery "adapters/osquery.json"
}

msa_santa_run() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5
    if ! _msa_bin=$(msd_ensure santa "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.santa not_installed "Santa is unavailable after the allowed Homebrew installation attempt." false santa "adapters/install.log"
        return 0
    fi
    _msa_raw="$_msa_out/santa-status.txt"; _msa_err="$_msa_out/santa.stderr"
    msc_run_timed_capture 20 "$_msa_raw" "$_msa_err" "$_msa_out/.santa.timeout" "$_msa_bin" status; _msa_rc=$?
    if [ "$_msa_rc" -ne 0 ]; then
        mse_emit_coverage "$_msa_coverage" adapter.santa partial "Santa is installed but sensor status is unavailable; System Extension/FDA approval may still be required." false santa "adapters/santa.stderr"
        return 0
    fi
    mse_emit_observation "$_msa_observations" adapter.santa monitoring collected "Santa status collected. Installation does not imply that required macOS approvals are granted." "adapters/santa-status.txt" "$(jq -cn --arg version "$(msd_version santa "$_msa_bin")" '{tool_version:$version,mode_change_performed:false}')" high
    mse_emit_coverage "$_msa_coverage" adapter.santa collected "Santa status command succeeded; no mode or rule changes were made." false santa "adapters/santa-status.txt"
}
