# SPDX-License-Identifier: MIT
# Objective-See KnockKnock adapter. Sourced by adapters/run.sh.

msa_knockknock_run() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5
    _msa_raw="$_msa_out/knockknock.json"; _msa_err="$_msa_out/knockknock.stderr"
    if ! _msa_bin=$(msd_ensure knockknock "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.knockknock not_installed "KnockKnock is unavailable after the allowed Homebrew installation attempt." true knockknock "adapters/install.log"
        return 0
    fi
    msc_run_timed_capture 300 "$_msa_raw" "$_msa_err" "$_msa_out/.knockknock.timeout" \
        "$_msa_bin" -whosthere -pretty -skipVT
    _msa_rc=$?
    if [ "$_msa_rc" -eq 124 ]; then
        mse_emit_coverage "$_msa_coverage" adapter.knockknock timeout "KnockKnock exceeded 300 seconds." true knockknock "adapters/knockknock.stderr"
        return 0
    fi
    if [ "$_msa_rc" -ne 0 ] || ! jq -e . "$_msa_raw" >/dev/null 2>&1; then
        mse_emit_coverage "$_msa_coverage" adapter.knockknock error "KnockKnock did not produce valid JSON (exit=$_msa_rc)." true knockknock "adapters/knockknock.stderr"
        return 0
    fi
    _msa_count=$(jq '[.. | objects | select(has("path") or has("name") or has("plugin"))] | length' "$_msa_raw" 2>/dev/null || printf 0)
    _msa_data=$(jq -cn --arg path "$_msa_bin" --arg version "$(msd_version knockknock "$_msa_bin")" --argjson records "$_msa_count" '{tool_path:$path,tool_version:$version,record_count:$records,virustotal_queries:false}')
    mse_emit_observation "$_msa_observations" adapter.knockknock persistence collected "KnockKnock persistence inventory collected without VirusTotal queries." "adapters/knockknock.json" "$_msa_data" high
    mse_emit_coverage "$_msa_coverage" adapter.knockknock collected "Valid KnockKnock JSON collected; findings require contextual review." true knockknock "adapters/knockknock.json"
}
