# SPDX-License-Identifier: MIT
# ClamAV adapter for bounded candidate-file scanning. Sourced by adapters/run.sh.

msa_clamav_run() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5; _msa_candidates=$6
    _msa_raw="$_msa_out/clamav.txt"; _msa_err="$_msa_out/clamav.stderr"; _msa_db="$_msa_out/clamav-db"
    if [ -z "$_msa_candidates" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.clamav not_requested "No candidate list was supplied; broad whole-disk scanning is intentionally disabled." false clamav ""
        return 0
    fi
    if [ ! -f "$_msa_candidates" ] || [ ! -r "$_msa_candidates" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.clamav error "The supplied candidate inventory is unreadable." true clamav ""
        return
    fi
    if [ ! -s "$_msa_candidates" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.clamav not_requested "The candidate inventory is empty." false clamav ""
        return
    fi
    if ! _msa_bin=$(msd_ensure clamav "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.clamav not_installed "ClamAV is unavailable after the allowed Homebrew installation attempt." true clamav "adapters/install.log"
        return 0
    fi
    set -- --infected --no-summary --max-filesize=100M --file-list="$_msa_candidates"
    _msa_db_source=installed
    if [ "$MSC_ALLOW_NETWORK" -eq 1 ]; then
        /bin/mkdir -m 700 "$_msa_db" || return 1
        _msa_freshclam=$(command -v freshclam 2>/dev/null || true)
        if [ -z "$_msa_freshclam" ]; then
            mse_emit_coverage "$_msa_coverage" adapter.clamav partial "freshclam is unavailable; signature refresh did not run." true clamav ""
            return
        fi
        {
            printf 'DatabaseDirectory %s\n' "$_msa_db"
            printf '%s\n' 'DatabaseMirror database.clamav.net' 'CompressLocalDatabase yes'
        } >"$_msa_out/freshclam.conf" || return 1
        if ! msc_run_timed_capture 180 "$_msa_out/freshclam.log" "$_msa_out/freshclam.stderr" "$_msa_out/.freshclam.timeout" \
            "$_msa_freshclam" --config-file="$_msa_out/freshclam.conf" ||
            ! /usr/bin/find "$_msa_db" -type f \( -name '*.cvd' -o -name '*.cld' \) -print | /usr/bin/grep -q .; then
            mse_emit_coverage "$_msa_coverage" adapter.clamav partial "A refreshed signature database could not be confirmed." true clamav "adapters/freshclam.log"
            return
        fi
        set -- "$@" --database="$_msa_db"
        _msa_db_source=refreshed
    fi
    msc_run_timed_capture 600 "$_msa_raw" "$_msa_err" "$_msa_out/.clamav.timeout" "$_msa_bin" "$@"
    _msa_rc=$?
    _msa_count=$(/usr/bin/awk 'NF {n++} END {print n+0}' "$_msa_raw")
    _msa_data=$(jq -cn --arg version "$(msd_version clamav "$_msa_bin")" --argjson output_lines "$_msa_count" --arg database "$_msa_db_source" '{tool_version:$version,output_lines:$output_lines,signature_database:$database,automatic_removal:false}')
    mse_emit_observation "$_msa_observations" adapter.clamav malware_scan collected "ClamAV inspected the bounded candidate set using local signatures." "adapters/clamav.txt" "$_msa_data" high
    case $_msa_rc in
        0)
            mse_emit_coverage "$_msa_coverage" adapter.clamav collected "Candidate scan completed with available signatures. Installed signatures may need updating." true clamav "adapters/clamav.txt"
            mse_emit_finding "$_msa_findings" adapter.clamav adapters malware_scan pass info medium detection "ClamAV produced no candidate match" "No signature match in the bounded candidate set; this is not proof of absence." "adapters/clamav.txt" "No action required unless other evidence conflicts." clamav
            ;;
        1)
            mse_emit_coverage "$_msa_coverage" adapter.clamav collected "ClamAV reported at least one candidate match." true clamav "adapters/clamav.txt"
            mse_emit_finding "$_msa_findings" adapter.clamav adapters malware_scan fail critical high detection "ClamAV reported a candidate" "One or more bounded candidate files matched local ClamAV signatures." "adapters/clamav.txt" "Preserve the file and validate with a second independent source before containment." clamav
            ;;
        124) mse_emit_coverage "$_msa_coverage" adapter.clamav timeout "ClamAV exceeded 600 seconds." true clamav "adapters/clamav.stderr" ;;
        *) mse_emit_coverage "$_msa_coverage" adapter.clamav error "ClamAV scan failed (exit=$_msa_rc)." true clamav "adapters/clamav.stderr" ;;
    esac
}
