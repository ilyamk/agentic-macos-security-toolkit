# SPDX-License-Identifier: MIT
# YARA-X and classic YARA adapters. Matches are derived from structured/text
# output, never from the classic YARA exit code.

msa_yara_run() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5; _msa_candidates=$6; _msa_rules=$7
    if [ -z "$_msa_rules" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.yara not_requested "No reviewed local YARA rules were supplied." false yara-x ""
        return 0
    fi
    if [ ! -r "$_msa_rules" ] || [ -z "$_msa_candidates" ] || [ ! -s "$_msa_candidates" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.yara error "Rules or candidate list is unreadable." true yara-x ""
        return 0
    fi
    _msa_rule_hash=$(msc_sha256_file "$_msa_rules")
    if _msa_bin=$(msd_ensure yara-x "$_msa_log"); then
        _msa_raw="$_msa_out/yara-x.jsonl"; _msa_err="$_msa_out/yara-x.stderr"
        msc_run_timed_capture 600 "$_msa_raw" "$_msa_err" "$_msa_out/.yara-x.timeout" \
            "$_msa_bin" scan --output-format ndjson --scan-list --timeout 30 --skip-larger 104857600 "$_msa_rules" "$_msa_candidates"
        _msa_rc=$?
        if [ "$_msa_rc" -eq 0 ] && { [ ! -s "$_msa_raw" ] || jq -e . "$_msa_raw" >/dev/null 2>&1; }; then
            _msa_matches=$(jq -s '[.[] | select((.rules // []) | length > 0)] | length' "$_msa_raw" 2>/dev/null || printf 0)
            _msa_data=$(jq -cn --arg engine yara-x --arg rule_sha256 "$_msa_rule_hash" --argjson matches "$_msa_matches" '{engine:$engine,rule_sha256:$rule_sha256,matched_files:$matches}')
            mse_emit_observation "$_msa_observations" adapter.yara malware_scan collected "YARA-X scan completed against the bounded candidate list." "adapters/yara-x.jsonl" "$_msa_data" high
            mse_emit_coverage "$_msa_coverage" adapter.yara collected "YARA-X produced valid NDJSON." true yara-x "adapters/yara-x.jsonl"
            if [ "$_msa_matches" -gt 0 ]; then
                mse_emit_finding "$_msa_findings" adapter.yara adapters malware_scan warn high medium detection "YARA-X produced matches" "$_msa_matches candidate file(s) matched the reviewed rule set (sha256=$_msa_rule_hash)." "adapters/yara-x.jsonl" "Validate rule specificity and confirm with independent evidence." yara-x
            else
                mse_emit_finding "$_msa_findings" adapter.yara adapters malware_scan pass info medium detection "YARA-X produced no match" "No match in the selected candidates and rules; this is not proof of absence." "adapters/yara-x.jsonl" "" yara-x
            fi
            return 0
        fi
        _msa_state=error; [ "$_msa_rc" -eq 124 ] && _msa_state=timeout
        mse_emit_coverage "$_msa_coverage" adapter.yara "$_msa_state" "YARA-X failed or returned invalid NDJSON (exit=$_msa_rc)." true yara-x "adapters/yara-x.stderr"
        return 0
    fi
    if ! _msa_bin=$(msd_ensure yara "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.yara not_installed "Neither YARA-X nor classic YARA is available." true yara "adapters/install.log"
        return 0
    fi
    _msa_raw="$_msa_out/yara.txt"; _msa_err="$_msa_out/yara.stderr"
    msc_run_timed_capture 600 "$_msa_raw" "$_msa_err" "$_msa_out/.yara.timeout" \
        "$_msa_bin" --scan-list -a 30 -z 104857600 "$_msa_rules" "$_msa_candidates"
    _msa_rc=$?; _msa_matches=$(/usr/bin/awk 'NF {n++} END {print n+0}' "$_msa_raw")
    if [ "$_msa_rc" -eq 0 ]; then
        mse_emit_coverage "$_msa_coverage" adapter.yara collected "Classic YARA completed; matches were counted from stdout." true yara "adapters/yara.txt"
        if [ "$_msa_matches" -gt 0 ]; then
            mse_emit_finding "$_msa_findings" adapter.yara adapters malware_scan warn high medium detection "YARA produced matches" "$_msa_matches output line(s) matched the reviewed rule set (sha256=$_msa_rule_hash)." "adapters/yara.txt" "Validate with independent evidence." yara
        else
            mse_emit_finding "$_msa_findings" adapter.yara adapters malware_scan pass info medium detection "YARA produced no match" "No stdout match in the selected candidates and rules; this is not proof of absence." "adapters/yara.txt" "" yara
        fi
    else
        _msa_state=error; [ "$_msa_rc" -eq 124 ] && _msa_state=timeout
        mse_emit_coverage "$_msa_coverage" adapter.yara "$_msa_state" "Classic YARA failed (exit=$_msa_rc)." true yara "adapters/yara.stderr"
    fi
}
