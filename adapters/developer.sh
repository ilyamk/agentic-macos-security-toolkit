# SPDX-License-Identifier: MIT
# Developer dependency and secret scanning adapters.

msa_osv_scanner_run() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5; _msa_target=$6
    if [ -z "$_msa_target" ] || [ ! -d "$_msa_target" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.osv-scanner not_requested "No developer project directory was selected." false osv-scanner ""
        return 0
    fi
    if [ "$MSC_ALLOW_NETWORK" -ne 1 ]; then
        mse_emit_coverage "$_msa_coverage" adapter.osv-scanner not_requested "OSV needs explicit network access permitted by policy." true osv-scanner ""
        return
    fi
    if ! _msa_bin=$(msd_ensure osv-scanner "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.osv-scanner not_installed "OSV-Scanner is unavailable after the allowed Homebrew installation attempt." true osv-scanner "adapters/install.log"
        return 0
    fi
    _msa_raw="$_msa_out/osv-scanner.json"; _msa_err="$_msa_out/osv-scanner.stderr"
    msc_run_timed_capture 900 "$_msa_raw" "$_msa_err" "$_msa_out/.osv.timeout" \
        "$_msa_bin" scan source --recursive --allow-no-lockfiles --format json --verbosity error "$_msa_target"
    _msa_rc=$?
    if [ "$_msa_rc" -gt 1 ] || ! _msa_count=$(jq -es '
        select(length==1) | .[0] |
        select(type=="object" and has("results") and (.results | type=="array" or type=="null")) |
        [.results[]?.packages[]?.vulnerabilities[]?] | length
    ' "$_msa_raw" 2>/dev/null); then
        _msa_state=error; [ "$_msa_rc" -eq 124 ] && _msa_state=timeout
        mse_emit_coverage "$_msa_coverage" adapter.osv-scanner "$_msa_state" "OSV-Scanner failed or produced invalid JSON (exit=$_msa_rc)." true osv-scanner "adapters/osv-scanner.stderr"
        return 0
    fi
    _msa_data=$(jq -cn --arg target "$_msa_target" --argjson vulnerabilities "$_msa_count" '{target:$target,vulnerability_records:$vulnerabilities,scope:"selected_project"}')
    mse_emit_observation "$_msa_observations" adapter.osv-scanner supply_chain collected "OSV dependency scan completed for the selected project." "adapters/osv-scanner.json" "$_msa_data" high
    mse_emit_coverage "$_msa_coverage" adapter.osv-scanner collected "Valid OSV-Scanner JSON collected." true osv-scanner "adapters/osv-scanner.json"
    if [ "$_msa_count" -gt 0 ]; then
        mse_emit_finding "$_msa_findings" adapter.osv-scanner adapters supply_chain warn high high exposure "Known vulnerable project dependencies" "OSV-Scanner returned $_msa_count vulnerability record(s) in the selected project." "adapters/osv-scanner.json" "Review direct/transitive reachability and upgrade or document an expiring exception." osv-scanner
    else
        mse_emit_finding "$_msa_findings" adapter.osv-scanner adapters supply_chain pass info high configuration "No OSV dependency match" "No known vulnerability was returned for supported manifests; unsupported or unpinned dependencies may remain." "adapters/osv-scanner.json" "" osv-scanner
    fi
}

msa_gitleaks_run() (
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5; _msa_target=$6
    if [ -z "$_msa_target" ] || [ ! -d "$_msa_target" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.gitleaks not_requested "No developer project directory was selected." false gitleaks ""
        exit 0
    fi
    if ! _msa_bin=$(msd_ensure gitleaks "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.gitleaks not_installed "Gitleaks is unavailable after the allowed Homebrew installation attempt." true gitleaks "adapters/install.log"
        exit 0
    fi
    _msa_gitleaks_tmp=$(msc_mktemp_dir macos-security-gitleaks) || exit 2
    trap '/bin/rm -f "$_msa_gitleaks_tmp/report.json" "$_msa_gitleaks_tmp/timeout" "$_msa_gitleaks_tmp/config.toml" "$_msa_gitleaks_tmp/.gitleaksignore"; /bin/rmdir "$_msa_gitleaks_tmp"' EXIT
    _msa_raw="$_msa_gitleaks_tmp/report.json"; _msa_redacted="$_msa_out/gitleaks.json"
    printf '%s\n' '[extend]' 'useDefault = true' >"$_msa_gitleaks_tmp/config.toml" || exit 2
    : >"$_msa_gitleaks_tmp/.gitleaksignore" || exit 2
    msc_run_timed_capture 900 /dev/null /dev/null "$_msa_gitleaks_tmp/timeout" \
        "$_msa_bin" dir --config "$_msa_gitleaks_tmp/config.toml" --ignore-gitleaks-allow \
        --gitleaks-ignore-path "$_msa_gitleaks_tmp/.gitleaksignore" \
        --redact=100 --report-format json --report-path "$_msa_raw" "$_msa_target"
    _msa_rc=$?
    if [ "$_msa_rc" -eq 0 ] && [ ! -s "$_msa_raw" ]; then printf '[]\n' >"$_msa_raw" || exit 2; fi
    if [ "$_msa_rc" -gt 1 ] || ! jq -e 'type=="array"' "$_msa_raw" >/dev/null 2>&1; then
        _msa_state=error; [ "$_msa_rc" -eq 124 ] && _msa_state=timeout
        mse_emit_coverage "$_msa_coverage" adapter.gitleaks "$_msa_state" "Gitleaks failed or produced invalid JSON (exit=$_msa_rc)." true gitleaks ""
        exit $?
    fi
    jq '[.[] | {RuleID,Description,File,StartLine,EndLine,Fingerprint,Secret:"REDACTED"}]' "$_msa_raw" >"$_msa_redacted" || exit 2
    _msa_count=$(jq 'length' "$_msa_redacted") || exit 2
    mse_emit_observation "$_msa_observations" adapter.gitleaks supply_chain collected "Redacted secret scan completed for the selected project." "adapters/gitleaks.json" "$(jq -cn --argjson findings "$_msa_count" '{redacted:true,finding_count:$findings,scope:"selected_project"}')" secret
    mse_emit_coverage "$_msa_coverage" adapter.gitleaks collected "Gitleaks output was reduced to metadata; secret values are not retained." true gitleaks "adapters/gitleaks.json"
    if [ "$_msa_count" -gt 0 ]; then
        mse_emit_finding "$_msa_findings" adapter.gitleaks adapters supply_chain warn high high exposure "Potential secrets in selected project" "Gitleaks returned $_msa_count redacted finding(s). Secret values were discarded." "adapters/gitleaks.json" "Validate, revoke exposed credentials from a trusted device, remove from history, and add prevention controls." gitleaks
    fi
)

msa_trivy_run() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_log=$5; _msa_target=$6
    if [ -z "$_msa_target" ] || [ ! -d "$_msa_target" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.trivy not_requested "No developer project directory was selected." false trivy ""
        return 0
    fi
    if [ "$MSC_ALLOW_NETWORK" -ne 1 ]; then
        mse_emit_coverage "$_msa_coverage" adapter.trivy not_requested "Trivy needs explicit network access permitted by policy." true trivy ""
        return
    fi
    if ! _msa_bin=$(msd_ensure trivy "$_msa_log"); then
        mse_emit_coverage "$_msa_coverage" adapter.trivy not_installed "Trivy is unavailable after the allowed Homebrew installation attempt." true trivy "adapters/install.log"
        return 0
    fi
    _msa_raw="$_msa_out/trivy.json"; _msa_err="$_msa_out/trivy.stderr"
    msc_run_timed_capture 1200 "$_msa_raw" "$_msa_err" "$_msa_out/.trivy.timeout" \
        "$_msa_bin" filesystem --format json --scanners vuln,misconfig --quiet "$_msa_target"
    _msa_rc=$?
    if [ "$_msa_rc" -ne 0 ] || ! _msa_count=$(jq -es '
        select(length==1) | .[0] |
        select(type=="object" and .SchemaVersion==2 and (.Results | type=="array" or type=="null")) |
        [.Results[]? | (.Vulnerabilities[]?, .Misconfigurations[]?)] | length
    ' "$_msa_raw" 2>/dev/null); then
        _msa_state=error; [ "$_msa_rc" -eq 124 ] && _msa_state=timeout
        mse_emit_coverage "$_msa_coverage" adapter.trivy "$_msa_state" "Trivy failed or produced invalid JSON (exit=$_msa_rc)." true trivy "adapters/trivy.stderr"
        return 0
    fi
    mse_emit_observation "$_msa_observations" adapter.trivy supply_chain collected "Trivy vulnerability/misconfiguration scan completed; secret scanning was disabled." "adapters/trivy.json" "$(jq -cn --argjson findings "$_msa_count" '{finding_count:$findings,secret_scanning:false,scope:"selected_project"}')" high
    mse_emit_coverage "$_msa_coverage" adapter.trivy collected "Valid Trivy JSON collected." true trivy "adapters/trivy.json"
    if [ "$_msa_count" -gt 0 ]; then
        mse_emit_finding "$_msa_findings" adapter.trivy adapters supply_chain warn high medium exposure "Trivy project findings require review" "Trivy returned $_msa_count vulnerability or misconfiguration record(s)." "adapters/trivy.json" "Prioritize exploitable high/critical issues in shipped artifacts." trivy
    fi
}
