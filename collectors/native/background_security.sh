# SPDX-License-Identifier: MIT
# Background Security Improvements and system-data update state.

msn_collect_background_security() {
    _msn_out=$1; _msn_observations=$2; _msn_coverage=$3
    _msn_raw="$_msn_out/background-security.txt"
    /usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate >"$_msn_raw" 2>&1
    _msn_rc=$?
    if [ "$_msn_rc" -ne 0 ]; then
        mse_emit_coverage "$_msn_coverage" native.background_security partial "Software Update preferences were not fully readable." true native "native/background-security.txt"
        return 0
    fi
    _msn_disabled=0
    /usr/bin/grep -Eqi '(ConfigDataInstall|CriticalUpdateInstall|InstallSecurityUpdate)[^=]*=[[:space:]]*(0|false)' "$_msn_raw" && _msn_disabled=1
    _msn_keys=$(/usr/bin/grep -Eic 'ConfigDataInstall|CriticalUpdateInstall|InstallSecurityUpdate|EnableRollback|AutomaticallyInstall' "$_msn_raw" || true)
    _msn_data=$(jq -cn --argjson relevant_keys "$_msn_keys" --argjson explicit_disabled "$_msn_disabled" '{relevant_key_count:$relevant_keys,explicit_security_update_disable:$explicit_disabled,interpretation:"Preference keys vary by macOS build. An absent key does not indicate that updates are disabled."}')
    mse_emit_observation "$_msn_observations" native.background_security updates collected "Software Update and Background Security preference evidence collected." "native/background-security.txt" "$_msn_data" medium
    mse_emit_coverage "$_msn_coverage" native.background_security collected "Preference evidence collected; managed DDM supplemental version/build requires MDM context." true native "native/background-security.txt"
}
