# SPDX-License-Identifier: MIT
# Deterministic detectors over normalized native observations.

msd_detect_native() {
    _msd_observations=$1; _msd_findings=$2

    _msd_disabled=$(jq -r 'select(.id=="native.background_security") | .data.explicit_security_update_disable // 0' "$_msd_observations" | /usr/bin/tail -n 1)
    if [ "${_msd_disabled:-0}" -eq 1 ]; then
        mse_emit_finding "$_msd_findings" updates.background_security native updates warn high medium configuration "Background security updates may be disabled" "A security/system-data update preference was explicitly false in the effective preference evidence." "native/background-security.txt" "Enable automatic Background Security Improvements and system data/security updates unless a documented management policy replaces them." native-background-security
    fi

    _msd_shell=$(jq -r 'select(.id=="native.shell_startup") | .data.flagged_count // 0' "$_msd_observations" | /usr/bin/tail -n 1)
    if [ "${_msd_shell:-0}" -gt 0 ]; then
        mse_emit_finding "$_msd_findings" persistence.shell_startup native persistence warn medium low anomaly "Shell startup commands require review" "$_msd_shell startup file(s) matched downloader/interpreter/temp-path heuristics; developer configuration may be legitimate." "native/shell-startup.jsonl" "Inspect the local files and validate each command's origin before changing anything." native-shell-startup
    fi

    _msd_native=$(jq -r 'select(.id=="native.native_messaging") | .data.untrusted_macho_count // 0' "$_msd_observations" | /usr/bin/tail -n 1)
    if [ "${_msd_native:-0}" -gt 0 ]; then
        mse_emit_finding "$_msd_findings" browser.native_messaging native browser warn high medium anomaly "Untrusted browser native messaging executable" "$_msd_native native host executable(s) failed signature/policy assessment." "native/native-messaging.jsonl" "Match the host to an approved extension and verify publisher, provenance, hash, and necessity." native-messaging
    fi
    _msd_missing=$(jq -r 'select(.id=="native.native_messaging") | .data.missing_executable_count // 0' "$_msd_observations" | /usr/bin/tail -n 1)
    if [ "${_msd_missing:-0}" -gt 0 ]; then
        mse_emit_finding "$_msd_findings" browser.native_messaging_stale native browser warn medium high anomaly "Stale browser native messaging manifests" "$_msd_missing native host manifest(s) point to a missing executable." "native/native-messaging.jsonl" "Confirm the corresponding browser extension/application is removed or repair the approved installation." native-messaging
    fi

    _msd_creds=$(jq -r 'select(.id=="native.credential_metadata") | .data.overly_permissive_count // 0' "$_msd_observations" | /usr/bin/tail -n 1)
    if [ "${_msd_creds:-0}" -gt 0 ]; then
        mse_emit_finding "$_msd_findings" credentials.permissions native credentials warn high high exposure "Developer credential file permissions require review" "$_msd_creds credential metadata file(s) appear group/world readable or writable." "native/credential-metadata.jsonl" "Verify application requirements, then restrict permissions to the owning user where safe." credential-metadata
    fi
}
