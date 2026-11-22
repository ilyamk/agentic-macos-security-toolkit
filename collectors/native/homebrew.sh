# SPDX-License-Identifier: MIT
# Homebrew package inventory; no upgrade, cleanup, or remediation is performed.

msn_collect_homebrew() {
    _msn_out=$1; _msn_observations=$2; _msn_coverage=$3
    if [ "$(/usr/bin/id -u)" -eq 0 ]; then
        mse_emit_coverage "$_msn_coverage" native.homebrew denied "Homebrew inventory requires a separate unprivileged run." false homebrew ""
        return
    fi
    if ! _msn_brew=$(msd_brew_path); then
        mse_emit_coverage "$_msn_coverage" native.homebrew not_installed "Homebrew is unavailable; it is not bootstrapped via downloaded shell code." false homebrew ""
        return 0
    fi
    if ! HOMEBREW_NO_AUTO_UPDATE=1 msc_run_timed_capture 30 "$_msn_out/homebrew-formulae.txt" "$_msn_out/homebrew.stderr" "$_msn_out/.brew.timeout" "$_msn_brew" list --formula --versions ||
       ! HOMEBREW_NO_AUTO_UPDATE=1 msc_run_timed_capture 30 "$_msn_out/homebrew-casks.txt" "$_msn_out/homebrew.stderr" "$_msn_out/.brew.timeout" "$_msn_brew" list --cask --versions; then
        mse_emit_coverage "$_msn_coverage" native.homebrew partial "One or more package inventories failed or timed out." false homebrew "native/homebrew.stderr"
        return
    fi
    _msn_formulae=$(/usr/bin/awk 'NF {n++} END {print n+0}' "$_msn_out/homebrew-formulae.txt")
    _msn_casks=$(/usr/bin/awk 'NF {n++} END {print n+0}' "$_msn_out/homebrew-casks.txt")
    mse_emit_observation "$_msn_observations" native.homebrew supply_chain collected "Homebrew package inventory collected without updating or modifying packages." "native/homebrew-formulae.txt" "$(jq -cn --argjson formulae "$_msn_formulae" --argjson casks "$_msn_casks" '{formula_count:$formulae,cask_count:$casks,updates_performed:false}')" medium
    mse_emit_coverage "$_msn_coverage" native.homebrew collected "Formula and cask inventories collected; outdated does not by itself mean vulnerable." false homebrew "native/homebrew-formulae.txt"
}
