# SPDX-License-Identifier: MIT
# Permission-only inventory for common developer credential stores.

msn_collect_credential_metadata() {
    _msn_out=$1; _msn_observations=$2; _msn_coverage=$3; _msn_home=$4
    _msn_raw="$_msn_out/credential-metadata.jsonl"; : >"$_msn_raw"; _msn_count=0; _msn_open=0
    for _msn_path in \
        "$_msn_home/.npmrc" "$_msn_home/.pypirc" "$_msn_home/.netrc" \
        "$_msn_home/.config/gh/hosts.yml" "$_msn_home/.docker/config.json" \
        "$_msn_home/.kube/config" "$_msn_home/.aws/credentials" \
        "$_msn_home/.config/gcloud/credentials.db" "$_msn_home/.azure/accessTokens.json"; do
        [ -e "$_msn_path" ] || continue
        _msn_count=$((_msn_count + 1)); _msn_mode=$(/usr/bin/stat -f '%Lp' "$_msn_path" 2>/dev/null || printf unknown)
        _msn_owner=$(/usr/bin/stat -f '%Su:%Sg' "$_msn_path" 2>/dev/null || printf unknown)
        _msn_risky=false
        case $_msn_mode in *[4-7][0-7]|*[0-7][4-7]) _msn_risky=true; _msn_open=$((_msn_open + 1)) ;; esac
        jq -cn --arg path "$(msc_redact_home "$_msn_path" "$_msn_home")" --arg owner "$_msn_owner" --arg mode "$_msn_mode" --argjson overly_permissive "$_msn_risky" '{path:$path,owner:$owner,mode:$mode,overly_permissive:$overly_permissive,contents_collected:false}' >>"$_msn_raw"
    done
    mse_emit_observation "$_msn_observations" native.credential_metadata credentials collected "Credential-store existence, ownership, and permissions collected without values." "native/credential-metadata.jsonl" "$(jq -cn --argjson files "$_msn_count" --argjson risky "$_msn_open" '{file_count:$files,overly_permissive_count:$risky,contents_collected:false}')" secret
    mse_emit_coverage "$_msn_coverage" native.credential_metadata collected "Selected developer credential paths checked; secret values were never read into evidence." true native "native/credential-metadata.jsonl"
}
