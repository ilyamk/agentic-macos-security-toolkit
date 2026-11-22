# SPDX-License-Identifier: MIT
# Browser Native Messaging Host inventory and executable linkage.

msn_collect_native_messaging() {
    _msn_out=$1; _msn_observations=$2; _msn_coverage=$3; _msn_home=$4
    _msn_raw="$_msn_out/native-messaging.jsonl"; : >"$_msn_raw"; _msn_count=0; _msn_untrusted=0
    for _msn_dir in \
        "$_msn_home/Library/Application Support/Google/Chrome/NativeMessagingHosts" \
        "$_msn_home/Library/Application Support/Chromium/NativeMessagingHosts" \
        "$_msn_home/Library/Application Support/Mozilla/NativeMessagingHosts" \
        "/Library/Google/Chrome/NativeMessagingHosts" \
        "/Library/Application Support/Chromium/NativeMessagingHosts" \
        "/Library/Application Support/Mozilla/NativeMessagingHosts"; do
        [ -d "$_msn_dir" ] || continue
        /usr/bin/find -x "$_msn_dir" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null
    done | LC_ALL=C /usr/bin/sort -u | while IFS= read -r _msn_manifest; do
        _msn_count=$((_msn_count + 1))
        if ! jq -e . "$_msn_manifest" >/dev/null 2>&1; then
            jq -cn --arg manifest "$(msc_redact_home "$_msn_manifest" "$_msn_home")" '{manifest:$manifest,valid_json:false}' >>"$_msn_raw"
            continue
        fi
        _msn_path=$(jq -r '.path // ""' "$_msn_manifest")
        _msn_exists=false; _msn_trusted=null; _msn_assessment=missing; _msn_signing=""
        if [ -n "$_msn_path" ] && [ -e "$_msn_path" ]; then
            _msn_exists=true
            if /usr/bin/file -b "$_msn_path" 2>/dev/null | /usr/bin/grep -q 'Mach-O'; then
                if /usr/bin/codesign --verify --strict "$_msn_path" >/dev/null 2>&1 || /usr/sbin/spctl -a -t execute "$_msn_path" >/dev/null 2>&1; then _msn_trusted=true; _msn_assessment=trusted; else _msn_trusted=false; _msn_assessment=failed; fi
                _msn_signing=$(/usr/bin/codesign -dv --verbose=2 "$_msn_path" 2>&1 | /usr/bin/grep -E '^(Identifier|TeamIdentifier)=' | /usr/bin/tr '\n' ' ')
            else
                _msn_assessment=non_macho
            fi
        fi
        jq -c --arg manifest "$(msc_redact_home "$_msn_manifest" "$_msn_home")" --arg signing "$_msn_signing" --arg assessment "$_msn_assessment" --argjson exists "$_msn_exists" --argjson trusted "$_msn_trusted" '{manifest:$manifest,name:(.name//null),description:(.description//null),path:(.path//null),allowed_origins:(.allowed_origins//[]),allowed_extensions:(.allowed_extensions//[]),executable_exists:$exists,trust_assessment:$assessment,executable_trusted:$trusted,signing:$signing,manifest_sha256:null}' "$_msn_manifest" >>"$_msn_raw"
    done
    # The pipeline loop is a subshell in POSIX sh, so derive totals from evidence.
    _msn_count=$(/usr/bin/awk 'NF {n++} END {print n+0}' "$_msn_raw")
    _msn_untrusted=$(jq -s '[.[] | select(.trust_assessment=="failed")] | length' "$_msn_raw" 2>/dev/null || printf 0)
    _msn_missing=$(jq -s '[.[] | select(.trust_assessment=="missing")] | length' "$_msn_raw" 2>/dev/null || printf 0)
    mse_emit_observation "$_msn_observations" native.native_messaging browser collected "Browser Native Messaging Host manifests and executable trust were mapped." "native/native-messaging.jsonl" "$(jq -cn --argjson hosts "$_msn_count" --argjson untrusted "$_msn_untrusted" --argjson missing "$_msn_missing" '{host_count:$hosts,untrusted_macho_count:$untrusted,missing_executable_count:$missing}')" high
    mse_emit_coverage "$_msn_coverage" native.native_messaging collected "Known Chrome/Chromium/Firefox user and system manifest paths checked." true native "native/native-messaging.jsonl"
}
