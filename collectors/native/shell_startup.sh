# SPDX-License-Identifier: MIT
# Shell startup persistence inventory. File contents are inspected locally but
# never copied into evidence.

msn_collect_shell_startup() {
    _msn_out=$1; _msn_observations=$2; _msn_coverage=$3; _msn_home=$4
    _msn_raw="$_msn_out/shell-startup.jsonl"; : >"$_msn_raw"; _msn_count=0; _msn_suspicious=0
    for _msn_file in \
        "$_msn_home/.zshenv" "$_msn_home/.zprofile" "$_msn_home/.zshrc" "$_msn_home/.zlogin" \
        "$_msn_home/.bash_profile" "$_msn_home/.bashrc" "$_msn_home/.profile" \
        /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin /etc/profile /etc/bashrc; do
        [ -f "$_msn_file" ] || continue
        _msn_count=$((_msn_count + 1))
        _msn_mode=$(/usr/bin/stat -f '%Lp' "$_msn_file" 2>/dev/null || printf unknown)
        _msn_owner=$(/usr/bin/stat -f '%Su:%Sg' "$_msn_file" 2>/dev/null || printf unknown)
        _msn_mtime=$(/usr/bin/stat -f '%m' "$_msn_file" 2>/dev/null || printf 0)
        _msn_hash=$(msc_sha256_file "$_msn_file")
        _msn_flags="[]"
        if /usr/bin/grep -Eqi '(curl|wget).*(\||sh|bash|zsh)|osascript|base64[[:space:]]+(-d|--decode)|DYLD_(INSERT_LIBRARIES|LIBRARY_PATH)|launchctl[[:space:]]+(load|bootstrap)|/private/tmp/|/var/tmp/' "$_msn_file" 2>/dev/null; then
            _msn_suspicious=$((_msn_suspicious + 1)); _msn_flags='["download_or_interpreter_pattern"]'
        fi
        jq -cn --arg path "$(msc_redact_home "$_msn_file" "$_msn_home")" --arg owner "$_msn_owner" --arg mode "$_msn_mode" --arg sha256 "$_msn_hash" --argjson mtime "$_msn_mtime" --argjson risk_flags "$_msn_flags" '{path:$path,owner:$owner,mode:$mode,mtime_epoch:$mtime,sha256:$sha256,risk_flags:$risk_flags,contents_collected:false}' >>"$_msn_raw"
    done
    _msn_data=$(jq -cn --argjson files "$_msn_count" --argjson flagged "$_msn_suspicious" '{file_count:$files,flagged_count:$flagged,contents_collected:false}')
    mse_emit_observation "$_msn_observations" native.shell_startup persistence collected "Shell startup metadata and local-only risk patterns collected." "native/shell-startup.jsonl" "$_msn_data" high
    mse_emit_coverage "$_msn_coverage" native.shell_startup collected "Standard user/system shell startup paths checked without retaining content." true native "native/shell-startup.jsonl"
}
