# SPDX-License-Identifier: MIT

msr_stealth_state() {
    _stealth_tool=$1; _stealth_dir=$2
    msc_run_timed_capture 15 "$_stealth_dir/state" /dev/null "$_stealth_dir/timeout" "$_stealth_tool" --getstealthmode || return 1
    if LC_ALL=C /usr/bin/grep -Eiq '^stealth mode (is )?(enabled|on)[.]?$' "$_stealth_dir/state"; then
        printf '%s\n' on
    elif LC_ALL=C /usr/bin/grep -Eiq '^stealth mode (is )?(disabled|off)[.]?$' "$_stealth_dir/state"; then
        printf '%s\n' off
    else
        return 1
    fi
}

msr_apply_stealth() (
    _stealth_tool=$1; _stealth_results=$2
    _stealth_tmp=$(msc_mktemp_dir macos-security-stealth) || exit 2
    trap '/bin/rm -f "$_stealth_tmp/state" "$_stealth_tmp/timeout"; /bin/rmdir "$_stealth_tmp"' EXIT
    _stealth_before=$(msr_stealth_state "$_stealth_tool" "$_stealth_tmp") || _stealth_before=unknown
    _stealth_after=$_stealth_before; _stealth_rc=0; _stealth_rollback=''
    case $_stealth_before in
        off)
            msc_run_timed_capture 15 /dev/null /dev/null "$_stealth_tmp/timeout" "$_stealth_tool" --setstealthmode on || _stealth_rc=$?
            _stealth_after=$(msr_stealth_state "$_stealth_tool" "$_stealth_tmp") || _stealth_after=unknown
            [ "$_stealth_after" = off ] || _stealth_rollback='/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off'
            ;;
        unknown) _stealth_rc=2 ;;
    esac
    jq -cn --arg before "$_stealth_before" --arg after "$_stealth_after" --argjson rc "$_stealth_rc" --arg rollback "$_stealth_rollback" '
        {id:"firewall.enable_stealth",before:$before,after:$after,exit_code:$rc,
         changed:($before=="off" and $after=="on"),verified:($rc==0 and $after=="on"),
         rollback:(if $rollback=="" then null else $rollback end)}' >>"$_stealth_results" || exit 2
    [ "$_stealth_rc" -eq 0 ] && [ "$_stealth_after" = on ]
)
