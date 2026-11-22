#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"

usage() {
    printf '%s\n' 'Usage: macos-security reports list [--kind KIND]' \
       '       macos-security reports prune --plan --older-than DAYS [--kind KIND]'
}
mode=${1:-}; kind=all; days=0; plan=0
case $mode in
    -h|--help) usage; exit 0 ;;
    list|prune) shift ;;
    *) usage >&2; exit 2 ;;
esac
while [ "$#" -gt 0 ]; do
    case $1 in
        --kind) [ "$#" -ge 2 ] || exit 2; shift; kind=$1 ;;
        --older-than)
            [ "$mode" = prune ] && [ "$#" -ge 2 ] || exit 2
            shift
            printf '%s\n' "$1" | /usr/bin/grep -Eq '^[1-9][0-9]{0,3}$' && [ "$1" -le 3650 ] || exit 2
            days=$1 ;;
        --plan) [ "$mode" = prune ] || exit 2; plan=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done
[ "$mode" = list ] || { [ "$plan" -eq 1 ] && [ "$days" -gt 0 ]; } || { usage >&2; exit 2; }
case $kind in all|assessments|monitoring|developer|remediation) ;; *) usage >&2; exit 2 ;; esac
msl_use_review_path
msc_require_jq || exit 2
now=$(/bin/date +%s)
uid=$(/usr/bin/id -u)
export LC_ALL=C

recognise_run() {
    [ -d "$run" ] && [ ! -L "$run" ] || return 1
    [ "$(/usr/bin/stat -f '%u' "$run" 2>/dev/null)" = "$uid" ] || return 1
    name=${run##*/}
    printf '%s\n' "$name" | /usr/bin/grep -Eq '^20[0-9]{2}(-[0-9]{2}-[0-9]{2}|[0-9]{4})T[0-9]{6}Z(-[0-9]+)?$'
}

complete_marker() {
    [ ! -e "$run/INCOMPLETE" ] && [ ! -L "$run/INCOMPLETE" ] &&
        msl_scoped_file "$run" SHA256SUMS 4194304 && [ -s "$run/SHA256SUMS" ] || return 1
    case $family in
        assessments|developer)
            msl_scoped_file "$run" "$marker" 4194304 && jq -e '.complete==true' "$run/$marker" >/dev/null 2>&1 ;;
        remediation)
            msl_scoped_file "$run" remediation-plan.json 4194304 || msl_scoped_file "$run" remediation-result.json 4194304 ;;
        monitoring)
            msl_scoped_file "$run" "$marker" 4194304 && jq -e '.record_type=="monitor_summary"' "$run/$marker" >/dev/null 2>&1 ;;
    esac
}

inventory() (
    root=$1; family=$2
    [ "$kind" = all ] || [ "$kind" = "$family" ] || exit 0
    [ -d "$root" ] && [ ! -L "$root" ] || exit 0
    canonical=$(msc_report_directory "$root" 2>/dev/null) || exit 0
    [ "$canonical" = "$root" ] || exit 0
    case $family in
        assessments) marker='run-manifest.json' ;;
        developer) marker=manifest.json ;;
        monitoring) marker=summary.json ;;
        remediation) marker=remediation-plan.json ;;
    esac
    newest=''; latest=''
    if [ -L "$root/latest" ]; then latest=$(/usr/bin/readlink "$root/latest") || latest=''; fi
    for run in "$root"/*; do
        recognise_run || continue
        if complete_marker; then newest=$name; fi
    done
    for run in "$root"/*; do
        recognise_run || continue
        state=incomplete; protected=false; candidate=false
        if complete_marker; then state=marked_complete; fi
        if [ "$name" = "$newest" ] || [ "$name" = "$latest" ]; then protected=true; fi
        modified=$(/usr/bin/stat -f '%m' "$run") || continue
        age=$(( (now - modified) / 86400 )); [ "$age" -ge 0 ] || age=0
        kib=$(/usr/bin/du -sk -P "$run" 2>/dev/null | /usr/bin/awk 'NR==1 { print $1 }')
        msc_is_uint "$kib" || kib=null
        if [ "$mode" = prune ] && [ "$state" = marked_complete ] && [ "$protected" = false ] &&
            [ "$age" -ge "$days" ]; then candidate=true; fi
        jq -cn --arg id "$name" --arg family "$family" --arg root_name "${root#"$ROOT_DIR"/}" --arg state "$state" \
            --argjson age "$age" --argjson size "$kib" --argjson protected "$protected" --argjson candidate "$candidate" '
            {run_id:$id,kind:$family,root:$root_name,state:$state,age_days:$age,kib_on_disk:$size,protected:$protected,prune_candidate:$candidate}'
    done
)
records=$(
    if [ ! -L "$ROOT_DIR/security-results" ]; then
        for family in assessments monitoring developer remediation; do
            inventory "$ROOT_DIR/security-results/$family" "$family"
        done
    fi
    inventory "$ROOT_DIR/audit-results" assessments
    inventory "$ROOT_DIR/monitoring-results" monitoring
    inventory "$ROOT_DIR/remediation-results" remediation
) || exit 2
printf '%s\n' "$records" | jq -cs --arg mode "$mode" --argjson days "$days" '
    {schema:"macos-security-report-inventory/v1",record_type:"report_inventory",mode:(if $mode=="prune" then "prune_plan" else "list" end),
     older_than_days:(if $mode=="prune" then $days else null end),mutates:false,
     candidate_count:([.[]|select(.prune_candidate)]|length),reports:.}'
