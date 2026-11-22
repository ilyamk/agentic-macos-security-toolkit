#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"

usage() { printf '%s\n' 'Usage: macos-security doctor [--json] [--profile NAME]'; }
format=text; profile=personal-remote-development
while [ "$#" -gt 0 ]; do
    case $1 in
        --json) format=json ;;
        --profile) [ "$#" -ge 2 ] || exit 2; shift; profile=$1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done
case $profile in personal|personal-remote-development|developer|high-risk) ;; *) usage >&2; exit 2 ;; esac
available() { if command -v "$1" >/dev/null 2>&1; then printf true; else printf false; fi; }
brew_found=$(available brew)
git_found=$(available git)
relative_path_entries=$(/usr/bin/awk 'BEGIN {
    path=ENVIRON["PATH"]; n=split(path,entries,":"); count=(n==0);
    for (i=1;i<=n;i++) if (entries[i] !~ /^\//) count++;
    print count+0
}')
msl_use_review_path
msc_system_path_if_root
if ! command -v jq >/dev/null 2>&1; then
    if [ "$format" = json ]; then
        printf '%s\n' '{"schema":"macos-security-doctor/v1","record_type":"doctor","state":"incomplete","missing":["jq"]}'
    else
        printf '%s\n' 'Doctor could not complete because jq is unavailable.'
    fi
    exit 2
fi
present() { if [ -x "$1" ]; then printf true; else printf false; fi; }
os=$(/usr/bin/uname -s)
root=false
[ "$(/usr/bin/id -u)" -ne 0 ] || root=true
policy=$(jq -ce '.dependency_policy | {allow_network:(.allow_network==true),auto_install:(.auto_install==true),
    allow_casks:(.allow_casks==true)}' "$ROOT_DIR/config/profiles/$profile.json") || exit 2
result=$(jq -cn --arg os "$os" --arg profile "$profile" --argjson root "$root" --argjson policy "$policy" \
    --argjson brew "$brew_found" --argjson git "$git_found" --argjson relative_path_entries "$relative_path_entries" \
    --argjson eslogger "$(present /usr/bin/eslogger)" --argjson sfltool "$(present /usr/bin/sfltool)" '
    {schema:"macos-security-doctor/v1",record_type:"doctor",state:(if $os=="Darwin" then "ready" else "unsupported_os" end),
     platform:$os,profile:$profile,elevated:$root,dependency_policy:$policy,
     commands:{jq:true,brew:$brew,git:$git},relative_path_entries:$relative_path_entries,
     default_checks:{
       network:{state:"not_requested",policy_allows:($policy.allow_network==true)},
       background_items:{state:"not_requested",binary_present:$sfltool},
       endpoint_security:{state:(if $eslogger and $root then "permission_unknown" elif $eslogger then "requires_root" else "unavailable" end)},
       full_disk_access:{state:"unknown"},
       optional_adapters:{state:(if $root then "disabled_under_root" else "check_inventory" end)}
     }}') || exit 2
if [ "$format" = json ]; then
    printf '%s\n' "$result"
else
    printf '%s\n' "$result" | jq -r '
        "Platform: \(.platform) (\(.state)). Policy: \(.profile). Elevated: \(.elevated). Relative PATH entries: \(.relative_path_entries).",
        (.default_checks|to_entries[]|"\(.key)\t\(.value.state)")'
fi
[ "$os" = Darwin ] || exit 2
