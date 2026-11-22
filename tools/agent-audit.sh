#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"
# shellcheck source=lib/macos_security_schema.sh
. "$ROOT_DIR/lib/macos_security_schema.sh"
usage() {
    printf '%s\n' 'Usage: macos-security agent-audit [--json] [--home DIR] [--project DIR] [--baseline FILE]'
}
format=text; home=$HOME; project=''; baseline=''; fixture_home=0
while [ "$#" -gt 0 ]; do
    case $1 in
        --json) format=json ;;
        --home) [ "$#" -ge 2 ] || exit 2; shift; home=$1; fixture_home=1 ;;
        --project) [ "$#" -ge 2 ] || exit 2; shift; project=$1 ;;
        --baseline) [ "$#" -ge 2 ] || exit 2; shift; baseline=$1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
    shift
done
[ "$(/usr/bin/id -u)" -ne 0 ] || { printf '%s\n' 'Run agent-audit without sudo.' >&2; exit 2; }
msl_use_review_path
msc_require_jq || exit 2
home=$(msl_directory "$home") || exit 2
if [ -n "$project" ]; then project=$(msl_directory "$project") || exit 2; fi
codex_home=$home; codex_path=.codex/config.toml
if [ "$fixture_home" -eq 0 ] && [ -n "${CODEX_HOME:-}" ]; then
    codex_home=$(msl_directory "$CODEX_HOME" 2>/dev/null) || codex_home=''
    codex_path=config.toml
fi

check_config() (
    base=$1; path=$2; client=$3; scope=$4; component=$5; registered_project=${6:-}
    state=unavailable
    if [ -n "$base" ] && msl_scoped_file "$base" "$path" 524288; then
        case $path in
            *.toml)
                if metrics=$(LC_ALL=C /usr/bin/awk -f "$ROOT_DIR/tools/agent-audit-codex.awk" "$base/$path"); then
                    jq -cn --arg client "$client" --arg scope "$scope" --arg component "$component" --argjson metrics "$metrics" \
                       '{state:"heuristic",client:$client,scope:$scope,component:$component,declared:$metrics}'
                    exit $?
                fi ;;
            *)
                if record=$(jq -ces --arg client "$client" --arg scope "$scope" --arg component "$component" \
                    --arg registered_project "$registered_project" \
                    -f "$ROOT_DIR/tools/agent-audit-settings.jq" "$base/$path" 2>/dev/null); then
                    printf '%s\n' "$record"
                    exit 0
                fi ;;
        esac
        state=unparsed
    else
        rc=$?
        if [ -n "$base" ] && [ "$rc" -eq 1 ]; then state=absent; fi
    fi
    jq -cn --arg client "$client" --arg scope "$scope" --arg component "$component" --arg state "$state" \
        '{client:$client,scope:$scope,component:$component,state:$state,declared:null}'
)

previous=null
if [ -n "$baseline" ]; then
    baseline=$(msl_explicit_file "$baseline" 1048576) || exit 2
    msc_schema_validate "$ROOT_DIR/schemas/agent-audit.schema.json" "$baseline" >/dev/null || exit 2
    previous=$(jq -ces 'select(length==1 and .[0].schema=="macos-security-agent-audit/v1" and
        (.[0].configurations|type)=="array") | .[0].configurations' "$baseline" 2>/dev/null) || exit 2
fi
records=$(
    check_config "$home" .claude.json claude user mcp
    check_config "$home" .claude/settings.json claude user settings
    check_config "$home" .cursor/mcp.json cursor user mcp
    check_config "$codex_home" "$codex_path" codex user settings
    if [ -n "$project" ]; then
        check_config "$home" .claude.json claude project registered_project "$project"
        check_config "$project" .mcp.json claude project mcp
        check_config "$project" .claude/settings.json claude project settings
        check_config "$project" .claude/settings.local.json claude project local_settings
        check_config "$project" .cursor/mcp.json cursor project mcp
        check_config "$project" .codex/config.toml codex project settings
    fi
) || exit 2
report=$(printf '%s\n' "$records" | jq -cs --argjson previous "$previous" '
    def flags: ["unrestricted_sandbox","automatic_approval","broad_roots","cleartext_http","inline_credentials"];
    def metrics: ["local_servers","remote_servers","declared_oauth_scopes"];
    . as $current |
    {schema:"macos-security-agent-audit/v1",record_type:"agent_audit",evidence_trust:"untrusted_observations",
     effective_permissions:"unknown",configurations:$current,
     coverage:(if any($current[]; .state|IN("unavailable","unparsed","heuristic")) then "partial" else "selected_scope" end),
     changes:(if $previous==null then [] else [
        $current[] as $cfg | select($cfg.declared!=null) |
        ([$previous[]|objects|select(.client==$cfg.client and .scope==$cfg.scope and .component==$cfg.component)][0].declared // {}) as $old |
        ((flags[] as $key | select($cfg.declared[$key]==true and $old[$key]!=true) | $key),
        (metrics[] as $key | select($cfg.declared[$key]!=null and
           $cfg.declared[$key] > (if $old[$key]|type=="number" then $old[$key] else 0 end)) | $key)) as $increase |
        {client:$cfg.client,scope:$cfg.scope,component:$cfg.component,expanded:$increase}
     ] end),
     requires_review:any($current[]; .declared as $declared | any(flags[]; $declared[.]==true))}
') || exit 2
if [ "$format" = json ]; then
    printf '%s\n' "$report"
else
    printf '%s\n' "$report" | jq -r '
        "Effective permissions: unknown. Coverage: \(.coverage).",
        (.configurations[] | "\(.client)\t\(.scope)\t\(.component)\t\(.state)\t\(.declared // {})"),
        (.changes[] | "EXPANDED\t\(.client)\t\(.scope)\t\(.expanded)")'
fi
if printf '%s\n' "$report" | jq -e 'any(.configurations[]; .state|IN("unavailable","unparsed"))' >/dev/null; then exit 2; fi
if printf '%s\n' "$report" | jq -e '.requires_review or (.changes|length)>0' >/dev/null; then exit 1; fi
