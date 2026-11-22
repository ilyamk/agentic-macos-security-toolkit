#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_local.sh
. "$ROOT_DIR/lib/macos_security_local.sh"

usage() { printf '%s\n' 'Usage: macos-security repo-preflight PATH [--json]'; }
case ${1:-} in -h|--help) usage; exit 0 ;; esac
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage >&2; exit 2; }
[ "$#" -eq 1 ] || [ "$2" = --json ] || { usage >&2; exit 2; }
[ "$(/usr/bin/id -u)" -ne 0 ] || { printf '%s\n' 'Run repo-preflight without sudo.' >&2; exit 2; }
msl_use_review_path
msc_require_jq || exit 2
project=$(msl_directory "$1") || exit 2
export LC_ALL=C

emit() {
    jq -cn --arg id "$1" --arg path "$file" --arg trigger "$2" --arg state "$3" --arg detail "$4" \
        --argjson line "${5:-null}" '{id:$id,path:$path,line:$line,trigger:$trigger,state:$state,detail:$detail}'
}
readable() { msl_scoped_file "$project" "$file" 524288; }
inspect() {
    file=$1; shift
    if readable; then
        emit "$1" "$2" review "$3"
    else
        result=$?
        [ "$result" -eq 1 ] || emit "$1" "$2" unknown 'File was inaccessible, linked or over the size limit.'
    fi
}
first_match() {
    /usr/bin/awk -v pattern="$1" '$0 ~ pattern { print NR; exit }' "$project/$file"
}
scan() {
    file=.git
    if [ -L "$project/.git" ] || [ -f "$project/.git" ]; then
        emit git.metadata git_operation unknown 'Git metadata is linked or uses an external worktree directory.'
    elif [ -d "$project/.git" ]; then
        file=.git/config
        if readable; then
            if /usr/bin/git config --file "$project/$file" --no-includes --get-all core.hooksPath >/dev/null 2>&1; then
                emit git.hookspath git_operation review 'The repository configures a custom hooks directory. Review it manually.'
            else
                rc=$?
                [ "$rc" -eq 1 ] || emit git.config git_operation unknown 'Git configuration could not be parsed.'
            fi
            if /usr/bin/git config --file "$project/$file" --no-includes --get-regexp '^include(if\..+)?\.path$' >/dev/null 2>&1; then
                emit git.include git_operation unknown 'A Git configuration include requires separate review.'
            fi
        else
            rc=$?
            [ "$rc" -eq 1 ] || emit git.config git_operation unknown 'Git configuration was inaccessible, linked or over the size limit.'
        fi
        for hook in applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg commit-msg post-commit pre-rebase post-checkout post-merge pre-push pre-receive update post-receive post-update push-to-checkout pre-auto-gc post-rewrite sendemail-validate fsmonitor-watchman; do
            file=".git/hooks/$hook"
            if readable; then
                [ ! -x "$project/$file" ] || emit git.executable_hook git_operation review 'A standard hook is executable.'
            else
                rc=$?
                [ "$rc" -eq 1 ] || emit git.executable_hook git_operation unknown 'A hook was inaccessible, linked or over the size limit.'
            fi
        done
    fi

    file=.vscode/tasks.json
    if readable; then
        line=$(first_match 'folderOpen|"command"')
        emit editor.tasks editor_open review 'Review task commands and when the editor runs them.' "${line:-null}"
    else
        rc=$?
        [ "$rc" -eq 1 ] || emit editor.tasks editor_open unknown 'Editor tasks could not be read safely.'
    fi
    inspect .vscode/settings.json editor.settings editor_open 'Review workspace settings that select runtimes, executables and extensions.'
    inspect .envrc shell.direnv directory_enter 'A direnv configuration can run commands once authorised.'
    inspect .npmrc package.npmrc dependency_install 'Review project registry, credential references and lifecycle-script policy.'
    inspect .gitmodules git.submodules git_operation 'Review submodule sources before fetching them.'
    inspect .devcontainer/devcontainer.json container.lifecycle container_start 'Review container source and lifecycle commands.'
    inspect .devcontainer.json container.lifecycle container_start 'Review container source and lifecycle commands.'

    file=package.json
    if readable; then
        if script_state=$(jq -ers '
            select(length==1 and (.[0]|type=="object")) | .[0] |
            if (.scripts // {} |type)!="object" then error("Invalid scripts map")
            elif (.scripts // {} | keys | any(IN("preinstall","install","postinstall","prepare","prepublish","prepack","postpack")))
            then "review" else "clear" end' "$project/$file" 2>/dev/null); then
            [ "$script_state" = clear ] || emit package.lifecycle dependency_install review 'A package lifecycle command is declared.'
        else
            emit package.lifecycle dependency_install unknown 'Package metadata could not be parsed.'
        fi
    else
        rc=$?
        [ "$rc" -eq 1 ] || emit package.lifecycle dependency_install unknown 'Package metadata could not be read safely.'
    fi
    for configuration in AGENTS.md CLAUDE.md .mcp.json .cursor/mcp.json .claude/settings.json .claude/settings.local.json .codex/config.toml .vscode/mcp.json .github/copilot-instructions.md; do
        inspect "$configuration" agent.project_config agent_start 'Review project-level agent instructions, tool configuration or permissions.'
    done
}

records=$(scan) || exit 2
report=$(printf '%s\n' "$records" | jq -cs '
    {schema:"macos-security-repo-preflight/v1",record_type:"repo_preflight",scope:"selected_root_allow_list",
     evidence_trust:"untrusted_observations",requires_review:any(.[];.state=="review"),
     coverage:(if any(.[];.state=="unknown") then "partial" else "selected_scope" end),findings:.}
') || exit 2
if [ "$#" -eq 2 ]; then
    printf '%s\n' "$report"
else
    printf '%s\n' "$report" | jq -r '
        if .findings==[] then "No review items in the selected root checks."
        else .findings[] | "\(.state|ascii_upcase)\t\(.path)\(if .line then ":\(.line)" else "" end)\t\(.trigger)\t\(.detail)" end'
fi
if printf '%s\n' "$report" | jq -e '.coverage=="partial"' >/dev/null; then exit 2; fi
if printf '%s\n' "$report" | jq -e .requires_review >/dev/null; then exit 1; fi
