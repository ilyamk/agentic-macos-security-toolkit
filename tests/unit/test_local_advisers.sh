#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && /bin/pwd -P)
cli=$ROOT_DIR/bin/macos-security
. "$ROOT_DIR/lib/macos_security_updates.sh"
. "$ROOT_DIR/lib/macos_security_schema.sh"
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

project=$TEST_TMP/project
home=$TEST_TMP/home
mkdir -p "$project/.git/hooks" "$project/.vscode" "$project/.devcontainer" "$home/.codex"
if "$cli" repo-preflight "$project" --json | jq -e '.findings==[] and .coverage=="selected_scope"' >/dev/null; then :; else exit 1; fi
printf '%s\n' '[core]' 'hooksPath = /unselected-hook-path' >"$project/.git/config"
printf '#!/bin/sh\ntouch "%s"\n' "$TEST_TMP/executed" >"$project/.git/hooks/pre-commit"
chmod 700 "$project/.git/hooks/pre-commit"
printf 'touch "%s"\n' "$TEST_TMP/executed" >"$project/.envrc"
printf '%s\n' '{"scripts":{"postinstall":"fixture-command-redacted"}}' >"$project/package.json"
printf '%s\n' '{"tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"fixture-command-redacted"}]}' >"$project/.vscode/tasks.json"
printf '%s\n' '{"postCreateCommand":"fixture-command-redacted"}' >"$project/.devcontainer/devcontainer.json"
rc=0
"$cli" repo-preflight "$project" --json >"$TEST_TMP/preflight.json" || rc=$?
[ "$rc" -eq 1 ] && [ ! -e "$TEST_TMP/executed" ]
printf '%s\n' '[Include]' 'path = /unselected-include-path' >>"$project/.git/config"
rc=0
"$cli" repo-preflight "$project" --json >"$TEST_TMP/include.json" || rc=$?
[ "$rc" -eq 2 ]
jq -e 'any(.findings[];.id=="git.include" and .state=="unknown")' "$TEST_TMP/include.json" >/dev/null
if grep -q 'unselected-include-path' "$TEST_TMP/include.json"; then exit 1; fi
printf '%s\n' '[core]' 'hooksPath = /unselected-hook-path' >"$project/.git/config"
jq -e '([.findings[].id]|sort)==(["git.hookspath","git.executable_hook","shell.direnv","package.lifecycle",
    "editor.tasks","container.lifecycle"]|sort) and all(.findings[];.state=="review")' "$TEST_TMP/preflight.json" >/dev/null
if grep -Eq 'fixture-command-redacted|unselected-hook-path' "$TEST_TMP/preflight.json"; then exit 1; fi
ln -s "$project/package.json" "$project/.mcp.json"
rc=0
"$cli" repo-preflight "$project" --json >"$TEST_TMP/linked.json" || rc=$?
[ "$rc" -eq 2 ]
jq -e '.coverage=="partial" and any(.findings[];.path==".mcp.json" and .state=="unknown")' "$TEST_TMP/linked.json" >/dev/null
rm "$project/.mcp.json"
printf '#!/bin/sh\ntouch "%s"\nexit 99\n' "$TEST_TMP/executed" >"$project/jq"
chmod 700 "$project/jq"
rc=0
(cd "$project" && PATH=".:$PATH" "$cli" repo-preflight . --json) >/dev/null || rc=$?
[ "$rc" -eq 1 ] && [ ! -e "$TEST_TMP/executed" ]

"$cli" agent-audit --home "$home" --project "$project" --json >"$TEST_TMP/baseline.json"
cat >"$home/.claude.json" <<'CONFIG'
{"mcpServers":{"private-server-identifier":{"url":"http://diagnostics.example.invalid/?token=private-url-value",
"headers":{"Authorization":"private-inline-value"},"env":{"API_TOKEN":"${MCP_KEY}"},"oauth":{"scopes":["private-scope"]}}}}
CONFIG
project_key=$(CDPATH='' cd -- "$project" && /bin/pwd -P)
jq --arg path "$project_key" '.projects[$path]={mcpServers:{"registered-private-name":{"command":"registered-private-tool"}}}' \
    "$home/.claude.json" >"$TEST_TMP/claude.json"
mv "$TEST_TMP/claude.json" "$home/.claude.json"
cat >"$home/.codex/config.toml" <<'CONFIG'
sandbox_mode = "danger-full-access"
approval_policy = "never"
[sandbox_workspace_write]
writable_roots = ["/"]
[mcp_servers.local]
command = "private-executable"
[mcp_servers.local.env]
PASSWORD = "private-env-value"
CONFIG
cat >"$project/.mcp.json" <<'CONFIG'
{"mcpServers":{"project-server":{"command":"project-fixture","args":["@modelcontextprotocol/server-filesystem","/"]}}}
CONFIG
rc=0
"$cli" agent-audit --home "$home" --project "$project" --baseline "$TEST_TMP/baseline.json" --json >"$TEST_TMP/audit.json" || rc=$?
[ "$rc" -eq 1 ]
jq -e '.effective_permissions=="unknown" and .coverage=="partial" and .requires_review and
    any(.configurations[]; .client=="codex" and .declared.unrestricted_sandbox and
        .declared.automatic_approval and .declared.broad_roots and .declared.inline_credentials) and
    any(.configurations[]; .client=="claude" and .scope=="user" and .declared.cleartext_http and
        .declared.inline_credentials and .declared.declared_oauth_scopes==1) and
    any(.configurations[]; .client=="claude" and .component=="registered_project" and .declared.local_servers==1) and
    any(.configurations[]; .scope=="project" and .component=="mcp" and .declared.broad_roots) and
    any(.changes[]; .scope=="project" and .expanded=="local_servers")' "$TEST_TMP/audit.json" >/dev/null
if grep -Eq 'private-|diagnostics\.example|MCP_KEY|project-fixture' "$TEST_TMP/audit.json"; then exit 1; fi
cat >"$home/.codex/config.toml" <<'CONFIG'
[mcp_servers.remote]
url = "https://diagnostics.example.invalid"
http_headers = { Authorization = "private-inline-header" }
CONFIG
rc=0
"$cli" agent-audit --home "$home" --json >"$TEST_TMP/inline.json" || rc=$?
[ "$rc" -eq 1 ]
jq -e 'any(.configurations[]; .client=="codex" and .declared.inline_credentials)' "$TEST_TMP/inline.json" >/dev/null
if grep -q 'private-inline-header' "$TEST_TMP/inline.json"; then exit 1; fi
mkdir "$home/.cursor"
cat >"$home/.cursor/mcp.json" <<'CONFIG'
{"mcpServers":{"fixture":{"url":"https://diagnostics.example.invalid","headers":{"Authorization":"Bearer YOUR_API_KEY","X-Api-Key":"Bearer ${env:MCP_KEY}"}}}}
CONFIG
rc=0
"$cli" agent-audit --home "$home" --json >"$TEST_TMP/placeholder.json" || rc=$?
[ "$rc" -eq 1 ]
jq -e 'any(.configurations[]; .client=="cursor" and .state=="parsed" and .declared.remote_servers==1 and (.declared.inline_credentials|not))' \
    "$TEST_TMP/placeholder.json" >/dev/null
printf '%s\n' '{"mcpServers":[]}' >"$project/.mcp.json"
rc=0
"$cli" agent-audit --home "$home" --project "$project" --json >"$TEST_TMP/unsupported.json" || rc=$?
[ "$rc" -eq 2 ]
jq -e '.coverage=="partial" and any(.configurations[]; .scope=="project" and .state=="unparsed")' "$TEST_TMP/unsupported.json" >/dev/null

catalogue=$ROOT_DIR/config/macos-updates.json
reviewed=$(jq -er .reviewed_at "$catalogue")
msu_branch_status 26.6.2 "$reviewed" "$catalogue" | jq -e '.status=="behind" and .branch=="26"' >/dev/null
msu_branch_status 27.10 "$reviewed" "$catalogue" | jq -e '.status=="at_or_above_reference"' >/dev/null
msu_branch_status 30.0 "$reviewed" "$catalogue" | jq -e '.status=="unlisted" and .reference==null' >/dev/null
msu_branch_status unknown "$reviewed" "$catalogue" | jq -e '.status=="unknown"' >/dev/null
msu_branch_status 27.2.1 2099-01-01 "$catalogue" | jq -e '.status=="stale"' >/dev/null
"$cli" updates status >"$TEST_TMP/updates.json"
jq -e '.software_update.state=="not_requested" and .background_security.pending_restart==null and
    (.background_security.installed_state|IN("unknown","supplement_reported"))' "$TEST_TMP/updates.json" >/dev/null
printf '%s\n' '{"schema":"macos-security-mscp-metadata/v1","release":"release_27.1","profile":"fixture","extra":"private-extra-label"}' >"$TEST_TMP/mscp.json"
"$cli" updates status --mscp-metadata "$TEST_TMP/mscp.json" | jq -e '.mscp=={release:"release_27.1",profile:"fixture",provenance:"user_supplied_metadata"}' >/dev/null
"$cli" doctor --json --profile developer >"$TEST_TMP/doctor.json"
jq -e '.profile=="developer" and .default_checks.full_disk_access.state=="unknown" and
    .default_checks.background_items.state=="not_requested" and .default_checks.network.state=="not_requested"' "$TEST_TMP/doctor.json" >/dev/null

mkdir -p "$TEST_TMP/suite/tools" "$TEST_TMP/suite/lib"
cp "$ROOT_DIR/tools/report-inventory.sh" "$TEST_TMP/suite/tools/"
cp "$ROOT_DIR/lib/macos_security_common.sh" "$ROOT_DIR/lib/macos_security_local.sh" "$TEST_TMP/suite/lib/"
root="$TEST_TMP/suite/audit-results"
old=2021-01-01T000000Z; incomplete=2022-01-01T000000Z; current=2023-01-01T000000Z
mkdir -p "$root/$old" "$root/$current" "$root/$incomplete"
for run in "$root/$old" "$root/$current" "$root/$incomplete"; do
    printf '%s\n' '{"complete":true}' >"$run/run-manifest.json"
    printf '%s\n' 'synthetic completion marker' >"$run/SHA256SUMS"
done
touch "$root/$incomplete/INCOMPLETE"
touch -t 202301010000 "$root/$old" "$root/$current" "$root/$incomplete"
ln -s "$current" "$root/latest"
ln -s "$root/$old" "$root/2020-01-01T000000Z"
"$TEST_TMP/suite/tools/report-inventory.sh" prune --plan --older-than 1 >"$TEST_TMP/retention.json"
jq -e --arg old "$old" '.mutates==false and .candidate_count==1 and (.reports|length)==3 and
    any(.reports[];.run_id==$old and .prune_candidate) and any(.reports[];.state=="incomplete" and (.prune_candidate|not))' "$TEST_TMP/retention.json" >/dev/null
[ -d "$root/$old" ] && [ -d "$root/$current" ]
for pair in repo-preflight:preflight agent-audit:audit update-status:updates doctor:doctor report-inventory:retention; do
    msc_schema_validate "$ROOT_DIR/schemas/${pair%:*}.schema.json" "$TEST_TMP/${pair#*:}.json" >/dev/null
done
printf '%s\n' 'PASS: local preflight, agent permission drift, update catalogue, doctor and retention plan'
