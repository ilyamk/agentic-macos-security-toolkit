def array: if type=="array" then . else [] end;
def object: if type=="object" then . else {} end;
def reference_or_placeholder:
    sub("^(Bearer|Basic)[[:space:]]+"; ""; "i") |
    test("^\\$\\{(env:)?[A-Za-z_][A-Za-z0-9_]*\\}$") or
    test("^(YOUR|REPLACE_WITH|INSERT|PASTE)[_-][A-Z0-9_-]+$");
def inline_secret:
    to_entries | any((.key | test("token|secret|password|api.*key|authorization|credential";"i")) and
        (.value | type=="string" and length>0 and (reference_or_placeholder|not)));
def path_flag:
    if type=="object" then (.path // .uri) else . end |
    type=="string" and (sub("^file://";"") |
        test("^(/|~|\\$HOME|\\$\\{HOME\\}|\\.\\.|/Users(/[^/]+)?|/Volumes)(/?$|/\\.\\.([/]|$))"));
def server_broad_path:
    (([.roots,.allowedPaths,.allowedDirectories] | map(array) | add) | any(path_flag)) or
    ((.args|array|any(type=="string" and contains("server-filesystem"))) and (.args|array|any(path_flag)));

select(length==1 and (.[0]|type)=="object") | .[0] |
if $registered_project!="" then
    if (.projects|type|IN("object","null")) then .projects[$registered_project]
    else error("Invalid Claude project map") end
else . end |
if .==null then {state:"absent",client:$client,scope:$scope,component:$component,declared:null}
else
select(type=="object" and ([.mcpServers,.servers]|all(type|IN("object","null")))) |
. as $settings |
((.mcpServers // .servers // {}) | object | [.[] | objects]) as $servers |
((.permissions.allow? // []) | array) as $allow |
{
  state:"parsed", client:$client, scope:$scope, component:$component,
  declared:{
    unrestricted_sandbox: (($settings.sandbox.mode // $settings.sandboxMode) | IN("danger-full-access","off")),
    automatic_approval: (
        (($settings.approval_policy // $settings.approvalMode) | IN("never","bypassPermissions")) or
        (($settings.permissions.defaultMode // "") | IN("bypassPermissions","dontAsk","auto")) or
        ($allow|any(type=="string" and test("^(Bash|Shell|Write|Edit|Read|mcp__\\*|\\*)($|\\(\\*\\)$)";"i")))
    ),
    broad_roots: (
        (([$settings.allowedPaths?, $settings.additionalDirectories?, $settings.permissions.additionalDirectories?, $settings.sandbox.writableRoots?] |
            map(array) | add) | any(path_flag)) or ($servers|any(server_broad_path))
    ),
    local_servers: ([$servers[] | select(.command|type=="string" and length>0)]|length),
    remote_servers: ([$servers[] | select(.url|type=="string" and length>0)]|length),
    cleartext_http: ($servers | any(.url|type=="string" and test("^http://";"i"))),
    inline_credentials: (($settings.env|object|inline_secret) or
        ($servers|any((.env|object|inline_secret) or (.headers|object|inline_secret) or
            (.url|type=="string" and test("://[^/?#]*@|[?&](token|key|secret|password)=";"i"))))),
    declared_oauth_scopes: ([$servers[] |
        (.oauth.scopes // .oauth.scope // .scopes // .scope // []) |
        if type=="array" then map(strings)|length elif type=="string" then [scan("[^[:space:]]+")]|length else 0 end] | add // 0)
  }
}
end
