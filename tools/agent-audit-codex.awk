function value() {
    v=$0
    sub(/^[^=]*=[[:space:]]*/, "", v)
    sub(/[[:space:]]+#.*$/, "", v)
    sub(/[[:space:]]+$/, "", v)
    return v
}
function flag(v) { return v ? "true" : "false" }
BEGIN { section="root" }
/^[[:space:]]*\[/ {
    section="other"
    if ($0 ~ /^[[:space:]]*\[mcp_servers\./) {
        section="server"
        if ($0 ~ /\.(env|http_headers)\][[:space:]]*(#.*)?$/) section="secrets"
    }
    if ($0 ~ /^[[:space:]]*\[sandbox_workspace_write\]/) section="sandbox"
}
/^[[:space:]]*sandbox_mode[[:space:]]*=/ && section=="root" {
    full_access=(value() ~ /^["\047]danger-full-access["\047]$/)
}
/^[[:space:]]*approval_policy[[:space:]]*=/ && section=="root" {
    never=(value() ~ /^["\047]never["\047]$/)
}
/^[[:space:]]*writable_roots[[:space:]]*=/ && section=="sandbox" {
    if ($0 ~ /["\047](\/|~|\$HOME|\.\.\/?)(["\047]|\/\.\.)/) broad=1
}
/^[[:space:]]*command[[:space:]]*=/ && section=="server" { local_count++ }
/^[[:space:]]*url[[:space:]]*=/ && section=="server" {
    remote_count++
    if (tolower(value()) ~ /^["\047]http:\/\//) http=1
    if (tolower(value()) ~ /:\/\/[^\/?#]*@|[?&](token|key|secret|password)=/) secret=1
}
/^[[:space:]]*(http_headers|env)[[:space:]]*=[[:space:]]*\{/ && section=="server" {
    if (tolower(value()) ~ /(token|secret|password|api[^=]*key|authorization|credential)["\047]?[[:space:]]*=/) secret=1
}
/^[[:space:]]*[^#=]+=/ && section=="secrets" {
    key=tolower($0); sub(/=.*/, "", key)
    if (key ~ /token|secret|password|api.*key|authorization|credential/ &&
        value() !~ /^["\047]\$\{(env:)?[A-Za-z_][A-Za-z0-9_]*\}["\047]$/) secret=1
}
END {
    printf "{\"unrestricted_sandbox\":%s,\"automatic_approval\":%s,\"broad_roots\":%s,", flag(full_access),flag(never),flag(broad)
    printf "\"local_servers\":%d,\"remote_servers\":%d,\"cleartext_http\":%s,", local_count,remote_count,flag(http)
    printf "\"inline_credentials\":%s,\"declared_oauth_scopes\":null}\n", flag(secret)
}
