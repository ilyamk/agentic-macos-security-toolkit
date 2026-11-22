# SPDX-License-Identifier: MIT

msu_branch_status() {
    jq -ces --arg version "$1" --arg checked "$2" '
        def version_ok: type=="string" and test("^[0-9]{1,3}(\\.[0-9]{1,3}){0,2}$");
        def parts: (split(".")|map(tonumber)) + [0,0] | .[0:3];
        def day: type=="string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$");
        select(length==1 and (.[0]|type)=="object") | .[0] |
        if .schema!="macos-security-update-catalogue/v1" or (.branches|type)!="object" or
            (.reviewed_at|day|not) or (.valid_until|day|not) or .valid_until<.reviewed_at or
            any(.branches|to_entries[]; (.value.version|version_ok|not) or
                ((.value.version|split(".")[0])!=.key) or (.value.released_at|day|not) or
                (.value.source|type!="string" or (test("^https://support\\.apple\\.com/")|not)))
        then error("Invalid macOS update catalogue") else . end |
        (if $version|version_ok then ($version|split(".")[0]) else null end) as $branch |
        (.branches[$branch // ""] // null) as $ref |
        {installed_version:$version,branch:$branch,reference:$ref,reviewed_at,valid_until,index,
         status:(if $checked<.reviewed_at or $checked>.valid_until then "stale"
            elif $branch==null then "unknown"
            elif $ref==null then "unlisted"
            elif ($version|parts)<($ref.version|parts) then "behind"
            else "at_or_above_reference" end)}
    ' "$3"
}
