#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
export LC_ALL=C
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$root"
pinned=$(jq -r 'to_entries[] | [.value.repository,.value.tag] | join(" ")' .github/ci-tools.json)
printf '%s\n' 'Pinned command-line tools'
printf '%s\n' "$pinned" | while read -r upstream tag; do
    latest=$(gh api "repos/$upstream/releases/latest" --jq '.tag_name')
    printf '%s  pinned=%s  upstream=%s\n' "$upstream" "$tag" "$latest"
done

actions=$(sed -nE 's|^[[:space:]]*- uses: ([^/[:space:]]+/[^/@[:space:]]+)(/[^@[:space:]]+)?@[a-f0-9]{40}.*$|\1|p' .github/workflows/*.yml)
ci_upstreams=$(printf '%s\n' "$pinned" | cut -d ' ' -f 1)
upstreams=$(printf '%s\n' "$actions" "$ci_upstreams" \
    objective-see/KnockKnock VirusTotal/yara-x VirusTotal/yara Cisco-Talos/clamav \
    google/osv-scanner aquasecurity/trivy osquery/osquery northpolesec/santa | sort -u)
since=$(jq -nr '(now - (35 * 86400)) | strftime("%Y-%m-%d")')
printf '\n%s\n' 'Public upstream advisories updated within the last 35 days'
printf '%s\n' "$upstreams" | while read -r upstream; do
    [ -n "$upstream" ] || continue
    advisories=$(gh api --paginate "repos/$upstream/security-advisories?per_page=100&sort=updated&direction=desc" \
        --jq '.[] | [.ghsa_id,.updated_at] | @tsv')
    printf '%s\n' "$advisories" | awk -v upstream="$upstream" -v since="$since" '
        $2 >= since { print upstream, $1, "https://github.com/advisories/" $1 }
    '
done
