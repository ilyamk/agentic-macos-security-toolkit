#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
[ "$#" -ge 2 ] || { printf 'Usage: %s NEW_BIN_DIR TOOL...\n' "$0" >&2; exit 2; }
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
destination=$1
shift
platform="$(uname -s)-$(uname -m)"
manifest=$root/.github/ci-tools.json
jq_path=$(command -v jq)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -- "$destination"
for tool do
    case $tool in jq|shellcheck|gitleaks|actionlint|zizmor) ;; *) exit 2 ;; esac
    # shellcheck disable=SC2016
    entry=$("$jq_path" -cer --arg tool "$tool" --arg platform "$platform" '
      .[$tool] as $tool | $tool.assets[$platform] as $asset |
      if $asset == null then error("Unsupported tool or platform")
      else {url:("https://github.com/"+$tool.repository+"/releases/download/"+$tool.tag+"/"+$asset[0]),
            sha:$asset[1], member:($tool.member // "")} end' "$manifest")
    url=$(printf '%s\n' "$entry" | "$jq_path" -er .url)
    sha=$(printf '%s\n' "$entry" | "$jq_path" -er '.sha | select(test("^[0-9a-f]{64}$"))')
    member=$(printf '%s\n' "$entry" | "$jq_path" -er .member)
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 180 --retry 2 --output "$tmp/asset" "$url"
    printf '%s  %s\n' "$sha" "$tmp/asset" | shasum --algorithm 256 --check --status
    if [ -n "$member" ]; then
        tar -xOzf "$tmp/asset" -- "$member" >"$tmp/$tool"
    else
        mv "$tmp/asset" "$tmp/$tool"
    fi
    [ -s "$tmp/$tool" ]
    chmod 700 "$tmp/$tool"
    mv "$tmp/$tool" "$destination/$tool"
done
