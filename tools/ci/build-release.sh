#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
[ "$#" -eq 2 ] || { printf 'Usage: %s VERSION_TAG NEW_OUTPUT_DIR\n' "$0" >&2; exit 2; }
tag=$1
printf '%s\n' "$tag" | grep -Exq 'v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?' || {
    printf 'Expected a version tag such as v1.0.0.\n' >&2
    exit 2
}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$root"
commit=$(git rev-parse --verify "refs/tags/$tag^{commit}")
"$root/tools/ci/check-public-tree.sh" "$commit"
name=agentic-macos-security-toolkit-$tag
mkdir -- "$2"
output=$(CDPATH='' cd -- "$2" && pwd -P)
git -c tar.umask=0022 archive --format=tar.gz -9 --prefix="$name/" \
    --output="$output/$name.tar.gz" "$commit"
(cd "$output" && shasum --algorithm 256 "$name.tar.gz" >"$name.tar.gz.sha256")
