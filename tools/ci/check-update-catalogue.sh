#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
today=$(date -u +%F)
catalogue=$root/config/macos-updates.json
jq -e --arg today "$today" '.reviewed_at<=$today and .valid_until>=$today' "$catalogue" >/dev/null || {
    printf '%s\n' 'The pinned macOS security catalogue needs review.' >&2
    exit 1
}

# The Apple update feed uses Apple Root CA, which is absent from some runner trust stores.
umask 077
cert_dir=$(mktemp -d)
trap 'rm -f "$cert_dir/root.cer" "$cert_dir/root.pem"; rmdir "$cert_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/curl -q --fail --silent --show-error --proto '=https' --connect-timeout 10 \
    --max-time 30 --max-filesize 8192 --output "$cert_dir/root.cer" \
    https://www.apple.com/appleca/AppleIncRootCertificate.cer
printf '%s  %s\n' b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024 \
    "$cert_dir/root.cer" | shasum --algorithm 256 --check --status
/usr/bin/openssl x509 -inform DER -in "$cert_dir/root.cer" -out "$cert_dir/root.pem"

feed=$(/usr/bin/curl -q --fail --silent --show-error --proto '=https' --cacert "$cert_dir/root.pem" --connect-timeout 10 \
    --max-time 30 --max-filesize 2097152 https://gdmf.apple.com/v2/pmv)
result=$(printf '%s\n' "$feed" | jq -ces --slurpfile catalogue "$catalogue" --arg today "$today" '
    def parts: (split(".")|map(tonumber)) + [0,0] | .[0:3];
    select(length==1 and (.[0].PublicAssetSets.macOS|type)=="array") |
    .[0].PublicAssetSets.macOS as $assets |
    [$catalogue[0].branches | to_entries[] as $branch |
     ($branch.value.version|parts) as $base |
     [$assets[] | select(.ExpirationDate==null or .ExpirationDate>=$today) |
      .ProductVersion | strings | select(test("^[0-9]{1,3}(\\.[0-9]{1,3}){0,2}$")) |
      select(split(".")[0]==$branch.key and (parts)>$base)] |
     if length>0 then {branch:$branch.key,reviewed:$branch.value.version,offered:(max_by(parts))} else empty end]
')
if [ "$result" != '[]' ]; then
    printf '%s\n' 'Apple advertises a newer public asset. Review its security bulletin and catalogue entry.'
    printf '%s\n' "$result" | jq .
else
    printf '%s\n' 'No newer public asset was found for the pinned branches.'
fi
