#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
git rev-parse --verify HEAD >/dev/null
scan=$(mktemp -d)
trap 'rm -rf "$scan"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
printf '%s\n' '[extend]' 'useDefault = true' >"$scan/config.toml"
: >"$scan/.gitleaksignore"
if ! gitleaks git --redact=100 --no-banner --config "$scan/config.toml" \
    --ignore-gitleaks-allow --gitleaks-ignore-path "$scan/.gitleaksignore" \
    --log-opts="--all HEAD" . >"$scan/log" 2>&1; then
    if [ "${1:-}" = --details ]; then
        cat "$scan/log" >&2
    else
        printf '%s\n' 'Secret scan failed. Rerun with --details in a private terminal.' >&2
    fi
    exit 1
fi
printf '%s\n' 'Git secret scan passed.'
