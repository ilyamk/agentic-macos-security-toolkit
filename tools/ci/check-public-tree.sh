#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
export LC_ALL=C
details=0
if [ "${1:-}" = --details ]; then details=1; shift; fi
if [ "$#" -ne 1 ]; then
    printf 'Usage: %s [--details] GIT_REVISION\n' "$0" >&2
    exit 2
fi
tree=$(git rev-parse --verify --end-of-options "$1^{tree}")
entries=$(git ls-tree -r "$tree")
printf '%s\n' "$entries" | awk -F '\t' -v details="$details" '
    $0 == "" { next }
    {
        path = $2
        name = path
        sub(/^.*\//, "", name)
        if (NF != 2 || $1 !~ /^100(644|755) blob / ||
            path !~ /^[a-zA-Z0-9._\/-]+$/ ||
            path ~ /(^|\/)(audit-results|monitoring-results|remediation-results|security-results|private-notes|\.codegraph)(\/|$)/ ||
            path ~ /(^|\/)(run-manifest\.json|agent-context\.json|posture\.jsonl|SHA256SUMS|\.DS_Store|\.envrc|\.netrc|id_rsa|id_ed25519)$/ ||
            path ~ /\.(key|pem|p12|pfx|sqlite3?|db|mobileprovision|log)$/ ||
            (name ~ /^\.env(\.|$)/ && name != ".env.example") ||
            (name ~ /^(report(-redacted)?|mac-security-report)\.jsonl$/ && path !~ /^tests\/(fixtures|golden)\//)) {
            if (details) print "Blocked publication path or file type: " path
            failed++
        }
    }
    END {
        if (failed && !details) print "Publication blocked by file path or type. Run with --details in a private terminal."
        exit failed ? 1 : 0
    }
'
