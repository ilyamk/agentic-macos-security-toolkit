#!/bin/sh
# SPDX-License-Identifier: MIT
# Install user-level helper tools (currently tools/brewup/brewup) into
# ${BREWUP_INSTALL_DIR:-$HOME/.local/bin}. Prints a plan by default and changes nothing;
# --apply performs it. Never uses sudo, never edits shell rc files and never
# installs packages.

set -u
SCRIPT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
TOOLS="brewup/brewup"
APPLY=0 SELF_TEST=0
PREFIX_DIR=${BREWUP_INSTALL_DIR:-$HOME/.local/bin}

usage() {
    /bin/cat <<'EOF'
Usage: tools/install-user-tools.sh [--apply] [--prefix DIR]
       tools/install-user-tools.sh --self-test
  (default)     print the installation plan; change nothing
  --apply       copy the tools into the prefix (existing different files are
                backed up to <file>.bak-<UTC timestamp> first)
  --prefix DIR  bin directory to install into (default $BREWUP_INSTALL_DIR
                or ~/.local/bin)
  --self-test   check the bundled tools without installing anything
EOF
}
die_usage() { printf '%s: %s\n' "${0##*/}" "$1" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
    case $1 in
        --apply) APPLY=1 ;;
        --prefix) [ "$#" -ge 2 ] && [ -n "$2" ] || die_usage "--prefix needs a directory"; PREFIX_DIR=$2; shift ;;
        --prefix=*) PREFIX_DIR=${1#--prefix=}; [ -n "$PREFIX_DIR" ] || die_usage "--prefix needs a directory" ;;
        --self-test) SELF_TEST=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die_usage "unknown argument: $1" ;;
    esac
    shift
done

if [ "$SELF_TEST" -eq 1 ]; then
    failed=''
    for t in $TOOLS; do
        src=$SCRIPT_DIR/$t
        if [ ! -x "$src" ] || ! /bin/sh -n "$src" 2>/dev/null || ! "$src" -h >/dev/null 2>&1; then
            failed="$failed${failed:+,}\"${t##*/}\""
        fi
    done
    if [ -n "$failed" ]; then
        printf '%s\n' "{\"schema\":\"macos-security-user-tools/v1\",\"record_type\":\"self_test\",\"status\":\"fail\",\"failed\":[$failed]}"
        exit 2
    fi
    printf '%s\n' '{"schema":"macos-security-user-tools/v1","record_type":"self_test","status":"pass","checks":["brewup"]}'
    exit 0
fi

[ "$(/usr/bin/id -u)" -ne 0 ] || die_usage "refusing to run as root; this installs per-user tools"
case $PREFIX_DIR in
    /*) ;;
    *) die_usage "--prefix must be an absolute path: $PREFIX_DIR" ;;
esac
PREFIX_DIR=${PREFIX_DIR%/}
STAMP=$(/bin/date -u '+%Y%m%dT%H%M%SZ')

on_path=0
_old_ifs=$IFS; IFS=:
for p in $PATH; do
    [ "${p%/}" != "$PREFIX_DIR" ] || on_path=1
done
IFS=$_old_ifs

[ "$APPLY" -eq 1 ] || printf '%s\n' "Plan (nothing changed; re-run with --apply):"
[ -d "$PREFIX_DIR" ] || {
    printf '  create directory %s\n' "$PREFIX_DIR"
    if [ "$APPLY" -eq 1 ]; then /bin/mkdir -p "$PREFIX_DIR" || exit 1; fi
}

rc=0
for t in $TOOLS; do
    src=$SCRIPT_DIR/$t
    dst=$PREFIX_DIR/${t##*/}
    [ -r "$src" ] || { printf 'missing source: %s\n' "$src" >&2; rc=1; continue; }
    if [ -e "$dst" ] && /usr/bin/cmp -s "$src" "$dst"; then
        printf '  %s: already installed and identical\n' "$dst"
        continue
    fi
    if [ -e "$dst" ]; then
        printf '  back up %s to %s.bak-%s\n' "$dst" "$dst" "$STAMP"
        if [ "$APPLY" -eq 1 ]; then /bin/cp -p "$dst" "$dst.bak-$STAMP" || { rc=1; continue; }; fi
    fi
    printf '  install %s -> %s (mode 755)\n' "$src" "$dst"
    if [ "$APPLY" -eq 1 ]; then
        tmp=$(/usr/bin/mktemp "$dst.XXXXXX") || { rc=1; continue; }
        if /bin/cp "$src" "$tmp" && /bin/chmod 755 "$tmp" && /bin/mv -f "$tmp" "$dst"; then
            :
        else
            /bin/rm -f "$tmp"; rc=1
        fi
    fi
done

if [ "$on_path" -eq 0 ]; then
    printf 'warning: %s is not on PATH; add it in your shell configuration yourself.\n' "$PREFIX_DIR" >&2
fi
exit "$rc"
