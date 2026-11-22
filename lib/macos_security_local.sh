# SPDX-License-Identifier: MIT

# The inspected repository can be the working directory. Use macOS and
# standard Homebrew executable locations for these inspection commands.
msl_use_review_path() {
    PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin
    export PATH
}

# Return 1 for missing input and 2 for unsafe, unreadable or oversized input.
msl_bounded_file() (
    [ ! -L "$1" ] || exit 2
    [ -e "$1" ] || exit 1
    [ -f "$1" ] && [ -r "$1" ] || exit 2
    _msl_bytes=$(/usr/bin/stat -f '%z' "$1" 2>/dev/null) || exit 2
    [ "$_msl_bytes" -le "$2" ] || exit 2
)

msl_directory() (
    [ -n "$1" ] || exit 2
    case $1 in /*) _msl_path=$1 ;; *) _msl_path=./$1 ;; esac
    CDPATH='' cd -P -- "$_msl_path" || exit 2
    case $PWD in *[[:cntrl:]]*) exit 2 ;; esac
    printf '%s\n' "$PWD"
)

msl_explicit_file() (
    case $1 in /*) _msl_file=$1 ;; *) _msl_file=$PWD/$1 ;; esac
    case $_msl_file in *[[:cntrl:]]*) exit 2 ;; esac
    msl_bounded_file "$_msl_file" "$2" || exit $?
    printf '%s\n' "$_msl_file"
)

# Resolve fixed paths beneath an explicitly selected directory without following
# symlinked files or ancestors. The directory itself is already canonical.
msl_scoped_file() (
    _msl_path="$1/$2"
    _msl_parent=${_msl_path%/*}
    while [ "$_msl_parent" != "$1" ]; do
        [ ! -L "$_msl_parent" ] || exit 2
        _msl_parent=${_msl_parent%/*}
    done
    msl_bounded_file "$_msl_path" "$3"
)

# Validate a whole assessment and pin the selected inputs to its checksum file.
# Only bounded regular files are copied to the caller's private scratch directory.
msl_snapshot_assessment() (
    _msl_root=$1; _msl_report=$2; _msl_stage=$3; shift 3
    msl_scoped_file "$_msl_report" SHA256SUMS 4194304 || exit 2
    /bin/cp "$_msl_report/SHA256SUMS" "$_msl_stage/SHA256SUMS" || exit 2
    for _msl_item do
        msl_scoped_file "$_msl_report" "$_msl_item" 4194304 || exit 2
        /bin/cp "$_msl_report/$_msl_item" "$_msl_stage/$_msl_item" || exit 2
        _msl_hash=$(msc_sha256_file "$_msl_stage/$_msl_item") || exit 2
        /usr/bin/awk -v wanted="./$_msl_item" -v hash="$_msl_hash" '
            $2 == wanted { n++; if ($1==hash && length(hash)==64) correct++ }
            END { exit !(n==1 && correct==1) }
        ' "$_msl_stage/SHA256SUMS" || exit 2
    done
    msc_run_timed_capture 60 /dev/null /dev/null "$_msl_stage/.validation.timeout" \
        "$_msl_root/validate-macos-security-report.sh" "$_msl_report" || exit 2
    /usr/bin/cmp -s "$_msl_stage/SHA256SUMS" "$_msl_report/SHA256SUMS" || exit 2
)
