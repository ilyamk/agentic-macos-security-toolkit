# SPDX-License-Identifier: MIT
# Safe execution helpers for modular collectors and adapters.
# shellcheck disable=SC2034

if [ "${MSC_EXECUTION_LOADED:-0}" = "1" ]; then
    return 0
fi
MSC_EXECUTION_LOADED=1
MSC_EXECUTION_VERSION="4.0.0"

msc_executable_path() {
    _mse_name=$1
    command -v "$_mse_name" 2>/dev/null || return 1
}

msc_write_private_file() {
    _mse_file=$1
    /usr/bin/touch "$_mse_file" || return 1
    /bin/chmod 600 "$_mse_file" || return 1
}

msc_safe_component() {
    case ${1:-} in
        ''|*[!A-Za-z0-9._-]*) return 1 ;;
        *) return 0 ;;
    esac
}

msc_command_metadata() {
    _mse_id=$1
    _mse_path=$2
    _mse_version=${3:-unknown}
    jq -cn --arg id "$_mse_id" --arg path "$_mse_path" --arg version "$_mse_version" \
        '{id:$id,path:$path,version:$version}'
}
