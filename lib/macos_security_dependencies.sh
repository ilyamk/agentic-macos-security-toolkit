# SPDX-License-Identifier: MIT
# Homebrew-backed dependency manager. Only the static allow-list below can be
# installed. Homebrew itself is never bootstrapped through a downloaded script.
# shellcheck disable=SC2034

if [ "${MSC_DEPENDENCIES_LOADED:-0}" = "1" ]; then
    return 0
fi
MSC_DEPENDENCIES_LOADED=1
MSC_DEPENDENCIES_VERSION="4.0.0"
MSC_AUTO_INSTALL=${MSC_AUTO_INSTALL:-0}
MSC_ALLOW_NETWORK=${MSC_ALLOW_NETWORK:-0}
MSC_ALLOW_CASKS=${MSC_ALLOW_CASKS:-0}

msd_spec() {
    case $1 in
        knockknock) printf '%s\n' 'cask|knockknock|/Applications/KnockKnock.app/Contents/MacOS/KnockKnock' ;;
        yara-x) printf '%s\n' 'formula|yara-x|yr' ;;
        yara) printf '%s\n' 'formula|yara|yara' ;;
        clamav) printf '%s\n' 'formula|clamav|clamscan' ;;
        osv-scanner) printf '%s\n' 'formula|osv-scanner|osv-scanner' ;;
        trivy) printf '%s\n' 'formula|trivy|trivy' ;;
        gitleaks) printf '%s\n' 'formula|gitleaks|gitleaks' ;;
        osquery) printf '%s\n' 'cask|osquery|/opt/osquery/bin/osqueryi' ;;
        santa) printf '%s\n' 'cask|santa|santactl' ;;
        jq) printf '%s\n' 'formula|jq|jq' ;;
        shellcheck) printf '%s\n' 'formula|shellcheck|shellcheck' ;;
        *) return 64 ;;
    esac
}

msd_resolve_path() {
    [ "$(/usr/bin/id -u)" -ne 0 ] || return 77
    _msd_id=$1
    _msd_spec=$(msd_spec "$_msd_id") || return 64
    _msd_locator=${_msd_spec##*|}
    case $_msd_locator in
        /*) [ -x "$_msd_locator" ] && printf '%s\n' "$_msd_locator" ;;
        *) command -v "$_msd_locator" 2>/dev/null ;;
    esac
}

msd_brew_path() {
    [ "$(/usr/bin/id -u)" -ne 0 ] || return 77
    command -v brew 2>/dev/null && return 0
    [ -x /opt/homebrew/bin/brew ] && { printf '%s\n' /opt/homebrew/bin/brew; return 0; }
    [ -x /usr/local/bin/brew ] && { printf '%s\n' /usr/local/bin/brew; return 0; }
    return 1
}

msd_load_policy() {
    _msd_policy=$1
    MSC_POLICY_NETWORK=$(jq -er 'if .dependency_policy.allow_network==true then 1 else 0 end' "$_msd_policy") || return 2
    MSC_ALLOW_CASKS=$(jq -er 'if .dependency_policy.allow_casks==true then 1 else 0 end' "$_msd_policy") || return 2
    MSC_POLICY_AUTO_INSTALL=$(jq -er 'if .dependency_policy.auto_install==true then 1 else 0 end' "$_msd_policy") || return 2
}

# Homebrew loads brew.env files after the process environment.
msd_check_brew_config() (
    _msd_config_home=${XDG_CONFIG_HOME:-${HOMEBREW_XDG_CONFIG_HOME:-}}
    if [ -n "$_msd_config_home" ]; then
        _msd_user_env="$_msd_config_home/homebrew/brew.env"
    else
        _msd_user_env="$HOME/.homebrew/brew.env"
    fi
    for _msd_env in /etc/homebrew/brew.env "$1/etc/homebrew/brew.env" "$_msd_user_env"; do
        [ -e "$_msd_env" ] || continue
        [ -f "$_msd_env" ] && [ -r "$_msd_env" ] || exit 1
        /usr/bin/awk -F= '
            {
                sub(/^[ \t]+/, "")
                sub(/[ \t]+$/, "")
                value = tolower(substr($0, index($0, "=")+1))
                if (($1 == "HOMEBREW_NO_VERIFY_ATTESTATIONS" && value != "") ||
                    ($1 == "HOMEBREW_VERIFY_ATTESTATIONS" && value == "") ||
                    ($1 == "HOMEBREW_NO_INSECURE_REDIRECT" && value ~ /^(false|no|off|nil|0)?$/)) exit 1
            }
        ' "$_msd_env" || exit 1
    done
)

msd_ensure() (
    _msd_id=$1; _msd_log=$2
    [ "$(/usr/bin/id -u)" -ne 0 ] || exit 77
    _msd_spec=$(msd_spec "$_msd_id") || exit 64
    if _msd_existing=$(msd_resolve_path "$_msd_id"); then
        printf '%s\n' "$_msd_existing"
        exit 0
    fi
    [ "$MSC_AUTO_INSTALL" = "1" ] && [ "$MSC_ALLOW_NETWORK" = "1" ] || exit 69
    _msd_type=${_msd_spec%%|*}; _msd_rest=${_msd_spec#*|}; _msd_package=${_msd_rest%%|*}
    case $_msd_type in
        formula) set -- install --formula --force-bottle "homebrew/core/$_msd_package" ;;
        cask) [ "$MSC_ALLOW_CASKS" = "1" ] || exit 69; set -- install --cask --require-sha "homebrew/cask/$_msd_package" ;;
        *) exit 64 ;;
    esac
    _msd_brew=$(msd_brew_path) || exit 69
    printf 'Installing allow-listed dependency %s (%s %s)\n' "$_msd_id" "$_msd_type" "$_msd_package" >>"$_msd_log" || exit 73
    _msd_tmp=$(msc_mktemp_dir macos-security-install) || exit 73
    trap '/bin/rm -f "$_msd_tmp/install.log" "$_msd_tmp/install.log.stderr.$$" "$_msd_tmp/install.log.timeout.$$" "$_msd_tmp/prefix" "$_msd_tmp/prefix.timeout"; /bin/rmdir "$_msd_tmp"' EXIT
    export HOMEBREW_VERIFY_ATTESTATIONS=1 HOMEBREW_NO_VERIFY_ATTESTATIONS=''
    export HOMEBREW_NO_INSECURE_REDIRECT=1 HOMEBREW_NO_INSTALL_CLEANUP=1
    export HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 HOMEBREW_NO_ANALYTICS=1
    msc_run_timed_capture 10 "$_msd_tmp/prefix" /dev/null "$_msd_tmp/prefix.timeout" "$_msd_brew" --prefix || exit 69
    _msd_prefix=$(/bin/cat "$_msd_tmp/prefix")
    case $_msd_prefix in /*) [ -d "$_msd_prefix" ] || exit 69 ;; *) exit 69 ;; esac
    if ! msd_check_brew_config "$_msd_prefix"; then
        printf '%s\n' 'Homebrew configuration may disable attestation verification or secure redirects. Review brew.env before installing.' >>"$_msd_log"
        exit 69
    fi
    _msd_rc=0
    msc_run_with_timeout 300 "$_msd_tmp/install.log" "$_msd_brew" "$@" || _msd_rc=$?
    /bin/cat "$_msd_tmp/install.log" >>"$_msd_log" || exit 73
    [ "$_msd_rc" -eq 0 ] || exit "$_msd_rc"
    msd_resolve_path "$_msd_id"
)

msd_version() (
    [ "$(/usr/bin/id -u)" -ne 0 ] || exit 77
    _msd_id=$1; _msd_path=$2
    _msd_tmp=$(msc_mktemp_dir macos-security-version) || exit 73
    trap '/bin/rm -f "$_msd_tmp/version" "$_msd_tmp/timeout"; /bin/rmdir "$_msd_tmp"' EXIT
    case $_msd_id in
        knockknock) set -- -version ;;
        santa) set -- version ;;
        *) set -- --version ;;
    esac
    msc_run_timed_capture 10 "$_msd_tmp/version" /dev/null "$_msd_tmp/timeout" "$_msd_path" "$@" || exit $?
    /usr/bin/head -n 1 "$_msd_tmp/version"
)

msd_inventory_json() {
    _msd_id=$1
    _msd_spec=$(msd_spec "$_msd_id") || return 64
    _msd_type=${_msd_spec%%|*}; _msd_rest=${_msd_spec#*|}; _msd_package=${_msd_rest%%|*}
    if _msd_path=$(msd_resolve_path "$_msd_id"); then
        _msd_version=$(msd_version "$_msd_id" "$_msd_path")
        jq -cn --arg id "$_msd_id" --arg type "$_msd_type" --arg package "$_msd_package" --arg path "$_msd_path" --arg version "${_msd_version:-unknown}" '{id:$id,install_type:$type,package:$package,installed:true,path:$path,version:$version}'
    else
        jq -cn --arg id "$_msd_id" --arg type "$_msd_type" --arg package "$_msd_package" '{id:$id,install_type:$type,package:$package,installed:false,path:null,version:null}'
    fi
}
