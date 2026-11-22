#!/bin/sh
# SPDX-License-Identifier: MIT
# Workstation supply-chain and agent-hygiene audit.
# Strictly read-only: it reads configuration files and runs a fixed set of
# inspection commands (brew --version/tap/config/developer/info, gh auth
# status, systemextensionsctl list, ps, sqlite3 -readonly). It never installs,
# upgrades, untaps or changes anything, and never prints secret values.

set -u
umask 077
SCRIPT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"

WA_SCHEMA="macos-security-workstation-audit/v1"
# Node.js majors that are end-of-life as of 2026-11 (all odd majors, and even
# majors up to 20). Review when Node 22 reaches end-of-life in April 2027.
NODE_EOL_MAJORS="0 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 23 25"
# Bundle IDs of terminals and AI-agent apps whose Full Disk Access is inherited
# by every command (and agent) they start.
TCC_TERMINAL_CLIENTS="com.apple.Terminal com.googlecode.iterm2 com.mitchellh.ghostty dev.warp.Warp-Stable dev.warp.Warp net.kovidgoyal.kitty io.alacritty org.alacritty com.github.wez.wezterm co.zeit.hyper com.microsoft.VSCode com.microsoft.VSCodeInsiders com.vscodium com.anthropic.claude-code com.anthropic.claudefordesktop com.openai.codex com.openai.chat com.exafunction.windsurf dev.zed.Zed com.google.antigravity"

export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1

usage() {
    cat <<'EOF'
Usage: workstation-audit.sh [options]

Read-only audit of package-manager supply-chain settings, JavaScript runtime
hygiene, infostealer defences and AI-agent configuration on this Mac.

Options:
  --json             JSONL output, one record per check
  --home DIR         Home directory to inspect (default $HOME)
  --brew PATH        Homebrew executable (default: brew on PATH, then /opt/homebrew/bin/brew)
  --only PREFIX      Only checks whose ID starts with PREFIX (e.g. HB, NPM, AGENT-01)
  --apps DIR         Applications directory (default /Applications); also skips
                     the live systemextensionsctl and ps checks (fixture mode)
  --tcc-db PATH      TCC database to read (default: the system TCC.db)
  --system-brew-env PATH
                     System brew.env (default /etc/homebrew/brew.env; for tests)
  --self-test        Test internal helpers without inspecting the machine
  -h, --help         Show this help

Exit codes: 0 no warn/fail, 1 at least one warn or fail, 2 usage or dependency error.
EOF
}

OUTPUT=text
HOME_DIR=${HOME:-}
BREW=''
ONLY=''
APPS_DIR=/Applications
FIXTURE=0
TCC_DB="/Library/Application Support/com.apple.TCC/TCC.db"
SYSTEM_BREW_ENV=/etc/homebrew/brew.env
SELF_TEST=0

need_value() { [ "$2" -ge 2 ] || { printf 'Option %s needs a value\n' "$1" >&2; exit 2; }; }
while [ "$#" -gt 0 ]; do
    case $1 in
        --json) OUTPUT=json ;;
        --home) need_value "$1" "$#"; HOME_DIR=$2; shift ;;
        --brew) need_value "$1" "$#"; BREW=$2; shift ;;
        --only) need_value "$1" "$#"; ONLY=$2; shift ;;
        --apps) need_value "$1" "$#"; APPS_DIR=$2; FIXTURE=1; shift ;;
        --tcc-db) need_value "$1" "$#"; TCC_DB=$2; shift ;;
        --system-brew-env) need_value "$1" "$#"; SYSTEM_BREW_ENV=$2; shift ;;
        --self-test) SELF_TEST=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

[ "$(/usr/bin/id -u)" -ne 0 ] || { printf '%s\n' 'Run workstation-audit without sudo.' >&2; exit 2; }
msc_require_jq || exit 2
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || { printf 'Home directory is unavailable: %s\n' "$HOME_DIR" >&2; exit 2; }
HOME_DIR=$(CDPATH='' cd -- "$HOME_DIR" && /bin/pwd -P) || exit 2
case $ONLY in *[!A-Za-z0-9-]*) printf 'Invalid --only prefix: %s\n' "$ONLY" >&2; exit 2 ;; esac

TMP_DIR=$(msc_mktemp_dir workstation-audit) || { printf '%s\n' 'Cannot create a temporary directory.' >&2; exit 2; }
# Invoked by the EXIT trap.
# shellcheck disable=SC2329
wa_cleanup() { /bin/rm -rf "$TMP_DIR"; }
trap wa_cleanup EXIT
trap 'exit 130' HUP INT TERM
RECORDS="$TMP_DIR/records.jsonl"
: >"$RECORDS"

# ---------------------------------------------------------------- helpers

# Registry metadata: playbook|attack IDs|title|remediation.
wa_meta() {
    case $1 in
        HB-01) printf '%s' 'PB-01|ATK-10|brew.env HOMEBREW_VERIFY_ATTESTATIONS|Add HOMEBREW_VERIFY_ATTESTATIONS=1 to the user brew.env (PB-01).' ;;
        HB-02) printf '%s' 'PB-01|ATK-10|brew.env HOMEBREW_CASK_OPTS --require-sha|Add HOMEBREW_CASK_OPTS=--require-sha to the user brew.env (PB-01).' ;;
        HB-03) printf '%s' 'PB-01|ATK-10|brew.env HOMEBREW_NO_INSECURE_REDIRECT|Add HOMEBREW_NO_INSECURE_REDIRECT=1 to the user brew.env (PB-01).' ;;
        HB-04) printf '%s' 'PB-01|ATK-10|gh for attestation verification|Install gh and run gh auth login so brew can verify attestations (PB-01).' ;;
        HB-05) printf '%s' 'PB-01|ATK-09|Whole-tap trust in trust.json|Replace trustedtaps entries with per-formula or per-cask trust (PB-01).' ;;
        HB-06) printf '%s' 'PB-01|ATK-09|Unused third-party taps|Review and untap unused taps by hand; mind the untap pitfalls in PB-01.' ;;
        HB-07) printf '%s' 'PB-01|ATK-09|Packages from third-party taps|Keep only taps you trust; prefer homebrew/core or homebrew/cask equivalents (PB-01).' ;;
        HB-08) printf '%s' 'PB-01|ATK-10|Casks without a checksum|Replace or verify casks without a checksum; HOMEBREW_CASK_OPTS=--require-sha blocks them (PB-01).' ;;
        HB-09) printf '%s' 'PB-01|ATK-10|Self-updating casks|Review self-updating apps; their updates bypass Homebrew checks (PB-01).' ;;
        HB-10) printf '%s' 'PB-01|ATK-09|Homebrew developer mode|Run brew developer off unless you develop Homebrew itself (PB-01).' ;;
        HB-11) printf '%s' 'PB-01|ATK-08|Brewfile|Keep a reviewed Brewfile in the Homebrew user config directory (PB-01).' ;;
        HB-12) printf '%s' 'PB-01|ATK-06|brewup delayed-upgrade helper|Install brewup and upgrade through it instead of brew upgrade (PB-01).' ;;
        NPM-01) printf '%s' 'PB-01|ATK-06 ATK-07|npm min-release-age|Add min-release-age=7 to ~/.npmrc (PB-01).' ;;
        NPM-02) printf '%s' 'PB-01|ATK-05|npm strict-allow-scripts|Add strict-allow-scripts=true to ~/.npmrc and allow-list needed install scripts (PB-01).' ;;
        NPM-03) printf '%s' 'PB-01|ATK-05|npm global ignore-scripts|Prefer strict-allow-scripts=true over a global ignore-scripts=true (PB-01).' ;;
        NPM-04) printf '%s' 'PB-02|ATK-05 ATK-06 ATK-12|npm versions that ignore the safety keys|Upgrade npm to 11.19 or later in the listed Node versions, or remove them (PB-02).' ;;
        NPM-05) printf '%s' 'PB-03|ATK-13 ATK-23|Auth tokens in ~/.npmrc|Move registry tokens out of ~/.npmrc into a password manager or env reference (PB-03).' ;;
        PNPM-01) printf '%s' 'PB-01|ATK-06 ATK-07|pnpm minimumReleaseAge|Add minimumReleaseAge: 10080 to the global pnpm config.yaml (PB-01).' ;;
        PNPM-02) printf '%s' 'PB-02|ATK-11|pnpm copies|Keep one pnpm (corepack, Homebrew or standalone) and remove the others (PB-02).' ;;
        NODE-01) printf '%s' 'PB-02|ATK-12|Duplicate Node patch versions|Remove superseded patch versions with nvm uninstall (PB-02).' ;;
        NODE-02) printf '%s' 'PB-02|ATK-12|End-of-life Node majors|Uninstall end-of-life Node majors or move projects to a supported LTS (PB-02).' ;;
        NODE-03) printf '%s' 'PB-02|ATK-11|Homebrew node alongside nvm|Keep Homebrew node patched if GUI apps or agent tools rely on it (PB-02).' ;;
        UV-01) printf '%s' 'PB-01|ATK-06|Global uv exclude-newer|Use per-project [tool.uv] exclude-newer instead of a global setting (PB-01).' ;;
        SHELL-01) printf '%s' 'PB-03|ATK-13|Secrets files sourced by shell rc|Load secrets per command (op run, password-manager agent) instead of from shell rc (PB-03).' ;;
        SHELL-02) printf '%s' 'PB-04|ATK-13 ATK-19|Secrets sourced before the agent early exit|Move secret sourcing below the agent early-exit block (PB-04).' ;;
        OSEE-01) printf '%s' 'PB-03|ATK-01 ATK-02 ATK-22|LuLu outbound firewall|Install LuLu and approve its network extension (PB-03).' ;;
        OSEE-02) printf '%s' 'PB-03|ATK-01 ATK-02 ATK-15|BlockBlock persistence monitor|Install BlockBlock and approve it so it runs as root (PB-03).' ;;
        OSEE-03) printf '%s' 'PB-03|ATK-01 ATK-03 ATK-15 ATK-17|KnockKnock persistence scanner|Install KnockKnock and scan persistence periodically (PB-03).' ;;
        TCC-01) printf '%s' 'PB-03|ATK-16 ATK-19|Full Disk Access for terminals and agents|Remove Full Disk Access from terminals and agent apps that do not need it (PB-03).' ;;
        AGENT-01) printf '%s' 'PB-04|ATK-06 ATK-07 ATK-20|Unpinned MCP server packages|Pin MCP launcher packages to an exact version (pkg@1.2.3, pkg==1.2.3) (PB-04).' ;;
        *) return 1 ;;
    esac
}

wa_selected() {
    [ -z "$ONLY" ] && return 0
    case $1 in "$ONLY"*) return 0 ;; esac
    return 1
}

# Run an area's checks when --only can match any of its IDs.
wa_want_area() {
    [ -z "$ONLY" ] && return 0
    case $1 in "$ONLY"*) return 0 ;; esac
    case $ONLY in "$1"-*) return 0 ;; esac
    return 1
}

wa_redact() {
    _wa_r=$(msc_redact_home "$1" "$HOME_DIR")
    if [ -n "${HOME:-}" ] && [ "$HOME" != "$HOME_DIR" ]; then
        _wa_r=$(msc_redact_home "$_wa_r" "$HOME")
    fi
    printf '%s' "$_wa_r"
}

# Usage: wa_emit ID STATUS DETAIL
wa_emit() {
    wa_selected "$1" || return 0
    _wa_meta=$(wa_meta "$1") || { printf 'internal error: unknown check %s\n' "$1" >&2; exit 2; }
    _wa_detail=$(wa_redact "$3")
    jq -nc --arg schema "$WA_SCHEMA" --arg id "$1" --arg status "$2" --arg meta "$_wa_meta" --arg detail "$_wa_detail" \
        '($meta|split("|")) as $m | {schema:$schema,id:$id,status:$status,title:$m[2],detail:$detail,playbook:$m[0],attack_ids:($m[1]|split(" ")),remediation:$m[3]}' >>"$RECORDS"
}

# Bounded command, stdout to FILE, stderr discarded. Returns the command status (124 on timeout).
wa_run() {
    _wa_secs=$1; _wa_out=$2; shift 2
    # The shell can report a harmless setpgid race (with its own path) on stderr.
    msc_run_timed_capture "$_wa_secs" "$_wa_out" "$TMP_DIR/run.err" "$TMP_DIR/run.timeout" "$@" 2>/dev/null
    _wa_rc=$?
    /bin/rm -f "$TMP_DIR/run.err" "$TMP_DIR/run.timeout"
    return "$_wa_rc"
}

wa_realpath() {
    /bin/realpath "$1" 2>/dev/null || printf '%s' "$1"
}

wa_join() { /usr/bin/paste -sd ',' - | /usr/bin/sed 's/,/, /g'; }

# Value of KEY in an npm-style ini file: blanks around "=" allowed, comments
# (# or ;) skipped, surrounding quotes stripped, last assignment wins.
wa_ini_get() {
    [ -r "$2" ] || return 1
    /usr/bin/awk -v key="$1" '
        { line=$0; sub(/^[ \t]+/, "", line) }
        line ~ /^[#;]/ { next }
        {
            eq=index(line, "="); if (!eq) next
            k=substr(line, 1, eq - 1); sub(/[ \t]+$/, "", k)
            if (k != key) next
            v=substr(line, eq + 1); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
            gsub(/^["'\'']|["'\'']$/, "", v); found=1
        }
        END { if (!found) exit 1; print v }
    ' "$2"
}

# Whole-word match of WORD in a shell-split VALUE (quotes removed, as
# Shellwords.shellsplit does for HOMEBREW_CASK_OPTS).
wa_has_word() {
    printf '%s' "$2" | /usr/bin/tr -d '"'\'  | /usr/bin/tr -s '[:blank:]' '\n' | /usr/bin/grep -qxF -- "$1"
}

# Prints the package spec of an unpinned MCP launcher invocation; returns 1
# when the command is not a package launcher or the package is pinned.
wa_mcp_unpinned() {
    [ "$#" -gt 0 ] || return 1
    _wa_l=${1##*/}; shift
    case $_wa_l in
        npx|pnpx|bunx) _wa_kind=npm ;;
        uvx) _wa_kind=uv ;;
        pnpm|yarn) [ "${1:-}" = dlx ] || return 1; shift; _wa_kind=npm ;;
        npm) [ "${1:-}" = exec ] || return 1; shift; _wa_kind=npm ;;
        bun) [ "${1:-}" = x ] || return 1; shift; _wa_kind=npm ;;
        uv) [ "${1:-}" = tool ] && [ "${2:-}" = run ] || return 1; shift 2; _wa_kind=uv ;;
        *) return 1 ;;
    esac
    _wa_pkg=''
    while [ "$#" -gt 0 ]; do
        case $_wa_kind:$1 in
            npm:-p|npm:--package|uv:--from) _wa_pkg=${2:-}; break ;;
            npm:--package=*|uv:--from=*) _wa_pkg=${1#*=}; break ;;
            npm:-c|npm:--call|uv:-p|uv:--python|uv:--with|uv:--with-editable|uv:--with-requirements|uv:--index|uv:--index-url|uv:--extra-index-url|uv:--default-index|uv:-c|uv:--constraints|uv:--overrides) shift ;;
            *:--) _wa_pkg=${2:-}; break ;;
            *:-*) ;;
            *) _wa_pkg=$1; break ;;
        esac
        [ "$#" -gt 0 ] && shift
    done
    case $_wa_pkg in ''|/*|./*|../*|'~'*) return 1 ;; esac
    if printf '%s' "${_wa_pkg#@}" | /usr/bin/grep -Eq '(@|==)v?[0-9]+\.[0-9]+\.[0-9]+|@[0-9a-f]{40}'; then
        return 1
    fi
    printf '%s' "$_wa_pkg"
}

# ---------------------------------------------------------------- Homebrew

BREW_PREFIX=''
BREW_OK=0
brew_setup() {
    if [ -z "$BREW" ]; then
        BREW=$(command -v brew 2>/dev/null || true)
        [ -n "$BREW" ] || for _wa_b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
            [ -x "$_wa_b" ] && { BREW=$_wa_b; break; }
        done
    fi
    [ -n "$BREW" ] && [ -x "$BREW" ] || return 0
    wa_run 20 "$TMP_DIR/brew-version" "$BREW" --version || return 0
    BREW_OK=1
    if wa_run 30 "$TMP_DIR/brew-config" "$BREW" config; then
        BREW_PREFIX=$(/usr/bin/sed -n 's/^HOMEBREW_PREFIX: *//p' "$TMP_DIR/brew-config" | /usr/bin/head -n 1)
    fi
    [ -n "$BREW_PREFIX" ] || BREW_PREFIX=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$BREW")/.." 2>/dev/null && /bin/pwd -P)
    # Installed taps with their contents; fall back to plain names.
    if wa_run 60 "$TMP_DIR/brew-tapinfo.json" "$BREW" tap-info --json --installed && jq -e 'type=="array"' "$TMP_DIR/brew-tapinfo.json" >/dev/null 2>&1; then
        jq -r '.[].name' "$TMP_DIR/brew-tapinfo.json" >"$TMP_DIR/brew-taps"
    else
        /bin/rm -f "$TMP_DIR/brew-tapinfo.json"
        wa_run 30 "$TMP_DIR/brew-taps" "$BREW" tap || : >"$TMP_DIR/brew-taps"
    fi
    if ! wa_run 120 "$TMP_DIR/brew-info.json" "$BREW" info --json=v2 --installed || ! jq -e . "$TMP_DIR/brew-info.json" >/dev/null 2>&1; then
        /bin/rm -f "$TMP_DIR/brew-info.json"
    fi
}

brew_user_dir() {
    if [ -n "${XDG_CONFIG_HOME:-}" ]; then printf '%s/homebrew' "$XDG_CONFIG_HOME"
    elif [ -n "${HOMEBREW_XDG_CONFIG_HOME:-}" ]; then printf '%s/homebrew' "$HOMEBREW_XDG_CONFIG_HOME"
    else printf '%s/.homebrew' "$HOME_DIR"; fi
}

# Mirrors export_homebrew_env_file in bin/brew: each line is read with
# "read -r" (surrounding blanks trimmed; a final line without a newline is
# never read), only lines starting with the variable name count (an "export "
# prefix makes brew skip the line) and the value is exported verbatim, quotes
# included. Usage: brew_env_file_value KEY FILE -> value of the last assignment.
brew_env_file_value() {
    [ -r "$2" ] || return 1
    _wa_skip_last=0
    [ -s "$2" ] && [ -n "$(/usr/bin/tail -c 1 "$2")" ] && _wa_skip_last=1
    /usr/bin/awk -v key="$1" -v skip_last="$_wa_skip_last" '
        { lines[NR]=$0 }
        END {
            n=NR; if (skip_last) n--
            for (i=1; i<=n; i++) {
                l=lines[i]; sub(/^[ \t]+/, "", l); sub(/[ \t]+$/, "", l)
                if (index(l, key "=") == 1) { v=substr(l, length(key) + 2); found=1 }
            }
            if (!found) exit 1
            print v
        }
    ' "$2"
}

# Order brew loads the files in; later wins. HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY
# (from the environment or the system file only) reloads the system file last.
brew_env_files() {
    printf '%s\n' "$SYSTEM_BREW_ENV"
    [ -n "$BREW_PREFIX" ] && printf '%s\n' "$BREW_PREFIX/etc/homebrew/brew.env"
    printf '%s\n' "$(brew_user_dir)/brew.env"
    if [ -n "${HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY:-}" ] || [ -n "$(brew_env_file_value HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY "$SYSTEM_BREW_ENV")" ]; then
        printf '%s\n' "$SYSTEM_BREW_ENV"
    fi
}

# Sets WA_EFF_VAL and WA_EFF_SRC (a file, or "environment") for KEY as brew
# would see it; returns 1 when brew would not see KEY at all.
brew_env_effective() {
    WA_EFF_VAL=''; WA_EFF_SRC=''
    eval "_wa_isset=\${$1+x}"
    if [ -n "$_wa_isset" ]; then eval "WA_EFF_VAL=\${$1}"; WA_EFF_SRC=environment; fi
    brew_env_files >"$TMP_DIR/brew-env-files"
    while IFS= read -r _wa_f; do
        if _wa_v=$(brew_env_file_value "$1" "$_wa_f"); then WA_EFF_VAL=$_wa_v; WA_EFF_SRC=$_wa_f; fi
    done <"$TMP_DIR/brew-env-files"
    [ -n "$WA_EFF_SRC" ]
}

# Explains assignments to KEY that brew ignores (export prefix, unterminated last line).
brew_env_notes() {
    brew_env_files | LC_ALL=C /usr/bin/sort -u | while IFS= read -r _wa_f; do
        [ -r "$_wa_f" ] || continue
        /usr/bin/awk -v key="$1" -v f="$_wa_f" '
            { l=$0; sub(/^[ \t]+/, "", l) }
            l ~ ("^export[ \t]+" key "=") { printf "; ignored by brew (export prefix) at %s:%d", f, NR }
        ' "$_wa_f"
        if [ -s "$_wa_f" ] && [ -n "$(/usr/bin/tail -c 1 "$_wa_f")" ] && /usr/bin/tail -n 1 "$_wa_f" | /usr/bin/grep -q "^[[:space:]]*$1="; then
            printf '; ignored by brew (last line of %s has no newline)' "$_wa_f"
        fi
    done
}

# Homebrew's boolean rule for "boolean: true" variables (env_config.rb):
# non-empty and, lower-cased, not false/no/off/nil/0. The value is verbatim,
# so a quoted "false" counts as on.
wa_brew_true() {
    [ -n "$1" ] || return 1
    case $(printf '%s' "$1" | /usr/bin/tr '[:upper:]' '[:lower:]') in false|no|off|nil|0) return 1 ;; esac
    return 0
}

# Usage: check_brew_env_key ID KEY set|bool. "set" variables (boolean: :set)
# are on for any non-empty value; "bool" ones follow wa_brew_true.
check_brew_env_key() {
    _wa_id=$1; _wa_key=$2; _wa_rule=$3
    _wa_notes=$(brew_env_notes "$_wa_key")
    if ! brew_env_effective "$_wa_key"; then
        wa_emit "$_wa_id" warn "$_wa_key not set in any brew.env ($(brew_user_dir)/brew.env)$_wa_notes"
        return
    fi
    _wa_val=$WA_EFF_VAL; _wa_src=$WA_EFF_SRC; _wa_on=0
    case $_wa_rule in
        set) [ -n "$_wa_val" ] && _wa_on=1 ;;
        bool) wa_brew_true "$_wa_val" && _wa_on=1 ;;
    esac
    if [ "$_wa_on" -ne 1 ]; then
        wa_emit "$_wa_id" warn "$_wa_key has a value Homebrew treats as off (from $_wa_src)$_wa_notes"
    elif [ "$_wa_key" = HOMEBREW_VERIFY_ATTESTATIONS ] && brew_env_effective HOMEBREW_NO_VERIFY_ATTESTATIONS && [ -n "$WA_EFF_VAL" ]; then
        wa_emit "$_wa_id" warn "$_wa_key is overridden by HOMEBREW_NO_VERIFY_ATTESTATIONS (from $WA_EFF_SRC)"
    elif [ "$_wa_src" = environment ]; then
        wa_emit "$_wa_id" warn "$_wa_key is set only in the environment; brew started by agents, cron or GUI apps will not see it$_wa_notes"
    else
        wa_emit "$_wa_id" pass "$_wa_key enabled in $_wa_src"
    fi
}

check_cask_require_sha() {
    _wa_notes=$(brew_env_notes HOMEBREW_CASK_OPTS)
    if brew_env_effective HOMEBREW_CASK_OPTS && wa_has_word --require-sha "$WA_EFF_VAL"; then
        if [ "$WA_EFF_SRC" = environment ]; then
            wa_emit HB-02 warn "HOMEBREW_CASK_OPTS contains --require-sha only in the environment; brew started by agents, cron or GUI apps will not see it$_wa_notes"
        else
            wa_emit HB-02 pass "HOMEBREW_CASK_OPTS contains --require-sha in $WA_EFF_SRC"
        fi
        return
    fi
    _wa_have=$WA_EFF_SRC
    if brew_env_effective HOMEBREW_CASK_OPTS_REQUIRE_SHA && [ -n "$WA_EFF_VAL" ]; then
        wa_emit HB-02 warn "only the deprecated HOMEBREW_CASK_OPTS_REQUIRE_SHA is set (from $WA_EFF_SRC); Homebrew 7 has disabled it and stops with an error$_wa_notes"
    elif [ -n "$_wa_have" ]; then
        wa_emit HB-02 warn "HOMEBREW_CASK_OPTS (from $_wa_have) has no --require-sha word$_wa_notes"
    else
        wa_emit HB-02 warn "HOMEBREW_CASK_OPTS not set in any brew.env ($(brew_user_dir)/brew.env)$_wa_notes"
    fi
}

check_hb() {
    brew_setup
    if [ "$BREW_OK" -ne 1 ]; then
        for _wa_id in HB-01 HB-02 HB-03 HB-04 HB-05 HB-06 HB-07 HB-08 HB-09 HB-10 HB-11 HB-12; do
            wa_emit "$_wa_id" not_applicable "Homebrew not found"
        done
        return
    fi
    check_brew_env_key HB-01 HOMEBREW_VERIFY_ATTESTATIONS set
    check_cask_require_sha
    check_brew_env_key HB-03 HOMEBREW_NO_INSECURE_REDIRECT bool

    # HB-04: never print gh output; it can contain account names.
    _wa_gh=$(command -v gh 2>/dev/null || true)
    [ -n "$_wa_gh" ] || { [ -x "$BREW_PREFIX/bin/gh" ] && _wa_gh=$BREW_PREFIX/bin/gh; }
    if [ -z "$_wa_gh" ]; then
        wa_emit HB-04 warn "gh not installed; attestation verification cannot run"
    elif wa_run 20 "$TMP_DIR/gh.out" "$_wa_gh" auth status; then
        wa_emit HB-04 pass "gh installed; authenticated: yes"
    else
        wa_emit HB-04 warn "gh installed; authenticated: no"
    fi
    /bin/rm -f "$TMP_DIR/gh.out"

    _wa_trust="$(brew_user_dir)/trust.json"
    if [ ! -f "$_wa_trust" ]; then
        wa_emit HB-05 pass "no trust.json (nothing trusted)"
    elif ! jq -e 'type=="object"' "$_wa_trust" >/dev/null 2>&1; then
        wa_emit HB-05 unknown "trust.json is not a JSON object"
    else
        _wa_taps=$(jq -r '(.trustedtaps // [])[]' "$_wa_trust" | wa_join)
        if [ -n "$_wa_taps" ]; then wa_emit HB-05 warn "whole-tap trust covers future formulae: $_wa_taps"
        else wa_emit HB-05 pass "no trustedtaps entries"; fi
    fi

    # Official taps (homebrew/*) are not third-party.
    _wa_third=$(/usr/bin/grep -v '^homebrew/' "$TMP_DIR/brew-taps" | /usr/bin/grep -v '^$' | LC_ALL=C /usr/bin/sort -u)
    _wa_cmdonly=''
    if [ -f "$TMP_DIR/brew-tapinfo.json" ]; then
        _wa_cmdonly=$(jq -r '.[] | select((.name|startswith("homebrew/"))|not) | select(((.command_files // [])|length) > 0 and ((.formula_names // [])|length) == 0 and ((.cask_tokens // [])|length) == 0) | .name' "$TMP_DIR/brew-tapinfo.json")
    fi
    if [ ! -f "$TMP_DIR/brew-info.json" ]; then
        for _wa_id in HB-06 HB-07 HB-08 HB-09; do wa_emit "$_wa_id" unknown "brew info --json=v2 --installed failed or timed out"; done
    else
        _wa_used=$(jq -r '[.formulae[].tap, .casks[].tap] | map(select(. != null)) | unique[]' "$TMP_DIR/brew-info.json")
        _wa_unused=$(printf '%s\n' "$_wa_third" | while IFS= read -r _wa_t; do
            [ -n "$_wa_t" ] || continue
            printf '%s\n' "$_wa_used" | /usr/bin/grep -qxF "$_wa_t" && continue
            printf '%s\n' "$_wa_cmdonly" | /usr/bin/grep -qxF "$_wa_t" && continue
            printf '%s\n' "$_wa_t"
        done | wa_join)
        _wa_cmds=$(printf '%s\n' "$_wa_cmdonly" | /usr/bin/grep -v '^$' | wa_join)
        if [ -n "$_wa_unused" ]; then wa_emit HB-06 warn "untap candidates (no installed package): $_wa_unused${_wa_cmds:+; command-only taps, not candidates: $_wa_cmds}"
        elif [ -n "$_wa_cmds" ]; then wa_emit HB-06 info "command-only taps (provide brew commands, no packages): $_wa_cmds"
        else wa_emit HB-06 pass "every third-party tap has an installed package"; fi

        _wa_from=$(jq -r '(.formulae[] | select(.tap != null and (.tap|startswith("homebrew/")|not)) | "\(.full_name) (\(.tap))"), (.casks[] | select(.tap != null and (.tap|startswith("homebrew/")|not)) | "\(.full_token) (\(.tap))")' "$TMP_DIR/brew-info.json" | wa_join)
        if [ -n "$_wa_from" ]; then wa_emit HB-07 info "installed from third-party taps: $_wa_from"
        else wa_emit HB-07 pass "no packages from third-party taps"; fi

        _wa_nocheck=$(jq -r '.casks[] | select(.sha256 == "no_check") | .full_token' "$TMP_DIR/brew-info.json" | wa_join)
        if [ -n "$_wa_nocheck" ]; then wa_emit HB-08 warn "casks without checksum: $_wa_nocheck"
        else wa_emit HB-08 pass "every installed cask has a checksum"; fi

        _wa_auto=$(jq -r '.casks[] | select(.auto_updates == true) | .full_token' "$TMP_DIR/brew-info.json" | wa_join)
        if [ -n "$_wa_auto" ]; then wa_emit HB-09 info "self-updating casks: $_wa_auto"
        else wa_emit HB-09 pass "no self-updating casks"; fi
    fi

    if wa_run 20 "$TMP_DIR/brew-developer" "$BREW" developer; then
        if /usr/bin/grep -q 'disabled' "$TMP_DIR/brew-developer"; then wa_emit HB-10 pass "developer mode disabled"
        elif /usr/bin/grep -q 'enabled' "$TMP_DIR/brew-developer"; then
            if brew_env_effective HOMEBREW_UPDATE_TO_TAG && [ -n "$WA_EFF_VAL" ]; then
                wa_emit HB-10 info "developer mode enabled, but HOMEBREW_UPDATE_TO_TAG (from $WA_EFF_SRC) keeps brew update on stable tags"
            else
                wa_emit HB-10 warn "developer mode enabled; brew update follows the unreleased main branch"
            fi
        else wa_emit HB-10 unknown "brew developer output not recognised"; fi
    else
        wa_emit HB-10 unknown "brew developer failed or timed out"
    fi

    if [ -f "$(brew_user_dir)/Brewfile" ]; then wa_emit HB-11 pass "$(brew_user_dir)/Brewfile present"
    else wa_emit HB-11 info "no Brewfile in $(brew_user_dir)"; fi

    _wa_bu=$(command -v brewup 2>/dev/null || true)
    [ -n "$_wa_bu" ] || { [ -x "$HOME_DIR/.local/bin/brewup" ] && _wa_bu=$HOME_DIR/.local/bin/brewup; }
    if [ -n "$_wa_bu" ]; then wa_emit HB-12 pass "brewup at $_wa_bu"
    else wa_emit HB-12 warn "brewup not found on PATH or in ~/.local/bin"; fi
}

# ---------------------------------------------------------------- npm

NVM_ROOT=''
npm_dirs() {
    for _wa_d in "$NVM_ROOT"/versions/node/v*/lib/node_modules/npm "${BREW_PREFIX:-/opt/homebrew}/lib/node_modules/npm"; do
        [ -f "$_wa_d/package.json" ] && printf '%s\n' "$_wa_d"
    done
}

check_npm() {
    _wa_rc="$HOME_DIR/.npmrc"
    if [ -r "$_wa_rc" ]; then
        _wa_age=$(wa_ini_get min-release-age "$_wa_rc" || true)
        _wa_strict=$(wa_ini_get strict-allow-scripts "$_wa_rc" || true)
        _wa_ignore=$(wa_ini_get ignore-scripts "$_wa_rc" || true)
    else
        _wa_age=''; _wa_strict=''; _wa_ignore=''
    fi
    if msc_is_uint "$_wa_age" && [ "$_wa_age" -gt 0 ]; then wa_emit NPM-01 pass "min-release-age=$_wa_age days"
    else wa_emit NPM-01 warn "min-release-age not set in ~/.npmrc"; fi
    if [ "$_wa_strict" = true ]; then wa_emit NPM-02 pass "strict-allow-scripts=true"
    else wa_emit NPM-02 warn "strict-allow-scripts=true not set in ~/.npmrc"; fi
    if [ "$_wa_ignore" = true ]; then wa_emit NPM-03 info "ignore-scripts=true is stricter than strict-allow-scripts but breaks packages with native builds, which tempts turning it off wholesale"
    else wa_emit NPM-03 pass "ignore-scripts not forced"; fi

    _wa_old=''; _wa_count=0
    npm_dirs >"$TMP_DIR/npm-dirs"
    while IFS= read -r _wa_d; do
        _wa_count=$((_wa_count + 1))
        _wa_ver=$(jq -r '.version // "?"' "$_wa_d/package.json" 2>/dev/null)
        _wa_defs="$_wa_d/node_modules/@npmcli/config/lib/definitions/definitions.js"
        if /usr/bin/grep -q "'min-release-age'" "$_wa_defs" 2>/dev/null && /usr/bin/grep -q "'strict-allow-scripts'" "$_wa_defs" 2>/dev/null; then
            continue
        fi
        case $_wa_d in
            "$NVM_ROOT"/versions/node/*) _wa_owner=$(printf '%s' "$_wa_d" | /usr/bin/sed 's|.*/versions/node/\([^/]*\)/.*|node \1|') ;;
            *) _wa_owner="Homebrew node" ;;
        esac
        _wa_old="$_wa_old${_wa_old:+, }$_wa_owner (npm $_wa_ver)"
    done <"$TMP_DIR/npm-dirs"
    if [ "$_wa_count" -eq 0 ]; then wa_emit NPM-04 not_applicable "no npm found under nvm or Homebrew"
    elif [ -n "$_wa_old" ]; then wa_emit NPM-04 warn "npm silently ignores the safety keys in: $_wa_old"
    else wa_emit NPM-04 pass "$_wa_count npm installation(s) understand both keys"; fi

    if [ -r "$_wa_rc" ]; then
        # Line numbers only; values are never copied into the output.
        _wa_lines=$(/usr/bin/grep -nE '(_authToken|_auth|_password)[[:space:]]*=' "$_wa_rc" | /usr/bin/grep -vE '^[0-9]+:[[:space:]]*[#;]' | /usr/bin/cut -d: -f1 | wa_join)
        _wa_envref=$(/usr/bin/grep -E '(_authToken|_auth|_password)[[:space:]]*=[[:space:]]*["'\'']?\$\{' "$_wa_rc" | /usr/bin/grep -cvE '^[[:space:]]*[#;]')
        if [ -n "$_wa_lines" ]; then
            _wa_n=$(printf '%s\n' "$_wa_lines" | /usr/bin/tr ',' '\n' | /usr/bin/grep -c .)
            if [ "$_wa_envref" -ge "$_wa_n" ]; then
                wa_emit NPM-05 pass "$_wa_n auth line(s) (lines $_wa_lines) reference environment variables only"
            else
                wa_emit NPM-05 warn "$_wa_n auth line(s) in ~/.npmrc (lines $_wa_lines); $_wa_envref use environment references"
            fi
        else
            wa_emit NPM-05 pass "no auth token lines"
        fi
    else
        wa_emit NPM-05 pass "no ~/.npmrc"
    fi
}

# ---------------------------------------------------------------- pnpm

check_pnpm() {
    if [ -n "${XDG_CONFIG_HOME:-}" ]; then _wa_cfg="$XDG_CONFIG_HOME/pnpm/config.yaml"
    else _wa_cfg="$HOME_DIR/Library/Preferences/pnpm/config.yaml"; fi
    _wa_min=''
    if [ -r "$_wa_cfg" ]; then
        _wa_min=$(/usr/bin/awk -F: '/^[[:space:]]*(minimumReleaseAge|minimum-release-age)[[:space:]]*:/ { v=$2; sub(/#.*/, "", v); gsub(/[ \t"'\'']/, "", v); print v; exit }' "$_wa_cfg")
    fi
    if msc_is_uint "$_wa_min" && [ "$_wa_min" -gt 0 ]; then
        wa_emit PNPM-01 pass "minimumReleaseAge=$_wa_min minutes ($((_wa_min / 1440)) days) in $_wa_cfg"
    else
        wa_emit PNPM-01 warn "minimumReleaseAge not set in $_wa_cfg"
    fi

    : >"$TMP_DIR/pnpm-paths"
    _wa_ifs=$IFS; IFS=:
    for _wa_p in $PATH; do
        [ -n "$_wa_p" ] && [ -x "$_wa_p/pnpm" ] && [ ! -d "$_wa_p/pnpm" ] && printf '%s\n' "$_wa_p/pnpm" >>"$TMP_DIR/pnpm-paths"
    done
    IFS=$_wa_ifs
    for _wa_p in "$HOME_DIR/Library/pnpm/pnpm" "$HOME_DIR/Library/pnpm/bin/pnpm" "$NVM_ROOT"/versions/node/v*/bin/pnpm "${BREW_PREFIX:-/opt/homebrew}/bin/pnpm"; do
        [ -x "$_wa_p" ] && [ ! -d "$_wa_p" ] && printf '%s\n' "$_wa_p" >>"$TMP_DIR/pnpm-paths"
    done
    _wa_list=$(while IFS= read -r _wa_p; do wa_realpath "$_wa_p"; printf '\n'; done <"$TMP_DIR/pnpm-paths" | /usr/bin/grep -v '^$' | LC_ALL=C /usr/bin/sort -u)
    _wa_n=$(printf '%s\n' "$_wa_list" | /usr/bin/grep -c .)
    if [ "$_wa_n" -eq 0 ]; then wa_emit PNPM-02 not_applicable "pnpm not found"
    elif [ "$_wa_n" -eq 1 ]; then wa_emit PNPM-02 pass "one pnpm: $_wa_list"
    else wa_emit PNPM-02 warn "$_wa_n distinct pnpm executables: $(printf '%s\n' "$_wa_list" | wa_join)"; fi
}

# ---------------------------------------------------------------- Node.js

check_node() {
    _wa_versions=$(for _wa_v in "$NVM_ROOT"/versions/node/v*; do [ -d "$_wa_v" ] && printf '%s\n' "${_wa_v##*/}"; done)
    if [ -z "$_wa_versions" ]; then
        wa_emit NODE-01 not_applicable "no nvm Node versions"
        wa_emit NODE-02 not_applicable "no nvm Node versions"
    else
        _wa_dups=$(printf '%s\n' "$_wa_versions" | /usr/bin/awk -F. '{ m=$1; sub(/^v/, "", m); list[m]=list[m] (list[m] ? " " : "") $0; n[m]++ } END { for (m in n) if (n[m] > 1) print "v" m ": " list[m] }' | LC_ALL=C /usr/bin/sort | /usr/bin/paste -sd ';' - | /usr/bin/sed 's/;/; /g')
        if [ -n "$_wa_dups" ]; then wa_emit NODE-01 warn "several patch versions per major: $_wa_dups"
        else wa_emit NODE-01 pass "one version per major: $(printf '%s\n' "$_wa_versions" | wa_join)"; fi
        _wa_eol=$(printf '%s\n' "$_wa_versions" | while IFS= read -r _wa_v; do
            _wa_m=${_wa_v#v}; _wa_m=${_wa_m%%.*}
            case " $NODE_EOL_MAJORS " in (*" $_wa_m "*) printf '%s\n' "$_wa_v" ;; esac
        done | wa_join)
        if [ -n "$_wa_eol" ]; then wa_emit NODE-02 warn "end-of-life Node installed: $_wa_eol"
        else wa_emit NODE-02 pass "no end-of-life Node majors"; fi
    fi
    _wa_bnode="${BREW_PREFIX:-/opt/homebrew}/bin/node"
    if [ -x "$_wa_bnode" ] && [ -n "$_wa_versions" ]; then
        wa_emit NODE-03 info "Homebrew node ($_wa_bnode) coexists with nvm; GUI apps and agent tools without nvm on PATH use it, so keep it patched rather than removing it blindly"
    elif [ -x "$_wa_bnode" ]; then
        wa_emit NODE-03 pass "only Homebrew node"
    else
        wa_emit NODE-03 pass "no Homebrew node"
    fi
}

# ---------------------------------------------------------------- uv

check_uv() {
    if [ -n "${XDG_CONFIG_HOME:-}" ]; then _wa_uv="$XDG_CONFIG_HOME/uv/uv.toml"; else _wa_uv="$HOME_DIR/.config/uv/uv.toml"; fi
    _wa_src=''
    [ -r "$_wa_uv" ] && /usr/bin/grep -Eq '^[[:space:]]*exclude-newer[[:space:]]*=' "$_wa_uv" && _wa_src=$_wa_uv
    [ -n "${UV_EXCLUDE_NEWER:-}" ] && _wa_src="$_wa_src${_wa_src:+ and }UV_EXCLUDE_NEWER"
    if [ -n "$_wa_src" ]; then
        wa_emit UV-01 info "global exclude-newer from $_wa_src writes exclude-newer-span into every project's uv.lock (churn in shared repositories)"
    else
        wa_emit UV-01 pass "no global exclude-newer"
    fi
}

# ---------------------------------------------------------------- shell rc

SHELL_RC_FILES=".zshenv .zprofile .zshrc .bash_profile .bashrc .profile"
check_shell() {
    : >"$TMP_DIR/shell-src"; : >"$TMP_DIR/shell-early"
    for _wa_f in $SHELL_RC_FILES; do
        [ -r "$HOME_DIR/$_wa_f" ] || continue
        # Only rc lines are read; the sourced files are never opened.
        /usr/bin/awk -v file="~/$_wa_f" -v early_out="$TMP_DIR/shell-early" '
            {
                line=$0; sub(/^[ \t]+/, "", line)
                if (line ~ /^#/) next
                if (line ~ /(CLAUDECODE|CLAUDE_CODE|CODEX_|CURSOR_AGENT|GEMINI_CLI|AI_AGENT)/ && line !~ /^(export[ \t]+|readonly[ \t]+|local[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=/ && line ~ /(^|[ \t])(if|elif|test|\[|\[\[)([ \t]|$)|&&|\|\|/) pending=NR
                if (pending && !early && NR - pending <= 5 && line ~ /(^|[^A-Za-z_])(return|exit)([^A-Za-z_]|$)/) early=pending
                n=split(line, w, /[ \t;&|()]+/)
                for (i=1; i<n; i++) if (w[i] == "source" || w[i] == ".") {
                    p=w[i+1]; gsub(/["'\'']/, "", p); lp=tolower(p)
                    if (lp ~ /(\.env|secret|private|credential|token)/ && lp !~ /\.zshenv$/) print file "\t" NR "\t" p
                }
            }
            END { if (early) print file "\t" early >> early_out }
        ' "$HOME_DIR/$_wa_f" >>"$TMP_DIR/shell-src"
    done
    if [ ! -s "$TMP_DIR/shell-src" ]; then
        wa_emit SHELL-01 pass "no shell rc file sources a secrets file"
        wa_emit SHELL-02 pass "no secrets files sourced"
        return
    fi
    _wa_list=$(/usr/bin/awk -F '\t' '{ print $1 ":" $2 " sources " $3 }' "$TMP_DIR/shell-src" | wa_join)
    wa_emit SHELL-01 info "every process started from the shell inherits these secrets: $_wa_list"

    _wa_before=''; _wa_after=''; _wa_noblock=''
    _wa_tab=$(printf '\t')
    while IFS="$_wa_tab" read -r _wa_file _wa_line _wa_path; do
        _wa_e=$(/usr/bin/awk -F '\t' -v f="$_wa_file" '$1 == f { print $2; exit }' "$TMP_DIR/shell-early")
        if [ -z "$_wa_e" ]; then _wa_noblock="$_wa_noblock${_wa_noblock:+, }$_wa_file:$_wa_line"
        elif [ "$_wa_line" -lt "$_wa_e" ]; then _wa_before="$_wa_before${_wa_before:+, }$_wa_file:$_wa_line (early exit at line $_wa_e)"
        else _wa_after="$_wa_after${_wa_after:+, }$_wa_file:$_wa_line"; fi
    done <"$TMP_DIR/shell-src"
    if [ -n "$_wa_before" ]; then wa_emit SHELL-02 warn "secrets sourced before the agent early exit, so agents inherit them: $_wa_before"
    elif [ -n "$_wa_noblock" ]; then wa_emit SHELL-02 info "no AI-agent early-exit block in the same file: $_wa_noblock"
    else wa_emit SHELL-02 pass "secrets sourced after the agent early exit: $_wa_after"; fi
}

# ---------------------------------------------------------------- Objective-See

check_osee() {
    if [ ! -d "$APPS_DIR/LuLu.app" ]; then
        wa_emit OSEE-01 warn "LuLu not installed in $APPS_DIR"
    elif [ "$FIXTURE" -eq 1 ]; then
        wa_emit OSEE-01 unknown "LuLu installed; network extension state not checked in fixture mode"
    elif wa_run 20 "$TMP_DIR/sysext" /usr/bin/systemextensionsctl list; then
        if /usr/bin/grep 'com.objective-see.lulu' "$TMP_DIR/sysext" | /usr/bin/grep -qF '[activated enabled]'; then
            wa_emit OSEE-01 pass "LuLu installed; network extension activated and enabled"
        else
            wa_emit OSEE-01 warn "LuLu installed but its network extension is not activated and enabled"
        fi
    else
        wa_emit OSEE-01 unknown "LuLu installed; systemextensionsctl list failed"
    fi

    if [ ! -d "$APPS_DIR/BlockBlock.app" ]; then
        wa_emit OSEE-02 warn "BlockBlock not installed in $APPS_DIR"
    elif [ "$FIXTURE" -eq 1 ]; then
        wa_emit OSEE-02 unknown "BlockBlock installed; process state not checked in fixture mode"
    elif wa_run 10 "$TMP_DIR/ps" /bin/ps -axo user=,comm=; then
        if /usr/bin/awk '$1 == "root" && /BlockBlock/ { found=1 } END { exit !found }' "$TMP_DIR/ps"; then
            wa_emit OSEE-02 pass "BlockBlock installed and running as root"
        else
            wa_emit OSEE-02 warn "BlockBlock installed but not running as root"
        fi
    else
        wa_emit OSEE-02 unknown "BlockBlock installed; process list unavailable"
    fi

    if [ -d "$APPS_DIR/KnockKnock.app" ]; then wa_emit OSEE-03 pass "KnockKnock installed"
    else wa_emit OSEE-03 warn "KnockKnock not installed in $APPS_DIR"; fi
}

# ---------------------------------------------------------------- TCC

check_tcc() {
    if [ ! -r "$TCC_DB" ] || ! wa_run 10 "$TMP_DIR/tcc" /usr/bin/sqlite3 -readonly "$TCC_DB" "select client, auth_value from access where service='kTCCServiceSystemPolicyAllFiles'"; then
        wa_emit TCC-01 unknown "Full Disk Access list not readable without Full Disk Access; check System Settings > Privacy & Security > Full Disk Access manually"
        return
    fi
    _wa_hits=$(/usr/bin/awk -F '|' -v list=" $TCC_TERMINAL_CLIENTS " '
        $2 == 2 && (index(list, " " $1 " ") || $1 ~ /^com\.todesktop\./) { print $1 }
    ' "$TMP_DIR/tcc" | LC_ALL=C /usr/bin/sort -u | wa_join)
    if [ -n "$_wa_hits" ]; then
        wa_emit TCC-01 warn "terminals or agent apps with Full Disk Access (agents they start inherit it): $_wa_hits"
    else
        wa_emit TCC-01 pass "no known terminal or agent app holds Full Disk Access"
    fi
}

# ---------------------------------------------------------------- AI agents

# Emits "scope<TAB>name<TAB>command args..." per MCP server. Project paths
# and env blocks are never output.
agent_servers() {
    if [ -r "$HOME_DIR/.claude.json" ]; then
        jq -r 'def row($scope): to_entries[] | select(.value|type=="object") | [$scope, .key, ([.value.command // ""] + ((.value.args // []) | map(tostring)) | join(" "))] | @tsv;
            ((.mcpServers // {}) | row("claude")), ((.projects // {}) | to_entries[] | (.value.mcpServers // {}) | row("claude-project"))' "$HOME_DIR/.claude.json" 2>/dev/null
    fi
    if [ -r "$HOME_DIR/.cursor/mcp.json" ]; then
        jq -r '(.mcpServers // {}) | to_entries[] | select(.value|type=="object") | ["cursor", .key, ([.value.command // ""] + ((.value.args // []) | map(tostring)) | join(" "))] | @tsv' "$HOME_DIR/.cursor/mcp.json" 2>/dev/null
    fi
    if [ -r "$HOME_DIR/.codex/config.toml" ]; then
        /usr/bin/awk '
            function flush() { if (name != "") printf "codex\t%s\t%s\n", name, (cmd " " args) }
            /^[ \t]*\[/ {
                inargs=0; flush(); name=""; cmd=""; args=""
                if ($0 ~ /^[ \t]*\[mcp_servers\.[^].]+\]/) { name=$0; sub(/^[ \t]*\[mcp_servers\./, "", name); sub(/\].*/, "", name); gsub(/"/, "", name) }
                next
            }
            name == "" { next }
            /^[ \t]*command[ \t]*=/ { v=$0; sub(/^[^=]*=[ \t]*/, "", v); gsub(/"/, "", v); cmd=v; next }
            /^[ \t]*args[ \t]*=/ { v=$0; sub(/^[^=]*=[ \t]*/, "", v); inargs=(v !~ /\]/); args=v; next }
            inargs { args=args " " $0; if ($0 ~ /\]/) inargs=0; next }
            END { flush() }
        ' "$HOME_DIR/.codex/config.toml" | /usr/bin/awk -F '\t' 'BEGIN { OFS="\t" } { a=$3; gsub(/[][,"]/, " ", a); gsub(/[ \t]+/, " ", a); sub(/^ /, "", a); sub(/ $/, "", a); print $1, $2, a }'
    fi
}

check_agent() {
    agent_servers >"$TMP_DIR/mcp" 2>/dev/null || true
    if [ ! -s "$TMP_DIR/mcp" ]; then
        wa_emit AGENT-01 not_applicable "no MCP servers in ~/.claude.json, ~/.cursor/mcp.json or ~/.codex/config.toml"
        return
    fi
    _wa_total=0; _wa_bad=''
    _wa_tab=$(printf '\t')
    while IFS="$_wa_tab" read -r _wa_scope _wa_name _wa_cmd; do
        _wa_total=$((_wa_total + 1))
        # Intentional word splitting (globbing off) of the launcher command line.
        set -f
        # shellcheck disable=SC2086
        if wa_mcp_unpinned $_wa_cmd >/dev/null; then _wa_hit=1; else _wa_hit=0; fi
        set +f
        if [ "$_wa_hit" -eq 1 ]; then
            _wa_l=$(printf '%s' "$_wa_cmd" | /usr/bin/awk '{ n=split($1, p, "/"); print p[n] }')
            _wa_bad="$_wa_bad${_wa_bad:+, }$_wa_scope:$_wa_name ($_wa_l)"
        fi
    done <"$TMP_DIR/mcp"
    if [ -n "$_wa_bad" ]; then wa_emit AGENT-01 warn "unpinned launcher packages: $_wa_bad"
    else wa_emit AGENT-01 pass "$_wa_total MCP server(s); no unpinned launcher packages"; fi
}

# ---------------------------------------------------------------- self-test

# Invoked indirectly through st in the self-test.
# shellcheck disable=SC2329
wa_not() { ! "$@"; }
self_test() {
    _wa_fail=0; _wa_n=0
    st() { _wa_n=$((_wa_n + 1)); if ! "$@" >/dev/null; then printf 'self-test failed: %s\n' "$*" >&2; _wa_fail=1; fi; }
    st wa_mcp_unpinned npx -y @modelcontextprotocol/server-memory
    st wa_mcp_unpinned npx some-server@latest
    st wa_mcp_unpinned /opt/homebrew/bin/npx --yes some-server
    st wa_mcp_unpinned pnpm dlx some-server
    st wa_mcp_unpinned uvx --python 3.12 mcp-server-fetch
    st wa_mcp_unpinned uvx --from mcp-server-git mcp-server-git
    st wa_not wa_mcp_unpinned npx -y @scope/server@1.2.3
    st wa_not wa_mcp_unpinned npx -y some-server@1.2.3
    st wa_not wa_mcp_unpinned uvx mcp-server-fetch==2025.1.0
    st wa_not wa_mcp_unpinned uvx --from mcp-server-git==1.0.0 mcp-server-git
    st wa_not wa_mcp_unpinned node /path/to/server.js
    st wa_not wa_mcp_unpinned docker run image
    st wa_not wa_mcp_unpinned npx ./local-server
    st wa_meta AGENT-01
    st wa_brew_true true
    st wa_brew_true 1
    st wa_not wa_brew_true Off
    st wa_not wa_brew_true 0
    st wa_not wa_meta NOPE-01
    printf '%s\n%s\n%s\n%s\n%s' 'min-release-age = 7' '; strict-allow-scripts=true' 'export HOMEBREW_X=1' '  HOMEBREW_Y="false"  ' 'HOMEBREW_Z=last' >"$TMP_DIR/kv"
    st test "$(wa_ini_get min-release-age "$TMP_DIR/kv")" = 7
    st wa_not wa_ini_get strict-allow-scripts "$TMP_DIR/kv"
    st wa_not brew_env_file_value HOMEBREW_X "$TMP_DIR/kv"
    st test "$(brew_env_file_value HOMEBREW_Y "$TMP_DIR/kv")" = '"false"'
    st wa_brew_true "$(brew_env_file_value HOMEBREW_Y "$TMP_DIR/kv")"
    st wa_not brew_env_file_value HOMEBREW_Z "$TMP_DIR/kv"
    st wa_has_word --require-sha '"--appdir=/Applications --require-sha"'
    st wa_not wa_has_word --require-sha '--require-sha-not'
    _wa_saved=$HOME_DIR; HOME_DIR=/Users/example
    _wa_tilde=\~
    st test "$(wa_redact /Users/example/.npmrc)" = "$_wa_tilde/.npmrc"
    HOME_DIR=$_wa_saved
    _wa_status=pass; [ "$_wa_fail" -eq 0 ] || _wa_status=fail
    jq -nc --arg schema "$WA_SCHEMA" --arg status "$_wa_status" --argjson checks "$_wa_n" '{schema:$schema,record_type:"self_test",status:$status,checks:$checks}'
    [ "$_wa_fail" -eq 0 ]
}

if [ "$SELF_TEST" -eq 1 ]; then
    self_test
    exit $?
fi

# ---------------------------------------------------------------- main

NVM_ROOT=${NVM_DIR:-$HOME_DIR/.nvm}
# Inspecting another home: the caller's NVM_DIR and XDG_CONFIG_HOME do not apply.
if [ "$HOME_DIR" != "${HOME:-}" ]; then NVM_ROOT=$HOME_DIR/.nvm; unset XDG_CONFIG_HOME; fi

if wa_want_area HB || wa_want_area NPM || wa_want_area PNPM || wa_want_area NODE; then
    # npm, pnpm and node checks need the Homebrew prefix too.
    if wa_want_area HB; then check_hb; else brew_setup; fi
fi
wa_want_area NPM && check_npm
wa_want_area PNPM && check_pnpm
wa_want_area NODE && check_node
wa_want_area UV && check_uv
wa_want_area SHELL && check_shell
wa_want_area OSEE && check_osee
wa_want_area TCC && check_tcc
wa_want_area AGENT && check_agent

[ -s "$RECORDS" ] || { printf 'No check matches --only %s\n' "$ONLY" >&2; exit 2; }

if [ "$OUTPUT" = json ]; then
    /bin/cat "$RECORDS"
else
    jq -rs '
        def pad($n): if length < $n then . + (" " * ($n - length)) else . end;
        def area: {"HB":"Homebrew","NPM":"npm","PNPM":"pnpm","NODE":"Node.js","UV":"uv","SHELL":"Shell startup files","OSEE":"Objective-See tools","TCC":"Full Disk Access (TCC)","AGENT":"AI agents"}[split("-")[0]] // .;
        def status_label: if . == "not_applicable" then "N/A" else ascii_upcase end;
        (reduce .[] as $r ([]; if (length > 0 and (.[-1][0].id|split("-")[0]) == ($r.id|split("-")[0])) then .[-1] += [$r] else . + [[$r]] end)) as $groups |
        ($groups[] | "", (.[0].id|area), (.[] | "  " + (.status|status_label|pad(8)) + (.id|pad(10)) + .title + " — " + .detail,
            (if .status == "warn" or .status == "fail" then ("" | pad(20)) + "fix: " + .remediation else empty end))),
        "",
        "Summary: \(length) checks; pass \(map(select(.status=="pass"))|length), warn \(map(select(.status=="warn"))|length), fail \(map(select(.status=="fail"))|length), info \(map(select(.status=="info"))|length), unknown \(map(select(.status=="unknown"))|length), n/a \(map(select(.status=="not_applicable"))|length). Read-only; nothing was changed."
    ' "$RECORDS"
fi

if /usr/bin/grep -qE '"status":"(warn|fail)"' "$RECORDS"; then exit 1; fi
exit 0
