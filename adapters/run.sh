#!/bin/sh
# SPDX-License-Identifier: MIT
# Static dispatcher for optional security adapters.

set -u
umask 077
ROOT_DIR=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)
# shellcheck source=lib/macos_security_common.sh
. "$ROOT_DIR/lib/macos_security_common.sh"
# shellcheck source=lib/macos_security_execution.sh
. "$ROOT_DIR/lib/macos_security_execution.sh"
# shellcheck source=lib/macos_security_evidence.sh
. "$ROOT_DIR/lib/macos_security_evidence.sh"
# shellcheck source=lib/macos_security_dependencies.sh
. "$ROOT_DIR/lib/macos_security_dependencies.sh"
# shellcheck source=adapters/knockknock.sh
. "$ROOT_DIR/adapters/knockknock.sh"
# shellcheck source=adapters/clamav.sh
. "$ROOT_DIR/adapters/clamav.sh"
# shellcheck source=adapters/yara.sh
. "$ROOT_DIR/adapters/yara.sh"
# shellcheck source=adapters/developer.sh
. "$ROOT_DIR/adapters/developer.sh"
# shellcheck source=adapters/telemetry.sh
. "$ROOT_DIR/adapters/telemetry.sh"
# shellcheck source=adapters/mscp.sh
. "$ROOT_DIR/adapters/mscp.sh"

OUTPUT=""; IDS=""; CANDIDATES=""; YARA_RULES=""; DEV_TARGET=""; MSCP_REPORT=""; SELF_TEST=0
usage() {
    cat <<'EOF'
Usage: adapters/run.sh --output DIR --ids CSV [options]

  --output DIR            New private report directory
  --candidates FILE       Newline-delimited bounded scan targets
  --yara-rules PATH       Reviewed local YARA/YARA-X rules
  --dev-target DIR        Explicit developer project scope
  --mscp-report FILE      Existing audit-only mSCP result
  --auto-install          Install missing allow-listed dependencies with brew
  --no-auto-install       Report missing dependencies without installation
  --self-test             Validate dispatcher without running tools
EOF
}
die() { printf '%s: %s\n' "${0##*/}" "$1" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
    case $1 in
        --output) [ "$#" -ge 2 ] || die "missing output"; shift; OUTPUT=$1 ;;
        --ids) [ "$#" -ge 2 ] || die "missing ids"; shift; IDS=$1 ;;
        --candidates) [ "$#" -ge 2 ] || die "missing candidates"; shift; CANDIDATES=$1 ;;
        --yara-rules) [ "$#" -ge 2 ] || die "missing rules"; shift; YARA_RULES=$1 ;;
        --dev-target) [ "$#" -ge 2 ] || die "missing dev target"; shift; DEV_TARGET=$1 ;;
        --mscp-report) [ "$#" -ge 2 ] || die "missing mSCP report"; shift; MSCP_REPORT=$1 ;;
        --auto-install) MSC_AUTO_INSTALL=1 ;;
        --no-auto-install) MSC_AUTO_INSTALL=0 ;;
        --self-test) SELF_TEST=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
msc_require_jq || exit 2
if [ "$SELF_TEST" -eq 1 ]; then
    for _msa_id in knockknock yara-x yara clamav osv-scanner trivy gitleaks osquery santa jq shellcheck; do
        msd_spec "$_msa_id" >/dev/null || die "missing dependency spec: $_msa_id"
    done
    printf '%s\n' '{"schema":"macos-security-adapters/v1","record_type":"self_test","status":"pass","installer":"homebrew_allowlist"}'
    exit 0
fi
[ -n "$OUTPUT" ] || die "--output is required"
[ -n "$IDS" ] || die "--ids is required"
OUTPUT=$(msc_create_private_dir "$OUTPUT") || die "cannot create new private output directory"
OBSERVATIONS="$OUTPUT/observations.jsonl"; COVERAGE="$OUTPUT/coverage.jsonl"; FINDINGS="$OUTPUT/findings.jsonl"; INSTALL_LOG="$OUTPUT/install.log"
: >"$OBSERVATIONS"; : >"$COVERAGE"; : >"$FINDINGS"; : >"$INSTALL_LOG"
/bin/chmod 600 "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG"

_msa_old_ifs=$IFS; IFS=,
# Intentional comma-separated allow-listed adapter split; case dispatch below
# rejects every identifier outside the static set.
# shellcheck disable=SC2086
set -- $IDS
IFS=$_msa_old_ifs
for _msa_id in "$@"; do
    if [ "$(/usr/bin/id -u)" -eq 0 ] && [ "$_msa_id" != mscp ]; then
        mse_emit_coverage "$COVERAGE" "adapter.$_msa_id" denied "External adapter skipped as root. Run the adapter as an unprivileged user." true "$_msa_id" "" || exit 2
        continue
    fi
    case $_msa_id in
        knockknock) msa_knockknock_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" ;;
        clamav) msa_clamav_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" "$CANDIDATES" ;;
        yara|yara-x) msa_yara_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" "$CANDIDATES" "$YARA_RULES" ;;
        osv-scanner) msa_osv_scanner_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" "$DEV_TARGET" ;;
        gitleaks) msa_gitleaks_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" "$DEV_TARGET" ;;
        trivy) msa_trivy_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" "$DEV_TARGET" ;;
        osquery) msa_osquery_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" ;;
        santa) msa_santa_run "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$INSTALL_LOG" ;;
        mscp) msa_mscp_import "$OUTPUT" "$OBSERVATIONS" "$COVERAGE" "$FINDINGS" "$MSCP_REPORT" ;;
        '') ;;
        *) mse_emit_coverage "$COVERAGE" "adapter.$_msa_id" not_supported "Adapter identifier is not in the static dispatcher." true "$_msa_id" "" ;;
    esac || exit 2
done
mse_aggregate_coverage "$COVERAGE" "$OUTPUT/coverage.json" || exit 2
jq -n --arg generated_at "$(msc_utc_now)" --arg ids "$IDS" --slurpfile coverage "$COVERAGE" '{schema:"macos-security-adapters/v1",record_type:"adapter_summary",generated_at:$generated_at,requested:($ids|split(",")),coverage:$coverage}' >"$OUTPUT/summary.json" || exit 2
printf '%s\n' "$OUTPUT/summary.json"
