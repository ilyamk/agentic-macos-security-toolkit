# SPDX-License-Identifier: MIT
# mSCP is not installed automatically because no supported Homebrew package is
# available. This adapter imports an explicitly supplied audit-only result.

msa_mscp_import() {
    _msa_out=$1; _msa_observations=$2; _msa_coverage=$3; _msa_findings=$4; _msa_report=$5
    if [ -z "$_msa_report" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.mscp not_requested "No mSCP audit-only report was supplied; mSCP has no allow-listed Homebrew package." false mscp ""
        return 0
    fi
    if [ ! -r "$_msa_report" ]; then
        mse_emit_coverage "$_msa_coverage" adapter.mscp error "The supplied mSCP report is unreadable." true mscp ""
        return 0
    fi
    /bin/cp "$_msa_report" "$_msa_out/mscp-audit.txt" || {
        mse_emit_coverage "$_msa_coverage" adapter.mscp error "The mSCP report could not be copied." true mscp ""
        return 0
    }
    mse_emit_observation "$_msa_observations" adapter.mscp compliance collected "An externally generated mSCP audit-only report was preserved for analysis." "adapters/mscp-audit.txt" '{"audit_only":true,"remediation_executed":false}' high
    mse_emit_coverage "$_msa_coverage" adapter.mscp collected "mSCP report imported; its baseline/release must be reviewed in the report itself." true mscp "adapters/mscp-audit.txt"
}
