# Incident response boundary

When a credential stealer is suspected, protect email/password-manager accounts and revoke sessions/tokens from a different trusted device. Do not enter new credentials on the suspect Mac. Preserve volatile and persistence evidence before cleanup if forensic value matters.

Use `macos-security incident` for bounded collection. A confirmed malware or credential-access chain requires independent validation, containment, credential rotation, and often erase/reinstall with selective restoration. Remediation plans are not authorization and remain review-first with rollback.
