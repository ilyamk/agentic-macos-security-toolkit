# Security policy

## Report a vulnerability

Use **Security → Advisories → Report a vulnerability** on the public GitHub repository. Include the affected tag or commit, the affected command, the impact and the steps needed to reproduce the behaviour safely. Use synthetic inputs where possible. Keep credentials, private reports, machine identifiers and exploit details out of issues, pull requests and public comments. If private reporting is unavailable, open a short issue requesting a private contact and omit technical details.

The latest tagged release and the default branch receive security fixes. Fix versions and disclosure details will be recorded in a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-coordinated-disclosure-of-security-vulnerabilities) when appropriate.

## Handling reports

Assessment, monitoring, developer scan and remediation output can contain account names, paths, process metadata, network endpoints and security settings. Share the minimum necessary evidence through a trusted private channel. For assessments, generate a portable summary with `./bin/macos-security assess --redact` and inspect it before sharing. See [the privacy contract](docs/privacy.md) for fields and limitations.

Verify downloaded release assets against the SHA-256 manifest and the repository's GitHub build attestation. See the [release guide](docs/releasing.md).
