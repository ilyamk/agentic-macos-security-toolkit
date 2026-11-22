# Publishing and releasing

## GitHub setup

1. Confirm the intended GitHub owner and repository destination. The repository name is `agentic-macos-security-toolkit` and the target default branch is `main`. Check the destination before the first push.
2. Review the [privacy contract](privacy.md), the output of `git status --short --ignored`, and every file in the first commit. Verify the author and committer emails on commits intended for publication. Enable GitHub's private email option and use its exact no-reply address if needed. Use `git log --format='%h %an <%ae> | %cn <%ce>'` in your terminal.
3. Enable the dependency graph, Dependabot alerts, secret scanning with push protection, and [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository). Use the checked-in CodeQL workflow for Actions code scanning and avoid setting up a duplicate CodeQL scan.
4. Protect `main` with a pull request, at least one independent review and the **Fast checks**, **Unprivileged live checks** and **Repository security** status checks. After the first public pull request, also require **Dependency review**. Restrict updates to `v*` tags and the `release` environment to release maintainers. Review workflow, CI tool and dependency pin changes through code ownership if a maintainer team is available.
5. Allow the scheduled workflows on the public repository and keep the default workflow token read-only. Run CI on GitHub-hosted runners. Pull requests use no deployment credentials and publish no host diagnostics.
6. Add dynamic badges after the workflows have run and the OpenSSF Scorecard result is published. Replace the owner and repository in the examples below. Keep OpenSSF Best Practices separate and only add its badge after the maintainers have completed and published the questionnaire.

~~~markdown
[![Tests](https://github.com/OWNER/REPOSITORY/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/OWNER/REPOSITORY/actions/workflows/tests.yml)
[![Security](https://github.com/OWNER/REPOSITORY/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/OWNER/REPOSITORY/actions/workflows/security.yml)
[![CodeQL](https://github.com/OWNER/REPOSITORY/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/OWNER/REPOSITORY/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/OWNER/REPOSITORY/badge)](https://scorecard.dev/viewer/?uri=github.com/OWNER/REPOSITORY)
~~~

[GitHub workflow badges](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/monitoring-workflows/adding-a-workflow-status-badge) · [OpenSSF Scorecard](https://github.com/ossf/scorecard-action) · [OpenSSF Best Practices](https://www.bestpractices.dev/)

## Verify a candidate

Run from the committed candidate, using a private terminal and a disposable macOS environment for the live checks.

~~~sh
make test-fast
make test-live
./tools/ci/check-public-tree.sh HEAD
./tools/ci/scan-git-secrets.sh
~~~

`test-fast` requires macOS, `jq` and ShellCheck. It runs synthetic tests and self-tests without collecting host security evidence. `test-live` runs the real unprivileged collectors and writes private temporary reports. Complete the [privileged smoke checks](#privileged-smoke-checks) for a first release and whenever the corresponding code changes. Review and rotate confirmed exposed credentials before publishing, and remove sensitive content from every Git ref intended for publication.

The tree guard checks the paths and modes of Git blobs. Gitleaks checks commit history on available refs, including detached `HEAD`. Review all text and binary inputs for personal data and internal information as well. Use the local `--details` option on either checker to investigate a failure in a private terminal.

## Build and publish

Once the matching commit has passed the required checks on `main`, create a reviewed `vMAJOR.MINOR.PATCH` tag. A push of the tag triggers [Release](../.github/workflows/release.yml). The build runs only for a protected tag in a public repository. It verifies ancestry, runs fast checks, scans Git history and builds an archive from the tag's committed tree with `git archive`. The protected release job verifies the checksum, attaches GitHub build provenance to the archive and creates a draft release. Review the draft, its tag and notes before publishing. Tag publication is a maintainer action.

To reproduce the packaging locally, pass a tag that already exists and a new output directory outside the checkout.

~~~sh
./tools/ci/build-release.sh v1.0.0 /path/to/new-release-output
~~~

From the downloaded assets directory, verify the files first.

~~~sh
shasum -a 256 -c agentic-macos-security-toolkit-v1.0.0.tar.gz.sha256
gh attestation verify agentic-macos-security-toolkit-v1.0.0.tar.gz --repo OWNER/agentic-macos-security-toolkit
~~~

[GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) provide provenance for the CI-built archive. The GitHub-generated source downloads are separate assets.

## Dependency maintenance

| Dependency | Where it is managed |
| --- | --- |
| macOS system utilities | Use supported, patched macOS releases. Read Apple's advisories for the installed branch. |
| `jq` | Confirm it is available before running the toolkit. Keep the system up to date where macOS provides it. CI uses a pinned upstream binary. |
| Optional local scanners | Inventory with `./bin/macos-security dependencies`. Review the upstream release, Homebrew formula or cask, advisory and test results before upgrading. |
| CI command-line tools | Version, selected platform asset and SHA-256 are pinned in [`.github/ci-tools.json`](../.github/ci-tools.json). Verify the upstream release, digest and publisher when updating a pin. Run the adapter canary when updating Gitleaks. |
| GitHub Actions | Dependabot proposes weekly SHA updates. Review the upstream change and verify the new full commit belongs to the intended release. Keep the version comment with the pin. |

The weekly Security workflow reports upstream CLI releases and recent public GitHub advisories for CI tools, listed scanners and Actions. Review advisories even if the release tag is unchanged. GitHub Dependabot alerts do not cover SHA-pinned Actions in the same way as semantic-version references. The project has no application package lockfile. Dependency Review uses the dependencies and advisories GitHub can identify in a change. Neither the advisory report nor an integrity hash assesses the behaviour of a downloaded program.

The same workflow checks the age of the [macOS update catalogue](../config/macos-updates.json) and looks for newer public Apple assets. Review the corresponding security bulletins before updating these pins. The [maintenance procedure](local-workflows.md#check-updates-and-visibility) records the review date and expiry.

[Dependabot for Actions](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot) · [Dependency Review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review) · [Apple security releases](https://support.apple.com/100100)

## Privileged smoke checks

Use a clean disposable macOS VM with a restorable snapshot and a local console. Keep fixtures and results inside the VM. Give the terminal only the permissions required for the current check.

| Check | Expected result |
| --- | --- |
| Run a normal quick assessment | It completes or reports scoped visibility gaps and makes no background-item permission request. |
| Run an assessment with `--background-items`; exercise both denial and permitted access | The assessment remains usable. The background-items evidence matches the permission outcome. |
| Run `monitor` unprivileged, then run a bounded `sudo` session with the access required by Apple for `eslogger` | Unprivileged output marks partial Endpoint Security visibility. The privileged timeline can capture a benign process event without command arguments or environment entries. |
| Interrupt a privileged monitor while it is running | The logger and normaliser exit, the FIFO is removed and the previous completed `latest` remains available. |
| Review a firewall stealth-mode remediation plan, apply it and follow its rollback command | The planned state is verified, a post-apply read confirms it and the rollback restores the recorded state. Restore the snapshot at the end. |

The fixture tests cover process control, failed collectors, redaction and command contracts. The VM checks cover macOS approvals and system behaviour.
