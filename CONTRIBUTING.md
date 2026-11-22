# Contributing

Help make the toolkit useful on more Macs. Documentation fixes, reproducible bug reports and synthetic test cases are welcome alongside collectors, checks and integrations.

## Find a contribution

| If you want to help with | A useful first change | Where to look |
|---|---|---|
| Documentation | Try a Quick start or playbook command and improve a confusing step, permission explanation or expected result. | [README](README.md), [playbooks](playbooks/README.md) |
| macOS compatibility | Reproduce a parsing or permission issue on your macOS version. Add a sanitised fixture and make the check distinguish a failed control from unavailable evidence. | [Test fixtures](tests/fixtures/), [Unit tests](tests/unit/) |
| Agent and project safety | Add a synthetic configuration case for execution triggers, declared MCP permissions or a report hand-off edge case. | [Local workflows](docs/local-workflows.md), [Local adviser tests](tests/unit/test_local_advisers.sh) |
| Platform controls and detections | Add a bounded, read-only check for a documented macOS control. Describe the evidence, coverage limits and how a user can verify the result. | [Native collectors](collectors/native/), [Detectors](detectors/), [Attack catalogue](docs/attack-catalogue.md) |
| Tool integrations | Add a fixture for an optional scanner's output or document how to convert a network provider's export to the existing observation format. | [Adapter authoring](docs/adapter-authoring.md), [Network import](docs/local-workflows.md#import-outbound-network-observations) |

The [roadmap](README.md#roadmap) lists larger gaps. For a new collector, adapter or change to a public report contract, a short issue with the use case, evidence source, permission requirements and proposed output helps coordinate the work.

## Work locally

Fork the repository, clone your fork and create a topic branch. Use macOS with `jq`, ShellCheck and `make` on your PATH for the full fast suite. A documentation change can start with checking links and examples.

```sh
git switch -c docs/clarify-audit-check
make test-fast
git diff --check
```

`make test-fast` runs ShellCheck, JSON contract checks, self-tests and fixture tests. Run `make test-live` on a Mac you control when a change depends on actual system behaviour. Run it without `sudo` and keep the resulting evidence private. Use the disposable VM procedure for tests involving elevation, protected permissions or remediation. [Privileged smoke checks](docs/releasing.md#privileged-smoke-checks)

## Keep changes safe and testable

- **Shell and collection.** Use POSIX `sh`, the existing helpers and absolute paths for system binaries. Bound commands that can block. Keep collection read-only by default and use the existing policy gates for network access, optional installation and privilege.
- **Evidence and reports.** Keep finding and check IDs stable across runs. Record PIDs and timestamps in evidence fields and mark missing visibility explicitly. Put report contracts in `schemas/` and cover a behaviour change with a focused regression test. Treat paths, names and strings from tools as data throughout the pipeline. [Data contract](docs/data-contract.md)
- **Privacy.** Build fixtures from synthetic data such as `example-user` and `/Users/example`. Check for secret and identifier leakage when changing an evidence or redaction path. Keep real reports, tokens and host identifiers out of commits, issues and pull requests. [Privacy and retention](docs/privacy.md)
- **Adapters.** Document exit codes, timeouts, dependency and network requirements, and coverage limits. Exercise success, missing dependency, timeout, invalid output and redaction with fixtures. [Adapter authoring](docs/adapter-authoring.md)
- **Playbooks and docs.** Write in British English. Give readers a verification step, cite primary sources for platform behaviour, and map new findings to relevant check and attack catalogue IDs. Update the operating manual when a script, schema or contract changes. [Playbook format](playbooks/README.md) · [Agent operating manual](AGENTS.md)

## Open a pull request

Push the topic branch to your fork and open a pull request against this project's default branch. Describe who it helps, the behaviour it changes and how you checked it. For a bug fix, include a minimal reproduction and the expected result. For a macOS-specific issue, include the macOS version, CPU architecture and whether the run was elevated. List the commands you ran, their results and any checks still pending. Use a small synthetic example when showing output.

File public issues for ordinary bugs, documentation gaps and feature proposals. Use the private reporting procedure for vulnerabilities or disclosures involving credentials or sensitive evidence. [Security policy](SECURITY.md)
