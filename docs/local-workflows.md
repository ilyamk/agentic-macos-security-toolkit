# Preflight, agent permissions and local follow-up

Run these commands from a trusted checkout or verified release of the toolkit. The local inspection commands use macOS tools and standard Homebrew binary locations for `jq`. They inspect the selected data offline unless you explicitly request a Software Update query.

## Check a project before opening it

~~~sh
project="$HOME/Downloads/example-project"
./bin/macos-security repo-preflight "$project"
./bin/macos-security agent-audit --project "$project"
~~~

`repo-preflight` inspects a fixed list of files at the selected root. Each review item gives a relative path, the line when available and the action that could trigger execution. It checks standard executable Git hooks, a local `core.hooksPath` declaration, workspace tasks and settings, direnv, npm project configuration, package lifecycle scripts, Dev Container settings and agent configuration. Review custom hook locations, linked Git worktree metadata, nested repositories and inherited Git/editor policies separately. A file declaration is evidence of something to review. Activation depends on the client, workspace trust and user policy.

The scanner reads configuration as data. Files above 512 KiB, symlinked inputs and unsupported Git metadata are reported as a coverage gap. Use `--json` for automation. Exit `0` means the selected checks found no review items, `1` means review is needed, and `2` means the selected scope was incomplete or the command failed. Review the result before continuing to dependency or vulnerability scanning with `dev-scan`.

`agent-audit` inspects supported user settings and, with `--project`, root project settings for Claude, Cursor and Codex. It reports declared sandbox and approval settings, broad root declarations, counts of local and remote MCP definitions, cleartext HTTP, likely inline credentials and counts of explicit OAuth scopes in supported JSON. Credentials, hosts, paths, server names and executable strings stay out of the output. Use `--json` for a snapshot and `--baseline FILE` to compare it later. With `--home DIR`, the audit reads an explicitly selected fixture or user home.

Codex TOML support uses heuristics for common declarations. The JSON readers cover named fields in recognised configurations, including Claude's registered entry for the selected project. Reported drift compares per-file flags and counts, so a server substitution with the same counts can require a manual review. Effective grants, inherited or managed settings, and server-side authorisation remain unknown. A configuration flag can warrant review even when the corresponding feature is currently inactive. Exit `1` signals a review flag or expanded declaration, and `2` signals unreadable or unparsed configuration or a command failure. Read `coverage` separately from the exit status.

[Model Context Protocol authorisation considerations](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx) · [OWASP MCP Security](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

## Give an agent a minimal assessment

~~~sh
report="$(./bin/macos-security latest assessments)"
./bin/macos-security report export "$report" --audience agent
~~~

The export validates the completed assessment and emits review status, severity, confidence, classification, aggregate coverage and typed follow-up actions. For recognised checks it includes a label selected from a fixed control list. It lists at most 100 review records in severity order, and gives the total count and a truncation flag. An ordinal identifies a record inside this bundle only. The export contains no report prose, paths, raw evidence, or shell commands. To save it to a new private file, pass `--output FILE`.

The supported action identifiers are `review-coverage` with empty arguments and `review-finding` with a positive integer `ordinal`. Resolve them locally using the same assessment directory and the export's `bundle_sha256`.

~~~sh
bundle="$(./bin/macos-security report export "$report" --audience agent | jq -er .bundle_sha256)"
./bin/macos-security report action "$report" --bundle "$bundle" review-coverage
~~~

Action results are read-only and use the same restricted data. The digest binds the action to one checksum manifest. Establish the report's origin separately. Treat all results as untrusted observations. The owner reviews and separately authorises any privilege escalation or system change using the documented workflow.

## Check updates and visibility

~~~sh
./bin/macos-security doctor --json
./bin/macos-security updates status
~~~

`doctor` explains default collection behaviour for the selected policy, whether binaries are present, and which checks need permission or further work. It counts empty or relative `PATH` entries without printing paths. Full Disk Access and the Endpoint Security grant remain unknown until independently established. The command does not open System Settings or start protected collectors.

`updates status` compares the installed version with the reviewed entry for the same major branch in [the local catalogue](../config/macos-updates.json). It prints the installed build and any recognised supplemental version reported by macOS. A missing supplemental value leaves the installed supplemental state unknown. Availability comes from the separate opt-in `--online` query. A restart marker in a Software Update offer applies to that offer. A pending restart after an installed change remains unknown.

Run the comparison with `--mscp-metadata FILE` to attach an owner-supplied mSCP release and profile label. An example of the [metadata contract](../schemas/mscp-metadata.schema.json) follows.

~~~json
{"schema":"macos-security-mscp-metadata/v1","release":"release_27.1","profile":"example_baseline"}
~~~

For importing actual mSCP audit evidence into an assessment, use the existing `assess --mscp-report FILE` workflow. Match the profile to the installed macOS and review the imported material locally.

The catalogue lists the reviewed versions, source bulletins, review date and expiry. An expired or future-dated catalogue yields `stale`. An unlisted branch yields `unlisted`. Scheduled CI checks catalog freshness and flags newer public assets for review. To refresh the catalogue, check each branch against Apple security bulletins, update its version, release date and source, and set the new review and expiry dates. Asset availability varies with hardware and management policy.

[Apple security releases](https://support.apple.com/en-us/100100) · [Apple Software Lookup Service](https://developer.apple.com/documentation/devicemanagement/deploying-software-updates-using-declarative-management) · [NIST mSCP](https://pages.nist.gov/macos_security/)

## Review backups and report retention

~~~sh
./bin/macos-security recovery check --report "$report"
./bin/macos-security reports list
./bin/macos-security reports prune --plan --older-than 30
~~~

`recovery check` reads Time Machine evidence from a validated local assessment. Without `--report`, it looks for the latest CLI assessment. A recognised backup path is reduced to a calendar date and age in days. The point-in-time assessment date is included when available. Portable redaction, missing evidence and unrecognised output yield `unknown`. For the restore drill, see [PB-05](../playbooks/PB-05-updates-and-recovery.md).

`reports list` inventories child run directories owned by the caller in the toolkit's standard and legacy report roots. The prune plan includes old entries with completion markers and keeps the newest marked-complete run per root, the current `latest` target and incomplete runs. Age uses directory modification time. The list only previews candidates. Review them in a private terminal before deleting anything. Use `validate` when you need to verify a particular assessment's evidence and checksums.

## Import outbound network observations

Use a trusted exporter from your existing firewall, extension or EDR to prepare JSONL. Map each outbound flow to the [network observation contract](../schemas/network-observation.schema.json). The exporter should provide UTC timestamps to second precision, a protocol, the observed decision and, when available, PID and the process creation time in Unix microseconds. Populate `process_start_us` only when the timestamp refers to the same machine and process generation as Endpoint Security.

~~~json
{"schema":"macos-security-network-observation/v1","direction":"outbound","observed_at":"2026-01-01T00:00:05Z","protocol":"tcp","decision":"allowed","remote_scope":"public","pid":33,"process_start_us":1767225600000100}
~~~

~~~sh
./bin/macos-security network import "$network_jsonl" --timeline "$timeline_jsonl"
./bin/macos-security monitor --duration 60 --network-jsonl "$network_jsonl"
~~~

The standalone import can use an explicit `--from` and `--to` window. The provider input is limited to 2 MiB, 4,000 observations and 8 KiB per line. Monitoring uses its own session window, adds `network.json` when import succeeds, and marks malformed imports as a visibility gap. It saves the normalised fields and drops destination strings, packet contents, vendor messages and arbitrary extra fields. Keep the original provider export private.

Correlation requires an unambiguous Endpoint Security exec record with the same PID and process start, with the flow within five minutes after exec. Missing or conflicting identifiers leave the entry uncorrelated. Imported coverage stays unknown and the matched records are investigation leads. The toolkit never starts the provider or changes its filter policy.

[Apple Network Extension](https://developer.apple.com/documentation/networkextension/) · [Apple process start time](https://developer.apple.com/documentation/endpointsecurity/es_process_t/start_time)
