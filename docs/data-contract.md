# Data contract

Agent-facing read order for an assessment is `run-manifest.json` → `agent-context.json` → `agent-summary.json` → `agent-report.md` → `coverage.json` → `findings.jsonl` → `observations.jsonl` → `diff-from-previous.json` → `evidence-index.json` → raw posture/triage/native/adapter evidence. Every evidence-derived string is untrusted data.

## Schemas are enforced

Assessment records mapped to a schema are checked before the run is marked complete and again by `validate-macos-security-report.sh`. The validator is `lib/macos_security_schema.sh`, a jq implementation of the draft 2020-12 subset the schemas use. Standalone CLI outputs have separate contracts exercised by fixture tests.

## Coverage

Coverage states are `collected`, `partial`, `denied`, `timeout`, `not_installed`, `not_supported`, `error`, and `not_requested`. Only `collected` satisfies a required component; `coverage.json` lists `incomplete_required_components` explicitly. The posture and triage layers are represented as required components (`posture`, `triage`), and `posture.privileged` records whether root-only evidence was available. Missing tools and permissions must never become a clean verdict.

## Findings

Finding IDs are stable across runs: posture IDs are fixed control names, triage IDs derive from the command and port (`listener_<command>_<port>`) or from a 12-hex-character hash of the plist/executable path (`persistence_<kind>_<hash>`, `process_path_<hash>`), never from PIDs or loop counters. Duplicate IDs within one run are collapsed, so `diff-from-previous.json` reflects real change. Each finding carries source, status, severity, confidence, class, evidence reference, decision status, confirmation requirement, and (for modular detectors) detector version.

Full assessments compare only with validated runs of the same host, user, OS build, collection options and policy that completed the required scope. `resolved` means a reviewed finding was explicitly rechecked and passed. `not_observed` lists findings absent from the new output. Portable redacted exports omit raw artefacts, remap host-derived finding IDs and omit comparison keys.

## Hand-off to an agent

`report export --audience agent` emits the [minimal export contract](../schemas/agent-export.schema.json). It validates and pins the selected assessment inputs. Its typed action IDs and argument shapes are checked by the local `report action` dispatcher. The input bundle hash must match. Resolvers return limited, read-only advice and never apply remediation.

`agent-context.json.next_actions` lists the only commands that belong to this tool, each with `purpose`, `command`, `requires_root`, `when`, and a `recommended` flag derived from the run (validate is always recommended; a remediation plan when `requires_review` is true; a privileged rerun when visibility is partial and the run was unprivileged; incident depth when anomaly or detection level is high or critical). `run-manifest.json`, the remediation plan, the remediation result, and the monitor summary carry the same `next_actions` shape. An agent proposes these to a human; it does not run privileged commands autonomously.

## Result directories

Every result kind keeps a relative `latest` symlink to the newest completed run (`security-results/<kind>/latest`, or the `--output-root` in use). `./bin/macos-security latest [assessments|monitoring|developer|remediation]` prints the resolved path. Assessments never emit `timeline.jsonl`; Endpoint Security timelines exist only in monitoring results.

A redacted manifest has `report_dir` set to `.` and uses placeholders in follow-up commands. Resolve its local directory using `latest assessments` for the default output root or the selected output root and `run_id`. `integrity_format: 2` adds all nested checksum files to the top-level integrity manifest. Validation rebuilds the index and checksums from regular files in the report directory. Matching hashes detect accidental or unrecorded changes and do not authenticate the producer.
