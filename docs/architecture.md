# Architecture

The v4 pipeline separates facts from interpretation:

1. Native collectors and optional adapters write immutable raw evidence plus normalized observations.
2. Detectors transform observations into findings without changing the host.
3. Policy marks expected services and determines which findings require review.
4. Reporting produces coverage, agent context, summaries, diffs, evidence hashes, and remediation plans.

`bin/macos-security` is the preferred entry point. Existing top-level scripts remain compatibility interfaces. Adapter installation is restricted by the static mapping in `lib/macos_security_dependencies.sh`; configuration can select an adapter but cannot choose an arbitrary package or executable.

Real-time prevention is intentionally external. Santa or an EDR can be installed and its health observed, while periodic shell collection remains bounded and read-only.

The standalone [local workflows](local-workflows.md) share the CLI and report path guards. They inspect selected configuration files and consume existing assessments. Agent export validates the source bundle and projects only fixed categories, ordinals and typed actions. Optional outbound telemetry is imported as a separate monitoring artefact, with observed coverage recorded independently from Endpoint Security.
