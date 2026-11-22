# Adapter authoring

An adapter must have a static identifier and Homebrew mapping, explicit timeout, private raw output, normalized observations/findings, and a coverage record. It must document exit-code semantics, privilege/network needs, false-negative limits, and whether it can modify the host.

Adapters must not use `eval`, execute values from evidence, auto-upload files or hashes, delete/quarantine findings, grant TCC/FDA, enable blocking mode, or install packages outside the dependency allowlist. New adapters require fixture tests for success, timeout, invalid output, missing dependency, and redaction.
