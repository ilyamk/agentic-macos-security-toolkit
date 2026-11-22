# Workstation audit fixtures

Host-free inputs for `tests/unit/test_workstation_audit.sh`. Top-level entries named
`dot-NAME` under `*/home/` are copied to `.NAME` in a temporary home at test time, so
no real dotfile is committed. Node/npm trees, application bundles and the TCC
database are created by the test. All names and values are placeholders.

- `hardened/`: every relevant check passes.
- `weak/`: the expected warnings listed in the test.
- `bin/`: fake `brew` and `gh` returning canned data; `brew` refuses any
  subcommand outside the audit's read-only allow-list.
