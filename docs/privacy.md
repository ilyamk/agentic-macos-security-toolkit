# Privacy and retention

Reports use private directories (`0700`) and files (`0600`) and are excluded from Git. Secret values, browser content, environment variables, and full process arguments are not collected into normalized artifacts. Gitleaks output is reduced to redacted metadata. VirusTotal upload and online hash lookup are disabled.

When saving a report, use the default results directory, a directory ignored by Git, or a path outside a checkout. The tools check output paths they open. If you redirect stdout in your shell, choose and protect the destination there.

For a portable summary, run `assess --redact`. The assessment builds the summary from a fixed set of fields and discards raw artefacts after collection. Findings, severity, timestamps and coverage remain available. Standalone `posture --redact` masks selected identifiers and still emits diagnostic data. Inspect any report before sharing it.

For agent hand-off, use `report export REPORT_DIR --audience agent`. The export contains fixed categories, ordinals, coverage totals and a bundle fingerprint. Set the output path explicitly with `--output FILE` to apply the normal private-output checks.

Treat reports as sensitive host inventory. Transfer only through an approved encrypted channel and retain only as long as required. Use `reports list` and `reports prune --plan --older-than DAYS` to review local retention. The owner controls deletion. Root/FDA runs expose more data than normal user runs. Keep original network provider exports private.
