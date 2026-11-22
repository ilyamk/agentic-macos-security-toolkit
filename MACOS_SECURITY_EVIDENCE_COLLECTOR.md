# macOS Security Evidence Collector

This document describes `macos-security-posture.sh`, a
dependency-free, read-only posture collector for macOS. It emits one
complete JSON object per line to stdout by default. It does not change system settings,
invoke `sudo`, install software, or upload data.

## Run

Run these commands from the project directory. Each `--output` requires a new
directory and writes `posture.jsonl` inside it. Use a fresh directory name when
repeating a run.

```sh
./macos-security-posture.sh --output security-results/posture
```

For the broadest local evidence (PF, audit configuration and system TCC), run
it as root only when authorized:

```sh
sudo ./macos-security-posture.sh --deep --online --output security-results/posture-online
```

Useful modes:

```sh
# Fast posture check
./macos-security-posture.sh --quick --output security-results/posture-quick

# App signature metadata, BTM, TCC and filtered security logs
sudo ./macos-security-posture.sh --deep --log-hours 48 --output security-results/posture-deep

# Best-effort masking before giving the report to an external agent
./macos-security-posture.sh --redact --output security-results/posture-redacted

# CI/compliance-style exit status (1 when FAIL findings exist)
./macos-security-posture.sh --quick --fail-on-findings --output security-results/posture-ci
```

Validate and summarise with `jq` if it is available:

```sh
jq -s '{meta: map(select(.record_type=="meta"))[0], findings: map(select(.record_type=="finding")), summary: map(select(.record_type=="summary"))[0]}' security-results/posture/posture.jsonl
```

The output can contain usernames, local addresses, installed software,
configuration profiles, persistence data and—under `--deep`—TCC grants and
security logs. `--redact` is best effort; always inspect a report before
sharing it outside the intended security boundary.

## Coverage and interpretation

The collector covers OS/build/architecture, updates, SIP, Authenticated Root,
FileVault, Gatekeeper, XProtect assets, boot policy, kernel/system extensions,
accounts, screen lock, USB Restricted Mode, remote services, firewall/PF,
interfaces, routes, DNS, proxies, VPN, listeners, MDM, persistence, application
signature metadata, TCC, selected logs, APFS, Time Machine, USB, auditd and
custom trust settings.

Use `--background-items` to request the protected login and background-item
inventory. macOS may prompt for permission. Deep mode records launch plist
metadata and omits the full plist contents.

`UNKNOWN`, `DENIED`, `ERROR`, and `TIMEOUT` are coverage states, not equivalent
to an insecure host. A security agent should correlate findings with the Mac's
role, threat model, MDM policy, approved exceptions, process ownership and
network reachability. The script is not a substitute for EDR telemetry,
vulnerability management or forensic acquisition.

## Research basis (snapshot 2026-08-27)

The collector has a patch reference of macOS 26.6.2 from the research date. For
other major releases, use Apple's security release page. Use `--online` to
check which updates are available for the Mac at the time of the run.

- [Apple security releases](https://support.apple.com/100100)
- [Apple Platform Security](https://support.apple.com/guide/security/welcome/web)
- [Gatekeeper and runtime protection](https://support.apple.com/guide/security/sec5599b66df/web)
- [FileVault volume encryption](https://support.apple.com/guide/security/sec4c6dc1b6e/web)
- [System Integrity Protection](https://support.apple.com/102149)
- [Background updates in macOS](https://support.apple.com/101591)
- [macOS Security Compliance Project (NIST mSCP)](https://pages.nist.gov/macos_security/)
- [CIS Benchmark for macOS](https://www.cisecurity.org/benchmark/apple_os)

## Verification

```sh
make lint
make test
```

`make test` runs a live quick collection on macOS and parses every JSONL record
with `jq` when available.
