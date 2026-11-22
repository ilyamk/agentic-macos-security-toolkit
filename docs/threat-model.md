# Threat model

This is the threat model for a personal or developer Mac assessed with this repository. The detailed, per-attack view (how each attack works, what it compromises, how to prevent and detect it) is in the [attack catalogue](attack-catalogue.md); IDs `ATK-01` to `ATK-26` below refer to it.

## Assets

| Asset | Examples |
|---|---|
| Passwords and Keychain | Login password, login Keychain, password-manager vault |
| Browser sessions | Cookies and tokens for e-mail, cloud consoles, code hosting, exchanges |
| Developer credentials | SSH keys, cloud credentials, registry and Git hosting tokens, AI provider keys |
| Source code and signing keys | Private repositories, code-signing and package-publishing identities |
| Crypto wallets | Browser-extension and desktop wallets |
| Messaging sessions | Desktop messaging apps whose session files live in the user's Library |
| The machine | Integrity of macOS, persistence, remote access |
| Downstream systems | CI/CD and production reachable through developer credentials |
| The AI agent's authority | Commands, file edits, commits and tokens an agent can use on the owner's behalf |

## Adversaries

- **Opportunistic infostealer operators.** The most likely threat. Commodity stealers sold as a service, delivered by fake installers, malvertising, ClickFix and fake password prompts (ATK-01 to ATK-04). Goal: fast theft of credentials, sessions and wallets.
- **Supply-chain attackers.** Malicious or hijacked packages, poisoned releases, typosquats and AI-hallucinated names, third-party taps, tampered downloads and long-term upstream backdoors (ATK-05 to ATK-10, ATK-23). Goal: developer tokens and access to downstream users.
- **Targeted actors.** Criminal groups or states focusing on one person or organisation, using tailored phishing, deepfakes and, at the top end, exploit chains (ATK-25, ATK-26).
- **Malicious insiders and compromised collaborators.** A trusted contributor, a hijacked colleague's account or a booby-trapped repository or extension (ATK-08, ATK-18).
- **AI-agent misuse.** Prompt injection steering a coding agent, malicious or unpinned MCP servers, and malware invoking locally installed AI CLIs to hunt for secrets (ATK-19, ATK-20). The agent is both a target and a tool for the attacker.
- **Physical and local-network attackers.** Theft of the device or access through exposed services (ATK-21, ATK-24).

## Trust boundaries

- **User account versus root.** Most attacks never need root: everything the user can read (home directory, credential files, browser profiles) is reachable by any process the user starts. Root and System Integrity Protection protect the operating system, not the user's data.
- **TCC and permission inheritance.** TCC attributes access to the responsible app. Anything launched from a terminal or IDE (scripts, package installs, AI agents) inherits that app's Full Disk Access, Automation and Accessibility grants (ATK-16).
- **Environment inheritance.** Secrets exported by shell startup files reach every child process, including install scripts and agents (ATK-13).
- **Package registries and taps.** npm, PyPI and Homebrew taps deliver code that executes at install time; a tap is a trust decision about its author (ATK-05, ATK-09).
- **Vendor downloads and self-updaters.** Gatekeeper, notarisation and the quarantine attribute protect downloads from browsers; `curl` downloads and in-app updaters bypass parts of that chain (ATK-02, ATK-10).
- **Browser.** Extensions and native messaging hosts cross from the web into the browser and from the browser onto the host (ATK-17).
- **Agent input.** Repository files, issues, web pages and tool output are untrusted data, not instructions (ATK-19). This repository applies the same rule to its own evidence.

## Assumptions

- macOS is current or close to current, with SIP, the Signed System Volume and Gatekeeper enabled; their absence is reported as a configuration finding.
- The owner can approve changes; the tool itself never changes the host except through a reviewed, explicitly applied remediation plan.
- The daily account may be an administrator, which is common on personal Macs and is treated as part of the risk.
- Collection is bounded in time and scope. Anything not collected is a visibility gap, never a clean result.

## Out of scope

- **Mercenary spyware and exploit chains** (ATK-26). The tool reports whether Lockdown Mode is on; it cannot detect such implants. People at elevated risk should enable Lockdown Mode and seek specialist incident response.
- **Firmware, hardware and supply-chain tampering of the device itself.**
- **Server-side compromise** of registries, code hosting or cloud providers, beyond reducing what laptop credentials can do.
- **Real-time prevention.** Blocking is delegated to macOS, Objective-See tools, Santa or an EDR; this repository observes and reports their state.

## How the layers map

| Layer | Question it answers | Typical attacks |
|---|---|---|
| Posture (`assess`) | Are platform controls on and remote services as expected? | ATK-03, ATK-12, ATK-21, ATK-24, ATK-26 |
| Triage (`assess`, `incident`) | What is running, persisting, listening or recently downloaded now? | ATK-01, ATK-02, ATK-15, ATK-17, ATK-21 |
| Native collectors | Shell startup, credential file permissions, native messaging, Homebrew, background updates | ATK-02, ATK-13, ATK-15, ATK-17 |
| Adapters | KnockKnock, ClamAV, YARA, osquery, Santa, mSCP | ATK-01, ATK-03, ATK-15 |
| Monitor (`monitor`) | What changed during a bounded window; with root, Endpoint Security events | ATK-01, ATK-03, ATK-15, ATK-16, ATK-21 |
| Project scan (`dev-scan`) | Vulnerable dependencies, misconfiguration and secrets in one project | ATK-05 to ATK-08, ATK-13, ATK-18, ATK-23 |
| Project preflight and agent audit | Execution triggers in selected project files and declared agent/MCP permissions | ATK-18, ATK-19, ATK-20 |
| Workstation audit (`tools/workstation-audit/`) | Is developer tooling (Homebrew, npm, pnpm, Node, uv, shell rc, Objective-See, TCC, MCP) configured defensively? | ATK-05 to ATK-11, ATK-13, ATK-16, ATK-19, ATK-20 |
| Playbooks ([`playbooks/`](../playbooks/)) | How to fix it, step by step | Most, through PB-01 to PB-04; the catalogue matrix marks attacks with no playbook |

Findings are classed as `configuration`, `exposure`, `anomaly`, `detection` or `visibility_gap`. A weak setting is not evidence of compromise, and a clean bounded snapshot is not proof of absence. See [AGENTS.md](../AGENTS.md) for how an agent must phrase each class, and the [attack catalogue](attack-catalogue.md#how-to-use-this-catalogue-with-an-agent) for mapping findings to attacks.
