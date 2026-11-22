# macOS security and monitoring tools — 2026

> A practical catalogue of command-line utilities and Homebrew packages for malware and infostealer detection, auditing, system monitoring, forensics, network privacy and careful cleanup.

The research snapshot is dated **27 August 2026**. It covers modern macOS releases, primarily on Apple silicon, with compatibility statements tied to the specified OS versions. The original notes record local checks of built-in command availability on **macOS 26.6.2, build 25G83**, with **Homebrew 6.0.20**. Sources include Apple and vendor documentation, official repositories, releases and Homebrew analytics APIs.

Versions, popularity figures and activity labels below describe that historical snapshot. Check the selected release and its security advisories before installation. The recorded analytics and original local checks have not been independently reproduced for this English edition.

## Overview

Most personal Macs can use the following manageable set of tools.

1. Keep Gatekeeper, XProtect, SIP and automatic security updates enabled. Enable FileVault and the built-in firewall.
2. Use **KnockKnock** and **EtreCheckPro** for periodic audits.
3. Use **BlockBlock** and **LuLu** for ongoing observation of persistence and outbound traffic.
4. When infection is suspected, use **Malwarebytes** as a straightforward second scanner. **ClamAV** is particularly useful for command-line automation and bounded sets of files.
5. For technical investigation, use the built-in **eslogger**, **Mac Monitor**, **TaskExplorer**, **YARA-X** and carefully authorised hash lookups through **VirusTotal CLI**.
6. For enterprise protection, assess **Santa**, **osquery/Fleet**, **NIST mSCP** and, where DFIR infrastructure exists, **Velociraptor**.

A clean scan cannot establish that a Mac is free of malware. Modern macOS infostealers often rely on social engineering that asks users to run commands, remove quarantine attributes or enter an administrator or keychain password. Execution control, persistence monitoring and outbound connection visibility therefore deserve the same attention as signature scans. Objective-See's 2025 report identifies infostealers as the most prevalent category of newly observed macOS malware. [The Mac Malware of 2025](https://objective-see.org/downloads/MacMalware_2025.pdf)

## How to read the ratings

Popularity figures use the following thresholds for the snapshot from 27 August 2026.

- **Very high** means at least 10,000 GitHub stars or 10,000 Homebrew installations over 30 days.
- **High** means at least 3,000 stars or 3,000 installations over 30 days.
- **Notable** means at least 500 stars or 100 installations over 30 days.
- **Niche** covers lower figures and specialist tools with a narrow professional audience.

`HB30` denotes a formula's `install-on-request` count or cask installation count over the preceding 30 days. The original research used Homebrew's JSON API and GitHub's API for stars and activity dates. These figures change quickly and provide only context. [Homebrew JSON API](https://formulae.brew.sh/docs/api/)

The compatibility and maintenance labels describe the evidence available at the snapshot date.

- **macOS 26** means the developer explicitly documented support or validation for macOS 26.
- **Active** means a recent release or visible development in 2026. Installation on macOS 26 was available at the snapshot date, although an explicit compatibility matrix might be absent.
- **Conditional** means the tool runs or is distributed for modern macOS but has testing or maintenance gaps.
- **Legacy/limited** means the tool serves a specific use case and offers limited coverage for a primary macOS protection role.

## 1. Built-in protection and macOS command-line tools

Apple describes three layers of malware protection. App Store checks, Gatekeeper and notarisation help prevent execution. XProtect blocks known malware and can remediate malware that has already run. Signatures update independently of full OS upgrades, and recent releases also include behavioural detection. [Apple Platform Security — protecting against malware](https://support.apple.com/guide/security/sec469d47bd8/web)

| Tool | What it shows | Practical value |
|---|---|---|
| **XProtect + XProtect Remediator** | Built-in detection, blocking and removal of known threats. XProtect also emits structured events through Endpoint Security. | An installed baseline layer. It has a different operating model from a user-initiated full-disk scan. Keep background security updates enabled. |
| **Gatekeeper / `spctl`** | Whether Gatekeeper policy permits an application or package to run. | A quick assessment of a downloaded `.app` or `.pkg`. Behaviour still needs separate analysis. |
| **`codesign`** | Signatures, Team ID, designated requirements, entitlements and Mach-O or app-bundle integrity. | Useful during triage. An unknown or ad hoc signature warrants investigation and needs corroboration before a malware verdict. |
| **`xattr`** | Extended attributes, especially `com.apple.quarantine` and download provenance. | Helps establish whether a file passed through the usual quarantine and Gatekeeper path. Absence of quarantine is inconclusive. |
| **`pkgutil`** | `.pkg` signatures, receipts and installed package file lists. | Useful for inspecting installers and auditing installed packages. |
| **`eslogger`** | A JSON stream of Endpoint Security events covering processes, files, SSH and login, Gatekeeper overrides, XProtect detection and remediation, and other activity. | A built-in sensor for live investigation. It requires root and Full Disk Access for the responsible Terminal or SSH context. Formats can change across releases. Apple presents it as an analysis tool. [WWDC22](https://developer.apple.com/videos/play/wwdc2022/110345/) |
| **`log show` / `log stream`** | Unified Log records selected by process, subsystem, category and time. | Supports historical and live observation. macOS may redact private fields. |
| **`systemextensionsctl`** | Installed System Extensions, including Endpoint Security and Network Extensions. | Covers modern system extensions alongside separate checks of older kernel extensions. |
| **`kmutil`** | Loaded and installed kernel extensions and kernel collections. | Useful for legacy drivers and unusual kernel extensions. Most modern security products on Apple silicon use System Extensions. |
| **`launchctl` + `sfltool dumpbtm`** | LaunchAgents, LaunchDaemons and Background Task Management. | Important persistence evidence. The `sfltool` output format can change, and the protected inventory may trigger a macOS permission prompt. |
| **`profiles`** | MDM enrolment and configuration-profile status. | Helps identify unexpected device management. Output can be incomplete without appropriate privileges or management context. |
| **`fdesetup`, `csrutil`, `softwareupdate`** | FileVault, SIP, and update state or history. | Three baseline posture checks. Use `csrutil` for status inspection in the running system. SIP changes require Recovery. |
| **`socketfilterfw`, `pfctl`** | Application Firewall and PF state. | `socketfilterfw` inspects the application firewall, while `pfctl` exposes lower-level packet filtering. Changes to system PF anchors require an understanding of the existing rules. |
| **`lsof`, `nettop`, `tcpdump`** | Listening sockets, process connections and network packets. | Helps investigate unexpected listeners or possible command-and-control traffic. Encrypted payloads usually remain unavailable. |
| **`system_profiler`, `ioreg`, `sysdiagnose`** | Hardware, software and extension inventories, plus broad diagnostic archives. | Useful for baselines and incident response. A `sysdiagnose` archive contains sensitive data and needs protected storage and transfer. |

Examples of read-only inspection commands follow. `softwareupdate --list` makes a network request, and the `sudo` command requires explicit authorisation.

```bash
sw_vers
softwareupdate --list
softwareupdate --history
csrutil status
fdesetup status
spctl --status
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
systemextensionsctl list
profiles status -type enrollment
kmutil showloaded
sudo lsof -nP -iTCP -sTCP:LISTEN
```

The following commands inspect an individual downloaded file or application.

```bash
spctl --assess --type execute --verbose=4 "/path/to/App.app"
codesign --verify --deep --strict --verbose=2 "/path/to/App.app"
codesign --display --verbose=4 --entitlements :- "/path/to/App.app"
xattr -l "/path/to/App.app"
pkgutil --check-signature "/path/to/Installer.pkg"
```

The following command observes live XProtect events and user overrides of Gatekeeper.

```bash
# Terminal needs Full Disk Access. Stop the stream with Ctrl-C.
sudo eslogger xp_malware_detected xp_malware_remediated gatekeeper_user_override
```

The original macOS 26 checks found `/usr/bin/xprotect`. Apple does not document a stable public command-line interface or manual page for that binary. Build automation around supported system interfaces and observe XProtect events through `eslogger`.

## 2. Malware, infostealer and persistence detection

### Scanners and triage tools

| Tool | Installation | Purpose | Popularity | Compatibility and maintenance |
|---|---|---|---|---|
| [Malwarebytes for Mac](https://www.malwarebytes.com/mac/) | `brew install --cask malwarebytes` | On-demand and real-time antivirus and potentially unwanted program detection. Useful as a second opinion for suspected adware or infostealers. | Notable, HB30 ≈405. | **macOS 26** is explicitly included in the vendor requirements. The snapshot cask was 5.26.1. [Requirements](https://help.malwarebytes.com/hc/en-us/articles/31589243089307-System-Requirements-for-Desktop-Security) · [Homebrew](https://formulae.brew.sh/cask/malwarebytes) |
| [ClamAV](https://www.clamav.net/) | `brew install clamav` | File and archive scans, with `freshclam` for signature updates, `clamscan` for one-off scans and `clamd` for automation. Useful for attachments and mixed Windows/macOS file sets. | High, 7.2k★ and HB30 ≈2,821. | **Active**, version 1.5.4 with development in 2026. The official macOS package is universal. Requires a signature database and has a different scope from an EDR. [Packages](https://docs.clamav.net/manual/Installing/Packages.html) · [Scanning](https://docs.clamav.net/manual/Usage/Scanning.html) |
| [YARA-X](https://virustotal.github.io/yara-x/) | `brew install yara-x` | Matches local files against rules. Its Mach-O module supports indicators of compromise and threat hunting. Rules must be supplied separately. | Notable, 1.3k★ and HB30 ≈58. | **Active**, version 1.20.0 with substantial development in 2026. A candidate for new custom rules. Check compatibility when migrating older YARA rules. |
| [YARA](https://github.com/VirusTotal/yara) | `brew install yara` | Widely used rule-based malware matching with a large ecosystem of existing rules. | Notable/high, 9.8k★ and HB30 ≈802. | **Active**, version 4.5.8. Useful where compatibility with existing rules or integrations is essential. |
| [VirusTotal CLI](https://virustotal.github.io/vt-cli/) | `brew install virustotal-cli` | Retrieves reports for SHA-256 hashes, domains, IP addresses and URLs. It can also upload samples. | Notable on GitHub, 1.5k★ and HB30 ≈62. | **Active**, version 1.3.1. Requires an API key. `vt scan file` sends the file to an external service. Keep documents, cookies, wallets, keys and private source code within the approved security boundary. [Command documentation](https://virustotal.github.io/vt-cli/doc/vt_scan_file.html) |
| [EtreCheckPro](https://etrecheck.com/) | `brew install --cask etrecheckpro` | Produces a readable inventory of software, launch items, extensions, performance and some security issues. It can identify and remove known malware. | Niche in Homebrew, HB30 ≈82. Widely used for diagnostic reports. | **macOS 26**, with specific support improvements in 6.8.16. Reports contain host inventory and need review before publication. [Changes](https://www.etrecheck.com/en/details.html) |

For a basic Homebrew ClamAV setup, create `freshclam.conf` from the supplied sample, remove its `Example` directive and update signatures using `freshclam` before scanning. On Apple silicon, Homebrew configuration usually resides in `/opt/homebrew/etc/clamav/`. Preserve a copy and validate a finding manually before considering quarantine or deletion. Keep `--remove` out of initial scans.

### Objective-See tools for macOS

The tools below are free and open source. They complement XProtect through behaviour and system artefact inspection. [Objective-See catalogue](https://objective-see.org/tools.html)

| Tool | Homebrew | Purpose | Popularity | Status |
|---|---|---|---|---|
| [LuLu](https://objective-see.org/products/lulu.html) | `brew install --cask lulu` | Controls outbound connections and shows the process, destination and ancestry. Can block command-and-control or exfiltration connections. The built-in macOS firewall primarily controls inbound traffic. | **Very high**, 13.1k★ and HB30 ≈1,976. | **Active**, version 4.5.1, macOS 10.15+, with 2026 updates. A free option for outbound application control. |
| [KnockKnock](https://objective-see.org/products/knockknock.html) | `brew install --cask knockknock` | Enumerates launch items, extensions, login items, cron and other persistence mechanisms. Saves JSON and compares scans. | Notable, 786★ and HB30 ≈571. | **Maintained**, snapshot version 4.0.3, macOS 10.15+. Useful for one-off persistence audits. Every listed item needs contextual interpretation. |
| [BlockBlock](https://objective-see.org/products/blockblock.html) | `brew install --cask blockblock` | Observes additions to persistence locations in real time. Recent versions also address command-pasting activity associated with ClickFix. | Notable, 836★ and HB30 ≈248. | **Active**, version 2.5.0 with 2026 updates and Endpoint Security support. Requires Full Disk Access. |
| [TaskExplorer](https://objective-see.org/products/taskexplorer.html) | `brew install --cask taskexplorer` | Displays processes, signatures, dylibs, open files, network activity, ancestry and VirusTotal information. Its CLI supports JSON with `-explore` and `-scan`. | Niche, 143★ and HB30 ≈156. Familiar to macOS researchers. | **Conditional**, version 2.1.0, macOS 11+. Useful on demand for investigation. |
| [RansomWhere?](https://objective-see.org/products/ransomwhere.html) | `brew install --cask ransomwhere` | Detects rapid creation of encrypted files by an unknown process and suspends that process. | Niche, 128★ and HB30 ≈67. | **Active**, version 2.2.0 with Endpoint Security and 2026 updates. Legitimate encryption can trigger false positives. Maintain backups. |
| [OverSight](https://objective-see.org/products/oversight.html) | `brew install --cask oversight` | Alerts on microphone and camera use and attempts to attach to an existing session. | Notable/niche, 675★ and HB30 ≈209. | **Conditional**, version 2.4.0, macOS 12+. Focuses on camera and microphone privacy. |
| [ReiKey](https://objective-see.org/products/reikey.html) | `brew install --cask reikey` | Detects and monitors persistent keyboard event taps, one possible keylogging mechanism. | Niche, 347★ and HB30 ≈54. | **Conditional**, version 1.4.2 with infrequent repository updates. Provides an additional signal with limited keylogger coverage. |
| [Netiquette](https://objective-see.org/products/netiquette.html) | `brew install --cask netiquette` | Associates sockets and connections with processes through a GUI and CLI. | Niche, 386★ and HB30 ≈66. | **Conditional**, version 2.3.0. Lighter than Wireshark, with less security context than LuLu or Mac Monitor. |
| [What's Your Sign?](https://objective-see.org/products/whatsyoursign.html) | `brew install --cask whatsyoursign` | Adds quick access to file code-signing information in Finder. | Niche, HB30 ≈34. | **Conditional**, version 3.2.2. A convenient interface for signature inspection. |
| [Dylib Hijack Scanner](https://objective-see.org/products/dhs.html) | `brew install --cask dhs` | Finds applications susceptible to dylib hijacking and possible hijack artefacts. | Niche, HB30 ≈31. | **Supported range**, version 1.6.0, macOS 11+. Findings require manual validation. |
| [ProcessMonitor / FileMonitor](https://objective-see.org/products/utilities.html) | `brew install --cask processmonitor filemonitor` | Endpoint Security command-line sensors that emit JSON for process and file activity. | Niche, HB30 ≈19/10. | **Legacy/conditional**, versions 1.5.0/1.3.0 with irregular source updates. On macOS 26, assess `eslogger` or Mac Monitor for the required event coverage. |

Choose one continuously running product for each task and run additional tools on demand. Installing several Endpoint Security or Network Extension products increases noise, privileged access and the chance of compatibility problems.

## 3. Detailed monitoring and execution control

| Tool | Installation | Purpose | Popularity | Maintenance and limitations |
|---|---|---|---|---|
| [Mac Monitor](https://github.com/Brandon7CC/mac-monitor) | `brew install --cask mac-monitor` | Captures and enriches Endpoint Security events covering execution, files, XPC, memory, login, XProtect and other activity. Supports event subscriptions and filters. | Notable, 1.4k★ and HB30 ≈42. | **Active**, version 2.1.0, macOS 13.1+, with 2026 development. Useful in a laboratory or incident investigation and requires analytical interpretation. |
| [Santa](https://github.com/northpolesec/santa) | `brew install --cask santa` | Allows, blocks or monitors binary execution using hashes, certificates, TeamID or SigningID. Provides an event database, `santactl`, and local or central policies. | Notable specialist tool, 754★ and HB30 ≈38. | **macOS 26**, with the 2025.9 branch explicitly validated on 26.0. The snapshot cask was 2026.7. Begin in MONITOR mode. Coverage of scripts and `dlopen` scenarios is limited. |
| [osquery](https://osquery.io/) | `brew install --cask osquery` | Exposes processes, launchd, browser extensions, sockets, hashes, users, packages and Unified Log through SQL tables. Supports scheduled queries and fleet aggregation. | **Very high**, 23.5k★ and HB30 ≈221. | **Active**, version 5.23.1. The snapshot documentation listed macOS 14/15 in CI. Validate individual tables on macOS 26. `es_process_events` needs a signed app bundle and Full Disk Access. [macOS installation](https://github.com/osquery/osquery/blob/master/docs/wiki/installation/install-macos.md) · [ES auditing](https://github.com/osquery/osquery/blob/master/docs/wiki/deployment/process-auditing.md) |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | Follow official release and package instructions | VQL-based endpoint visibility, remote collection, hunts and DFIR across a fleet. | High, 4.2k★. | **Active**, with 2026 development. A substantial deployment for one home Mac. Requires secure server architecture and access controls. |
| [Stats](https://github.com/exelban/stats) | `brew install --cask stats` | Shows CPU, memory, disk, network, battery and sensors in the menu bar. | **Very high in Homebrew**, HB30 ≈12,980. | **Active**, version 3.0.13. Useful for baselines and unusual load or traffic, with limited threat attribution. |
| [btop](https://github.com/aristocratos/btop) / [bottom](https://github.com/ClementTsang/bottom) | `brew install btop bottom` | Interactive views of processes, CPU, memory, disk and network usage. | High, HB30 ≈8,496/4,831. | **Active**. Useful for initial observation, although short-lived malware can evade a snapshot. |
| [mactop](https://github.com/context-labs/mactop) | `brew install mactop` | An Apple silicon terminal monitor for CPU, GPU, ANE, power and thermal state. | Notable, HB30 ≈790. | **Active**, version 2.1.5. Helps investigate resource anomalies, with limited threat attribution. |
| [smartmontools](https://www.smartmontools.org/) | `brew install smartmontools` | SMART/NVMe drive health, errors and self-tests. | High, HB30 ≈4,318. | **Active**, version 7.5. Available fields on internal Apple SSDs depend on the controller. Primarily useful for reliability investigations. |

## 4. Configuration auditing and hardening

### NIST macOS Security Compliance Project

The macOS Security Compliance Project generates baselines, documentation, configuration profiles, DDM assets and compliance or remediation scripts for NIST 800-53, CIS Levels 1/2, DISA STIG and other frameworks. The original 27 August 2026 snapshot recorded **revision 3.0 of the macOS 26 guidance**, **≈2.45k★** and active 2026 development. [mSCP](https://github.com/usnistgov/macos_security) · [Releases](https://github.com/usnistgov/macos_security/releases) · [README](https://github.com/usnistgov/macos_security/blob/main/README.md)

Obtain the generator from a reviewed upstream release and follow that release's installation instructions. Record the selected release tag and commit.

Generate and run compliance audits first, then inspect each remediation before applying it. CIS Level 2 and STIG settings can disrupt AirDrop, iCloud, sharing, developer workflows and personal use. Version-specific checks can also produce false negatives. Pilot the selected release before broad deployment.

### Additional tools

| Tool | Installation | Value | Assessment |
|---|---|---|---|
| [Lynis](https://github.com/CISOfy/lynis) | `brew install lynis` | General Unix auditing of permissions, services, logging and hardening opportunities. | Notable project, HB30 ≈163. **Conditional**, with shallower macOS coverage than Linux. An mSCP profile accounts for more macOS-specific controls. |
| [ALBATOR](https://github.com/cluster2600/ALBATOR) | Follow upstream instructions | Scripts and Swift tooling for macOS 26.x hardening and monitoring. | **Experimental/niche**, targeting macOS 26. Assess its rules against the relevant baseline. Use audit or dry-run modes and review the code before a privileged run. |
| Homebrew self-audit | Built into `brew` | `brew outdated`, `brew doctor`, `brew autoremove --dry-run` and `brew cleanup --dry-run`. Inventory with `brew list --formula` and `brew list --cask`. | Useful maintenance for a development Mac. `brew audit` checks formula and cask quality, with a different scope from malware inspection of installed binaries. |

### Important macOS security settings

- **Updates** — enable automatic security responses and system data files, and install patch releases promptly. Apple continues to address vulnerabilities between major releases. [macOS 26.4 security content](https://support.apple.com/en-us/126794)
- **FileVault** — enable it and store the personal recovery key securely. FileVault unlock over SSH on Apple silicon with macOS 26 is associated with Remote Login. Disable Remote Login when its functionality is unnecessary. [Apple FileVault guidance](https://support.apple.com/en-ca/guide/security/sec8447f5049/web)
- **SIP and Signed System Volume** — keep them enabled. Temporary research that requires weaker settings belongs in an isolated VM.
- **Firewall and stealth mode** — enable appropriate protection on untrusted networks. The built-in firewall handles incoming connections, while LuLu and Little Snitch provide outbound controls. [Apple firewall security](https://support.apple.com/guide/security/seca0e83763f/web)
- **Login Items & Extensions** — regularly review Background Activity, Endpoint Security Extensions and Network Extensions in System Settings. [Apple guide](https://support.apple.com/guide/mac-help/mtusr003/mac)
- **Full Disk Access, Accessibility and Screen Recording** — remove grants from unused applications. Each additional security tool increases the amount of software with privileged access.
- **Lockdown Mode** — consider it for a high risk of targeted attack. Its purpose is to reduce exposed functionality.
- **A separate standard user account** — everyday work without administrator privileges reduces the impact of some scenarios. User-level malware can still access data available to that account.

## 5. Development environments, dependencies and secrets

These tools inspect vulnerable packages, container images, infrastructure as code and accidentally exposed credentials. Memory-resident macOS infostealers require separate host investigation.

| Tool | Installation | Scope | Popularity and maintenance |
|---|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | `brew install trivy` | Filesystems, repositories, images, SBOMs, misconfigurations, vulnerabilities and secrets. | **Very high**, 37.7k★ and HB30 ≈14,734. Snapshot version 0.74.0, with 2026 activity. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `brew install osv-scanner` | Matches lockfiles, SBOMs and source dependencies against OSV. Supports transitive-dependency reachability in supported ecosystems. | **Very high/high**, 10.9k★ and HB30 ≈3,145. Snapshot version 2.5.1, actively maintained. |
| [Syft](https://github.com/anchore/syft) + [Grype](https://github.com/anchore/grype) | `brew install syft grype` | Syft produces an SBOM, which Grype can scan for known vulnerabilities. Grype also supports filesystem scanning. | High, 9.5k★/12.8k★ and HB30 ≈3,162/2,577. Active. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | `brew install gitleaks` | Secret detection in Git history, staged files and directories. | **Very high**, 29.0k★ and HB30 ≈12,765. Active. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | `brew install trufflehog` | Finds exposed credentials and, where supported, checks their validity. | **Very high**, 27.6k★ and HB30 ≈4,489. Active. Verification can contact external services. |
| [Semgrep](https://github.com/semgrep/semgrep) | `brew install semgrep` | Static application security testing and source-code policy checks. | **Very high**, 16.4k★ and HB30 ≈6,722. Active. Its scope is source code. |

## 6. Networking, privacy and anonymity

### Observation and control

| Tool | Installation | Purpose | Popularity and status |
|---|---|---|---|
| **LuLu** | `brew install --cask lulu` | Free application-aware outbound connection control. | 13.1k★ and active development. A baseline option. |
| [Little Snitch](https://www.obdev.at/products/littlesnitch/) | `brew install --cask little-snitch` | A commercial outbound firewall and network monitor with detailed maps and rules. | HB30 ≈439, snapshot cask 6.4.1. **Active**. Choose a single outbound firewall unless a tested deployment specifically requires several. |
| [Wireshark / tshark](https://www.wireshark.org/) | `brew install wireshark` or `brew install --cask wireshark` | Packet capture and protocol analysis, with `tshark` for command-line automation. | High, HB30 ≈4,655. Version 4.6.8, active. Capture needs appropriate privileges. |
| [mitmproxy](https://mitmproxy.org/) | `brew install --cask mitmproxy` | An interactive HTTP(S) proxy for authorised testing of your applications or laboratory. | High, HB30 ≈9,192. Version 12.2.3. Installing its CA grants substantial trust. Remove the test root certificate when it is no longer needed. |
| [Nmap](https://nmap.org/) | `brew install nmap` | Inventory of authorised hosts, ports and services. | **Very high**, HB30 ≈31,756. Version 7.991. Scan only networks within the authorised scope. |
| [Sniffnet](https://github.com/GyulyVGC/sniffnet) | `brew install sniffnet` | Visualises local traffic, domains and transfer volumes. | **Very high**, 40.9k★. HB30 ≈211, version 1.5.1, active. Provides traffic observation. |
| [bandwhich](https://github.com/imsnif/bandwhich) / `iftop` | `brew install bandwhich iftop` | Terminal views of bandwidth by connection, process or flow. | bandwhich has 11.9k★. HB30 ≈243/264. Useful for anomalies, with less security context than Endpoint Security-aware tools. |

### Transport privacy

| Tool | Installation | Benefits and limits | Popularity and status |
|---|---|---|---|
| [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) | `brew install dnscrypt-proxy` | DNSCrypt, DoH, ODoH, filtering and DNS query logs. Encrypts DNS to the selected resolver. The resolver remains a trusted party and other traffic stays visible at its own protocol layer. | **Very high**, 13.6k★. Version 2.1.18, active in 2026. |
| [Tor Browser](https://www.torproject.org/download/) | `brew install --cask tor-browser` | A ready-made browser for web anonymity and reduced fingerprinting. | Notable, HB30 ≈1,690. Version 15.0.20. **Active**, with official macOS builds. Operational choices still affect anonymity. |
| `tor` + `torsocks` | `brew install tor torsocks` | Routes correctly configured command-line applications through Tor. | HB30 ≈1,282/98. **For experts**, because DNS, UDP or child processes can bypass the intended route. Tor Project recommends Tor Browser for browsing. [Guidance](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/) |
| [Mullvad Browser](https://mullvad.net/browser) | `brew install --cask mullvad-browser` | Reduces fingerprinting without bundling routing through the Tor network. | HB30 ≈400. Version 15.0.20. A separate network route is needed to conceal the source IP address. |
| WireGuard tools | `brew install wireguard-tools` | Command-line WireGuard tunnel configuration. | HB30 ≈2,877, with a 2026 build. Protects transport to the VPN endpoint. Anonymity also depends on endpoint trust and account activity. |
| OpenVPN | `brew install openvpn` | A command-line client for OpenVPN configurations. | High, HB30 ≈3,768. Version 2.7.6. Requires the same consideration of VPN endpoint trust. |
| Mullvad VPN / Proton VPN | `brew install --cask mullvad-vpn` / `protonvpn` | Full VPN clients using Network Extensions and kill-switch features. | HB30 ≈576/2,081. Versions for macOS 26 were available at the snapshot date. Assess the provider's trust model separately from the host audit. |

Anonymity depends on the complete operating practice. A VPN sees the source IP address and often destination metadata. DNS encryption leaves IP connections visible. Signing into a personal account identifies that session, and an ordinary browser routed through SOCKS remains fingerprintable.

## 7. Package inspection and unknown-file analysis

| Tool | Installation | Purpose | Popularity and maintenance |
|---|---|---|---|
| [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/) | `brew install --cask suspicious-package` | Inspects signatures, notarisation, payloads, scripts and potential `.pkg` issues before installation. | Notable, HB30 ≈301. Snapshot cask 4.7 with explicit **macOS 26** support. Useful for preventive inspection. |
| [Apparency](https://www.mothersruin.com/software/Apparency/) | `brew install --cask apparency` | Displays application signatures, notarisation, entitlements, architectures, embedded frameworks and launch information. | Notable, HB30 ≈171. Version 3.3. A GUI for examining complex code-signing data. |
| **YARA-X / YARA** | See above | Local indicators and malware-family matching, including Mach-O metadata. | Active. Results depend on the rules. |
| [capa](https://github.com/mandiant/capa) | Follow official release and Python instructions | Identifies binary capabilities through static or dynamic analysis for reverse engineering. | High, 6.2k★ and active in 2026. Verify support for the relevant Mach-O format and architecture. |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | `brew install ghidra` | A disassembler and decompiler for manual reverse engineering. | High, HB30 ≈2,595. Version 12.1.3. Analyse unknown samples in an isolated laboratory. |
| [radare2](https://github.com/radareorg/radare2) | `brew install radare2` | Command-line reverse engineering and scripting. | Notable, HB30 ≈2,441. Version 6.2.0, active. Requires specialist knowledge. |

For dynamic analysis, use a separate VM with a snapshot taken before execution. Keep personal Apple IDs, iCloud, password managers, wallets, SSH/GPG keys and shared folders out of the analysis environment.

## 8. Forensics and incident response

| Tool | Installation | Evidence collected or analysed | Popularity and status |
|---|---|---|---|
| [mac_apt](https://github.com/ydkhatri/mac_apt) | Upstream Python virtual environment or release | Live-system and APFS/HFS image artefacts covering users, applications, browsers, quarantine, Spotlight, knowledgeC and more. Exports to SQLite and CSV. | Notable, 1.1k★ with active 2026 updates. A widely used open-source macOS forensic parser. |
| [Velociraptor](https://docs.velociraptor.app/) | Upstream client and server | Remote collection, hunts, VQL artefacts and triage across endpoints. | High, 4.2k★, active. Requires protected infrastructure. |
| [UAC](https://github.com/tclahr/uac) | Upstream script or package | Live-response artefact collection for Unix-like systems, including macOS. | Notable, 1.4k★, active in 2026. Review the selected profile and expected sensitive-data volume. |
| [macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs) | Upstream Rust release or build | Parses macOS Unified Log archives away from the source system. | Niche specialist tool, 373★, active in 2026. Useful for analysis beyond the original host's `log show`. |
| [APOLLO](https://github.com/mac4n6/APOLLO) | Upstream | SQLite queries for patterns of activity in Apple application databases. | Notable niche tool, 652★. **Conditional/ageing**, with the last recorded substantial activity in 2024. Database schemas may have changed in newer macOS releases. |
| [The Sleuth Kit](https://www.sleuthkit.org/) | `brew install sleuthkit` | Low-level filesystem forensics and timeline components. | Notable, HB30 ≈426. Version 4.15.0. mac_apt is often more convenient for APFS and macOS metadata. |
| `sysdiagnose` | Built in | A broad snapshot of logs and subsystem diagnostics. | Maintained with macOS. Archives can disclose names, paths, networks, processes and other sensitive data. |

During an incident, establish whether the immediate objective is cleanup or evidence preservation. Installing scanners, rebooting and deleting files change timestamps and logs. For evidence with legal significance, preserve the system and involve a qualified forensic specialist.

## 9. Careful cleanup and application removal

Cleanup can remove forgotten helper tools, launch agents, privileged helpers and remnants of unused software. Aggressive cache deletion usually offers temporary space savings and can disrupt applications.

| Tool | Installation | Purpose | Popularity and maintenance |
|---|---|---|---|
| [Mole](https://github.com/tw93/Mole) | `brew install mole` | CLI/TUI cleanup, application removal, disk analysis and Homebrew maintenance. Includes previews and confirmation, with a published security audit. | **Very high**, 65.1k★ and HB30 ≈49,156. Version 1.52.0, active in 2026. Review a dry-run or preview before applying changes. |
| [Pearcleaner](https://github.com/alienator88/Pearcleaner) | `brew install --cask pearcleaner` | Finds application-associated files, orphaned files and launch items. Supports Trash and restore. | High in Homebrew, HB30 ≈4,354. Version 5.4.3, active in the original snapshot. Requires broad TCC permissions. Grant access for the period it is needed. |
| [AppCleaner](https://freemacsoft.net/appcleaner/) | `brew install --cask appcleaner` | Removes applications and related files after review. | High, HB30 ≈4,886. Version 3.6.8, with documented support from macOS 10.14 to 26. |
| [OnyX](https://www.titanium-software.fr/en/onyx.html) | `brew install --cask onyx` | Maintenance, caches, hidden settings and system checks, with builds tied to macOS versions. | Notable, HB30 ≈1,253. Version 5.0.2. Choose the build for the installed macOS release and apply only the operations needed. |
| `ncdu`, `dust`, `dua-cli` | `brew install ncdu dust dua-cli` | Shows which files consume disk space so the user can decide what to remove. | High/notable, HB30 ≈2,878/4,456/3,335. A useful first stage of cleanup. |
| Homebrew cleanup | Built in | Preview with `brew cleanup --dry-run` and `brew autoremove --dry-run`, then review before applying changes. | Covers objects managed by Homebrew. Manually installed applications can leave separate files. |

Before cleanup, take a current backup and review the proposed file list. Prefer moving removable items to Trash first. Changes under `/System`, `/Library` and `~/Library` require specific knowledge of the files and their owners.

## 10. Approaches with limited value for primary macOS protection

| Tool or approach | Limitations |
|---|---|
| `rkhunter`, `chkrootkit` | Built around Linux and Unix rootkit assumptions, with limited coverage of Endpoint Security, System Extensions, TCC, APFS and the Signed System Volume. Their snapshot HB30 figures were ≈18/21. |
| Older viewers and scanners limited to kernel extensions | Modern persistence and security products also use System Extensions and Network Extensions. Kernel-extension auditing covers one narrower layer. |
| Disabling SIP, Gatekeeper or quarantine for convenience | Removes important boundaries and facilitates infostealer execution or persistence. Research requiring disabled protections belongs in an isolated laboratory VM. |
| `curl ... \| sudo sh` from an arbitrary gist or website | Grants the downloaded hardening or cleanup script control of the host. Select a reviewed tag or commit, download the file, verify its signature or hash and read the code before execution. |
| Several AV, EDR and firewall products running together | Can cause Endpoint Security or Network Extension conflicts, unnecessary Full Disk Access, noise, load and difficult fault attribution. |
| Uploading a file to VirusTotal as a precaution | Uploaded samples may become available to researchers or service partners. For a private file, calculate SHA-256 locally and make an explicitly authorised lookup of an existing report first. |
| RAM optimisers and generic registry cleaners | macOS manages memory and caches, and has a different configuration model from the Windows registry. Such cleanup offers little value and can remove needed data. |

## 11. Practical tool sets

### A personal Mac with a manageable set of tools

```bash
brew install --cask knockknock lulu
brew install --cask malwarebytes  # On-demand second opinion
```

Add BlockBlock where real-time persistence observation is needed, and EtreCheckPro for periodic reports. Consider overlap with any existing continuously running endpoint product before enabling another real-time scanner.

### Technical investigation of a suspicious Mac

```bash
brew install --cask knockknock taskexplorer mac-monitor suspicious-package apparency
brew install yara-x virustotal-cli
```

Preserve reports and hashes before making changes or deleting files. Disable automatic VirusTotal integration unless the policy permits sending hashes or metadata.

### An enterprise fleet

- Use an mSCP profile for the deployed macOS release as the source of controls and compliance scripts.
- Start Santa in MONITOR mode, then introduce CEL or rule policies in stages.
- Use osquery with a fleet manager and a bounded set of event tables and queries.
- Collect XProtect, Gatekeeper and Endpoint Security events centrally.
- Deploy Velociraptor or another managed DFIR collector with RBAC, TLS and retention controls.

### A development Mac

```bash
brew install trivy osv-scanner syft grype gitleaks
brew outdated
brew cleanup --dry-run
```

## 12. Responding to a suspected infostealer

1. From another trusted device, change passwords for critical accounts, revoke active sessions and replace tokens and API keys. Secure the primary email account and password manager first.
2. Keep new passwords and wallet access off the suspicious Mac until it has been assessed and recovered.
3. Where forensics is required, preserve the system until a specialist has collected volatile evidence before cleanup or rebooting.
4. For user-level triage, retain KnockKnock JSON, an EtreCheck report, system and network extension inventories, listeners and hashes of suspicious files.
5. Review browser extensions, login and background items, TCC permissions, configuration profiles, SSH keys and `authorized_keys`, shell startup files and developer credentials.
6. Use Malwarebytes and reviewed local YARA rules for corroboration. Assess ClamAV findings alongside those sources.
7. For a confirmed credential stealer, erasing and reinstalling the OS and restoring reviewed documents provides stronger assurance than migrating the complete user environment.

## Sources and reproducibility

The research uses the following primary references.

- [Apple — protecting against malware in macOS](https://support.apple.com/guide/security/sec469d47bd8/web)
- [Apple — Gatekeeper and runtime protection](https://support.apple.com/guide/security/sec5599b66df/web)
- [Apple — Endpoint Security framework](https://developer.apple.com/documentation/endpointsecurity)
- [Apple WWDC22 — eslogger and XProtect events](https://developer.apple.com/videos/play/wwdc2022/110345/)
- [Objective-See tools](https://objective-see.org/tools.html)
- [NIST macOS Security Compliance Project](https://github.com/usnistgov/macos_security)
- [Homebrew Formulae and JSON API](https://formulae.brew.sh/)
- [osquery](https://github.com/osquery/osquery)
- [Santa](https://github.com/northpolesec/santa)
- [ClamAV documentation](https://docs.clamav.net/)
- [YARA-X documentation](https://virustotal.github.io/yara-x/docs/)
- [Tor Project safety guidance](https://support.torproject.org/tor-browser/security/using-tb-safely/)

To refresh the figures, use the relevant formula or cask page on `formulae.brew.sh`, its JSON endpoint and the GitHub repository API. Before installing, verify the current release, minimum macOS version, signature and security advisories with the upstream project. Review each tool's provenance separately from this historical catalogue.
