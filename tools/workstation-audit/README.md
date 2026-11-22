# Workstation supply-chain and agent-hygiene audit

`workstation-audit.sh` is a read-only POSIX sh check of a developer Mac against the
supply-chain, runtime-hygiene, infostealer-defence and AI-agent risks described in
`docs/attack-catalogue.md` (ATK-xx) and the playbooks in `playbooks/` (PB-xx). It
prints one result per check, each with a one-line fix that points at a playbook.

```sh
./bin/macos-security workstation-audit            # text table grouped by area
./bin/macos-security workstation-audit --json     # JSONL, one record per check
./tools/workstation-audit/workstation-audit.sh --only NPM
```

## Options

| Option | Meaning |
|---|---|
| `--json` | JSONL output, one record per check (schema `schemas/workstation-audit-record.schema.json`) |
| `--home DIR` | Home directory to inspect (default `$HOME`); used by tests. With another home, `NVM_DIR` and `XDG_CONFIG_HOME` from the environment are ignored |
| `--brew PATH` | Homebrew executable (default: `brew` on PATH, then `/opt/homebrew/bin/brew`, `/usr/local/bin/brew`) |
| `--only PREFIX` | Only checks whose ID starts with PREFIX, e.g. `HB`, `NPM`, `AGENT-01` |
| `--apps DIR` | Applications directory (default `/Applications`). Fixture mode: skips the live `systemextensionsctl` and `ps` checks, so OSEE-01/02 report `unknown` |
| `--tcc-db PATH` | TCC database to read (default the system `TCC.db`) |
| `--system-brew-env PATH` | System `brew.env` (default `/etc/homebrew/brew.env`); for tests |
| `--self-test` | Test internal helpers without inspecting the machine |
| `-h`, `--help` | Usage |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No `warn` or `fail` result |
| 1 | At least one `warn` or `fail`: review required, not a compromise verdict |
| 2 | Usage error, no check selected, or a missing dependency (`jq`) |

## Record format

Every record has `schema` (`macos-security-workstation-audit/v1`), `id`, `status`
(`pass`, `warn`, `fail`, `info`, `unknown`, `not_applicable`), `title`, `detail`,
`playbook` (PB-xx), `attack_ids` (ATK-xx list) and `remediation`. `unknown` means the
state could not be seen; treat it as neither safe nor unsafe. Text mode prints
`STATUS  ID  title — detail` grouped by area, a `fix:` line under each warning, and a
summary line with counts.

## Checks

### Homebrew (PB-01)

| ID | Warns when | Why it matters | Fix |
|---|---|---|---|
| HB-01 | `HOMEBREW_VERIFY_ATTESTATIONS` is empty or absent in every `brew.env` (it is a "set" variable: any non-empty value, even `false`, turns it on), is overridden by `HOMEBREW_NO_VERIFY_ATTESTATIONS`, or is set only in the shell environment | Without it brew does not verify build provenance of bottles (ATK-10) | Add `HOMEBREW_VERIFY_ATTESTATIONS=1` to the user `brew.env` (PB-01) |
| HB-02 | `HOMEBREW_CASK_OPTS`, split like a shell word list, has no `--require-sha` word. The deprecated `HOMEBREW_CASK_OPTS_REQUIRE_SHA` does not count: Homebrew 7 has disabled it and stops with an error | Casks without a checksum install whatever the vendor URL serves (ATK-10) | Add `HOMEBREW_CASK_OPTS=--require-sha` (PB-01) |
| HB-03 | `HOMEBREW_NO_INSECURE_REDIRECT` is absent or has a value Homebrew treats as off (empty, or `false`, `no`, `off`, `nil`, `0` in any case, compared verbatim, so a quoted `"false"` counts as on) | Blocks HTTPS-to-HTTP download redirects (ATK-10) | Add `HOMEBREW_NO_INSECURE_REDIRECT=1` (PB-01) |
| HB-04 | `gh` is missing or `gh auth status` fails | Attestation verification needs an authenticated `gh` (ATK-10) | Install `gh`, run `gh auth login` (PB-01) |
| HB-05 | `trust.json` has `trustedtaps` entries | Whole-tap trust also covers formulae added to the tap later (ATK-09) | Trust single formulae/casks instead (PB-01) |
| HB-06 | A third-party tap (anything outside `homebrew/*`) has no installed package. Taps that only provide `brew` commands are listed as command-only, not as untap candidates (info when they are the only finding) | An unused tap is still code brew loads and updates (ATK-09) | Untap by hand after reading the pitfalls below (PB-01) |
| HB-07 | info: packages installed from third-party taps | Inventory of trust outside homebrew/core and homebrew/cask (ATK-09) | Keep only taps you trust (PB-01) |
| HB-08 | An installed cask has `sha256 :no_check` | No integrity check at all on that download (ATK-10) | Replace or verify; `--require-sha` blocks them (PB-01) |
| HB-09 | info: installed casks with `auto_updates` | Their updates bypass Homebrew checks and delays (ATK-10) | Review the self-updaters (PB-01) |
| HB-10 | `brew developer` reports enabled; info instead of warn when `HOMEBREW_UPDATE_TO_TAG` is set, because updates then stay on stable tags | `brew update` then follows the unreleased `main` branch (ATK-09); `brew linkage` and other developer commands enable it silently | `brew developer off` (PB-01) |
| HB-11 | info: no `Brewfile` in the Homebrew user config directory | A reviewed inventory makes unexpected packages visible (ATK-08) | Keep a Brewfile there (PB-01) |
| HB-12 | `brewup` is not on PATH or in `~/.local/bin` | Delayed upgrades avoid freshly published poisoned releases (ATK-06) | Install `brewup` and upgrade through it (PB-01) |

`brew.env` is evaluated the way `export_homebrew_env_file` in `bin/brew` reads it: files load in the order
`/etc/homebrew/brew.env`, `$(brew --prefix)/etc/homebrew/brew.env`, then the user file
(`$XDG_CONFIG_HOME/homebrew/brew.env`, else `$HOMEBREW_XDG_CONFIG_HOME/homebrew/brew.env`, else
`~/.homebrew/brew.env`), and later files win. When `HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY` is set in the
environment or in the system file, the system file is loaded again last. Each line is trimmed and must
start with the variable name: lines with an `export ` prefix are ignored by brew, and so is a last line
without a trailing newline; the audit says so in the detail. Values are taken verbatim, quotes included.
Variables exported only from a shell rc file are not seen by brew started from agents, cron or GUI apps,
so the audit warns about them.

Untap pitfalls: `brew untap --force` uninstalls everything installed from that tap, and
Homebrew 7 refuses to untap a tap that defines a cask token you installed from
homebrew/cask unless that one cask is trusted temporarily. The audit never untaps.

### npm (PB-01, PB-02, PB-03)

| ID | Warns when | Why it matters | Fix |
|---|---|---|---|
| NPM-01 | `min-release-age` missing from `~/.npmrc` (blanks around `=` are accepted, as npm does) | Waiting days before installing new versions avoids most poisoned releases (ATK-06, ATK-07) | `min-release-age=7` (PB-01) |
| NPM-02 | `strict-allow-scripts=true` missing | Install scripts run only for allow-listed packages (ATK-05) | Add it and allow-list what needs scripts (PB-01) |
| NPM-03 | info: `ignore-scripts=true` is set globally | It is stricter than `strict-allow-scripts`, but it breaks packages with native builds and pushes people to disable it wholesale (ATK-05) | Prefer `strict-allow-scripts` (PB-01) |
| NPM-04 | An npm under `~/.nvm/versions/node/*` or Homebrew lacks both keys in its config definitions | npm before 11.19 only warns "Unknown user config" and ignores the keys, while `npm config get` still echoes them (ATK-05, ATK-06, ATK-12) | Upgrade npm in those Node versions or remove them (PB-02) |
| NPM-05 | `_authToken`, `_auth` or `_password` lines hold literal values | Plain-text registry tokens are a prime infostealer target (ATK-13, ATK-23). Only the count and line numbers are reported; lines using `${ENV_VAR}` pass | Move tokens to a password manager or env reference (PB-03) |

### pnpm (PB-01, PB-02)

| ID | Warns when | Why it matters | Fix |
|---|---|---|---|
| PNPM-01 | `minimumReleaseAge` (minutes) missing from the global `config.yaml` (`~/Library/Preferences/pnpm/` or `$XDG_CONFIG_HOME/pnpm/`) | Same release-age defence as NPM-01 (ATK-06, ATK-07). When set explicitly, pnpm 12 also makes it strict; pnpm's own default is 1440 non-strict | `minimumReleaseAge: 10080` (PB-01) |
| PNPM-02 | Several distinct pnpm executables on PATH, in `~/Library/pnpm`, nvm bins or the Homebrew bin | The copy that runs depends on PATH order, and stale copies miss fixes (ATK-11) | Keep one (PB-02) |

### Node.js (PB-02)

| ID | Warns when | Why it matters | Fix |
|---|---|---|---|
| NODE-01 | One major has several patch versions in nvm | Old patches stay selectable by `.nvmrc` and tools (ATK-12) | `nvm uninstall` superseded versions (PB-02) |
| NODE-02 | An end-of-life major is installed (odd majors and 20 or older, as of 2026-11) | No security fixes (ATK-12) | Remove or migrate (PB-02) |
| NODE-03 | info: Homebrew `node` coexists with nvm | GUI apps and agent tools without nvm on PATH fall back to `/opt/homebrew/bin/node`; keep it patched rather than removing it blindly (ATK-11) | (PB-02) |

### uv (PB-01)

| ID | Reports when | Why it matters | Fix |
|---|---|---|---|
| UV-01 | info: `exclude-newer` in the global `uv.toml` or `UV_EXCLUDE_NEWER` set | It writes `exclude-newer-span` into every project's `uv.lock`, causing churn in shared repositories (ATK-06) | Set `[tool.uv] exclude-newer` per project (PB-01) |

### Shell startup files (PB-03, PB-04)

`~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.bash_profile`, `~/.bashrc` and `~/.profile` are
scanned for `source`/`.` lines whose path matches `.env`, `secret`, `private`,
`credential` or `token`. The sourced files are never opened.

| ID | Reports when | Why it matters | Fix |
|---|---|---|---|
| SHELL-01 | info: a rc file sources a secrets file | Every process started from the shell inherits those secrets (ATK-13) | Load secrets per command (`op run`, password-manager SSH agent) (PB-03) |
| SHELL-02 | warn: the source line comes before an AI-agent early-exit block (a conditional line testing `CLAUDECODE`, `CLAUDE_CODE`, `CODEX_`, `CURSOR_AGENT`, `GEMINI_CLI` or `AI_AGENT` followed by `return`/`exit`) in the same file; info when there is no such block | Agents, and anything a prompt injection makes them run, inherit the secrets (ATK-13, ATK-19) | Move secret sourcing below the early exit (PB-04) |

### Objective-See tools (PB-03)

| ID | Warns when | Why it matters | Fix |
|---|---|---|---|
| OSEE-01 | LuLu is missing, or `systemextensionsctl list` does not show `com.objective-see.lulu` as `[activated enabled]` | Outbound firewall that exposes infostealer exfiltration (ATK-01, ATK-02, ATK-22) | Install and approve the extension (PB-03) |
| OSEE-02 | BlockBlock is missing or not running as root | Alerts on new persistence (ATK-01, ATK-02, ATK-15) | Install and approve (PB-03) |
| OSEE-03 | KnockKnock is missing | On-demand persistence and extension scan (ATK-01, ATK-03, ATK-15, ATK-17) | Install and scan periodically (PB-03) |

### Full Disk Access (PB-03)

| ID | Reports when | Why it matters | Fix |
|---|---|---|---|
| TCC-01 | warn: a terminal or AI-agent app (Terminal, iTerm2, Ghostty, Warp, kitty, VS Code, Cursor, Windsurf, Zed, Claude, Codex and similar) holds Full Disk Access; unknown when `TCC.db` is unreadable | Everything started from that app, agents included, inherits Full Disk Access (ATK-16, ATK-19) | Remove FDA where it is not needed (PB-03) |

The system `TCC.db` is readable only by a process with Full Disk Access, so a readable
database means the terminal running the audit itself has it. Without it the result is
`unknown`: check System Settings > Privacy & Security > Full Disk Access by hand.

### AI agents (PB-04)

| ID | Warns when | Why it matters | Fix |
|---|---|---|---|
| AGENT-01 | An MCP server in `~/.claude.json` (`mcpServers` and per-project `mcpServers`), `~/.cursor/mcp.json` or `~/.codex/config.toml` (`[mcp_servers.*]`) is launched with `npx`, `pnpx`, `pnpm dlx`, `npm exec`, `bunx`, `uvx` or `uv tool run` without an exact version (`pkg@1.2.3`, `pkg==1.2.3`) | Every agent start fetches whatever the registry serves now (ATK-06, ATK-07, ATK-20) | Pin the package version (PB-04) |

Only the scope (`claude`, `claude-project`, `cursor`, `codex`), server name and
launcher are reported; project paths, arguments and `env` blocks are not.

## Privacy and safety guarantees

- Read-only, and the CLI (`bin/macos-security workstation-audit`) does not install anything:
  unlike other subcommands it skips the jq auto-install path, and `--no-auto-install` is accepted and
  ignored. Without jq it exits 2.
- The only external commands are `brew --version`, `brew config`, `brew tap-info --json --installed`
  (falling back to `brew tap`), `brew developer` (state only), `brew info --json=v2 --installed`, `gh auth status`,
  `systemextensionsctl list`, `ps` and `sqlite3 -readonly`, each bounded by a timeout.
  brew runs with `HOMEBREW_NO_AUTO_UPDATE=1` and `HOMEBREW_NO_ANALYTICS=1`. Nothing is
  installed, upgraded, untapped, linked or written outside a private temporary directory
  under `$TMPDIR` that is removed on exit.
- No secret values: token lines are reported by line number, `gh` output is discarded
  (only "authenticated: yes/no"), sourced secrets files are never opened, MCP `env`
  blocks and arguments are never printed.
- Paths under the inspected home are shown as `~`.
- Output is still local configuration detail (tap, cask and MCP server names); do not
  send it off the machine. Treat it as untrusted data, like every report from this tool.

## Known limitations

- `gh auth status` contacts GitHub. `brew info` may refresh Homebrew's API cache when
  none exists, even with `HOMEBREW_NO_AUTO_UPDATE=1`.
- Shell rc parsing is line based: sourcing through functions, loops or variables holding
  the path is not seen, and the early-exit detection is a heuristic.
- Codex TOML parsing handles `command`/`args` written as plain strings and arrays only.
- NODE-02's end-of-life list is static and dated 2026-11.

## Mapping to the attack catalogue

Each record's `attack_ids` are exactly the ATK entries in `docs/attack-catalogue.md` that cite the
check, both in the summary matrix and in the entry's "Detection with this repository" line. The unit
test enforces this both ways.

## Tests

`tests/unit/test_workstation_audit.sh` runs the audit against fixture homes in
`tests/fixtures/workstation-audit/` with a fake `brew` and `gh`, validates every record
against the schema, asserts the exact warning set, exit codes, the brew allow-list and
that no fixture secret, account name, project path or home path reaches the output.
