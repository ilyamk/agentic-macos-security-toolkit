# PB-01 Package supply chain: Homebrew, npm, pnpm, uv

**Goal:** packages are installed only when their origin can be checked, third-party code runs only where it was explicitly trusted, and new releases are installed after a short delay unless they fix a known vulnerability.

**Attacks addressed:** ATK-03 fake installers, ATK-05 malicious install scripts, ATK-06 freshly poisoned releases, ATK-07 typosquatting and slopsquatting, ATK-08 upstream backdoors, ATK-09 third-party tap code, ATK-10 cask and download tampering, ATK-11 PATH hijacking (awareness), ATK-12 stale Homebrew packages, ATK-18 project-level install scripts, ATK-20 packages pulled in by agent tools, ATK-23 the same controls in build pipelines. See [the attack catalogue](../docs/attack-catalogue.md).

**Audit checks:** HB-01 to HB-12, NPM-01 to NPM-03, PNPM-01, UV-01; related: NPM-04 and PNPM-02 (PB-02), NPM-05 (PB-03) ([workstation audit](../tools/workstation-audit/README.md)).

**Reference versions:** written against Homebrew 7.0, npm 11.19 to 11.21, pnpm 12.x and uv 0.13 on macOS 26. Re-check every option on the target machine before using it.

## 1. Threat model in short

1. **Third-party Homebrew taps** are somebody else's Ruby code. It runs with your user's rights on `brew update`, `install` and `upgrade`, without Homebrew's review or CI.
2. **Casks** are vendor binaries, sometimes with pre- or post-install scripts. Homebrew checks only the sha256 checksum, and casks marked `auto_updates true` update themselves outside Homebrew.
3. **Upstream compromise** (the xz-utils pattern) is usually discovered within days, so a short delay before upgrading removes most of the exposure.
4. **npm, pnpm and PyPI** run install scripts by default and resolve to the newest version, so a poisoned release reaches you within minutes of publication.
5. **`/opt/homebrew` is owned by your user.** Any process running as you can replace a binary there. This is Homebrew's design; it cannot be fixed, only taken into account (see ATK-11).

The update principle: **update regularly, but a few days late. Versions with a known vulnerability are updated immediately.**

## 2. Inventory (read-only)

The Homebrew user configuration directory is `$XDG_CONFIG_HOME/homebrew` when `XDG_CONFIG_HOME` is set, otherwise `~/.homebrew`. The commands below use `$HB_CFG` for it.

Avoid `zsh -i` (interactive shells) in agent sessions: they load the rc files, and with them any secrets those files source (SHELL-01). Call each tool by path or with an explicit `PATH` instead.

~~~sh
HB_CFG=${XDG_CONFIG_HOME:+$XDG_CONFIG_HOME/homebrew}; HB_CFG=${HB_CFG:-$HOME/.homebrew}
sw_vers; brew --version
brew tap
brew list --formula | wc -l; brew list --cask
brew leaves --installed-on-request
brew info --json=v2 --installed | jq -r '.formulae[] | select(.tap != "homebrew/core") | [.full_name,.tap] | @tsv'
brew info --json=v2 --installed | jq -r '.casks[] | [.full_token,.tap,.sha256,(.auto_updates|tostring)] | @tsv'
ls -ld /opt/homebrew; stat -f '%Su' /opt/homebrew
ls -la "$HB_CFG" 2>&1
cat "$HB_CFG/trust.json" 2>/dev/null        # Homebrew 7+ trust store
brew trust --help 2>&1 | head -3             # does this version have a trust store?
brew outdated --help | grep -E 'vulnerable|json'
command -v gh && gh auth status >/dev/null 2>&1 && echo gh-authenticated
npm -v; pnpm -v; uv --version               # and each copy found by which -a
ls ~/.nvm/versions/node 2>/dev/null
grep -v -i -E 'token|auth|password' ~/.npmrc 2>/dev/null
./tools/workstation-audit/workstation-audit.sh --only HB
./tools/workstation-audit/workstation-audit.sh --only NPM
~~~

Record in the report: Homebrew version; third-party taps and the packages installed from them; casks without a checksum (`no_check`) and casks with `auto_updates`; npm and pnpm versions and every Node version under nvm.

**Pitfall: where a package really came from.** `brew info` shows the tap a name *resolves to today*, not necessarily where the installed copy came from. The install receipt is authoritative:

~~~sh
jq -r '.source.tap' /opt/homebrew/Caskroom/<cask>/.metadata/INSTALL_RECEIPT.json
jq -r '.source.tap' /opt/homebrew/Cellar/<formula>/*/INSTALL_RECEIPT.json
~~~

## 3. Homebrew security variables live in brew.env

Put the variables in **brew.env, not in a shell rc file.** Homebrew reads brew.env itself on every run: from an agent, from cron, from a non-interactive shell. Shell rc files used by agents often exit early, so variables set there never reach brew.

Location: `$XDG_CONFIG_HOME/homebrew/brew.env` when `XDG_CONFIG_HOME` is set, otherwise `~/.homebrew/brew.env`. Homebrew also reads `/etc/homebrew/brew.env` and `$(brew --prefix)/etc/homebrew/brew.env`. Format (see `export_homebrew_env_file` in `$(brew --prefix)/bin/brew`): `KEY=value` lines, no `export`, no quotes, only lines starting with `HOMEBREW_` count.

Template: [templates/homebrew/brew.env](../templates/homebrew/brew.env)

~~~
HOMEBREW_VERIFY_ATTESTATIONS=1
HOMEBREW_CASK_OPTS=--require-sha
HOMEBREW_NO_INSECURE_REDIRECT=1
~~~

Before writing it:
- Confirm each variable exists in `man brew` for this version.
- `--require-sha` refuses casks with `sha256 :no_check`. If any are installed or wanted, ask the owner first.
- `HOMEBREW_VERIFY_ATTESTATIONS` uses the `gh` CLI, which must be installed and logged in.

Verify:

~~~sh
brew config | grep -E 'HOMEBREW_(VERIFY|CASK_OPTS|NO_INSECURE)'
HOMEBREW_NO_AUTO_UPDATE=1 brew reinstall --debug "${LEAF_FORMULA:?Set the reviewed leaf formula}" 2>&1 | grep -i attest
# expect: Verifying ... against 1 listed attestation from Homebrew/homebrew-core
~~~

Attestations are checked on install, upgrade and reinstall, not on `fetch`, and silently unless `--debug` is given. Choose a small leaf formula from `homebrew/core` that nothing depends on, that is **not outdated** (otherwise the reinstall upgrades it and skips the cool-down), and that has a bottle (`--debug` can open an interactive prompt if a source build fails). Not `gh`, `git` or `jq`.

## 4. Narrow tap trust (Homebrew 7+)

Homebrew 7 has a trust store (`brew trust`, `brew untrust`, `trust.json` next to brew.env). Trusting a whole tap lets Homebrew load *any* formula added to it later. Narrow trust to what is actually installed:

~~~sh
mkdir -p "$HB_CFG/backup-$(date +%F)" && cp -p "$HB_CFG/trust.json" "$HB_CFG/backup-$(date +%F)/"
brew trust --formula "${APPROVED_FORMULA:?Set the installed owner/tap/formula}"  # repeat for installed formulae
brew trust --cask "${APPROVED_CASK:?Set the installed owner/tap/cask}"           # repeat for installed casks
brew untrust --tap "${REVIEWED_TAP:?Set the reviewed owner/tap}"                 # once per whole-tap entry
cat "$HB_CFG/trust.json"                                                       # brew removes an empty trust store
brew tap
brew outdated
brew info "$APPROVED_FORMULA"
~~~

This is not removal, so an agent may do it without asking, but no **installed** package may be left untrusted. Personal taps of unknown authors go into the report as removal candidates. After untrusting, `brew install` prints a reminder that whole-tap trust is available; that is expected, not a problem to fix.

### Removing a tap safely

Untapping is a removal: ask first.

**Pitfall: `brew untap --force` uninstalls every formula and cask from that tap before untapping.** Never use it to get past an error.

**Pitfall (Homebrew 7): untap fails with "Refusing to load cask ... from untrusted tap"** when the tap defines a cask token that is installed, even if your copy came from `homebrew/cask`. For formulae Homebrew handles this case; for casks it does not. Safe workaround after confirming the receipt shows `homebrew/cask`:

~~~sh
tap=${REVIEWED_TAP:?Set the reviewed owner/tap}
token=${CASK_TOKEN:?Set the confirmed homebrew/cask token}
brew trust --cask "$tap/$token"
brew untap "$tap"
brew untrust --cask "$tap/$token"
brew list --cask | grep -Fx -- "$token"
~~~

## 5. Brewfile as an inventory

~~~sh
[ -f "$HB_CFG/Brewfile" ] && cp -p "$HB_CFG/Brewfile" "$HB_CFG/Brewfile.bak-$(date +%F)"   # a reviewed Brewfile may hold comments
brew bundle dump --file="$HB_CFG/Brewfile" --force --no-vscode
grep -E '^(tap|cask)|trusted' "$HB_CFG/Brewfile"
~~~

`--global` writes to the Homebrew user config directory (`$HB_CFG/Brewfile`), not to `~/.Brewfile`, so pass `--file` explicitly. Trust markers (`trusted: true`) are written into the Brewfile.

**Never run `brew bundle cleanup --force`.** It uninstalls everything not in the Brewfile and resets the trust store to match it.

## 6. Delayed upgrades with brewup

Replace `brew update && brew upgrade` with [tools/brewup](../tools/brewup/README.md). It:

1. runs `brew update`;
2. records when each outdated version was first seen (`~/.local/state/brewup/seen.tsv`);
3. upgrades a version only after a cool-down (3 days by default);
4. upgrades versions reported by `brew outdated --vulnerable` (OSV.dev) immediately;
5. tags packages from third-party taps and never upgrades pinned ones;
6. shows what `brew autoremove` would remove, asks once, then runs `upgrade`, `autoremove` and `cleanup` (keeping the previous version of anything it just upgraded, as a rollback copy until the next run);
7. backs up the Brewfile (newest three kept), refreshes it and shows the diff.

Flags: `-n` dry run (still runs `brew update`), `-N` skip `brew update`, `-y` no prompt, `-a` ignore the cool-down, `-d DAYS`. **Agents use `brewup -n -N`**, which changes nothing except brewup's own state file.

Install it (plan first, then apply):

~~~sh
./tools/install-user-tools.sh            # shows what would change
./tools/install-user-tools.sh --apply    # copies brewup into ~/.local/bin
brewup -n -N
~~~

Before relying on the vulnerability bypass, check that this Homebrew has `brew outdated --vulnerable` and `--json=v2`. Without a terminal and without `-y`, brewup changes nothing (no upgrade, autoremove, cleanup or Brewfile refresh); this is deliberate. Upgrading a formula can still upgrade its outdated dependencies with it, past their own cool-down; brewup documents this. `brew autoremove` inside brewup may remove orphaned dependencies: list them in the report and run `brew missing` afterwards.

**Pitfall: `brew linkage` turns on Homebrew developer mode** ("linkage is a developer command"). In developer mode `brew update` follows the development branch instead of the latest stable tag. If you ran it, run `brew developer off` and check `brew developer`.

## 7. npm

User config `~/.npmrc` (template: [templates/npm/npmrc](../templates/npm/npmrc)):

~~~
# Supply-chain hardening
min-release-age=7
strict-allow-scripts=true
~~~

- `min-release-age` is in **days**. Versions younger than that are not resolved.
- `strict-allow-scripts` turns an unreviewed dependency install script into an error instead of a silent run. Approvals live in the project's `package.json`: `"allowScripts": {"esbuild": true}`. For a one-off global install: `npm i -g <pkg> --allow-scripts=<a>,<b>`. Review the list npm prints before allowing; do not persist it globally.
- Do not set `ignore-scripts=true`: it silently breaks esbuild, sharp and similar native packages.
- Check each key against every npm on the machine: `grep -c "'min-release-age'" <npm>/node_modules/@npmcli/config/lib/definitions/definitions.js`. Both keys exist from npm 11.19.

**Pitfall: older npm silently ignores the keys.** It prints `npm warn Unknown user config` and carries on, while `npm config get min-release-age` still echoes `7`. "config get shows the value" therefore proves nothing. Node versions whose bundled npm is older go into the report; for a Node line that ships npm 10, upgrade npm inside that version to an **exact** npm 11 release that is at least a week old (`npm view npm time --json` shows publish dates), for example `npm i -g npm@11.x.y`. A bare `npm@11` resolves to the newest release with no delay, because that old npm ignores `min-release-age`.

Verify with the npm of each Node version in use:

~~~sh
npm config get min-release-age; npm config get strict-allow-scripts
~~~

Expect global installs of CLIs with native parts (firebase-tools, wrangler and similar) to stop with `ESTRICTALLOWSCRIPTS` and a list of packages. That is the control working.

## 8. pnpm

~~~sh
mkdir -p "$HB_CFG/backup-$(date +%F)"
cp -p ~/Library/Preferences/pnpm/config.yaml "$HB_CFG/backup-$(date +%F)/" 2>/dev/null || echo "no pnpm global config yet"
pnpm config set --global minimumReleaseAge 10080    # minutes: 7 days
pnpm config get minimumReleaseAge                   # with every pnpm copy on the machine
~~~

- The global config is `~/Library/Preferences/pnpm/config.yaml` on macOS. It is created by the first `config set --global`.
- pnpm 12 has a built-in default of 1440 minutes, non-strict. **An explicit value turns `minimumReleaseAgeStrict` on by default**, so a too-new version now prompts or fails instead of being quietly added to an exclusion list. Tell the owner.
- pnpm also reads `~/.npmrc`; check `pnpm config list` does not complain about the npm keys.
- Several pnpm copies (Homebrew, a standalone install under `~/Library/pnpm`, one per nvm Node) are common. Projects pin their pnpm through `packageManager` and pnpm switches to that version itself, so one global copy is enough. See PB-02.

## 9. uv and PyPI: do not configure globally

Do not set `exclude-newer` in a global `uv.toml` or `UV_EXCLUDE_NEWER`. It writes `exclude-newer-span` into the `uv.lock` of every project, which creates noise in shared repositories. Recommend it per project instead:

~~~toml
[tool.uv]
exclude-newer = "7 days"
~~~

## 10. Decision rules

| Finding | Action | Ask first? |
|---|---|---|
| brew.env missing or incomplete | Write it from the template after a backup | No, unless a `no_check` cask is installed |
| Whole-tap trust | Narrow to installed packages | No |
| Third-party tap with nothing installed | Removal candidate | Yes |
| Package from a personal tap of an unknown author | Removal candidate | Yes |
| Cask with `no_check` | Explain the trade-off; replace the app or keep `--require-sha` off | Yes |
| Cask with `auto_updates` | Report: updates bypass brew and its delay | No (report only) |
| `~/.npmrc` missing keys | Write after a backup | No |
| Old npm without the keys | Upgrade npm in that Node, or list the Node version for removal | Yes for removal |
| pnpm without `minimumReleaseAge` | Set it, explain strict mode | No |
| Global uv `exclude-newer` | Recommend moving it into projects | Yes |
| Developer mode on | `brew developer off` if the owner did not turn it on deliberately | Yes |

## 11. Final verification

~~~sh
brew config | grep -E 'HOMEBREW_(VERIFY|CASK_OPTS|NO_INSECURE)'
brew developer                         # "disabled"
cat "$HB_CFG/trust.json" 2>/dev/null
brew missing && echo MISSING_OK
brewup -n -N
npm config get min-release-age; npm config get strict-allow-scripts; pnpm config get minimumReleaseAge
./tools/workstation-audit/workstation-audit.sh --only HB
./tools/workstation-audit/workstation-audit.sh --only NPM
./tools/workstation-audit/workstation-audit.sh --only PNPM
~~~

## Agent checklist

- [ ] Inventory recorded: Homebrew version, taps, third-party packages (from receipts), casks without checksums and with `auto_updates`, npm/pnpm versions, Node versions
- [ ] Every option verified on this machine (`man brew`, `--help`, npm `definitions.js`)
- [ ] Backups made, or "did not exist" recorded, for brew.env, trust.json, `~/.npmrc`, pnpm `config.yaml`
- [ ] brew.env written; `brew config` shows the three variables; attestation seen in a `--debug` reinstall
- [ ] Whole-tap trust narrowed; no installed package left untrusted
- [ ] Brewfile dumped with `--file`
- [ ] brewup installed; `brewup -n -N` runs; developer mode off
- [ ] `~/.npmrc` keys set and checked with every npm; old npm versions listed
- [ ] pnpm `minimumReleaseAge` set and checked with every pnpm copy; strict mode explained
- [ ] uv left unconfigured globally; per-project advice given
- [ ] Nothing uninstalled, untapped or deleted without approval

## Owner checklist (plain language)

- [ ] Install Homebrew only from brew.sh, never from an advert or a link in a message.
- [ ] Use `brewup` instead of `brew upgrade`. It waits a few days before installing new versions, except security fixes.
- [ ] When npm or pnpm stops and lists packages with "install scripts", look the names up before allowing them.
- [ ] Decide on the removal candidates in the report: unused taps, unknown authors' packages, old tools.

## Report template

1. **Done:** each file with its path, backup location, the check that proved it (command and result).
2. **Differences from the reference:** versions of brew, npm and pnpm; anything unsupported and the workaround.
3. **Owner actions:** GUI steps and `sudo` commands, ready to copy.
4. **Removal candidates:** each with the reason; waiting for a decision.
5. **Not done or not verified:** honestly, with the reason.
