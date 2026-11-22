# brewup

A cautious Homebrew upgrade. It upgrades a new version only after it has been
seen as outdated for a cool-down period (3 days by default), and lets versions
with known vulnerabilities skip the wait.

## Why

Supply-chain attacks on package managers usually arrive as a new release: a
hijacked maintainer account or a compromised build publishes a poisoned
version, and anyone who upgrades in the next hours or days installs it. Most
such releases are spotted and pulled within days, so waiting a few days before
installing a new version avoids that window at little cost.

The wait is not applied when the version you have is itself the danger:
versions that `brew outdated --vulnerable` (OSV.dev data) reports as
vulnerable are upgraded straight away.

## What it does

1. `brew update` (skipped with `-N`).
2. Lists outdated formulae and casks (`brew outdated --json=v2`, parsed with jq).
3. Records when each outdated version was first seen, in the state file.
4. Prints one row per package. The status is one of:
   - `waiting Nd more`: still in the cool-down;
   - `ready (seen Nd)`: cool-down passed;
   - `VULNERABLE: upgrade now`: known vulnerable, so no cool-down;
   - `pinned`: a pinned formula or cask, never upgraded, not even with `-a`.
   Packages from a third-party tap are shown by full name and tagged
   `[3rd-party: user/tap]`.
5. Shows what `brew autoremove --dry-run` would remove.
6. Asks once, on the terminal, before changing anything. With `-y` it does
   not ask. With no terminal and no `-y` it changes nothing and exits 0.
7. After a yes, it does the following:
   - runs `brew upgrade --formula ...` and `brew upgrade --cask ...` for the
     ready packages;
   - runs `brew autoremove` and `brew cleanup`;
   - backs up the Brewfile, refreshes it with
     `brew bundle dump --force --no-vscode` and prints a diff.

These steps need the confirmation (or `-y`) even when nothing is ready or
everything is up to date. Without it, brewup changes only Homebrew's own
metadata (`brew update`) and the state file.

It never runs `brew bundle cleanup`, `brew linkage` (which silently enables
developer mode) or forced upgrades, and it never uses sudo.

## Usage

```sh
brewup [-n] [-N] [-y] [-a] [-d DAYS]
```

| Flag | Meaning |
|---|---|
| `-n` | Dry run: show the plan and stop. Upgrades and removes nothing, but **still runs `brew update`** (fetches tap code) and records first-seen times. Add `-N` for a run that fetches nothing |
| `-N` | Skip `brew update`; work from the current local Homebrew state |
| `-y` | Do not ask for confirmation |
| `-a` | Ignore the cool-down and upgrade everything outdated except pinned packages |
| `-d DAYS` | Cool-down in days (default 3, or `BREWUP_COOLDOWN_DAYS`); a non-negative integer |
| `-h` | Help |

`brewup -n -N` is the inspection-only form: it changes nothing except the state file.

Exit codes: `0` success, nothing to do or declined; `1` a brew command failed;
`2` usage error, an invalid `BREWUP_BREWFILE`, or a missing dependency
(`brew` or `jq` not on PATH).

## Upgrades, dependencies and rollback

- brewup upgrades with `HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1`, so
  Homebrew does not also upgrade outdated *dependents* of the chosen formulae.
  However, `brew upgrade` still upgrades outdated *dependencies* that a
  formula needs. Those dependencies can then be installed before their own
  cool-down has passed. Check the table and use `-n` if that matters.
- Upgrades run with `HOMEBREW_NO_INSTALL_CLEANUP=1`. The cleanup step sets
  `HOMEBREW_NO_CLEANUP_FORMULAE` to the formulae upgraded in this run, adding
  to any value you already have. The previous version of each upgraded formula
  therefore stays installed until the next brewup run cleans it up, so you can
  roll back to it. Casks keep only the current version, which is Homebrew's
  normal behaviour.

## Files

| Path | Purpose |
|---|---|
| `${XDG_STATE_HOME:-~/.local/state}/brewup/seen.tsv` | `kind<TAB>name<TAB>version<TAB>first_seen_epoch` for each outdated version. It is rewritten every run (including `-n`) to hold only versions that are still outdated, and emptied when everything is up to date. Delete it to restart every cool-down. |
| `$BREWUP_BREWFILE` (absolute path), else `$XDG_CONFIG_HOME/homebrew/Brewfile` if `XDG_CONFIG_HOME` is set, else `~/.homebrew/Brewfile` | Brewfile refreshed after a confirmed run. The default follows Homebrew's own user configuration directory, and the parent directory is created if it is missing. A relative `BREWUP_BREWFILE` is rejected. |
| `<Brewfile>.bak-<UTC timestamp>` | Copy of the previous Brewfile, taken before each refresh. The newest three are kept. |

## Examples

```sh
brewup -n -N       # what is waiting, without fetching anything
brewup -n          # same, after brew update
brewup             # upgrade what has passed the cool-down, after confirmation
brewup -d 7        # a more conservative week-long cool-down
brewup -a -y       # upgrade everything now (pinned packages excepted)
```

## Install

```sh
tools/install-user-tools.sh                 # show the plan
tools/install-user-tools.sh --apply         # copy to ~/.local/bin
```

To install elsewhere, use `--prefix DIR` or `BREWUP_INSTALL_DIR=DIR`. DIR is
the bin directory itself; the generic `PREFIX` variable is ignored. An
existing, different `brewup` there is backed up to
`brewup.bak-<UTC timestamp>`. The installer warns if the directory is not on
PATH. It does not edit shell configuration, use sudo or install packages.
brewup needs `jq` (`/usr/bin/jq` ships with recent macOS, or
`brew install jq`).

## Scheduling

Nothing is scheduled automatically. The cool-down counts from the first run
that saw a version, so run brewup regularly, for example daily:

- Run `brewup` by hand, or `brewup -n` from a login shell to see what is waiting.
- Or use a user LaunchAgent or cron job running `brewup -y`. Unattended runs
  then upgrade without asking, so do this only if that is what you want. The
  job's PATH must contain brew and jq (for example `/opt/homebrew/bin`).
  Without `-y`, a scheduled run only records first-seen times.

## Limitations

- The cool-down measures when *this machine* first saw a version as outdated,
  not when the version was published. The first run after installing brewup
  starts every clock at zero.
- The vulnerability bypass is only as good as OSV.dev data and
  `brew outdated --vulnerable`. If that scan fails, brewup prints a warning
  and nothing skips the cool-down on that run.
- Outdated dependencies of an upgraded formula may be upgraded with it (see
  above).
- A cool-down lowers the risk from poisoned releases but does not remove it,
  since a slow-burning compromise can outlast any wait. Homebrew's own
  controls, such as attestation verification and `--require-sha` for casks,
  are configured separately in your Homebrew environment.
- External commands have no time limit; a hung `brew` call blocks brewup.
