# PB-02 JavaScript runtime hygiene: Node, nvm, pnpm copies, version pins

**Goal:** one supported Node per major line that projects actually need, one global pnpm, global CLIs in a known place, and project version pins that stay in step with CI and get security patches without manual chasing.

**Attacks addressed:** ATK-11 PATH hijacking through user-writable prefixes, ATK-12 unpatched runtimes and stale pins, ATK-23 CI/CD pipeline drift. Related: ATK-06 through the npm bundled with each Node, and ATK-08 because a release-age delay on pins also delays a backdoored release.

**Audit checks:** NODE-01, NODE-02, NODE-03, NPM-04, PNPM-02.

## 1. Why this matters

- Every Node version under nvm ships its own npm. Old npm silently ignores the hardening keys from PB-01, so an old Node quietly removes protection (NPM-04).
- Several copies of the same tool (Node from Homebrew and nvm, pnpm from Homebrew, a standalone installer and npm) mean that *which* copy runs depends on PATH order, and each copy updates differently.
- Global CLIs installed into an old Node vanish when that Node is removed, and some agent tooling depends on them.
- Projects that pin an exact Node patch in `.nvmrc`, Dockerfile and CI are doing the right thing for reproducibility, but pins that nobody bumps go stale and miss security releases.

## 2. Inventory (read-only)

~~~sh
ls ~/.nvm/versions/node; cat ~/.nvm/alias/default; ls ~/.nvm/alias
for d in ~/.nvm/versions/node/*; do echo "$(basename "$d") npm=$("$d/bin/npm" -v)"; done
for v in ~/.nvm/versions/node/*; do echo "== $(basename "$v")"; "$v/bin/npm" ls -g --depth=0 2>/dev/null | tail -n +2; done
brew uses --installed node; brew uses --installed pnpm      # does anything in brew need them?
which -a node npm pnpm corepack
which -a pnpm; pnpm -v                                       # in the owner's terminal: what an interactive shell runs
pnpm ls -g                                                   # standalone pnpm under ~/Library/pnpm?
curl -s https://nodejs.org/dist/index.json | jq -r '.[0:40][] | [.version,.date,.npm,(.security|tostring),(.lts|tostring)] | @tsv'
./tools/workstation-audit/workstation-audit.sh --only NODE
~~~

Then map what projects need. Search only directories the owner points you at:

~~~sh
find <projects-dir> -maxdepth 4 \( -name .nvmrc -o -name .node-version -o -name .tool-versions \) -not -path '*/node_modules/*' \
  -exec sh -c 'printf "%s: %s\n" "$1" "$(head -1 "$1")"' _ {} \;
find <projects-dir> -maxdepth 3 -name package.json -not -path '*/node_modules/*' \
  -exec jq -c '{f: input_filename, node: .engines.node, pm: .packageManager}' {} \; | grep -v '"node":null,"pm":null'
~~~

Also find what depends on a specific Node path before removing anything:

~~~sh
grep -rIl -E 'nvm/versions/node/v<X>|/opt/homebrew/bin/(node|npx|npm)' \
  ~/.config ~/Library/LaunchAgents ~/.local/bin ~/.zshrc ~/.zprofile 2>/dev/null
# Agent configs too: ~/.claude.json, ~/.codex/config.toml, ~/.cursor/mcp.json (server commands only, never env values)
~~~

## 3. Decision rules

| Situation | Recommendation |
|---|---|
| Several patches of one major | Keep the newest patch of each major a project needs; remove the rest (ask first) |
| A major nobody needs | Remove (ask first); it can be reinstalled in a minute with `nvm install` |
| An end-of-life major | Remove unless a project needs it; then flag that project |
| A needed major ships npm older than 11.19 | Inside that version: `npm i -g npm@<exact 11.x release at least a week old>` (old npm ignores `min-release-age`, so a bare `npm@11` gets the newest release immediately) |
| Global CLIs in a Node being removed | Reinstall in the default Node first (with `--allow-scripts=<listed packages>` if PB-01 is active), check each runs, then remove |
| A CLI that also exists as a standalone install (for example an agent CLI in `~/.local/bin`) | The npm copy is a duplicate; do not reinstall it |
| Homebrew `node` next to nvm | **Keep it if anything uses `/opt/homebrew/bin/node`**: GUI apps do not see nvm's PATH, and some agent tools fall back to that path. It updates through brewup with attestations, which is fine |
| Several pnpm copies | Keep one (Homebrew is a good choice: delayed upgrades and attestations). Remove the standalone one with `pnpm rm -g pnpm` and per-Node copies with `npm rm -g pnpm`. Projects still get their pinned pnpm through `packageManager` |
| Left-over shims (`pnpx`, `pnx`) pointing at a removed pnpm | Remove them; otherwise they shadow working copies earlier in PATH |

Before removing Node versions, check that the owner's agent tooling is not affected: record checksums of agent instruction and config files (for example `shasum -a 256 ~/.codex/AGENTS.md ~/.codex/config.toml`) and compare them afterwards. Removing an nvm version deletes only `~/.nvm/versions/node/vX`.

## 4. Applying (after approval)

~~~sh
nvm install "${NEW_NODE_VERSION:?Set the approved Node patch with its v prefix}"
# Run this npm upgrade only if the new Node ships an older npm.
PATH="${NVM_DIR:-$HOME/.nvm}/versions/node/$NEW_NODE_VERSION/bin:/usr/bin:/bin" \
  npm i -g "npm@${APPROVED_NPM_VERSION:?Set the exact approved npm release}"
# Reinstall and verify each approved global CLI in the intended default Node.
default_bin="${NVM_DIR:-$HOME/.nvm}/versions/node/${DEFAULT_NODE_VERSION:?Set the intended default Node version with its v prefix}/bin"
PATH="$default_bin:/usr/bin:/bin" npm i -g "${APPROVED_CLI_PACKAGE:?Set the approved CLI package}" \
  --allow-scripts="${APPROVED_SCRIPT_PACKAGES:?Set the reviewed comma-separated script allow-list}"
"$default_bin/${APPROVED_CLI_COMMAND:?Set the installed CLI command}" --version
# Repeat for each approved removal. Keep the active and default versions.
nvm uninstall "${OLD_NODE_VERSION:?Set the approved obsolete Node version}"
nvm alias default "$DEFAULT_NODE_VERSION"
nvm ls
~~~

Check new Node releases against the cool-down idea too: a patch that came out yesterday can wait a few days unless it is a security release (the `security` flag in `index.json`).

## 5. Project version pins: leave them alone

**Lesson learned the hard way.** It is tempting to "relax" `.nvmrc` from `24.20.0` to `24` so that one installed Node serves every project. **Do not do that in shared repositories.** In practice the exact patch was deliberately pinned in every repository examined, and a relaxed pin would have:

- failed a CI step that compares `node --version` with `.node-version`;
- failed an architecture test asserting `.nvmrc`, `engines` and the Docker image tag name the same version;
- broken a written rule that the Node pin moves together with the Dockerfile `FROM` line and digest-pinned CI images in a dedicated merge request;
- made local development run a different Node from CI and production.

Before touching any pin, search the repository: `git grep -n -E 'nvmrc|node-version|NODE_VERSION|FROM node|image: node'`. If anything else names the version, the pin is intentional.

What to do instead locally: install the exact version when working on that project (`nvm install` in the project directory reads `.nvmrc`). Do not keep every historical patch "just in case".

## 6. Keeping pins fresh: automate the bump, not the loosening

Exact pins are correct (reproducible builds; digest pins also stop a re-pushed image tag). The real problem is that they age: a check on real projects found every pin behind the latest patch, each missing one or two Node security releases. The fix is automation that **moves all pins together**:

- A self-hosted Renovate run (a scheduled CI job in a dedicated project with a bot account, not a personal or admin token) reads `.nvmrc`, `.node-version`, `engines`, Dockerfile `FROM`, CI `image:` and docker-compose, plus custom regex managers for places like `ARG NODE_VERSION` or CI variables.
- A grouping rule puts every Node reference of a repository into **one** merge request, with the image digest updated alongside the tag.
- Each repository's own CI validates that merge request; consistency tests are the safety net.
- Keep a cool-down (a few days) and use the dependency dashboard to fast-track security releases.
- Add a consistency check (".nvmrc, engines and image tag name one version") to repositories that lack one.

Legacy worth flagging while you are there: end-of-life Node in docker-compose files, sub-package CI files with floating old tags, and code generators whose templates still emit old base images.

## 7. Verification

~~~sh
nvm ls; cat ~/.nvm/alias/default
for d in ~/.nvm/versions/node/*; do PATH="$d/bin:/usr/bin:/bin" npm config get strict-allow-scripts; done
which -a pnpm pnpx; pnpm -v                    # in the owner's terminal
(cd "${PROJECT_DIR:?Set the project path}" && pnpm -v)  # compare with the project's packageManager version
default_bin="${NVM_DIR:-$HOME/.nvm}/versions/node/${DEFAULT_NODE_VERSION:?Set the intended default Node version with its v prefix}/bin"
PATH="$default_bin:/usr/bin:/bin" "$default_bin/${APPROVED_CLI_COMMAND:?Set the installed CLI command}" --version
shasum -a 256 "$HOME/.codex/AGENTS.md" "$HOME/.codex/config.toml"  # compare with the checksums recorded before the change
./tools/workstation-audit/workstation-audit.sh --only NODE
./tools/workstation-audit/workstation-audit.sh --only PNPM
~~~

## Agent checklist

- [ ] Node versions, their npm versions and global packages listed
- [ ] Project needs mapped from `.nvmrc`, `.node-version`, `engines`, `packageManager`
- [ ] Dependants of each Node path found (configs, LaunchAgents, agent configs, GUI fallbacks)
- [ ] Removal list approved by the owner; global CLIs reinstalled and run before removal
- [ ] Old npm upgraded in kept versions; hardening keys effective everywhere
- [ ] One global pnpm; stale shims removed; project-pinned pnpm still selected
- [ ] Agent config checksums unchanged
- [ ] No shared repository pin edited; stale pins reported with the security releases they miss

## Owner checklist (plain language)

- [ ] Keep only the Node versions your projects use; reinstalling one takes a minute.
- [ ] Do not change version files in team repositories to make your laptop simpler; agree a bump with the team.
- [ ] Ask the team to automate version bumps (one merge request per bump, checked by CI).

## Report template

Done (versions kept, removed, installed; CLIs reinstalled and proven) · Pins found and how stale they are · Owner decisions needed · Not done and why.
