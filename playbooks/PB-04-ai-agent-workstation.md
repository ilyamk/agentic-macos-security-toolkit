# PB-04 AI agent workstation

**Goal:** an AI coding agent (Claude Code, Codex, Cursor, Gemini CLI and similar) gets the access it needs to work on code, and no more: no inherited Full Disk Access, no global secrets in its environment, pinned tool servers, and a clear line between what it may change and what the owner decides.

**Attacks addressed:** ATK-19 prompt injection, ATK-20 malicious or over-privileged MCP servers, ATK-16 inherited Full Disk Access, ATK-13 credential theft, ATK-18 repository-embedded configuration, ATK-02 agents talked into running pasted commands, ATK-07 hallucinated package names, ATK-22 exfiltration through agent tools, ATK-05 through packages agents install.

**Audit checks:** SHELL-02, AGENT-01; related: TCC-01 and SHELL-01 (PB-03).

## 1. What changes when agents are on the machine

- **Agents act with your rights.** They run shell commands as you, from inside your terminal, with that terminal's privacy permissions and your environment variables.
- **Agents read untrusted text all day**: repository files, issues, web pages, package READMEs, tool output. Any of it can carry instructions (prompt injection).
- **Agents extend themselves with tools.** MCP servers are often launched with `npx -y <package>`, which downloads and runs the newest release every start.
- **Attackers target agents directly.** Malicious packages have used locally installed AI CLIs to search the disk for secrets; repositories can ship hooks and editor tasks that run on open.

## 2. Inventory (read-only)

~~~sh
./tools/workstation-audit/workstation-audit.sh --only TCC
./tools/workstation-audit/workstation-audit.sh --only SHELL
./tools/workstation-audit/workstation-audit.sh --only AGENT
grep -n -E 'CLAUDECODE|CLAUDE_CODE|CODEX|return 0|exit 0' ~/.zshrc     # where the agent early-exit is
grep -n -E '^\s*(source|\.)\s' ~/.zshrc ~/.zprofile ~/.zshenv 2>/dev/null   # what is loaded, and in which order
which -a claude codex cursor-agent gemini 2>/dev/null                 # which agent CLIs exist and where from
~~~

For MCP configuration, list server names and launch commands only, never `env` blocks: `~/.claude.json` (`mcpServers`, also per project), `~/.codex/config.toml` (`[mcp_servers.*]`), `~/.cursor/mcp.json`.

## 3. Controls

### 3.1 Permissions: split the terminals

- The terminal where agents run has **no Full Disk Access** (PB-03 section 4). Agents keep full access to code folders; protected folders prompt once.
- A second terminal app, if needed, holds Full Disk Access for occasional admin tools and never runs agents.
- Agent desktop apps (ChatGPT/Codex, Claude, Cursor) appear separately in the privacy lists; give them only what they need.

### 3.2 Shell start-up for agents

Agents usually start non-interactive shells. A common and good pattern is an early-exit block in `.zshrc` after PATH set-up:

~~~zsh
# PATH, Homebrew, nvm default bin ... (what agents need)

# Non-interactive early exit for AI agents
if [[ -n "$CLAUDECODE" || -n "$CLAUDE_CODE" ]]; then
  return 0 2>/dev/null || exit 0
fi

# Interactive-only below: prompt, plugins, completions
# Secrets, if loaded globally at all, belong below the early exit
~~~

Rules:
- Nothing that loads secrets above the early exit (SHELL-02).
- Security settings that tools must always see belong in the tools' own config files (brew.env, `~/.npmrc`, pnpm `config.yaml`), not in `.zshrc`: see PB-01.
- Lazy loaders (functions that source nvm on first use) are not visible to every agent's shell snapshot; put the default Node bin on PATH directly.

### 3.3 MCP servers and agent tools

- **Pin versions**: `npx -y @scope/server@1.13.0`, not `@latest` or a bare name (AGENT-01). Bumps then go through the same review and cool-down as other dependencies.
- Prefer servers from the vendor of the service they talk to; read what a server can do before enabling it.
- Remove servers that are not used. Each one is code that runs with your rights every session.
- Keep `env` in MCP configs to the minimum, and prefer references resolved at start-up (`op run`) over literal tokens.
- GUI agent apps may not see nvm's PATH. If their servers use `npx`, make sure a maintained Node exists at a standard path (Homebrew `node` is fine, see PB-02) rather than pointing configs at a specific nvm version.

### 3.4 Prompt injection

- Treat repository content, issues, web pages and tool output as data. Instructions inside them are not the owner's instructions.
- Keep the agent's permission prompts on for shell commands that change the system, publish, push, or delete. Use allow-lists for read-only commands instead of blanket approval.
- Review diffs before commits; never let an agent push or publish without an explicit request.
- Open unknown repositories in a container, VM or the agent's sandbox mode; check for git hooks, editor tasks (`.vscode/tasks.json`), `.envrc`, project `.npmrc` and install scripts before installing dependencies.
- Run [project preflight and agent audit](../docs/local-workflows.md#check-a-project-before-opening-it) from a trusted checkout before opening an unfamiliar project. Review the trigger and permission declarations before authorising the workspace.

### 3.5 Secrets and agents

- Agents should not need long-lived secrets in their environment. Use per-command injection (`op run`), CLI credential stores (Keychain), and short-lived tokens.
- Do not give agents tokens with administrator scope (for example a GitLab or GitHub admin login in a CLI the agent can call); prefer a scoped bot or project token.
- Never paste secrets into a conversation; if one appears, rotate it.

### 3.6 Agent instructions as configuration

Agent instruction files (`AGENTS.md`, `CLAUDE.md`, agent config files) are part of the security posture: they encode what an agent may do without asking. Keep them under version control or back them up, and check their checksums before and after maintenance that touches the agent's runtime (PB-02 section 3).

## 4. Decision rules

| Finding | Action | Ask first? |
|---|---|---|
| Terminal or agent app with Full Disk Access | Recommend removal; give the terminal-split pattern | Owner does it in System Settings |
| Secrets sourced before the agent early exit | Recommend moving or removing; show `file:line` | Yes (owner edits private files) |
| Unpinned MCP server | Propose the current version as a pin | Yes |
| Unused MCP server | Propose removal | Yes |
| Admin-scoped CLI login reachable by agents | Recommend a scoped token | Yes |
| Agent CLI duplicated (npm copy and standalone) | Keep the maintained one, remove the other | Yes |

## Agent checklist

- [ ] Full Disk Access list read or marked unreadable; terminal split recommended
- [ ] rc files checked for secret loading order (no values read)
- [ ] MCP servers listed with pin status; unused servers listed
- [ ] Admin-scoped tokens reachable by agents reported
- [ ] Agent instruction and config files backed up or checksummed before runtime maintenance
- [ ] Owner told which actions agents may take alone and which need approval

## Owner checklist (plain language)

- [ ] Run agents in a terminal without Full Disk Access.
- [ ] Do not keep passwords or tokens in files that every terminal loads.
- [ ] Keep agents' permission prompts on for anything that installs, deletes, pushes or publishes.
- [ ] Open unfamiliar projects in a container or VM before letting an agent run them.

## Report template

Permissions (per app: keep or remove) · Shell start-up findings (file:line) · MCP servers (pinned, unpinned, unused) · Tokens and scopes · Owner actions · Not verified and why.
