# PB-03 Infostealer defence

**Goal:** make the common macOS stealer chain fail at as many steps as possible: getting the user to run it, reading secrets from disk, persisting, and sending data out.

**Attacks addressed:** ATK-01 infostealers, ATK-02 ClickFix, ATK-03 fake installers, ATK-04 fake password prompts, ATK-13 credential files, ATK-14 session and token theft, ATK-15 persistence, ATK-16 Full Disk Access abuse, ATK-17 browser extensions, ATK-22 exfiltration, ATK-25 AI-assisted phishing (verification habits).

**Audit checks:** OSEE-01 to OSEE-03, TCC-01, SHELL-01, NPM-05 (tokens in `~/.npmrc`); related: SHELL-02 (PB-04). The main assessment (`./bin/macos-security assess --deep`) adds persistence, browser extension, native messaging and credential-permission findings.

## 1. How a typical stealer works

1. **Delivery** through the user: a fake download page reached from an advert, a "paste this into Terminal to fix it" page (ClickFix), a cracked app, a fake meeting or update app.
2. **Password grab**: an `osascript` dialog that looks like a system prompt asks for the login password, which unlocks the login Keychain.
3. **Collection**: browser cookies and saved passwords, Keychain, `~/.ssh`, cloud credentials (`~/.aws`, `~/.config/gcloud`), `.env` files, CLI tokens, messaging sessions (Telegram), crypto wallets, notes and documents.
4. **Exfiltration** over HTTPS to a server or a messaging bot, often within seconds.
5. **Optional persistence** through a LaunchAgent or login item.

Each control below breaks one of those steps.

## 2. Inventory (read-only)

~~~sh
./bin/macos-security assess --profile developer --deep
./bin/macos-security validate "$(./bin/macos-security latest assessments)"
ls /Applications | grep -i -E 'lulu|blockblock|knockknock'
systemextensionsctl list
ls /Library/LaunchDaemons | grep -i objective
spctl --status                                        # Gatekeeper
./tools/workstation-audit/workstation-audit.sh --only OSEE
./tools/workstation-audit/workstation-audit.sh --only TCC
./tools/workstation-audit/workstation-audit.sh --only SHELL
~~~

Do not open `.env` files, private rc files, `~/.ssh` or keychains. Report where secrets are loaded from (`file:line`), never what they contain.

## 3. Objective-See tools (free, open source)

| Tool | Breaks | Install | Needs |
|---|---|---|---|
| **LuLu** | Exfiltration (step 4): asks before any new outbound connection | `brew install --cask lulu` (no sudo) | Owner approves the network extension |
| **BlockBlock** | Persistence (step 5): alerts when something installs itself to auto-start | `brew install --cask blockblock` **in the owner's own terminal** (the installer asks for a password) | Full Disk Access for BlockBlock |
| **KnockKnock** | Finds what already auto-starts | `brew install --cask knockknock` | None |

Owner steps for LuLu:
1. Open `/Applications/LuLu.app`.
2. System Settings → General → Login Items & Extensions → Network Extensions: allow LuLu.
3. Confirm the network filter prompt.
4. If a VPN (Tailscale, WireGuard and so on) is in use, allow its connections in LuLu.

Verification:

~~~sh
systemextensionsctl list | grep -i lulu                       # [activated enabled]
pgrep -lx BlockBlock; /bin/ps -axo user=,comm= | grep -i blockblock   # runs as root
ls /Library/LaunchDaemons | grep -i objective
codesign -dv --verbose=2 /Applications/LuLu.app 2>&1 | grep TeamIdentifier   # VBG97UB4TA (Objective-See)
spctl -a -vv /Applications/LuLu.app                            # Notarized Developer ID
log show --last 30m --predicate 'process == "BlockBlock"' --style compact | grep -i -E 'not permitted|denied|error'
~~~

The same `codesign`/`spctl` pair is a good habit for any downloaded app: check the Team ID and notarisation, including for apps the owner renamed on purpose.

## 4. Full Disk Access: who should hold it

macOS grants privacy permissions to the **responsible application**. A CLI started in a terminal inherits that terminal's permissions, so if the terminal has Full Disk Access, so does every script, every package install script and every AI agent started in it.

Reading the system TCC database works only for a process that already has Full Disk Access, so the attempt is itself a test:

~~~sh
/usr/bin/sqlite3 -readonly "/Library/Application Support/com.apple.TCC/TCC.db" \
  "select client, auth_value from access where service='kTCCServiceSystemPolicyAllFiles'"
# auth_value 2 = allowed. "unable to open" = this terminal does not have Full Disk Access.
~~~

Recommendation:
- **Remove Full Disk Access from the terminal used for development and agents.** Code in ordinary home folders, git, builds, Docker and the network keep working. Desktop, Documents, Downloads and cloud folders ask once. Mail, Messages, Safari data, other apps' containers and Time Machine become unreachable, which is the point.
- If a tool genuinely needs Full Disk Access (a disk cleaner, a backup check), use a **second terminal app** that holds it, and never run agents or package installs there.
- Keep BlockBlock (and any EDR) in the list.
- Review every other entry; apps that are not security or backup tools rarely need it.
- Restart the terminal after changing the setting.

## 5. Secrets out of files

| Where secrets usually sit | Better place |
|---|---|
| `~/.ssh/id_*` private keys | Password manager SSH agent (1Password, Secretive, or a hardware key) |
| `~/.env` sourced from `.zshrc` | References (`op://vault/item/field`) resolved at run time with `op run -- <command>` |
| Tokens exported in rc files | The tool's own credential store (`gh auth login` uses the Keychain) |
| Project `.env` | Not committed; loaded per command; scanned with `./bin/macos-security dev-scan` (Gitleaks, values redacted) |
| Browser-saved passwords | A password manager with a separate master password |

**Pitfall: secrets sourced before the agent early-exit.** Many rc files end the interactive part early for AI agents. If `source ~/.env` comes *before* that block, every agent shell inherits every secret (SHELL-02). Move secret loading after the block, or better, stop loading secrets globally.

## 6. Social-engineering hygiene (ClickFix, fake prompts)

- Never paste commands from a web page, chat or "verification" box into Terminal.
- An unexpected password dialog, especially one that appears right after opening a download, is a warning sign. Cancel it and check what launched it.
- Install apps from the vendor's site or the App Store; install Homebrew only from brew.sh.
- Do not disable Gatekeeper, do not remove quarantine attributes (`xattr -d com.apple.quarantine`) blindly, do not use `--no-quarantine`.
- Run unknown CLIs, other people's `npm install`, and agents on untrusted code in a container or VM (OrbStack, Lima, a devcontainer) or in the agent's sandbox mode.

## 7. If a stealer is suspected

Follow [docs/incident-response.md](../docs/incident-response.md) and `AGENTS.md` P4: preserve first, run `./bin/macos-security incident`, and rotate passwords, tokens and sessions **from a different, trusted device**. Revoke browser sessions (Google, GitHub, cloud consoles), messaging sessions (Telegram: Settings → Devices) and API keys.

## Agent checklist

- [ ] Assessment run and validated; persistence and extension findings reviewed
- [ ] LuLu, KnockKnock installed; BlockBlock command handed to the owner
- [ ] Owner steps for the network extension and BlockBlock Full Disk Access given
- [ ] Signature and notarisation of installed security tools verified
- [ ] Full Disk Access list read (or marked as not readable) and recommendations given per entry
- [ ] Places where secrets are loaded reported as `file:line`; no values read
- [ ] SHELL-02 ordering checked
- [ ] Incident procedure referenced if anything looked like a detection

## Owner checklist (plain language)

- [ ] Open LuLu and allow its extension; answer its questions thoughtfully, and block what you do not recognise.
- [ ] Install BlockBlock yourself in Terminal and give it Full Disk Access.
- [ ] Remove Full Disk Access from your everyday terminal.
- [ ] Move SSH keys into your password manager; stop keeping tokens in `.env` files.
- [ ] Never paste commands from websites into Terminal. Unexpected password windows mean "stop".
- [ ] If you think you were infected, change passwords from another device.

## Report template

Done (tools installed and verified) · Owner steps (GUI, sudo) · Full Disk Access: remove / keep, per app · Secret locations to migrate · Not verified (Full Disk Access state, extension approval) and why.
