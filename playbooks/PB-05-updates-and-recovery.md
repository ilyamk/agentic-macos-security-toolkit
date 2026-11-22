# PB-05 — macOS updates, recovery and suspicious commands

The goal is to establish patch and restore readiness and help the owner respond to a suspicious terminal instruction. See [the threat catalogue](../docs/attack-catalogue.md) for ATK-02, ATK-12, ATK-21, ATK-24 and ATK-25.

## Read-only audit

~~~sh
./bin/macos-security doctor --json
./bin/macos-security updates status
./bin/macos-security recovery check
~~~

1. Read the version, build and status for the installed branch. When the reference is stale, compare with Apple's current security bulletins. For an organisation-managed Mac, confirm the approved update and deadline with IT.
2. Ask the owner to verify Time Machine's destination and encryption in System Settings. Record the approximate age of the last successful backup and where the owner can recover the credentials needed to read it. Keep recovery keys and passwords in the owner's approved storage.
3. Check FileVault, remote access and physical-security settings in the assessment. Test the intended remote access from an approved device before making changes that could lock the owner out.
4. Review the state after the owner applies a change. Recheck the installed build after restarting. A background correction reported by the operating system is a separate observation from an available full system update.

[Apple software update management](https://support.apple.com/guide/deployment/install-and-enforce-software-updates-depd30715cbb/web) · [Apple Time Machine](https://support.apple.com/en-us/104984)

## Verify a small restore

1. Create a disposable file containing non-sensitive text. Include it in the next successful Time Machine backup.
2. Preserve the original. Use Time Machine to recover the sample into a separate location. If the restore UI would overwrite the original, use a disposable folder or a separate Mac and follow the owner's recovery procedure.
3. Compare the original and recovered copies with `recovery record-drill`. Save the record locally for the next `recovery check`.

~~~sh
./bin/macos-security recovery record-drill "$original_sample" "$restored_sample" --output "$drill_record"
./bin/macos-security recovery check --drill "$drill_record"
~~~

The record confirms that the owner-selected copies matched. It contains the time and outcome. Test critical data and account recovery separately on a schedule suited to the owner or organisation.

## Respond to a suspicious command or request

| Situation | First steps |
| --- | --- |
| macOS blocked the paste or script | Dismiss the alert. Verify the request using an independently chosen support channel. Preserve the time and context privately if the request needs reporting. |
| The command may have run | Stop the activity and alert IT or the owner. If your incident procedure calls for isolation, use its approved method and preserve evidence privately. Use the [incident-response guide](../docs/incident-response.md) for collection and escalation. |
| An account session or credential may have been exposed | Move to a known-clean device. Revoke applicable sessions and tokens, review sign-ins and new authorisations, rotate affected credentials and escalate to the organisation as appropriate. |
| A message, approval or call claims to come from someone you know | Confirm the request using a known number, trusted channel or existing approval workflow independently of the sender's contact details. |

Apple documents terminal paste and script protections beginning in macOS 26.4. Alert behaviour depends on which protection applies and on how the Mac is used. Keep remote access, security updates and recovery instructions available offline.

[Apple Terminal and script protections](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web) · [Apple blocked paste guidance](https://support.apple.com/en-us/127377)

## Owner checklist

- [ ] I know which macOS branch and build I am running and where to check for its updates.
- [ ] I can reach my backup and its recovery credentials without relying on the affected Mac.
- [ ] I restored and compared a disposable sample.
- [ ] I know whom to contact through a trusted channel after a suspicious command.
