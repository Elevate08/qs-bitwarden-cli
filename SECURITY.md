# Security policy

## Reporting a vulnerability

Please report it privately through GitHub:
**[Report a vulnerability](https://github.com/Elevate08/qs-bitwarden-cli/security/advisories/new)**.
Do not open a public issue, pull request or discussion for it.

Include what you can: the version (`manifest.json`), what an attacker needs
(another local user, a program running as you, root, physical access), steps
to reproduce, and what it exposes. Never send a real vault secret, master
password, keyring file or session token; a made-up test account shows the
same thing.

## What to expect

This is maintained by one person, so these are targets, not guarantees:

- an acknowledgement within 7 days;
- an assessment, and whether it is accepted, within 14 days;
- a fix released within 90 days of the report, sooner for anything that
  leaks the master password, a session key or an SSH private key.

The fix ships as a patch release with a GitHub security advisory, and you are
credited in both unless you ask not to be. Please keep the details private
until the advisory is published, or until 90 days have passed.

## Supported versions

Only the latest release gets security fixes. `omarchy plugin update` moves
you to it.

## In scope

- A master password, session key, PIN, FIDO2 hmac-secret or SSH private key
  reaching disk, the journal, another process's argv or environment, or
  another user.
- Opening the quick-unlock envelope without the PIN, key or fingerprint it is
  protected by, beyond the limits the README documents.
- The SSH agent signing without an approval, outside the grant's program, key,
  kind of signature or server, or for a forwarded request.
- The bundled helpers (`bin/`) not matching their source, or a release whose
  checksums, attestations or SBOM do not match it.
- Anything reachable through the IPC target or the agent socket by a program
  that should not have that power.
- Damage to the OS keyring or to other apps' secrets in it.

## Out of scope

- Limits the README already documents: with fingerprint unlock on, a program
  running as you can open the stored password; root can read anything.
- Bugs in the Bitwarden server, `bw`, gnome-keyring, systemd, Quickshell or
  Omarchy. Report those upstream, and tell us if the plugin makes them worse.
- An attacker who already controls your unlocked session or your user
  account, unless the plugin gives them more than that already does.

## Safe harbor

Good-faith research on your own machine and your own Bitwarden account is
welcome and will not be treated as hostile. Do not test against accounts or
vaults that are not yours.
