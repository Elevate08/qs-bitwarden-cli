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
- Auto-type typing while it is off, without an armed login, more than once
  for one arm, after the arm has expired or been dropped, or anything other
  than the armed login's username and password.
- Damage to the OS keyring or to other apps' secrets in it.

## Out of scope

- Limits the README already documents: with fingerprint unlock on, a program
  running as you can open the stored password; root can read anything.
- The quick-unlock envelope's data key kept by a program that recovered it
  by guessing the PIN from a copy, or read it while fingerprint unlock was on
  and before it was turned off. Changing the master password re-wraps the
  same key, so that program can open the later copies too until the envelope
  is deleted: turning fingerprint unlock off deletes it, and so does logging
  out of the account; the methods are then set up again under a new key.
- What the IPC target lets any program running as you do. Its commands are:
  - the panel: `open`, `close`, `toggle`; `settings` opens it on the settings
    screen and `setup` on the setup screen, running the dependency check
    again. Neither changes a setting;
  - the vault: `lock`, `sync`, and `status` (locked, unlocked and so on);
  - accounts: `accounts` reads which exist (their emails and servers, and
    which is active) and `switchAccount <email>` makes another one active,
    locking the current one;
  - auto-type: `autoType` triggers an armed type, only with auto-type on;
  - diagnostics, read-only: `vaultHost` (which screens show the panel and
    which is focused), `desktopState` (vault status, the current screen,
    whether an unlock or PIN entry is under way and which unlock methods are
    ready) and `sshAgentStatus` (the agent's state, how many keys and
    approvals it holds, whether a prompt is showing, the screen-lock reading
    and the cooldown; no key, fingerprint or path);
  - SSH requests, below.

  With the SSH agent on, `sshPending` lists the SSH requests waiting for an
  answer (each one's id, key name and fingerprint, the requesting program's
  path and pid, what is being signed, a login's server host key, whether it
  was forwarded, and whether terminal approval is on). `sshReply <id> deny`
  denies any one of them: the signing request on the card, one queued behind
  it, the unlock request showing, or a queued unlock request. Each of those
  denials counts toward the five-minute signing cooldown except a queued
  unlock request's, and two in a row start it, so such a program can stop the
  agent signing. `sshReply <id> allow` is refused unless you turned on
  **Allow approving from a terminal** (`sshAgentTerminalApproval`, off by
  default); with it on, any program running as you can approve a signing
  request once, its own included, which is what that setting documents. An
  unlock request is never allowed this way. The IPC target never unlocks,
  reads an item or changes a setting.
- The desktop notification for an unanswered SSH request being answered by
  another program. A notification daemon lets any program running as you
  press a notification's button, so the only action on the notification that decides the request is
  **Deny** (its other action, **Answer on the card**, which some daemons
  draw as a second button, decides nothing). **Deny** denies the one signing request on the card at that moment (and
  counts toward the cooldown); it cannot reach a queued request or an unlock
  request, as `sshReply <id> deny` can. Activating the notification any
  other way, dismissing it or letting it expire decides nothing. Nothing a
  notification returns approves a signature; if it does, that is in scope.
- What auto-type, when you turn it on, documents it gives away: the focused
  window gets the password; while a login is armed any program running as
  you can make it type, since the IPC cannot tell who calls it; and `wtype`'s
  keymap, which a program running as you can read while it types, lists the
  characters it is typing.
- Helper memory reaching swap. Neither helper locks its memory (`mlockall` would
  hit the default 8 MiB `RLIMIT_MEMLOCK`), so the kernel may write a page
  holding a decrypted key or the session key to swap. Use encrypted swap, or
  zram with no disk swap, if that matters to you.
- Secrets the shell itself has held (what you type or reveal) appearing in a
  shell core dump. The plugin does not lower the shell's core-file limit,
  because the limit would also apply to every other shell plugin and every app
  the shell starts; see docs/vault-helper.md.
- The address of a link you open from an item. The browser has to be given
  it, so it is an argument to `xdg-open` and, when that starts the browser,
  to the browser for as long as it runs, where other local users can read it.
  Keep tokens and passwords out of the URIs you open, or open them by hand.
- What **Show website icons** (on by default) tells the icon service: the
  host name of each login's first URI, your IP address, and so which sites
  you have saved. The service is your account's server (`icons.bitwarden.net`
  or `.eu` on Bitwarden's cloud); it can also redirect the request to
  another `http` or `https` address, and what it sends back is decoded as an
  image in the shell. Turn the setting off to make no request. A site name
  reaching the journal or a file this way is in scope.
- Your account email and server address in the arguments of `bw login` and
  `bw config server`, which take them only that way, while you sign in.
- The remembered two-step method of a guessed address. It is stored, and passed
  in the arguments of `omarchy bar set`, under an unkeyed SHA-256 of the
  email, so the address is not there in plain text. Anyone who can read those
  arguments (other local users, through `/proc`) or `shell.json` and guesses
  the address can confirm it with one hash and see which two-step method it
  uses. The method is a small number, not a secret.
- Bugs in the Bitwarden server, `bw`, gnome-keyring, systemd, Quickshell or
  Omarchy. Report those upstream, and tell us if the plugin makes them worse.
- An attacker who already controls your unlocked session or your user
  account, unless the plugin gives them more than that already does.

## Safe harbor

Good-faith research on your own machine and your own Bitwarden account is
welcome and will not be treated as hostile. Do not test against accounts or
vaults that are not yours.
