# Vault helper

The unlocked vault is held by a small helper process, `qs-bitwarden-vault`,
not by the shell. If the shell crashes while your vault is open, the core
dump systemd keeps (in `/var/lib/systemd/coredump`, readable by you, for about
two weeks) does not contain your session key or your items' secrets. The
shell's own core dumps are left alone, so a shell crash can still be
diagnosed.

The [README](../README.md#how-your-vault-is-held) has the short version.

## What the helper holds, and what the shell holds

| | Helper | Shell |
|---|---|---|
| Session key | yes | a placeholder that says the helper has it |
| The item list | every item in full | names, usernames, websites, folders, flags such as "has a password" |
| Passwords, TOTP keys, passkeys, password history, notes, card numbers and codes, identity numbers, hidden custom fields | yes | only a value you reveal, while it is revealed; the whole item while you edit it |
| The master password a PIN, fingerprint or FIDO2 key opens | yes, for that unlock | a reference by name |
| What you type: the master password and PIN for unlocking, and the master password for a re-prompt | yes: typed into pinentry, a separate process, and passed to the helper | a reference by name |
| What else you type (the email login, a new item's fields) | | yes, until you submit |

Opening an item shows its name, username, websites, card brand, holder and
expiry, identity name, email, address and phone, plain custom fields and
attachment names. Each secret is a masked row, and notes are hidden until you
click their eye button. Revealing one asks the helper for that one value; the
shell keeps it until you hide it, close the item or open another, leave the
screen, close the panel or lock. Editing asks for the whole item and drops it
when the form is left. These values are dropped, not wiped: a dropped value
can stay in the shell's memory until that memory is reused, so a shell core
dump taken after you revealed something can still contain it.

A password or other secret you copy goes from the helper straight to
`wl-copy` (with the same timed clear and "sensitive" marking); it never passes
through the shell. TOTP codes are computed in the helper, and only the code
reaches the shell, not the key. Search runs in the helper too, so it still
finds text in notes the shell does not have, and it stays fast on a large
vault. Notes of an item that asks for the master password are not searched.

An item that asks for the master password asks for it before a value is
revealed, copied or edited, and its TOTP code is fetched only when you reveal
or copy it.

Locking, logging out and switching accounts tell the helper to forget
everything. A lock that is still running `bw lock` keeps its own copy of the
key until it finishes.

## How the shell talks to it

The shell starts the helper as its own child process and talks to it only on
the helper's stdin and stdout, one JSON object per line. There is no socket,
FIFO or port: no other program can connect to it or ask it anything.

Every `bw` command the panel runs goes through the helper, which adds
`BW_SESSION` (or a held password) to that one command's environment. Its
output is handed back as it is, except:

- a session key in it (`bw unlock`, `bw login`, a remembered session) is kept
  by the helper and replaced by a placeholder;
- the item list and a saved item are kept, and handed back with their
  secrets removed (the shell then asks for one value at a time: `field` to
  show it, `copyField` to copy it, `item` to edit);
- the master password a quick-unlock method opens is kept, and the shell gets
  a reference to it;
- a password or PIN typed into pinentry (below) is kept, and the shell gets
  only whether there was an answer.

## Typing into pinentry

A string typed into the panel stays in the shell's memory after the field is
cleared, so a shell core dump could hold it. The master password for
unlocking and for a re-prompt, and the PIN, are therefore typed into
`pinentry`, a separate process. The panel hides while it runs so it can take
the keyboard, and shows again after.

The helper runs a small script that speaks the pinentry protocol, and keeps
what it prints, decoded, under a name; the shell only learns whether you
answered or cancelled. The held password or PIN goes to `bw unlock`, the
quick-unlock check or the re-prompt check by name, and is forgotten as soon as
that has finished. A wrong password or PIN opens pinentry again with the
reason.

The pinentry used is `pinentry` from `PATH`; `pinentryProgram` in `shell.json`
names another, and the setting "Type secrets in pinentry" turns this off. The
panel's own field is used instead when pinentry is turned off or not installed,
when the helper is not running (typed into the shell, pinentry would gain
nothing), or when pinentry fails to run, which shows a short notice. The
email login and the item forms are not covered.

## Hardening

Before it reads anything, the helper sets its core-file limit to zero (soft
and hard) and makes itself non-dumpable, so no core is written for it and
other programs cannot attach to it or read its memory. Buffers holding
secrets are wiped when dropped; as with the SSH helper, that is best effort
and cannot cover memory the allocator or the kernel keeps. Neither helper
locks its memory, so the session key can be written to swap; encrypted swap,
or zram with no disk swap, avoids that. Release builds abort on panic rather
than unwinding.

The commands it runs inherit the zero core limit, so a `bw` that crashes
while holding your decrypted vault does not leave a core either.

## Limits

- **Other programs running as you are not kept out.** `bw` takes the session
  key only in its environment, and Linux lets any process running as the same
  user read another's `/proc/<pid>/environ`, so the key is readable while a
  `bw` command runs. That was true before the helper and is true of `bw`
  everywhere; see [SECURITY.md](../SECURITY.md) for what is in scope.
- **What is on screen, and what you type, is in the shell.** That is what you
  type into the panel's own fields (the email login, item fields, and the
  master password or PIN when pinentry is not used). Clearing it does not wipe
  it, so it can stay in the shell's memory and be in a shell core dump.
- **The shell's core dumps are left on.** The plugin does not lower the
  shell's core-file limit. The limit is per process and inherited, so it would
  also turn off core dumps for every other plugin in the shell and for every
  app started from the shell's launcher, until the shell restarts. The plugin
  keeps secrets out of the shell instead.
- **Code running in the shell.** The helper does not protect against it.
  Such code can ask the helper to run a command with the session key or a
  held password in its environment.
- **The master-password reprompt** is checked by the panel, not the helper.

## If the helper is missing or fails

It is checked like the other helpers: present, executable, the right
architecture, the checksum in `bin/SHA256SUMS`, its own self-test, and the
protocol version. A locally built one (`vault/target/debug/`) is used if the
shipped one is absent or unusable.

If none can be used when the shell starts, the panel works as it did before:
the session and the items are held in the shell, and a banner says crash
protection is off and why.

If the helper stops while the vault is open, the session key goes with it, so
the vault locks as the lock button would: the SSH agent drops its private keys
and grants, the remembered session is cleared, and the panel asks you to
unlock again. The helper is restarted up to three times; the count clears
once it has stayed up for a minute. If it keeps stopping, the vault stays
locked and the banner offers to try again. The panel does not move the vault
into the shell in that case.

## Verifying the shipped binary

The binary is built reproducibly and attested like the SSH helper
([docs/ssh-agent.md](ssh-agent.md#verifying-the-helper)):

```bash
./scripts/build-agent.sh --compare-tracked
gh attestation verify bin/x86_64-linux/qs-bitwarden-vault --repo Elevate08/qs-bitwarden-cli
bin/x86_64-linux/qs-bitwarden-vault --self-test
```
