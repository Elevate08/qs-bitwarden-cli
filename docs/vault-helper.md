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
| Passwords, TOTP keys, passkeys, password history, notes, card numbers and codes, identity numbers, hidden custom fields | yes | only the one item you open, while it is open |
| The master password a PIN, fingerprint or FIDO2 key opens | yes, for that unlock | a reference by name |
| What you type (master password, PIN, a new item's fields) | | yes, until you submit |

A password you copy goes from the helper straight to `wl-copy` (with the same
timed clear and "sensitive" marking); it never passes through the shell. TOTP
codes are computed in the helper, and only the code reaches the shell. Search
runs in the helper too, so it still finds text in notes the shell no longer
has (except on items that ask for the master password), and it stays fast on a large vault.

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
  secrets removed;
- the master password a quick-unlock method opens is kept, and the shell gets
  a reference to it.

## Hardening

Before it reads anything, the helper sets its core-file limit to zero (soft
and hard) and makes itself non-dumpable, so no core is written for it and
other programs cannot attach to it or read its memory. Buffers holding
secrets are wiped when dropped; as with the SSH helper, that is best effort
and cannot cover memory the allocator or the kernel keeps. Release builds
abort on panic rather than unwinding.

The commands it runs inherit the zero core limit, so a `bw` that crashes
while holding your decrypted vault does not leave a core either.

## Limits

- **Other programs running as you are not kept out.** `bw` takes the session
  key only in its environment, and Linux lets any process running as the same
  user read another's `/proc/<pid>/environ`, so the key is readable while a
  `bw` command runs. That was true before the helper and is true of `bw`
  everywhere; see [SECURITY.md](../SECURITY.md) for what is in scope.
- What is on screen, and what you type, is in the shell.

## If the helper is missing or fails

It is checked like the other helpers: present, executable, the right
architecture, the checksum in `bin/SHA256SUMS`, its own self-test, and the
protocol version. A locally built one (`vault/target/debug/`) is used if the
shipped one is absent or unusable.

If none can be used, or the helper keeps stopping, the panel works as it did
before: the session and the items are held in the shell. A banner says crash
protection is off and why. If the helper stops while the vault is open, the
session key goes with it, so the vault locks as the lock button would: the
SSH agent drops its private keys and grants, the remembered session is
cleared, and the panel asks you to unlock again.

## Verifying the shipped binary

The binary is built reproducibly and attested like the SSH helper
([docs/ssh-agent.md](ssh-agent.md#verifying-the-helper)):

```bash
./scripts/build-agent.sh --compare-tracked
gh attestation verify bin/x86_64-linux/qs-bitwarden-vault --repo Elevate08/qs-bitwarden-cli
bin/x86_64-linux/qs-bitwarden-vault --self-test
```
