# SSH Agent

Optional, off by default. Serves the SSH keys in your vault to `ssh`, Git and
`ssh-keygen -Y sign` while the vault is unlocked, from a helper process that
holds the private keys in memory and never writes them to disk.

This is the setup, verification and threat-model reference. The
[README](../README.md#ssh-agent) has the short version.

Off by default. Turn on **Act as your SSH agent** in the settings screen and the panel starts a separate helper process that serves the SSH keys in your vault to `ssh`, `git`, and `ssh-keygen -Y sign` for as long as the vault is unlocked.

Private keys are held only by that helper, in memory. They never reach QML -- the vault read is split in a `jq` stage and the panel's half has the private material removed before it arrives -- they are never written to disk, and they are dropped when the vault locks, when you log out, and when the helper exits.

**Requirements.** Bitwarden CLI `2025.1.2+` for SSH key items; `2026.8.0+` also fixes a bug where one malformed SSH item fails the whole vault list. `jq`, which the plugin already needs. The helper ships prebuilt for x86_64 Linux. A missing, corrupt, stale, wrong-architecture, non-executable or self-test-failing helper disables **only** this feature, names the reason under **SSH AGENT STATUS**, and leaves the rest of the plugin working.

#### Pointing SSH clients at it

The helper binds `$XDG_RUNTIME_DIR/qs-bitwarden-cli/ssh-agent.sock` (mode `600`, in a `700` directory) and never reads `SSH_AUTH_SOCK` itself -- that variable is how *clients* find an agent. The panel offers **Route SSH Clients Here**, which writes exactly one file:

```
~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent
```

Omarchy runs the graphical session through UWSM, which reads that directory at login, so **the change takes effect at your next login**, not immediately. If something else already owns `SSH_AUTH_SOCK`, the panel names it and asks before replacing it. The file is plugin-owned and recognised by its full contents rather than its name: a symlink, or a file containing anything else, is reported and left alone rather than overwritten.

What the panel says about routing is a hint, not a verdict. It sees the graphical session's environment, while a `.bashrc` export, a systemd user unit, a TTY login or an incoming SSH session can each differ and are invisible from there -- so the status section prints a one-line check to run in the terminal you actually use. To route a shell by hand:

```bash
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/qs-bitwarden-cli/ssh-agent.sock"
```

#### Approving a signature

Every signature asks first. The prompt names the key, its `SHA256:` fingerprint, and the program asking -- its name and the absolute path it ran from -- and gives you two minutes to answer. Not its pid: the number is gone by the time you could look it up, and the grant is not scoped to it.

By default, that prompt appears in a transient card centered on your active screen (**Use centered approval popup**, `sshAgentApprovalPopup`). If you prefer prompts to open the anchored Bitwarden panel instead, disable this setting in Settings or config (`"sshAgentApprovalPopup": false`). If the vault is locked, the card first explains that it must be unlocked and offers the configured PIN, fingerprint, and master-password methods. Unlocking does not approve anything; the same card then changes to the signing question. Escape or a click outside the card denies the request, and keyboard focus starts on **Deny** rather than an approval action.

When multiple SSH requests arrive concurrently (such as parallel `git fetch` or `git submodule` tasks), requests are queued in order (up to 4 deep, matching helper capacity). A badge indicates **1 of N** requests. Answering or denying advances to the next request in the queue. Clicking **Deny all (N)** or pressing `Shift+Escape` dismisses all pending requests immediately. If an SSH client aborts while queued, it is removed automatically.

- **Approve once** signs this request and nothing further.
- **Approve for this program · 2m** also covers later requests from the same executable with the same key, for `sshAgentApprovalWindowSec` seconds (default `120`, maximum `900`, `0` to ask every time). Git spawns a fresh `ssh-keygen -Y sign` for every commit it signs, so this is what makes a twenty-commit rebase one prompt instead of twenty. The grant matches on your UID, the executable path captured at approval, and the key -- deliberately not the pid, which changes with every commit.

Live grants appear under **ACTIVE APPROVALS** with the program and time remaining, revocable one at a time or all at once, and are dropped on lock, logout, and helper exit. They are never written to disk.

Two unanswered or refused prompts in a row start a five-minute cooldown during which signing requests are refused without raising an approval surface. A banner in the panel says so and counts down, because a silent multi-minute SSH outage is impossible to connect back to its cause -- and unattended requests, the case the cooldown exists for, are exactly the ones you were not watching. Approving cannot end a cooldown that is already running: it is the prompts an approval would answer that the cooldown is suppressing. **Resume Signing Now** on that banner is the way out, or wait the five minutes. A process that keeps asking neither shortens the window nor extends it; the refusals it collects are answered without a prompt and never counted.

#### While the vault is locked

Public identities stay advertised, so `ssh` can still offer them, but nothing is signed while the vault is locked. A signing request for a key the helper already knows raises the unlock prompt and holds the request rather than failing it: by that point a specific vault key has been chosen, and refusing a client that has no way to retry is worse than asking. Dismiss the prompt and the signature is refused at once. This does not depend on any setting.

**Unlock on demand** governs a different moment -- the first connection of a session, before any key has been loaded. With no cache there is nothing to offer, and no signing request can ever follow to ask, so the setting lets the identity listing itself raise the unlock prompt. It is off by default because `ssh` asks the agent for identities on every connection -- including ones that go on to authenticate with an on-disk key -- so leaving it on raises the configured unlock surface on the first `ssh` after every login.

#### Public key files, and Git signing

Git needs paths rather than inline keys (`user.signingkey` takes a file; `gpg.ssh.allowedSignersFile` has no inline form at all), so the helper's validated public identities are projected to files:

```
~/.local/share/qs-bitwarden-cli/ssh/<item name>.pub
```

Mode `600` inside a `700` directory. Only public material is ever written there, and only what the helper vouched for. The projection is refreshed on each load and removed on logout, on an account change, and when you turn the feature off; a lock leaves it in place, because locked keys are still advertised. Not `~/.ssh`: that directory belongs to you and to OpenSSH, and a plugin that rewrote a set of files in it would eventually delete something it did not create.

Authentication needs nothing beyond routing. Signing needs Git told where to look:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.local/share/qs-bitwarden-cli/ssh/work.pub
git config --global commit.gpgsign true
```

#### Verifying the helper

The panel checks the shipped binary against `bin/SHA256SUMS` at launch and shows "checksum verified", and says plainly when it is running a locally built development helper instead of the shipped one. Be clear about what that check is worth: `SHA256SUMS` sits in the same directory as the binary *and* as the QML that reads it, so anyone able to replace one can replace the others. It is not tamper detection. What it does catch is real -- a partial clone, an LFS placeholder, an architecture or format mismatch, and above all a stale binary left behind by a `git pull` that updated the source.

Provenance is the separate mechanism with a different root of trust. Releases from `v1.5.0` on carry a GitHub build-provenance attestation binding the binary's digest to this repository, workflow and commit, published alongside an SBOM and a dependency/licence report:

```bash
gh attestation verify bin/x86_64-linux/qs-bitwarden-ssh-agent \
   --repo Elevate08/qs-bitwarden-cli
```

`gh` is not an Omarchy dependency, so this is a check you run if you want it, not one the plugin can assume. Worth re-running after a plugin update, when the binary has changed.

**When the check fails.** The panel disables SSH support, names the reason, and leaves the rest of the plugin working. If a locally built helper is present it falls back to that instead and says so on a banner -- which is the state to be careful about, because signing carries on with a binary that has no recorded digest and no provenance behind it. Either way the fix is to restore the shipped artifact:

```bash
omarchy plugin remove io.github.elevate08.qs-bitwarden-cli
omarchy plugin add https://github.com/Elevate08/qs-bitwarden-cli --enable
```

`omarchy plugin update` is not enough on its own: it pulls, and a pull will not overwrite a tracked file you have modified locally. Removing and re-adding gets you a clean checkout. Nothing you care about lives in the plugin folder -- the session key and stored password are in the keyring, learned suggestions in `~/.local/state` -- so this costs you your `shell.json` settings for the plugin and nothing else.

`omarchy-shell io.github.elevate08.qs-bitwarden-cli sshAgentStatus` reports `helperSource`, `helperChecksum` and `helperState` if you want the verdict without opening the panel.

#### What this does not defend against

- **Anything running as you.** The socket enforces the peer's UID and nothing more. A process running as you can ask for signatures -- it gets a prompt, and the cooldown limits how often it can raise one -- and it can equally replace the helper, the checksum file, and the QML that checks them. Filesystem permissions own that boundary; the plugin cannot defend itself against a same-UID attacker, and neither can any other agent.
- **The process shown in the prompt.** The executable path is reported by the system for context. Only the requesting user is verified. Treat it as a useful hint about *what* is asking, not proof.
- **Agent forwarding.** This release does not support it. A forwarded request is labelled in the prompt, and the process it shows is not the one that will use the signature.
- **Erasure.** Secret memory is zeroized on a best-effort basis and the helper disables core dumps and `PR_SET_DUMPABLE` before the first key is read, but nothing can guarantee that a page freed by an allocator or swapped by the kernel is gone.
- **Root, and the vault itself.** Root reads any process's memory. Separately, `bw` is the source of the keys and holds its own decrypted copies while it runs.

#### Turning it off

Switching **Act as your SSH agent** off stops the helper, removes the socket and FIFO, drops every key and grant, deletes the public-key projection, and removes the routing file -- but only when that file is byte-for-byte the one this plugin wrote. Anything you manage by hand is left alone. Turning the agent back on writes the routing file again, so a toggle costs you nothing; it will not do so when another agent already owns `SSH_AUTH_SOCK`, or when something other than this plugin's own file is sitting at that path. Either way, clients keep the `SSH_AUTH_SOCK` they were given until your next login, so nothing changes under a running session.

To remove the routing file without turning the agent off:

```bash
# Or press "Remove Routing File" in the panel
rm ~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent
```

---
