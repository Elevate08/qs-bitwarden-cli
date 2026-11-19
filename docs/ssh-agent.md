# SSH Agent

Optional, off by default. Serves the SSH keys in your vault to `ssh`, Git and
`ssh-keygen -Y sign` while the vault is unlocked, from a helper process that
holds the private keys in memory and never writes them to disk.

This is the setup, verification and threat-model reference. The
[README](../README.md#ssh-agent) has the short version.

Off by default. Turn on **Act as your SSH agent** in the settings screen and the panel starts a separate helper process that serves the SSH keys in your vault to `ssh`, `git`, and `ssh-keygen -Y sign` for as long as the vault is unlocked.

Private keys are held only by that helper, in memory. They never reach QML -- the vault read is split in a `jq` stage and the panel's half has the private material removed before it arrives -- they are never written to disk, and they are dropped when the vault locks, when you log out, and when the helper exits.

**Requirements.** Bitwarden CLI `2025.1.2+` for SSH key items; `2026.8.0+` also fixes a bug where one malformed SSH item fails the whole vault list. `jq`, which the plugin already needs. The helper ships prebuilt for x86_64 and aarch64 Linux (`bin/x86_64-linux/`, `bin/aarch64-linux/`); the panel picks the one for the machine's processor (`uname -m`). A missing, corrupt, stale, wrong-architecture, non-executable or self-test-failing helper disables **only** this feature, names the reason under **SSH AGENT STATUS**, and leaves the rest of the plugin working.

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

Every signature asks first. The prompt says what is being signed -- a Git commit or tag signature, a signature in another `ssh-keygen -Y` namespace, an SSH login as a named user, or data the helper does not recognise -- and, for a login, the `SHA256:` fingerprint of the server's host key -- then names the key, its `SHA256:` fingerprint, and the program asking -- its name and the absolute path it ran from -- and gives you two minutes to answer. Not its pid: the number is gone by the time you could look it up, and the grant is not scoped to it.

By default, that prompt appears in a transient card centered on your active screen (**Use centered approval popup**, `sshAgentApprovalPopup`). If you prefer prompts to open the anchored Bitwarden panel instead, disable this setting in Settings or config (`"sshAgentApprovalPopup": false`). If the vault is locked, the card first explains that it must be unlocked and offers the configured PIN, fingerprint, and master-password methods. Unlocking does not approve anything; the same card then changes to the signing question. Escape or a click outside the card denies the request, and keyboard focus starts on **Deny** rather than an approval action.

When multiple SSH requests arrive concurrently (such as parallel `git fetch` or `git submodule` tasks), requests are queued in order (up to 4 deep, matching helper capacity). A badge indicates **1 of N** requests. Answering or denying advances to the next request in the queue. Clicking **Deny all (N)** or pressing `Shift+Escape` dismisses all pending requests immediately. If an SSH client aborts while queued, it is removed automatically.

- **Approve once** signs this request and nothing further.
- **Approve 2m** (the window's length; its tooltip spells out "for this program") also covers later requests from the same executable with the same key, for `sshAgentApprovalWindowSec` seconds (default `120`, maximum `900`, `0` to ask every time). Git spawns a fresh `ssh-keygen -Y sign` for every commit it signs, so this is what makes a twenty-commit rebase one prompt instead of twenty. The grant matches on your UID, the executable path captured at approval, the key, the kind of signature and, for a login, the server -- deliberately not the pid, which changes with every commit. Requests already queued behind the one you approve are covered too: approving the first of three `ssh -T git@github.com` answers the other two, by the same rule a new request would meet, and anything the grant does not cover stays queued.

  The kind of signature is read from the data being signed: SSHSIG signatures in one namespace (Git uses `git`), or SSH logins as one user. A grant for Git's commit signatures does not cover a login from the same program, and a grant for logging in as `git` does not cover logging in as `root`, or as `git` on another server. It is offered only for those two shapes. Data the helper does not recognise, and any request that arrived over agent forwarding, can be approved once but never for a window -- the helper enforces this itself, whatever the panel sends back.

Live grants appear under **ACTIVE APPROVALS** with the program, what they cover, and time remaining, revocable one at a time or all at once, and are dropped on lock, logout, and helper exit. They are never written to disk.

Two unanswered or refused prompts in a row start a five-minute cooldown during which signing requests are refused without raising an approval surface. A banner in the panel says so and counts down, because a silent multi-minute SSH outage is impossible to connect back to its cause -- and unattended requests, the case the cooldown exists for, are exactly the ones you were not watching. Approving cannot end a cooldown that is already running: it is the prompts an approval would answer that the cooldown is suppressing. **Resume Signing Now** on that banner is the way out, or wait the five minutes. A process that keeps asking neither shortens the window nor extends it; the refusals it collects are answered without a prompt and never counted.

#### When the card goes unanswered, and answering from a terminal

**Desktop notification.** If a signing request is still waiting about eight seconds after its card appeared (the card is on a screen nobody is looking at, or hidden), the request is repeated as a desktop notification from `notify-send` (libnotify, through whatever notification daemon the desktop runs) with two actions: **Deny**, the only one that decides the request, and **Answer on the card**, which decides nothing (below). It shows only what the card shows: key name and fingerprint, the program's name and the absolute path it ran from with the same "not verified" note, and what is being signed. As on the card, characters that would draw as nothing (control and direction marks, zero-width characters, a soft hyphen and the other default-ignorable ones) are written out as `\uXXXX` (`\u{XXXXX}` beyond U+FFFF), and the path is shortened from the left past the display limit (it then starts with `…`), so the executable's end of it is what remains. The limit is 512 UTF-16 code units of the text as written out, one of them reserved for the `…` of a shortened path, cut between whole characters and never inside a written-out one, whether the panel wrote it out or the text arrived that way (the agent writes control characters out itself). This shows that such a character is there; it does not make every pair of different paths look different. A path that literally contains the six characters `\u00ad` reads the same as one containing a soft hyphen, because a backslash is shown as it is; two long paths that differ only in the part cut off read the same; and look-alike letters from other scripts are shown as they are. It cannot approve: notification daemons let any program running as you press a notification's buttons (`makoctl invoke`, `dunstctl action`, the Omarchy shell's own `notifications` IPC), so an approve button there would let a program approve its own request. Approving is done on the card. **Deny** denies the request, and counts toward the cooldown as a refusal on the card does. **Answer on the card** is the notification's default action: what a daemon runs when the notification itself is clicked (Dunst's middle click), and some daemons (Xfce's, for one) draw it as a second button beside **Deny**. That, dismissing the notification, the notification's own expiry, or a daemon that drops it (do-not-disturb) decides nothing and counts toward nothing: the request stays on the card. The request's own two-minute deadline is separate and unchanged: a request nobody answers by then is refused, and that does count toward the cooldown, with or without a notification. Answering the card first removes the request's claim on the notification. A stale notification may stay on screen until its own expiry, but it no longer does anything. Unlock requests never get a notification, because unlocking means typing a secret. If `notify-send` is missing or no daemon is running, nothing changes and the card stays. Turn it off with **Notify when a prompt goes unanswered** (`sshAgentNotifyFallback`, on by default). The helper is a child of the shell, so a shell that is not running has no agent to ask; there is no notification path without it.

**Terminal.** Pending requests can be listed and answered through the plugin's IPC target, so a terminal on another workspace can handle one:

```sh
omarchy-shell io.github.elevate08.qs-bitwarden-cli sshPending
omarchy-shell io.github.elevate08.qs-bitwarden-cli sshReply 12 deny
omarchy-shell io.github.elevate08.qs-bitwarden-cli sshReply 12 allow
```

`sshPending` prints JSON with each request's `id`, `kind` (`sign` or `unlock`), key, fingerprint, program, what is being signed and whether it was forwarded, plus the local process id of the program that connected to the agent (for a forwarded request, the local ssh relaying it), which the card leaves out -- no secret. `sshReply <id> deny` is always available. `sshReply <id> allow` approves once, never as a grant, and is refused (`disabled`) unless **Allow approving from a terminal** (`sshAgentTerminalApproval`) is on. It is off by default, because any program running as you can call the IPC target and so could approve its own request, which the card (needing a person at the screen) prevents. An unlock request can be denied from a terminal but never allowed. Replies return `allowed`, `denied`, `disabled`, `unlock-only`, `unknown` (no such request) or `invalid`.

#### Auto-lock and listing keys

`ssh-add -l`, and any `ssh` connection that only asks which keys the agent holds, does not count as activity: it never moves the auto-lock deadline. Approving a signature does, as the person's own action does; an approval answered by a grant window, or by a request that is denied, does not.

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

On an ARM64 machine, the same with `bin/aarch64-linux/`. Releases from `v1.13.0` on attest both architectures' binaries.

`scripts/verify-helpers.sh` runs this for all six helpers, checks `bin/SHA256SUMS`, and rebuilds this checkout's helpers in the pinned image (`--attestations` or `--rebuild` runs just one check). See [REVIEWING.md](../REVIEWING.md).

`gh` is not an Omarchy dependency, so this is a check you run if you want it, not one the plugin can assume. Worth re-running after a plugin update, when the binary has changed.

**When the check fails.** The panel disables SSH support, names the reason, and leaves the rest of the plugin working. If a locally built helper is present it falls back to that instead and says so on a banner -- which is the state to be careful about, because signing carries on with a binary that has no recorded digest and no provenance behind it. Either way the fix is to restore the shipped artifact:

```bash
omarchy plugin remove io.github.elevate08.qs-bitwarden-cli
omarchy plugin add https://github.com/Elevate08/qs-bitwarden-cli --enable
```

`omarchy plugin update` is not enough on its own: it pulls, and a pull will not overwrite a tracked file you have modified locally. Removing and re-adding gets you a clean checkout. Nothing you care about lives in the plugin folder -- the session key and stored password are in the keyring, learned suggestions in `~/.local/state` -- so this costs you your `shell.json` settings for the plugin and nothing else.

`omarchy-shell io.github.elevate08.qs-bitwarden-cli sshAgentStatus` reports `helperSource`, `helperChecksum` and `helperState` if you want the verdict without opening the panel.

#### Known limits

When a list read's key batch failed and the read that replaces it fails as well, the agent has no keys until the next list read (a refresh, a sync or a save) succeeds. A signing request that arrives in the instant the last approval is answered can be failed by the key load that follows it, and has to be run again.

#### What this does not defend against

- **Anything running as you.** The socket enforces the peer's UID and nothing more. A process running as you can ask for signatures -- it gets a prompt, and the cooldown limits how often it can raise one -- and it can equally replace the helper, the checksum file, and the QML that checks them. It can also answer a prompt without you: the helper takes `approve` from whoever holds its stdin, and a same-UID program can open the panel's end of that pipe through `/proc/<panel pid>/fd/` (Yama's `ptrace_scope=1` does not block that) and approve a request that is waiting. A per-request secret in the prompt would not stop it, because the prompt reaches the panel over the helper's stdout pipe, which that program can open and read the same way. Filesystem permissions own that boundary; the plugin cannot defend itself against a same-UID attacker, and neither can any other agent.
- **The process shown in the prompt.** The executable path is reported by the system for context. Only the requesting user is verified. Treat it as a useful hint about *what* is asking, not proof.
- **Which server a login goes to.** OpenSSH 8.9 and later binds each agent connection to the server's host key (`session-bind@openssh.com`), and the helper matches a login to the bind for its session. The prompt shows that host key's fingerprint, so you can check it against `ssh-keygen -lF <host>`; a login grant is scoped to it. The helper does not verify the server's signature on the bind, so the fingerprint is what your SSH client reported -- like the program path, context rather than proof. On a forwarded connection it is weaker still: after the forwarding bind, everything on the connection comes from the remote host, including any further bind, which can name any server it likes. The helper records which binds arrived that way, and a login whose server is named only by one of them is shown as **Server claimed by the remote host, not verified** (on the card, in the notification and in `sshPending`), in the warning colour, instead of as a server host key. Checking that fingerprint against `ssh-keygen -lF` proves nothing; approve such a login only if you trust the host you forwarded to. Two forwarded logins are not shown as a claim: one on a session your own `ssh` bound before it started forwarding (the remote host cannot replace that bind), and one made with OpenSSH's host-bound method (`publickey-hostbound-v00@openssh.com`), where the host key is inside the data being signed, so the signature is of no use on any other server. A plain `publickey` login from the remote host is the claimed kind. A helper from before this change does not say which is which, and the panel then treats every forwarded login's server as claimed. A login made with the host-bound method shows the host key in its signed data even when no bind names its session. A login with neither -- no bind for its session, and not host-bound -- shows "Server not reported", and a grant for it covers only other unreported logins.
- **Agent forwarding.** Supported only as a request you approve each time. OpenSSH 8.9 and later tells the agent when a connection carries a remote host's requests (`session-bind@openssh.com`); the prompt labels those as forwarded, and they can neither open a grant nor use one the local `ssh` already holds. A bind the helper refuses -- one it cannot parse, such as a server host key over 16 KiB, or one past OpenSSH's 16-per-connection limit -- is treated as forwarding too, because OpenSSH carries on after a refused bind: otherwise a hostile server could hide that its requests are relayed and have them answered by the local `ssh`'s grant. The program the prompt shows is the local `ssh` relaying the request, not the one that will use the signature. Forwarded connections list their keys without item names, so a remote host cannot read your vault's item names with `ssh-add -l`. An older client does not say, so its forwarded requests look like its own -- use `ForwardAgent` only with a current OpenSSH.
- **Erasure.** Secret memory is zeroized on a best-effort basis and the helper disables core dumps and `PR_SET_DUMPABLE` before the first key is read, but nothing can guarantee that a page freed by an allocator or swapped by the kernel is gone. The helper does not lock its memory, so a key can be written to swap while it is loaded; encrypted swap, or zram with no disk swap, avoids that.
- **Root, and the vault itself.** Root reads any process's memory. Separately, `bw` is the source of the keys and holds its own decrypted copies while it runs.

#### Turning it off

Switching **Act as your SSH agent** off stops the helper, removes the socket and FIFO, drops every key and grant, deletes the public-key projection, and removes the routing file -- but only when that file is byte-for-byte the one this plugin wrote. Anything you manage by hand is left alone. Turning the agent back on writes the routing file again, so a toggle costs you nothing; it will not do so when another agent already owns `SSH_AUTH_SOCK`, or when something other than this plugin's own file is sitting at that path. Either way, clients keep the `SSH_AUTH_SOCK` they were given until your next login, so nothing changes under a running session.

To remove the routing file without turning the agent off:

```bash
# Or press "Remove Routing File" in the panel
rm ~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent
```

---
