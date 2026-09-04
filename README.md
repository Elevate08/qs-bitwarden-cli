# qs-bitwarden-cli

A modern, fast, and feature-rich Bitwarden password manager plugin for the **Omarchy** shell environment and **Hyprland** desktop.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.7.0-green.svg)](manifest.json)
[![Platform: Omarchy](https://img.shields.io/badge/platform-Omarchy%20%2F%20Hyprland-7c3aed.svg)](https://omarchy.org/)
[![Requires: Bitwarden CLI + jq](https://img.shields.io/badge/requires-bw%20CLI%20%2B%20jq-175ddc.svg)](https://bitwarden.com/help/cli/)

![Bitwarden Vault Plugin preview](preview.png)

---

## Overview

`qs-bitwarden-cli` seamlessly integrates your Bitwarden vault into the Omarchy status bar and quick access panel. Built with native QML/C++ bindings on top of Quickshell and the official Bitwarden CLI (`bw`), it provides lightning-fast search, secure credential auto-copy, live 2FA TOTP generation, multi-organization switching, and complete vault item management without ever opening a web browser.

---

## Installation & Setup

### 1. Install the Plugin

```bash
omarchy plugin add https://github.com/Elevate08/qs-bitwarden-cli --enable
```

That is the whole install. It clones the plugin into
`~/.config/omarchy/plugins/`, enables it, and places it in the bar section named
by the manifest (`right`). Nothing else has to be installed first. To update it
later:

```bash
omarchy plugin update io.github.elevate08.qs-bitwarden-cli
```

### 2. First Run

The widget appears in the bar straight away, with a small `+` badge if anything
it drives is still missing. Click it and the panel opens on its setup screen:
on a stock Omarchy install that is the Bitwarden CLI and nothing else, with an
**Install** button. Pressing it opens Omarchy's own installer window -- floating,
centred and themed, the same one every other app install on the system uses.

The panel watches that window's work for you. As soon as the tools land, it
moves on to the login or unlock screen on its own -- there is nothing to come
back and re-check, and no command to run first.

You can reopen it any time with <kbd>,</kbd> from the settings screen, or:

```bash
omarchy-shell io.github.elevate08.qs-bitwarden-cli setup
```

On the login screen, choose **US** (the default), **EU**, or **Custom** under
**Server Region**. EU connects the Bitwarden CLI to
`https://vault.bitwarden.eu`; Custom reveals the existing server URL field for
self-hosted Bitwarden and Vaultwarden installations. The selection applies to
email/password, API-key, and interactive terminal login.

<details>
<summary>What the setup screen installs, and why</summary>

The plugin shells out to these rather than bundling them, so they are ordinary
system packages you can also install by hand:

| Tool | Package | Required | Used for |
| --- | --- | :---: | --- |
| `bw` | `bitwarden-cli` | yes | Reading and writing your vault. |
| `jq` | `jq` | yes | Safe SSH-aware vault sanitization before QML reads item data. SSH support requires Bitwarden `2025.1.2+`. |
| `fprintd-list` | (via `omarchy setup security fingerprint`) | no | Fingerprint unlock. Omarchy installs the reader stack, enrols your finger and writes the PAM config in one command; the row only appears if you have a reader. |

The equivalent of what the Install button runs:

```bash
omarchy install app 'Bitwarden plugin dependencies' 'bitwarden-cli jq'
```

That is the whole list, and only the first entry holds the panel back. The
plugin also uses `wl-copy` for the clipboard, `secret-tool` for the keyring,
`hyprctl` for window detection, and `gdbus`, `systemd-inhibit` and `openssl`
for suspend handling and PIN encryption -- but Omarchy ships every one of
those, so the setup screen does not list what it would only ever find already
there.

</details>

### 3. Bar Placement & Configuration

`--enable` already puts the widget in the bar. To move it:

```bash
omarchy bar move io.github.elevate08.qs-bitwarden-cli --section right
```

Settings are editable from the panel's own settings screen, or directly in
`~/.config/omarchy/shell.json`. Each setting lives **inline on the bar entry**,
not in a separate block:

```json
{
  "bar": {
    "layout": {
      "right": [
        {
          "id": "io.github.elevate08.qs-bitwarden-cli",
          "autoLockMinutes": 15,
          "lockOnScreenLock": true,
          "lockOnSuspend": true,
          "clearClipboardSec": 30,
          "rememberSession": true,
          "fingerprintUnlock": false,
          "sshAgentEnabled": false,
          "sshAgentApprovalPopup": true
        }
      ]
    }
  }
}
```

### 4. Global Hotkey Configuration

To toggle the Bitwarden panel with a keyboard shortcut (e.g. `SUPER + CTRL + /`), add the binding to `~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + CTRL + SLASH", "Bitwarden vault", "omarchy-shell io.github.elevate08.qs-bitwarden-cli toggle")
```

Apply changes by restarting the shell:

```bash
omarchy restart shell
```

### 5. Optional: PIN Unlock

Turn on **Unlock with PIN** in the settings screen. You are asked for your master password once (it is needed to encrypt) and for a PIN. Six digits or more is what the screen asks for; four and five are accepted but shown in red with the number of combinations spelled out, so a weak PIN is a decision rather than an accident.

**How it differs from fingerprint unlock.** Fingerprint unlock keeps your master password in the login keyring in the clear, because PAM can only prove presence. A PIN can do better: the master password is encrypted with a key derived from the PIN (PBKDF2-SHA256, 600,000 iterations, salted) and only the ciphertext is stored, so reading the keyring is not by itself enough. A wrong PIN fails decryption, which means correctness needs no stored hash and there is no hash to attack.

**The honest limit.** A short PIN is a small search space, and if the ciphertext leaks, the iteration count is the only thing standing between an attacker and your master password. Five wrong attempts at the panel deletes the stored ciphertext, but that is a UI throttle and does nothing against an offline attack on a copy of the blob. Concretely: 4 digits is 10,000 candidates, which is minutes of offline guessing even at 600,000 PBKDF2 rounds each; 6 digits is 1,000,000, and 8 is 100,000,000. Pick accordingly.

The stored ciphertext is removed when you turn the setting off, after five wrong attempts, or when the vault rejects the decrypted password (for example after a master password change).

### 6. Optional: Fingerprint Unlock

Set `fingerprintUnlock` to `true` to unlock the vault with a finger instead of your master password.

**Requirements**

- A fingerprint reader with at least one enrolled finger, configured through `omarchy setup security fingerprint`. The plugin verifies all of this itself (`/etc/pam.d/omarchy-lock-fingerprint`, `fprintd-list`) and silently stays hidden when any part is missing.
- A running, unlocked OS keyring, as used by `rememberSession`. Omarchy ships libsecret itself, so there is nothing to install for this.

**How it works**

1. Switch **Unlock with fingerprint** on in the settings screen. It asks for your master password once -- the same way setting a PIN does -- and stores it in the login keyring under `service=qs-bitwarden-cli, account=master_password`.
2. On every later lock, opening the panel arms the reader. A verified fingerprint releases the stored password to `bw unlock`; the password field remains available as a fallback at all times.
3. Unlocking with your master password afterwards refreshes the stored copy, so changing your master password does not silently strand the enrolment.

**Security trade-off -- read before enabling**

PAM can prove that you are present, but it cannot produce your Bitwarden master password, and `bw unlock` accepts nothing else. Fingerprint unlock therefore keeps your master password in the OS login keyring and treats a verified fingerprint as the gate on reading it back. This is the same trade the official Bitwarden desktop client makes for its own biometric unlock, and it means **anyone who can read your unlocked login keyring can read your master password**. It is off by default and worth leaving off on a shared or unattended machine.

The stored password is removed when you turn the setting off, press **Forget Fingerprint** on the locked screen, log out of the account, or when the vault rejects it (for example after a master password change, which then prompts you for the new one).

### 7. Optional: SSH Agent

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

## Usage & Keyboard Shortcuts

The panel opens with the item list focused, so single-letter shortcuts work straight away. Press <kbd>/</kbd> to type a search.

**While the search box has focus** every letter is search text -- as a text field should behave. Hold <kbd>Alt</kbd> to reach the same shortcuts without leaving the box or disturbing your query; <kbd>↓</kbd> also hands focus back to the list.

### Vault List View (Main Screen)

| Shortcut | Action |
| :--- | :--- |
| <kbd>Enter</kbd> | Copy password (and arm the TOTP follow-up), or open the item when there is no password to copy -- a card, an identity, a note, an SSH key |
| <kbd>Enter</kbd> *(again)* | Copy the TOTP code during the follow-up window |
| <kbd>↑</kbd> / <kbd>↓</kbd> / <kbd>j</kbd> / <kbd>k</kbd> | Move through items, or through an open filter drawer |
| <kbd>/</kbd> | Focus the search box |
| <kbd>Tab</kbd> / <kbd>Shift+Tab</kbd> | Cycle types without opening the drawer |
| <kbd>p</kbd> *(or <kbd>y</kbd>)* | Copy **p**assword |
| <kbd>u</kbd> *(or <kbd>c</kbd>)* | Copy **u**sername / email |
| <kbd>m</kbd> | Copy TOTP **m**ulti-factor code |
| <kbd>w</kbd> | Open the **w**ebsite in your browser |
| <kbd>e</kbd> | Open the detail inspector / **e**dit |
| <kbd>f</kbd> | **F**olders filter |
| <kbd>o</kbd> | **O**rganizations filter |
| <kbd>t</kbd> | **T**ypes filter |
| <kbd>g</kbd> | **G**enerator |
| <kbd>n</kbd> | **N**ew vault item |
| <kbd>s</kbd> | **S**ettings |
| <kbd>r</kbd> | Sync (**r**efresh) |
| <kbd>l</kbd> | **L**ock the vault |
| <kbd>Alt</kbd>+<kbd>s</kbd> | Bitwarden **S**end |
| <kbd>Alt</kbd>+<kbd>,</kbd> | Settings |
| <kbd>Esc</kbd> | Close the filter drawer, clear the search, or close the panel |

`Alt` + any letter above runs the same action from inside the search box. Two are `Alt`-only: <kbd>Alt</kbd>+<kbd>s</kbd> opens **Send** (which has no bare letter, since <kbd>s</kbd> is Settings), and <kbd>Alt</kbd>+<kbd>,</kbd> opens **Settings**, so Settings is still reachable while searching.

### Detail Inspector

| Shortcut | Action |
| :--- | :--- |
| <kbd>Enter</kbd> / <kbd>y</kbd> / <kbd>p</kbd> | Copy what the item is for: the password on a login, the number on a card |
| <kbd>u</kbd> / <kbd>c</kbd> | Copy username; on an identity <kbd>u</kbd> is the username and <kbd>c</kbd> the email |
| <kbd>n</kbd> | Copy a card's **n**umber |
| <kbd>k</kbd> | Copy a card's security code |
| <kbd>m</kbd> | Copy TOTP code |
| <kbd>v</kbd> | Toggle re**v**eal on the item's principal secret -- the password on a login, the number on a card. Every other masked field has its own eye, and each reveals independently |
| <kbd>a</kbd> | Save every **a**ttachment on this item |
| <kbd>e</kbd> | Edit this item |
| <kbd>x</kbd> | Delete this item (asks first) |
| <kbd>b</kbd> / <kbd>q</kbd> / <kbd>Esc</kbd> | Back to the list |

### Filter Drawer (Folders / Organizations / Types)

| Shortcut | Action |
| :--- | :--- |
| <kbd>f</kbd> / <kbd>o</kbd> / <kbd>t</kbd> | Open (or close) that drawer |
| <kbd>↑</kbd> / <kbd>↓</kbd> | Move through the options |
| <kbd>Enter</kbd> | Apply the highlighted option |
| <kbd>Esc</kbd> | Close without changing anything |

The cursor starts on the option already in effect, so <kbd>Enter</kbd> never changes a filter by accident.

### Settings Screen

| Shortcut | Action |
| :--- | :--- |
| <kbd>↑</kbd> / <kbd>↓</kbd> | Move between settings |
| <kbd>←</kbd> / <kbd>→</kbd> | Decrease / increase a number by its step, or switch a toggle off / on |
| <kbd>Enter</kbd> | Flip the highlighted toggle, or open the PIN / fingerprint form |
| <kbd>Esc</kbd> | Back |

### Send Screen

| Shortcut | Action |
| :--- | :--- |
| <kbd>Alt</kbd>+<kbd>s</kbd> | Open Sends |
| <kbd>n</kbd> | New Send |
| <kbd>r</kbd> | Refresh the list |
| <kbd>x</kbd> | Delete the highlighted Send |
| <kbd>Enter</kbd> | Copy the highlighted Send's link |
| <kbd>Esc</kbd> | Back |

---

## Features

- **Full Status Bar & Quick Access Panel Integration**:
  - Live vault lock state indicated in the status bar (`󰞀` shield icon: accent when unlocked, base when locked, urgent when unauthenticated).
  - Clean drop-down panel with fast navigation and keyboard-first workflow.

- **Authentication & Secure Keyring Storage**:
  - Direct Master Password unlock.
  - Interactive login starts with Email + Password and reveals the 2FA prompt only when Bitwarden requires it (Authenticator App or Email); API Key credentials (`BW_CLIENTID` / `BW_CLIENTSECRET`) remain available as a separate method.
  - **Custom Server Support**: Works seamlessly with official Bitwarden servers and self-hosted Vaultwarden instances.
  - **Terminal login fallback**: when the built-in form cannot cover your login method -- SSO, a Duo push, a hardware key -- the login screen offers **Launch Terminal**, which runs `bw login` in a real terminal so Bitwarden's own prompts handle it.
  - That terminal hands its session straight back: it captures the key with `bw login --raw` (prompts stay on stderr, so the login is still interactive) and writes it to `$XDG_RUNTIME_DIR/qs-bitwarden-cli/session-handoff`, mode `600`, in a directory created `700` before the file exists. There is no fallback path: if `XDG_RUNTIME_DIR` is somehow unset the login refuses to run rather than putting a session key anywhere a second user could have prepared. The panel reads that file once, deletes it, and comes back unlocked -- no second login just to get in. If the vault was merely locked rather than logged out, the same button unlocks instead. **It only reads it when it is expecting to.** The check runs on every status refresh, and it used to adopt whatever was at that path whether or not the panel had ever asked for a terminal login -- so anything able to write the file could hand the panel a session key at a moment of its own choosing, and the panel would take it and write it to the keyring. The runtime directory is `0700`, so that is one of your own processes rather than a stranger and it was never a privilege boundary; it was a window with no reason to be open. A key is only expected in the ten minutes after the panel itself launched a terminal, so those are the only minutes it is read in. Outside them the file is deleted unread -- not reading it is not a reason to leave a live session key lying in the runtime directory, and a login abandoned halfway leaves exactly that.
  - **The terminal reopens the panel for you** on success, then closes itself; you only have to dismiss it if something went wrong and there is an error worth reading.
  - Two `bw status` calls used to sit on that path, each around three seconds on a real vault: one in the terminal to decide login-versus-unlock, one in the panel to confirm a key `bw` had just minted. Neither is needed -- the panel already knows which state it is in, and the confirming check now starts only after the item list has been rendered instead of sitting in front of it.

- **PIN Unlock** (opt-in, `pinUnlock`):
  - Unlock with a numeric PIN instead of typing the master password. **6 digits or more is the recommendation**, 4 is the hard floor, and there is no upper limit. A PIN under 6 digits is accepted but the field turns red and tells you how small the search space you just chose is -- every extra digit multiplies an attacker's work by ten.
  - Unlike fingerprint unlock, the master password is **not** stored in the clear: it is encrypted with a key derived from your PIN (PBKDF2-SHA256, 600,000 iterations, salted) and only the ciphertext is kept, so reading the keyring alone does not reveal it.
  - A wrong PIN simply fails to decrypt, so no PIN hash is stored and there is none to attack.
  - Five wrong attempts removes the stored ciphertext entirely; re-enabling needs the master password again. So does a master password change, which is detected on the first failed unlock.

- **Fingerprint Unlock** (opt-in, `fingerprintUnlock`):
  - Unlock the vault with an enrolled fingerprint instead of retyping your master password.
  - Verifies through the same PAM stack as the Omarchy lock screen (`/etc/pam.d/omarchy-lock-fingerprint`), so it works wherever `omarchy setup security fingerprint` has been run.
  - Enrolling asks for your master password up front in the settings screen, rather than quietly capturing it on some later unlock.
  - The reader is armed automatically whenever you open the panel on a locked vault; the master password field always stays available as a fallback.
  - See [Optional: Fingerprint Unlock](#6-optional-fingerprint-unlock) for the security trade-off before enabling it.

- **SSH Agent** (opt-in, `sshAgentEnabled`):
  - Serves the SSH keys in your vault to `ssh`, `git` and `ssh-keygen -Y sign` while the vault is unlocked, from a separate helper process that holds the private keys in memory and drops them on lock, logout, or exit. They are never written to disk and never reach QML.
  - Every signature shows the key, its fingerprint and the program asking. The default prompt lives in the panel; the opt-in centered popup makes the plugin otherwise disappear until a decision is needed. One approval can cover a whole rebase; live approvals are listed and revocable, and repeated unanswered prompts fall back to a cooldown rather than pestering.
  - Public keys are projected to files for Git signing, one file per item, public material only. See [SSH Agent](#7-optional-ssh-agent).

- **Context-Aware Password Suggestions (Active Window / Browser Tab)**:
  - Reads the active window on open (`hyprctl activewindow -j`, falling back to the `hyprctl clients -j` focus history when the panel itself holds focus).
  - Recognises the current site from the browser's page title and matches it against each item's URLs and name using Bitwarden-style host and base-domain rules, brand aliases (a `Gmail` tab matches a `google.com` item), and word-boundary matching that ignores public suffixes and generic labels such as `www`, `login`, or `com`.
  - Places a highlighted **`󰌠 Suggested for <App / Website>`** banner and pins matching credentials to the top of the list with pre-selection, so pressing <kbd>Enter</kbd> immediately copies the right credential.
  - Only the strongest tier of matches is shown (at most 6), and a title with nothing identifiable in it produces no suggestions rather than a guess.
  - Standalone desktop apps match on window class; terminals only suggest for remote `ssh`/`mosh`/`sftp` hosts, never for local shells.
  - **It learns.** Opening or copying an item while a window is active records that window against the item, and it is suggested outright next time -- ahead of every heuristic. This is what handles sites a title can never match: a portal on `auth.example.xyz` titled `Home - authentik` shares no word with the stored credential, so pick it once and it sticks. Learned suggestions are marked `󰐾` rather than `󰌠`.
  - **Suggest here / Suggested here** in an item's detail view pins or unpins that item for the current site or app deliberately, without waiting to be taught.
  - Re-picking a different item retargets what was learned, so a bad association corrects itself the next time you choose.
  - Associations live in `~/.local/state/qs-bitwarden-cli/associations.json` (mode `600`) and hold only vault item IDs and the title words they were learned from -- never credentials. Writes replace a private temporary file atomically, never follow a symlink, and narrow an older permissive file back to `600`; reads validate the schema and discard unknown versions, malformed entries, and keys outside the `domain:`, `app:`, and `word:` namespaces. **Logging out deletes the file after any active writer has exited**, so an in-flight update cannot resurrect the previous account's metadata. It holds no secrets, but between them the domains, app names and timestamps are a record of which sites the account has logins for and when each was last used, in the clear and with no expiry of its own.
  - **Limitation:** browsers do not publish the active tab URL to Wayland or Hyprland, so the *heuristics* work from the page title. A site whose title mentions neither its name nor its domain (`New Tab`, a bare `Sign in`) cannot be inferred -- teach it once instead.

- **Smart Auto-Copy TOTP Flow on <kbd>Enter</kbd>**:
  - Selecting a login item and pressing <kbd>Enter</kbd> copies the **Password** to the clipboard and automatically closes the panel, returning focus immediately to your target application so you can paste (<kbd>Ctrl+V</kbd>) and submit.
  - If the item has a TOTP 2FA secret configured, the plugin automatically copies the live 6-digit **TOTP code** to your clipboard after a brief delay (default: 3s) and posts a desktop notification saying so. The notification deliberately does **not** contain the code: a notification daemon keeps history and can render a body over a lock screen, which is no place for a live second factor. The digits are shown in the panel itself, with their countdown.
    - You can immediately paste the TOTP code into the 2FA prompt without ever reopening or refocusing the plugin!
    - If you prefer manual progression, pressing <kbd>Enter</kbd> or <kbd>t</kbd> while the follow-up banner is active also copies the code immediately.

- **Every item type is readable, not just logins**:
  - **Cards** show the cardholder, brand, number, expiry and security code. The number and the code are masked until revealed, and each reveals independently of the other -- an eye is a statement about the field it sits on.
  - **Identities** show the name, username, company, email and phone, the social security, passport and licence numbers, and the address as a single copyable block rather than seven separate rows. Empty fields are not drawn, so a sparsely filled identity stays short. The three identifiers are masked for the reason a password is, with the difference that these cannot be rotated afterwards.
  - Both are searchable by what the list shows them as: a card by brand, cardholder or last four digits, an identity by name, email, username or company. Deliberately **not** by the middle of a card number -- a substring search across stored card numbers is not a lookup this box should perform.
  - **SSH keys** remain public records: the panel lists them, shows the public key and fingerprint, and serves them through the agent, but never draws or writes private material. See [ADR 0004](docs/decisions/0004-ssh-key-creation.md).

- **Full Add, Edit & Delete (CRUD) Operations**:
  - **Create Items (`n` key or `+` button)**: Add new **Logins** (`󰌋`), **Secure Notes** (`󰈐`), **Cards** (`󰿯`) or **Identities** (``). SSH keys are read-only here -- see [ADR 0004](docs/decisions/0004-ssh-key-creation.md) for why the plugin does not create them.
  - **Password Generator**: A full generator screen (<kbd>g</kbd> or the `󰌆` button) mirroring the Bitwarden browser extension's options -- password (length, A-Z, a-z, 0-9, special, minimum numbers, minimum special, avoid ambiguous) or passphrase (word count, separator, capitalise, include number), with a live strength meter. Generation comes from Bitwarden's own generator rather than a reimplementation, and the item form's **Generate...** button opens this same screen and fills the password field in on the way back.
  - **It is fast.** A fresh `bw generate` costs about 2.9 seconds, almost none of it generation: roughly 0.9s is the CLI's Node bootstrap and 2s is Bitwarden's service container starting, and every option toggle paid it again. The panel now starts `bw serve` on loopback the first time you open the generator and asks that, which answers in about **2ms**. The server is deliberately started with **no session**, so it is a locked vault that can generate passwords and nothing else -- a loopback port has no authentication and is reachable by every user on the machine, so it must never hold an unlocked vault. The server is also only up while the generator screen is: `bw serve` answers `/status` with your account email and user id to anyone on the machine who asks, so it goes up with the screen and comes down with it rather than idling on a port for the whole session. And an answer on that port is not taken as proof the server is ours -- there is no authentication to lean on, so the port is probed before we start, and anything already answering means the panel uses `bw generate` for that visit instead of letting a stranger's server pick your password. If our own server later dies, any value it had already supplied is discarded rather than left on screen to be copied. **And no request to that port can hold the panel up, fill it, or leave loopback.** Every request runs through a managed child process with curl's config disabled, proxies bypassed, a two-second deadline, and a producer-side 64 KB cap. A request cut short counts as an occupied port, never a free one.
  - **Edit Items (`e` key or Edit button)**: Modify titles, credentials, authenticator keys, URLs, notes, and every card and identity field. <kbd>Enter</kbd> saves from anywhere in the form, so a long item does not have to be scrolled to the bottom to be committed -- except while a folder, organization or collection picker is open, where <kbd>Enter</kbd> belongs to the list being picked from.
  - **Delete Items (`x` key or Delete button)**: Delete items with confirmation protection.
  - **Saving and deleting do not hold the panel.** Both cost whatever `bw` costs -- a second or two of CLI startup, vault decryption and a round trip -- and the panel used to spend all of it on a frozen form. The form closes as soon as the command is launched and the list shows the item as it will be, its icon replaced by a spinner until the vault answers, at which point the authoritative version takes its place. An item still being saved cannot be edited or deleted, and a second save waits for the first. If the vault refuses one, the list goes straight back to what the vault actually holds and the message offers to reopen what you typed rather than costing you the edit.

- **Bitwarden Send** (<kbd>Alt</kbd>+<kbd>S</kbd> or the `󰒗` button):
  - Share a secret through a link that expires on its own, so a credential need not live in a chat log.
  - Create a text Send with a name, hidden-by-default text, a deletion window (1-31 days), a maximum view count, and an optional password. The access link is copied to your clipboard the moment it is created.
  - Lists your existing Sends with how long each has left (`in 3 days`, `expired`), views used against the maximum, and whether a password is set. Copy a link or delete a Send from the row.
  - Keyboard: <kbd>n</kbd> new, <kbd>r</kbd> refresh, <kbd>x</kbd> delete the highlighted Send, <kbd>Enter</kbd> copy its link, <kbd>Esc</kbd> back.
  - The Send payload -- which carries the Send password -- is passed to `bw` through the environment, never on the command line.

- **Attachments**:
  - Items that carry files are marked with a `󰏢` paperclip in the list, and the detail view lists each attachment with its name and size.
  - The list costs nothing: `bw list items` already returns the attachment metadata with the cipher, so the files are on screen the moment the item opens. Only the bytes need the CLI, and only for the file you ask for.
  - **Save** puts a file in your download directory (`xdg-user-dir DOWNLOAD`, falling back to `~/Downloads`), then offers **Open** and **Show in folder** for it. <kbd>a</kbd> saves every attachment on the item; they are fetched one at a time rather than starting a `bw` per file.
  - Nothing is ever written through whatever already sits at the chosen path: the bytes land in a private staging directory first and the finished file claims its name atomically, so a symlink left in the download folder is stepped around rather than followed, and an existing file is never overwritten -- " (1)", " (2)" and so on go before the extension until the name is free.
  - A download is bounded before it starts and while it runs: 512 MB per file, 15 minutes, and a check that the disk has room. If the server omits the size, the preflight reserves for the full 512 MB ceiling rather than treating it as an empty file. A transfer that breaks a limit leaves nothing behind.
  - **A file name out of the vault is treated as hostile.** It is decrypted content that is about to become part of a path, so path separators and control characters are replaced rather than stripped, a leading dot or dash is dropped, and the result is quoted on top of that: `../../.bashrc` saves as `bashrc` in your download directory and nowhere else. Tests run the real script against a stub `bw` to prove it.

- **Folders**:
  - Filter by folder from the bottom filter bar: **All Folders**, **No Folder**, or any specific folder.
  - Items show their folder inline (`󰉋 Name`) when no folder filter is active.
  - Assign a folder when creating or editing an item from an expandable list, including clearing an existing assignment, and create a new folder inline without leaving the form.

- **Unified Bottom Filter Bar**:
  - Three identical buttons centred at the bottom -- **Folders**, **Organizations**, **Types** -- each showing its current selection, so the active filters are readable at a glance without opening anything.
  - Opening one drops the window down like a drawer rather than squeezing the item list, with a pinned header naming the group (and its total when it overflows).
  - Five options are visible at a time and the rest scroll underneath the pinned header.
  - Any action outside the drawer closes it -- selecting an item, searching, copying, syncing, locking or opening another screen -- so it never sits over the results.
  - Fully keyboard driven: <kbd>f</kbd> folders, <kbd>v</kbd> organizations, <kbd>i</kbd> types; <kbd>↑</kbd>/<kbd>↓</kbd> move through the options, <kbd>Enter</kbd> applies, <kbd>Esc</kbd> closes. The cursor starts on the option already active, so <kbd>Enter</kbd> changes nothing by accident.

- **Organizations & Collections**:
  - The item form picks an organization from an expandable list, and reveals that organization's **collections** once one is chosen -- Bitwarden files org-owned items into collections rather than folders, and refuses to save one that is in none.
  - Collections are a multi-select, since an item can belong to several. A lone collection is pre-selected, and the form says "pick at least one" before the CLI would.
  - Choosing **My Vault** for an organization item clears both its organization and its collections.

- **Multi-Organization & Vault Filtering**:
  - Automatically queries and displays organizations you belong to.
  - Organization filter bar: **All Vaults**, **My Vault** (Personal items), or specific shared **Organization**.
  - Shared items display a prominent `󰓹 Org` tag in the list and detail views.
  - Choose destination vault (Personal vs. Organization) when creating or editing items.

- **Guided First Run — no prerequisites**:
  - `omarchy plugin add ... --enable` is the entire install. The widget enables into the bar with nothing else installed, wearing a `+` badge, and opens on its setup screen instead of a login form it cannot service.
  - The dependency probe runs ahead of anything that touches `bw`, so a machine without the CLI never lands on a dead end.
  - The setup screen watches for the install it launched and moves on to the vault by itself the moment the tools land — no re-check, no restart.

- **Setup Wizard & In-Panel Settings**:
  - Checks the tools Omarchy does not already ship (`bw`, plus fingerprint unlock) in a single probe, marking each required or optional and saying what it is for. Everything else the plugin shells out to comes with Omarchy, so the screen stays one short list rather than a wall of rows that are green on every machine.
  - A missing **required** tool opens the wizard automatically. **Install** hands off to `omarchy install app`, which surfaces the install in Omarchy's own floating, centred terminal -- the same window every other app install on the system opens.
  - Fingerprint unlock is Omarchy's job end to end: **Set up** runs `omarchy setup security fingerprint`, which detects the reader, installs `libfprint`/`fprintd`/`usbutils`, enrols a finger, verifies it, and writes the PAM stacks. The row is only drawn on a machine with a reader (`omarchy-hw-fingerprint`), and there is no `pkg add fprintd` button, because installing the package alone leaves the row exactly as red as it was.
  - Press <kbd>,</kbd> or the `󰒓` button for settings, grouped into **General**, **Security** and **SSH Agent**: auto-lock timeout, clipboard clear delay, TOTP auto-copy delay, and every toggle. The section you are reading is named above the list and stays there as you scroll. Maintenance actions sit under their own heading, and the destructive one -- **Remove Plugin Data** -- under a separated **DANGER ZONE**, so the button that clears your keyring entries does not look as safe to press as the one that opens a checklist. A setting whose dependency is missing is shown but inert, with the reason given.
  - Changes are written to the plugin's entry in `~/.config/omarchy/shell.json` through `omarchy bar set`, so Omarchy owns the file and the shell hot-reloads the change. Nothing is stored in a second place.
  - Reachable from a keybind too: `omarchy-shell io.github.elevate08.qs-bitwarden-cli settings` (or `setup`).

- **Hardware-Accelerated Performance & Security**:
  - Virtualized `ListView` with component delegate recycling for instant rendering of large vaults.
  - Asynchronous search debouncing (50ms) for responsive 0ms typing latency.
  - **Unlock and password-login startup is prewarmed.** Opening the locked screen, or focusing the password field while logged out, starts the Bitwarden CLI and leaves it waiting on a private mode-`600` FIFO. Submitting the form writes the exact password bytes into that pipe, so most of the CLI's Node and service-container startup has already happened. Closing the panel cancels the waiting process and removes the FIFO.
  - **Items load before secondary metadata.** After authentication, the first command fetches only the item list. Folders, organizations and the confirming status refresh begin after those items have been parsed and rendered. Short `Loading items...` and `Syncing...` status text exposes the work without adding another screen.
  - **There is no persistent item cache.** Every authenticated cold load is verified through `bw`; decrypted vault items are never written into the plugin directory or another cache. The speedup comes from moving startup off the submit path and removing unrelated commands from the critical item path.
  - **Credentials do not reach a command line.** `/proc/<pid>/cmdline` is world-readable on a default Linux install while `/proc/<pid>/environ` is not. The session token travels in `BW_SESSION`; direct unlock and email-login passwords move from `BW_PASSWORD` through the private FIFO selected with `--passwordfile`; API key credentials use `BW_CLIENTID` / `BW_CLIENTSECRET`; item, folder, and Send payloads and copied secrets use their own variables. None is interpolated into a command or shell script. The one exception is the two-step login code: `bw` offers no environment option for it, so `--code` puts it in `bw`'s own argv for the length of the login — it is carried in `QSBW_CODE` and expanded there, which at least keeps it out of the wrapping shell. Tests assert that no builder emits `--session` and that no auth command carries a password, client secret or client ID in argv.
  - **The custom-server field is checked before the master password is sent to it.** `bw config server` takes whatever it is given, and the next thing down that path is your master password, so a plain `http://` address is refused unless it is loopback -- where there is no wire to listen on, and where a local Vaultwarden or an SSH tunnel to one is a normal way to run this. Any scheme that is not `http` or `https` is refused outright. The loopback exemption is anchored and userinfo is stripped before the host is judged, so `http://localhost.evil.com` and `http://localhost@evil.com` are both refused. Backslashes are refused too: WHATWG clients interpret them as path separators, and otherwise `http://evil.example\@localhost` can look local to a lightweight parser while connecting to `evil.example`.
  - Automatic clipboard clearing (`wl-copy --clear`) after a configurable timeout (default: 30s), and immediately whenever the vault locks. Password and TOTP fallback reads are managed and generation-checked, so a command that finishes after a lock cannot put its result on the clipboard.
  - Optional session token caching in Linux Secret Service (`secret-tool` / libsecret).
  - **Keyring writes cannot race a lock, logout, or cancelled setup.** Session, PIN, and fingerprint-password stores are generation-stamped; a completion from an old vault or an authentication setup form the user left is cleared instead of recreating a credential that was just removed.
  - **Locking the vault also discards what was still on its way out of it.** Every read and operation records the vault generation it started under, and the generation moves whenever the vault is locked, logged out of, or unlocked. A late item list, generated password, attachment completion, CRUD result, or newly created Send link is dropped instead of repopulating memory, navigating the locked panel, or copying a secret after the lock. Process output is accepted only after its exit status is known.
  - **And a lock forgets it as well as refuses it.** Refusing a stale answer still leaves it in the pipe it came down. Quickshell's `StdioCollector` keeps whatever its process last printed for as long as that process is not started again -- `text` is read-only, there is no `clear()`, and nothing drops the buffer when the panel stops reading it -- so every secret that had ever come back through one was still in the shell after the vault locked: the session key from the handoff file and from the keyring, the master password from the PIN and fingerprint lookups, both halves of a login or unlock, the whole item list with each login's password in its raw object, an item detail, a live TOTP. Clearing the properties those were copied into left the originals sitting behind them. The buffer *is* replaced when the process next starts, so a lock now runs a command that prints nothing through every collector that can hold vault data or a credential; anything still mid-read is come back for once it finishes.
  - **Auto-lock counts the time the machine was asleep.** Qt schedules its timers on the monotonic clock, which Linux stops while the machine is suspended, so a fifteen-minute countdown armed just before the lid closed still had fifteen minutes to run when the lid opened -- a vault left overnight came back exactly as open as it was left. The deadline is kept in wall-clock terms as well and polled every thirty seconds, so waking a suspended machine locks the vault rather than resuming the countdown. Between the monotonic timer and the wall clock, whichever notices first does the locking.
  - **The vault locks when the screen locks and when the machine suspends.**
  - **Settings are validated where they are read, not only where they are written.** Nothing validates `shell.json`, and a bad value there can fail open rather than loudly: a non-numeric minute count reaches QML as `NaN`, lands in an integer property as `0`, and `0` is how "never lock" is spelled, while a count past the documented ceiling overflows the timer's 32-bit interval into a negative number that never fires. Each numeric setting is held to the range in the table below, and anything unreadable falls back to its default instead of to zero. Boolean settings accept only actual JSON booleans, so strings such as `"false"` cannot become truthy by JavaScript coercion.
  - **A remembered session does not survive a reboot.** The login keyring is a file on disk that PAM unlocks again at the next login, so a machine powered off with an unlocked vault used to come back unlocked. Two things stop that. The token is written to libsecret's `session` collection, which the secret service holds in memory and destroys with the login session, so there is nothing on disk to come back; and it is stamped with the kernel's boot id, so a token that does survive -- a secret service with no session collection, a keyring restored from a backup -- no longer matches the running boot and is refused and cleared instead of used. Restarting the shell still keeps you unlocked. Powering the machine off does not.

---

## Uninstall

**Turn the SSH agent off first, if you had it on**, and press **Remove Plugin
Data** on the settings screen. Between them those clear everything this plugin
put outside its own folder: the helper stops cleanly and takes its socket,
FIFO and routing file with it, and the button clears the keyring entries, the
learned suggestions and the exported public keys. Both have to happen before
the next step, because `omarchy plugin remove` has no uninstall hook -- once
the folder is gone there is no code left to run.

```bash
omarchy plugin remove io.github.elevate08.qs-bitwarden-cli
```

That removes the plugin folder and its bar entry. If you skipped the two steps
above, or you are cleaning up after a plugin that is already gone, this is the
same work by hand:

```bash
# Session key, and the master password stored for PIN/fingerprint unlock
secret-tool clear service qs-bitwarden-cli

# Learned window-title -> vault item suggestions
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli"

# Settings block: already gone. `omarchy plugin remove` takes the bar entry
# and its settings with it. If a stale one is left -- from a plugin removed
# some other way -- clear it through the shell, never by editing the file:
#   omarchy plugin disable io.github.elevate08.qs-bitwarden-cli

# SSH agent, if you used it: the exported public keys and the routing file
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/qs-bitwarden-cli/ssh"
rm -f ~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent
```

**Do not hand-edit `~/.config/omarchy/shell.json`.** On many setups it is not a
regular file: Omarchy configs are commonly managed with `stow` or another
dotfile manager, which puts a symlink there pointing into a repository. Deleting
"the file" then deletes the link, the shell falls back to its built-in defaults,
and every plugin you had configured disappears at once -- not just this one. The
config itself is unharmed, sitting in the repository the link pointed at, but
working that out from an empty bar is not a pleasant few minutes. Every command
above goes through the shell or touches only this plugin's own paths.

The agent's socket, FIFO and lock under `$XDG_RUNTIME_DIR` are removed when the
helper shuts down, which is what turning the agent off does. Removing the
plugin while the agent is still running kills the helper instead, so those
three files are left until you log out and the tmpfs goes with the session; a
stale socket at the routed path is harmless but answers nothing. Deleting the
directory by hand is safe once no helper is running.

Two more paths are written but need no cleaning up, because neither outlives
the moment it is used: the session handoff file under `$XDG_RUNTIME_DIR`, which
is read once and deleted and is on a tmpfs that goes with the login session,
and a `.qsbw-` staging directory inside your download folder, which exists only
for the length of an attachment download and is removed however that download
ends. Saved attachments themselves stay where you saved them, mode `600`.

Beyond those, the plugin writes nothing outside the paths above and your
`shell.json` entry, and it never modifies your Bitwarden vault on removal. Your vault is untouched -- log
out of the `bw` CLI separately with `bw logout` if you also want that cleared.

---

## IPC & Scripting Interface

You can control and query the Bitwarden plugin from the terminal, scripts, or window manager bindings. The form is `omarchy-shell <target> <method>`:

```bash
# Show, hide, or toggle the popup panel
omarchy-shell io.github.elevate08.qs-bitwarden-cli open
omarchy-shell io.github.elevate08.qs-bitwarden-cli close
omarchy-shell io.github.elevate08.qs-bitwarden-cli toggle

# Jump straight to a screen
omarchy-shell io.github.elevate08.qs-bitwarden-cli settings     # -> "settings"
omarchy-shell io.github.elevate08.qs-bitwarden-cli setup        # -> "setup" (dependency wizard)

# Lock the vault immediately
omarchy-shell io.github.elevate08.qs-bitwarden-cli lock         # -> "locked"

# Sync with Bitwarden
omarchy-shell io.github.elevate08.qs-bitwarden-cli sync         # -> "syncing"

# Query vault state
omarchy-shell io.github.elevate08.qs-bitwarden-cli status       # -> "unlocked" | "locked" | "unauthenticated"
```

`open`, `close` and `toggle` return nothing; the rest echo the state they moved to.

Omarchy's shell-level dispatcher also toggles any plugin, and works equally well for a keybinding:

```bash
omarchy-shell shell toggle io.github.elevate08.qs-bitwarden-cli
```

Only `toggle` exists at that level, though -- `omarchy-shell shell open|close <id>` answers `Function not found`, and `omarchy-shell shell call <id> <method> '{}'` answers `unknown`. Use the plugin-target form above for everything other than toggling.

The same calls work through Quickshell directly, which is useful when `omarchy-shell` is not on `PATH`:

```bash
qs -p /usr/share/omarchy/shell/shell.qml ipc call io.github.elevate08.qs-bitwarden-cli status
```

---

## Configuration Reference

The following settings are read from the plugin's own entry in the
`bar.layout` array of `~/.config/omarchy/shell.json` -- inline alongside its
`id`, as shown above. The panel's settings screen writes them for you via
`omarchy bar set`, so editing the file by hand is optional:

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `autoLockMinutes` | `number` | `15` | Minutes of inactivity before automatically locking the vault (`0` to disable). Range `0`-`1440`; out of range is clamped and an unreadable value falls back to `15`. |
| `clearClipboardSec` | `number` | `30` | Seconds before automatically clearing copied secrets from the clipboard (`0` to disable). Range `0`-`300`; out of range is clamped and an unreadable value falls back to `30`. |
| `lockOnScreenLock` | `boolean` | `true` | Lock the vault as soon as the screen locks, rather than waiting out `autoLockMinutes`. Reads the Omarchy lock screen's own state, so it follows a manual lock and an idle lock alike. A shell without the lock plugin simply never reports a lock; it is never read as one. |
| `lockOnSuspend` | `boolean` | `true` | Lock the vault when the machine is going to sleep, so no unlocked session key is left in the suspended machine's memory. Holds a `delay` sleep inhibitor for about a second so the lock finishes first. Needs `gdbus` (glib2) and `systemd-inhibit`; without them the setting is simply inert. |
| `rememberSession` | `boolean` | `true` | Persist session token in OS keyring (`secret-tool`) while unlocked. Survives a shell restart, never a reboot -- see the note above. |
| `autoCopyTotpSec` | `number` | `3` | Seconds after password copy to automatically replace clipboard with TOTP code (`0` to disable). Range `0`-`30`; out of range is clamped and an unreadable value falls back to `3`. |
| `closeOnCopy` | `boolean` | `true` | Automatically close panel on Enter copy so target application receives focus immediately. |
| `suggestOnOpen` | `boolean` | `true` | Automatically suggest matching vault items for the active window or browser tab on open. |
| `fingerprintUnlock` | `boolean` | `false` | Unlock the vault with an enrolled fingerprint. Stores your master password in the OS login keyring -- see [Optional: Fingerprint Unlock](#6-optional-fingerprint-unlock). |
| `pinUnlock` | `boolean` | `false` | Unlock with a numeric PIN. Stores the master password encrypted under a PIN-derived key -- see [Optional: PIN Unlock](#5-optional-pin-unlock). |
| `sshAgentEnabled` | `boolean` | `false` | Serve your vault's SSH keys to `ssh`, Git and signing while the vault is unlocked. Starts a helper process and a socket under `$XDG_RUNTIME_DIR`; private keys stay in that helper and are dropped on lock -- see [SSH Agent](#7-optional-ssh-agent). |
| `sshAgentUnlockOnDemand` | `boolean` | `false` | Let an identity listing raise the unlock prompt when the vault is locked and no keys have been loaded yet, instead of answering with an empty list. Signing a key the helper already knows always raises the prompt, with or without this. Off by default: `ssh` asks the agent for identities on every connection, so this raises the configured approval surface on the first `ssh` after every login. |
| `sshAgentApprovalPopup` | `boolean` | `true` | Show SSH unlock and signing requests in a transient card in the middle of the screen instead of opening the anchored panel. Disable to show prompts in the panel. Multiple concurrent requests are queued sequentially with a "1 of N" counter and "Deny all" option. Escape and outside click deny. |
| `sshAgentApprovalWindowSec` | `number` | `120` | How long one approval keeps covering further signatures from the same program with the same key. Range `0`-`900`; `0` asks every time. Held in memory only and dropped on lock, logout or exit. |

One further key, `twoFactorMethods`, is written to the same entry but is not a
setting you configure. It records which two-step method last logged each
account in, keyed by login address -- `{"you@example.com": 0}`, where `0` is
authenticator, `1` email and `3` YubiKey -- so an account with more than one
method is asked only once, and two vaults on one machine each keep their own
answer. **Change method** on the code screen asks again and rewrites it. Entries
are capped at ten accounts, and anything unreadable is treated as not
remembered, which costs that account one extra prompt.

Learned suggestions are stored separately in `~/.local/state/qs-bitwarden-cli/associations.json`. Delete that file to reset everything the panel has learned; logging out deletes it for you.

---

## Dependencies

The helper's crates are updated by Dependabot under `versioning-strategy:
lockfile-only`, so a proposed bump only ever moves `agent/Cargo.lock` within
the bounds `agent/Cargo.toml` already allows. Crossing a major is a manual
edit, on purpose: several of the version floors in that manifest exist to keep
one copy of the RustCrypto traits in the graph, and Dependabot raising them
one at a time is what broke the build in PR #11.

**The crypto stack moves together or not at all.** `ssh-key` and `rsa`
re-export the trait generation their callers must match, and `agent/src/lib.rs`
calls those traits directly -- `Verifier::verify`, `try_sign`,
`pkcs1v15::SigningKey`. Bump one crate without the others and cargo resolves
two versions side by side, at which point the traits stop unifying and
nothing compiles. The coupled set is `ssh-key`, `ssh-encoding`,
`ed25519-dalek`, `rsa`, `signature`, `sha2`/`digest`, `zeroize` and
`rand_core`; Dependabot groups them under `crypto` for the same reason.

As of 2026-08-31 that upgrade is gated upstream: `ssh-key` is at `0.7.0-rc.11`
and `rsa` at `0.10.0-rc.18`, both still pre-release, and the stable releases
still pin the older generation. When they land, raise every crate in the set
in one commit and expect real source changes, not just a manifest edit.
Nothing will prompt you -- there are no `ignore` conditions to trip, because
cargo's own semver rules already hold `0.10` back from `0.11`.

Every accepted bump, major or not, changes the shipped bytes and so needs the
binary rebuilt in the same change -- see the `needs-binary-rebuild` label:

```bash
gh pr checkout <n>
./scripts/build-agent.sh    # re-enters the digest-pinned image
git commit -am "deps: rebuild the agent binary" && git push
```

CI never does this for you. `--compare-tracked` proves the committed bytes are
what the committed source builds; it cannot tell you whether that source is
trustworthy, and a malicious crate builds just as reproducibly as an honest
one. Reading the `Cargo.lock` diff before you commit the binary is the only
check that covers that, which is why the rebuild stays a human step.

---

## Linting

Omarchy plugins are Qt6/Quickshell, so lint with the **Qt6** `qmllint` --
`/usr/bin/qmllint` on Arch is the Qt5 binary from `qt5-declarative` and exits
255 with no diagnostics on this file. The `qs.*` modules resolve only when the
import path contains a directory named `qs`:

```bash
mkdir -p /tmp/qs-imports && ln -sfn /usr/share/omarchy/shell /tmp/qs-imports/qs
/usr/lib/qt6/bin/qmllint -I /tmp/qs-imports Panel.qml FormPickerRow.qml
```

Remaining `unqualified` and `missing-property` warnings are baseline Quickshell
noise -- the stock Omarchy plugins report the same categories -- as are the
`signal-handler-parameters` warnings on `Process.onExited`, whose
`QProcess::ExitStatus` argument qmllint cannot see.

Validate the manifest against the schema the shell enforces:

```bash
omarchy plugin validate .
```

---

## Tests

Regression suites require Node; the SSH-items boundary suite also exercises jq:

```bash
node tests/auth.test.js             # unlock/login commands, and that no credential reaches argv
node tests/auth-prewarm.test.js     # private FIFO lifecycle, byte-exact password delivery, and cancellation
node tests/context-match.test.js    # window-title matching and learned suggestions
node tests/setup-settings.test.js   # dependency probe, settings writer, PIN crypto
node tests/ssh-items.test.js         # bounded out-of-process vault sanitization and SSH private-key exclusion
node tests/first-run.test.js        # a fresh install with no `bw` yet: the setup gate, the
                                    # sequence that follows the install, and what the
                                    # in-panel install button asks for
node tests/generator.test.js        # generator option clamping and strength
node tests/folders.test.js          # folder parsing, filtering and assignment
node tests/sends.test.js            # Send payloads, parsing, and argv-safety
node tests/collections.test.js      # organization collections and item ownership
node tests/items.test.js            # item parsing, and that a list entry can build the detail view
node tests/attachments.test.js      # attachment metadata, that a vault file name cannot escape ~/Downloads,
                                    # that a symlink cannot redirect a download, and the transfer ceilings
node tests/handoff-urls.test.js     # session-handoff file path, and which URI schemes may be opened
node tests/rich-text.test.js        # vault text is drawn as text, never parsed as markup
node tests/session-boot.test.js     # a remembered session dies with the boot that minted it
node tests/stream-limits.test.js    # every stream the shell reads is capped by its producer
node tests/lock-state.test.js       # the auto-lock survives a suspend, the timings are clamped
                                    # on the way in, and a read of a vault that has since closed
                                    # is refused rather than rendered
node tests/lock-triggers.test.js    # locking on screen lock and on suspend, and the window in
                                    # which a terminal login's session key is accepted
node tests/hardening.test.js        # `--` before every server-chosen id, the custom-server check,
                                    # and that logging out takes the learned suggestions with it
node tests/buffer-scrub.test.js     # emptying the pipe buffers a lock used to leave full, and the
                                    # deadline and size ceiling on every generator-port request
node tests/initial-load.test.js     # items render before folders, organizations and status refresh
node tests/performance.test.js      # deterministic small/typical/large/stress vault guardrails
```

The performance suite generates invented 100-item/0.25 MiB, 500-item/1 MiB,
2,000-item/5 MiB and 5,000-item/14 MiB vaults. It reports p95 JSON parsing,
filtering and contextual-match times over 20 warm samples and fails on broad
regressions. It measures only in-process work after `bw` returns, so network,
server and CLI startup latency should be measured separately on the target
machine.

The 2026-08-24 auth benchmark used Bitwarden CLI 2026.2.0 and three runs with a
deliberately invalid password. A normal unlock took 2,641 ms median from submit
to result; after a three-second prewarm while the password screen was already
open, it took 1,026 ms -- a 1,615 ms / 61.1% reduction. These figures are a
same-machine comparison, not a universal latency promise.

Two suites need Qt rather than Node -- which any machine running the plugin
already has. One checks that Escape reaches the panel from inside a text
field; the other checks how Qt itself decides to draw a string, which is what
makes a vault value markup or text:

```bash
QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml
```

---

## License

MIT -- see [LICENSE](LICENSE).
