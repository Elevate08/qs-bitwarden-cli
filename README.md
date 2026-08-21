# qs-bitwarden-cli

A modern, fast, and feature-rich Bitwarden password manager plugin for the **Omarchy** shell environment and **Hyprland** desktop.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](manifest.json)
[![Platform: Omarchy](https://img.shields.io/badge/platform-Omarchy%20%2F%20Hyprland-7c3aed.svg)](https://omarchy.org/)
[![Requires: Bitwarden CLI](https://img.shields.io/badge/requires-bw%20CLI-175ddc.svg)](https://bitwarden.com/help/cli/)

![Status Bar Integration](https://raw.githubusercontent.com/bitwarden/brand/main/icons/icon.png)

---

## Overview

`qs-bitwarden-cli` seamlessly integrates your Bitwarden vault into the Omarchy status bar and quick access panel. Built with native QML/C++ bindings on top of Quickshell and the official Bitwarden CLI (`bw`), it provides lightning-fast search, secure credential auto-copy, live 2FA TOTP generation, multi-organization switching, and complete vault item management without ever opening a web browser.

---

## Features

- **Full Status Bar & Quick Access Panel Integration**:
  - Live vault lock state indicated in the status bar (`󰞀` shield icon: accent when unlocked, base when locked, urgent when unauthenticated).
  - Clean drop-down panel with fast navigation and keyboard-first workflow.

- **Authentication & Secure Keyring Storage**:
  - Direct Master Password unlock.
  - Interactive login with Email + Password / 2FA (Authenticator App, Email, Duo, YubiKey) or API Key credentials (`BW_CLIENTID` / `BW_CLIENTSECRET`).
  - **Custom Server Support**: Works seamlessly with official Bitwarden servers and self-hosted Vaultwarden instances.
  - Optional quick-launch button for interactive terminal login (`bw login`).

- **PIN Unlock** (opt-in, `pinUnlock`):
  - Unlock with a numeric PIN instead of typing the master password. Minimum 4 digits, no upper limit -- longer is meaningfully harder to guess.
  - Unlike fingerprint unlock, the master password is **not** stored in the clear: it is encrypted with a key derived from your PIN (PBKDF2-SHA256, 600,000 iterations, salted) and only the ciphertext is kept, so reading the keyring alone does not reveal it.
  - A wrong PIN simply fails to decrypt, so no PIN hash is stored and there is none to attack.
  - Five wrong attempts removes the stored ciphertext entirely; re-enabling needs the master password again. So does a master password change, which is detected on the first failed unlock.

- **Fingerprint Unlock** (opt-in, `fingerprintUnlock`):
  - Unlock the vault with an enrolled fingerprint instead of retyping your master password.
  - Verifies through the same PAM stack as the Omarchy lock screen (`/etc/pam.d/omarchy-lock-fingerprint`), so it works wherever `omarchy setup security fingerprint` has been run.
  - The reader is armed automatically whenever you open the panel on a locked vault; the master password field always stays available as a fallback.
  - See [Fingerprint Unlock](#fingerprint-unlock) below for the security trade-off before enabling it.

- **Context-Aware Password Suggestions (Active Window / Browser Tab)**:
  - Reads the active window on open (`hyprctl activewindow -j`, falling back to the `hyprctl clients -j` focus history when the panel itself holds focus).
  - Recognises the current site from the browser's page title and matches it against each item's URLs and name using Bitwarden-style host and base-domain rules, brand aliases (a `Gmail` tab matches a `google.com` item), and word-boundary matching that ignores public suffixes and generic labels such as `www`, `login`, or `com`.
  - Places a highlighted **`󰌠 Suggested for <App / Website>`** banner and pins matching credentials to the top of the list with pre-selection, so pressing <kbd>Enter</kbd> immediately copies the right credential.
  - Only the strongest tier of matches is shown (at most 6), and a title with nothing identifiable in it produces no suggestions rather than a guess.
  - Standalone desktop apps match on window class; terminals only suggest for remote `ssh`/`mosh`/`sftp` hosts, never for local shells.
  - **It learns.** Opening or copying an item while a window is active records that window against the item, and it is suggested outright next time -- ahead of every heuristic. This is what handles sites a title can never match: a portal on `auth.example.xyz` titled `Home - authentik` shares no word with the stored credential, so pick it once and it sticks. Learned suggestions are marked `󰐾` rather than `󰌠`.
  - **Suggest here / Suggested here** in an item's detail view pins or unpins that item for the current site or app deliberately, without waiting to be taught.
  - Re-picking a different item retargets what was learned, so a bad association corrects itself the next time you choose.
  - Associations live in `~/.local/state/qs-bitwarden-cli/associations.json` (mode `600`) and hold only vault item IDs and the title words they were learned from -- never credentials.
  - **Limitation:** browsers do not publish the active tab URL to Wayland or Hyprland, so the *heuristics* work from the page title. A site whose title mentions neither its name nor its domain (`New Tab`, a bare `Sign in`) cannot be inferred -- teach it once instead.

- **Smart Auto-Copy TOTP Flow on <kbd>Enter</kbd>**:
  - Selecting a login item and pressing <kbd>Enter</kbd> copies the **Password** to the clipboard and automatically closes the panel, returning focus immediately to your target application so you can paste (<kbd>Ctrl+V</kbd>) and submit.
  - If the item has a TOTP 2FA secret configured, the plugin automatically copies the live 6-digit **TOTP code** to your clipboard after a brief delay (default: 3s) and displays a desktop notification:
    - You can immediately paste the TOTP code into the 2FA prompt without ever reopening or refocusing the plugin!
    - If you prefer manual progression, pressing <kbd>Enter</kbd> or <kbd>t</kbd> while the follow-up banner is active also copies the code immediately.

- **Full Add, Edit & Delete (CRUD) Operations**:
  - **Create Items (`n` key or `+` button)**: Add new **Logins** (`󰌋`) or **Secure Notes** (`󰈐`).
  - **Password Generator**: A full generator screen (<kbd>g</kbd> or the `󰌆` button) mirroring the Bitwarden browser extension's options -- password (length, A-Z, a-z, 0-9, special, minimum numbers, minimum special, avoid ambiguous) or passphrase (word count, separator, capitalise, include number), with a live strength meter. Generation is delegated to `bw generate`, so the output comes from Bitwarden's own generator rather than a reimplementation.
  - **Edit Items (`e` key or Edit button)**: Modify titles, credentials, authenticator keys, URLs, and notes.
  - **Delete Items (`x` key or Delete button)**: Delete items with confirmation protection.

- **Folders**:
  - Filter by folder from the bottom filter bar: **All Folders**, **No Folder**, or any specific folder.
  - Items show their folder inline (`󰉋 Name`) when no folder filter is active.
  - Assign a folder when creating or editing an item, including clearing an existing assignment, and create a new folder inline from the item form without leaving it.

- **Unified Bottom Filter Bar**:
  - Three identical buttons centred at the bottom -- **Folders**, **Organizations**, **Types** -- each showing its current selection, so the active filters are readable at a glance without opening anything.
  - Clicking one expands a vertical list in place. Only one opens at a time, and the item list gives back exactly the height the open list takes, so the panel does not jump.
  - Lists show up to five rows and scroll beyond that; shorter lists size to their content.
  - Selecting an item collapses whichever list is open, so it never sits over the results.
  - Keyboard: <kbd>f</kbd> for folders, <kbd>v</kbd> for organizations, <kbd>Tab</kbd> still cycles types.

- **Multi-Organization & Vault Filtering**:
  - Automatically queries and displays organizations you belong to.
  - Organization filter bar: **All Vaults**, **My Vault** (Personal items), or specific shared **Organization**.
  - Shared items display a prominent `󰓹 Org` tag in the list and detail views.
  - Choose destination vault (Personal vs. Organization) when creating or editing items.

- **Setup Wizard & In-Panel Settings**:
  - Checks every external tool the plugin shells out to (`bw`, `wl-copy`, `hyprctl`, `secret-tool`, `fprintd`) in a single probe, marking each required or optional and saying what it is for.
  - A missing **required** tool opens the wizard automatically; **Install** runs `omarchy pkg add <pkg>` in a terminal so you can see it happen and answer the password prompt. `fprintd` present without an enrolled finger offers **Enroll** (`omarchy setup security fingerprint`).
  - Press <kbd>,</kbd> or the `󰒓` button for settings, grouped into **Security**, **Behavior** and **Suggestions**: auto-lock timeout, clipboard clear delay, TOTP auto-copy delay, and every toggle. A setting whose dependency is missing is shown but inert, with the reason given.
  - Changes are written to the plugin's entry in `~/.config/omarchy/shell.json` through `omarchy bar set`, so Omarchy owns the file and the shell hot-reloads the change. Nothing is stored in a second place.
  - Reachable from a keybind too: `omarchy-shell shell call qs-bitwarden-cli settings '{}'` (or `setup`).

- **Hardware-Accelerated Performance & Security**:
  - Virtualized `ListView` with component delegate recycling for instant rendering of large vaults.
  - Asynchronous search debouncing (50ms) for responsive 0ms typing latency.
  - Master password passed exclusively through environment variables (`--passwordenv`), never command-line arguments.
  - Automatic clipboard clearing (`wl-copy --clear`) after a configurable timeout (default: 30s).
  - Optional session token caching in Linux Secret Service (`secret-tool` / libsecret).

---

## Installation & Setup

### 1. Requirements

Ensure the required dependencies are installed on your Arch Linux system:

```bash
sudo pacman -S bitwarden-cli wl-clipboard libsecret
```

### 2. Plugin Installation

Clone or place the plugin repository in `~/projects/qs-bitwarden-cli` and symlink it to Omarchy's user plugin directory:

```bash
mkdir -p ~/.config/omarchy/plugins
ln -s ~/projects/qs-bitwarden-cli ~/.config/omarchy/plugins/qs-bitwarden-cli
```

### 3. Add to Bar Configuration

Add the plugin to your `~/.config/omarchy/shell.json` in the status bar layout:

```bash
omarchy plugin enable qs-bitwarden-cli
omarchy bar move qs-bitwarden-cli --section right
```

Or edit `~/.config/omarchy/shell.json` directly:

```json
{
  "plugins": {
    "qs-bitwarden-cli": {
      "autoLockMinutes": 15,
      "clearClipboardSec": 30,
      "rememberSession": true,
      "fingerprintUnlock": false
    }
  },
  "bar": {
    "layout": {
      "right": [
        "qs-bitwarden-cli"
      ]
    }
  }
}
```

### 4. Global Hotkey Configuration

To toggle the Bitwarden panel with a keyboard shortcut (e.g. `SUPER + CTRL + /`), add the binding to `~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + CTRL + SLASH", "Bitwarden vault", "omarchy-shell shell toggle qs-bitwarden-cli")
```

Apply changes by restarting the shell:

```bash
omarchy restart shell
```

---

## Usage & Keyboard Shortcuts

### Vault List View (Main Screen)

| Shortcut | Action |
| :--- | :--- |
| <kbd>Enter</kbd> | Copy Password (and arm TOTP follow-up) |
| <kbd>Enter</kbd> *(again)* | Copy TOTP code during follow-up window |
| <kbd>↑</kbd> / <kbd>↓</kbd> / <kbd>j</kbd> / <kbd>k</kbd> | Navigate through items in list |
| <kbd>/</kbd> | Focus the search input field |
| <kbd>Tab</kbd> / <kbd>Shift+Tab</kbd> | Cycle through categories (All, Logins, Notes, Cards, Identities, Favorites) |
| <kbd>y</kbd> / <kbd>p</kbd> | Copy password to clipboard |
| <kbd>u</kbd> / <kbd>c</kbd> | Copy username / email to clipboard |
| <kbd>t</kbd> | Copy TOTP 2FA code to clipboard |
| <kbd>o</kbd> | Open website URL in default browser |
| <kbd>n</kbd> | Create a new vault item |
| <kbd>e</kbd> | Open detail inspector / Edit item |
| <kbd>r</kbd> | Synchronize vault with Bitwarden cloud |
| <kbd>l</kbd> | Lock the vault |
| <kbd>Esc</kbd> | Clear search query or close panel |

### Detail Inspector View

| Shortcut | Action |
| :--- | :--- |
| <kbd>y</kbd> / <kbd>p</kbd> | Copy password to clipboard |
| <kbd>u</kbd> / <kbd>c</kbd> | Copy username to clipboard |
| <kbd>t</kbd> | Copy TOTP code to clipboard |
| <kbd>v</kbd> | Toggle reveal / mask password |
| <kbd>e</kbd> | Edit this item |
| <kbd>x</kbd> | Delete this item (opens confirmation) |
| <kbd>b</kbd> / <kbd>q</kbd> / <kbd>Esc</kbd> | Return to main list view |

---

## IPC & Scripting Interface

You can control and query the Bitwarden plugin from the terminal, scripts, or window manager bindings via `omarchy-shell`:

```bash
# Toggle the popup panel
omarchy-shell shell toggle qs-bitwarden-cli

# Open the popup panel
omarchy-shell shell open qs-bitwarden-cli

# Close the popup panel
omarchy-shell shell close qs-bitwarden-cli

# Lock the vault immediately
omarchy-shell shell call qs-bitwarden-cli lock '{}'

# Trigger a vault sync with Bitwarden cloud
omarchy-shell shell call qs-bitwarden-cli sync '{}'

# Query vault status ("unlocked" | "locked" | "unauthenticated")
omarchy-shell shell call qs-bitwarden-cli status '{}'
```

---

## Configuration Reference

The following settings can be configured under `plugins.qs-bitwarden-cli` in `~/.config/omarchy/shell.json`:

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `autoLockMinutes` | `number` | `15` | Minutes of inactivity before automatically locking the vault (`0` to disable). |
| `clearClipboardSec` | `number` | `30` | Seconds before automatically clearing copied secrets from the clipboard (`0` to disable). |
| `rememberSession` | `boolean` | `true` | Persist session token in OS keyring (`secret-tool`) while unlocked. |
| `autoCopyTotpSec` | `number` | `3` | Seconds after password copy to automatically replace clipboard with TOTP code (`0` to disable). |
| `closeOnCopy` | `boolean` | `true` | Automatically close panel on Enter copy so target application receives focus immediately. |
| `suggestOnOpen` | `boolean` | `true` | Automatically suggest matching vault items for the active window or browser tab on open. |
| `fingerprintUnlock` | `boolean` | `false` | Unlock the vault with an enrolled fingerprint. Stores your master password in the OS login keyring -- see below. |
| `pinUnlock` | `boolean` | `false` | Unlock with a numeric PIN. Stores the master password encrypted under a PIN-derived key -- see below. |

Learned suggestions are stored separately in `~/.local/state/qs-bitwarden-cli/associations.json`. Delete that file to reset everything the panel has learned.

---

## PIN Unlock

Turn on **Unlock with PIN** in the settings screen. You are asked for your master password once (it is needed to encrypt) and for a PIN of at least 4 digits; there is no upper limit and a longer PIN is stronger.

**How it differs from fingerprint unlock.** Fingerprint unlock keeps your master password in the login keyring in the clear, because PAM can only prove presence. A PIN can do better: the master password is encrypted with a key derived from the PIN (PBKDF2-SHA256, 600,000 iterations, salted) and only the ciphertext is stored, so reading the keyring is not by itself enough. A wrong PIN fails decryption, which means correctness needs no stored hash and there is no hash to attack.

**The honest limit.** A short PIN is a small search space, and if the ciphertext leaks, the iteration count is the only thing standing between an attacker and your master password. Five wrong attempts at the panel deletes the stored ciphertext, but that does nothing against an offline attack on a copy of it. Prefer more than 4 digits.

The stored ciphertext is removed when you turn the setting off, after five wrong attempts, or when the vault rejects the decrypted password (for example after a master password change).

---

## Fingerprint Unlock

Set `fingerprintUnlock` to `true` to unlock the vault with a finger instead of your master password.

**Requirements**

- A fingerprint reader with at least one enrolled finger, configured through `omarchy setup security fingerprint`. The plugin verifies all of this itself (`/etc/pam.d/omarchy-lock-fingerprint`, `fprintd-list`) and silently stays hidden when any part is missing.
- `secret-tool` (libsecret) and a running OS keyring, as used by `rememberSession`.

**How it works**

1. Enable the setting, then unlock the vault once with your master password. That unlock stores the password in the login keyring under `service=qs-bitwarden-cli, account=master_password`.
2. On every later lock, opening the panel arms the reader. A verified fingerprint releases the stored password to `bw unlock`; the password field remains available as a fallback at all times.

**Security trade-off -- read before enabling**

PAM can prove that you are present, but it cannot produce your Bitwarden master password, and `bw unlock` accepts nothing else. Fingerprint unlock therefore keeps your master password in the OS login keyring and treats a verified fingerprint as the gate on reading it back. This is the same trade the official Bitwarden desktop client makes for its own biometric unlock, and it means **anyone who can read your unlocked login keyring can read your master password**. It is off by default and worth leaving off on a shared or unattended machine.

The stored password is removed when you turn the setting off, press **Forget Fingerprint** on the locked screen, log out of the account, or when the vault rejects it (for example after a master password change, which then prompts you for the new one).

---

## Tests

Regression suites, no dependencies beyond Node:

```bash
node tests/context-match.test.js    # window-title matching and learned suggestions
node tests/setup-settings.test.js   # dependency probe, settings writer, PIN crypto
node tests/generator.test.js        # generator option clamping and strength
node tests/folders.test.js          # folder parsing, filtering and assignment
```

---

## License

MIT -- see [LICENSE](LICENSE).
