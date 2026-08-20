# Bitwarden Plugin for Omarchy Shell

A native Bitwarden password manager bar widget and popup panel for [Omarchy](https://omarchy.org/) powered by [Quickshell](https://quickshell.org/) and the official [`bw`](https://bitwarden.com/help/bitwarden-cli/) CLI.

## Features

- **Bar Widget & Status Indicator**:
  - Live status in the top bar: Shield icon (`󰞀`) when unlocked, Lock icon (`󰒃`) when locked, warning badge if unauthenticated.
  - Middle-click to sync vault with Bitwarden cloud.
  - Right-click to lock/unlock.
  - Left-click or hotkey to open the popup panel.
- **Secure Authentication & Unlocking**:
  - Unlocks using your Master Password passed securely through environment variables (never command-line arguments).
  - Optional session persistence via Linux Secret Service (`secret-tool` / libsecret) so you stay unlocked across panel closes.
  - Configurable auto-lock inactivity timer.
- **Fast Vault Search & Filtering**:
  - Live as-you-type search across item names, usernames, URIs, and notes.
  - Category filter pills: All, Logins (`󰌋`), Secure Notes (`󰈐`), Cards (`󰅝`), Identities (`󰓹`), and Favorites (`★`).
- **Quick Actions & Clipboard Integration**:
  - One-click or keyboard shortcut to copy passwords, usernames, and notes via `wl-copy`.
  - **Live TOTP (2FA)** generation with real-time 30-second countdown timer and instant copy.
  - One-click "Open URL" in default browser.
  - Automatic clipboard clearing after a configurable timeout (default: 30s) for enhanced security.
- **Full Item Inspector**:
  - Detailed view of logins, credit cards (with formatted expiration & CVV), identities, custom fields, and secure notes.
  - Show/Hide password toggle (`v`).
- **Full Keyboard Navigation**:
  - Arrow keys / `j` `k` to move through items.
  - `Enter` to inspect details.
  - `y` or `p` to copy password.
  - `u` or `c` to copy username.
  - `t` to copy TOTP 2FA code.
  - `o` to open URL in browser.
  - `l` to lock vault.
  - `r` to sync with Bitwarden.
  - `Tab` / `Shift+Tab` to cycle categories.
  - `Esc` to go back or close.

## Installation & Configuration

### 1. Enable the Plugin in Omarchy

Add the plugin to your status bar layout in `~/.config/omarchy/shell.json`:

```bash
omarchy plugin enable qs-bitwarden-cli
omarchy bar move qs-bitwarden-cli --section right
```

### 2. Optional Keybinding

To summon or toggle the Bitwarden panel with a shortcut (e.g. `SUPER + B`), add this to `~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + B", "Bitwarden vault", "omarchy-shell shell toggle qs-bitwarden-cli")
```

### 3. IPC Commands

You can interact with the plugin directly from scripts or terminal:

```bash
# Toggle panel
omarchy-shell shell toggle qs-bitwarden-cli

# Lock vault
omarchy-shell shell call qs-bitwarden-cli lock '{}'

# Sync vault
omarchy-shell shell call qs-bitwarden-cli sync '{}'

# Check status
omarchy-shell shell call qs-bitwarden-cli status '{}'
```

## Requirements

- `bitwarden-cli` (`bw`)
- `wl-clipboard` (`wl-copy`)
- `libsecret` (`secret-tool`)
