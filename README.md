# Bitwarden Plugin for Omarchy Shell

A native, high-performance Bitwarden password manager widget and panel for [Omarchy](https://omarchy.org/) powered by [Quickshell](https://quickshell.org/) and the official [Bitwarden CLI](https://bitwarden.com/help/bitwarden-cli/) (`bw`).

---

## Features

- **Status Bar Widget**:
  - **Dynamic Shield Icon**:
    - **Unlocked**: Full opacity accent shield (`󰞀`).
    - **Locked**: Full opacity base shield with a mini padlock badge (`󰌾`) in the corner.
    - **Logged Out**: Dimmed shield icon.
  - **Mouse Controls**:
    - **Left-click**: Toggle the popup vault panel.
    - **Right-click**: Instantly lock the vault (or open if locked).
    - **Middle-click**: Trigger a background vault synchronization with Bitwarden cloud.

- **Seamless In-Plugin Authentication**:
  - Log in directly from the panel without opening a terminal:
    - **Email & Master Password** with built-in **Two-Step Verification (2FA)** code input.
    - **API Key** authentication (Client ID + Client Secret + Master Password).
    - **Custom Server Support**: Works seamlessly with official Bitwarden servers and self-hosted Vaultwarden instances.
    - Optional quick-launch button for interactive terminal login (`bw login`).

- **Sequential Password → TOTP Copy on <kbd>Enter</kbd>**:
  - Selecting a login item and pressing <kbd>Enter</kbd> immediately copies the **Password** to your clipboard.
  - If the login item has a TOTP 2FA secret configured, a follow-up action banner activates for 8 seconds with a live countdown:
    - Pressing <kbd>Enter</kbd> a second time (or pressing <kbd>t</kbd>) immediately copies the live 6-digit **TOTP code** to your clipboard.

- **Full Add, Edit & Delete (CRUD) Operations**:
  - **Create Items (`n` key or `+` button)**: Add new **Logins** (`󰌋`) or **Secure Notes** (`󰈐`).
  - **Password Generator**: Built-in 1-click strong password generator (20-character uppercase, lowercase, numbers, special characters).
  - **Edit Items (`e` key or Edit button)**: Modify titles, credentials, authenticator keys, URLs, and notes.
  - **Delete Items (`x` key or Delete button)**: Delete items with confirmation protection.

- **Multi-Organization & Vault Filtering**:
  - Automatically queries and displays organizations you belong to.
  - Organization filter bar: **All Vaults**, **My Vault** (Personal items), or specific shared **Organization**.
  - Shared items display a prominent `󰓹 Org` tag in the list and detail views.
  - Choose destination vault (Personal vs. Organization) when creating or editing items.

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
      "rememberSession": true
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

To toggle the Bitwarden panel with a keyboard shortcut (e.g. `SUPER + B`), add the binding to `~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + B", "Bitwarden vault", "omarchy-shell shell toggle qs-bitwarden-cli")
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
| <kbd>Enter</kbd> *(again)* | Copy TOTP code during 8-second follow-up window |
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

---

## License

MIT
