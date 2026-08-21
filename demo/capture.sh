#!/usr/bin/env bash
# Capture README screenshots against a fixture vault.
#
# Restarts the Omarchy shell with demo/bin ahead of it on PATH, so the plugin
# resolves `bw` to the shim and shows made-up data. Your real vault is never
# read, and the shell is restored on the way out -- including if this script
# is interrupted.
#
#   ./demo/capture.sh [output-dir]     (default: docs/screenshots)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO/docs/screenshots}"
IPC=(qs -p /usr/share/omarchy/shell/shell.qml ipc call io.github.elevate08.qs-bitwarden-cli)

for tool in grim magick wtype hyprctl quickshell /usr/bin/python3; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

mkdir -p "$OUT"

restore() {
  echo "restoring the real shell..."
  pkill -f "quickshell -n -p /usr/share/omarchy/shell" 2>/dev/null || true
  sleep 1
  omarchy restart shell >/dev/null 2>&1 || true
}
trap restore EXIT INT TERM

# start_shell <vault-state>
#
# The fixture shell is restarted per vault state rather than driven between
# them: the panel reads `bw status` once on open, so the logged-out screen
# cannot be reached from a running unlocked instance.
start_shell() {
  echo "starting shell with the fixture vault ($1)..."
  pkill -f "quickshell -n -p /usr/share/omarchy/shell" 2>/dev/null || true
  sleep 1
  PATH="$REPO/demo/bin:$PATH" QSBW_DEMO_STATUS="$1" \
    nohup quickshell -n -p /usr/share/omarchy/shell >/dev/null 2>&1 &
  sleep 6
  # Park the pointer so hover states and tooltips stay out of the shots.
  hyprctl dispatch movecursor 100 100 >/dev/null 2>&1 || true
}

# Crop to the panel itself rather than a fixed box. The panel resizes with its
# content, and -- more importantly -- a loose crop would put whatever is behind
# it (windows, filenames, terminal scrollback) into the published image.
shot() { # shot <name>
  sleep 1
  grim "$OUT/.raw.png"
  local box err
  # Keep the locator's own reason. Swallowing it turned a theme change into
  # six identical "could not locate the panel border" lines and no clue why.
  if box="$(/usr/bin/python3 "$REPO/demo/find_panel.py" "$OUT/.raw.png" 2>/tmp/find_panel.err)"; then
    magick "$OUT/.raw.png" -crop "$box" +repage "$OUT/$1.png"
    echo "  wrote $1.png  ($box)"
  else
    err="$(cat /tmp/find_panel.err)"
    echo "  SKIPPED $1: ${err:-could not locate the panel border}" >&2
  fi
  rm -f /tmp/find_panel.err
  rm -f "$OUT/.raw.png"
}

# --- logged out -------------------------------------------------------------

start_shell unauthenticated
"${IPC[@]}" open >/dev/null 2>&1; sleep 4
shot 06-login
"${IPC[@]}" close >/dev/null 2>&1 || true

# --- unlocked, populated vault ----------------------------------------------

start_shell unlocked
"${IPC[@]}" open >/dev/null 2>&1; sleep 4
shot 01-vault-list

wtype "f" 2>/dev/null; sleep 2
shot 02-folder-drawer
wtype -k Escape 2>/dev/null; sleep 1

wtype "g" 2>/dev/null; sleep 5
shot 03-generator
wtype -k Escape 2>/dev/null; sleep 1

wtype -M alt -k s -m alt 2>/dev/null; sleep 3
shot 04-sends
wtype -k Escape 2>/dev/null; sleep 1

wtype -M alt -k comma -m alt 2>/dev/null; sleep 3
shot 05-settings

"${IPC[@]}" close >/dev/null 2>&1 || true
echo "done -> $OUT"
