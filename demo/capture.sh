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
  # The fixture vault's SSH key gets projected to the same directory the real
  # one uses. The real shell rewrites its own keys on the next load but will
  # not remove a file it never wrote, so a demo key would sit there for good.
  rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/qs-bitwarden-cli/ssh/Demo Deploy Key.pub"
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
  if [ -n "${QSBW_KEEP_RAW:-}" ]; then mv -f "$OUT/.raw.png" "$OUT/.raw-$1.png" 2>/dev/null || true
  else rm -f "$OUT/.raw.png"; fi
}

# --- SSH signing approval ---------------------------------------------------
#
# The approval screen exists only while a real signing request is waiting, so
# it cannot be navigated to -- it has to be raised. `ssh-add -T` asks the agent
# to sign one challenge with one key and nothing else, which is the smallest
# request that produces this prompt.
#
# Everything here is the fixture vault: the key is the throwaway pair in
# fixtures.json, and the socket belongs to the fixture shell started above.
# The request is denied rather than approved, so no signature is ever made.
capture_ssh_approval() {
  local sock="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/qs-bitwarden-cli/ssh-agent.sock"
  local pub="${XDG_DATA_HOME:-$HOME/.local/share}/qs-bitwarden-cli/ssh/Demo Deploy Key.pub"

  # The helper starts with the panel and projects its public keys after the
  # vault loads, so wait for the file rather than guessing at a delay.
  local waited=0
  while [ ! -S "$sock" ] || [ ! -f "$pub" ]; do
    sleep 1; waited=$((waited + 1))
    if [ "$waited" -ge 30 ]; then
      echo "  skipped 07-ssh-approval: no agent socket or projected key after ${waited}s" >&2
      echo "  (is 'Act as your SSH agent' enabled in shell.json?)" >&2
      return 0
    fi
  done

  "${IPC[@]}" open >/dev/null 2>&1; sleep 2
  # In the background: it blocks until the prompt is answered, which is the
  # point -- the prompt has to still be on screen when the shot is taken.
  SSH_AUTH_SOCK="$sock" ssh-add -T "$pub" >/dev/null 2>&1 &
  local asker=$!
  sleep "${QSBW_SSH_SETTLE:-4}"
  shot 07-ssh-approval
  # Deny it. Escape is the approval screen's own deny, so nothing is signed.
  wtype -k Escape 2>/dev/null; sleep 1
  wait "$asker" 2>/dev/null || true
  "${IPC[@]}" close >/dev/null 2>&1 || true
}

# QSBW_ONLY_SSH=1 captures the approval shot alone. It is the only shot that
# depends on timing rather than on a keystroke, so it is the one that gets
# iterated on, and re-running the whole sequence to retake it costs a minute
# and five shells.
if [ -n "${QSBW_ONLY_SSH:-}" ]; then
  start_shell unlocked
  capture_ssh_approval
  echo "done -> $OUT"
  exit 0
fi

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

capture_ssh_approval

echo "done -> $OUT"
