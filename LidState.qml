import QtQuick
import Quickshell.Io

// Whether the laptop lid is closed, which puts the fingerprint reader out of
// reach, so the vault stops offering fingerprint unlock. Reads Omarchy's
// detector (exit 0 = closed; no lid or no detector reads as open), polled only
// while the panel or an SSH prompt is showing.
Item {
  id: lid

  // Asked only whether the panel or an SSH prompt is up.
  required property var vault

  // False until the first reading: better to offer a reader than hide one.
  property bool closed: false

  // Catches a lid moving while the panel is up; each opening reads at once.
  readonly property int pollMs: 30000

  function refresh() {
    if (!lidStateProc.running) lidStateProc.running = true
  }

  Timer {
    id: lidPoll
    interval: lid.pollMs
    repeat: true
    // Only in a live vault, and only while something is on screen.
    running: lid.vault && lid.vault.live && (lid.vault.opened || lid.vault.sshAuthSurfaceActive)
    // Read once as it starts, so the panel never decides from a stale reading.
    onRunningChanged: if (running) lid.refresh()
    onTriggered: lid.refresh()
  }

  Process {
    id: lidStateProc
    // Exit status is the answer: 0 when the lid is closed.
    command: ["bash", "-c", "omarchy-hw-laptop-closed 2>/dev/null"]
    onExited: function(exitCode) { lid.closed = (exitCode === 0) }
  }
}
