import QtQuick
import Quickshell.Io

// Tracks whether the laptop lid is closed.
//
// The fingerprint reader sits on the laptop body, so a shut lid puts it out of
// reach -- clamshell mode on a desk, or the lid simply closed on a docked
// machine. Offering "Unlock with Fingerprint" there is a button that cannot
// work, so the vault drops it while the lid is down. Nothing else changes: the
// master password field stays, and a FIDO2 key on a cable is unaffected.
//
// Omarchy's own detector reads /proc/acpi/button/lid/*/state and exits 0 when
// the lid is closed, so a machine with no lid never reports one and a machine
// without the detector exits non-zero, which reads as open. Polled rather than
// watched: the state lives behind a glob, and the poll runs only while the
// panel or an SSH prompt is actually on screen.
Item {
  id: lid

  // The vault that instantiated this. It is asked only whether the panel or an
  // SSH prompt is up, so the poll stops when neither is.
  required property var vault

  // Read by the vault as `lidClosed`. False until the first reading lands --
  // the safe direction: a fingerprint reader that turns out to be reachable is
  // better than one that never appears.
  property bool closed: false

  readonly property int pollMs: 5000

  function refresh() {
    if (!lidStateProc.running) lidStateProc.running = true
  }

  Timer {
    id: lidPoll
    interval: lid.pollMs
    repeat: true
    // An unattached vault must do nothing, exactly as every other self-starting
    // process in the vault is gated on `live`. The tighter gate is the screen:
    // there is nothing to decide while no panel and no prompt is showing.
    running: lid.vault && lid.vault.live && (lid.vault.opened || lid.vault.sshAuthSurfaceActive)
    // The first tick is up to `pollMs` away, and the panel decides which unlock
    // buttons to draw the moment it opens. Read once as the gate opens, so that
    // decision is never made from a reading taken minutes ago.
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
