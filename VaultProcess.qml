import QtQuick
import Quickshell.Io
import "BitwardenModel.js" as Model

// A `bw` run, used like Process + StdioCollector. While the vault helper is
// up it runs there, with the session (and any held secret `inject` names)
// added by the helper, so neither passes through the shell; `capture` says
// what the helper keeps of its stdout (see docs/vault-helper.md). Otherwise
// it runs here as a plain Process with the session from `vault.session`.
Item {
  id: proc
  visible: false

  required property var vault
  property var command: []
  property var environment: ({})
  property bool running: false
  property VaultCollector stdout: null
  property VaultCollector stderr: null
  // "plain" | "session" | "vault" | "vaultMerge" | "secret:<name>"
  property string capture: "plain"
  // Add BW_SESSION.
  property bool session: true
  // More held values, { VAR: "secret:<name>" }.
  property var inject: ({})
  // Written to stdin, then closed.
  property string stdinText: ""
  // Whether the helper kept a session key from this run's output.
  property bool sessionHeld: false
  // Whether a `secret:<name>` capture kept the output.
  property bool outputHeld: false

  signal started()
  signal exited(int exitCode, int exitStatus)

  // The helper's id for the run in flight, 0 if none, -1 while it runs here.
  property int runId: 0
  property bool finishing: false

  onRunningChanged: {
    if (finishing) return
    if (running && runId === 0) start()
    else if (!running && runId !== 0) vault.vaultKill(proc)
  }

  function start() {
    sessionHeld = false
    outputHeld = false
    // A lock's scrub (Model.scrubCommand()): here it is only clearing text.
    if (Model.isScrubCommand(command)) {
      if (stdout) stdout.text = ""
      if (stderr) stderr.text = ""
      local.command = Model.scrubCommand()
      local.environment = ({})
      runId = -1
      local.running = true
      return
    }
    vault.vaultStart(proc)
  }

  // Called by the vault: run here instead of in the helper.
  function runLocally(env) {
    // The previous run's collector clear may still be going.
    if (local.running) {
      Qt.callLater(function() { proc.runLocally(env) })
      return
    }
    runId = -1
    local.command = command
    local.environment = env
    local.stdinEnabled = stdinText !== ""
    local.running = true
  }

  // Called by the vault (or `local`) when the run has ended.
  function finish(code, out, err, heldSession, heldOutput) {
    if (stdout) stdout.text = String(out || "")
    if (stderr) stderr.text = String(err || "")
    sessionHeld = Boolean(heldSession)
    outputHeld = Boolean(heldOutput)
    runId = 0
    finishing = true
    running = false
    finishing = false
    if (stdout) stdout.streamFinished()
    if (stderr) stderr.streamFinished()
    exited(code, 0)
  }

  function killLocal() {
    if (local.running) local.running = false
  }

  Process {
    id: local
    stdout: StdioCollector { id: localOut; waitForEnd: true }
    stderr: StdioCollector { id: localErr; waitForEnd: true }
    onStarted: {
      if (stdinEnabled) {
        write(proc.stdinText)
        stdinEnabled = false
      }
      proc.started()
    }
    onExited: function(exitCode, exitStatus) {
      var scrub = Model.isScrubCommand(command)
      var out = localOut.text
      var err = localErr.text
      // The copies here were only the way in; the caller's collector keeps them.
      if (!scrub) Qt.callLater(function() {
        if (local.running) return
        local.command = Model.scrubCommand()
        local.running = true
      })
      if (scrub && proc.runId !== -1) return
      // A held value stays out of the caller's collector here too.
      var held = false
      if (!scrub && proc.capture.indexOf("secret:") === 0) {
        if (out) {
          proc.vault.holdLocalSecret(proc.capture.slice(7), out)
          held = true
        }
        out = ""
      }
      proc.finish(exitCode, scrub ? "" : out, scrub ? "" : err, false, held)
    }
  }
}
