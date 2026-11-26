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
  // "plain" | "session" | "vault" | "vaultMerge" | "secret:<name>" |
  // "pinentry:<name>" (the answer of Model.pinentryCommand(), held decoded)
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
  // Moves on every start, so a deferred local start can tell it was replaced.
  property int startSeq: 0
  // The startSeq of the run this process is running now, held by the vault
  // with the run so a delayed exit is stamped with its own start.
  property int runSeq: 0
  // The runSeq of the local child, so its exit is stamped with the run that
  // produced it too.
  property int localSeq: 0
  // The startSeq of the run whose exit this is; set before exited() so a
  // handler can tell a delayed exit from an earlier (cancelled) run.
  property int finishSeq: 0

  onRunningChanged: {
    if (finishing) return
    if (running && runId === 0) start()
    else if (!running && runId !== 0) vault.vaultKill(proc)
  }

  function start() {
    startSeq += 1
    runSeq = startSeq
    sessionHeld = false
    outputHeld = false
    // A lock's scrub (Model.scrubCommand()): here it is only clearing text.
    if (Model.isScrubCommand(command)) {
      if (stdout) stdout.text = ""
      if (stderr) stderr.text = ""
      local.command = Model.scrubCommand()
      local.environment = ({})
      runId = -1
      localSeq = runSeq
      local.launchedSeq = runSeq
      local.running = true
      return
    }
    vault.vaultStart(proc)
  }

  // Called by the vault: run here instead of in the helper.
  function runLocally(env) {
    launchLocal(command, env, startSeq)
  }

  // The command is taken with its environment. A start deferred behind the
  // previous run's collector clear is dropped once replaced, and once
  // cancelled ends as a killed run would, so exited() still arrives.
  function launchLocal(cmd, env, seq) {
    if (seq !== startSeq) return
    if (!running) {
      finish(143, "", "", false, false, seq)
      return
    }
    // The old child can be on its way out (killLocal() set `exiting`): its
    // onExited has not run yet, so launching now would overwrite the sequence
    // it must be stamped with. Wait for it, then try again.
    if (local.running || local.exiting) {
      Qt.callLater(function() { proc.launchLocal(cmd, env, seq) })
      return
    }
    runId = -1
    runSeq = seq
    localSeq = seq
    // The child's own exit reads this, not the mutable localSeq a later run
    // would overwrite before a delayed exit arrives.
    local.launchedSeq = seq
    local.command = cmd
    local.environment = env
    local.stdinEnabled = stdinText !== ""
    local.running = true
  }

  // Called by the vault (or `local`) when the run has ended. `seq` is the
  // startSeq of the run that ended, so a delayed exit from a cancelled run
  // cannot borrow the generation of the run that replaced it.
  function finish(code, out, err, heldSession, heldOutput, seq) {
    // A delayed exit from a run that has been replaced is not this run's:
    // clearing runId, running and the collectors would lose the newer run.
    if (seq !== undefined && seq !== runSeq) return
    if (stdout) stdout.text = String(out || "")
    if (stderr) stderr.text = String(err || "")
    sessionHeld = Boolean(heldSession)
    outputHeld = Boolean(heldOutput)
    finishSeq = (seq === undefined ? runSeq : seq)
    runId = 0
    finishing = true
    running = false
    finishing = false
    if (stdout) stdout.streamFinished()
    if (stderr) stderr.streamFinished()
    exited(code, 0)
  }

  function killLocal() {
    // Only a child that is actually running will report an exit. Setting
    // `exiting` when nothing runs would strand the next launch.
    if (local.running) {
      local.exiting = true
      local.running = false
    }
  }

  Process {
    id: local
    // The startSeq of the child running here now; its exit is stamped with
    // this rather than the process's latest run.
    property int launchedSeq: 0
    // A killed child is still on its way to onExited; a start waits for it so
    // it cannot overwrite the sequence that exit must carry.
    property bool exiting: false
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
      // This child's own start generation: launching was held back while it
      // was exiting, so nothing has overwritten it yet.
      var seq = launchedSeq
      exiting = false
      var scrub = Model.isScrubCommand(command)
      var out = localOut.text
      var err = localErr.text
      // The copies here were only the way in; the caller's collector keeps them.
      if (!scrub) Qt.callLater(function() {
        if (local.running) return
        local.command = Model.scrubCommand()
        // The next command starts with no environment of the run it scrubs.
        local.environment = ({})
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
      proc.finish(exitCode, scrub ? "" : out, scrub ? "" : err, false, held, seq)
    }
  }
}
