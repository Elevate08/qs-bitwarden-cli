import QtQuick
import Quickshell
import Quickshell.Io
import "FidoModel.js" as Fido
import "BitwardenModel.js" as Model

// Owns "unlock with FIDO2 key". A touch asks the key for the hmac-secret of
// Omarchy's existing pam-u2f credential, which opens the envelope's FIDO wrap
// (BitwardenModel.js), so unlocking needs the physical key. The vault only
// passes in the setting and takes back the password.
Item {
  id: fido

  // No visuals; holds the key request, its processes and state.
  visible: false
  width: 0
  height: 0

  required property var vault
  // The fidoUnlock setting, pushed down by the vault.
  property bool armed: false

  // The last probe: which plugged-in key holds which registered credential.
  property var probe: Fido.parseFidoProbe("")
  // Tools installed, a credential registered, and a key holding a usable one
  // plugged in.
  property bool available: false
  // Any of those three present: worth drawing the option.
  property bool applicable: false
  // The legacy plaintext entry (account=fido_password), migrated by the first
  // touch that finds it.
  property bool legacyStored: false
  // Credentials the envelope has a FIDO wrap for.
  readonly property var envelopeCredentials: vault && vault.envelopeSummary
    && Array.isArray(vault.envelopeSummary.fido) ? vault.envelopeSummary.fido : []
  readonly property bool stored: legacyStored || envelopeCredentials.length > 0
  property bool scanning: false
  property bool authorized: false     // a live touch may consume one answer
  // Attempt progress, shown on the FIDO2 screen.
  property string message: ""
  // Why the last attempt failed; kept apart from `message` so it survives a
  // switch to another method.
  property string failure: ""

  // Setup form.
  property bool setupActive: false
  property string setupMaster: ""
  property string error: ""
  property bool busy: false
  property bool clearPending: false

  readonly property bool ready: armed && available && stored

  // "envelope" (a wrap exists) or "legacy" (migrating with the same touch).
  property string assertMode: ""
  property bool startAfterProbe: false

  // A key holds an abandoned request until its presence timeout; meanwhile
  // (~15 s on a YubiKey 5) new requests fail in <0.1 s with a misleading
  // error. A failure that fast, soon after abandoning one, is retried.
  property double abandonedAtMs: 0
  property double startedAtMs: 0
  property int busyRetries: 0
  readonly property int busyRetryMs: 2000
  // Outlasts the authenticator's presence timeout.
  readonly property int busyWindowMs: 40000
  // Faster than any real touch, so a failure inside it is the device refusing.
  readonly property int busyFailureMs: 1500
  readonly property int busyRetryLimit: 15
  // The key's own timeout for an unanswered request is ~28.6 s.
  readonly property int noTouchMs: 20000

  readonly property string touchMessage: "󰟵  Touch your FIDO2 key..."
  readonly property string busyMessage: "󰟵  Your key is finishing an earlier request -- touch it to clear it, or wait a moment..."

  // After a touch and a successful read; the vault decides what to do.
  signal unlocked(string password)

  // -------------------------------------------------------------------------
  // Readiness
  // -------------------------------------------------------------------------

  // The setting is usually true at construction, so onArmedChanged never
  // fires; probe now.
  Component.onCompleted: if (armed) refresh()

  function refresh() {
    // A probe would find the key busy with our own request.
    if (assertProc.running) return
    if (!probeProc.running) probeProc.running = true
  }

  function onProbe(raw) {
    var state = Fido.parseFidoProbe(raw)
    probe = state
    applicable = state.applicable
    available = state.ready
    if (available && armed) {
      if (!hasProc.running) hasProc.running = true
    }
    if (startAfterProbe) {
      startAfterProbe = false
      if (scanning) launchAssert()
    }
  }

  function onHasChecked(raw) {
    legacyStored = String(raw || "").trim() === "yes"
    // An SSH request can raise the auth surface before the panel opens.
    if (ready && vault && vault.status === "locked" && vault.sshAuthSurfaceActive) startUnlock()
  }

  // A credential with an envelope wrap on a plugged-in key; failing that,
  // while the legacy entry exists, any usable one (its touch migrates it).
  function unlockTarget() {
    var usable = probe.usable || []
    for (var i = 0; i < usable.length; i++) {
      for (var j = 0; j < envelopeCredentials.length; j++) {
        var wrap = envelopeCredentials[j]
        if (wrap.cred === usable[i].cred) {
          return { mode: "envelope", device: usable[i].device, cred: wrap.cred, rp: wrap.rp, salt: wrap.salt }
        }
      }
    }
    if (legacyStored && usable.length > 0 && probe.rp) {
      return { mode: "legacy", device: usable[0].device, cred: usable[0].cred, rp: probe.rp }
    }
    return null
  }

  function unavailableReason() {
    if (probe.pinOnly) {
      return "Your key's registration asks for its PIN as well as a touch, which vault unlock "
        + "cannot collect yet. Use your master password."
    }
    if (!probe.usable || probe.usable.length === 0) return "No registered FIDO2 key is plugged in."
    return "This key is not set up for vault unlock. Set up FIDO2 unlock again."
  }

  // -------------------------------------------------------------------------
  // Unlock
  // -------------------------------------------------------------------------

  function startUnlock() {
    if (!ready || !vault || vault.status !== "locked" || vault.isUnlocking) return
    if (!vault.quickUnlockAvailable || !vault.accountId) return
    // A request left by a closed panel is still waiting on the key: adopt it.
    if (assertProc.running) {
      scanning = true
      failure = ""
      if (message === "") message = touchMessage
      return
    }
    if (scanning) return
    authorized = false
    failure = ""
    scanning = true
    message = busyRetries > 0
      ? busyMessage
      : touchMessage
    // Re-probe first: a replugged key can move to another hidraw node.
    startAfterProbe = true
    if (!probeProc.running) probeProc.running = true
  }

  function launchAssert() {
    var target = unlockTarget()
    if (!target) {
      scanning = false
      message = ""
      failure = unavailableReason()
      return
    }
    assertMode = target.mode
    startedAtMs = Date.now()
    var tool = vault.envelopeTool()
    var account = vault.envelopeAccount()
    assertProc.command = target.mode === "envelope"
      ? Model.fidoUnlockCommand(tool, account, target)
      : Model.fidoLegacyUnlockCommand(tool, account, target)
    assertProc.running = true
  }

  // Leave the screen but keep the key's request running: stopping our side
  // would not free the key. A touch with no surface up is discarded; reopening
  // the panel just keeps waiting.
  function releaseSurface() {
    busyRetryTimer.stop()
    busyRetries = 0
    startAfterProbe = false
    if (!assertProc.running) {
      cancelUnlock()
      return
    }
    scanning = false
    authorized = false
    message = ""
  }

  function cancelUnlock() {
    busyRetryTimer.stop()
    startAfterProbe = false
    // Only an abandoned request leaves the key holding one.
    if (assertProc.running) {
      abandonedAtMs = Date.now()
      assertProc.running = false
    }
    scanning = false
    authorized = false
  }

  // Failed too fast to be an answer, soon after this panel abandoned a request.
  function deviceStillBusy() {
    var now = Date.now()
    return busyRetries < busyRetryLimit
      && (now - startedAtMs) < busyFailureMs
      && (now - abandonedAtMs) < busyWindowMs
  }

  function retryAfterBusy() {
    busyRetries += 1
    failure = ""
    message = busyMessage
    busyRetryTimer.restart()
  }

  function onAssertExited(exitCode) {
    if (vault && vault.finishScrubRun(assertProc)) return
    // Read, then scrubbed: on success this holds the password.
    var out = String(assertStdout.text || "")
    if (vault) vault.clearProcessCollectorSoon(assertProc)
    var mode = assertMode
    assertMode = ""
    var accepting = scanning && vault && vault.sshAuthSurfaceActive && vault.status === "locked"
    scanning = false
    var codes = Model.fidoExitCodes()
    var migrated = exitCode === 0 && mode === "legacy"
    if (migrated) {
      // The legacy entry was migrated and deleted, even if nobody is looking.
      legacyStored = false
      if (vault) vault.refreshEnvelope()
    }
    if (!accepting) { out = ""; return }

    if (exitCode === 0 || exitCode === codes.legacyUsed) {
      busyRetries = 0
      abandonedAtMs = 0
      authorized = false
      // The button shows "Unlocking..." by itself.
      message = "󰟵  Key verified"
      if (exitCode === codes.legacyUsed) {
        console.log("qs-bitwarden envelope: FIDO2 unlocked from the legacy entry; migration did not finish")
      }
      if (!out) {
        message = ""
        failure = "The key answered but no password came back. Use your master password."
        return
      }
      vault.fidoFromEnvelope = exitCode === 0
      unlocked(out)
      out = ""
      return
    }
    if (exitCode === codes.assert || exitCode === codes.noSecret) {
      if (deviceStillBusy()) {
        retryAfterBusy()
        return
      }
      message = ""
      failure = (Date.now() - startedAtMs) > noTouchMs
        ? "No touch received. Touch your key again or use your master password."
        : "Key not recognised. Touch it again or use your master password."
      return
    }
    if (exitCode === Model.legacyMigrationExitCodes().none) {
      legacyStored = false
      message = ""
      failure = unavailableReason()
      return
    }
    message = ""
    failure = "Could not read the stored password. Use your master password."
    if (vault) vault.refreshEnvelope()
  }

  // -------------------------------------------------------------------------
  // Stored credentials
  // -------------------------------------------------------------------------

  // Processes whose output can hold the master password, for the lock scrub.
  function secretProcesses() { return [assertProc] }

  function dropSecrets() { setupMaster = "" }

  // Clears the legacy entry, if any.
  function requestClear() {
    if (clearProc.running) {
      clearPending = true
      return
    }
    clearProc.running = true
  }

  // Remove every FIDO2 way in (envelope wraps and legacy entry). `notify`
  // false skips the confirmation.
  function forget(reasonMessage, notify) {
    cancelUnlock()
    var creds = envelopeCredentials.slice()
    for (var i = 0; i < creds.length; i++) {
      if (vault) vault.removeQuickUnlockMethod({ kind: "remove", method: "fido", cred: creds[i].cred })
    }
    legacyStored = false
    message = ""
    failure = String(reasonMessage === undefined || reasonMessage === null ? "" : reasonMessage)
    requestClear()
    if (notify !== false && vault) vault.flashNotification("FIDO2 unlock forgotten")
  }

  // State only: logout already cleared the keyring.
  function reset() {
    cancelUnlock()
    busyRetries = 0
    abandonedAtMs = 0
    legacyStored = false
    message = ""
    failure = ""
    setupActive = false
    busy = false
    setupMaster = ""
  }

  onArmedChanged: {
    if (!armed) {
      cancelUnlock()
      message = ""
      failure = ""
      // Unconditional, not `if (stored)`: that flag also goes false when the
      // key or packages are missing, and a way in may still be stored.
      forget("")
    } else {
      refresh()
    }
  }

  // -------------------------------------------------------------------------
  // Setup
  // -------------------------------------------------------------------------

  function beginSetup() {
    setupMaster = ""
    error = ""
    setupActive = true
    // Probe even if the setting is off: the form needs to know whether a key
    // is registered.
    refresh()
    if (vault) vault.currentScreen = "fido"
  }

  // Omarchy's enrolment, in a floating terminal (it prompts for sudo and a touch).
  function runOmarchySetup() {
    Quickshell.execDetached(Fido.fidoSetupCommand())
    if (vault) vault.flashNotification("FIDO2 setup opened -- this screen updates itself")
  }

  function abandonSetup() {
    // A wrap still being written is removed when it lands (see submitSetup()).
    if (busy && vault) vault.invalidateEpochOperation("fidoAdd")
    setupActive = false
    busy = false
    setupMaster = ""
  }

  // The typed master password is checked against the stored one; one touch
  // adds this key's wrap. Nothing typed is stored.
  function submitSetup() {
    if (busy || !vault) return
    if (!vault.quickUnlockAvailable) {
      error = vault.quickUnlockUnavailableReason
      return
    }
    if (!setupMaster) {
      error = "Confirm your master password to enable FIDO2 unlock"
      return
    }
    var usable = probe.usable || []
    if (usable.length === 0 || !probe.rp) {
      error = unavailableReason()
      return
    }
    var target = { device: usable[0].device, cred: usable[0].cred, rp: probe.rp }
    var typed = setupMaster
    setupMaster = ""
    error = ""
    busy = true
    setupActive = true
    message = "󰟵  Touch your FIDO2 key to finish..."
    startedAtMs = Date.now()
    vault.beginEpochOperation("fidoAdd")
    vault.addQuickUnlockMethodWith(typed, function(tool, account) {
      return Model.fidoEnrollCommand(tool, account, target)
    }, null, function(ok, why, code) {
      typed = ""
      busy = false
      message = ""
      // Stale by the time it landed: remove the wrap again.
      if (vault.epochOperationIsStale("fidoAdd") || !setupActive) {
        setupActive = false
        if (ok) vault.removeQuickUnlockMethod({ kind: "remove", method: "fido", cred: target.cred })
        return
      }
      setupActive = false
      if (!ok) {
        var codes = Model.fidoExitCodes()
        if (why === "wrong-password" || why === "stale") error = vault.quickUnlockErrorText(why, "")
        else if (code === codes.assert || code === codes.noSecret) error = "No touch received. Try again."
        else error = "Could not enable FIDO2 unlock. Is the OS keyring available?"
        setupActive = true
        return
      }
      // Supersedes any legacy entry.
      legacyStored = false
      requestClear()
      vault.writeSetting("fidoUnlock", true, "bool")
      vault.flashNotification("FIDO2 unlock enabled")
      vault.currentScreen = "settings"
    })
  }

  // -------------------------------------------------------------------------

  Process {
    id: probeProc
    command: Fido.fidoProbeCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: fido.onProbe(text)
    }
  }

  Process {
    id: hasProc
    command: Model.keyringHasFidoPasswordCommand(fido.vault ? fido.vault.activeSlot : "")
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: fido.onHasChecked(text)
    }
  }

  // One touch; the password is the only output. See Model.fidoUnlockCommand().
  Process {
    id: assertProc
    stdout: StdioCollector {
      id: assertStdout
      waitForEnd: true
    }
    onExited: function(exitCode) { fido.onAssertExited(exitCode) }
  }

  Process {
    id: clearProc
    command: Model.keyringClearFidoPasswordCommand(fido.vault ? fido.vault.activeSlot : "")
    onExited: function(exitCode) {
      if (fido.clearPending) {
        fido.clearPending = false
        clearProc.running = true
      }
    }
  }

  // Retry after the key had a moment, only while the conditions still hold.
  Timer {
    id: busyRetryTimer
    interval: fido.busyRetryMs
    repeat: false
    onTriggered: {
      if (!fido.ready || !fido.vault || fido.vault.status !== "locked"
          || !fido.vault.sshAuthSurfaceActive) {
        fido.busyRetries = 0
        return
      }
      fido.startUnlock()
    }
  }
}
