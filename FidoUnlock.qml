import QtQuick
import Quickshell
import Quickshell.Io
import "FidoModel.js" as Fido
import "BitwardenModel.js" as Model

// Owns "unlock with FIDO2 key".
//
// The credential is Omarchy's own registration in /etc/fido2/fido2, written by
// pam-u2f -- nobody re-enrolls anything for this. A touch no longer answers a
// PAM conversation, which can only say yes or no; it asks the key for that
// credential's hmac-secret, and the secret opens the envelope's FIDO wrap
// (BitwardenModel.js). No touch, no secret: the key itself refuses to produce
// one without presence. So unlocking needs the physical key, not just a
// program able to read the keyring.
//
// Almost all of FIDO2 lives here and in FidoModel.js; the vault keeps only the
// handful of lines that hand it a setting and take a password back.
Item {
  id: fido

  // No visual presence of its own; it exists to hold the key's request, the
  // processes and the state they act on.
  visible: false
  width: 0
  height: 0

  // The vault that instantiated this. The setting and the unlocked password
  // pass between them, and nothing else.
  required property var vault
  // The fidoUnlock setting, pushed down by the vault.
  property bool armed: false

  // The last probe: which plugged-in key holds which registered credential.
  property var probe: Fido.parseFidoProbe("")
  // Readiness: the tools are installed, Omarchy registered a credential, and a
  // key holding a usable one is plugged in right now.
  property bool available: false
  // Worth drawing at all -- any one of the three parts is present.
  property bool applicable: false
  // The plaintext entry older versions kept (account=fido_password). Migrated
  // by the first touch that finds it, then deleted.
  property bool legacyStored: false
  // Credentials the envelope has a FIDO wrap for.
  readonly property var envelopeCredentials: vault && vault.envelopeSummary
    && Array.isArray(vault.envelopeSummary.fido) ? vault.envelopeSummary.fido : []
  readonly property bool stored: legacyStored || envelopeCredentials.length > 0
  property bool scanning: false
  property bool authorized: false     // a live touch may consume one answer
  // Progress of an attempt at the key, shown only on the FIDO2 screen.
  property string message: ""
  // Why the last attempt failed. Kept apart from `message` for the reason the
  // fingerprint's own split exists: an unreadable key is exactly when the user
  // moves to another method, and the reason has to go with them.
  property string failure: ""

  // Setup form.
  property bool setupActive: false
  property string setupMaster: ""
  property string error: ""
  property bool busy: false
  property bool clearPending: false

  readonly property bool ready: armed && available && stored

  // Which kind of request is in flight: "envelope" (a wrap exists) or
  // "legacy" (migrating the plaintext entry with the same touch).
  property string assertMode: ""
  property bool startAfterProbe: false

  // A key answers one request at a time, and an abandoned request lives on in
  // the authenticator until its own presence timeout. Measured on a YubiKey 5:
  // for about 15 s after a request is abandoned, every new one fails in under
  // 0.1 s with a misleading FIDO_ERR_UNSUPPORTED_OPTION. So a failure that
  // arrives too fast to have been a real answer, soon after a request was
  // abandoned, is retried rather than reported.
  property double abandonedAtMs: 0
  property double startedAtMs: 0
  property int busyRetries: 0
  readonly property int busyRetryMs: 2000
  // Long enough to outlast the authenticator's presence timeout.
  readonly property int busyWindowMs: 40000
  // A real touch cannot arrive this fast, so a failure inside it is the device
  // refusing rather than the user being rejected.
  readonly property int busyFailureMs: 1500
  readonly property int busyRetryLimit: 15
  // An unanswered request ends on the key's own timeout, about 28.6 s.
  readonly property int noTouchMs: 20000

  // Emitted only after a touch and a successful read of the stored password.
  // The vault decides what to do with the password; here it is only the gate.
  signal unlocked(string password)

  // -------------------------------------------------------------------------
  // Readiness
  // -------------------------------------------------------------------------

  // The setting is usually already true when this is built, so onArmedChanged
  // never fires and nothing else would probe. Without this the option is not
  // offered until something else happens to refresh it, and the lock screen
  // leads with another method while the key sits plugged in.
  Component.onCompleted: if (armed) refresh()

  function refresh() {
    // A probe while the key holds our request would find it busy and report
    // it absent; the answer to that request is coming anyway.
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
    // An SSH request raises the auth surface before the panel is open; if the
    // key is ready, arm it the same way the panel's own open does.
    if (ready && vault && vault.status === "locked" && vault.sshAuthSurfaceActive) startUnlock()
  }

  // The credential to ask for: one the envelope has a wrap for, on a key that
  // is plugged in; otherwise, while the plaintext entry is still there, any
  // usable registered credential, whose touch will migrate it.
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
    // A request left running by a closed panel is still waiting on the same
    // key. Adopt it rather than asking the authenticator for a second request
    // it would refuse.
    if (assertProc.running) {
      scanning = true
      failure = ""
      if (message === "") message = "󰟵  Touch your FIDO2 key..."
      return
    }
    if (scanning) return
    authorized = false
    failure = ""
    scanning = true
    message = busyRetries > 0
      ? "󰟵  Your key is finishing an earlier request -- touch it to clear it, or wait a moment..."
      : "󰟵  Touch your FIDO2 key..."
    // Which device holds the credential can change between probes -- a key
    // replugged lands on another hidraw node -- so ask first. It is silent and
    // takes a fraction of a second.
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

  // Let go of the screen without letting go of the key.
  //
  // Stopping our side buys nothing: the authenticator keeps the request it was
  // already given until a touch or its own presence timeout. So the request is
  // left running instead: if the key is touched while no panel is up,
  // onAssertExited() sees no auth surface and drops the result (the vault
  // stays locked), and the key is free again. Re-opening the panel finds the
  // request still armed and simply keeps waiting.
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
    // Only an abandoned request leaves the authenticator holding one.
    if (assertProc.running) {
      abandonedAtMs = Date.now()
      assertProc.running = false
    }
    scanning = false
    authorized = false
  }

  // A failure too fast to be an answer, while the key is still holding the
  // request this panel abandoned a moment ago.
  function deviceStillBusy() {
    var now = Date.now()
    return busyRetries < busyRetryLimit
      && (now - startedAtMs) < busyFailureMs
      && (now - abandonedAtMs) < busyWindowMs
  }

  function retryAfterBusy() {
    busyRetries += 1
    failure = ""
    message = "󰟵  Your key is finishing an earlier request -- touch it to clear it, or wait a moment..."
    busyRetryTimer.restart()
  }

  function onAssertExited(exitCode) {
    if (vault && vault.finishScrubRun(assertProc)) return
    // Taken, then scrubbed: on success this collector holds the password.
    var out = String(assertStdout.text || "")
    if (vault) vault.clearProcessCollectorSoon(assertProc)
    var mode = assertMode
    assertMode = ""
    var accepting = scanning && vault && vault.sshAuthSurfaceActive && vault.status === "locked"
    scanning = false
    var codes = Model.fidoExitCodes()
    var migrated = exitCode === 0 && mode === "legacy"
    if (migrated) {
      // The touch that unlocked also moved the plaintext entry into the
      // envelope and deleted it. True whether or not anyone is still looking.
      legacyStored = false
      if (vault) vault.refreshEnvelope()
    }
    if (!accepting) { out = ""; return }

    if (exitCode === 0 || exitCode === codes.legacyUsed) {
      busyRetries = 0
      abandonedAtMs = 0
      authorized = false
      // The button under this says "Unlocking..." on its own.
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
  // Stored credential
  // -------------------------------------------------------------------------

  // The processes whose collector can hold the master password, so the vault's
  // lock-time buffer scrub reaches this one too.
  function secretProcesses() { return [assertProc] }

  function dropSecrets() { setupMaster = "" }

  // The plaintext entry, if an older version left one.
  function requestClear() {
    if (clearProc.running) {
      clearPending = true
      return
    }
    clearProc.running = true
  }

  // Take away every way in FIDO2 has: the envelope's wraps and any plaintext
  // entry. Used when the user turns the feature off. `notify` is false when
  // there is nothing to confirm.
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

  // State only, no keyring touch: logging out already swept the keyring.
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
      // Not `if (stored)`. That flag is false whenever the key or the packages
      // are missing, which says nothing about whether a way in is still in the
      // keyring -- and turning the feature off is precisely when it must not
      // be. The clear is unconditional for the same reason the vault's logout
      // sweep is.
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
    // Probe now rather than only when the setting is on: the form has to know
    // whether a key is registered before it can decide between offering
    // Omarchy's setup and asking for the master password.
    refresh()
    if (vault) vault.currentScreen = "fido"
  }

  // Omarchy owns the enrolment end to end (`omarchy setup security fido2`:
  // install, detect, register, wire the system's own authentication prompts,
  // test). This only opens it in the same floating terminal an install uses --
  // it needs an administrator prompt and a touch.
  function runOmarchySetup() {
    Quickshell.execDetached(Fido.fidoSetupCommand())
    if (vault) vault.flashNotification("FIDO2 setup opened -- this screen updates itself")
  }

  function abandonSetup() {
    // A wrap still being written is taken back out when it lands: its
    // completion finds the operation stale. See submitSetup().
    if (busy && vault) vault.invalidateEpochOperation("fidoAdd")
    setupActive = false
    busy = false
    setupMaster = ""
  }

  // The master password is a check against the stored password, and one touch
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
      // Locked, logged out or abandoned while the wrap was being written: a
      // way in for a setting that never turned on. Take it back out.
      if (vault.epochOperationIsStale("fidoAdd") || !setupActive) {
        setupActive = false
        if (ok) vault.removeQuickUnlockMethod({ kind: "remove", method: "fido", cred: target.cred })
        return
      }
      setupActive = false
      if (!ok) {
        var codes = Model.fidoExitCodes()
        if (why === "wrong-password") error = "That is not your master password."
        else if (code === codes.assert || code === codes.noSecret) error = "No touch received. Try again."
        else error = "Could not enable FIDO2 unlock. Is the OS keyring available?"
        setupActive = true
        return
      }
      // The plaintext entry, if an older version left one, is superseded.
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
    command: Model.keyringHasFidoPasswordCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: fido.onHasChecked(text)
    }
  }

  // One touch: the key's hmac-secret opens the envelope, and the password is
  // the only output. See Model.fidoUnlockCommand().
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
    command: Model.keyringClearFidoPasswordCommand()
    onExited: function(exitCode) {
      if (fido.clearPending) {
        fido.clearPending = false
        clearProc.running = true
      }
    }
  }

  // Re-arms once the authenticator has had a moment to finish what it was
  // holding. Gated on the same conditions as an ordinary arm, so a panel closed
  // in the meantime stops the retries rather than reviving them.
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
