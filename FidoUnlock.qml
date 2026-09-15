import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Services.Pam
import "FidoModel.js" as Fido
import "BitwardenModel.js" as Model

// Owns the "unlock with FIDO2 key" presence gate.
//
// A FIDO2 key proves presence, but it cannot produce the master password, and
// `bw unlock` accepts nothing else. So this keeps its own copy of the master
// password in the login keyring and uses a verified key touch as the gate on
// reading it back -- the same trade the fingerprint path makes, and the same
// one the Bitwarden desktop client makes for its own biometrics. The entry is
// its own (`account=fido_password`), so enabling, forgetting or failing FIDO2
// unlock never reaches into the fingerprint's state or vice versa.
//
// Almost all of FIDO2 lives here and in FidoModel.js; the vault keeps only the
// handful of lines that hand it a setting and take a password back. The PAM
// stack it runs is shipped in the plugin's own `pam/` directory and loaded
// through PamContext's configDirectory, so enabling the option needs no
// privileged change to /etc/pam.d.
Item {
  id: fido

  // No visual presence of its own; it exists to hold the PAM conversation, the
  // keyring processes and the state they act on.
  visible: false
  width: 0
  height: 0

  // The vault that instantiated this. The setting and the unlocked password
  // pass between them, and nothing else.
  required property var vault
  // The fidoUnlock setting, pushed down by the vault.
  property bool armed: false

  // Readiness: the tools are installed, Omarchy registered a credential, and a
  // key is plugged in right now.
  property bool available: false
  // Worth drawing at all -- any one of the three parts is present.
  property bool applicable: false
  // A master password is present in the keyring under account=fido_password.
  property bool stored: false
  property bool scanning: false
  property bool authorized: false     // a live PAM success may consume one lookup
  property string message: ""

  // Setup form.
  property bool setupActive: false
  property string setupMaster: ""
  property string error: ""
  property bool busy: false
  property bool clearPending: false

  readonly property bool ready: armed && available && stored

  // Emitted only after a verified touch and a successful keyring read. The
  // vault decides what to do with the password; here it is only the gate.
  signal unlocked(string password)

  // -------------------------------------------------------------------------
  // Readiness
  // -------------------------------------------------------------------------

  function refresh() {
    if (!probeProc.running) probeProc.running = true
  }

  function onProbe(raw) {
    var state = Fido.parseFidoProbe(raw)
    applicable = state.applicable
    available = state.ready
    if (available && armed) {
      if (!hasProc.running) hasProc.running = true
    } else {
      // `available` false says nothing about the keyring -- an unplugged key
      // or an uninstalled pam-u2f do not remove a stored password -- but there
      // is no way to read one to act on, so the flag falls back to "not
      // stored" until the device or the packages are back. The entry itself is
      // left alone; only Forget clears it.
      stored = false
    }
  }

  function onHasChecked(raw) {
    stored = String(raw || "").trim() === "yes"
    // An SSH request raises the auth surface before the panel is open; if the
    // key is ready, arm it the same way the panel's own open does.
    if (ready && vault && vault.status === "locked" && vault.sshAuthSurfaceActive) startUnlock()
  }

  // -------------------------------------------------------------------------
  // Unlock
  // -------------------------------------------------------------------------

  function startUnlock() {
    if (!ready || !vault || vault.status !== "locked" || vault.isUnlocking) return
    if (scanning || pam.active) return
    if (!vault.userName) {
      message = "Cannot determine current user for FIDO2 verification"
      return
    }
    authorized = false
    scanning = true
    message = "󰟵  Touch your FIDO2 key..."
    if (!pam.start()) {
      scanning = false
      message = "Could not start FIDO2 verification"
    }
  }

  function cancelUnlock() {
    scanning = false
    authorized = false
    if (pam.active) pam.abort()
  }

  function onResult(result) {
    var accepting = scanning && vault && vault.sshAuthSurfaceActive && vault.status === "locked"
    scanning = false
    if (!accepting) return

    if (result === PamResult.Success) {
      authorized = true
      message = "󰟵  Key verified, unlocking..."
      if (!lookupProc.running) {
        // Restore the command first. Locking the vault scrubs this process's
        // collector by running it once with an empty command, and that
        // replacement stays in place: without re-arming it the "lookup" would
        // print nothing, the keyring would never be read, and the vault would
        // sit on "Key verified, unlocking..." forever. The fingerprint path
        // re-arms its own lookup the same way, for the same reason.
        lookupProc.command = Model.keyringLookupFidoPasswordCommand()
        lookupProc.running = true
      }
    } else if (result === PamResult.MaxTries) {
      message = "Too many key attempts. Use your master password."
    } else {
      message = "Key not recognised. Touch it again or use your master password."
    }
  }

  // Only ever reached with a live PamResult.Success behind it.
  function onLookupDone() {
    if (!authorized || !vault || !vault.sshAuthSurfaceActive || vault.status !== "locked") {
      authorized = false
      if (vault) vault.clearProcessCollectorSoon(lookupProc)
      return
    }
    authorized = false
    // The keyring command removed secret-tool's trailing newline. Do not trim
    // here: spaces at either end can be part of the actual master password.
    var pw = String(lookupStdout.text || "")
    if (!pw) {
      stored = false
      message = "No stored master password. Unlock with your password once to enable this."
      return
    }
    unlocked(pw)
  }

  // -------------------------------------------------------------------------
  // Stored credential
  // -------------------------------------------------------------------------

  // The processes whose collector can hold the master password, so the vault's
  // lock-time buffer scrub reaches this one too. Only the lookup prints the
  // secret; the store never writes it to stdout.
  function secretProcesses() { return [lookupProc] }

  function dropSecrets() { setupMaster = "" }

  function requestClear() {
    if (clearProc.running) {
      clearPending = true
      return
    }
    clearProc.running = true
  }

  // Clear the stored password and say why, if there is a why. Used when the
  // user turns the feature off, and when the vault rejects the stored password.
  // `notify` is false for the rejection path: there is nothing to confirm --
  // the password was not forgotten by anyone, it was refused.
  function forget(reasonMessage, notify) {
    cancelUnlock()
    stored = false
    message = String(reasonMessage === undefined || reasonMessage === null ? "" : reasonMessage)
    requestClear()
    if (notify !== false && vault) vault.flashNotification("FIDO2 unlock forgotten")
  }

  // State only, no keyring touch: logging out already swept the keyring.
  function reset() {
    cancelUnlock()
    stored = false
    message = ""
    setupActive = false
    busy = false
    setupMaster = ""
  }

  onArmedChanged: {
    if (!armed) {
      cancelUnlock()
      message = ""
      // Not `if (stored)`. That flag is false whenever the key or the packages
      // are missing, which says nothing about whether the password is still in
      // the keyring -- and turning the feature off is precisely when it must
      // not be. The clear is unconditional for the same reason the vault's
      // logout sweep is.
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
  // install, detect, register, wire sudo and polkit, test). This only opens it
  // in the same floating terminal an install uses -- it needs sudo and a touch.
  function runOmarchySetup() {
    Quickshell.execDetached(Fido.fidoSetupCommand())
    if (vault) vault.flashNotification("FIDO2 setup opened -- this screen updates itself")
  }

  function abandonSetup() {
    var active = setupActive
    if (active && storeProc.running && vault) vault.invalidateEpochOperation("fidoStore")
    setupActive = false
    busy = false
    setupMaster = ""
  }

  function submitSetup() {
    if (busy || storeProc.running) return
    if (!setupMaster) {
      error = "Master password is required to enable FIDO2 unlock"
      return
    }
    error = ""
    busy = true
    setupActive = true
    if (vault) vault.beginEpochOperation("fidoStore")
    storeProc.running = true
  }

  function onStored(exitCode) {
    var stale = vault ? vault.epochOperationIsStale("fidoStore") : false
    setupMaster = ""
    if (stale) {
      // The vault locked or logged out mid-store; drop what was just written
      // rather than recreate a credential that was meant to be gone.
      setupActive = false
      busy = false
      stored = false
      requestClear()
      return
    }
    stored = (exitCode === 0)
    if (setupActive) {
      setupActive = false
      busy = false
      if (exitCode !== 0) {
        error = "Could not save the master password. Is the OS keyring available?"
        return
      }
      if (vault) {
        vault.writeSetting("fidoUnlock", true, "bool")
        vault.flashNotification("FIDO2 unlock enabled")
        vault.currentScreen = "settings"
      }
      return
    }
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

  Process {
    id: storeProc
    command: Model.keyringStoreFidoPasswordCommand()
    environment: fido.vault ? fido.vault.secretEnv(fido.setupMaster) : ({})
    onExited: function(exitCode) { fido.onStored(exitCode) }
  }

  Process {
    id: lookupProc
    command: Model.keyringLookupFidoPasswordCommand()
    stdout: StdioCollector {
      id: lookupStdout
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (fido.vault && fido.vault.finishScrubRun(lookupProc)) return
      if (exitCode === 0) {
        fido.onLookupDone()
      } else {
        fido.authorized = false
        fido.stored = false
        fido.message = "Stored master password unavailable. Use your password."
      }
    }
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

  PamContext {
    id: pam
    config: Fido.fidoPamConfigName()
    // Resolved against this file's URL by PamContext itself, so the stack
    // travels with the plugin instead of living under /etc/pam.d.
    configDirectory: Fido.fidoPamDirectory()
    user: fido.vault ? fido.vault.userName : ""

    onCompleted: function(result) { fido.onResult(result) }
    onError: function(error) {
      fido.scanning = false
      fido.authorized = false
      fido.message = "FIDO2 verification unavailable"
    }
  }
}
