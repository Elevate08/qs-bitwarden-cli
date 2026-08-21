import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Services.Pam
import qs.Commons
import qs.Ui
import "BitwardenModel.js" as Model

Panel {
  id: root
  moduleName: "qs-bitwarden-cli"
  ipcTarget: "qs-bitwarden-cli"
  manageIpc: false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // Configuration settings from shell.json
  readonly property int autoLockMinutes: Number(setting("autoLockMinutes", 15))
  readonly property int clearClipboardSec: Number(setting("clearClipboardSec", 30))
  readonly property bool rememberSession: Boolean(setting("rememberSession", true))
  readonly property int autoCopyTotpSec: Number(setting("autoCopyTotpSec", 3))
  readonly property bool closeOnCopy: Boolean(setting("closeOnCopy", true))
  readonly property bool suggestOnOpen: Boolean(setting("suggestOnOpen", true))
  readonly property bool fingerprintUnlock: Boolean(setting("fingerprintUnlock", false))
  readonly property bool pinUnlock: Boolean(setting("pinUnlock", false))

  // State
  // status: "checking" | "unauthenticated" | "locked" | "unlocked"
  property string status: "checking"
  property string userEmail: ""
  property string session: ""
  property string masterPassword: ""

  // Login form state
  property string loginMethod: "email" // "email" | "apikey"
  property string loginEmail: ""
  property string loginPassword: ""
  property string login2faCode: ""
  property string loginServerUrl: ""
  property string loginClientId: ""
  property string loginClientSecret: ""
  property bool show2faField: false
  property bool showServerField: false

  // Screens: "main" | "detail" | "edit" | "locked" | "login" | "settings" | "setup"
  property string currentScreen: "main"
  property string screenBeforeSettings: "main"

  // Dependency / setup state
  property var dependencies: ({ items: [], hasOmarchy: true })
  property bool depsChecked: false
  property bool setupDismissed: false
  property string settingsFlash: ""

  // Vault data
  property var items: []
  // `bw list items` costs seconds on a large vault, so a reopen reuses what is
  // already in memory until it goes stale. Any mutation reloads unconditionally.
  property double itemsLoadedAt: 0
  readonly property int itemsFreshMs: 60000
  property var filteredItems: []
  property var organizations: []
  property string selectedOrg: "all" // "all" | "personal" | orgId
  property string searchQuery: ""
  property string selectedCategory: "all"
  property int selectedIndex: 0

  // Selected item detail
  property var detailItem: null
  property string detailPassword: ""
  property bool passwordRevealed: false
  property string liveTotp: ""
  property int totpSecRemaining: 30

  // Follow-up TOTP sequential copy state (Enter -> Password -> Enter -> TOTP)
  property var totpFollowupItem: null
  property string totpFollowupCode: ""
  property bool totpFollowupActive: false

  // Add / Edit Form State
  property bool formIsEditing: false
  property string formItemId: ""
  property int formTypeCode: 1 // 1: Login, 2: Secure Note
  property string formName: ""
  property string formUsername: ""
  property string formPassword: ""
  property string formTotp: ""
  property string formUri: ""
  property string formNotes: ""
  property bool formFavorite: false
  property string formOrgId: ""
  property bool formPasswordRevealed: false
  property bool showDeleteConfirm: false

  // Status & indicators
  property bool isLoading: false
  property bool isUnlocking: false
  property bool isSyncing: false
  property string errorMessage: ""
  property string flashMessage: ""
  property bool cursorActive: false

  // Fingerprint unlock state.
  // PAM only proves presence, so a verified finger is used as the gate on
  // reading the master password back out of the login keyring.
  property bool fingerprintAvailable: false   // PAM stack + reader + enrolled finger
  property bool fingerprintStored: false      // master password present in keyring
  property bool fingerprintScanning: false
  property string fingerprintMessage: ""
  property string pendingUnlockPassword: ""   // held only until the unlock lands
  // Which credential source drove the in-flight unlock, so a stale stored
  // secret can be discarded rather than retried forever. "" | "fingerprint" | "pin"
  property string pendingUnlockFrom: ""

  // Generator state (session-scoped, mirroring the browser extension's options)
  property var genOpts: Model.generatorDefaults()
  property string genValue: ""
  property bool genBusy: false

  // PIN unlock state
  property bool pinConfigured: false        // ciphertext present in the keyring
  property string pinEntry: ""              // locked-screen input
  property int pinAttempts: 0
  readonly property int pinMaxAttempts: 5
  property string pinError: ""
  property string pinSetupPin: ""
  property string pinSetupConfirm: ""
  property string pinSetupMaster: ""
  property bool pinBusy: false
  readonly property bool pinReady: pinUnlock && pinConfigured
  readonly property string userName: Quickshell.env("USER") || Quickshell.env("LOGNAME") || ""
  readonly property bool fingerprintReady: fingerprintUnlock && fingerprintAvailable && fingerprintStored

  // Contextual suggestions state
  property var activeWindowData: null
  property var detectedContext: null
  property var suggestedItems: []
  property bool suggestionsDismissed: false
  property var associations: ({ version: 1, keys: {} })
  property var learnedIds: ({})
  property string pendingAssociationsJson: ""

  // Visual styles
  readonly property color fg: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accent: Color.accent
  readonly property color dim: Qt.darker(fg, 1.5)
  readonly property color barIconColor: {
    var base = bar ? bar.barForeground : Color.foreground
    if (status === "unlocked") return Color.accent
    if (status === "locked" || status === "checking") return base
    return bar ? bar.urgent : Color.urgent
  }
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  Component.onCompleted: {
    root.refreshStatus()
    root.refreshFingerprintAvailability()
    root.loadAssociations()
  }

  readonly property var categories: [
    { id: "all", label: "All", icon: "󰞀" },
    { id: "login", label: "Logins", icon: "󰌋" },
    { id: "secureNote", label: "Notes", icon: "󰈐" },
    { id: "card", label: "Cards", icon: "󰅝" },
    { id: "identity", label: "Identities", icon: "" },
    { id: "favorite", label: "★ Favorites", icon: "󰓎" }
  ]

  // -------------------------------------------------------------------------
  // Lifecycle & Open / Close
  // -------------------------------------------------------------------------

  function open() {
    errorMessage = ""
    flashMessage = ""
    passwordRevealed = false
    cursorActive = true
    showDeleteConfirm = false
    totpFollowupActive = false
    isUnlocking = false
    suggestionsDismissed = false
    fingerprintMessage = ""

    // controller.show() flips `opened`, which runs onPanelOpened via
    // onOpenedChanged. Only drive it directly when the panel was already open
    // and that signal will not fire -- otherwise every open did its startup
    // work twice, including two `bw status` calls at ~3s each.
    var wasOpen = opened
    root.controller.show()
    if (wasOpen) onPanelOpened()
  }

  function close() {
    errorMessage = ""
    passwordRevealed = false
    masterPassword = ""
    loginPassword = ""
    showDeleteConfirm = false
    totpFollowupActive = false
    isUnlocking = false
    pendingUnlockPassword = ""
    cancelFingerprintUnlock()
    root.controller.hide()
  }

  function toggle() {
    if (opened) close()
    else open()
  }

  function detectActiveWindowContext() {
    if (!suggestOnOpen) return
    activeWindowProc.command = ["sh", "-c", "hyprctl activewindow -j 2>/dev/null | grep -q '\"class\": \"[^\"]' && hyprctl activewindow -j || hyprctl clients -j 2>/dev/null"]
    activeWindowProc.running = true
  }

  function loadAssociations() {
    if (!associationsReadProc.running) associationsReadProc.running = true
  }

  function onAssociationsLoaded(raw) {
    associations = Model.parseAssociations(raw)
    if (activeWindowData) handleActiveWindowDetected(activeWindowData)
  }

  function saveAssociations(next) {
    associations = next
    pendingAssociationsJson = Model.serializeAssociations(next)
    associationsWriteProc.running = true
  }

  // Called whenever the user acts on an item while a window context is active.
  // Silent by design: teaching happens as a side effect of normal use.
  function learnFromPick(item) {
    if (!suggestOnOpen || !item || !item.id || !detectedContext) return
    if (Model.isAssociated(associations, detectedContext, item.id)) return
    saveAssociations(Model.recordAssociation(associations, detectedContext, item.id, new Date().toISOString()))
  }

  // Explicit pin/unpin from the detail view.
  function toggleAssociation(item) {
    if (!item || !item.id || !detectedContext) return
    if (Model.isAssociated(associations, detectedContext, item.id)) {
      saveAssociations(Model.forgetAssociation(associations, detectedContext, item.id))
      flashNotification("No longer suggested for " + detectedContext.displayName)
    } else {
      saveAssociations(Model.recordAssociation(associations, detectedContext, item.id, new Date().toISOString()))
      flashNotification("Always suggested for " + detectedContext.displayName)
    }
    if (activeWindowData) handleActiveWindowDetected(activeWindowData)
  }

  function handleActiveWindowDetected(data) {
    activeWindowData = data
    if (!suggestOnOpen) {
      suggestedItems = []
      detectedContext = null
      rebuildFilter()
      return
    }
    if (items.length === 0) {
      return
    }
    var res = Model.findContextualMatches(items, data, associations)
    detectedContext = res.context
    suggestedItems = res.matches
    learnedIds = res.learnedIds || ({})
    rebuildFilter()
  }

  function focusAppropriateField() {
    Qt.callLater(function() {
      if (status === "unlocked" && currentScreen === "main") {
        searchField.forceActiveFocus()
      } else if (status === "locked" || status === "checking") {
        if (pinReady) pinField.forceActiveFocus()
        else passField.forceActiveFocus()
      } else if (status === "unauthenticated") {
        emailField.forceActiveFocus()
      }
    })
  }

  onOpenedChanged: {
    if (opened) onPanelOpened()
    else cancelFingerprintUnlock()
  }

  function onPanelOpened() {
    focusAppropriateField()
    detectActiveWindowContext()
    refreshFingerprintAvailability()

    if (status === "unlocked") {
      currentScreen = "main"
      ensureItemsFresh()
    } else if (status === "locked") {
      startFingerprintUnlock()
    } else {
      refreshStatus()
    }
  }

  // -------------------------------------------------------------------------
  // Status & Keyring Handlers
  // -------------------------------------------------------------------------

  function refreshStatus() {
    if (status === "locked" && !session) return
    errorMessage = ""
    if (session) {
      statusProc.command = Model.statusCommand(session)
      statusProc.running = true
    } else if (rememberSession && status !== "locked") {
      keyringLookupProc.running = true
    } else {
      statusProc.command = Model.statusCommand("")
      statusProc.running = true
    }
  }

  function onKeyringLookupFinished(rawToken) {
    var token = String(rawToken || "").trim()
    if (token) {
      session = token
      statusProc.command = Model.statusCommand(session)
      statusProc.running = true
    } else {
      statusProc.command = Model.statusCommand("")
      statusProc.running = true
    }
  }

  function onKeyringLookupFailed() {
    statusProc.command = Model.statusCommand("")
    statusProc.running = true
  }

  function onStatusFinished(rawJson) {
    isLoading = false
    var st = Model.parseStatus(rawJson)
    if (!st) {
      status = "unauthenticated"
      currentScreen = "login"
      focusAppropriateField()
      return
    }

    userEmail = st.userEmail
    if (st.userEmail && !loginEmail) {
      loginEmail = st.userEmail
    }

    if (st.unlocked) {
      status = "unlocked"
      currentScreen = "main"
      ensureItemsFresh()
      resetAutoLockTimer()
      focusAppropriateField()
    } else if (st.locked) {
      status = "locked"
      currentScreen = "locked"
      items = []
      filteredItems = []
      focusAppropriateField()
      if (opened) startFingerprintUnlock()
    } else {
      status = "unauthenticated"
      currentScreen = "login"
      items = []
      filteredItems = []
      focusAppropriateField()
    }
  }

  // -------------------------------------------------------------------------
  // In-Plugin Login & Authentication
  // -------------------------------------------------------------------------

  function submitLogin() {
    errorMessage = ""
    if (loginMethod === "email") {
      var email = String(loginEmail || "").trim()
      var pass = String(loginPassword || "").trim()
      if (!email) {
        errorMessage = "Email address is required"
        return
      }
      if (!pass) {
        errorMessage = "Master password is required"
        return
      }

      isLoading = true
      loginProc.command = Model.emailLoginCommand(email, pass, login2faCode.trim(), loginServerUrl.trim())
      loginProc.running = true
    } else {
      var id = String(loginClientId || "").trim()
      var secret = String(loginClientSecret || "").trim()
      var pass2 = String(loginPassword || "").trim()

      if (!id) {
        errorMessage = "API Client ID is required"
        return
      }
      if (!secret) {
        errorMessage = "API Client Secret is required"
        return
      }
      if (!pass2) {
        errorMessage = "Master password is required to unlock vault"
        return
      }

      isLoading = true
      loginProc.command = Model.apiKeyLoginCommand(id, secret, pass2, loginServerUrl.trim())
      loginProc.running = true
    }
  }

  function onLoginOutput(stdoutText, stderrText, exitCode) {
    isLoading = false
    var out = String(stdoutText || "").trim()
    var err = String(stderrText || "").trim()

    var combined = (err + " " + out).toLowerCase()
    if (combined.indexOf("two-step") !== -1 || combined.indexOf("verification") !== -1 || combined.indexOf("twofactor") !== -1 || combined.indexOf("2fa") !== -1 || combined.indexOf("invalid_grant") !== -1 || combined.indexOf("code") !== -1) {
      show2faField = true
      errorMessage = "Two-step verification code required or incorrect. Please enter your 6-digit code below."
      Qt.callLater(function() { code2faField.forceActiveFocus() })
      return
    }

    if (exitCode === 0 && out.length > 10) {
      loginPassword = ""
      login2faCode = ""
      onUnlockSuccess(out)
      return
    }

    if (err) {
      errorMessage = err
    } else if (exitCode !== 0) {
      errorMessage = "Login failed. Please check your credentials."
    } else {
      unlockVaultWithPassword(loginPassword)
    }
  }

  function launchTerminalLogin() {
    close()
    Quickshell.execDetached(["bash", "-c", "omarchy launch terminal -e bash -c 'bw login; read -p \"Login complete. Press enter to close...\"' || alacritty -e bash -c 'bw login; read -p \"Login complete. Press enter to close...\"'"])
  }

  function logoutAccount() {
    lockVault()
    if (fingerprintStored) {
      keyringClearMasterProc.running = true
      fingerprintStored = false
    }
    pendingUnlockPassword = ""
    logoutProc.command = Model.logoutCommand()
    logoutProc.running = true
    status = "unauthenticated"
    currentScreen = "login"
    userEmail = ""
    flashNotification("Logged out")
  }

  // -------------------------------------------------------------------------
  // Fingerprint Unlock
  // -------------------------------------------------------------------------

  // Secrets go to secret-tool through the environment, never argv. See
  // keyringStoreScript() in BitwardenModel.js for why stdin is not usable.
  function associationsEnv() {
    var env = {}
    env[Model.associationsEnvVar()] = String(pendingAssociationsJson || "")
    return env
  }

  function pinEnv(pin, secret) {
    var env = {}
    env[Model.pinEnvVar()] = String(pin || "")
    if (secret) env[Model.keyringSecretEnvVar()] = String(secret)
    return env
  }

  function secretEnv(value) {
    var env = {}
    env[Model.keyringSecretEnvVar()] = String(value || "")
    return env
  }

  // -------------------------------------------------------------------------
  // Generator
  // -------------------------------------------------------------------------

  function openGenerator() {
    screenBeforeSettings = "main"
    currentScreen = "generator"
    if (!genValue) regenerate()
  }

  // Generation is delegated to `bw generate`, so the output comes from
  // Bitwarden's own generator rather than a local reimplementation of it.
  function regenerate() {
    genBusy = true
    generateProc.command = Model.generateCommand(genOpts)
    generateProc.running = true
  }

  function onGenerated(text, exitCode) {
    genBusy = false
    var v = String(text || "").trim()
    if (exitCode !== 0 || !v) {
      errorMessage = "Could not generate with these options"
      return
    }
    genValue = v
  }

  // Every control funnels through here, so a change always regenerates --
  // matching the extension's live behaviour -- and options stay normalised.
  function setGenOpt(key, value) {
    var next = {}
    for (var k in genOpts) next[k] = genOpts[k]
    next[key] = value
    genOpts = Model.normalizeGeneratorOptions(next)
    regenerate()
  }

  function copyGenerated() {
    if (!genValue) return
    copyToClipboard(genValue, genOpts.type === "passphrase" ? "Passphrase" : "Password")
  }

  // -------------------------------------------------------------------------
  // PIN Unlock
  // -------------------------------------------------------------------------

  function refreshPinConfigured() {
    if (!keyringHasPinProc.running) keyringHasPinProc.running = true
  }

  function onPinConfiguredChecked(raw) {
    pinConfigured = String(raw || "").trim() === "yes"
  }

  function beginPinSetup() {
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
    pinError = ""
    screenBeforeSettings = "main"
    currentScreen = "pin"
    Qt.callLater(function() { pinSetupPinField.forceActiveFocus() })
  }

  // Encrypting needs the master password, and the vault does not keep it in
  // memory once unlocked, so setting a PIN has to ask for it.
  function submitPinSetup() {
    var err = Model.validatePin(pinSetupPin, pinSetupConfirm)
    if (err) { pinError = err; return }
    if (!pinSetupMaster) { pinError = "Master password is required to encrypt the PIN"; return }

    pinError = ""
    pinBusy = true
    pinStoreProc.running = true
  }

  function onPinStored(exitCode) {
    pinBusy = false
    if (exitCode !== 0) {
      pinError = "Could not save the PIN. Is the OS keyring available?"
      return
    }
    pinConfigured = true
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
    pinAttempts = 0
    writeSetting("pinUnlock", true, "bool")
    flashNotification("PIN unlock enabled")
    currentScreen = "settings"
  }

  function submitPinUnlock() {
    if (!pinReady || isUnlocking || pinBusy) return
    if (String(pinEntry || "").length < Model.pinMinLength()) {
      pinError = "PIN must be at least " + Model.pinMinLength() + " digits"
      return
    }
    pinError = ""
    pinBusy = true
    pinUnlockProc.running = true
  }

  function onPinUnlockResult(exitCode, password) {
    pinBusy = false
    var pw = String(password || "").trim()

    if (exitCode !== 0 || !pw) {
      pinAttempts += 1
      pinEntry = ""
      if (pinAttempts >= pinMaxAttempts) {
        // Refuse to keep serving guesses at the UI. The ciphertext goes too,
        // so re-enabling requires the master password again.
        clearPin()
        pinError = "Too many incorrect PINs. PIN unlock has been removed -- use your master password."
      } else {
        pinError = "Incorrect PIN (" + pinAttempts + " of " + pinMaxAttempts + ")"
      }
      return
    }

    pinAttempts = 0
    pendingUnlockFrom = "pin"
    unlockVaultWithPassword(pw)
  }

  function clearPin() {
    keyringClearPinProc.running = true
    pinConfigured = false
    pinEntry = ""
    pinAttempts = 0
    if (pinUnlock) writeSetting("pinUnlock", false, "bool")
  }

  function disablePinUnlock() {
    clearPin()
    pinError = ""
    flashNotification("PIN unlock removed")
  }

  onPinUnlockChanged: {
    if (pinUnlock) refreshPinConfigured()
    else if (pinConfigured) clearPin()
  }

  // -------------------------------------------------------------------------
  // Setup Wizard & Settings
  // -------------------------------------------------------------------------

  function checkDependencies() {
    if (!depsCheckProc.running) depsCheckProc.running = true
  }

  function onDependenciesChecked(raw) {
    dependencies = Model.parseDependencies(raw)
    depsChecked = true
    if (pinUnlock) refreshPinConfigured()

    // Fingerprint availability comes from the same probe, so keep them in step.
    for (var i = 0; i < dependencies.items.length; i++) {
      if (dependencies.items[i].key === "fprintd") fingerprintAvailable = dependencies.items[i].ready
    }
    if (fingerprintAvailable && fingerprintUnlock) {
      if (!keyringHasMasterProc.running) keyringHasMasterProc.running = true
    } else {
      fingerprintStored = false
    }

    // A missing required tool is not something to discover mid-task.
    if (!setupDismissed && Model.missingRequired(dependencies).length > 0) {
      currentScreen = "setup"
    }
  }

  readonly property var missingRequired: Model.missingRequired(dependencies)

  function installMissing() {
    var pkgs = []
    for (var i = 0; i < dependencies.items.length; i++) {
      if (!dependencies.items[i].installed) pkgs.push(dependencies.items[i].pkg)
    }
    var cmd = Model.installPackagesCommand(pkgs)
    if (!cmd) return
    Quickshell.execDetached(cmd)
    flashNotification("Installing in a terminal, then re-check")
  }

  function installOne(dep) {
    if (!dep) return
    var cmd = Model.installPackagesCommand([dep.pkg])
    if (!cmd) return
    Quickshell.execDetached(cmd)
    flashNotification("Installing " + dep.pkg + " in a terminal")
  }

  function runFingerprintSetup() {
    Quickshell.execDetached(Model.fingerprintSetupCommand())
    flashNotification("Fingerprint setup opened in a terminal")
  }

  function openSettings() {
    if (currentScreen !== "settings") screenBeforeSettings = currentScreen
    settingsFlash = ""
    checkDependencies()
    currentScreen = "settings"
  }

  function closeSettings() {
    currentScreen = (screenBeforeSettings === "settings" ? "main" : screenBeforeSettings)
  }

  // Persisted via `omarchy bar set`, which owns shell.json. The shell reloads
  // on write, so setting() reflects the new value without us caching it.
  function writeSetting(key, value, type) {
    settingWriteProc.command = Model.settingWriteCommand(key, value, type)
    settingWriteProc.running = true
    settingsFlash = "Saved"
    settingsFlashTimer.restart()
  }

  // Read back through the same properties the plugin actually runs on, so the
  // settings screen can never show a different value than the one in effect.
  // (setting() alone would miss the manifest defaults for unset keys.)
  function settingValue(entry) {
    if (!entry) return 0
    switch (entry.key) {
      case "autoLockMinutes": return autoLockMinutes
      case "clearClipboardSec": return clearClipboardSec
      case "autoCopyTotpSec": return autoCopyTotpSec
      case "closeOnCopy": return closeOnCopy
      case "suggestOnOpen": return suggestOnOpen
      case "rememberSession": return rememberSession
      case "fingerprintUnlock": return fingerprintUnlock
      // The toggle reflects a PIN actually being set, not just the flag.
      case "pinUnlock": return pinUnlock && pinConfigured
    }
    return entry.type === "bool" ? Boolean(setting(entry.key, false)) : Number(setting(entry.key, 0))
  }

  function refreshFingerprintAvailability() {
    checkDependencies()
  }

  function onFingerprintStoredChecked(raw) {
    fingerprintStored = String(raw || "").trim() === "yes"
    if (opened && status === "locked") startFingerprintUnlock()
  }

  function startFingerprintUnlock() {
    if (!fingerprintReady || status !== "locked" || isUnlocking) return
    if (fingerprintScanning || fingerprintPam.active) return
    if (!userName) {
      fingerprintMessage = "Cannot determine current user for fingerprint verification"
      return
    }

    errorMessage = ""
    fingerprintScanning = true
    fingerprintMessage = "󰈷  Touch the fingerprint reader..."
    if (!fingerprintPam.start()) {
      fingerprintScanning = false
      fingerprintMessage = "Could not start fingerprint verification"
    }
  }

  function cancelFingerprintUnlock() {
    fingerprintScanning = false
    if (fingerprintPam.active) fingerprintPam.abort()
  }

  function onFingerprintResult(result) {
    fingerprintScanning = false
    if (status !== "locked") return

    if (result === PamResult.Success) {
      fingerprintMessage = "󰈷  Fingerprint verified, unlocking..."
      if (!keyringLookupMasterProc.running) keyringLookupMasterProc.running = true
    } else if (result === PamResult.MaxTries) {
      fingerprintMessage = "Too many fingerprint attempts. Use your master password."
    } else {
      fingerprintMessage = "Fingerprint not recognised. Try again or use your master password."
    }
  }

  // Only ever called after PamResult.Success.
  function onFingerprintPasswordRetrieved(raw) {
    var pw = String(raw || "").trim()
    if (!pw) {
      fingerprintStored = false
      fingerprintMessage = "No stored master password. Unlock with your password once to enable this."
      return
    }
    pendingUnlockFrom = "fingerprint"
    unlockVaultWithPassword(pw)
  }

  function forgetFingerprintUnlock() {
    keyringClearMasterProc.running = true
    fingerprintStored = false
    cancelFingerprintUnlock()
    fingerprintMessage = ""
    flashNotification("Fingerprint unlock forgotten")
  }

  onFingerprintUnlockChanged: {
    if (!fingerprintUnlock) {
      cancelFingerprintUnlock()
      fingerprintMessage = ""
      if (fingerprintStored) forgetFingerprintUnlock()
    } else {
      refreshFingerprintAvailability()
    }
  }

  // -------------------------------------------------------------------------
  // Vault Unlock & Lock
  // -------------------------------------------------------------------------

  function unlockVault() {
    pendingUnlockFrom = ""
    unlockVaultWithPassword(masterPassword)
  }

  function unlockVaultWithPassword(pass) {
    var p = String(pass || "").trim()
    if (!p) {
      errorMessage = "Master password required"
      return
    }
    cancelFingerprintUnlock()
    errorMessage = ""
    isUnlocking = true
    // Kept only until the unlock result is known; cleared on both paths below.
    pendingUnlockPassword = p
    unlockProc.command = Model.unlockCommand(p)
    unlockProc.running = true
  }

  function onUnlockOutput(stdoutText, stderrText, exitCode) {
    isUnlocking = false
    var out = String(stdoutText || "").trim()
    var err = String(stderrText || "").trim()

    if (exitCode === 0 && out) {
      onUnlockSuccess(out)
    } else {
      pendingUnlockPassword = ""
      // A stored secret the vault no longer accepts is useless: drop it rather
      // than fail on every open, and say which one went stale.
      if (pendingUnlockFrom === "fingerprint") {
        pendingUnlockFrom = ""
        keyringClearMasterProc.running = true
        fingerprintStored = false
        fingerprintMessage = "Stored password no longer valid. Unlock with your master password to re-enable fingerprint unlock."
        errorMessage = ""
        focusAppropriateField()
        return
      }
      if (pendingUnlockFrom === "pin") {
        pendingUnlockFrom = ""
        clearPin()
        pinError = "Your master password changed, so the PIN no longer works. Unlock with your password and set a new PIN."
        errorMessage = ""
        focusAppropriateField()
        return
      }
      if (err.indexOf("not logged in") !== -1) {
        status = "unauthenticated"
        currentScreen = "login"
        errorMessage = "You are not logged in. Please log in below."
      } else {
        errorMessage = err || "Unlock failed: invalid master password"
      }
    }
  }

  function onUnlockSuccess(rawSession) {
    var s = Model.extractSessionToken(rawSession)
    masterPassword = ""
    loginPassword = ""
    isUnlocking = false
    if (!s) {
      errorMessage = "Unlock did not return a session key"
      return
    }

    session = s
    status = "unlocked"
    currentScreen = "main"
    flashNotification("Vault unlocked successfully!")

    if (rememberSession) {
      keyringStoreProc.running = true
    }

    // Opting in stores the master password so a finger can stand in for it later.
    if (fingerprintUnlock && fingerprintAvailable && pendingUnlockPassword && pendingUnlockFrom === "") {
      keyringStoreMasterProc.running = true
    } else {
      pendingUnlockPassword = ""
    }
    pendingUnlockFrom = ""
    pinEntry = ""
    pinAttempts = 0
    pinError = ""
    fingerprintMessage = ""

    loadItems()
    loadOrganizations()
    resetAutoLockTimer()
    focusAppropriateField()
  }

  function lockVault() {
    if (session) {
      lockProc.command = Model.lockCommand(session)
      lockProc.running = true
    }
    if (rememberSession) {
      keyringClearProc.running = true
    }

    session = ""
    masterPassword = ""
    itemsLoadedAt = 0
    status = "locked"
    currentScreen = "locked"
    items = []
    filteredItems = []
    organizations = []
    detailItem = null
    detailPassword = ""
    liveTotp = ""
    totpFollowupActive = false
    isUnlocking = false
    pendingUnlockPassword = ""
    fingerprintMessage = ""
    flashNotification("Vault locked")
    focusAppropriateField()
    if (opened) startFingerprintUnlock()
  }

  // -------------------------------------------------------------------------
  // Vault Data Operations
  // -------------------------------------------------------------------------

  // Open-time load: skip the CLI entirely when the cached vault is still fresh.
  function ensureItemsFresh() {
    if (items.length > 0 && (Date.now() - itemsLoadedAt) < itemsFreshMs) {
      if (activeWindowData) handleActiveWindowDetected(activeWindowData)
      else rebuildFilter()
      return
    }
    loadItems()
    loadOrganizations()
  }

  function loadItems() {
    if (!session) return
    isLoading = true
    listProc.command = Model.listCommand(session)
    listProc.running = true
  }

  function onListFinished(rawJson) {
    isLoading = false
    items = Model.parseItems(rawJson)
    itemsLoadedAt = Date.now()
    if (activeWindowData) {
      handleActiveWindowDetected(activeWindowData)
    } else {
      rebuildFilter()
    }
  }

  function loadOrganizations() {
    if (!session) return
    listOrgsProc.command = Model.listOrganizationsCommand(session)
    listOrgsProc.running = true
  }

  function onListOrgsFinished(rawJson) {
    organizations = Model.parseOrganizations(rawJson)
  }

  function syncVault() {
    if (!session) return
    isSyncing = true
    syncProc.command = Model.syncCommand(session)
    syncProc.running = true
  }

  function onSyncFinished(exitCode) {
    isSyncing = false
    if (exitCode === 0) {
      flashNotification("Vault synced with Bitwarden")
      loadItems()
      loadOrganizations()
    } else {
      errorMessage = "Sync failed"
    }
  }

  function openDetail(item) {
    if (!item || !item.id) return
    learnFromPick(item)
    isLoading = true
    errorMessage = ""
    passwordRevealed = false
    showDeleteConfirm = false
    detailItem = null
    detailPassword = ""
    liveTotp = ""
    currentScreen = "detail"

    getItemProc.command = Model.getItemCommand(item.id, session)
    getItemProc.running = true

    if (item.hasTotp) {
      fetchTotp(item.id)
    }
  }

  function onDetailFinished(rawJson) {
    isLoading = false
    var parsed = Model.parseItemDetail(rawJson)
    if (parsed) {
      detailItem = parsed
      detailPassword = parsed.password
    } else {
      errorMessage = "Could not load item details"
    }
  }

  function fetchTotp(itemId) {
    if (!session || !itemId) return
    getTotpProc.command = Model.getTotpCommand(itemId, session)
    getTotpProc.running = true
  }

  function onTotpFinished(code) {
    var c = String(code || "").trim()
    liveTotp = c
    if (totpFollowupActive && totpFollowupItem) {
      totpFollowupCode = c
    }
  }

  // -------------------------------------------------------------------------
  // CRUD Operations (Add, Edit, Delete)
  // -------------------------------------------------------------------------

  function startAddNewItem() {
    formIsEditing = false
    formItemId = ""
    formTypeCode = 1
    formName = ""
    formUsername = ""
    formPassword = ""
    formTotp = ""
    formUri = ""
    formNotes = ""
    formFavorite = false
    formOrgId = selectedOrg !== "all" ? selectedOrg : ""
    formPasswordRevealed = false
    errorMessage = ""
    currentScreen = "edit"
  }

  function startEditItem(item) {
    if (!item) return
    formIsEditing = true
    formItemId = item.id
    formTypeCode = item.typeCode || 1
    formName = item.name || ""
    formUsername = item.username || ""
    formPassword = detailPassword || (item.rawObject && item.rawObject.login ? item.rawObject.login.password : "") || ""
    formTotp = item.totpKey || (item.rawObject && item.rawObject.login ? item.rawObject.login.totp : "") || ""
    formUri = item.uris && item.uris.length > 0 ? item.uris[0] : ""
    formNotes = item.notes || ""
    formFavorite = Boolean(item.favorite)
    formOrgId = item.organizationId || ""
    formPasswordRevealed = false
    errorMessage = ""
    currentScreen = "edit"
  }

  function generateAndSetPassword() {
    var generated = Model.generatePassword(20, true, true, true, true)
    formPassword = generated
    formPasswordRevealed = true
    flashNotification("Generated strong password!")
  }

  function saveItemForm() {
    var name = String(formName || "").trim()
    if (!name) {
      errorMessage = "Item title is required"
      return
    }

    errorMessage = ""
    isLoading = true

    if (formIsEditing) {
      var editPayload = Model.buildEditPayload(detailItem, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId)
      editItemProc.command = Model.editItemCommand(formItemId, editPayload, session)
      editItemProc.running = true
    } else {
      var createPayload = Model.buildCreatePayload(formTypeCode, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId)
      createItemProc.command = Model.createItemCommand(createPayload, session)
      createItemProc.running = true
    }
  }

  function onSaveItemFinished(exitCode, stdoutText, stderrText) {
    isLoading = false
    if (exitCode === 0) {
      flashNotification(formIsEditing ? "Item updated successfully!" : "Item created successfully!")
      currentScreen = "main"
      loadItems()
    } else {
      errorMessage = stderrText || "Failed to save item"
    }
  }

  function deleteCurrentItem() {
    if (!detailItem || !detailItem.id) return
    isLoading = true
    deleteItemProc.command = Model.deleteItemCommand(detailItem.id, session)
    deleteItemProc.running = true
  }

  function onDeleteItemFinished(exitCode, stdoutText, stderrText) {
    isLoading = false
    showDeleteConfirm = false
    if (exitCode === 0) {
      flashNotification("Item deleted")
      currentScreen = "main"
      loadItems()
    } else {
      errorMessage = stderrText || "Failed to delete item"
    }
  }

  // -------------------------------------------------------------------------
  // Filtering & Selection
  // -------------------------------------------------------------------------

  function rebuildFilter() {
    var baseList = Model.filterItems(items, searchQuery, selectedCategory, selectedOrg)
    if (searchQuery.trim() === "" && selectedCategory === "all" && selectedOrg === "all" && !suggestionsDismissed && suggestedItems.length > 0) {
      var suggestedIds = {}
      var topMatches = []
      for (var s = 0; s < suggestedItems.length; s++) {
        var sItem = Object.assign({}, suggestedItems[s], { isSuggested: true })
        topMatches.push(sItem)
        suggestedIds[sItem.id] = true
      }
      var otherItems = []
      for (var o = 0; o < baseList.length; o++) {
        if (!suggestedIds[baseList[o].id]) {
          otherItems.push(baseList[o])
        }
      }
      filteredItems = topMatches.concat(otherItems)
    } else {
      filteredItems = baseList
    }

    if (selectedIndex >= filteredItems.length) {
      selectedIndex = Math.max(0, filteredItems.length - 1)
    }
    if (selectedIndex < 0 && filteredItems.length > 0) {
      selectedIndex = 0
    }
  }

  function selectCategory(catId) {
    selectedCategory = catId
    selectedIndex = 0
    rebuildFilter()
  }

  function selectOrganization(orgId) {
    selectedOrg = orgId
    selectedIndex = 0
    rebuildFilter()
  }

  function cycleCategory(delta) {
    var currentIndex = 0
    for (var i = 0; i < categories.length; i++) {
      if (categories[i].id === selectedCategory) {
        currentIndex = i
        break
      }
    }
    var nextIndex = (currentIndex + delta + categories.length) % categories.length
    selectCategory(categories[nextIndex].id)
  }

  function moveCursor(delta) {
    if (filteredItems.length === 0) return
    selectedIndex = Math.max(0, Math.min(filteredItems.length - 1, selectedIndex + delta))
    if (itemsListView) {
      itemsListView.positionViewAtIndex(selectedIndex, ListView.Contain)
    }
  }

  function getSelectedItem() {
    if (filteredItems.length === 0 || selectedIndex < 0 || selectedIndex >= filteredItems.length) {
      return null
    }
    return filteredItems[selectedIndex]
  }

  // -------------------------------------------------------------------------
  // Clipboard Actions & Sequential Password -> TOTP Follow-Up
  // -------------------------------------------------------------------------

  function copyToClipboard(text, label) {
    if (!text) return
    resetAutoLockTimer()
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(text) + " | wl-copy --sensitive"])
    flashNotification(label + " copied!")

    if (clearClipboardSec > 0) {
      clipboardClearTimer.restart()
    }
  }

  // Smart sequential Enter handler: Copies Password, then arms and auto-copies TOTP
  function handleSmartEnter(item) {
    if (!item) return

    // If already in active TOTP follow-up mode for this item, copy TOTP now!
    if (totpFollowupActive && totpFollowupItem && totpFollowupItem.id === item.id) {
      copyTotpCode(item)
      totpFollowupActive = false
      if (closeOnCopy) close()
      return
    }

    // Step 1: Copy password
    copyPassword(item)

    // Step 2: If item has TOTP, arm follow-up and schedule auto-copy!
    if (item.hasTotp) {
      totpFollowupItem = item
      totpFollowupActive = true
      fetchTotp(item.id)
      totpFollowupTimer.restart()

      if (autoCopyTotpSec > 0) {
        autoTotpTimer.interval = autoCopyTotpSec * 1000
        autoTotpTimer.restart()
      }
    }

    if (closeOnCopy) {
      close()
    }
  }

  function copyPassword(item) {
    if (!item) return
    learnFromPick(item)
    var pass = (detailItem && detailItem.id === item.id && detailPassword) ? detailPassword : (item.password || "")
    if (pass) {
      copyToClipboard(pass, "Password")
      return
    }
    if (session) {
      Quickshell.execDetached(["bash", "-c", "bw get password " + Util.shellQuote(item.id) + " --session " + Util.shellQuote(session) + " --raw | wl-copy --sensitive"])
      flashNotification("Password copied!")
      if (clearClipboardSec > 0) clipboardClearTimer.restart()
    } else {
      errorMessage = "Vault is locked or session expired. Please unlock your vault."
    }
  }

  function copyUsername(item) {
    if (!item || !item.username) return
    copyToClipboard(item.username, "Username")
  }

  function copyTotpCode(item) {
    if (!item) return
    if (liveTotp && item.id === (detailItem ? detailItem.id : "")) {
      copyToClipboard(liveTotp, "TOTP code")
      return
    }
    Quickshell.execDetached(["bash", "-c", "bw get totp " + Util.shellQuote(item.id) + " --session " + Util.shellQuote(session) + " --raw | wl-copy --sensitive"])
    flashNotification("TOTP code copied!")
    if (clearClipboardSec > 0) clipboardClearTimer.restart()
  }

  function openUrl(url) {
    if (!url) return
    var target = url
    if (!target.match(/^[a-zA-Z]+:\/\//)) {
      target = "https://" + target
    }
    Quickshell.execDetached(["xdg-open", target])
    flashNotification("Opening " + target)
  }

  function flashNotification(msg) {
    flashMessage = msg
    flashTimer.restart()
  }

  function resetAutoLockTimer() {
    if (autoLockMinutes > 0) {
      autoLockTimer.interval = autoLockMinutes * 60 * 1000
      autoLockTimer.restart()
    }
  }

  // -------------------------------------------------------------------------
  // Timers
  // -------------------------------------------------------------------------

  Timer {
    id: searchDebounceTimer
    interval: 50
    repeat: false
    onTriggered: root.rebuildFilter()
  }

  Timer {
    id: flashTimer
    interval: 2500
    onTriggered: root.flashMessage = ""
  }

  Timer {
    id: totpFollowupTimer
    interval: 8000
    onTriggered: root.totpFollowupActive = false
  }

  Timer {
    id: autoTotpTimer
    repeat: false
    onTriggered: {
      if (root.totpFollowupItem && root.totpFollowupItem.hasTotp) {
        root.copyTotpCode(root.totpFollowupItem)
        var codeStr = root.totpFollowupCode || root.liveTotp
        var msg = codeStr ? ("2FA Code: " + codeStr + " (Ready to paste!)") : "2FA verification code ready to paste!"
        Quickshell.execDetached(["omarchy-notification-send", "-g", "󰥔", "--app-name", "Bitwarden", "-t", "4000", "TOTP Code Copied", msg])
        root.totpFollowupActive = false
      }
    }
  }

  Timer {
    id: clipboardClearTimer
    interval: root.clearClipboardSec * 1000
    onTriggered: {
      Quickshell.execDetached(["bash", "-c", "wl-copy --clear"])
    }
  }

  Timer {
    id: autoLockTimer
    interval: root.autoLockMinutes * 60 * 1000
    running: root.status === "unlocked" && root.autoLockMinutes > 0
    onTriggered: {
      if (root.status === "unlocked") {
        root.lockVault()
      }
    }
  }

  Timer {
    id: totpCountdownTimer
    interval: 1000
    running: root.opened && (root.currentScreen === "detail" || root.totpFollowupActive)
    repeat: true
    onTriggered: {
      var sec = 30 - (Math.floor(Date.now() / 1000) % 30)
      root.totpSecRemaining = sec
      if (sec === 30) {
        if (root.currentScreen === "detail" && root.detailItem && root.detailItem.hasTotp) {
          root.fetchTotp(root.detailItem.id)
        } else if (root.totpFollowupActive && root.totpFollowupItem) {
          root.fetchTotp(root.totpFollowupItem.id)
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Processes (Quickshell.Io)
  // -------------------------------------------------------------------------

  Process {
    id: statusProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onStatusFinished(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
    }
  }

  Process {
    id: keyringLookupProc
    command: Model.keyringLookupCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onKeyringLookupFinished(text)
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        root.onKeyringLookupFailed()
      }
    }
  }

  Process {
    id: keyringStoreProc
    command: Model.keyringStoreCommand()
    environment: root.secretEnv(root.session)
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        console.warn("qs-bitwarden-cli: could not store session in keyring (exit " + exitCode + ")")
      }
    }
  }

  Process {
    id: keyringClearProc
    command: Model.keyringClearCommand()
  }

  // ---- Fingerprint unlock ----

  Process {
    id: generateProc
    stdout: StdioCollector { id: generateStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onGenerated(generateStdout.text, exitCode) }
  }

  // ---- PIN unlock ----
  //
  // PIN and master password are handed over in the environment; encrypt-and-store
  // and lookup-and-decrypt each run inside one process, so the plaintext never
  // travels back through QML on its way to or from the keyring.

  Process {
    id: pinStoreProc
    command: Model.pinStoreCommand()
    environment: root.pinEnv(root.pinSetupPin, root.pinSetupMaster)
    onExited: function(exitCode) { root.onPinStored(exitCode) }
  }

  Process {
    id: pinUnlockProc
    command: Model.pinUnlockCommand()
    environment: root.pinEnv(root.pinEntry, "")
    stdout: StdioCollector { id: pinUnlockStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onPinUnlockResult(exitCode, pinUnlockStdout.text) }
  }

  Process {
    id: keyringHasPinProc
    command: Model.keyringHasPinCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onPinConfiguredChecked(text)
    }
  }

  Process {
    id: keyringClearPinProc
    command: Model.keyringClearPinCommand()
  }

  Process {
    id: depsCheckProc
    command: Model.dependencyCheckCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onDependenciesChecked(text)
    }
  }

  Process {
    id: settingWriteProc
    stderr: StdioCollector {
      id: settingWriteStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        root.settingsFlash = ""
        root.errorMessage = (settingWriteStderr.text || "").trim() || "Could not save setting to shell.json"
      }
    }
  }

  Timer {
    id: settingsFlashTimer
    interval: 1600
    onTriggered: root.settingsFlash = ""
  }

  Process {
    id: keyringHasMasterProc
    command: Model.keyringHasMasterPasswordCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onFingerprintStoredChecked(text)
    }
  }

  Process {
    id: keyringStoreMasterProc
    command: Model.keyringStoreMasterPasswordCommand()
    environment: root.secretEnv(root.pendingUnlockPassword)
    onExited: function(exitCode) {
      root.pendingUnlockPassword = ""
      root.fingerprintStored = (exitCode === 0)
      if (exitCode === 0) {
        root.flashNotification("Fingerprint unlock enabled")
      } else {
        root.errorMessage = "Could not save master password to the OS keyring, so fingerprint unlock is unavailable."
      }
    }
  }

  Process {
    id: keyringLookupMasterProc
    command: Model.keyringLookupMasterPasswordCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onFingerprintPasswordRetrieved(text)
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) {
        root.fingerprintStored = false
        root.fingerprintMessage = "Stored master password unavailable. Use your password."
      }
    }
  }

  Process {
    id: keyringClearMasterProc
    command: Model.keyringClearMasterPasswordCommand()
  }

  // ---- Learned associations ----

  Process {
    id: associationsReadProc
    command: Model.associationsReadCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onAssociationsLoaded(text)
    }
  }

  Process {
    id: associationsWriteProc
    command: Model.associationsWriteCommand()
    environment: root.associationsEnv()
    onExited: function(exitCode) {
      root.pendingAssociationsJson = ""
      if (exitCode !== 0) {
        console.warn("qs-bitwarden-cli: could not save learned suggestions (exit " + exitCode + ")")
      }
    }
  }

  PamContext {
    id: fingerprintPam
    config: "omarchy-lock-fingerprint"
    user: root.userName

    onCompleted: function(result) {
      root.onFingerprintResult(result)
    }

    onError: function(error) {
      root.fingerprintScanning = false
      root.fingerprintMessage = "Fingerprint verification unavailable"
    }
  }

  Process {
    id: loginProc
    stdout: StdioCollector {
      id: loginStdout
      waitForEnd: true
    }
    stderr: StdioCollector {
      id: loginStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      root.onLoginOutput(loginStdout.text, loginStderr.text, exitCode)
    }
  }

  Process {
    id: unlockProc
    stdout: StdioCollector {
      id: unlockStdout
      waitForEnd: true
    }
    stderr: StdioCollector {
      id: unlockStderr
      waitForEnd: true
    }
    onExited: function(exitCode) {
      root.onUnlockOutput(unlockStdout.text, unlockStderr.text, exitCode)
    }
  }

  Process {
    id: logoutProc
  }

  Process {
    id: listProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onListFinished(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (text && text.trim()) {
          root.errorMessage = text.trim()
          root.isLoading = false
        }
      }
    }
  }

  Process {
    id: listOrgsProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onListOrgsFinished(text)
    }
  }

  Process {
    id: getItemProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onDetailFinished(text)
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (text && text.trim()) root.errorMessage = text.trim()
      }
    }
  }

  Process {
    id: getTotpProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onTotpFinished(text)
    }
  }

  Process {
    id: activeWindowProc
    command: ["sh", "-c", "hyprctl activewindow -j 2>/dev/null | grep -q '\"class\": \"[^\"]' && hyprctl activewindow -j || hyprctl clients -j 2>/dev/null"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (text && text.trim()) {
          try {
            var data = JSON.parse(text)
            root.handleActiveWindowDetected(data)
          } catch (e) {
            root.suggestedItems = []
            root.detectedContext = null
          }
        }
      }
    }
  }

  Process {
    id: createItemProc
    stdout: StdioCollector { id: createItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: createItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.onSaveItemFinished(exitCode, createItemStdout.text, createItemStderr.text)
    }
  }

  Process {
    id: editItemProc
    stdout: StdioCollector { id: editItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: editItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.onSaveItemFinished(exitCode, editItemStdout.text, editItemStderr.text)
    }
  }

  Process {
    id: deleteItemProc
    stdout: StdioCollector { id: deleteItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: deleteItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.onDeleteItemFinished(exitCode, deleteItemStdout.text, deleteItemStderr.text)
    }
  }

  Process {
    id: syncProc
    onExited: function(exitCode) {
      root.onSyncFinished(exitCode)
    }
  }

  Process {
    id: lockProc
  }

  // -------------------------------------------------------------------------
  // IPC Handler
  // -------------------------------------------------------------------------

  IpcHandler {
    target: "qs-bitwarden-cli"
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function lock(): string { root.lockVault(); return "locked" }
    function settings(): string { root.open(); root.openSettings(); return "settings" }
    function setup(): string {
      root.open()
      root.setupDismissed = false
      root.checkDependencies()
      root.currentScreen = "setup"
      return "setup"
    }
    function sync(): string { root.syncVault(); return "syncing" }
    function status(): string { return root.status }
  }

  Component {
    id: shieldIconComp

    Item {
      anchors.fill: parent

      // Constant Base Shield
      Text {
        anchors.centerIn: parent
        text: "󰞀"
        font.family: root.fontFamily
        font.pixelSize: Style.bar.iconFont
        color: bar ? bar.barForeground : Color.foreground
        renderType: Text.NativeRendering
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
      }

      // Mini Padlock Badge in Bottom-Right Corner when locked
      Item {
        visible: root.status === "locked"
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.rightMargin: -Style.space(2)
        anchors.bottomMargin: -Style.space(2)
        width: Style.space(10)
        height: Style.space(10)

        Rectangle {
          anchors.fill: parent
          radius: width / 2
          color: bar ? bar.background : Color.background
        }

        Text {
          anchors.centerIn: parent
          text: "󰌾"
          font.family: root.fontFamily
          font.pixelSize: Style.space(8)
          color: bar ? bar.barForeground : Color.foreground
          renderType: Text.NativeRendering
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Status Bar Button
  // -------------------------------------------------------------------------

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: shieldIconComp
    useActiveColor: false
    dimmed: root.status === "unauthenticated" || root.status === "checking"
    tooltipText: {
      if (root.status === "unlocked") {
        return "Bitwarden (" + (root.items.length > 0 ? root.items.length + " items" : "Unlocked") + ")"
      }
      if (root.status === "locked") {
        return "Bitwarden (Locked)"
      }
      return "Bitwarden (Not Logged In)"
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) {
        if (root.status === "unlocked") root.lockVault()
        else root.open()
      } else if (buttonCode === Qt.MiddleButton) {
        root.syncVault()
      } else {
        root.toggle()
      }
    }
  }

  // -------------------------------------------------------------------------
  // Popup Window (KeyboardPanel)
  // -------------------------------------------------------------------------

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: (root.status === "unlocked" && root.currentScreen === "main")
      ? keyCatcher
      : (root.status === "unauthenticated" ? emailField : passField)
    contentWidth: panel.fittedContentWidth(Style.space(450))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: searchField.activeFocus
        || emailField.activeFocus
        || loginPassField.activeFocus
        || code2faField.activeFocus
        || passField.activeFocus
        || pinField.activeFocus
        || (root.currentScreen === "edit")
        || (root.currentScreen === "pin")

      onCloseRequested: {
        if (root.currentScreen === "generator") {
          root.currentScreen = "main"
        } else if (root.currentScreen === "pin") {
          root.pinError = ""
          root.currentScreen = "settings"
        } else if (root.currentScreen === "settings") {
          root.closeSettings()
        } else if (root.currentScreen === "setup") {
          root.setupDismissed = true
          root.currentScreen = root.status === "unlocked" ? "main"
            : (root.status === "locked" ? "locked" : "login")
        } else if (root.currentScreen === "detail" || root.currentScreen === "edit") {
          root.currentScreen = "main"
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) {
        if (root.currentScreen === "main") {
          root.cycleCategory(direction)
        } else {
          root.switchPanel(direction)
        }
      }
      onMoveRequested: function(dx, dy) {
        if (!root.cursorActive) {
          root.cursorActive = true
          return
        }
        if (root.currentScreen === "main") {
          if (dy !== 0) root.moveCursor(dy)
          else if (dx !== 0) root.cycleCategory(dx)
        }
      }
      onActivateRequested: {
        if (root.currentScreen === "main") {
          var item = root.getSelectedItem()
          if (item) {
            root.handleSmartEnter(item)
          }
        }
      }
      onTextKey: function(key) {
        var lower = String(key).toLowerCase()
        if (root.currentScreen === "main") {
          var item = root.getSelectedItem()
          if (lower === "y" || lower === "p") {
            if (item) root.copyPassword(item)
          } else if (lower === "u" || lower === "c") {
            if (item) root.copyUsername(item)
          } else if (lower === "t") {
            if (item && item.hasTotp) root.copyTotpCode(item)
          } else if (lower === "o") {
            if (item && item.uris && item.uris.length > 0) root.openUrl(item.uris[0])
          } else if (lower === "n") {
            root.startAddNewItem()
          } else if (lower === "e") {
            if (item) root.openDetail(item)
          } else if (lower === "l") {
            root.lockVault()
          } else if (lower === "r") {
            root.syncVault()
          } else if (lower === "g") {
            root.openGenerator()
          } else if (lower === ",") {
            root.openSettings()
          } else if (lower === "/") {
            searchField.forceActiveFocus()
          }
        } else if (root.currentScreen === "detail") {
          if (lower === "y" || lower === "p") {
            if (root.detailPassword) root.copyToClipboard(root.detailPassword, "Password")
          } else if (lower === "u" || lower === "c") {
            if (root.detailItem && root.detailItem.username) root.copyToClipboard(root.detailItem.username, "Username")
          } else if (lower === "t") {
            if (root.liveTotp) root.copyToClipboard(root.liveTotp, "TOTP")
          } else if (lower === "e") {
            if (root.detailItem) root.startEditItem(root.detailItem)
          } else if (lower === "x") {
            root.showDeleteConfirm = true
          } else if (lower === "v") {
            root.passwordRevealed = !root.passwordRevealed
          } else if (lower === "b" || lower === "q") {
            root.currentScreen = "main"
          }
        }
      }

      Column {
        id: mainColumn
        anchors.fill: parent
        spacing: Style.space(12)

        // -------------------------------------------------------------------
        // Hero Header
        // -------------------------------------------------------------------
        PanelHero {
          width: parent.width
          title: "Bitwarden"
          meta: {
            if (root.status === "unlocked") {
              var count = root.filteredItems.length
              return root.userEmail ? (root.userEmail + " • " + count + " items") : (count + " items")
            }
            if (root.status === "locked") return "Vault Locked"
            if (root.status === "checking") return "Checking status..."
            return "Log In"
          }
          foreground: root.fg
          fontFamily: root.fontFamily

          iconComponent: Text {
            text: "󰞀"
            color: root.barIconColor
            font.family: root.fontFamily
            font.pixelSize: Style.font.display
          }

          trailingControl: Row {
            spacing: Style.space(6)

            // New Item Button
            PanelActionButton {
              visible: root.status === "unlocked" && root.currentScreen === "main"
              iconText: "󰐕"
              tooltipText: "New item (n)"
              fontFamily: root.fontFamily
              onClicked: root.startAddNewItem()
            }

            // Sync Vault Button
            PanelActionButton {
              visible: root.status === "unlocked"
              iconText: "󰑐"
              tooltipText: "Sync vault (r)"
              fontFamily: root.fontFamily
              enabled: !root.isSyncing
              onClicked: root.syncVault()
            }

            // Generator Button
            PanelActionButton {
              visible: root.status === "unlocked" && root.currentScreen !== "generator"
              iconText: "󰌆"
              tooltipText: "Password generator (g)"
              fontFamily: root.fontFamily
              onClicked: root.openGenerator()
            }

            // Settings Button
            PanelActionButton {
              visible: root.currentScreen !== "settings" && root.currentScreen !== "setup" && root.currentScreen !== "pin"
              iconText: "󰒓"
              tooltipText: "Settings (,)"
              fontFamily: root.fontFamily
              onClicked: root.openSettings()
            }

            // Lock Vault Button
            PanelActionButton {
              visible: root.status === "unlocked"
              iconText: "󰌾"
              tooltipText: "Lock vault (l)"
              fontFamily: root.fontFamily
              onClicked: root.lockVault()
            }

            // Close Panel Button
            PanelActionButton {
              iconText: "󰅖"
              tooltipText: "Close (Esc)"
              fontFamily: root.fontFamily
              onClicked: root.close()
            }
          }
        }

        // -------------------------------------------------------------------
        // Sequential TOTP Follow-Up Action Banner
        // -------------------------------------------------------------------
        BorderSurface {
          visible: root.totpFollowupActive && root.totpFollowupItem !== null
          width: parent.width
          implicitHeight: Style.space(42)
          color: Util.alpha(Color.accent, 0.2)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.accent, 1)

          Row {
            anchors.fill: parent
            anchors.leftMargin: Style.space(10)
            anchors.rightMargin: Style.space(10)
            spacing: Style.space(8)

            Text {
              anchors.verticalCenter: parent.verticalCenter
              text: "󰄬"
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Column {
              anchors.verticalCenter: parent.verticalCenter
              width: parent.width - copyFollowupTotpBtn.width - Style.space(40)
              spacing: 1

              Text {
                text: "Password copied! Press Enter for TOTP"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }

              Text {
                text: root.totpFollowupCode ? ("Code: " + root.totpFollowupCode + " (expires in " + root.totpSecRemaining + "s)") : "Fetching 2FA code..."
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }

            Button {
              id: copyFollowupTotpBtn
              anchors.verticalCenter: parent.verticalCenter
              text: "Copy TOTP (Enter)"
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: {
                if (root.totpFollowupItem) root.copyTotpCode(root.totpFollowupItem)
                root.totpFollowupActive = false
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // Flash Message Banner
        // -------------------------------------------------------------------
        BorderSurface {
          visible: root.flashMessage !== "" && !root.totpFollowupActive
          width: parent.width
          implicitHeight: flashText.implicitHeight + Style.space(10)
          color: Util.alpha(Color.accent, 0.15)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.accent, 1)

          Row {
            anchors.centerIn: parent
            spacing: Style.space(8)
            Text {
              text: "󰄬"
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              id: flashText
              text: root.flashMessage
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              font.bold: true
            }
          }
        }

        // -------------------------------------------------------------------
        // Error Message Banner
        // -------------------------------------------------------------------
        BorderSurface {
          visible: root.errorMessage !== ""
          width: parent.width
          implicitHeight: errorText.implicitHeight + Style.space(12)
          color: Util.alpha(Color.urgent, 0.15)
          radius: Style.cornerRadius
          borderSpec: Border.surfaceSpec("menu", "border", Color.urgent, 1)

          Row {
            anchors.centerIn: parent
            width: parent.width - Style.space(16)
            spacing: Style.space(8)
            Text {
              text: "󰅚"
              color: Color.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              id: errorText
              text: root.errorMessage
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.Wrap
              width: parent.width - Style.space(24)
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0c: PIN SETUP
        // -------------------------------------------------------------------
        // -------------------------------------------------------------------
        // SCREEN 0d: GENERATOR
        // -------------------------------------------------------------------
        Flickable {
          id: genFlick
          visible: root.currentScreen === "generator"
          width: parent.width
          height: Math.min(Style.space(520), genCol.implicitHeight)
          contentWidth: width
          contentHeight: genCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: genCol
            width: genFlick.width
            spacing: Style.space(10)

            PanelSeparator { width: parent.width }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.currentScreen = "main"
              }
            }

            // Generated value
            BorderSurface {
              width: parent.width
              implicitHeight: Style.space(58)
              radius: Style.cornerRadius
              color: Style.hoverFillFor(root.fg, Color.accent)
              borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

              Row {
                anchors.fill: parent
                anchors.leftMargin: Style.space(12)
                anchors.rightMargin: Style.space(6)
                spacing: Style.space(4)

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(90)
                  text: root.genBusy ? "Generating..." : (root.genValue || "-")
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.subtitle
                  font.bold: true
                  wrapMode: Text.WrapAnywhere
                  maximumLineCount: 2
                  elide: Text.ElideRight
                }

                PanelActionButton {
                  anchors.verticalCenter: parent.verticalCenter
                  iconText: "󰑐"
                  tooltipText: "Regenerate"
                  fontFamily: root.fontFamily
                  enabled: !root.genBusy
                  onClicked: root.regenerate()
                }

                PanelActionButton {
                  anchors.verticalCenter: parent.verticalCenter
                  iconText: "󰆏"
                  tooltipText: "Copy"
                  fontFamily: root.fontFamily
                  enabled: root.genValue !== ""
                  onClicked: root.copyGenerated()
                }
              }
            }

            // Strength meter
            Column {
              width: parent.width
              spacing: Style.space(3)

              readonly property var strength: Model.generatorStrength(root.genOpts)

              Row {
                width: parent.width
                Text {
                  text: parent.parent.strength.label
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
                Item { width: Style.space(6); height: 1 }
                Text {
                  text: "~" + parent.parent.strength.bits + " bits of entropy"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }

              Rectangle {
                width: parent.width
                height: Style.space(4)
                radius: height / 2
                color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.15)

                Rectangle {
                  width: parent.width * parent.parent.strength.fraction
                  height: parent.height
                  radius: height / 2
                  color: Color.accent
                }
              }
            }

            PanelSeparator { width: parent.width }

            // Type
            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: "Password"
                iconText: "󰌆"
                selected: root.genOpts.type === "password"
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.setGenOpt("type", "password")
              }

              Button {
                text: "Passphrase"
                iconText: "󰈚"
                selected: root.genOpts.type === "passphrase"
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.setGenOpt("type", "passphrase")
              }
            }

            // ---- Password options ----
            Column {
              visible: root.genOpts.type === "password"
              width: parent.width
              spacing: Style.space(8)

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Length"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.length
                  from: 5
                  to: 128
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("length", v) }
                }
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "A-Z"
                  selected: root.genOpts.uppercase
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("uppercase", !root.genOpts.uppercase)
                }
                Button {
                  text: "a-z"
                  selected: root.genOpts.lowercase
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("lowercase", !root.genOpts.lowercase)
                }
                Button {
                  text: "0-9"
                  selected: root.genOpts.numbers
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("numbers", !root.genOpts.numbers)
                }
                Button {
                  text: "!@#$%^&*"
                  selected: root.genOpts.special
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("special", !root.genOpts.special)
                }
                Button {
                  text: "Avoid ambiguous"
                  tooltipText: "Exclude characters that are easy to confuse, such as l, 1, I, O and 0"
                  selected: root.genOpts.ambiguous
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("ambiguous", !root.genOpts.ambiguous)
                }
              }

              Row {
                visible: root.genOpts.numbers
                width: parent.width
                spacing: Style.space(10)
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Minimum numbers"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.minNumber
                  from: 0
                  to: 9
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("minNumber", v) }
                }
              }

              Row {
                visible: root.genOpts.special
                width: parent.width
                spacing: Style.space(10)
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Minimum special"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.minSpecial
                  from: 0
                  to: 9
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("minSpecial", v) }
                }
              }
            }

            // ---- Passphrase options ----
            Column {
              visible: root.genOpts.type === "passphrase"
              width: parent.width
              spacing: Style.space(8)

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Number of words"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.genOpts.words
                  from: 3
                  to: 20
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.setGenOpt("words", v) }
                }
              }

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Word separator"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                TextField {
                  anchors.verticalCenter: parent.verticalCenter
                  width: Style.space(90)
                  text: root.genOpts.separator
                  onTextChanged: if (text && text !== root.genOpts.separator) root.setGenOpt("separator", text.charAt(0))
                }
              }

              Flow {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Capitalize"
                  selected: root.genOpts.capitalize
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("capitalize", !root.genOpts.capitalize)
                }
                Button {
                  text: "Include number"
                  selected: root.genOpts.includeNumber
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.setGenOpt("includeNumber", !root.genOpts.includeNumber)
                }
              }
            }
          }
        }

        // Scrolls rather than overflowing the panel: this screen is taller
        // than the popup's height cap on smaller displays.
        Flickable {
          id: pinFlick
          visible: root.currentScreen === "pin"
          width: parent.width
          height: Math.min(Style.space(520), pinCol.implicitHeight)
          contentWidth: width
          contentHeight: pinCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: pinCol
            width: pinFlick.width
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          Column {
            width: parent.width
            spacing: Style.space(4)

            Text {
              text: "Set an unlock PIN"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              width: parent.width
              text: "Your master password is encrypted with a key derived from this PIN, and only the encrypted form is stored. "
                + "Minimum " + Model.pinMinLength() + " digits -- a longer PIN is meaningfully harder to guess."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Column {
            width: parent.width
            spacing: Style.space(8)

            Text { text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
            TextField {
              width: parent.width
              placeholderText: "Needed once, to encrypt the PIN..."
              password: true
              text: root.pinSetupMaster
              onTextChanged: root.pinSetupMaster = text
              enabled: !root.pinBusy
            }

            Text { text: "PIN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
            TextField {
              id: pinSetupPinField
              width: parent.width
              placeholderText: "At least " + Model.pinMinLength() + " digits..."
              password: true
              text: root.pinSetupPin
              onTextChanged: root.pinSetupPin = text.replace(/[^0-9]/g, "")
              enabled: !root.pinBusy
            }

            Text { text: "CONFIRM PIN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
            TextField {
              width: parent.width
              placeholderText: "Repeat the PIN..."
              password: true
              text: root.pinSetupConfirm
              onTextChanged: root.pinSetupConfirm = text.replace(/[^0-9]/g, "")
              onAccepted: root.submitPinSetup()
              enabled: !root.pinBusy
            }

            Text {
              visible: root.pinError !== ""
              width: parent.width
              text: root.pinError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.pinBusy ? "Encrypting..." : "Save PIN"
                iconText: root.pinBusy ? "󰑐" : "󰄬"
                iconSpinning: root.pinBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.pinBusy
                onClicked: root.submitPinSetup()
              }

              Button {
                text: "Cancel"
                iconText: "󰅖"
                fontFamily: root.fontFamily
                enabled: !root.pinBusy
                onClicked: { root.pinError = ""; root.currentScreen = "settings" }
              }
            }
          }
                  }
        }

        // -------------------------------------------------------------------
        // SCREEN 0a: SETUP WIZARD (missing dependencies)
        // -------------------------------------------------------------------
        // Scrolls rather than overflowing the panel: this screen is taller
        // than the popup's height cap on smaller displays.
        Flickable {
          id: setupFlick
          visible: root.currentScreen === "setup"
          width: parent.width
          height: Math.min(Style.space(520), setupCol.implicitHeight)
          contentWidth: width
          contentHeight: setupCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: setupCol
            width: setupFlick.width
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          Column {
            width: parent.width
            spacing: Style.space(4)

            Text {
              text: root.missingRequired.length > 0 ? "Setup required" : "All set"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              width: parent.width
              text: root.missingRequired.length > 0
                ? "The plugin shells out to these tools. The ones marked required must be installed for it to work at all."
                : "Every required tool is installed. Optional ones below unlock extra features."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Repeater {
            model: root.dependencies.items

            delegate: BorderSurface {
              required property var modelData
              width: parent.width
              implicitHeight: depRow.implicitHeight + Style.space(16)
              radius: Style.cornerRadius
              color: modelData.ready ? "transparent" : Util.alpha(root.urgent, 0.12)
              borderSpec: Border.surfaceSpec("menu", "border",
                modelData.ready ? Color.accent : root.urgent, 1)

              Row {
                id: depRow
                anchors.fill: parent
                anchors.margins: Style.space(8)
                spacing: Style.space(10)

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: modelData.ready ? "󰄬" : (modelData.required ? "󰅖" : "󰋗")
                  color: modelData.ready ? Color.accent : (modelData.required ? root.urgent : root.dim)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.subtitle
                }

                Column {
                  width: parent.width - Style.space(170)
                  spacing: Style.space(2)

                  Row {
                    spacing: Style.space(6)
                    Text {
                      text: modelData.label
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.bold: true
                    }
                    Text {
                      anchors.verticalCenter: parent.verticalCenter
                      text: modelData.required ? "required" : "optional"
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Text {
                    width: parent.width
                    text: modelData.purpose
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }

                  // fprintd on PATH still needs an enrolled finger.
                  Text {
                    visible: modelData.key === "fprintd" && modelData.installed && !modelData.ready
                    width: parent.width
                    text: "Installed, but no finger is enrolled yet."
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }

                Button {
                  anchors.verticalCenter: parent.verticalCenter
                  visible: !modelData.installed
                  text: "Install"
                  iconText: "󰐕"
                  tooltipText: "omarchy pkg add " + modelData.pkg
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.installOne(modelData)
                }

                Button {
                  anchors.verticalCenter: parent.verticalCenter
                  visible: modelData.key === "fprintd" && modelData.installed && !modelData.ready
                  text: "Enroll"
                  iconText: "󰈷"
                  tooltipText: "omarchy setup security fingerprint"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.runFingerprintSetup()
                }
              }
            }
          }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Re-check"
              iconText: "󰑐"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.checkDependencies()
            }

            Button {
              visible: root.missingRequired.length > 1
              text: "Install all missing"
              iconText: "󰐕"
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.installMissing()
            }

            Button {
              text: root.missingRequired.length > 0 ? "Continue anyway" : "Done"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: {
                root.setupDismissed = true
                root.currentScreen = root.status === "unlocked" ? "main"
                  : (root.status === "locked" ? "locked" : "login")
              }
            }
          }
                  }
        }

        // -------------------------------------------------------------------
        // SCREEN 0b: SETTINGS
        // -------------------------------------------------------------------
        // Scrolls rather than overflowing the panel: this screen is taller
        // than the popup's height cap on smaller displays.
        Flickable {
          id: settingsFlick
          visible: root.currentScreen === "settings"
          width: parent.width
          height: Math.min(Style.space(520), settingsCol.implicitHeight)
          contentWidth: width
          contentHeight: settingsCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: settingsCol
            width: settingsFlick.width
          spacing: Style.space(10)

          PanelSeparator { width: parent.width }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Back (Esc)"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.closeSettings()
            }

            Item {
              width: parent.width - Style.space(220)
              height: 1
            }

            Text {
              anchors.verticalCenter: parent.verticalCenter
              visible: root.settingsFlash !== ""
              text: "󰄬 " + root.settingsFlash
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          Repeater {
            model: Model.groupedSettings()

            delegate: Column {
              required property var modelData
              width: parent.width
              spacing: Style.space(4)

              // One header per group, drawn by the first entry in it.
              Item {
                visible: modelData.groupLabel !== ""
                width: parent.width
                height: visible ? Style.space(18) : 0
              }

              PanelSectionHeader {
                visible: modelData.groupLabel !== ""
                text: modelData.groupLabel === "" ? "" : modelData.groupLabel.toUpperCase()
                foreground: root.fg
                fontFamily: root.fontFamily
              }

              // A setting whose dependency is missing is shown but inert, with
              // the reason stated rather than the control silently doing nothing.
              readonly property bool blocked: {
                if (!modelData.requires) return false
                for (var i = 0; i < root.dependencies.items.length; i++) {
                  if (root.dependencies.items[i].key === modelData.requires) {
                    return !root.dependencies.items[i].ready
                  }
                }
                return false
              }

              Row {
                width: parent.width
                spacing: Style.space(10)

                Column {
                  width: parent.width - Style.space(modelData.type === "int" ? 200 : 130)
                  spacing: Style.space(2)

                  Text {
                    text: modelData.label
                    color: blocked ? root.dim : root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                  }

                  Text {
                    width: parent.width
                    text: blocked
                      ? "Needs fingerprint setup -- see Dependencies below."
                      : modelData.description
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }
                }

                ToggleSwitch {
                  anchors.verticalCenter: parent.verticalCenter
                  visible: modelData.type === "bool"
                  checked: modelData.type === "bool" && root.settingValue(modelData)
                  interactive: !blocked
                  foreground: root.fg
                  accent: Color.accent
                  onToggled: {
                    if (blocked) return
                    // A PIN cannot simply be switched on: it has to be chosen,
                    // and encrypting it needs the master password.
                    if (modelData.action === "pin") {
                      if (checked) root.disablePinUnlock()
                      else root.beginPinSetup()
                      return
                    }
                    root.writeSetting(modelData.key, !checked, "bool")
                  }
                }

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  visible: modelData.type === "int" && !!modelData.unit
                  text: modelData.unit || ""
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  visible: modelData.type === "int"
                  value: modelData.type === "int" ? root.settingValue(modelData) : 0
                  from: modelData.min || 0
                  to: modelData.max || 100
                  stepSize: modelData.step || 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.writeSetting(modelData.key, v, "int") }
                }
              }

              Text {
                visible: modelData.type === "int" && root.settingValue(modelData) === 0 && !!modelData.zeroLabel
                text: modelData.zeroLabel + " -- this is disabled."
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              PanelSeparator { width: parent.width }
            }
          }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Dependencies"
              iconText: "󰏗"
              tooltipText: "Check the tools this plugin needs"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: {
                root.setupDismissed = false
                root.checkDependencies()
                root.currentScreen = "setup"
              }
            }

            Button {
              visible: root.fingerprintStored
              text: "Forget Fingerprint"
              iconText: "󰈷"
              tooltipText: "Remove the stored master password from the OS keyring"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.forgetFingerprintUnlock()
            }
          }

          Text {
            width: parent.width
            text: "Saved to the plugin's entry in ~/.config/omarchy/shell.json via `omarchy bar set`."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }
                  }
        }

        // -------------------------------------------------------------------
        // SCREEN 1: LOGIN VIEW (When unauthenticated)
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unauthenticated" && root.currentScreen !== "settings" && root.currentScreen !== "setup" && root.currentScreen !== "pin"
          width: parent.width
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              text: "Email & Password"
              iconText: "󰇮"
              selected: root.loginMethod === "email"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.loginMethod = "email"
            }

            Button {
              text: "API Key"
              iconText: "󰌋"
              selected: root.loginMethod === "apikey"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.loginMethod = "apikey"
            }
          }

          // METHOD A: Email & Password
          Column {
            visible: root.loginMethod === "email"
            width: parent.width
            spacing: Style.space(10)

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { text: "EMAIL ADDRESS"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: emailField
                width: parent.width
                placeholderText: "you@example.com"
                text: root.loginEmail
                onTextChanged: root.loginEmail = text
                onAccepted: loginPassField.forceActiveFocus()
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              Row {
                width: parent.width
                spacing: Style.space(6)
                TextField {
                  id: loginPassField
                  width: parent.width - eyeBtnLogin.width - Style.space(6)
                  placeholderText: "Master password..."
                  password: !eyeBtnLogin.revealed
                  text: root.loginPassword
                  onTextChanged: root.loginPassword = text
                  onAccepted: code2faField.forceActiveFocus()
                }
                Button {
                  id: eyeBtnLogin
                  property bool revealed: false
                  iconText: revealed ? "󰈉" : "󰈈"
                  tooltipText: revealed ? "Hide password" : "Show password"
                  fontFamily: root.fontFamily
                  onClicked: revealed = !revealed
                }
              }
            }

            // 2FA Field (Always visible)
            Column {
              width: parent.width
              spacing: Style.space(3)

              Row {
                width: parent.width
                Text {
                  text: "TWO-STEP VERIFICATION CODE (2FA)"
                  color: root.show2faField ? Color.accent : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
                Item { Layout.fillWidth: true }
                Text {
                  text: "Optional if not enabled"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
              }

              TextField {
                id: code2faField
                width: parent.width
                placeholderText: "6-digit Authenticator / Email verification code..."
                text: root.login2faCode
                onTextChanged: root.login2faCode = text
                onAccepted: root.submitLogin()
              }
            }

            // Custom Server URL (collapsible)
            Column {
              width: parent.width
              spacing: Style.space(4)

              MouseArea {
                width: parent.width
                height: Style.space(20)
                cursorShape: Qt.PointingHandCursor
                onClicked: root.showServerField = !root.showServerField
                Row {
                  spacing: Style.space(4)
                  Text {
                    text: root.showServerField ? "▾ Custom Server URL" : "▸ Custom Server (Self-hosted Vaultwarden)"
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }
              }

              TextField {
                visible: root.showServerField
                width: parent.width
                placeholderText: "https://vault.example.com"
                text: root.loginServerUrl
                onTextChanged: root.loginServerUrl = text
              }
            }

            Button {
              width: parent.width
              text: root.isLoading ? "Logging in..." : "Log In & Unlock"
              iconText: root.isLoading ? "󰑐" : "󰌋"
              iconSpinning: root.isLoading
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: !root.isLoading
              onClicked: root.submitLogin()
            }
          }

          // METHOD B: API Key
          Column {
            visible: root.loginMethod === "apikey"
            width: parent.width
            spacing: Style.space(10)

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { text: "CLIENT ID"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                width: parent.width
                placeholderText: "user.xxxxxxxx-xxxx-xxxx..."
                text: root.loginClientId
                onTextChanged: root.loginClientId = text
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { text: "CLIENT SECRET"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                width: parent.width
                placeholderText: "Client secret string..."
                password: true
                text: root.loginClientSecret
                onTextChanged: root.loginClientSecret = text
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(3)
              Text { text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                width: parent.width
                placeholderText: "Master password to unlock vault..."
                password: true
                text: root.loginPassword
                onTextChanged: root.loginPassword = text
                onAccepted: root.submitLogin()
              }
            }

            Button {
              width: parent.width
              text: root.isLoading ? "Logging in..." : "Log In with API Key"
              iconText: root.isLoading ? "󰑐" : "󰌋"
              iconSpinning: root.isLoading
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: !root.isLoading
              onClicked: root.submitLogin()
            }
          }

          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)
            Text {
              text: "Prefer interactive TTY login?"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              anchors.verticalCenter: parent.verticalCenter
            }
            Button {
              text: "Launch Terminal"
              iconText: "󰞷"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.launchTerminalLogin()
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 2: LOCKED VIEW (When authenticated, but vault locked)
        // -------------------------------------------------------------------
        Column {
          visible: (root.status === "locked" || root.status === "checking")
            && root.currentScreen !== "settings" && root.currentScreen !== "setup" && root.currentScreen !== "pin"
          width: parent.width
          spacing: Style.space(14)

          PanelSeparator { width: parent.width }

          Item { height: Style.space(8); width: 1 }

          Column {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)

            Text {
              anchors.horizontalCenter: parent.horizontalCenter
              text: root.fingerprintScanning ? "󰈷" : "󰌋"
              color: root.fingerprintScanning ? Color.accent : root.fg
              opacity: 0.85
              font.family: root.fontFamily
              font.pixelSize: Style.space(38)

              SequentialAnimation on opacity {
                running: root.fingerprintScanning
                loops: Animation.Infinite
                NumberAnimation { to: 0.35; duration: 700; easing.type: Easing.InOutQuad }
                NumberAnimation { to: 0.95; duration: 700; easing.type: Easing.InOutQuad }
                onStopped: parent.opacity = 0.85
              }
            }

            Text {
              anchors.horizontalCenter: parent.horizontalCenter
              text: root.fingerprintReady ? "Unlock Vault" : "Enter Master Password"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              visible: root.userEmail !== ""
              anchors.horizontalCenter: parent.horizontalCenter
              text: root.userEmail
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
            }
          }

          // Fingerprint status / prompt
          Text {
            visible: root.fingerprintMessage !== ""
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: root.fingerprintMessage
            color: root.fingerprintScanning ? Color.accent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // Offered when fingerprint unlock is on but nothing is stored yet.
          Text {
            visible: root.fingerprintUnlock && root.fingerprintAvailable && !root.fingerprintStored
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: "󰈷  Unlock once with your master password to enable fingerprint unlock."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }

          // PIN entry, offered above the password field when one is set.
          Column {
            visible: root.pinReady
            width: parent.width
            spacing: Style.space(8)

            Text { text: "PIN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

            Row {
              width: parent.width
              spacing: Style.space(8)

              TextField {
                id: pinField
                width: parent.width - pinUnlockBtn.width - Style.space(8)
                placeholderText: "Enter your PIN..."
                password: true
                text: root.pinEntry
                onTextChanged: root.pinEntry = text.replace(/[^0-9]/g, "")
                onAccepted: root.submitPinUnlock()
                enabled: !root.pinBusy && !root.isUnlocking
              }

              Button {
                id: pinUnlockBtn
                text: root.pinBusy ? "Checking..." : "Unlock"
                iconText: root.pinBusy ? "󰑐" : "󰌿"
                iconSpinning: root.pinBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.pinBusy && !root.isUnlocking
                onClicked: root.submitPinUnlock()
              }
            }

            Text {
              visible: root.pinError !== ""
              width: parent.width
              text: root.pinError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Text {
              text: "or use your master password below"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          // A PIN was set but the vault rejected it -- surfaced even once
          // pinReady has gone false, so the reason is not lost.
          Text {
            visible: !root.pinReady && root.pinError !== ""
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: root.pinError
            color: root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          Column {
            width: parent.width
            spacing: Style.space(10)

            Button {
              visible: root.fingerprintReady
              width: parent.width
              text: root.fingerprintScanning ? "Waiting for fingerprint..." : "Unlock with Fingerprint"
              iconText: "󰈷"
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: !root.isUnlocking && !root.fingerprintScanning
              onClicked: root.startFingerprintUnlock()
            }

            Row {
              width: parent.width
              spacing: Style.space(8)

              TextField {
                id: passField
                width: parent.width - eyeBtnUnlock.width - Style.space(8)
                placeholderText: "Master password..."
                password: !eyeBtnUnlock.revealed
                text: root.masterPassword
                onTextChanged: root.masterPassword = text
                onAccepted: root.unlockVault()
                enabled: !root.isUnlocking
              }

              Button {
                id: eyeBtnUnlock
                property bool revealed: false
                iconText: revealed ? "󰈉" : "󰈈"
                tooltipText: revealed ? "Hide password" : "Show password"
                fontFamily: root.fontFamily
                onClicked: revealed = !revealed
              }
            }

            Button {
              width: parent.width
              text: root.isUnlocking ? "Unlocking..." : "Unlock Vault"
              iconText: root.isUnlocking ? "󰑐" : "󰌋"
              iconSpinning: root.isUnlocking
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
              enabled: !root.isUnlocking
              onClicked: root.unlockVault()
            }
          }

          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(8)

            Button {
              text: "Switch / Log Out"
              iconText: "󰍃"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.logoutAccount()
            }

            Button {
              visible: root.fingerprintStored
              text: "Forget Fingerprint"
              iconText: "󰈷"
              tooltipText: "Remove the stored master password from the OS keyring"
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.forgetFingerprintUnlock()
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 3: UNLOCKED - ITEM LIST VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.currentScreen === "main"
          width: parent.width
          spacing: Style.space(8)

          // Search Field
          Row {
            width: parent.width
            spacing: Style.space(6)

            TextField {
              id: searchField
              width: parent.width - (root.searchQuery ? clearSearchBtn.width + Style.space(6) : 0)
              placeholderText: "Search items, usernames, URLs..."
              text: root.searchQuery
              onTextChanged: {
                root.searchQuery = text
                root.selectedIndex = 0
                searchDebounceTimer.restart()
              }
              Keys.onDownPressed: {
                keyCatcher.forceActiveFocus()
                root.moveCursor(1)
              }
              Keys.onReturnPressed: {
                var itm = root.getSelectedItem()
                if (itm) root.handleSmartEnter(itm)
              }
              Keys.onEscapePressed: {
                if (text) text = ""
                else root.close()
              }
            }

            PanelActionButton {
              id: clearSearchBtn
              visible: root.searchQuery !== ""
              iconText: "󰅖"
              tooltipText: "Clear search"
              fontFamily: root.fontFamily
              onClicked: searchField.text = ""
            }
          }

          // Organization / Vault Selector Bar (Shown if organizations exist)
          Flickable {
            visible: root.organizations.length > 0
            width: parent.width
            height: Style.space(26)
            contentWidth: orgRow.implicitWidth
            flickableDirection: Flickable.HorizontalFlick
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Row {
              id: orgRow
              spacing: Style.space(6)

              Button {
                text: "All Vaults"
                iconText: "󰞀"
                selected: root.selectedOrg === "all"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                horizontalPadding: Style.space(8)
                verticalPadding: Style.space(2)
                onClicked: root.selectOrganization("all")
              }

              Button {
                text: "My Vault"
                iconText: ""
                selected: root.selectedOrg === "personal"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                horizontalPadding: Style.space(8)
                verticalPadding: Style.space(2)
                onClicked: root.selectOrganization("personal")
              }

              Repeater {
                model: root.organizations
                delegate: Button {
                  text: modelData.name
                  iconText: "󰓹"
                  selected: root.selectedOrg === modelData.id
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(2)
                  onClicked: root.selectOrganization(modelData.id)
                }
              }
            }
          }

          // Category Pills
          Flickable {
            width: parent.width
            height: Style.space(28)
            contentWidth: categoryRow.implicitWidth
            flickableDirection: Flickable.HorizontalFlick
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Row {
              id: categoryRow
              spacing: Style.space(6)

              Repeater {
                model: root.categories
                delegate: Button {
                  text: modelData.label
                  selected: root.selectedCategory === modelData.id
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(3)
                  onClicked: root.selectCategory(modelData.id)
                }
              }
            }
          }

          // Contextual Suggestion Banner
          BorderSurface {
            visible: Boolean(root.suggestedItems.length > 0 && !root.suggestionsDismissed && root.searchQuery.trim() === "" && root.detectedContext && root.detectedContext.displayName)
            width: parent.width
            implicitHeight: Style.space(28)
            radius: Style.cornerRadius
            color: Style.selectedFillFor(root.fg, Color.accent)
            borderSpec: Border.controlSpec("normal", Color.accent, Color.accent)

            Row {
              anchors.fill: parent
              anchors.leftMargin: Style.space(8)
              anchors.rightMargin: Style.space(6)
              spacing: Style.space(6)

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "󰌠"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "Suggested for " + (root.detectedContext ? root.detectedContext.displayName : "active window")
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                elide: Text.ElideRight
                width: parent.width - Style.space(60)
              }

              Item { Layout.fillWidth: true }

              PanelActionButton {
                anchors.verticalCenter: parent.verticalCenter
                iconText: "󰅖"
                tooltipText: "Dismiss suggestion"
                fontFamily: root.fontFamily
                size: Style.space(18)
                fontSize: Style.font.caption
                onClicked: {
                  root.suggestionsDismissed = true
                  root.rebuildFilter()
                }
              }
            }
          }

          PanelSeparator { width: parent.width }

          // Item List View (Fast Virtualized ListView with Delegate Recycling)
          Item {
            width: parent.width
            height: Style.space(320)

            ListView {
              id: itemsListView
              anchors.fill: parent
              clip: true
              model: root.filteredItems
              spacing: Style.space(4)
              boundsBehavior: Flickable.StopAtBounds
              reuseItems: true
              currentIndex: root.selectedIndex
              ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

              delegate: BorderSurface {
                id: itemRow
                required property var modelData
                required property int index

                readonly property var itemData: modelData
                readonly property bool isSelected: root.cursorActive && root.selectedIndex === index
                readonly property bool isHovered: rowMouseArea.containsMouse

                width: ListView.view.width
                implicitHeight: Style.space(46)
                radius: Style.cornerRadius
                color: isSelected
                  ? Style.selectedFillFor(root.fg, Color.accent)
                  : (isHovered ? Style.hoverFillFor(root.fg, Color.accent) : "transparent")
                borderSpec: isSelected
                  ? Border.controlSpec("selected", root.fg, Color.accent)
                  : Border.none()

                Row {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(8)
                  spacing: Style.space(10)

                  // Type Icon
                  Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: Model.itemTypeGlyph(itemData.typeCode)
                    color: itemData.favorite ? Color.accent : root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.title
                    width: Style.space(20)
                  }

                  // Labels (Title + Subtitle + Org Tag)
                  Column {
                    anchors.verticalCenter: parent.verticalCenter
                    width: parent.width - Style.space(20) - actionButtonsRow.implicitWidth - Style.space(28)
                    spacing: Style.space(1)

                    Row {
                      spacing: Style.space(4)
                      width: parent.width

                      Text {
                        text: itemData.name
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        font.bold: true
                        elide: Text.ElideRight
                        width: Math.min(implicitWidth, parent.width - (itemData.favorite ? Style.space(16) : 0))
                      }

                      Text {
                        visible: itemData.favorite
                        text: "★"
                        color: Color.accent
                        font.pixelSize: Style.font.bodySmall
                        anchors.verticalCenter: parent.verticalCenter
                      }
                    }

                    Row {
                      spacing: Style.space(4)
                      width: parent.width

                      Text {
                        visible: Boolean(itemData.isSuggested)
                        text: root.learnedIds[itemData.id] ? "󰐾 Suggested" : "󰌠 Suggested"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        visible: Boolean(itemData.organizationId)
                        text: "󰓹 Org"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        text: itemData.subtitle || Model.itemTypeLabel(itemData.typeCode)
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                        width: parent.width - (itemData.organizationId ? Style.space(40) : 0) - (itemData.isSuggested ? Style.space(75) : 0)
                      }
                    }
                  }

                  // Quick Action Buttons
                  Row {
                    id: actionButtonsRow
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(4)
                    visible: isSelected || isHovered

                    PanelActionButton {
                      visible: itemData.hasPassword
                      iconText: "󰌆"
                      tooltipText: "Copy password (Enter / y)"
                      fontFamily: root.fontFamily
                      onClicked: root.handleSmartEnter(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.username !== ""
                      iconText: ""
                      tooltipText: "Copy username (u)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyUsername(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.hasTotp
                      iconText: "󰥔"
                      tooltipText: "Copy TOTP code (t)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyTotpCode(itemData)
                    }

                    PanelActionButton {
                      iconText: "󰏫"
                      tooltipText: "View / Edit item (e)"
                      fontFamily: root.fontFamily
                      onClicked: root.openDetail(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.uris && itemData.uris.length > 0
                      iconText: "󰖟"
                      tooltipText: "Open URL (o)"
                      fontFamily: root.fontFamily
                      onClicked: root.openUrl(itemData.uris[0])
                    }
                  }
                }

                MouseArea {
                  id: rowMouseArea
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.cursorActive = true
                    root.selectedIndex = index
                    root.openDetail(itemData)
                  }
                }
              }
            }

            // Empty state overlay
            Item {
              visible: root.filteredItems.length === 0
              anchors.fill: parent

              Column {
                anchors.centerIn: parent
                spacing: Style.space(6)

                Text {
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.items.length === 0 ? "󰞀" : "󰍡"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(36)
                }

                Text {
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.items.length === 0 ? "Vault is empty" : ("No items match '" + root.searchQuery + "'")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
              }
            }
          }

        }

        // -------------------------------------------------------------------
        // SCREEN 4: UNLOCKED - ITEM DETAIL VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.currentScreen === "detail"
          width: parent.width
          spacing: Style.space(12)

          // Back Navigation & Action Header
          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Back to list (Esc)"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.currentScreen = "main"
            }

            Item { Layout.fillWidth: true }

            Button {
              visible: Boolean(root.detectedContext && root.detectedContext.displayName && root.detailItem)
              readonly property bool pinned: Boolean(root.detailItem
                && Model.isAssociated(root.associations, root.detectedContext, root.detailItem.id))
              text: pinned ? "Suggested here" : "Suggest here"
              iconText: pinned ? "󰐾" : "󰐽"
              selected: pinned
              accent: Color.accent
              tooltipText: (pinned ? "Stop suggesting this for " : "Always suggest this for ")
                + (root.detectedContext ? root.detectedContext.displayName : "")
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.toggleAssociation(root.detailItem)
            }

            Button {
              text: "Edit"
              iconText: "󰏫"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: if (root.detailItem) root.startEditItem(root.detailItem)
            }

            Button {
              text: "Delete"
              iconText: "󰆴"
              accent: Color.urgent
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.showDeleteConfirm = true
            }
          }

          // Delete Confirmation Banner
          BorderSurface {
            visible: root.showDeleteConfirm
            width: parent.width
            implicitHeight: Style.space(64)
            color: Util.alpha(Color.urgent, 0.15)
            radius: Style.cornerRadius
            borderSpec: Border.surfaceSpec("menu", "border", Color.urgent, 1)

            Row {
              anchors.centerIn: parent
              spacing: Style.space(12)

              Text {
                text: "Permanently delete this item?"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                anchors.verticalCenter: parent.verticalCenter
              }

              Button {
                text: "Confirm Delete"
                iconText: "󰆴"
                selected: true
                accent: Color.urgent
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.deleteCurrentItem()
              }

              Button {
                text: "Cancel"
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.showDeleteConfirm = false
              }
            }
          }

          PanelSeparator { width: parent.width }

          Flickable {
            id: detailFlickable
            width: parent.width
            height: Math.min(Style.space(380), detailContentColumn.implicitHeight)
            contentWidth: width
            contentHeight: detailContentColumn.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            Column {
              id: detailContentColumn
              width: detailFlickable.width
              spacing: Style.space(12)

              // Item Header
              Row {
                width: parent.width
                spacing: Style.space(10)

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.detailItem ? Model.itemTypeGlyph(root.detailItem.typeCode) : "󰌋"
                  color: (root.detailItem && root.detailItem.favorite) ? Color.accent : root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(26)
                }

                Column {
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(40)
                  spacing: Style.space(2)

                  Row {
                    spacing: Style.space(6)
                    width: parent.width

                    Text {
                      text: root.detailItem ? root.detailItem.name : "Loading..."
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.title
                      font.bold: true
                      elide: Text.ElideRight
                      width: Math.min(implicitWidth, parent.width - Style.space(20))
                    }

                    Text {
                      visible: Boolean(root.detailItem && root.detailItem.favorite)
                      text: "★"
                      color: Color.accent
                      font.pixelSize: Style.font.body
                    }
                  }

                  Row {
                    spacing: Style.space(6)
                    Text {
                      text: root.detailItem ? Model.itemTypeLabel(root.detailItem.typeCode) : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                    Text {
                      visible: Boolean(root.detailItem && root.detailItem.organizationId)
                      text: "• Shared Organization"
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }
                }
              }

              // FIELD: Username
              Column {
                visible: Boolean(root.detailItem && root.detailItem.username !== "")
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "USERNAME / EMAIL" }

                BorderSurface {
                  width: parent.width
                  implicitHeight: Style.space(34)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Row {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(10)
                    anchors.rightMargin: Style.space(6)

                    Text {
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.detailItem ? root.detailItem.username : ""
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      elide: Text.ElideRight
                      width: parent.width - copyUserBtn.width - Style.space(10)
                    }

                    PanelActionButton {
                      id: copyUserBtn
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: ""
                      tooltipText: "Copy username (u)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyToClipboard(root.detailItem ? root.detailItem.username : "", "Username")
                    }
                  }
                }
              }

              // FIELD: Password
              Column {
                visible: Boolean(root.detailItem && (root.detailPassword !== "" || root.detailItem.hasPassword))
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "PASSWORD" }

                BorderSurface {
                  width: parent.width
                  implicitHeight: Style.space(34)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Row {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(10)
                    anchors.rightMargin: Style.space(6)

                    Text {
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.passwordRevealed ? root.detailPassword : Model.maskString(root.detailPassword || "password")
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      elide: Text.ElideRight
                      width: parent.width - passActions.width - Style.space(10)
                    }

                    Row {
                      id: passActions
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: Style.space(4)

                      PanelActionButton {
                        iconText: root.passwordRevealed ? "󰈉" : "󰈈"
                        tooltipText: root.passwordRevealed ? "Hide password (v)" : "Reveal password (v)"
                        fontFamily: root.fontFamily
                        onClicked: root.passwordRevealed = !root.passwordRevealed
                      }

                      PanelActionButton {
                        iconText: "󰌆"
                        tooltipText: "Copy password (y / Enter)"
                        fontFamily: root.fontFamily
                        onClicked: root.copyToClipboard(root.detailPassword, "Password")
                      }
                    }
                  }
                }
              }

              // FIELD: TOTP (2FA Code)
              Column {
                visible: Boolean(root.detailItem && root.detailItem.hasTotp)
                width: parent.width
                spacing: Style.space(4)

                Row {
                  width: parent.width
                  PanelSectionHeader { text: "VERIFICATION CODE (TOTP)" }
                  Item { Layout.fillWidth: true }
                  Text {
                    text: root.totpSecRemaining + "s"
                    color: Color.accent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: true
                    anchors.verticalCenter: parent.verticalCenter
                  }
                }

                BorderSurface {
                  width: parent.width
                  implicitHeight: Style.space(44)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Rectangle {
                    anchors.left: parent.left
                    anchors.bottom: parent.bottom
                    height: Style.space(3)
                    radius: Style.cornerRadius
                    width: parent.width * (root.totpSecRemaining / 30.0)
                    color: Color.accent
                  }

                  Row {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(12)
                    anchors.rightMargin: Style.space(6)

                    Text {
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.liveTotp ? (root.liveTotp.length === 6 ? root.liveTotp.slice(0, 3) + " " + root.liveTotp.slice(3) : root.liveTotp) : "Loading..."
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.title
                      font.bold: true
                      font.letterSpacing: 2.0
                      width: parent.width - copyTotpBtn.width - Style.space(10)
                    }

                    PanelActionButton {
                      id: copyTotpBtn
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "󰥔"
                      tooltipText: "Copy TOTP code (t)"
                      fontFamily: root.fontFamily
                      enabled: root.liveTotp !== ""
                      onClicked: root.copyToClipboard(root.liveTotp, "TOTP code")
                    }
                  }
                }
              }

              // FIELD: Website / URIs
              Column {
                visible: Boolean(root.detailItem && root.detailItem.uris && root.detailItem.uris.length > 0)
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "WEBSITE" }

                Repeater {
                  model: root.detailItem ? root.detailItem.uris : []
                  delegate: BorderSurface {
                    width: detailContentColumn.width
                    implicitHeight: Style.space(34)
                    radius: Style.cornerRadius
                    color: Style.hoverFillFor(root.fg, Color.accent)
                    borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                    Row {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(6)

                      Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: modelData
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        elide: Text.ElideRight
                        width: parent.width - openUriBtn.width - Style.space(10)
                      }

                      PanelActionButton {
                        id: openUriBtn
                        anchors.verticalCenter: parent.verticalCenter
                        iconText: "󰖟"
                        tooltipText: "Open in browser (o)"
                        fontFamily: root.fontFamily
                        onClicked: root.openUrl(modelData)
                      }
                    }
                  }
                }
              }

              // FIELD: Notes
              Column {
                visible: Boolean(root.detailItem && root.detailItem.notes !== "")
                width: parent.width
                spacing: Style.space(4)

                Row {
                  width: parent.width
                  PanelSectionHeader { text: "NOTES" }
                  Item { Layout.fillWidth: true }
                  PanelActionButton {
                    iconText: "󰈐"
                    tooltipText: "Copy notes"
                    size: Style.space(20)
                    fontFamily: root.fontFamily
                    onClicked: if (root.detailItem) root.copyToClipboard(root.detailItem.notes, "Notes")
                  }
                }

                BorderSurface {
                  width: parent.width
                  implicitHeight: notesText.implicitHeight + Style.space(16)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Text {
                    id: notesText
                    anchors.fill: parent
                    anchors.margins: Style.space(10)
                    text: root.detailItem ? root.detailItem.notes : ""
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.bodySmall
                    wrapMode: Text.Wrap
                  }
                }
              }

            }
          }

        }

        // -------------------------------------------------------------------
        // SCREEN 5: ADD / EDIT ITEM FORM VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.currentScreen === "edit"
          width: parent.width
          spacing: Style.space(10)

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              text: "Cancel (Esc)"
              iconText: "󰁍"
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: root.currentScreen = root.formIsEditing ? "detail" : "main"
            }

            Item { Layout.fillWidth: true }

            Text {
              anchors.verticalCenter: parent.verticalCenter
              text: root.formIsEditing ? "Edit Item" : "New Vault Item"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }
          }

          PanelSeparator { width: parent.width }

          Flickable {
            id: editFlickable
            width: parent.width
            height: Math.min(Style.space(420), editFormCol.implicitHeight)
            contentWidth: width
            contentHeight: editFormCol.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            flickableDirection: Flickable.VerticalFlick
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            Column {
              id: editFormCol
              width: editFlickable.width
              spacing: Style.space(10)

              // Item Type Selector (only for new items)
              Row {
                visible: !root.formIsEditing
                spacing: Style.space(8)

                Button {
                  text: "Login"
                  iconText: "󰌋"
                  selected: root.formTypeCode === 1
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.formTypeCode = 1
                }

                Button {
                  text: "Secure Note"
                  iconText: "󰈐"
                  selected: root.formTypeCode === 2
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.formTypeCode = 2
                }
              }

              // FIELD: Title / Name
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { text: "TITLE / NAME *"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "e.g. GitHub, Google, Work Server..."
                  text: root.formName
                  onTextChanged: root.formName = text
                }
              }

              // FIELD: Vault / Organization Selector
              Column {
                visible: root.organizations.length > 0
                width: parent.width
                spacing: Style.space(3)
                Text { text: "ORGANIZATION / VAULT"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                Row {
                  spacing: Style.space(6)
                  Button {
                    text: "Personal Vault"
                    iconText: ""
                    selected: !root.formOrgId || root.formOrgId === "personal"
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    onClicked: root.formOrgId = ""
                  }
                  Repeater {
                    model: root.organizations
                    delegate: Button {
                      text: modelData.name
                      iconText: "󰓹"
                      selected: root.formOrgId === modelData.id
                      fontFamily: root.fontFamily
                      fontSize: Style.font.caption
                      onClicked: root.formOrgId = modelData.id
                    }
                  }
                }
              }

              // FIELD: Username (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { text: "USERNAME / EMAIL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "username or email address..."
                  text: root.formUsername
                  onTextChanged: root.formUsername = text
                }
              }

              // FIELD: Password with Generator (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Row {
                  width: parent.width
                  Text { text: "PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Item { Layout.fillWidth: true }
                  Button {
                    text: "Generate Strong Password"
                    iconText: "󰑐"
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    onClicked: root.generateAndSetPassword()
                  }
                }
                Row {
                  width: parent.width
                  spacing: Style.space(6)
                  TextField {
                    id: formPassField
                    width: parent.width - eyeBtnForm.width - Style.space(6)
                    placeholderText: "Password..."
                    password: !root.formPasswordRevealed
                    text: root.formPassword
                    onTextChanged: root.formPassword = text
                  }
                  Button {
                    id: eyeBtnForm
                    iconText: root.formPasswordRevealed ? "󰈉" : "󰈈"
                    tooltipText: root.formPasswordRevealed ? "Hide password" : "Show password"
                    fontFamily: root.fontFamily
                    onClicked: root.formPasswordRevealed = !root.formPasswordRevealed
                  }
                }
              }

              // FIELD: TOTP Authenticator Key (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { text: "AUTHENTICATOR KEY (TOTP SECRET)"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "e.g. JBSWY3DPEHPK3PXP (optional)..."
                  text: root.formTotp
                  onTextChanged: root.formTotp = text
                }
              }

              // FIELD: Website URL (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { text: "WEBSITE URL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "https://example.com/login..."
                  text: root.formUri
                  onTextChanged: root.formUri = text
                }
              }

              // FIELD: Notes
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { text: "NOTES"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  width: parent.width
                  placeholderText: "Additional secure notes..."
                  text: root.formNotes
                  onTextChanged: root.formNotes = text
                }
              }

              // Favorite Star Toggle
              Row {
                spacing: Style.space(8)
                Button {
                  text: root.formFavorite ? "★ In Favorites" : "☆ Add to Favorites"
                  selected: root.formFavorite
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onClicked: root.formFavorite = !root.formFavorite
                }
              }

              // Save Action Button
              Button {
                width: parent.width
                text: root.isLoading ? "Saving..." : (root.formIsEditing ? "Save Changes" : "Create Item")
                iconText: root.isLoading ? "󰑐" : "󰄬"
                iconSpinning: root.isLoading
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.isLoading
                onClicked: root.saveItemForm()
              }

              Item { height: Style.space(12); width: 1 }
            }
          }
        }
      }
    }
  }
}
