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
  moduleName: "io.github.elevate08.qs-bitwarden-cli"
  ipcTarget: "io.github.elevate08.qs-bitwarden-cli"
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
  property int settingsIndex: 0
  readonly property var settingsEntries: Model.groupedSettings()

  // Vault data
  property var items: []
  // `bw list items` costs seconds on a large vault, so a reopen reuses what is
  // already in memory until it goes stale. Any mutation reloads unconditionally.
  property double itemsLoadedAt: 0
  property double orgsLoadedAt: 0
  property double foldersLoadedAt: 0
  readonly property int itemsFreshMs: 60000
  // Organizations and folders outlive an item refresh many times over.
  readonly property int metaFreshMs: 600000
  property var filteredItems: []
  property var organizations: []
  property string selectedOrg: "all" // "all" | "personal" | orgId
  property var folders: []
  property string selectedFolder: "all" // "all" | "none" | folderId
  // Which bottom filter group is open: "" | "folders" | "organizations" | "types".
  // Only one at a time, so the panel grows by one list at most.
  property string openFilterGroup: ""
  property int filterOptionIndex: 0

  readonly property int filterRowHeight: Style.space(30)
  readonly property int filterVisibleRows: 5
  readonly property var currentFilterOptions: openFilterGroup === "" ? [] : filterOptions(openFilterGroup)
  // The drawer's own height. The panel adds this to its cap so the window
  // opens downward like a drawer instead of squeezing the item list.
  readonly property int filterDrawerHeight: openFilterGroup === ""
    ? 0
    : Style.space(30) + Math.min(filterVisibleRows, currentFilterOptions.length) * filterRowHeight + Style.space(8)
  property string formFolderId: ""
  property string newFolderName: ""
  // Which picker in the item form is expanded: "" | "folder" | "organization"
  property string formPicker: ""
  property var formCollections: []
  property var formCollectionIds: []
  property bool formCollectionsLoading: false
  property bool creatingFolder: false
  property string searchQuery: ""
  property string selectedCategory: "all"
  property int selectedIndex: 0

  // Selected item detail
  property var detailItem: null
  property string detailPassword: ""
  property bool passwordRevealed: false
  property string liveTotp: ""
  property int totpSecRemaining: 30

  // Attachment downloads. One `bw get attachment` runs at a time and the rest
  // wait in the queue, so "Save all" on an item with six files does not fire
  // six CLI bootstraps at once. `attachmentSaved` maps an attachment id to the
  // path it landed on, which is what turns the row's Download button into Open
  // and Show in folder; it is cleared whenever a different item is opened.
  property var attachmentQueue: []
  property string attachmentBusyId: ""
  property var attachmentSaved: ({})

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
  // The value the keyring store process reads. Set from whichever path is
  // storing: the explicit setup form, or the automatic refresh after unlock.
  property string masterToStore: ""
  // Item JSON on its way to `bw encode`. Held here so the create/edit processes
  // can pass it in the environment instead of on the command line.
  property string itemPayloadJson: ""
  property bool fpSetupActive: false
  property string fpSetupMaster: ""
  property string fpError: ""
  property bool fpBusy: false
  // Which credential source drove the in-flight unlock, so a stale stored
  // secret can be discarded rather than retried forever. "" | "fingerprint" | "pin"
  property string pendingUnlockFrom: ""

  // Send state
  property var sends: []
  property bool sendsLoading: false
  property string sendMode: "list"      // "list" | "create"
  property string sendPayloadJson: ""
  property bool sendBusy: false
  property string sendError: ""
  property string sendFormName: ""
  property string sendFormText: ""
  property bool sendFormHidden: false
  property int sendFormDays: 7
  property int sendFormMaxAccess: 0
  property string sendFormPassword: ""
  property int sendIndex: 0

  // Generator state (session-scoped, mirroring the browser extension's options)
  property var genOpts: Model.generatorDefaults()
  property string genValue: ""
  property bool genBusy: false
  // `bw serve` state. Ready means the loopback generator answered; failed
  // means we stopped trying and the CLI carries the feature instead -- most
  // likely because something else already holds the port, in which case we
  // must not talk to it: a "generated password" from a stranger's server is
  // a password they know.
  property bool generateServeReady: false
  property bool generateServeStarting: false
  property bool generateServeFailed: false
  // Set while we are the ones shutting the server down, so its exit is not
  // mistaken for the bind failure that gives up on the port.
  property bool generateServeStopping: false
  // Where Back and Esc go, and whether the generator can hand its value
  // somewhere. Opened from the item form it fills the password field in and
  // returns; opened on its own it is just the generator. One screen either
  // way, so the item form offers Bitwarden's own generator rather than a
  // second, weaker one of its own.
  property string generatorReturnScreen: "main"
  readonly property bool generatorFeedsForm: generatorReturnScreen === "edit"

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
  // Long enough to save, short enough to be a bad idea. Drives the red state
  // on the PIN field during setup; see pinWeakWarning() in BitwardenModel.js.
  readonly property bool pinSetupWeak: Model.isPinWeak(pinSetupPin)
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
    { id: "secureNote", label: "Notes", icon: "󰈙" },
    { id: "card", label: "Cards", icon: "󰿯" },
    { id: "identity", label: "Identities", icon: "" },
    { id: "favorite", label: "Favorites", icon: "󰓒" }
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
    // A half-typed PIN and either setup form's master password are abandoned
    // by closing the panel just as surely as by cancelling, and reopening
    // never lands back on those screens.
    pinEntry = ""
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
    fpSetupMaster = ""
    cancelFingerprintUnlock()
    stopGeneratorServe()
    root.controller.hide()
  }

  function toggle() {
    if (opened) close()
    else open()
  }

  function detectActiveWindowContext() {
    if (!suggestOnOpen) return
    activeWindowProc.command = ["sh", "-c", "hyprctl activewindow -j 2>/dev/null | grep -q '\"class\": \"[^\"]' && (hyprctl activewindow -j 2>/dev/null | head -c 65536) || (hyprctl clients -j 2>/dev/null | head -c 1048576)"]
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
      // Still check for a handed-over session: a terminal login leaves the
      // panel locked, which is precisely when the handoff matters.
      refreshStatus()
      startFingerprintUnlock()
    } else {
      refreshStatus()
    }
  }

  // -------------------------------------------------------------------------
  // Status & Keyring Handlers
  // -------------------------------------------------------------------------

  function refreshStatus() {
    errorMessage = ""
    // A terminal login may have left a session waiting. Check before anything
    // else, including the locked-with-no-session short circuit below, since
    // that is exactly the state a terminal login leaves the panel in.
    if (!sessionHandoffProc.running) sessionHandoffProc.running = true
  }

  function onSessionHandoff(raw) {
    var handed = Model.extractSessionToken(String(raw || "").trim())
    if (handed) {
      session = handed
      if (rememberSession) keyringStoreProc.running = true

      // bw minted this key moments ago, so trust it and start loading rather
      // than spending another `bw status` (~3.3s) to be told what we know.
      // The status check still runs, but alongside the loads instead of in
      // front of them -- it only fills in the account email.
      status = "unlocked"
      currentScreen = "main"
      itemsLoadedAt = 0
      loadItems()
      loadOrganizations()
      loadFolders()
      resetAutoLockTimer()
      focusAppropriateField()
      statusProc.command = Model.statusCommand()
      statusProc.running = true
      flashNotification("Signed in from the terminal")
      return
    }

    if (status === "locked" && !session) return

    if (session) {
      statusProc.command = Model.statusCommand()
      statusProc.running = true
    } else if (rememberSession && status !== "locked") {
      keyringLookupProc.running = true
    } else {
      statusProc.command = Model.statusCommand()
      statusProc.running = true
    }
  }

  function onKeyringLookupFinished(rawToken) {
    var token = String(rawToken || "").trim()
    if (token) {
      session = token
      statusProc.command = Model.statusCommand()
      statusProc.running = true
    } else {
      statusProc.command = Model.statusCommand()
      statusProc.running = true
    }
  }

  function onKeyringLookupFailed() {
    statusProc.command = Model.statusCommand()
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
      // The password and the code go to loginProc through the environment;
      // only whether a code was entered shapes the command itself.
      loginProc.command = Model.emailLoginCommand(email, login2faCode.trim().length > 0, loginServerUrl.trim())
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
      // Client ID, client secret and password all travel in the environment.
      loginProc.command = Model.apiKeyLoginCommand(loginServerUrl.trim())
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
    // The panel knows whether this is a login or an unlock, so the terminal
    // does not have to spend a `bw status` round trip working it out.
    var mode = (status === "locked") ? "unlock" : "login"
    close()
    Quickshell.execDetached(Model.terminalLoginCommand(mode))
  }

  function logoutAccount() {
    lockVault()
    forgetStoredCredentials()
    pendingUnlockPassword = ""
    logoutProc.command = Model.logoutCommand()
    logoutProc.running = true
    status = "unauthenticated"
    currentScreen = "login"
    userEmail = ""
    flashNotification("Logged out")
  }

  // Logging out takes the keyring with it. Two of the entries there are the
  // master password -- fingerprint unlock keeps it as it is, PIN unlock keeps
  // it encrypted -- and both are written to the default collection so they
  // survive a reboot, which is exactly why a logout has to be the end of them.
  //
  // Nothing here asks whether we think an entry exists. `fingerprintStored`
  // and `pinConfigured` describe what the settings screen last saw, and both
  // go false for reasons that leave the keyring untouched: an unplugged
  // reader, an uninstalled fprintd, a dependency probe that has not answered
  // yet. Gating the clear on them is how a master password came to outlive the
  // account it belonged to. See keyringClearAllCommand() for why asking
  // unconditionally is free.
  function forgetStoredCredentials() {
    keyringClearAllProc.running = true
    cancelFingerprintUnlock()
    fingerprintStored = false
    fingerprintMessage = ""
    pinConfigured = false
    pinEntry = ""
    pinAttempts = 0
    pinError = ""
    if (pinUnlock) writeSetting("pinUnlock", false, "bool")
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

  // BW_SESSION rather than --session: bw reads it natively, and it keeps the
  // token out of /proc/<pid>/cmdline, which any local user can read.
  function bwEnv(extra) {
    var env = {}
    if (session) env[Model.sessionEnvVar()] = String(session)
    if (extra) for (var k in extra) env[k] = extra[k]
    return env
  }

  // The credentials that unlock the vault, handed to bw the same way the
  // session token is: through the environment. bw reads BW_PASSWORD (named by
  // --passwordenv), BW_CLIENTID and BW_CLIENTSECRET natively, so none of them
  // reaches an argv -- neither bw's nor that of the shell wrapping it.
  // /proc/<pid>/cmdline is world-readable on a default install; environ is not.
  //
  // Read as a binding by loginProc and unlockProc, so it always reflects the
  // fields as they are when the process starts.
  function authEnv(password, clientId, clientSecret, code) {
    var env = bwEnv()
    env[Model.noInteractionEnvVar()] = "true"
    if (password) env[Model.passwordEnvVar()] = String(password)
    if (clientId) env[Model.clientIdEnvVar()] = String(clientId)
    if (clientSecret) env[Model.clientSecretEnvVar()] = String(clientSecret)
    // The only one bw has no environment option for; see the comment on
    // TWOFACTOR_CODE_ENV in BitwardenModel.js.
    if (code) env[Model.twoFactorCodeEnvVar()] = String(code)
    return env
  }

  function itemEnv() {
    var e = {}
    e[Model.itemEnvVar()] = String(itemPayloadJson || "")
    return bwEnv(e)
  }

  function sendEnv(json) {
    var e = {}
    e[Model.sendEnvVar()] = String(json || "")
    return bwEnv(e)
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
  // Bitwarden Send
  // -------------------------------------------------------------------------

  function openSends() {
    closeFilterGroup()
    sendMode = "list"
    sendError = ""
    sendIndex = 0
    currentScreen = "sends"
    loadSends()
  }

  function loadSends() {
    if (!session) return
    sendsLoading = true
    listSendsProc.command = Model.listSendsCommand()
    listSendsProc.running = true
  }

  function onSendsLoaded(raw) {
    sendsLoading = false
    sends = Model.parseSends(raw)
    if (sendIndex >= sends.length) sendIndex = Math.max(0, sends.length - 1)
  }

  function beginCreateSend() {
    sendFormName = ""
    sendFormText = ""
    sendFormHidden = false
    sendFormDays = 7
    sendFormMaxAccess = 0
    sendFormPassword = ""
    sendError = ""
    sendMode = "create"
    Qt.callLater(function() { sendNameField.forceActiveFocus() })
  }

  function submitCreateSend() {
    if (!String(sendFormText || "").trim()) {
      sendError = "Nothing to send -- enter some text"
      return
    }
    sendError = ""
    sendBusy = true
    sendPayloadJson = JSON.stringify(Model.buildSendPayload(
      sendFormName, sendFormText, sendFormHidden,
      sendFormDays, sendFormMaxAccess, sendFormPassword, ""))
    createSendProc.command = Model.createSendCommand()
    createSendProc.running = true
  }

  function onSendCreated(exitCode, stdoutText, stderrText) {
    sendBusy = false
    sendPayloadJson = ""
    if (exitCode !== 0) {
      sendError = String(stderrText || "").trim() || "Could not create the Send"
      return
    }
    // bw prints the access URL; put it straight on the clipboard, since a Send
    // is useless until the link reaches someone.
    var created = null
    try { created = JSON.parse(stdoutText) } catch (e) { created = null }
    var url = created && created.accessUrl ? String(created.accessUrl) : String(stdoutText || "").trim()
    if (url) {
      copyToClipboard(url, "Send link")
    } else {
      flashNotification("Send created")
    }
    sendFormText = ""
    sendFormPassword = ""
    sendMode = "list"
    loadSends()
  }

  function copySendLink(send) {
    if (!send || !send.accessUrl) return
    copyToClipboard(send.accessUrl, "Send link")
  }

  function deleteSend(send) {
    if (!send || !send.id) return
    sendBusy = true
    deleteSendProc.command = Model.deleteSendCommand(send.id)
    deleteSendProc.running = true
  }

  function onSendDeleted(exitCode) {
    sendBusy = false
    if (exitCode !== 0) {
      sendError = "Could not delete the Send"
      return
    }
    flashNotification("Send deleted")
    loadSends()
  }

  function moveSendCursor(delta) {
    if (sends.length === 0) return
    sendIndex = Math.max(0, Math.min(sends.length - 1, sendIndex + delta))
  }

  // -------------------------------------------------------------------------
  // Generator
  // -------------------------------------------------------------------------

  // Reached from the header button on any screen and from the item form's
  // Generate button, which is the same thing: the form is just a caller that
  // wants the value back.
  function openGenerator() {
    closeFilterGroup()
    generatorReturnScreen = (currentScreen === "edit") ? "edit" : "main"
    screenBeforeSettings = "main"
    currentScreen = "generator"
    // A form asking for a password wants a new one every time. A standalone
    // visit keeps whatever was last generated, so reopening does not throw
    // away a value you were about to copy.
    if (generatorFeedsForm || !genValue) regenerate()
  }

  function closeGenerator() {
    var toForm = generatorFeedsForm
    currentScreen = generatorReturnScreen
    generatorReturnScreen = "main"
    // Land back on the field the trip was about, filled in or not.
    if (toForm) Qt.callLater(function() { formPassField.forceActiveFocus() })
  }

  // The whole point of the round trip: put the value in the field the caller
  // was on, and go back to it.
  function useGeneratedPassword() {
    if (!generatorFeedsForm || !genValue) return
    formPassword = genValue
    // Show it. A password you cannot read is hard to trust, and it is going
    // into a form you are still filling in rather than straight to the vault.
    formPasswordRevealed = true
    closeGenerator()
    flashNotification("Generated password filled in")
  }

  // Generation is delegated to Bitwarden's own generator either way; the only
  // question is how we reach it. `bw serve` answers in ~2ms against ~2.9s for
  // a fresh `bw generate`, so the server is started on first use and the CLI
  // stays as the fallback for when it cannot be.
  function regenerate() {
    genBusy = true
    if (generateServeReady) {
      requestGeneratedValue()
      return
    }
    startGeneratorServe()
    // Nothing to wait on if the server is already coming up -- onExited or the
    // ready poll will drive the request.
    if (!generateServeStarting) regenerateViaCli()
  }

  function regenerateViaCli() {
    genBusy = true
    generateProc.command = Model.generateCommand(genOpts)
    generateProc.running = true
  }

  // A locked server: no session in its environment, so it can generate and
  // nothing else. See the comment on generateServeCommand in BitwardenModel.js
  // for why that restriction is the whole point.
  function generatorServeEnv() {
    var env = {}
    env[Model.sessionEnvVar()] = null
    env[Model.noInteractionEnvVar()] = "true"
    return env
  }

  // Nothing about an HTTP 200 proves the process that sent it is ours. Another
  // account can bind the port first and answer /generate with passwords it
  // already knows, and the panel would show one as freshly generated. There is
  // no handshake to lean on -- `bw serve` prints no banner and offers no
  // authentication -- so the evidence has to be that the port was silent before
  // our own server took it. Anything already answering means the serve path is
  // not available, and the CLI carries the feature instead.
  function startGeneratorServe() {
    if (generateServeReady || generateServeStarting || generateServeFailed) return
    generateServeStarting = true
    probeGeneratorPort()
  }

  function probeGeneratorPort() {
    var req = new XMLHttpRequest()
    req.onreadystatechange = function() {
      if (req.readyState !== XMLHttpRequest.DONE) return
      if (Model.generatorPortIsForeign(req.status)) {
        root.generateServeStarting = false
        root.generateServeFailed = true
        if (root.genBusy) root.regenerateViaCli()
        return
      }
      // The screen can close while a probe is in flight, and starting a server
      // for a screen nobody is looking at is the exposure this all avoids.
      if (root.currentScreen !== "generator") {
        root.generateServeStarting = false
        return
      }
      generateServeProc.running = true
      generateServePoll.attempts = 0
      generateServePoll.restart()
    }
    req.open("GET", Model.generateServeUrl(root.genOpts))
    req.send()
  }

  function stopGeneratorServe() {
    generateServePoll.stop()
    generateServeStarting = false
    generateServeReady = false
    // A deliberate shutdown is not the permanent bind failure, so the next
    // visit is free to start a server again.
    generateServeFailed = false
    if (generateServeProc.running) {
      generateServeStopping = true
      generateServeProc.running = false
    }
  }

  // The server is up when it answers. Polling rather than trusting a fixed
  // delay: bw takes a couple of seconds to bind, and the first generator open
  // should not sit behind a guess.
  function pollGeneratorServe() {
    var req = new XMLHttpRequest()
    req.onreadystatechange = function() {
      if (req.readyState !== XMLHttpRequest.DONE) return
      if (req.status === 200 && Model.parseServeGenerated(req.responseText)) {
        generateServeStarting = false
        generateServeReady = true
        generateServePoll.stop()
        onGenerated(Model.parseServeGenerated(req.responseText), 0)
      }
    }
    req.open("GET", Model.generateServeUrl(genOpts))
    req.send()
  }

  function requestGeneratedValue() {
    var req = new XMLHttpRequest()
    req.onreadystatechange = function() {
      if (req.readyState !== XMLHttpRequest.DONE) return
      var value = req.status === 200 ? Model.parseServeGenerated(req.responseText) : ""
      if (value) {
        onGenerated(value, 0)
        return
      }
      // The server went away mid-session; fall back and stop trusting it.
      root.generateServeReady = false
      root.regenerateViaCli()
    }
    req.open("GET", Model.generateServeUrl(genOpts))
    req.send()
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

  // A setting whose dependency is missing is inert; the cursor may sit on it,
  // but changing it would silently do nothing.
  function settingBlocked(entry) {
    if (!entry || !entry.requires) return false
    for (var i = 0; i < dependencies.items.length; i++) {
      if (dependencies.items[i].key === entry.requires) return !dependencies.items[i].ready
    }
    return false
  }

  function moveSettingsCursor(delta) {
    var n = settingsEntries.length
    if (n === 0) return
    settingsIndex = Math.max(0, Math.min(n - 1, settingsIndex + delta))
  }

  // Left/right nudge a value: numbers by their step, switches off and on.
  function adjustSetting(direction) {
    var e = settingsEntries[settingsIndex]
    if (!e || settingBlocked(e)) return

    if (e.type === "int") {
      var cur = Number(settingValue(e))
      var step = e.step || 1
      var next = Math.max(e.min || 0, Math.min(e.max || 100, cur + direction * step))
      if (next !== cur) writeSetting(e.key, next, "int")
      return
    }

    if (e.type === "bool") {
      var want = direction > 0
      if (Boolean(settingValue(e)) !== want) activateSettingRow()
    }
  }

  function activateSettingRow() {
    var e = settingsEntries[settingsIndex]
    if (!e || settingBlocked(e)) return

    // These two open a form rather than flipping a value.
    if (e.action === "pin") {
      if (pinConfigured) disablePinUnlock()
      else beginPinSetup()
      return
    }
    if (e.action === "fingerprint") {
      if (fingerprintStored) forgetFingerprintUnlock()
      else beginFingerprintSetup()
      return
    }
    if (e.type === "bool") writeSetting(e.key, !settingValue(e), "bool")
  }

  function openSettings() {
    closeFilterGroup()
    if (currentScreen !== "settings") screenBeforeSettings = currentScreen
    settingsFlash = ""
    settingsIndex = 0
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
      case "fingerprintUnlock": return fingerprintUnlock && fingerprintStored
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

  // Enrolling asks for the master password up front, the same way setting a
  // PIN does, rather than silently capturing it on some later unlock.
  function beginFingerprintSetup() {
    fpSetupMaster = ""
    fpError = ""
    currentScreen = "fingerprint"
    Qt.callLater(function() { fpMasterField.forceActiveFocus() })
  }

  function submitFingerprintSetup() {
    if (!fpSetupMaster) {
      fpError = "Master password is required to enable fingerprint unlock"
      return
    }
    fpError = ""
    fpBusy = true
    fpSetupActive = true
    masterToStore = fpSetupMaster
    keyringStoreMasterProc.running = true
  }

  function onMasterPasswordStored(exitCode) {
    masterToStore = ""
    pendingUnlockPassword = ""
    fingerprintStored = (exitCode === 0)

    if (fpSetupActive) {
      fpSetupActive = false
      fpBusy = false
      fpSetupMaster = ""
      if (exitCode !== 0) {
        fpError = "Could not save the master password. Is the OS keyring available?"
        return
      }
      writeSetting("fingerprintUnlock", true, "bool")
      flashNotification("Fingerprint unlock enabled")
      currentScreen = "settings"
      return
    }

    if (exitCode !== 0) {
      errorMessage = "Could not save master password to the OS keyring, so fingerprint unlock is unavailable."
    }
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
      // Not `if (fingerprintStored)`. That flag is false whenever the reader
      // or fprintd is missing, which says nothing about whether the master
      // password is still sitting in the keyring -- and turning the feature
      // off is precisely when it must not be.
      forgetFingerprintUnlock()
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
    // unlockProc reads it as the BW_PASSWORD binding, so it must be set before
    // the process starts.
    pendingUnlockPassword = p
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
    // Keep an existing enrolment current after a master password change. It no
    // longer creates one -- that is what the setup form is for.
    if (fingerprintUnlock && fingerprintAvailable && fingerprintStored
        && pendingUnlockPassword && pendingUnlockFrom === "") {
      masterToStore = pendingUnlockPassword
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
    loadFolders()
    resetAutoLockTimer()
    focusAppropriateField()
  }

  function lockVault() {
    closeFilterGroup()
    if (session) {
      lockProc.command = Model.lockCommand()
      lockProc.running = true
    }
    // Not `if (rememberSession)`. The setting says whether to write a token,
    // not whether one is there: turning it off after a session was remembered
    // used to mean the lock skipped the erase and left the token behind.
    // Clearing an entry that was never written is a no-op nobody reads.
    keyringClearProc.running = true

    session = ""
    masterPassword = ""
    itemsLoadedAt = 0
    orgsLoadedAt = 0
    foldersLoadedAt = 0
    status = "locked"
    currentScreen = "locked"
    items = []
    filteredItems = []
    organizations = []
    detailItem = null
    totpFollowupActive = false
    isUnlocking = false
    pendingUnlockPassword = ""
    fingerprintMessage = ""
    dropVaultSecrets()
    flashNotification("Vault locked")
    focusAppropriateField()
    if (opened) startFingerprintUnlock()
  }

  // A locked vault means the panel is holding nothing out of it, and nothing
  // that would open it again. detailPassword and liveTotp were always dropped
  // here; the rest were not, and each of them is the same kind of thing -- a
  // generated password nobody copied, an item or Send form left mid-compose,
  // the payload JSON on its way to bw, the master password typed into whichever
  // setup form was open. The vault relocks after fifteen idle minutes and the
  // shell process lives for the whole desktop session, so a property that
  // survives a lock survives everything.
  function dropVaultSecrets() {
    detailPassword = ""
    liveTotp = ""
    totpFollowupItem = null
    totpFollowupCode = ""
    genValue = ""
    formPassword = ""
    formTotp = ""
    itemPayloadJson = ""
    sends = []
    sendPayloadJson = ""
    sendFormText = ""
    sendFormPassword = ""
    loginPassword = ""
    loginClientSecret = ""
    pinEntry = ""
    pinSetupPin = ""
    pinSetupConfirm = ""
    pinSetupMaster = ""
    fpSetupMaster = ""
    masterToStore = ""
  }

  // -------------------------------------------------------------------------
  // Vault Data Operations
  // -------------------------------------------------------------------------

  // Open-time load: skip the CLI entirely when the cached vault is still fresh.
  // Stale-while-revalidate. `bw list items` is a CLI bootstrap plus a full
  // vault decrypt, so blocking the panel on it means a spinner on every open
  // once the cache ages out. Show what we already have immediately, refresh
  // behind it, and swap the list in when it lands. The spinner is only for
  // the case where there is genuinely nothing to show yet.
  function ensureItemsFresh() {
    var haveItems = items.length > 0
    var stale = (Date.now() - itemsLoadedAt) >= itemsFreshMs

    if (haveItems) {
      if (activeWindowData) handleActiveWindowDetected(activeWindowData)
      else rebuildFilter()
      if (!stale) return
    }

    loadItems(!haveItems)
    // Organizations and folders change far less often than items and cost a
    // separate `bw` each, so they get their own, longer freshness window.
    loadOrganizations()
    loadFolders()
  }

  // `showSpinner` defaults to true, so existing callers are unchanged; a
  // background revalidation passes false and refreshes without the UI moving.
  function loadItems(showSpinner) {
    if (!session) return
    if (showSpinner !== false) isLoading = true
    listProc.command = Model.listCommand()
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

  // Each of these is its own `bw` invocation, and organizations and folders
  // change rarely -- new ones arrive through this panel, which invalidates
  // them explicitly. `force` is for exactly that case.
  function loadOrganizations(force) {
    if (!session) return
    if (!force && organizations.length > 0 && (Date.now() - orgsLoadedAt) < metaFreshMs) return
    listOrgsProc.command = Model.listOrganizationsCommand()
    listOrgsProc.running = true
  }

  function onListOrgsFinished(rawJson) {
    organizations = Model.parseOrganizations(rawJson)
    orgsLoadedAt = Date.now()
  }

  function loadFolders(force) {
    if (!session) return
    if (!force && folders.length > 0 && (Date.now() - foldersLoadedAt) < metaFreshMs) return
    listFoldersProc.command = Model.listFoldersCommand()
    listFoldersProc.running = true
  }

  function onListFoldersFinished(rawJson) {
    folders = Model.parseFolders(rawJson)
    foldersLoadedAt = Date.now()
  }

  function selectFolder(folderId) {
    selectedFolder = folderId
    selectedIndex = 0
    openFilterGroup = ""
    rebuildFilter()
  }

  function toggleFilterGroup(group) {
    if (openFilterGroup === group) {
      openFilterGroup = ""
      return
    }
    openFilterGroup = group
    // Start on whichever option is currently active, so Enter is a no-op
    // rather than a surprise.
    var opts = filterOptions(group)
    filterOptionIndex = 0
    for (var i = 0; i < opts.length; i++) {
      if (opts[i].active) { filterOptionIndex = i; break }
    }
  }

  // Any action that is not part of the drawer closes it, so it never lingers
  // over the results the user just filtered down to.
  function closeFilterGroup() {
    if (openFilterGroup !== "") openFilterGroup = ""
  }

  function moveFilterCursor(delta) {
    var n = currentFilterOptions.length
    if (n === 0) return
    filterOptionIndex = Math.max(0, Math.min(n - 1, filterOptionIndex + delta))
  }

  function activateFilterOption() {
    var opts = currentFilterOptions
    if (filterOptionIndex < 0 || filterOptionIndex >= opts.length) return
    applyFilterOption(openFilterGroup, opts[filterOptionIndex].id)
  }

  // Labels for the collapsed buttons, so the current filter is readable
  // without opening anything.
  function folderFilterLabel() {
    if (selectedFolder === "all") return "All"
    if (selectedFolder === "none") return "Unfiled"
    return Model.folderName(folders, selectedFolder) || "Folder"
  }

  function organizationFilterLabel() {
    if (selectedOrg === "all") return "All"
    if (selectedOrg === "personal") return "Personal"
    for (var i = 0; i < organizations.length; i++) {
      if (organizations[i].id === selectedOrg) return organizations[i].name
    }
    return "Vault"
  }

  function typeFilterLabel() {
    for (var i = 0; i < categories.length; i++) {
      if (categories[i].id === selectedCategory) return categories[i].label
    }
    return "All"
  }

  // Option rows for whichever group is open, in one shape so the three lists
  // render identically.
  function filterOptions(group) {
    var out = []
    var i
    if (group === "folders") {
      out.push({ id: "all", label: "All Folders", icon: "󰉋", active: selectedFolder === "all" })
      out.push({ id: "none", label: "No Folder", icon: "󰉖", active: selectedFolder === "none" })
      for (i = 0; i < folders.length; i++) {
        out.push({ id: folders[i].id, label: folders[i].name, icon: "󰉋", active: selectedFolder === folders[i].id })
      }
    } else if (group === "organizations") {
      out.push({ id: "all", label: "All Organizations", icon: "󰦑", active: selectedOrg === "all" })
      out.push({ id: "personal", label: "My Vault", icon: "", active: selectedOrg === "personal" })
      for (i = 0; i < organizations.length; i++) {
        out.push({ id: organizations[i].id, label: organizations[i].name, icon: "󰓹", active: selectedOrg === organizations[i].id })
      }
    } else if (group === "types") {
      for (i = 0; i < categories.length; i++) {
        out.push({ id: categories[i].id, label: categories[i].label, icon: categories[i].icon, active: selectedCategory === categories[i].id })
      }
    }
    return out
  }

  function applyFilterOption(group, id) {
    if (group === "folders") selectFolder(id)
    else if (group === "organizations") { selectOrganization(id); openFilterGroup = "" }
    else if (group === "types") { selectCategory(id); openFilterGroup = "" }
  }

  function toggleFormPicker(which) {
    formPicker = (formPicker === which) ? "" : which
  }

  // What Escape does, wherever it is pressed. Kept here rather than inline in
  // the key handler because it has two callers: PanelKeyCatcher's
  // closeRequested, and the shortcut interceptor -- the catcher goes `blocked`
  // on every screen with a text field, which used to take Escape down with it.
  //
  // Innermost thing first: a drawer or picker closes before the screen it is
  // on, and a screen goes back before the panel closes.
  function handleEscape() {
    if (openFilterGroup !== "") {
      closeFilterGroup()
      return
    }
    if (currentScreen === "edit" && formPicker !== "") {
      formPicker = ""
      return
    }
    if (currentScreen === "sends") {
      if (sendMode === "create") {
        sendError = ""
        sendMode = "list"
        // Leaving the composer does not change the screen, so nothing else
        // takes focus off its (now hidden) name field.
        restoreScreenFocus()
      } else {
        currentScreen = "main"
      }
    } else if (currentScreen === "generator") {
      // Back to the item form when that is where this came from, leaving
      // the password field as it was.
      closeGenerator()
    } else if (currentScreen === "fingerprint") {
      fpError = ""
      currentScreen = "settings"
    } else if (currentScreen === "pin") {
      pinError = ""
      currentScreen = "settings"
    } else if (currentScreen === "settings") {
      closeSettings()
    } else if (currentScreen === "setup") {
      setupDismissed = true
      currentScreen = status === "unlocked" ? "main"
        : (status === "locked" ? "locked" : "login")
    } else if (currentScreen === "edit") {
      // Editing is abandoned, not saved -- the form is scratch space until
      // Save, and Escape is how you throw it away. Back where the form was
      // opened from, which is what the form's own Cancel button does.
      currentScreen = formIsEditing ? "detail" : "main"
    } else if (currentScreen === "detail") {
      currentScreen = "main"
    } else {
      close()
    }
  }

  // Qt does not clear active focus when an item is hidden, so leaving a screen
  // whose field had focus leaves that field owning the keyboard from behind
  // whatever replaced it -- which is how Escape on the item form reached the
  // search box and closed the panel. Re-home focus whenever the screen
  // changes, and the stale owner goes with it.
  onCurrentScreenChanged: {
    // The server lives as long as the screen that needs it and no longer. A
    // loopback port has no authentication and every account on the machine can
    // reach it, and `bw serve` answers /status with the account email and user
    // id whether the vault is locked or not. Holding that open for hours to
    // save a second on a screen visited for a few is the wrong trade.
    if (currentScreen !== "generator") stopGeneratorServe()
    // Both setup forms ask for the master password, and both used to keep it
    // for the rest of the shell's life: Cancel and Escape only reset the error
    // line. Leaving the form is the answer either way, so the clearing lives
    // here rather than at each of the ways out.
    if (currentScreen !== "pin") {
      pinSetupPin = ""
      pinSetupConfirm = ""
      pinSetupMaster = ""
    }
    if (currentScreen !== "fingerprint") fpSetupMaster = ""
    restoreScreenFocus()
  }

  function restoreScreenFocus() {
    Qt.callLater(function() {
      if (status !== "unlocked") { focusAppropriateField(); return }
      switch (currentScreen) {
        case "main": searchField.forceActiveFocus(); return
        case "edit": formNameField.forceActiveFocus(); return
        // These open through a function that focuses their own first field.
        case "pin": case "fingerprint": return
        case "sends": if (sendMode === "create") return; break
      }
      // Everything else is keyboard-navigated rather than typed into.
      keyCatcher.forceActiveFocus()
    })
  }

  function setFormFolder(id) {
    formFolderId = id
    formPicker = ""
  }

  // Changing owner invalidates the collection choice: collections belong to a
  // single organization, and a personal item cannot have any.
  function setFormOrganization(id) {
    formOrgId = id
    formPicker = ""
    formCollectionIds = []
    formCollections = []
    if (id && id !== "personal" && id !== "all") loadOrgCollections(id)
  }

  function loadOrgCollections(orgId) {
    if (!session || !orgId) return
    formCollectionsLoading = true
    orgCollectionsProc.command = Model.listOrgCollectionsCommand(orgId)
    orgCollectionsProc.running = true
  }

  function onOrgCollectionsLoaded(raw) {
    formCollectionsLoading = false
    formCollections = Model.parseCollections(raw)
    // A single collection is not a choice; pre-select it.
    if (formCollections.length === 1 && formCollectionIds.length === 0) {
      formCollectionIds = [formCollections[0].id]
    }
  }

  function toggleFormCollection(id) {
    var next = []
    var found = false
    for (var i = 0; i < formCollectionIds.length; i++) {
      if (formCollectionIds[i] === id) found = true
      else next.push(formCollectionIds[i])
    }
    if (!found) next.push(id)
    formCollectionIds = next
  }

  function isFormCollectionSelected(id) {
    for (var i = 0; i < formCollectionIds.length; i++) {
      if (formCollectionIds[i] === id) return true
    }
    return false
  }

  function formFolderLabel() {
    if (!formFolderId) return "No Folder"
    return Model.folderName(folders, formFolderId) || "No Folder"
  }

  function formOrgLabel() {
    if (!formOrgId || formOrgId === "personal") return "My Vault"
    for (var i = 0; i < organizations.length; i++) {
      if (organizations[i].id === formOrgId) return organizations[i].name
    }
    return "My Vault"
  }

  function submitNewFolder() {
    var name = String(newFolderName || "").trim()
    if (!name) return
    creatingFolder = true
    createFolderProc.command = Model.createFolderCommand(name)
    createFolderProc.running = true
  }

  function onFolderCreated(exitCode, stdoutText) {
    creatingFolder = false
    if (exitCode !== 0) {
      errorMessage = "Could not create folder"
      return
    }
    var created = null
    try { created = JSON.parse(stdoutText) } catch (e) { created = null }
    newFolderName = ""
    // Creating a folder from the item form is only ever a prelude to filing
    // the item into it, so select it straight away.
    if (created && created.id) formFolderId = String(created.id)
    flashNotification("Folder created")
    loadFolders(true)
  }

  function syncVault() {
    closeFilterGroup()
    if (!session) return
    isSyncing = true
    syncProc.command = Model.syncCommand()
    syncProc.running = true
  }

  function onSyncFinished(exitCode) {
    isSyncing = false
    if (exitCode === 0) {
      flashNotification("Vault synced with Bitwarden")
      itemsLoadedAt = 0
      loadItems()
      loadOrganizations(true)
      loadFolders(true)
    } else {
      errorMessage = "Sync failed"
    }
  }

  function openDetail(item) {
    closeFilterGroup()
    if (!item || !item.id) return
    learnFromPick(item)
    isLoading = true
    errorMessage = ""
    passwordRevealed = false
    showDeleteConfirm = false
    detailItem = null
    detailPassword = ""
    liveTotp = ""
    // Another item's downloads say nothing about this one's.
    attachmentQueue = []
    attachmentSaved = ({})
    currentScreen = "detail"

    // The list already fetched the whole item, so render from that rather than
    // spending a second CLI round trip on data we are holding. Only fall back
    // to `bw get item` if this item somehow arrived without its raw object.
    var detail = item.rawObject ? Model.itemDetailFromObject(item.rawObject) : null
    if (detail) {
      isLoading = false
      detailItem = detail
      detailPassword = detail.password
    } else {
      getItemProc.command = Model.getItemCommand(item.id)
      getItemProc.running = true
    }

    // The TOTP code is time-based, so it is the one thing the list cannot
    // carry. It loads alongside rather than in front of the detail view.
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

  // -------------------------------------------------------------------------
  // Attachments
  // -------------------------------------------------------------------------

  function queueAttachment(att) {
    if (!detailItem || !att || !att.id) return
    if (attachmentBusyId === att.id) return
    for (var i = 0; i < attachmentQueue.length; i++) {
      if (attachmentQueue[i].id === att.id) return
    }
    resetAutoLockTimer()
    errorMessage = ""
    var next = attachmentQueue.slice()
    // The declared size travels with the job so the saver can refuse an
    // oversized attachment before it starts, and check the disk has room.
    next.push({ id: att.id, fileName: att.fileName, itemId: detailItem.id, size: att.size })
    attachmentQueue = next
    pumpAttachmentQueue()
  }

  function saveAllAttachments() {
    if (!detailItem || !detailItem.attachments) return
    for (var i = 0; i < detailItem.attachments.length; i++) {
      queueAttachment(detailItem.attachments[i])
    }
  }

  function pumpAttachmentQueue() {
    if (attachmentBusyId !== "" || attachmentQueue.length === 0) return
    if (!session) {
      attachmentQueue = []
      errorMessage = "Vault is locked or session expired. Please unlock your vault."
      return
    }
    var next = attachmentQueue.slice()
    var job = next.shift()
    attachmentQueue = next
    attachmentBusyId = job.id
    attachmentProc.command = Model.attachmentDownloadCommand(job.id, job.itemId, job.fileName, job.size)
    attachmentProc.running = true
  }

  function onAttachmentDownloaded(exitCode, savedPath, stderrText) {
    var id = attachmentBusyId
    attachmentBusyId = ""
    var path = String(savedPath || "").trim()

    if (exitCode !== 0 || !path) {
      // bw's own message is the useful one -- "Not found." for an attachment
      // that has since been deleted, or a permission error on the directory.
      var err = String(stderrText || "").trim().split("\n")[0]
      errorMessage = err ? ("Could not save the attachment: " + err)
                         : "Could not save the attachment"
      attachmentQueue = []
      return
    }

    var saved = {}
    for (var k in attachmentSaved) saved[k] = attachmentSaved[k]
    saved[id] = path
    attachmentSaved = saved
    flashNotification("Saved " + Model.baseName(path))
    pumpAttachmentQueue()
  }

  function attachmentSavedPath(id) {
    return (attachmentSaved && attachmentSaved[id]) ? String(attachmentSaved[id]) : ""
  }

  function isAttachmentQueued(id) {
    for (var i = 0; i < attachmentQueue.length; i++) {
      if (attachmentQueue[i].id === id) return true
    }
    return false
  }

  function openSavedAttachment(id) {
    var path = attachmentSaved[id]
    if (!path) return
    resetAutoLockTimer()
    Quickshell.execDetached(["xdg-open", path])
  }

  function revealSavedAttachment(id) {
    var path = attachmentSaved[id]
    if (!path) return
    var dir = Model.parentDirectory(path)
    if (!dir) return
    resetAutoLockTimer()
    Quickshell.execDetached(["xdg-open", dir])
  }

  function fetchTotp(itemId) {
    if (!session || !itemId) return
    getTotpProc.command = Model.getTotpCommand(itemId)
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
    closeFilterGroup()
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
    formFolderId = (selectedFolder !== "all" && selectedFolder !== "none") ? selectedFolder : ""
    newFolderName = ""
    formPicker = ""
    formCollections = []
    formCollectionIds = []
    if (formOrgId && formOrgId !== "personal") loadOrgCollections(formOrgId)
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
    formFolderId = item.folderId || ""
    newFolderName = ""
    formPicker = ""
    formCollections = []
    // Editing keeps whatever collections the item already has until changed.
    formCollectionIds = (item.rawObject && item.rawObject.collectionIds)
      ? item.rawObject.collectionIds.slice() : []
    if (formOrgId && formOrgId !== "personal") loadOrgCollections(formOrgId)
    formPasswordRevealed = false
    errorMessage = ""
    currentScreen = "edit"
  }

  function saveItemForm() {
    // Bitwarden refuses an organization item with no collection; say so here
    // rather than letting the CLI fail after the form is gone.
    var problem = Model.validateItemForm(formName, formOrgId, formCollectionIds)
    if (problem) {
      errorMessage = problem
      return
    }

    errorMessage = ""
    isLoading = true

    if (formIsEditing) {
      var editPayload = Model.buildEditPayload(detailItem, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId, formFolderId, formCollectionIds)
      itemPayloadJson = JSON.stringify(editPayload)
      editItemProc.command = Model.editItemCommand(formItemId)
      editItemProc.running = true
    } else {
      var createPayload = Model.buildCreatePayload(formTypeCode, formName, formUsername, formPassword, formTotp, formUri, formNotes, formFavorite, formOrgId, formFolderId, formCollectionIds)
      itemPayloadJson = JSON.stringify(createPayload)
      createItemProc.command = Model.createItemCommand(createPayload)
      createItemProc.running = true
    }
  }

  function onSaveItemFinished(exitCode, stdoutText, stderrText) {
    isLoading = false
    // The payload carries the item's password in the clear, the same way a
    // Send payload does, so it goes the same way the Send one does: as soon as
    // the process that needed it has exited.
    itemPayloadJson = ""
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
    deleteItemProc.command = Model.deleteItemCommand(detailItem.id)
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
    var baseList = Model.filterItems(items, searchQuery, selectedCategory, selectedOrg, selectedFolder)
    if (searchQuery.trim() === "" && selectedCategory === "all" && selectedOrg === "all" && selectedFolder === "all" && !suggestionsDismissed && suggestedItems.length > 0) {
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

  // Every main-screen shortcut in one place. Reached two ways: bare letters
  // when the list has focus, and Alt+letter from inside the search box, where
  // a bare letter is search text and must stay that way.
  // Alt+letter. Same table as the bare letters, except Alt+s opens Sends --
  // Send has no bare letter of its own, and plain s is already Settings.
  function runAltShortcut(lower) {
    // Alt+s is Send, which has no bare letter of its own, so Settings keeps
    // its own Alt binding on the comma rather than losing one.
    if (lower === "s") { openSends(); return true }
    if (lower === ",") { openSettings(); return true }
    return runShortcut(lower)
  }

  function runShortcut(lower) {
    var item = getSelectedItem()
    switch (lower) {
      case "y": case "p": if (item) copyPassword(item); return true
      case "u": case "c": if (item) copyUsername(item); return true
      case "m": if (item && item.hasTotp) copyTotpCode(item); return true
      case "w": if (item && item.uris && item.uris.length > 0) openUrl(item.uris[0]); return true
      case "e": if (item) openDetail(item); return true
      case "n": startAddNewItem(); return true
      case "l": lockVault(); return true
      case "r": syncVault(); return true
      case "f": toggleFilterGroup("folders"); return true
      case "o": toggleFilterGroup("organizations"); return true
      case "t": toggleFilterGroup("types"); return true
      case "g": openGenerator(); return true
      case "s": openSettings(); return true
    }
    return false
  }

  function moveCursor(delta) {
    if (filteredItems.length === 0) return
    // Moving to an item means the user is done filtering; get the list out of
    // the way rather than leaving it covering the results.
    openFilterGroup = ""
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
    // The value goes through the environment: `printf %s '<secret>'` would put
    // the password or TOTP code straight into /proc/<pid>/cmdline.
    Quickshell.execDetached({
      command: ["bash", "-c", "printf '%s' \"$QSBW_CLIP\" | wl-copy --sensitive"],
      environment: { "QSBW_CLIP": String(text) }
    })
    flashNotification(label + " copied!")

    if (clearClipboardSec > 0) {
      clipboardClearTimer.restart()
    }
  }

  // Smart sequential Enter handler: Copies Password, then arms and auto-copies TOTP
  function handleSmartEnter(item) {
    openFilterGroup = ""
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
    closeFilterGroup()
    if (!item) return
    learnFromPick(item)
    var pass = (detailItem && detailItem.id === item.id && detailPassword) ? detailPassword : (item.password || "")
    if (pass) {
      copyToClipboard(pass, "Password")
      return
    }
    if (session) {
      Quickshell.execDetached({
        command: ["bash", "-c", "bw get password " + Util.shellQuote(item.id) + " --raw | head -c 4096 | wl-copy --sensitive"],
        environment: root.bwEnv()
      })
      flashNotification("Password copied!")
      if (clearClipboardSec > 0) clipboardClearTimer.restart()
    } else {
      errorMessage = "Vault is locked or session expired. Please unlock your vault."
    }
  }

  function copyUsername(item) {
    closeFilterGroup()
    if (!item || !item.username) return
    copyToClipboard(item.username, "Username")
  }

  function copyTotpCode(item) {
    closeFilterGroup()
    if (!item) return
    if (liveTotp && item.id === (detailItem ? detailItem.id : "")) {
      copyToClipboard(liveTotp, "TOTP code")
      return
    }
    Quickshell.execDetached({
      command: ["bash", "-c", "bw get totp " + Util.shellQuote(item.id) + " --raw | head -c 1024 | wl-copy --sensitive"],
      environment: root.bwEnv()
    })
    flashNotification("TOTP code copied!")
    if (clearClipboardSec > 0) clipboardClearTimer.restart()
  }

  function openUrl(url) {
    if (!url) return
    // Only http and https are handed to xdg-open; see normalizeOpenableUrl().
    var resolved = Model.normalizeOpenableUrl(url)
    if (!resolved.ok) {
      errorMessage = resolved.scheme
        ? ("Refusing to open a " + resolved.scheme + ": link -- only http and https are opened")
        : "That item has no link to open"
      return
    }
    Quickshell.execDetached(["xdg-open", resolved.url])
    flashNotification("Opening " + resolved.url)
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
        // The code itself stays out of the notification. It is already on the
        // clipboard, and a notification is not a private channel: the daemon
        // keeps history and can render the body over a lock screen. The panel
        // shows the digits on screen instead, where you asked for them.
        Quickshell.execDetached(["omarchy-notification-send", "-g", "󰥔", "--app-name", "Bitwarden", "-t", "4000", "TOTP Code Copied", "2FA verification code ready to paste"])
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
    environment: root.bwEnv()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onStatusFinished(text)
    }
  }

  Process {
    id: sessionHandoffProc
    command: Model.sessionHandoffReadCommand()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onSessionHandoff(text)
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
    id: listFoldersProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onListFoldersFinished(text)
    }
  }

  Process {
    id: orgCollectionsProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onOrgCollectionsLoaded(text)
    }
    onExited: function(exitCode) { if (exitCode !== 0) root.formCollectionsLoading = false }
  }

  Process {
    id: createFolderProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: createFolderStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onFolderCreated(exitCode, createFolderStdout.text) }
  }

  Process {
    id: attachmentProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: attachmentStdout; waitForEnd: true }
    stderr: StdioCollector { id: attachmentStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.onAttachmentDownloaded(exitCode, attachmentStdout.text, attachmentStderr.text)
    }
  }

  Process {
    id: listSendsProc
    environment: root.bwEnv()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onSendsLoaded(text)
    }
    onExited: function(exitCode) { if (exitCode !== 0) root.sendsLoading = false }
  }

  Process {
    id: createSendProc
    environment: root.sendEnv(root.sendPayloadJson)
    stdout: StdioCollector { id: createSendStdout; waitForEnd: true }
    stderr: StdioCollector { id: createSendStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.onSendCreated(exitCode, createSendStdout.text, createSendStderr.text)
    }
  }

  Process {
    id: deleteSendProc
    environment: root.bwEnv()
    onExited: function(exitCode) { root.onSendDeleted(exitCode) }
  }

  Process {
    id: generateProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: generateStdout; waitForEnd: true }
    onExited: function(exitCode) { root.onGenerated(generateStdout.text, exitCode) }
  }

  // The generator server. A managed Process rather than execDetached, so it
  // exits with the shell instead of outliving it.
  Process {
    id: generateServeProc
    command: Model.generateServeCommand()
    environment: root.generatorServeEnv()
    onExited: function(exitCode) {
      generateServePoll.stop()
      var act = Model.generatorServeExitAction({
        stopping: root.generateServeStopping,
        wasReady: root.generateServeReady,
        busy: root.genBusy,
        onGeneratorScreen: root.currentScreen === "generator"
      })
      root.generateServeStarting = false
      root.generateServeReady = false
      root.generateServeStopping = false
      if (act.giveUp) root.generateServeFailed = true
      if (act.dropValue) root.genValue = ""
      if (act.useCli) root.regenerateViaCli()
    }
  }

  Timer {
    id: generateServePoll
    property int attempts: 0
    interval: 250
    repeat: true
    onTriggered: {
      attempts++
      if (attempts > 40) {   // 10s, well past bw's usual couple of seconds
        stop()
        root.generateServeStarting = false
        root.generateServeFailed = true
        if (root.genBusy) root.regenerateViaCli()
        return
      }
      root.pollGeneratorServe()
    }
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
    environment: root.secretEnv(root.masterToStore)
    onExited: function(exitCode) { root.onMasterPasswordStored(exitCode) }
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

  // Logout's clean sweep; see forgetStoredCredentials().
  Process {
    id: keyringClearAllProc
    command: Model.keyringClearAllCommand()
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
    environment: root.authEnv(root.loginPassword.trim(),
                              root.loginMethod === "apikey" ? root.loginClientId.trim() : "",
                              root.loginMethod === "apikey" ? root.loginClientSecret.trim() : "",
                              root.login2faCode.trim())
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
    command: Model.unlockCommand()
    environment: root.authEnv(root.pendingUnlockPassword, "", "", "")
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
    environment: root.bwEnv()
  }

  Process {
    id: listProc
    environment: root.bwEnv()
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
    environment: root.bwEnv()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onListOrgsFinished(text)
    }
  }

  Process {
    id: getItemProc
    environment: root.bwEnv()
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
    environment: root.bwEnv()
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onTotpFinished(text)
    }
  }

  Process {
    id: activeWindowProc
    command: ["sh", "-c", "hyprctl activewindow -j 2>/dev/null | grep -q '\"class\": \"[^\"]' && (hyprctl activewindow -j 2>/dev/null | head -c 65536) || (hyprctl clients -j 2>/dev/null | head -c 1048576)"]
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
    environment: root.itemEnv()
    stdout: StdioCollector { id: createItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: createItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.itemPayloadJson = ""
      root.onSaveItemFinished(exitCode, createItemStdout.text, createItemStderr.text)
    }
  }

  Process {
    id: editItemProc
    environment: root.itemEnv()
    stdout: StdioCollector { id: editItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: editItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.itemPayloadJson = ""
      root.onSaveItemFinished(exitCode, editItemStdout.text, editItemStderr.text)
    }
  }

  Process {
    id: deleteItemProc
    environment: root.bwEnv()
    stdout: StdioCollector { id: deleteItemStdout; waitForEnd: true }
    stderr: StdioCollector { id: deleteItemStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root.onDeleteItemFinished(exitCode, deleteItemStdout.text, deleteItemStderr.text)
    }
  }

  Process {
    id: syncProc
    environment: root.bwEnv()
    onExited: function(exitCode) {
      root.onSyncFinished(exitCode)
    }
  }

  Process {
    id: lockProc
    environment: root.bwEnv()
  }

  // -------------------------------------------------------------------------
  // IPC Handler
  // -------------------------------------------------------------------------

  IpcHandler {
    target: "io.github.elevate08.qs-bitwarden-cli"
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
        textFormat: Text.PlainText
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
          textFormat: Text.PlainText
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
    // Every unlocked screen except the two that are text entry drives the key
    // catcher, so arrow navigation works on settings and the generator too.
    focusTarget: (root.status === "unlocked"
                  && root.currentScreen !== "edit"
                  && root.currentScreen !== "pin"
                  && root.currentScreen !== "fingerprint")
      ? keyCatcher
      : (root.status === "unauthenticated" ? emailField : passField)
    contentWidth: panel.fittedContentWidth(Style.space(450))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight, Style.space(640) + root.filterDrawerHeight)

    // PanelKeyCatcher maps h/j/k/l to arrow navigation and consumes them before
    // its textKey signal fires, which silently swallowed the l (lock) shortcut.
    // Forwarding here first gives our letter bindings the first look; anything
    // we do not accept falls through to the catcher's own navigation.
    Item {
      id: shortcutInterceptor
      Keys.onPressed: function(event) {
        // Escape is handled here rather than in the key catcher because the
        // catcher is blocked on every screen built around a text field -- the
        // item form, the PIN and fingerprint screens, the Send composer --
        // and a blocked catcher swallows Escape along with everything else.
        // This interceptor runs first and is not gated by `blocked`, so
        // cancelling out of a form works while the cursor is in a field.
        if (event.key === Qt.Key_Escape && !(event.modifiers & ~Qt.KeypadModifier)) {
          root.handleEscape()
          event.accepted = true
          return
        }

        // Alt may arrive with no text depending on the keymap, so fall back to
        // the key code for A-Z.
        var t = event.text ? String(event.text).toLowerCase() : ""
        if (!t && event.key >= Qt.Key_A && event.key <= Qt.Key_Z) {
          t = String.fromCharCode(event.key).toLowerCase()
        }

        if (event.modifiers & Qt.AltModifier) {
          if (t && root.status === "unlocked" && root.runAltShortcut(t)) event.accepted = true
          return
        }

        if (event.modifiers & ~Qt.KeypadModifier) return
        if (!t || root.currentScreen !== "main") return
        if (root.openFilterGroup !== "") return
        if (t !== "h" && t !== "j" && t !== "k" && t !== "l") return
        if (root.runShortcut(t)) event.accepted = true
      }
    }

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      Keys.forwardTo: [shortcutInterceptor]
      blocked: searchField.activeFocus
        || emailField.activeFocus
        || loginPassField.activeFocus
        || code2faField.activeFocus
        || passField.activeFocus
        || pinField.activeFocus
        || (root.currentScreen === "edit")
        || (root.currentScreen === "pin")
        || (root.currentScreen === "fingerprint")
        || (root.currentScreen === "sends" && root.sendMode === "create")

      // Reached only on screens where the catcher is not blocked; the
      // interceptor handles Escape everywhere else. Same dispatch either way.
      onCloseRequested: root.handleEscape()
      onTabRequested: function(direction) {
        if (root.currentScreen === "main") {
          root.cycleCategory(direction)
        } else {
          root.switchPanel(direction)
        }
      }
      onMoveRequested: function(dx, dy) {
        if (root.currentScreen === "sends" && root.sendMode === "list") {
          if (dy !== 0) root.moveSendCursor(dy)
          return
        }
        if (root.currentScreen === "settings") {
          if (dy !== 0) root.moveSettingsCursor(dy)
          else if (dx !== 0) root.adjustSetting(dx)
          return
        }
        // While a filter drawer is open the arrows drive it, not the item list.
        if (root.openFilterGroup !== "" && root.currentScreen === "main") {
          if (dy !== 0) root.moveFilterCursor(dy)
          return
        }
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
        if (root.currentScreen === "generator" && root.generatorFeedsForm) {
          root.useGeneratedPassword()
          return
        }
        if (root.currentScreen === "sends" && root.sendMode === "list") {
          if (root.sendIndex < root.sends.length) root.copySendLink(root.sends[root.sendIndex])
          return
        }
        if (root.currentScreen === "settings") {
          root.activateSettingRow()
          return
        }
        if (root.openFilterGroup !== "" && root.currentScreen === "main") {
          root.activateFilterOption()
          return
        }
        if (root.currentScreen === "main") {
          var item = root.getSelectedItem()
          if (item) {
            root.handleSmartEnter(item)
          }
        }
      }
      onTextKey: function(key) {
        var lower = String(key).toLowerCase()
        if (root.currentScreen === "sends" && root.sendMode === "list") {
          if (lower === "n") root.beginCreateSend()
          else if (lower === "r") root.loadSends()
          else if (lower === "x" && root.sendIndex < root.sends.length) root.deleteSend(root.sends[root.sendIndex])
          return
        }
        if (root.currentScreen === "main") {
          if (lower === "/") searchField.forceActiveFocus()
          else root.runShortcut(lower)
        } else if (root.currentScreen === "detail") {
          if (lower === "y" || lower === "p") {
            if (root.detailPassword) root.copyToClipboard(root.detailPassword, "Password")
          } else if (lower === "u" || lower === "c") {
            if (root.detailItem && root.detailItem.username) root.copyToClipboard(root.detailItem.username, "Username")
          } else if (lower === "m") {
            if (root.liveTotp) root.copyToClipboard(root.liveTotp, "TOTP")
          } else if (lower === "e") {
            if (root.detailItem) root.startEditItem(root.detailItem)
          } else if (lower === "x") {
            root.showDeleteConfirm = true
          } else if (lower === "v") {
            root.passwordRevealed = !root.passwordRevealed
          } else if (lower === "a") {
            root.saveAllAttachments()
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
              // The email arrives with `bw status`, which lags the item list on
              // a cold start and after a terminal-login handoff. Fall back to
              // the count so the subtitle is never blank in that gap.
              return root.userEmail || (root.filteredItems.length + " items")
            }
            if (root.status === "locked") return "Vault Locked"
            if (root.status === "checking") return "Checking status..."
            return "Log In"
          }
          foreground: root.fg
          fontFamily: root.fontFamily

          iconComponent: Text {
            textFormat: Text.PlainText
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

            // Send Button
            PanelActionButton {
              visible: root.status === "unlocked" && root.currentScreen !== "sends"
              iconText: "󰒗"
              tooltipText: "Bitwarden Send (Alt+S)"
              fontFamily: root.fontFamily
              onClicked: root.openSends()
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
              tooltipText: "Settings (s)"
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
              textFormat: Text.PlainText
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
                textFormat: Text.PlainText
                text: "Password copied! Press Enter for TOTP"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
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
              textFormat: Text.PlainText
              text: "󰄬"
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              textFormat: Text.PlainText
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
              textFormat: Text.PlainText
              text: "󰅚"
              color: Color.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              textFormat: Text.PlainText
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
        // SCREEN 0f: BITWARDEN SEND
        // -------------------------------------------------------------------
        Flickable {
          id: sendFlick
          visible: root.currentScreen === "sends"
          width: parent.width
          height: Math.min(Style.space(520), sendCol.implicitHeight)
          contentWidth: width
          contentHeight: sendCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: sendCol
            width: sendFlick.width
            spacing: Style.space(10)

            PanelSeparator { width: parent.width }

            Row {
              width: parent.width
              spacing: Style.space(8)

              Button {
                text: root.sendMode === "create" ? "Back to Sends" : "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: {
                  if (root.sendMode === "create") { root.sendError = ""; root.sendMode = "list" }
                  else root.currentScreen = "main"
                }
              }

              Button {
                visible: root.sendMode === "list"
                text: "New Send"
                iconText: "󰐕"
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.beginCreateSend()
              }

              Button {
                visible: root.sendMode === "list"
                text: "Refresh"
                iconText: "󰑐"
                iconSpinning: root.sendsLoading
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.loadSends()
              }
            }

            Text {
              textFormat: Text.PlainText
              visible: root.sendError !== ""
              width: parent.width
              text: root.sendError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            // ---------------- list ----------------
            Column {
              visible: root.sendMode === "list"
              width: parent.width
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                visible: !root.sendsLoading && root.sends.length === 0
                width: parent.width
                text: "No Sends yet. A Send shares a secret through a link that expires on its own -- useful for handing someone a credential without it living in a chat log."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Text {
                textFormat: Text.PlainText
                visible: root.sendsLoading
                text: "Loading Sends..."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Repeater {
                model: root.sends

                delegate: BorderSurface {
                  required property var modelData
                  required property int index
                  width: parent.width
                  implicitHeight: sendRowCol.implicitHeight + Style.space(16)
                  radius: Style.cornerRadius
                  readonly property bool cursored: index === root.sendIndex
                  color: cursored ? Style.hoverFillFor(root.fg, Color.accent) : "transparent"
                  borderSpec: Border.surfaceSpec("menu", "border",
                    cursored ? Color.accent : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.18), 1)

                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    onEntered: root.sendIndex = index
                  }

                  Row {
                    anchors.fill: parent
                    anchors.margins: Style.space(8)
                    spacing: Style.space(8)

                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      text: modelData.isFile ? "󰈤" : "󰈙"
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.subtitle
                    }

                    Column {
                      id: sendRowCol
                      width: parent.width - Style.space(110)
                      spacing: Style.space(2)

                      Text {
                        textFormat: Text.PlainText
                        width: parent.width
                        text: modelData.name
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        font.bold: true
                        elide: Text.ElideRight
                      }

                      Row {
                        spacing: Style.space(6)

                        Text {
                          textFormat: Text.PlainText
                          text: Model.sendExpiryLabel(modelData, Date.now())
                          color: Model.sendExpiryLabel(modelData, Date.now()) === "expired" ? root.urgent : root.dim
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                        }
                        Text {
                          textFormat: Text.PlainText
                          text: "\u00b7 " + Model.sendAccessLabel(modelData)
                          color: root.dim
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                        }
                        Text {
                          textFormat: Text.PlainText
                          visible: modelData.passwordSet
                          text: "\u00b7 󰌾 password"
                          color: Color.accent
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                        }
                      }
                    }

                    PanelActionButton {
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "󰆏"
                      tooltipText: "Copy Send link"
                      fontFamily: root.fontFamily
                      onClicked: root.copySendLink(modelData)
                    }

                    PanelActionButton {
                      anchors.verticalCenter: parent.verticalCenter
                      iconText: "󰆴"
                      tooltipText: "Delete this Send"
                      fontFamily: root.fontFamily
                      enabled: !root.sendBusy
                      onClicked: root.deleteSend(modelData)
                    }
                  }
                }
              }
            }

            // ---------------- create ----------------
            Column {
              visible: root.sendMode === "create"
              width: parent.width
              spacing: Style.space(8)

              Text { textFormat: Text.PlainText; text: "NAME"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                id: sendNameField
                width: parent.width
                placeholderText: "What is this? (optional)"
                text: root.sendFormName
                onTextChanged: root.sendFormName = text
                enabled: !root.sendBusy
              }

              Text { textFormat: Text.PlainText; text: "TEXT TO SEND"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                width: parent.width
                placeholderText: "The secret to share..."
                text: root.sendFormText
                onTextChanged: root.sendFormText = text
                enabled: !root.sendBusy
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Button {
                  text: "Hide text by default"
                  tooltipText: "The recipient must click to reveal it"
                  selected: root.sendFormHidden
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.sendFormHidden = !root.sendFormHidden
                }
              }

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Delete after"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  text: "days"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.sendFormDays
                  from: 1
                  to: 31
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.sendFormDays = v }
                }
              }

              Row {
                width: parent.width
                spacing: Style.space(10)
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  width: parent.width - Style.space(170)
                  text: "Maximum views"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
                Text {
                  textFormat: Text.PlainText
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.sendFormMaxAccess === 0 ? "unlimited" : ""
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }
                NumberField {
                  anchors.verticalCenter: parent.verticalCenter
                  value: root.sendFormMaxAccess
                  from: 0
                  to: 100
                  stepSize: 1
                  foreground: root.fg
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  onModified: function(v) { root.sendFormMaxAccess = v }
                }
              }

              Text { textFormat: Text.PlainText; text: "PASSWORD (OPTIONAL)"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
              TextField {
                width: parent.width
                placeholderText: "Recipient must enter this to open the Send..."
                password: true
                text: root.sendFormPassword
                onTextChanged: root.sendFormPassword = text
                enabled: !root.sendBusy
              }

              Button {
                width: parent.width
                text: root.sendBusy ? "Creating..." : "Create Send & Copy Link"
                iconText: root.sendBusy ? "󰑐" : "󰒗"
                iconSpinning: root.sendBusy
                selected: true
                accent: Color.accent
                fontFamily: root.fontFamily
                enabled: !root.sendBusy
                onClicked: root.submitCreateSend()
              }
            }
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 0e: FINGERPRINT SETUP
        // -------------------------------------------------------------------
        Flickable {
          id: fpFlick
          visible: root.currentScreen === "fingerprint"
          width: parent.width
          height: Math.min(Style.space(520), fpCol.implicitHeight)
          contentWidth: width
          contentHeight: fpCol.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: fpCol
            width: fpFlick.width
            spacing: Style.space(12)

            PanelSeparator { width: parent.width }

            Column {
              width: parent.width
              spacing: Style.space(4)

              Text {
                textFormat: Text.PlainText
                text: "Enable fingerprint unlock"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                font.bold: true
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "A fingerprint proves you are present but cannot produce your master password, and bw unlock accepts nothing else. The password is stored in the OS login keyring, and a verified fingerprint is the gate on reading it back."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: "Anyone who can read your unlocked login keyring can read the password. A PIN stores it encrypted instead."
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                wrapMode: Text.WordWrap
              }
            }

            Column {
              width: parent.width
              spacing: Style.space(8)

              Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

              TextField {
                id: fpMasterField
                width: parent.width
                placeholderText: "Needed once, to store for fingerprint unlock..."
                password: true
                text: root.fpSetupMaster
                onTextChanged: root.fpSetupMaster = text
                onAccepted: root.submitFingerprintSetup()
                enabled: !root.fpBusy
              }

              Text {
                textFormat: Text.PlainText
                visible: root.fpError !== ""
                width: parent.width
                text: root.fpError
                color: root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }

              Row {
                width: parent.width
                spacing: Style.space(8)

                Button {
                  text: root.fpBusy ? "Saving..." : "Enable"
                  iconText: root.fpBusy ? "󰑐" : "󰈷"
                  iconSpinning: root.fpBusy
                  selected: true
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  enabled: !root.fpBusy
                  onClicked: root.submitFingerprintSetup()
                }

                Button {
                  text: "Cancel"
                  iconText: "󰅖"
                  fontFamily: root.fontFamily
                  enabled: !root.fpBusy
                  onClicked: { root.fpError = ""; root.currentScreen = "settings" }
                }
              }
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
                text: root.generatorFeedsForm ? "Back to item (Esc)" : "Back (Esc)"
                iconText: "󰁍"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                onClicked: root.closeGenerator()
              }

              // Only when the generator was opened from the item form: hand
              // the value back to the password field and return there.
              Button {
                visible: root.generatorFeedsForm
                text: "Use this password (Enter)"
                iconText: "󰄬"
                fontFamily: root.fontFamily
                fontSize: Style.font.bodySmall
                selected: true
                accent: Color.accent
                enabled: !root.genBusy && root.genValue !== ""
                onClicked: root.useGeneratedPassword()
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
                  textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
                  text: parent.parent.strength.label
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
                Item { width: Style.space(6); height: 1 }
                Text {
                  textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
              textFormat: Text.PlainText
              text: "Set an unlock PIN"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: "Your master password is encrypted with a key derived from this PIN, and only the encrypted form is stored. "
                + "Use " + Model.pinRecommendedLength() + " digits or more; " + Model.pinMinLength()
                + " is the floor, and every extra digit multiplies an attacker's work by ten."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Column {
            width: parent.width
            spacing: Style.space(8)

            Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
            TextField {
              width: parent.width
              placeholderText: "Needed once, to encrypt the PIN..."
              password: true
              text: root.pinSetupMaster
              onTextChanged: root.pinSetupMaster = text
              enabled: !root.pinBusy
            }

            Text {
              textFormat: Text.PlainText
              text: "PIN"
              // The label turns with the field, so the warning is visible even
              // when the cursor has moved on to Confirm.
              color: root.pinSetupWeak ? root.urgent : root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }
            TextField {
              id: pinSetupPinField
              width: parent.width
              placeholderText: Model.pinRecommendedLength() + " digits or more..."
              password: true
              text: root.pinSetupPin
              onTextChanged: root.pinSetupPin = text.replace(/[^0-9]/g, "")
              enabled: !root.pinBusy
              // A short PIN is allowed but not waved through: the border goes
              // red rather than accent while it is under the recommendation.
              accent: root.pinSetupWeak ? root.urgent : Color.accent
              foreground: root.pinSetupWeak ? root.urgent : root.fg
            }

            Text {
              textFormat: Text.PlainText
              visible: root.pinSetupWeak
              width: parent.width
              text: "󰀪  " + Model.pinWeakWarning(root.pinSetupPin)
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Text { textFormat: Text.PlainText; text: "CONFIRM PIN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
              textFormat: Text.PlainText
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
              textFormat: Text.PlainText
              text: root.missingRequired.length > 0 ? "Setup required" : "All set"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
                      textFormat: Text.PlainText
                      text: modelData.label
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      font.bold: true
                    }
                    Text {
                      textFormat: Text.PlainText
                      anchors.verticalCenter: parent.verticalCenter
                      text: modelData.required ? "required" : "optional"
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: modelData.purpose
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    wrapMode: Text.WordWrap
                  }

                  // fprintd on PATH still needs an enrolled finger.
                  Text {
                    textFormat: Text.PlainText
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
              textFormat: Text.PlainText
              anchors.verticalCenter: parent.verticalCenter
              visible: root.settingsFlash !== ""
              text: "󰄬 " + root.settingsFlash
              color: Color.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          Connections {
            target: root
            function onSettingsIndexChanged() {
              var row = settingsRepeater.itemAt(root.settingsIndex)
              if (!row) return
              if (row.y < settingsFlick.contentY) {
                settingsFlick.contentY = Math.max(0, row.y - Style.space(8))
              } else if (row.y + row.height > settingsFlick.contentY + settingsFlick.height) {
                settingsFlick.contentY = Math.min(
                  Math.max(0, settingsFlick.contentHeight - settingsFlick.height),
                  row.y + row.height - settingsFlick.height + Style.space(8))
              }
            }
          }

          Repeater {
            id: settingsRepeater
            model: root.settingsEntries

            delegate: Column {
              required property var modelData
              required property int index
              width: parent.width
              spacing: Style.space(4)
              readonly property bool cursored: index === root.settingsIndex

              // One header per group, drawn by the first entry in it.
              Item {
                visible: modelData.groupLabel !== ""
                width: parent.width
                height: visible ? Style.space(18) : 0
              }

              PanelSectionHeader {
                textFormat: Text.PlainText
                visible: modelData.groupLabel !== ""
                text: modelData.groupLabel === "" ? "" : modelData.groupLabel.toUpperCase()
                foreground: root.fg
                fontFamily: root.fontFamily
              }

              // A setting whose dependency is missing is shown but inert, with
              // the reason stated rather than the control silently doing nothing.
              readonly property bool blocked: root.settingBlocked(modelData)

              Item {
                width: parent.width
                implicitHeight: Math.max(settingTextCol.implicitHeight, settingControlRow.implicitHeight, Style.space(32))

                // Keyboard cursor: a bar in the gutter, so the row it marks is
                // unmistakable without recolouring the whole row.
                Rectangle {
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                  width: Style.space(3)
                  height: parent.height - Style.space(6)
                  radius: width / 2
                  color: Color.accent
                  visible: cursored
                }

                Column {
                  id: settingTextCol
                  anchors.left: parent.left
                  anchors.leftMargin: cursored ? Style.space(10) : 0
                  anchors.right: settingControlRow.left
                  anchors.rightMargin: Style.space(12)
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(2)

                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    text: modelData.label
                    color: blocked ? root.dim : root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                  }

                  Text {
                    textFormat: Text.PlainText
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

                Row {
                  id: settingControlRow
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(8)

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
                      if (modelData.action === "fingerprint") {
                        if (checked) root.forgetFingerprintUnlock()
                        else root.beginFingerprintSetup()
                        return
                      }
                      root.writeSetting(modelData.key, !checked, "bool")
                    }
                  }

                  Text {
                    textFormat: Text.PlainText
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
              }

              Text {
                textFormat: Text.PlainText
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
            textFormat: Text.PlainText
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
          visible: root.status === "unauthenticated" && root.currentScreen !== "settings" && root.currentScreen !== "setup" && root.currentScreen !== "pin" && root.currentScreen !== "fingerprint"
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
              Text { textFormat: Text.PlainText; text: "EMAIL ADDRESS"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
              Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
                  textFormat: Text.PlainText
                  text: "TWO-STEP VERIFICATION CODE (2FA)"
                  color: root.show2faField ? Color.accent : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
                Item { Layout.fillWidth: true }
                Text {
                  textFormat: Text.PlainText
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
                    textFormat: Text.PlainText
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
              Text { textFormat: Text.PlainText; text: "CLIENT ID"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
              Text { textFormat: Text.PlainText; text: "CLIENT SECRET"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
              Text { textFormat: Text.PlainText; text: "MASTER PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
              textFormat: Text.PlainText
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
            && root.currentScreen !== "settings" && root.currentScreen !== "setup" && root.currentScreen !== "pin" && root.currentScreen !== "fingerprint"
          width: parent.width
          spacing: Style.space(14)

          PanelSeparator { width: parent.width }

          Item { height: Style.space(8); width: 1 }

          Column {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)

            Text {
              textFormat: Text.PlainText
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
              textFormat: Text.PlainText
              anchors.horizontalCenter: parent.horizontalCenter
              text: root.fingerprintReady ? "Unlock Vault" : "Enter Master Password"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Text {
              textFormat: Text.PlainText
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
            textFormat: Text.PlainText
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
            textFormat: Text.PlainText
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

            Text { textFormat: Text.PlainText; text: "PIN"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

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
              textFormat: Text.PlainText
              visible: root.pinError !== ""
              width: parent.width
              text: root.pinError
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Text {
              textFormat: Text.PlainText
              text: "or use your master password below"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          // A PIN was set but the vault rejected it -- surfaced even once
          // pinReady has gone false, so the reason is not lost.
          Text {
            textFormat: Text.PlainText
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
                root.closeFilterGroup()
                searchDebounceTimer.restart()
              }
              // Alt+letter runs the same shortcuts without leaving the box.
              Keys.onPressed: function(event) {
                if (!(event.modifiers & Qt.AltModifier)) return
                if (!event.text) return
                if (root.runAltShortcut(String(event.text).toLowerCase())) {
                  event.accepted = true
                }
              }
              Keys.onDownPressed: {
                keyCatcher.forceActiveFocus()
                root.moveCursor(1)
              }
              Keys.onReturnPressed: {
                var itm = root.getSelectedItem()
                if (itm) root.handleSmartEnter(itm)
              }
              // Only while the search box is the screen. A hidden item keeps
              // active focus in Qt, so without this guard the search field
              // still owned Escape from behind the item form and closed the
              // whole panel instead of cancelling the edit.
              Keys.onEscapePressed: function(event) {
                if (root.currentScreen !== "main") {
                  event.accepted = false   // let it reach the panel's dispatch
                  return
                }
                if (text) text = ""
                else root.handleEscape()
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
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: "󰌠"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
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
                    textFormat: Text.PlainText
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
                        textFormat: Text.PlainText
                        text: itemData.name
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        font.bold: true
                        elide: Text.ElideRight
                        width: Math.min(implicitWidth, parent.width
                          - (itemData.favorite ? Style.space(16) : 0)
                          - (itemData.hasAttachments ? Style.space(18) : 0))
                      }

                      Text {
                        textFormat: Text.PlainText
                        visible: itemData.favorite
                        text: "★"
                        color: Color.accent
                        font.pixelSize: Style.font.bodySmall
                        anchors.verticalCenter: parent.verticalCenter
                      }

                      // A paperclip is the whole badge: the file names live in
                      // the detail view, and the row only has to say they exist.
                      Text {
                        textFormat: Text.PlainText
                        visible: Boolean(itemData.hasAttachments)
                        text: "󰏢"
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        anchors.verticalCenter: parent.verticalCenter
                      }
                    }

                    Row {
                      spacing: Style.space(4)
                      width: parent.width

                      Text {
                        textFormat: Text.PlainText
                        visible: Boolean(itemData.isSuggested)
                        text: root.learnedIds[itemData.id] ? "󰐾 Suggested" : "󰌠 Suggested"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        textFormat: Text.PlainText
                        visible: Boolean(itemData.organizationId)
                        text: "󰓹 Org"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }

                      Text {
                        textFormat: Text.PlainText
                        id: rowSubtitle
                        text: itemData.subtitle || Model.itemTypeLabel(itemData.typeCode)
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                        // Take only what is needed, so the folder tag that follows
                        // keeps its place instead of being pushed off the row.
                        width: Math.min(implicitWidth,
                          parent.width
                            - (itemData.organizationId ? Style.space(40) : 0)
                            - (itemData.isSuggested ? Style.space(75) : 0)
                            - (rowFolderTag.visible ? Style.space(90) : 0))
                      }

                      Text {
                        textFormat: Text.PlainText
                        id: rowFolderTag
                        // Only worth showing when it is not already implied by the filter.
                        visible: Boolean(itemData.folderId) && root.selectedFolder === "all"
                        text: "· 󰉋 " + Model.folderName(root.folders, itemData.folderId)
                        color: Qt.darker(root.dim, 1.1)
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        elide: Text.ElideRight
                        width: Math.min(implicitWidth, Style.space(90))
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
                      tooltipText: "Copy TOTP code (m)"
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
                      tooltipText: "Open URL (w)"
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
                    root.openFilterGroup = ""
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
                  textFormat: Text.PlainText
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.items.length === 0 ? "󰞀" : "󰍡"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(36)
                }

                Text {
                  textFormat: Text.PlainText
                  anchors.horizontalCenter: parent.horizontalCenter
                  text: root.items.length === 0 ? "Vault is empty" : ("No items match '" + root.searchQuery + "'")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }
              }
            }
          }

          // -----------------------------------------------------------------
          // Bottom filter bar: Folders / Vaults / Types
          // -----------------------------------------------------------------
          // Three horizontally scrolling strips were easy to miss and awkward
          // to reach. One collapsed row instead, each opening a vertical list
          // in place; the item list gives back exactly the height the open
          // list takes, so the panel does not jump.

          PanelSeparator { width: parent.width }

          // The open group's options: a pinned header naming the group, then up
          // to five rows with the rest scrolling underneath it.
          Column {
            id: filterDrawer
            width: parent.width
            height: root.filterDrawerHeight
            visible: height > 0
            clip: true
            spacing: 0

            Behavior on height { NumberAnimation { duration: 130; easing.type: Easing.OutQuad } }

            // Pinned header -- stays put while the options scroll.
            Row {
              width: parent.width
              height: Style.space(30)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: root.openFilterGroup === "folders" ? "󰉋"
                    : root.openFilterGroup === "organizations" ? "󰦑"
                    : "󰀻"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                text: root.openFilterGroup === "folders" ? "FOLDERS"
                    : root.openFilterGroup === "organizations" ? "ORGANIZATIONS"
                    : "TYPES"
                color: Color.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Item { width: parent.width - Style.space(190); height: 1 }

              Text {
                textFormat: Text.PlainText
                anchors.verticalCenter: parent.verticalCenter
                visible: root.currentFilterOptions.length > root.filterVisibleRows
                text: root.currentFilterOptions.length + " total"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }

            Flickable {
              id: filterOptionsList
              width: parent.width
              height: Math.min(root.filterVisibleRows, root.currentFilterOptions.length) * root.filterRowHeight
              contentWidth: width
              contentHeight: filterOptionsCol.implicitHeight
              clip: true
              boundsBehavior: Flickable.StopAtBounds
              flickableDirection: Flickable.VerticalFlick
              ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

              // Keep the keyboard cursor in view when it runs past the fold.
              function revealCursor() {
                var y = root.filterOptionIndex * root.filterRowHeight
                if (y < contentY) contentY = y
                else if (y + root.filterRowHeight > contentY + height) {
                  contentY = y + root.filterRowHeight - height
                }
              }

              Connections {
                target: root
                function onFilterOptionIndexChanged() { filterOptionsList.revealCursor() }
              }

              Column {
                id: filterOptionsCol
                width: filterOptionsList.width
                spacing: 0

                Repeater {
                  model: root.currentFilterOptions

                  delegate: BorderSurface {
                    required property var modelData
                    required property int index
                    width: filterOptionsCol.width
                    implicitHeight: root.filterRowHeight
                    radius: Style.cornerRadius
                    readonly property bool cursored: index === root.filterOptionIndex
                    color: modelData.active ? Style.selectedFillFor(root.fg, Color.accent)
                         : (cursored || optionMouse.containsMouse) ? Style.hoverFillFor(root.fg, Color.accent)
                         : "transparent"
                    borderSpec: Border.surfaceSpec("menu", "border",
                      (modelData.active || cursored) ? Color.accent : "transparent",
                      (modelData.active || cursored) ? 1 : 0)

                    MouseArea {
                      id: optionMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onEntered: root.filterOptionIndex = index
                      onClicked: root.applyFilterOption(root.openFilterGroup, modelData.id)
                    }

                    Row {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(10)
                      spacing: Style.space(8)

                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        text: modelData.icon
                        color: modelData.active ? Color.accent : root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                      }

                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        width: parent.width - Style.space(50)
                        text: modelData.label
                        color: modelData.active ? Color.accent : root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        font.bold: modelData.active
                        elide: Text.ElideRight
                      }

                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        visible: modelData.active
                        text: "󰄬"
                        color: Color.accent
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                      }
                    }
                  }
                }
              }
            }
          }

          // The three collapsed buttons. Identical shape, so none reads as a
          // different kind of control from the others.
          Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)

            Repeater {
              model: [
                { group: "folders", icon: "󰉋", name: "Folders", value: root.folderFilterLabel() },
                { group: "organizations", icon: "󰦑", name: "Organizations", value: root.organizationFilterLabel() },
                { group: "types",   icon: "󰀻", name: "Types",   value: root.typeFilterLabel() }
              ]

              delegate: Button {
                required property var modelData
                // The value half is a vault folder/organization name, and
                // Ui.Button renders it with an auto-detecting Text.
                text: Model.plainLabel(modelData.name + ": " + modelData.value)
                iconText: root.openFilterGroup === modelData.group ? "󰅀" : modelData.icon
                selected: root.openFilterGroup === modelData.group
                accent: Color.accent
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                horizontalPadding: Style.space(10)
                tooltipText: modelData.name + " filter ("
                  + (modelData.group === "folders" ? "f"
                     : modelData.group === "organizations" ? "o" : "t") + ")"
                onClicked: root.toggleFilterGroup(modelData.group)
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
              // The window title is no more trustworthy than a vault value,
              // and the kit renders tooltips with an auto-detecting Text.
              tooltipText: Model.plainLabel((pinned ? "Stop suggesting this for " : "Always suggest this for ")
                + (root.detectedContext ? root.detectedContext.displayName : ""))
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
                textFormat: Text.PlainText
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
                  textFormat: Text.PlainText
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
                      textFormat: Text.PlainText
                      text: root.detailItem ? root.detailItem.name : "Loading..."
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.title
                      font.bold: true
                      elide: Text.ElideRight
                      width: Math.min(implicitWidth, parent.width - Style.space(20))
                    }

                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.detailItem && root.detailItem.favorite)
                      text: "★"
                      color: Color.accent
                      font.pixelSize: Style.font.body
                    }
                  }

                  Row {
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      text: root.detailItem ? Model.itemTypeLabel(root.detailItem.typeCode) : ""
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.detailItem && root.detailItem.organizationId)
                      text: "• Shared Organization"
                      color: Color.accent
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: Boolean(root.detailItem && root.detailItem.folderId)
                      text: root.detailItem
                        ? "• 󰉋 " + Model.folderName(root.folders, root.detailItem.folderId)
                        : ""
                      color: root.dim
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
                      textFormat: Text.PlainText
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
                      textFormat: Text.PlainText
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
                    textFormat: Text.PlainText
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
                      textFormat: Text.PlainText
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
                      tooltipText: "Copy TOTP code (m)"
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
                        textFormat: Text.PlainText
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
                        tooltipText: "Open in browser (w)"
                        fontFamily: root.fontFamily
                        onClicked: root.openUrl(modelData)
                      }
                    }
                  }
                }
              }

              // FIELD: Attachments
              //
              // The metadata came down with the item, so the list is here the
              // moment the detail view opens; only the bytes cost a CLI call,
              // and only for the file the user actually asks for.
              //
              // Above NOTES on purpose. Notes is the one section with no height
              // of its own -- it grows with the text -- and this Flickable is
              // capped, so anything after it starts below the fold on exactly
              // the items whose note is long. A secure note with a file
              // attached is that case, and the files were the thing being
              // pushed out of sight.
              Column {
                visible: Boolean(root.detailItem && root.detailItem.hasAttachments)
                width: parent.width
                spacing: Style.space(4)

                Row {
                  width: parent.width
                  spacing: Style.space(6)
                  PanelSectionHeader { text: "ATTACHMENTS" }
                  Item { Layout.fillWidth: true }
                  PanelActionButton {
                    visible: Boolean(root.detailItem && root.detailItem.attachments
                      && root.detailItem.attachments.length > 1)
                    iconText: "󰇚"
                    tooltipText: "Save all attachments (a)"
                    size: Style.space(20)
                    fontFamily: root.fontFamily
                    onClicked: root.saveAllAttachments()
                  }
                }

                Repeater {
                  model: root.detailItem ? root.detailItem.attachments : []
                  delegate: BorderSurface {
                    readonly property string savedPath: root.attachmentSavedPath(modelData.id)
                    readonly property bool busy: root.attachmentBusyId === modelData.id
                    readonly property bool queued: root.isAttachmentQueued(modelData.id)

                    width: detailContentColumn.width
                    implicitHeight: Style.space(34)
                    radius: Style.cornerRadius
                    color: Style.hoverFillFor(root.fg, Color.accent)
                    borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                    Row {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(6)
                      spacing: Style.space(6)

                      Text {
                        textFormat: Text.PlainText
                        id: attachmentGlyph
                        anchors.verticalCenter: parent.verticalCenter
                        text: "󰈔"
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                      }

                      // The file name is vault text, so it is drawn as text.
                      Text {
                        textFormat: Text.PlainText
                        anchors.verticalCenter: parent.verticalCenter
                        text: modelData.fileName
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        elide: Text.ElideRight
                        width: Math.max(0, parent.width - attachmentGlyph.width
                          - attachmentStatus.width - attachmentActions.width - Style.space(34))
                      }

                      Text {
                        textFormat: Text.PlainText
                        id: attachmentStatus
                        anchors.verticalCenter: parent.verticalCenter
                        text: busy ? "Saving..." : queued ? "Queued" : modelData.sizeName
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                      }

                      Row {
                        id: attachmentActions
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.space(2)

                        PanelActionButton {
                          visible: savedPath === ""
                          enabled: !busy && !queued
                          iconText: "󰇚"
                          tooltipText: "Save to your download folder"
                          fontFamily: root.fontFamily
                          onClicked: root.queueAttachment(modelData)
                        }

                        PanelActionButton {
                          visible: savedPath !== ""
                          iconText: "󰏌"
                          tooltipText: "Open the saved file"
                          fontFamily: root.fontFamily
                          onClicked: root.openSavedAttachment(modelData.id)
                        }

                        PanelActionButton {
                          visible: savedPath !== ""
                          iconText: "󰝰"
                          // The path is ours -- a download directory plus a
                          // sanitised name -- but it is still drawn as text.
                          tooltipText: Model.plainLabel("Show in " + Model.parentDirectory(savedPath))
                          fontFamily: root.fontFamily
                          onClicked: root.revealSavedAttachment(modelData.id)
                        }
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
                    iconText: "󰈙"
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
                    textFormat: Text.PlainText
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
              textFormat: Text.PlainText
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
                  iconText: "󰈙"
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
                Text { textFormat: Text.PlainText; text: "TITLE / NAME *"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                TextField {
                  id: formNameField
                  width: parent.width
                  placeholderText: "e.g. GitHub, Google, Work Server..."
                  text: root.formName
                  onTextChanged: root.formName = text
                }
              }

              // FIELD: Folder -- expandable list rather than a wrapping row of
              // buttons, which grew unreadable once a vault had more than a few.
              Column {
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "FOLDER"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

                Button {
                  width: parent.width
                  text: Model.plainLabel(root.formFolderLabel())
                  iconText: root.formPicker === "folder" ? "\u{F0140}" : "\u{F024B}"
                  selected: root.formPicker === "folder"
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  leftAlign: true
                  onClicked: root.toggleFormPicker("folder")
                }

                Flickable {
                  id: folderPickList
                  visible: root.formPicker === "folder"
                  width: parent.width
                  height: visible ? Math.min(Style.space(150), folderPickCol.implicitHeight) : 0
                  contentWidth: width
                  contentHeight: folderPickCol.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  flickableDirection: Flickable.VerticalFlick
                  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                  Column {
                    id: folderPickCol
                    width: folderPickList.width
                    spacing: Style.space(2)

                    FormPickerRow {
                      width: parent.width
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      label: "No Folder"
                      glyph: "\u{F0256}"
                      picked: !root.formFolderId
                      onActivated: root.setFormFolder("")
                    }

                    Repeater {
                      model: root.folders
                      delegate: FormPickerRow {
                        required property var modelData
                        width: parent.width
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        label: modelData.name
                        glyph: "\u{F024B}"
                        picked: root.formFolderId === modelData.id
                        onActivated: root.setFormFolder(modelData.id)
                      }
                    }
                  }
                }

                // Creating a folder here saves leaving the form to make one.
                Row {
                  width: parent.width
                  spacing: Style.space(6)

                  TextField {
                    width: parent.width - Style.space(96)
                    placeholderText: "New folder name..."
                    text: root.newFolderName
                    onTextChanged: root.newFolderName = text
                    onAccepted: root.submitNewFolder()
                    enabled: !root.creatingFolder
                  }

                  Button {
                    text: root.creatingFolder ? "Adding..." : "Add"
                    iconText: root.creatingFolder ? "\u{F0450}" : "\u{F0415}"
                    iconSpinning: root.creatingFolder
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    enabled: !root.creatingFolder && root.newFolderName.trim() !== ""
                    onClicked: root.submitNewFolder()
                  }
                }
              }

              // FIELD: Organization, and the collections it files items into.
              Column {
                visible: root.organizations.length > 0
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "ORGANIZATION"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }

                Button {
                  width: parent.width
                  text: Model.plainLabel(root.formOrgLabel())
                  iconText: root.formPicker === "organization" ? "\u{F0140}" : "\u{F0991}"
                  selected: root.formPicker === "organization"
                  accent: Color.accent
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  leftAlign: true
                  onClicked: root.toggleFormPicker("organization")
                }

                Flickable {
                  id: orgPickList
                  visible: root.formPicker === "organization"
                  width: parent.width
                  height: visible ? Math.min(Style.space(150), orgPickCol.implicitHeight) : 0
                  contentWidth: width
                  contentHeight: orgPickCol.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  flickableDirection: Flickable.VerticalFlick
                  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                  Column {
                    id: orgPickCol
                    width: orgPickList.width
                    spacing: Style.space(2)

                    FormPickerRow {
                      width: parent.width
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      label: "My Vault"
                      glyph: "\u{F0004}"
                      picked: !root.formOrgId || root.formOrgId === "personal"
                      onActivated: root.setFormOrganization("")
                    }

                    Repeater {
                      model: root.organizations
                      delegate: FormPickerRow {
                        required property var modelData
                        width: parent.width
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        label: modelData.name
                        glyph: "\u{F0991}"
                        picked: root.formOrgId === modelData.id
                        onActivated: root.setFormOrganization(modelData.id)
                      }
                    }
                  }
                }

                // Collections only exist for org-owned items, and Bitwarden
                // requires at least one, so this appears with the choice.
                Column {
                  visible: Boolean(root.formOrgId) && root.formOrgId !== "personal"
                  width: parent.width
                  spacing: Style.space(3)

                  Item { width: 1; height: Style.space(4) }

                  Row {
                    width: parent.width
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      text: "COLLECTIONS"
                      color: root.formCollectionIds.length === 0 ? root.urgent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                    Text {
                      textFormat: Text.PlainText
                      text: root.formCollectionsLoading
                        ? "loading..."
                        : (root.formCollectionIds.length === 0
                            ? "pick at least one"
                            : root.formCollectionIds.length + " selected")
                      color: root.formCollectionIds.length === 0 ? root.urgent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                    }
                  }

                  Flickable {
                    id: collectionList
                    width: parent.width
                    height: Math.min(Style.space(150), collectionCol.implicitHeight)
                    contentWidth: width
                    contentHeight: collectionCol.implicitHeight
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    flickableDirection: Flickable.VerticalFlick
                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                    Column {
                      id: collectionCol
                      width: collectionList.width
                      spacing: Style.space(2)

                      Text {
                        textFormat: Text.PlainText
                        visible: !root.formCollectionsLoading && root.formCollections.length === 0
                        width: parent.width
                        text: "No collections available in this organization."
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        wrapMode: Text.WordWrap
                      }

                      Repeater {
                        model: root.formCollections
                        delegate: FormPickerRow {
                          required property var modelData
                          width: parent.width
                          foreground: root.fg
                          fontFamily: root.fontFamily
                          label: modelData.name
                          glyph: "\u{F0290}"
                          picked: root.isFormCollectionSelected(modelData.id)
                          // Several collections may hold one item, so these
                          // toggle instead of replacing the choice.
                          multi: true
                          onActivated: root.toggleFormCollection(modelData.id)
                        }
                      }
                    }
                  }
                }
              }

              // FIELD: Username (Login only)
              Column {
                visible: root.formTypeCode === 1
                width: parent.width
                spacing: Style.space(3)
                Text { textFormat: Text.PlainText; text: "USERNAME / EMAIL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
                  Text { textFormat: Text.PlainText; text: "PASSWORD"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
                  Item { Layout.fillWidth: true }
                  // Opens the real generator, which fills this field in and
                  // comes back. The ellipsis says it goes somewhere first.
                  Button {
                    text: "Generate..."
                    iconText: "󰌆"
                    fontFamily: root.fontFamily
                    fontSize: Style.font.caption
                    onClicked: root.openGenerator()
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
                Text { textFormat: Text.PlainText; text: "AUTHENTICATOR KEY (TOTP SECRET)"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
                Text { textFormat: Text.PlainText; text: "WEBSITE URL"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
                Text { textFormat: Text.PlainText; text: "NOTES"; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; font.bold: true }
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
