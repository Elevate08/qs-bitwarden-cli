import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
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

  // Screens: "main" (item list) | "detail" (item detail) | "locked" | "login"
  property string currentScreen: "main"

  property var items: []
  property var filteredItems: []
  property string searchQuery: ""
  property string selectedCategory: "all"
  property int selectedIndex: 0

  // Selected item detail
  property var detailItem: null
  property string detailPassword: ""
  property bool passwordRevealed: false
  property string liveTotp: ""
  property int totpSecRemaining: 30

  // Status & indicators
  property bool isLoading: false
  property bool isSyncing: false
  property string errorMessage: ""
  property string flashMessage: ""
  property bool cursorActive: false

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

  Component.onCompleted: root.refreshStatus()

  readonly property var categories: [
    { id: "all", label: "All", icon: "󰞀" },
    { id: "login", label: "Logins", icon: "󰌋" },
    { id: "secureNote", label: "Notes", icon: "󰈐" },
    { id: "card", label: "Cards", icon: "󰅝" },
    { id: "identity", label: "Identities", icon: "󰓹" },
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
    root.controller.show()
    refreshStatus()
  }

  function close() {
    errorMessage = ""
    passwordRevealed = false
    masterPassword = ""
    loginPassword = ""
    root.controller.hide()
  }

  function toggle() {
    if (opened) close()
    else open()
  }

  onOpenedChanged: {
    if (opened) {
      if (status === "unlocked") {
        currentScreen = "main"
        loadItems()
      } else {
        refreshStatus()
      }
      Qt.callLater(function() {
        if (status === "unlocked") {
          searchField.forceActiveFocus()
        } else if (status === "locked") {
          passField.forceActiveFocus()
        } else if (status === "unauthenticated") {
          emailField.forceActiveFocus()
        }
      })
    }
  }

  // -------------------------------------------------------------------------
  // Status & Keyring Handlers
  // -------------------------------------------------------------------------

  function refreshStatus() {
    isLoading = true
    errorMessage = ""
    if (session) {
      statusProc.command = Model.statusCommand(session)
      statusProc.running = true
    } else if (rememberSession) {
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
      return
    }

    userEmail = st.userEmail
    if (st.userEmail && !loginEmail) {
      loginEmail = st.userEmail
    }

    if (st.unlocked) {
      status = "unlocked"
      currentScreen = "main"
      loadItems()
      resetAutoLockTimer()
    } else if (st.locked) {
      status = "locked"
      currentScreen = "locked"
      items = []
      filteredItems = []
    } else {
      status = "unauthenticated"
      currentScreen = "login"
      items = []
      filteredItems = []
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
      // API Key method
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

    // Check if 2FA code is needed or failed
    var combined = (err + " " + out).toLowerCase()
    if (combined.indexOf("two-step") !== -1 || combined.indexOf("verification") !== -1 || combined.indexOf("twofactor") !== -1 || combined.indexOf("2fa") !== -1 || combined.indexOf("invalid_grant") !== -1 || combined.indexOf("code") !== -1) {
      show2faField = true
      errorMessage = "Two-step verification code required or incorrect. Please enter your 6-digit code below."
      Qt.callLater(function() { code2faField.forceActiveFocus() })
      return
    }

    if (exitCode === 0 && out.length > 10) {
      // Login succeeded and returned session key!
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
      // Try unlocking now that login completed
      unlockVaultWithPassword(loginPassword)
    }
  }

  function launchTerminalLogin() {
    close()
    Quickshell.execDetached(["bash", "-c", "omarchy launch terminal -e bash -c 'bw login; read -p \"Login complete. Press enter to close...\"' || alacritty -e bash -c 'bw login; read -p \"Login complete. Press enter to close...\"'"])
  }

  function logoutAccount() {
    lockVault()
    logoutProc.command = Model.logoutCommand()
    logoutProc.running = true
    status = "unauthenticated"
    currentScreen = "login"
    userEmail = ""
    flashNotification("Logged out")
  }

  // -------------------------------------------------------------------------
  // Vault Unlock & Lock
  // -------------------------------------------------------------------------

  function unlockVault() {
    unlockVaultWithPassword(masterPassword)
  }

  function unlockVaultWithPassword(pass) {
    var p = String(pass || "").trim()
    if (!p) {
      errorMessage = "Master password required"
      return
    }
    errorMessage = ""
    isLoading = true
    unlockProc.command = Model.unlockCommand(p)
    unlockProc.running = true
  }

  function onUnlockOutput(stdoutText, stderrText, exitCode) {
    isLoading = false
    var out = String(stdoutText || "").trim()
    var err = String(stderrText || "").trim()

    if (exitCode === 0 && out) {
      onUnlockSuccess(out)
    } else {
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
    var s = String(rawSession || "").trim()
    masterPassword = ""
    loginPassword = ""
    if (!s) {
      errorMessage = "Unlock did not return a session key"
      isLoading = false
      return
    }

    session = s
    status = "unlocked"
    currentScreen = "main"
    flashNotification("Vault unlocked successfully!")

    if (rememberSession) {
      keyringStoreProc.running = true
    }

    loadItems()
    resetAutoLockTimer()
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
    status = "locked"
    currentScreen = "locked"
    items = []
    filteredItems = []
    detailItem = null
    detailPassword = ""
    liveTotp = ""
    flashNotification("Vault locked")
  }

  // -------------------------------------------------------------------------
  // Vault Data Operations
  // -------------------------------------------------------------------------

  function loadItems() {
    if (!session) return
    isLoading = true
    listProc.command = Model.listCommand(session)
    listProc.running = true
  }

  function onListFinished(rawJson) {
    isLoading = false
    items = Model.parseItems(rawJson)
    rebuildFilter()
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
    } else {
      errorMessage = "Sync failed"
    }
  }

  function openDetail(item) {
    if (!item || !item.id) return
    isLoading = true
    errorMessage = ""
    passwordRevealed = false
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
    liveTotp = String(code || "").trim()
  }

  // -------------------------------------------------------------------------
  // Filtering & Selection
  // -------------------------------------------------------------------------

  function rebuildFilter() {
    filteredItems = Model.filterItems(items, searchQuery, selectedCategory)
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
  // Clipboard Actions
  // -------------------------------------------------------------------------

  function copyToClipboard(text, label) {
    if (!text) return
    resetAutoLockTimer()
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(text) + " | wl-copy"])
    flashNotification(label + " copied!")

    if (clearClipboardSec > 0) {
      clipboardClearTimer.restart()
    }
  }

  function copyPassword(item) {
    if (!item) return
    if (item.id === (detailItem ? detailItem.id : "") && detailPassword) {
      copyToClipboard(detailPassword, "Password")
      return
    }
    Quickshell.execDetached(["bash", "-c", "bw get password " + Util.shellQuote(item.id) + " --session " + Util.shellQuote(session) + " --raw | wl-copy"])
    flashNotification("Password copied!")
    if (clearClipboardSec > 0) clipboardClearTimer.restart()
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
    Quickshell.execDetached(["bash", "-c", "bw get totp " + Util.shellQuote(item.id) + " --session " + Util.shellQuote(session) + " --raw | wl-copy"])
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
    running: root.opened && root.currentScreen === "detail" && root.detailItem !== null && root.detailItem.hasTotp
    repeat: true
    onTriggered: {
      var sec = 30 - (Math.floor(Date.now() / 1000) % 30)
      root.totpSecRemaining = sec
      if (sec === 30 && root.detailItem) {
        root.fetchTotp(root.detailItem.id)
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
    stdinEnabled: true
    onStarted: {
      write(String(root.session || "") + "\n")
    }
  }

  Process {
    id: keyringClearProc
    command: Model.keyringClearCommand()
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
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight, Style.space(620))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: searchField.activeFocus
        || emailField.activeFocus
        || loginPassField.activeFocus
        || code2faField.activeFocus
        || passField.activeFocus

      onCloseRequested: {
        if (root.currentScreen === "detail") {
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
          if (item) root.openDetail(item)
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
          } else if (lower === "l") {
            root.lockVault()
          } else if (lower === "r") {
            root.syncVault()
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
              return root.userEmail ? (root.userEmail + " • " + root.items.length + " items") : (root.items.length + " items")
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

            PanelActionButton {
              visible: root.status === "unlocked"
              iconText: "󰑐"
              tooltipText: "Sync vault (r)"
              fontFamily: root.fontFamily
              enabled: !root.isSyncing
              onClicked: root.syncVault()
            }

            PanelActionButton {
              visible: root.status === "unlocked"
              iconText: "󰒃"
              tooltipText: "Lock vault (l)"
              fontFamily: root.fontFamily
              onClicked: root.lockVault()
            }

            PanelActionButton {
              iconText: "󰅖"
              tooltipText: "Close (Esc)"
              fontFamily: root.fontFamily
              onClicked: root.close()
            }
          }
        }

        // -------------------------------------------------------------------
        // Flash Message Banner
        // -------------------------------------------------------------------
        BorderSurface {
          visible: root.flashMessage !== ""
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
        // SCREEN 1: LOGIN VIEW (When unauthenticated)
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unauthenticated"
          width: parent.width
          spacing: Style.space(12)

          PanelSeparator { width: parent.width }

          // Login Method Selector
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

            // 2FA / Verification Code Field (Always visible)
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

          // Terminal Login Alternative
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
          visible: root.status === "locked" || root.status === "checking"
          width: parent.width
          spacing: Style.space(14)

          PanelSeparator { width: parent.width }

          Item { height: Style.space(8); width: 1 }

          Column {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Style.space(6)

            Text {
              anchors.horizontalCenter: parent.horizontalCenter
              text: "󰌋"
              color: root.fg
              opacity: 0.85
              font.family: root.fontFamily
              font.pixelSize: Style.space(38)
            }

            Text {
              anchors.horizontalCenter: parent.horizontalCenter
              text: "Enter Master Password"
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

          Column {
            width: parent.width
            spacing: Style.space(10)

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
                enabled: !root.isLoading
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
              text: root.isLoading ? "Unlocking..." : "Unlock Vault"
              iconText: root.isLoading ? "󰑐" : "󰌋"
              iconSpinning: root.isLoading
              selected: true
              accent: Color.accent
              fontFamily: root.fontFamily
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
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 3: UNLOCKED - ITEM LIST VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.currentScreen === "main"
          width: parent.width
          spacing: Style.space(10)

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
                if (itm) root.openDetail(itm)
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

          PanelSeparator { width: parent.width }

          // Item List View (Fast Virtualized ListView with Delegate Recycling)
          Item {
            width: parent.width
            height: Style.space(340)

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

                  // Labels (Title + Subtitle)
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

                    Text {
                      text: itemData.subtitle || Model.itemTypeLabel(itemData.typeCode)
                      color: root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      elide: Text.ElideRight
                      width: parent.width
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
                      tooltipText: "Copy password (y)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyPassword(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.username !== ""
                      iconText: "󰀭"
                      tooltipText: "Copy username (u)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyUsername(itemData)
                    }

                    PanelActionButton {
                      visible: itemData.hasTotp
                      iconText: "󰑐"
                      tooltipText: "Copy TOTP code (t)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyTotpCode(itemData)
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
                  text: root.items.length === 0 ? "󰒃" : "󰍡"
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.space(32)
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

          // Keyboard Shortcuts Footer
          Text {
            width: parent.width
            text: "↑↓: move   Enter: view   y: pass   u: user   t: totp   l: lock   /: search"
            color: Qt.darker(root.dim, 1.2)
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            horizontalAlignment: Text.AlignHCenter
          }
        }

        // -------------------------------------------------------------------
        // SCREEN 4: UNLOCKED - ITEM DETAIL VIEW
        // -------------------------------------------------------------------
        Column {
          visible: root.status === "unlocked" && root.currentScreen === "detail"
          width: parent.width
          spacing: Style.space(12)

          // Back Navigation Button
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
          }

          PanelSeparator { width: parent.width }

          Flickable {
            id: detailFlickable
            width: parent.width
            height: Math.min(Style.space(400), detailContentColumn.implicitHeight)
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

              // Item Header (Icon, Name, Type Pill)
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
                      visible: root.detailItem && root.detailItem.favorite
                      text: "★"
                      color: Color.accent
                      font.pixelSize: Style.font.body
                    }
                  }

                  Text {
                    text: root.detailItem ? Model.itemTypeLabel(root.detailItem.typeCode) : ""
                    color: root.dim
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }
              }

              // FIELD: Username
              Column {
                visible: root.detailItem && root.detailItem.username !== ""
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
                      iconText: "󰀭"
                      tooltipText: "Copy username (u)"
                      fontFamily: root.fontFamily
                      onClicked: root.copyToClipboard(root.detailItem.username, "Username")
                    }
                  }
                }
              }

              // FIELD: Password
              Column {
                visible: root.detailItem && (root.detailPassword !== "" || root.detailItem.hasPassword)
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
                        tooltipText: "Copy password (y)"
                        fontFamily: root.fontFamily
                        onClicked: root.copyToClipboard(root.detailPassword, "Password")
                      }
                    }
                  }
                }
              }

              // FIELD: TOTP (2FA Code)
              Column {
                visible: root.detailItem && root.detailItem.hasTotp
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

                  // Progress bar at bottom showing TOTP countdown
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
                      iconText: "󰑐"
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
                visible: root.detailItem && root.detailItem.uris && root.detailItem.uris.length > 0
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

              // FIELD: Card details
              Column {
                visible: root.detailItem && root.detailItem.card !== null
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "CARD INFORMATION" }

                BorderSurface {
                  width: parent.width
                  implicitHeight: cardDetailsCol.implicitHeight + Style.space(16)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, Color.accent)
                  borderSpec: Border.controlSpec("normal", root.fg, Color.accent)

                  Column {
                    id: cardDetailsCol
                    anchors.fill: parent
                    anchors.margins: Style.space(10)
                    spacing: Style.space(6)

                    Row {
                      width: parent.width
                      Text { text: "Cardholder:"; color: root.dim; width: Style.space(100); font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                      Text { text: (root.detailItem && root.detailItem.card) ? root.detailItem.card.cardholderName : ""; color: root.fg; font.family: root.fontFamily; font.pixelSize: Style.font.bodySmall }
                    }
                    Row {
                      width: parent.width
                      Text { text: "Number:"; color: root.dim; width: Style.space(100); font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                      Text {
                        text: (root.detailItem && root.detailItem.card) ? (root.passwordRevealed ? root.detailItem.card.number : Model.maskString(root.detailItem.card.number)) : ""
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                      }
                      Item { Layout.fillWidth: true }
                      PanelActionButton {
                        iconText: "󰅝"
                        tooltipText: "Copy card number"
                        size: Style.space(20)
                        fontFamily: root.fontFamily
                        onClicked: if (root.detailItem && root.detailItem.card) root.copyToClipboard(root.detailItem.card.number, "Card number")
                      }
                    }
                    Row {
                      width: parent.width
                      Text { text: "Expiration:"; color: root.dim; width: Style.space(100); font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                      Text { text: (root.detailItem && root.detailItem.card) ? (root.detailItem.card.expMonth + "/" + root.detailItem.card.expYear) : ""; color: root.fg; font.family: root.fontFamily; font.pixelSize: Style.font.bodySmall }
                    }
                    Row {
                      width: parent.width
                      Text { text: "Security Code:"; color: root.dim; width: Style.space(100); font.family: root.fontFamily; font.pixelSize: Style.font.caption }
                      Text { text: (root.detailItem && root.detailItem.card) ? (root.passwordRevealed ? root.detailItem.card.code : "•••") : ""; color: root.fg; font.family: root.fontFamily; font.pixelSize: Style.font.bodySmall }
                    }
                  }
                }
              }

              // FIELD: Notes
              Column {
                visible: root.detailItem && root.detailItem.notes !== ""
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

              // Custom Fields
              Column {
                visible: root.detailItem && root.detailItem.fields && root.detailItem.fields.length > 0
                width: parent.width
                spacing: Style.space(4)

                PanelSectionHeader { text: "CUSTOM FIELDS" }

                Repeater {
                  model: root.detailItem ? root.detailItem.fields : []
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
                        text: modelData.name + ":"
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        width: Style.space(100)
                        elide: Text.ElideRight
                      }

                      Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: (modelData.type === 1 && !root.passwordRevealed) ? Model.maskString(modelData.value) : modelData.value
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.bodySmall
                        elide: Text.ElideRight
                        width: parent.width - Style.space(110) - copyFieldBtn.width - Style.space(6)
                      }

                      PanelActionButton {
                        id: copyFieldBtn
                        anchors.verticalCenter: parent.verticalCenter
                        iconText: "󰌆"
                        tooltipText: "Copy " + modelData.name
                        fontFamily: root.fontFamily
                        onClicked: root.copyToClipboard(modelData.value, modelData.name)
                      }
                    }
                  }
                }
              }

              Item { height: Style.space(8); width: 1 }
            }
          }
        }
      }
    }
  }
}
